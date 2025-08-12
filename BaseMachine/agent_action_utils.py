# agent_action_utils.py

import anyio
import logging
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional, List, AsyncIterator, Union, TYPE_CHECKING

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if TYPE_CHECKING:
    from BaseMachine.state_machine import StateMachine
from claude_code_sdk import (
    query,
    ClaudeCodeOptions,
    AssistantMessage,
    TextBlock,
    ToolUseBlock,
    ToolResultBlock,
    UserMessage,
    SystemMessage,
    ResultMessage,
    CLINotFoundError,
    ProcessError,
    CLIJSONDecodeError
)

logger = logging.getLogger(__name__)


class StreamingJSONLogger:
    """
    Logger for saving streaming JSON messages from Claude Code SDK.
    """
    def __init__(self, base_log_dir: str = None):
        if base_log_dir is None:
            base_log_dir = os.path.join(SCRIPT_DIR, 'qlworkspace')
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(parents=True, exist_ok=True)
        self.current_session_id = None
        self.session_messages = []
        
    def create_session(self, context: Dict[str, Any]) -> str:
        """
        Create a new logging session.
        
        Args:
            context: Context containing session metadata
            
        Returns:
            Session ID
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Include action type in session ID if available
        action_type = context.get('action_type', 'general')
        self.current_session_id = f"{action_type}_{timestamp}"
        
        # Build log directory path
        # Use custom log path if provided, otherwise use default
        if 'log_path' in context:
            self.session_log_dir = Path(context['log_path'])
        else:
            # Create a general session directory
            self.session_log_dir = self.base_log_dir / 'sessions' / self.current_session_id
        
        self.session_log_dir.mkdir(parents=True, exist_ok=True)
        self.session_messages = []
        
        # Log session start
        self.log_message({
            'type': 'session_start',
            'session_id': self.current_session_id,
            'timestamp': timestamp,
            'context': context
        })
        
        return self.current_session_id
    
    def log_message(self, message: Dict[str, Any]):
        """
        Log a streaming JSON message.
        
        Args:
            message: The message to log
        """
        if not self.current_session_id:
            logger.warning("No active session. Message not logged.")
            return
        
        # Add timestamp if not present
        if 'timestamp' not in message:
            message['timestamp'] = datetime.now().isoformat()
        
        self.session_messages.append(message)
        
        # Write to single log file (append mode) - no longer separate streaming file
        log_path = self.session_log_dir / f"{self.current_session_id}.jsonl"
        with open(log_path, 'a') as f:
            f.write(json.dumps(message) + '\n')
    
    def finalize_session(self, result: Any = None):
        """
        Finalize the current session and save complete log.
        
        Args:
            result: Final result of the session
        """
        if not self.current_session_id:
            return
        
        # Log session end
        self.log_message({
            'type': 'session_end',
            'session_id': self.current_session_id,
            'timestamp': datetime.now().isoformat(),
            'result_summary': str(result) if result else None
        })
        
        # No need to save a separate complete log file - the JSONL file has everything
        # Just log the final statistics
        logger.info(f"Session {self.current_session_id} completed with {len(self.session_messages)} messages")
        
        logger.info(f"Session {self.current_session_id} finalized. Logs saved to {self.session_log_dir}")
        
        # Reset session
        self.current_session_id = None
        self.session_messages = []


# Global logger instance
streaming_logger = StreamingJSONLogger()


def parse_streaming_json_message(message: Any) -> Dict[str, Any]:
    """
    Parse a streaming JSON message from Claude Code SDK.
    
    Args:
        message: The message object from the SDK
        
    Returns:
        A dictionary representing the JSON message
    """
    message_dict = {
        'type': type(message).__name__.lower().replace('message', '')
    }
    
    if isinstance(message, (SystemMessage, UserMessage)):
        message_dict['content'] = str(message.content) if hasattr(message, 'content') else ''
    elif isinstance(message, AssistantMessage):
        content_list = []
        for block in message.content:
            if isinstance(block, TextBlock):
                content_list.append({
                    'type': 'text',
                    'text': block.text
                })
            elif isinstance(block, ToolUseBlock):
                content_list.append({
                    'type': 'tool_use',
                    'name': block.name,
                    'input': block.input
                })
        message_dict['content'] = content_list
    elif isinstance(message, ResultMessage):
        message_dict.update({
            'session_id': getattr(message, 'session_id', None),
            'duration': getattr(message, 'duration', None),
            'total_cost': getattr(message, 'total_cost', None),
            'turn_count': getattr(message, 'turn_count', None)
        })
    
    return message_dict


def create_agent_action(
    prompt_template: str,
    response_parser: Optional[Callable[[str], Any]] = None,
    save_option: str = 'both',
    allowed_tools: Optional[List[str]] = None,
    permission_mode: str = 'default',
    system_prompt: Optional[str] = None,
    max_turns: Optional[int] = None,
    output_format: str = 'default',
    stream_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    enable_stream_logging: bool = False,
    debug: bool = False
) -> Callable[['StateMachine', Dict[str, Any]], Any]:
    """
    Create an agent action function using Claude Code SDK.
    
    Args:
        prompt_template: Template string for the prompt
        response_parser: Optional function to parse response
        save_option: How to save the interaction (unused in agent mode)
        allowed_tools: List of tools the agent can use
        permission_mode: 'acceptEdits', 'bypassPermissions', 'default', or 'plan'
        system_prompt: System prompt for the agent
        max_turns: Maximum conversation turns
        output_format: Output format - 'default' or 'stream-json'
        stream_callback: Optional callback for streaming JSON messages
        enable_stream_logging: Enable automatic streaming JSON logging
        debug: Enable debug logging
        
    Returns:
        An action function that can be used in state definitions
    """
    def action(machine: 'StateMachine', **kwargs) -> Any:
        # Format the prompt using template
        formatted_prompt = prompt_template.format(**kwargs)
        
        if debug:
            logger.debug(f"Agent action prompt: {formatted_prompt}")
        
        # Initialize streaming logger session if enabled
        session_id = None
        if enable_stream_logging or output_format == 'stream-json':
            # Extract context from machine for logging
            log_context = {
                'action_type': machine.context.get('action_type', 'general'),
                'working_directory': machine.context.get('working_directory'),
                'prompt': formatted_prompt[:200] + '...' if len(formatted_prompt) > 200 else formatted_prompt
            }
            # Allow machine context to override log path
            if hasattr(machine.context, 'session_log_path'):
                log_context['log_path'] = machine.context.session_log_path
            session_id = streaming_logger.create_session(log_context)
        
        # Configure Claude Code options
        options = ClaudeCodeOptions(
            cwd=machine.context.get('working_directory', None),
            allowed_tools=allowed_tools or [],
            permission_mode=permission_mode,
            system_prompt=system_prompt,
            max_turns=max_turns
        )
        
        # Collect all responses
        responses = []
        tool_uses = []
        streaming_messages = []
        
        try:
            # Run the async query synchronously
            async def run_query():
                async for message in query(prompt=formatted_prompt, options=options):
                    if debug:
                        logger.debug(f"Received message: {type(message).__name__}")
                    
                    # Handle streaming JSON output
                    if output_format == 'stream-json' or enable_stream_logging:
                        json_message = parse_streaming_json_message(message)
                        streaming_messages.append(json_message)
                        
                        # Log to file if enabled
                        if enable_stream_logging:
                            streaming_logger.log_message(json_message)
                        
                        # Call stream callback if provided
                        if stream_callback:
                            stream_callback(json_message)
                    
                    if isinstance(message, AssistantMessage):
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                responses.append(block.text)
                                # Check for Claude AI usage limit error
                                if "Claude AI usage limit reached" in block.text:
                                    logger.error("Claude AI usage limit reached - stopping pipeline")
                                    raise RuntimeError("Claude AI usage limit reached")
                            elif isinstance(block, ToolUseBlock):
                                tool_uses.append({
                                    'tool': block.name,
                                    'input': block.input
                                })
                    elif isinstance(message, ResultMessage):
                        # Handle result message with metadata
                        if debug:
                            logger.debug(f"Result message: {message}")
                
                return responses, tool_uses, streaming_messages
            
            responses, tool_uses, streaming_messages = anyio.run(run_query)
            
            # Join all text responses
            full_response = '\n'.join(responses)
            
            # Store in machine's context for hybrid mode
            if hasattr(machine, 'agent_results'):
                machine.agent_results.append({
                    'prompt': formatted_prompt,
                    'response': full_response,
                    'tool_uses': tool_uses
                })
            
            # Finalize streaming logger session
            if session_id:
                streaming_logger.finalize_session({
                    'response_length': len(full_response),
                    'tool_use_count': len(tool_uses),
                    'message_count': len(streaming_messages)
                })
            
            # Parse response if parser provided
            if response_parser:
                parsed_result = response_parser(full_response)
                if output_format == 'stream-json':
                    return {
                        'parsed': parsed_result,
                        'streaming_messages': streaming_messages
                    }
                return parsed_result
            
            result = {
                'response': full_response,
                'tool_uses': tool_uses
            }
            
            if output_format == 'stream-json':
                result['streaming_messages'] = streaming_messages
            
            return result
            
        except CLINotFoundError:
            logger.error("Claude Code CLI not found. Please install with: npm install -g @anthropic-ai/claude-code")
            raise
        except ProcessError as e:
            logger.error(f"Process failed with exit code: {e.exit_code}")
            raise
        except RuntimeError as e:
            # Re-raise RuntimeError (including usage limit) without wrapping
            if "Claude AI usage limit reached" in str(e):
                logger.error("Claude AI usage limit reached - stopping execution")
            raise
        except Exception as e:
            logger.error(f"Agent action failed: {e}")
            raise
    
    return action


