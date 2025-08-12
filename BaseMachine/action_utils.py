"""
LLM Action Functions Module
Contains various action functions for interacting with LLMs
"""

from typing import Any, List
from pydantic import BaseModel, Field
import logging
from colorama import Fore
import json
import requests
# Fix import errors by adapting to different OpenAI library versions
try:
    # Try importing from newer version
    from openai.types.chat import ChatCompletion, ChatCompletionMessage
    from openai.types.chat.chat_completion import Choice
except ImportError:
    try:
        # Try importing from another possible location
        from openai.types.chat import ChatCompletion, ChatCompletionMessage
        from openai.types import Choice
    except ImportError:
        # If both fail, create a simple implementation
        class ChatCompletion:
            def __init__(self, id, choices, created, model, object, system_fingerprint, usage):
                self.id = id
                self.choices = choices
                self.created = created
                self.model = model
                self.object = object
                self.system_fingerprint = system_fingerprint
                self.usage = usage
                
        class ChatCompletionMessage:
            def __init__(self, content, role, function_call=None, tool_calls=None):
                self.content = content
                self.role = role
                self.function_call = function_call
                self.tool_calls = tool_calls
                
        class Choice:
            def __init__(self, finish_reason, index, message, logprobs=None):
                self.finish_reason = finish_reason
                self.index = index
                self.message = message
                self.logprobs = logprobs


class ContextCode(BaseModel):
    name: str = Field(description="Function or Class name")
    reason: str = Field(description="Brief reason why this function's code is needed for analysis")
    code_line: str = Field(description="The single line of code where where this context object is referenced.")
    file_path: str = Field(description="The file path of the code line.")

class Response(BaseModel):
    analysis: str = Field(description="The analysis result of the question.")
    context_code: List[str] = Field(description="If you need additional context code to analyze the question, please provide the context code's names you need additionally to analyze the question.")

# Import helper functions
from BaseMachine.llm_helpers import (
    reliable_parse, 
    safe_format, 
    extract_code_snippets, 
    parse_and_validate_json_response
)

def create_chat_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o', debug=False):
    """
    Create a chat action function for sending prompts and handling responses.
    Maintains the complete chat history.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :param debug: Whether to enable debugging
    :return: The action function
    """
    def chat_action(machine, **kwargs):
        from BaseMachine.state_machine import StateMachine  # Move import here
        prompt = prompt_template.format(**kwargs)

        if debug:
            logging.info(Fore.BLUE + f'Chat Action Prompt: {prompt}')

        machine.messages.append({"role": "user", "content": prompt})

        # Select the appropriate client based on model_name
        client_to_use, info = next(((client, info) for client, info in machine.clients if info['name'] == model_name), (None, None))
        if client_to_use is None:
            raise ValueError(f"Model '{model_name}' not found in initialized clients.")

        # Ensure info is a dictionary
        if isinstance(info, tuple):
            info = dict(info)

        # Build request parameters based on whether response_parser is None or not
        request_params = {
            'model': info['model_name'],
            'messages': machine.messages,
            **(
                {"temperature": 0.01, "top_p": machine.config.top_p}
                if info['model_name'] not in ["o1-mini", "o1-preview"]
                else {}
            ),
        }
        if response_parser is not None:
            request_params['response_format'] = response_parser

        # Change to use the reliable_parse function to make the request
        # Use the selected client to make the request
        logging.info(Fore.YELLOW + f'Waiting for the model {info["model_name"]} to process the request...')
        response = reliable_parse(client_to_use, request_params, max_retries=3, debug=debug, model_info=info)
        logging.info(Fore.GREEN + f'Model {info["model_name"]} processed the request successfully.')
        # machine.total_input_tokens += response.usage.prompt_tokens
        # machine.total_output_tokens += response.usage.completion_tokens

        # Add the assistant's reply to the message list
        machine.messages.append(
            {"role": "assistant", "content": response.choices[0].message.content}
        )

        # Parse the assistant's reply
        message = response.choices[0].message
        # parsed_result = getattr(message, "parsed", message.content)
        parsed_result = message.content if getattr(message, "parsed", None) is None else message.parsed

        # Save content based on the save_option parameter
        if save_option == 'prompt':
            machine.analysis_result.append(prompt)
        elif save_option == 'result':
            machine.analysis_result.append(parsed_result)
        elif save_option == 'both':
            machine.analysis_result.append({'prompt': prompt, 'result': parsed_result})
        elif save_option == 'none':
            pass
        else:
            # If an invalid save_option is provided, throw an exception or perform default handling
            raise ValueError("Invalid save_option value. Choose from 'prompt', 'result', or 'both'.")

        return parsed_result

    return chat_action


def create_new_chat_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o', debug=False):
    """
    Create a new chat action function that ignores previous messages but updates the machine's message history.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :param debug: Whether to enable debugging
    :return: The action function
    """
    pass


def create_context_filling_new_chat_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o'):
    """
    Create a context-filling chat action function.
    The first response includes a general chat result and a context filling field.
    Then, include the filled context code at the end of the prompt and re-ask.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :return: The action function
    """
    pass


def create_context_filling_new_chat_json_action(prompt_template, response_parser=None, save_option='both', model_name='azure-gpt4o', debug=False, use_hardcoded_json=False, accelerated_mode=True):
    """
    Create a context-filling chat action function with JSON response format.
    Provides accelerated mode and debugging features.
    
    :param prompt_template: The prompt template
    :param response_parser: Optional response parser
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :param model_name: The model name to use
    :param debug: Whether to enable debugging
    :param use_hardcoded_json: Whether to use hardcoded JSON (for debugging)
    :param accelerated_mode: Whether to enable accelerated mode
    :return: The action function
    """
    pass


def call_sub_state_machine_action(sub_state_definitions, sub_initial_state, sub_context_cls, save_option='both'):
    """
    Create an action function that calls a sub-state machine
    
    :param sub_state_definitions: The sub-state machine's state definitions
    :param sub_initial_state: The sub-state machine's initial state
    :param sub_context_cls: The sub-state machine's context class
    :param save_option: Save option, can be 'both', 'prompt', 'result', or 'none'
    :return: The action function
    """
    def sub_state_machine_action(machine, **kwargs):
        from BaseMachine.state_machine import StateMachine  # Move import here
        # Create the sub-state machine's context
        sub_context = sub_context_cls(**kwargs)
        
        # Create and run the sub-state machine
        sub_machine = StateMachine(
            context=sub_context,
            state_definitions=sub_state_definitions,
            initial_state=sub_initial_state,
            config_path=machine.config.config_path
        )
        sub_result = sub_machine.process()
        
        # Merge the sub-state machine's results and resource consumption
        machine.total_input_tokens += sub_machine.total_input_tokens
        machine.total_output_tokens += sub_machine.total_output_tokens
        machine.messages.extend(sub_machine.messages)
        
        # Save content based on the save_option parameter
        if save_option == 'prompt':
            machine.analysis_result.append(sub_context)
        elif save_option == 'result':
            machine.analysis_result.append(sub_result)
        elif save_option == 'both':
            machine.analysis_result.append({'context': sub_context, 'result': sub_result})
        else:
            # If an invalid save_option is provided, throw an exception or perform default handling
            raise ValueError("Invalid save_option value. Choose from 'prompt', 'result', or 'both'.")
        
        return sub_result
    return sub_state_machine_action
