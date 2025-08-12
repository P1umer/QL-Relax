# statemachine.py

import os
import sys
from typing import Any, Callable, Dict, Tuple
import logging

# Import configuration loading function
from BaseMachine.config_loader import load_config
from BaseMachine.model_manager import ModelManager

from openai import OpenAI
from openai import AzureOpenAI

# Add utils directory to system path (as needed)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

class BaseState:
    def __init__(
        self,
        name: str,
        action: Callable[..., Any],
        next_state_func: Callable[[Any, 'StateMachine'], Tuple[str, Dict[str, Any]]] = None,
    ):
        self.name = name
        self.action = action
        self.next_state_func = next_state_func

    def process(self, machine: 'StateMachine', **kwargs):
        # Execute action, pass in machine and optional parameters, get result
        result = self.action(machine, **kwargs)
        # Call next_state_func, may return next state name or (state name, parameters)
        next_state_info = self.next_state_func(result, machine)
        return next_state_info, result  # Return next state info and result

class ExitState(BaseState):
    def __init__(self):
        super().__init__(name="Exit", action=lambda machine: None)

    def process(self, machine, **kwargs):
        pass  # Exit state, no processing needed

class StateMachine:
    def __init__(self, context, state_definitions: Dict[str, Dict], initial_state: str, config_path='', unified_config=None, mode='chat', require_models=True, cwd=None):
        self.state = None
        self.context = context
        self.unified_config = unified_config
        self.mode = mode  # 'chat', 'agent', 'hybrid', or 'action'
        self.require_models = require_models
        self.cwd = cwd or os.getcwd()  # Use provided cwd or current working directory
        
        # Change to the specified working directory if provided
        if cwd and os.path.isdir(cwd):
            self.original_cwd = os.getcwd()
            os.chdir(self.cwd)
        else:
            self.original_cwd = None
        
        # Initialize model manager only if needed
        if self.require_models and mode != 'action':
            config_dir = os.path.dirname(config_path) if config_path else os.path.join(os.path.dirname(__file__), '../.config')
            self.model_manager = ModelManager(config_dir)
        else:
            self.model_manager = None
        
        # Initialize agent-specific attributes
        self.agent_results = []  # Store agent action results
        self.hybrid_history = []  # Store hybrid mode history

        # # Test model 'create_success' functionality
        # self._test_model_create_success()

        # Load configuration
        self.config = self._load_config(config_path)

        self.analysis_result = []
        self.messages = getattr(self.context, 'messages', [])
        self.total_input_tokens = 0
        self.total_output_tokens = 0

        # Initialize all model clients only if model manager exists
        if self.model_manager:
            self.clients = self.model_manager.initialize_client()
        else:
            self.clients = {}

        # Note: Client selection is handled by create_chat_action, not here.

        # Create state instances
        self.states = self._create_states(state_definitions)
        self.state = self.states.get(initial_state, None)
        if self.state is None:
            raise ValueError(f"Initial state '{initial_state}' is not defined in state_definitions.")
        
    def _load_config(self, config_path):
        if not config_path:
            default_config_path = '../.config/config.json'
            config_path = os.path.join(os.path.dirname(__file__), default_config_path)
        config = load_config(config_path)
        config.config_path = config_path  # Set config_path attribute
        return config

    def _create_states(self, state_definitions):
        states = {}
        for name, config in state_definitions.items():
            if name == "Exit":
                states[name] = ExitState()
            else:
                states[name] = BaseState(
                    name=name,
                    action=config['action'],
                    next_state_func=config.get("next_state_func", None),
                )
        return states

    def process(self):
        previous_result = None  # Save the result of the previous action
        extra_args = {}  # Store parameters to pass to the next action
        while True:
            try:
                if isinstance(self.state, ExitState) or self.state is None:
                    return previous_result  # or self.analysis_result
                else:
                    # Call action function, pass in machine and optional parameters
                    action_func = self.state.action

                    # Get the parameter list of action_func
                    args_spec = action_func.__code__.co_varnames
                    if len(args_spec) > 1:
                        # There are other parameters besides 'machine'
                        # Prepare parameters
                        kwargs = extra_args if extra_args else {}
                        result = action_func(self, **kwargs)
                        extra_args = {}  # Clear extra_args
                    else:
                        result = action_func(self)

                    # Call next_state_func, may return next state name or (state name, parameter dict)
                    next_state_info = self.state.next_state_func(result, self)
                    if isinstance(next_state_info, tuple):
                        next_state_name = next_state_info[0]
                        extra_args = next_state_info[1] if len(next_state_info) > 1 else {}
                        self.state = self.states.get(next_state_name, ExitState())
                    elif isinstance(next_state_info, str):
                        next_state_name = next_state_info
                        self.state = self.states.get(next_state_name, ExitState())
                        extra_args = {}
                    else:
                        raise ValueError("next_state_func must return a string or a tuple (state_name, args_dict)")
                    previous_result = result  # Update previous_result
            except RuntimeError as e:
                # Check for Claude AI usage limit
                if "Claude AI usage limit reached" in str(e):
                    logging.error(f"\033[91mClaude AI usage limit reached in state '{self.state.name}'\033[0m")
                    # Re-raise to let the caller handle it
                    raise
                else:
                    logging.error(f"\033[91mRuntime error in state '{self.state.name}': {e}\033[0m")
                    import traceback
                    tb_str = ''.join(traceback.format_exception(None, e, e.__traceback__))
                    logging.error(f"\033[90m{tb_str}\033[0m")
                    break
            except Exception as e:
                logging.error(f"\033[91mError in state '{self.state.name}': {e}\033[0m")
                import traceback
                tb_str = ''.join(traceback.format_exception(None, e, e.__traceback__))
                logging.error(f"\033[90m{tb_str}\033[0m")
                break

    def results(self):
        return self.analysis_result

    def get_completion_kwargs(self):
        """Get the kwargs for completion API call"""
        return self.model_manager.get_completion_kwargs()

