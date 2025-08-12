"""
LLM Response Processing and Tool Functions Module
Contains helper functions for LLM API interactions, response parsing, and formatting
"""

import logging
import json
import re
import requests
from colorama import Fore

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


def reliable_parse(client, request_params, max_retries=3, debug=False, model_info=None):
    """
    Reliably parse LLM completion responses with retry logic.

    :param client: The client to use for parsing (OpenAI client)
    :param request_params: The parameters for the parsing request
    :param max_retries: Maximum number of retries
    :param debug: Enable debug logging
    :param model_info: Optional model information containing additional parameters
    :return: The message content if successful, None otherwise
    """
    # Initialize retry counter
    retries = 0
    
    # Create a copy of request parameters
    merged_params = {**request_params}
    
    # Handle OpenRouter provider
    if model_info and model_info.get('provider') == 'openrouter':
        # Get OpenRouter API key
        openrouter_api_key = model_info.get('openrouter_api_key', None)
        if not openrouter_api_key and 'additional_kwargs' in model_info and 'openrouter_api_key' in model_info['additional_kwargs']:
            openrouter_api_key = model_info['additional_kwargs']['openrouter_api_key']
        
        if not openrouter_api_key:
            raise ValueError("OpenRouter API key not found in model_info")
        
        # Set up extra headers for OpenRouter
        extra_headers = {}
        if 'additional_kwargs' in model_info:
            if 'http_referer' in model_info['additional_kwargs']:
                extra_headers["HTTP-Referer"] = model_info['additional_kwargs']['http_referer']
            if 'x_title' in model_info['additional_kwargs']:
                extra_headers["X-Title"] = model_info['additional_kwargs']['x_title']
        
        # Set up extra body parameters for OpenRouter
        extra_body = {}
        if 'additional_kwargs' in model_info:
            # Add reasoning parameter support
            if 'reasoning' in model_info['additional_kwargs']:
                extra_body['reasoning'] = model_info['additional_kwargs']['reasoning']
                logging.info(Fore.CYAN + f"Using OpenRouter reasoning parameter: {extra_body['reasoning']}")
            
            # Add provider if specified
            if 'provider' in model_info['additional_kwargs']:
                extra_body['provider'] = model_info['additional_kwargs']['provider']
            
            # Add models array if specified
            if 'models' in model_info['additional_kwargs']:
                extra_body['models'] = model_info['additional_kwargs']['models']
            
            # Add any other OpenRouter-specific parameters
            for param in ['routes', 'transforms', 'stream_options']:
                if param in model_info['additional_kwargs']:
                    extra_body[param] = model_info['additional_kwargs'][param]
        
        # Add extra parameters to merged_params
        if extra_headers:
            merged_params['extra_headers'] = extra_headers
        if extra_body:
            merged_params['extra_body'] = extra_body
        
        # Use the client directly with OpenRouter base URL
        while retries < max_retries:
            try:
                if debug:
                    logging.info(Fore.BLUE + f"OpenRouter request params: {json.dumps(merged_params, default=str, ensure_ascii=False)}")
                
                # Use the OpenAI client to make the request
                response = client.beta.chat.completions.parse(**merged_params)
                
                # Check if we have a valid message content
                if not response.choices or not response.choices[0].message.content:
                    logging.info(Fore.YELLOW + "Message content is empty, resending request...")
                    retries += 1
                    continue
                
                return response
                
            except Exception as e:
                logging.error(Fore.RED + f"OpenRouter request exception: {str(e)}")
                retries += 1
        
        logging.error(Fore.RED + "Unable to get a valid OpenRouter response after maximum retries.")
        return None
    
    # Other providers use standard OpenAI client
    else:
        while retries < max_retries:            
            response = client.beta.chat.completions.parse(**request_params)
            message = response.choices[0].message

            if message.content:
                return response
            else:
                logging.info(Fore.YELLOW + "The message content is null or empty, re-running the request...")
                retries += 1

        logging.error(Fore.RED + "Failed to get a valid response after maximum retries.")
        return None


def safe_format(template_str, **kwargs):
    """
    Safely format a string, preserving original placeholders if parameters are missing
    """
    class SafeDict(dict):
        def __missing__(self, key):
            return '{' + key + '}'
    
    try:
        return template_str.format_map(SafeDict(kwargs))
    except Exception:
        return template_str


def extract_code_snippets(prompt):
    """Extract all code snippets from the prompt"""
    pass


def parse_and_validate_json_response(message, machine, debug=False):
    """Process and validate JSON responses, automatically fixing format issues"""
    pass 