import os
import json
from typing import Dict, Any
from openai import OpenAI, AzureOpenAI

class ModelManager:
    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.model_config = self._load_model_config()
        self.config = self._load_main_config()
        
    def _load_model_config(self) -> Dict[str, Any]:
        model_config_path = os.path.join(self.config_dir, 'model_config.json')
        with open(model_config_path, 'r') as f:
            return json.load(f)
            
    def _load_main_config(self) -> Dict[str, Any]:
        config_path = os.path.join(self.config_dir, 'config.json')
        with open(config_path, 'r') as f:
            return json.load(f)
            
    def get_available_models(self):
        """Return list of available models with their descriptions"""
        return {
            model_id: {
                "description": info["description"],
                "provider": info["provider"]
            }
            for model_id, info in self.model_config["models"].items()
        }
        
    def initialize_client(self):
        """Initialize and return a list of all model clients based on model_config."""
        clients = []
        for model_id, model_info in self.model_config['models'].items():
            provider = model_info['provider']
            provider_config = self.model_config['provider_configs'][provider]

            # Verify required credentials are present
            for required_key in provider_config.get('requires', []):
                if not self.config.get(required_key):
                    raise ValueError(f"Missing required credential: {required_key}")

            # Add 'name' to model_info for easy access
            model_info['name'] = model_id

            # Initialize appropriate client
            if provider == 'azure':
                client = AzureOpenAI(
                    api_key=self.config['azure_key'],
                    api_version=model_info['api_version'],
                    azure_endpoint=self.config['azure_endpoint']
                )
            elif provider == 'siliconflow':
                client = OpenAI(
                    api_key=self.config['siliconflow_key'],
                    base_url=provider_config['base_url']
                )
            elif provider == 'azure-deepseek':
                client = AzureOpenAI(
                    api_key=self.config['ds_azure_key'],
                    api_version=model_info['api_version'],
                    azure_endpoint=self.config['ds_azure_endpoint']
                )
            elif provider == 'openrouter':
                # OpenRouter integration with API version
                client = OpenAI(
                    api_key=self.config['openrouter_api_key'],
                    base_url='https://openrouter.ai/api/v1'
                )
                # Only add API key to model_info, without site information
                model_info['openrouter_api_key'] = self.config['openrouter_api_key']
                
            else:  # openai
                client = OpenAI(
                    api_key=self.config['api_key'],
                    base_url=provider_config.get('base_url')
                )
            
            # Store completion kwargs in model_info
            model_info = self.get_completion_kwargs(model_info)

            clients.append((client, model_info))

        return clients
        
    def get_completion_kwargs(self, model_info):
        """Get kwargs for completion API call based on selected model"""

        provider = model_info.get("provider")
        
        kwargs = {
            "model": model_info["model_name"],
            "max_tokens": model_info["max_tokens"],
            "temperature": self.config["temperature"],
            "top_p": self.config["top_p"],
            "stop": self.config["stop_sequences"]
        }
        
        # Handle provider-specific parameters
        if provider == "azure":
            if "deployment_name" in model_info:
                kwargs["deployment_id"] = model_info["deployment_name"]
                # For Azure, deployment_id is used instead of model
                del kwargs["model"]
        elif provider == "azure-deepseek":
            if "deployment_name" in model_info:
                kwargs["deployment_id"] = model_info["deployment_name"]
                del kwargs["model"]
        elif provider == "openrouter":
            # Add OpenRouter-specific parameters
            # Set up headers with minimum required information
            
            # Handle OpenRouter's API version if specified
            if "api_version" in model_info:
                kwargs["openrouter_version"] = model_info["api_version"]
            
            # Add OpenRouter provider routing parameters if specified
            if "openrouter_provider" in model_info:
                # Add provider preferences to request
                routing_params = {}
                provider_config = model_info["openrouter_provider"]
                
                # Map provider preferences to OpenRouter parameters
                if "order" in provider_config:
                    routing_params["order"] = provider_config["order"]
                
                if "allow_fallbacks" in provider_config:
                    routing_params["allow_fallbacks"] = provider_config["allow_fallbacks"]
                    
                if "sort" in provider_config:
                    routing_params["sort"] = provider_config["sort"]
                    
                if "ignore" in provider_config:
                    routing_params["skip"] = provider_config["ignore"]
                    
                if "require_parameters" in provider_config:
                    routing_params["filterParams"] = provider_config["require_parameters"]
                    
                if "data_collection" in provider_config:
                    routing_params["data_collection"] = provider_config["data_collection"]
                
                if "quantizations" in provider_config:
                    routing_params["quantizations"] = provider_config["quantizations"]
                
                # Add provider parameters directly to the request body
                if routing_params:
                    kwargs["provider"] = routing_params
            
            # Add OpenRouter reasoning parameter support
            if "reasoning" in model_info:
                # Store reasoning as a separate parameter, not nested in kwargs
                # This way it can be used directly in reliable_parse
                kwargs["reasoning"] = model_info["reasoning"]
        
        # Store the kwargs in model_info's additional_kwargs parameter instead of returning them
        model_info["additional_kwargs"] = kwargs
        return model_info 