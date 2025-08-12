import json
import os

class chatGPTConfig:
    def __init__(self, api_key, model, max_tokens, temperature, top_p, stop_sequences, azure_key, azure_endpoint, use_provider="openai", siliconflow_key=None, siliconflow_base_url=None, siliconflow_model=None):
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.stop_sequences = stop_sequences
        self.azure_key = azure_key
        self.azure_endpoint = azure_endpoint
        self.use_provider = use_provider
        self.siliconflow_key = siliconflow_key
        self.siliconflow_base_url = siliconflow_base_url
        self.siliconflow_model = siliconflow_model

    def __str__(self):
        return f"api_key: {self.api_key}, model: {self.model}, max_tokens: {self.max_tokens}, temperature: {self.temperature}, top_p: {self.top_p}, stop_sequences: {self.stop_sequences}"

    def __repr__(self):
        return f"api_key: {self.api_key}, model: {self.model}, max_tokens: {self.max_tokens}, temperature: {self.temperature}, top_p: {self.top_p}, stop_sequences: {self.stop_sequences}"

    def __eq__(self, other):
        if not isinstance(other, chatGPTConfig):
            return False
        return self.api_key == other.api_key and self.model == other.model and self.max_tokens == other.max_tokens and self.temperature == other.temperature and self.top_p == other.top_p and self.stop_sequences == other.stop_sequences

def load_config(file_path) -> chatGPTConfig:
    log_file_path = os.path.join(os.path.dirname(__file__), file_path)
    # print("[I] Loading ChatGPT configure from", log_file_path)
    with open(log_file_path, 'r') as file:
        config = json.load(file)
    
    default_model = 'gpt-4o'
    default_max_tokens = 8192
    default_temperature = 0.7
    default_top_p = 1.0
    default_stop_sequences = '\n'
    default_provider = 'openai'

    model = config.get('model')
    max_tokens = config.get('max_tokens')
    temperature = config.get('temperature')
    top_p = config.get('top_p')
    stop_sequences = config.get('stop_sequences')
    azure_key = config.get('azure_key')
    azure_endpoint = config.get('azure_endpoint')
    use_provider = config.get('use_provider', default_provider)
    siliconflow_key = config.get('siliconflow_key')
    siliconflow_base_url = config.get('siliconflow_base_url')
    siliconflow_model = config.get('siliconflow_model')

    # if (not model):
    #     print("[W] Model is not specified. Use", default_model, "by default.")
    #     model = default_model
    if (not max_tokens):
        print("[W] Max token length is not specified. Use", default_max_tokens, "by default.")
        max_tokens = default_max_tokens
    if (not temperature):
        print("[W] Temperature is not specified. Using", default_temperature, "by default.")
        temperature = default_temperature
    if (not top_p):
        print("[W] Top_p is not specified. Using", default_top_p, "by default.")
        top_p = default_top_p
    if (not stop_sequences):
        print("[W] Stop sequence char are not specified. Using", repr(default_stop_sequences), "by default.")
        stop_sequences = default_stop_sequences

    config_obj = chatGPTConfig(
        config['api_key'], 
        model, 
        max_tokens, 
        temperature, 
        top_p, 
        stop_sequences, 
        azure_key, 
        azure_endpoint,
        use_provider,
        siliconflow_key,
        siliconflow_base_url,
        siliconflow_model
    )
    return config_obj


if __name__ == "__main__":
    from openai import OpenAI 
    config = load_config('../config/config.json')
    client = OpenAI(api_key=config.api_key)

    print("ChatGPT CLI. Type 'exit' to quit.")
    while True:
        user_input = input("You: ")
        if user_input.lower() == 'exit':
            break
        try:
            completion = client.chat.completions.create(
                model=config.model,
                messages=[
                    {"role": "user", "content": user_input}
                ],
                max_tokens=config.max_tokens,
                temperature=config.temperature,
                top_p=config.top_p,
                stop=config.stop_sequences
            )
            message = completion.choices[0].message.content
            print(f"ChatGPT: {message}")
        except Exception as e:
            print(f"[E]: {e}")
