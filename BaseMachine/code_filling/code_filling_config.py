from BaseMachine.code_filling.code_filling_tools import query_symbol_definition
from BaseMachine.action_utils import create_chat_action

# Control whether to guess the code definition or simply return "missing" message
# Set to True to enable guessing, False to return missing definition message
DEF_GUESS = False

def initialize_system_prompt_action(machine) -> None:
    machine.messages = [
        {
            "role": "system",
            "content": f'You are an expert in code search.',
        }
    ]
    symbol = machine.context.name
    machine.search_results = query_symbol_definition(symbol)
    machine.code_snippet = machine.context.context_code
    return None

def guess_the_code_action(machine):
    machine.definition = create_chat_action(
        prompt_template='''
        You have to guess the code function definition with its possiable implementation of the function {name} based on the following code snippet:
        {code_snippet}
        '''
    )(
        machine, 
        name=machine.context.name, 
        code_snippet=machine.code_snippet
    )
    
    return None

def return_missing_definition_action(machine):
    # Simply set the definition to indicate it's missing
    machine.definition = f"ERROR!:{machine.context.name} definition missing because of the function definition tools is broken when search for the symbol name {machine.context.name} definitions."
    return None

def use_single_result_action(machine):
    """
    Directly use the single search result without LLM selection.
    """
    if len(machine.search_results) == 1:
        machine.definition = machine.search_results[0]
    else:
        # This should not happen if state transitions are correct
        machine.definition = f"ERROR!: Expected single result but got {len(machine.search_results)} results."
    return None

def choose_most_related_result_action(machine):
    machine.definition = create_chat_action(
        prompt_template='''
        Below are some definitions return by openGrok code search platform when I search for the symbol name {name} definitions. 
        The use of this symbol is in the following code snippet:
        {code_snippet}
        
        Please choose the most related one based on the provided symbol using context, and return the full definition of the chosen one.
        the search results are as follows, stored in an array:
        {search_results}
        ''',
        save_option='both' 
    )(
        machine, 
        name=machine.context.name, 
        code_snippet=machine.code_snippet,
        search_results=machine.search_results
    )
    # print(machine.definition)
    return None

def exit_action(machine):
    return None


# 1. init the system prompt (input is a symbol and context)
# 2. choose the most related result (only if more than 1 result)
# 3. use single result directly if only 1 result
state_definitions = {
    'InitializeSystemPrompt': {
        'action': initialize_system_prompt_action,
        'next_state_func': lambda result, machine: (
            'SelectAndChooseMostRelatedResult' if len(machine.search_results) > 1 
            else 'UseSingleResult' if len(machine.search_results) == 1 
            else ('GuessTheCode' if DEF_GUESS else 'ReturnMissingDefinition')
        ),
    },
    'UseSingleResult': {
        'action': use_single_result_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'SelectAndChooseMostRelatedResult': {
        'action': choose_most_related_result_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'GuessTheCode': {
        'action': guess_the_code_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'ReturnMissingDefinition': {
        'action': return_missing_definition_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}