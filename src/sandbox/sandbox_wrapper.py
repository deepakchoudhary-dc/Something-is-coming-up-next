"""
Restricted Python Execution Wrapper for AI Security Gateway
Executes target script in a highly restricted globals/builtins scope
"""

import sys
import importlib
import traceback

def run_safe(code_path: str):
    with open(code_path, "r", encoding="utf-8") as f:
        code = f.read()

    # Allowed standard modules list
    ALLOWED_MODULES = {
        'math', 'datetime', 'time', 'json', 'random', 're', 
        'collections', 'itertools', 'functools', 'string', 'typing'
    }

    # Custom __import__ function to block restricted modules
    def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        # Extract base module name (e.g., 'collections' from 'collections.abc')
        base_module = name.split('.')[0]
        if base_module in ALLOWED_MODULES:
            return importlib.__import__(name, globals, locals, fromlist, level)
        raise ImportError(f"Import of module '{name}' is blocked by sandbox policy.")

    # List of safe builtins to allow inside execution
    safe_builtins = {
        'print': print,
        'range': range,
        'len': len,
        'abs': abs,
        'min': min,
        'max': max,
        'sum': sum,
        'any': any,
        'all': all,
        'enumerate': enumerate,
        'zip': zip,
        'map': map,
        'filter': filter,
        'list': list,
        'dict': dict,
        'set': set,
        'tuple': tuple,
        'str': str,
        'int': int,
        'float': float,
        'bool': bool,
        'round': round,
        'divmod': divmod,
        'pow': pow,
        'repr': repr,
        'sorted': sorted,
        'reversed': reversed,
        'isinstance': isinstance,
        'issubclass': issubclass,
        'type': type,
        'Exception': Exception,
        'ValueError': ValueError,
        'TypeError': TypeError,
        'KeyError': KeyError,
        'IndexError': IndexError,
        'AttributeError': AttributeError,
        'NameError': NameError,
        'ImportError': ImportError,
        'RuntimeError': RuntimeError,
        'ZeroDivisionError': ZeroDivisionError,
        'StopIteration': StopIteration,
        'AssertionError': AssertionError,
        '__import__': safe_import,
    }

    # Define clean globals dictionary
    safe_globals = {
        '__builtins__': safe_builtins,
        '__name__': '__main__',
        '__doc__': None,
        '__package__': None,
    }

    # Compile the code to catch syntax errors cleanly before execution
    compiled_code = compile(code, code_path, "exec")

    # Execute the code in the restricted environment
    exec(compiled_code, safe_globals)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sandbox_wrapper.py <script_to_run>", file=sys.stderr)
        sys.exit(1)

    try:
        run_safe(sys.argv[1])
    except Exception as e:
        # Get traceback information
        exc_type, exc_value, tb = sys.exc_info()
        # Skip the first frame (which points to run_safe inside this wrapper)
        if tb and tb.tb_next:
            tb = tb.tb_next
        
        # Output clean traceback to stderr
        traceback.print_exception(exc_type, exc_value, tb, file=sys.stderr)
        sys.exit(1)
