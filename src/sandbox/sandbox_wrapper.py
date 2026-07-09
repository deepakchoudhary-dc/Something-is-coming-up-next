"""
Restricted Python Execution Wrapper for AI Security Gateway
Executes target script in a highly restricted globals/builtins scope
"""

import sys
import importlib
import os
import traceback


class CappedTextWriter:
    def __init__(self, wrapped, limit: int):
        self._wrapped = wrapped
        self._limit = max(0, limit)
        self._written = 0
        self._truncated = False

    def write(self, text):
        if not isinstance(text, str):
            text = str(text)
        remaining = self._limit - self._written
        if remaining <= 0:
            self._write_truncation_notice()
            return len(text)
        chunk = text[:remaining]
        self._wrapped.write(chunk)
        self._written += len(chunk)
        if len(text) > remaining:
            self._write_truncation_notice()
        return len(text)

    def flush(self):
        return self._wrapped.flush()

    def _write_truncation_notice(self):
        if not self._truncated:
            self._wrapped.write("\n[TRUNCATED: sandbox output limit exceeded]\n")
            self._truncated = True

def run_safe(code_path: str):
    with open(code_path, "r", encoding="utf-8") as f:
        code = f.read()

    max_output = int(os.environ.get("SANDBOX_MAX_OUTPUT_CHARS", "20000"))
    sys.stdout = CappedTextWriter(sys.stdout, max_output)
    sys.stderr = CappedTextWriter(sys.stderr, max_output)

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
