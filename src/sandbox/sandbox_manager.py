"""
Sandbox Execution Module - Safe execution of AI-generated code snippets using AST validation and isolated runtimes
"""

import logging
import subprocess
import tempfile
import os
import sys
import ast
from typing import Dict, Any, Optional
from ..config.settings import settings

logger = logging.getLogger(__name__)

class ASTSafetyVisitor(ast.NodeVisitor):
    """
    AST Visitor to statically check for malicious code, imports, and dunder attribute accesses
    """
    def __init__(self):
        self.safe = True
        self.issues = []
        
        # Strictly permitted standard modules
        self.allowed_modules = {
            'math', 'datetime', 'time', 'json', 'random', 're', 
            'collections', 'itertools', 'functools', 'string', 'typing'
        }
        
        # Dangerous builtins/functions that are explicitly prohibited
        self.dangerous_builtins = {
            'eval', 'exec', 'open', 'compile', 'globals', 'locals', 
            '__import__', 'dir', 'help', 'input', 'raw_input', 'builtins',
            'getattr', 'setattr', 'delattr'
        }

    def visit_Import(self, node):
        for name in node.names:
            base_module = name.name.split('.')[0]
            if base_module not in self.allowed_modules:
                self.safe = False
                self.issues.append(f"Import of module '{name.name}' is prohibited.")
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module not in self.allowed_modules:
                self.safe = False
                self.issues.append(f"Import from module '{node.module}' is prohibited.")
        self.generic_visit(node)

    def visit_Call(self, node):
        # Prevent direct calls to restricted builtins
        if isinstance(node.func, ast.Name):
            if node.func.id in self.dangerous_builtins:
                self.safe = False
                self.issues.append(f"Call to prohibited builtin '{node.func.id}()' is blocked.")
        self.generic_visit(node)

    def visit_Name(self, node):
        # Prevent access/assignment to dangerous builtins by name reference
        if node.id in self.dangerous_builtins:
            self.safe = False
            self.issues.append(f"Reference to dangerous builtin '{node.id}' is blocked.")
        
        # Prevent system double-underscore names
        if node.id.startswith('__'):
            self.safe = False
            self.issues.append(f"System/dunder variable name '{node.id}' is blocked.")
            
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # Block private or double-underscore attribute lookups/mutations
        if node.attr.startswith('_'):
            self.safe = False
            self.issues.append(f"Access to private/dunder attribute '{node.attr}' is blocked.")
        self.generic_visit(node)


class SandboxManager:
    def __init__(self):
        self.timeout = settings.SANDBOX_TIMEOUT

    def execute_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Execute code in a sandboxed environment after validation
        """
        if not code.strip():
            return {
                "success": False,
                "error": "Code block is empty",
                "output": ""
            }

        if language.lower() != "python":
            return {
                "success": False,
                "error": f"Unsupported execution language: {language}",
                "output": ""
            }

        # Step 1: Pre-validation of safety using AST parsing
        validation = self.validate_code_safety(code)
        if not validation["safe"]:
            logger.warning(f"Code block blocked by safety check: {validation['issues']}")
            return {
                "success": False,
                "error": f"Blocked by Security Gateway. Issues: {', '.join(validation['issues'])}",
                "output": "",
                "safety_details": validation
            }

        # Step 2: Isolated process execution
        return self.execute_in_isolated_process(code)

    def execute_in_isolated_process(self, code: str) -> Dict[str, Any]:
        """
        Execute code in an isolated process with strict time limits using the sandbox wrapper
        """
        sandbox_dir = self.create_sandbox_environment()
        script_path = os.path.join(sandbox_dir, "sandbox_run.py")

        try:
            # Write python script to sandbox folder
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)

            # Get absolute path to the sandbox runtime wrapper
            wrapper_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "sandbox_wrapper.py")
            )

            # Execute code using the wrapper
            result = subprocess.run(
                [sys.executable, wrapper_path, script_path],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=sandbox_dir
            )

            success = result.returncode == 0
            output = result.stdout
            error = result.stderr

            return {
                "success": success,
                "output": output,
                "error": error if error else None
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Sandbox execution timeout: exceeded {self.timeout}s limit")
            return {
                "success": False,
                "error": f"Execution timed out. Execution limit is {self.timeout} seconds.",
                "output": ""
            }
        except Exception as e:
            logger.error(f"Isolated process execution error: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": ""
            }
        finally:
            self.cleanup_sandbox(sandbox_dir)

    def validate_code_safety(self, code: str) -> Dict[str, Any]:
        """
        Validate code for safety before execution using AST parsing
        """
        validation = {
            "safe": True,
            "issues": [],
            "score": 1.0
        }

        # 1. Parse Abstract Syntax Tree statically
        try:
            tree = ast.parse(code)
            visitor = ASTSafetyVisitor()
            visitor.visit(tree)
            
            if not visitor.safe:
                validation["safe"] = False
                validation["issues"].extend(visitor.issues)
                validation["score"] = max(0.0, 1.0 - len(visitor.issues) * 0.15)
                
        except SyntaxError as se:
            validation["safe"] = False
            validation["issues"].append(f"Syntax error during safety check: {se}")
            validation["score"] = 0.0
            return validation
        except Exception as e:
            validation["safe"] = False
            validation["issues"].append(f"AST parsing failed: {e}")
            validation["score"] = 0.0
            return validation

        # 2. Check line count constraints
        lines = len(code.split('\n'))
        if lines > 150:
            validation["score"] -= 0.1
            validation["issues"].append("Script length exceeds allowed gateway limit of 150 lines")
            if lines > 300:
                validation["safe"] = False

        # Ensure safety score is normalized
        validation["score"] = max(0.0, min(1.0, validation["score"]))

        return validation

    def create_sandbox_environment(self) -> str:
        """
        Create a temporary sandbox directory
        """
        sandbox_dir = tempfile.mkdtemp(prefix="ai_sandbox_")
        logger.debug(f"Created sandbox environment directory: {sandbox_dir}")
        return sandbox_dir

    def cleanup_sandbox(self, sandbox_path: str):
        """
        Clean up sandbox environment directory
        """
        if not sandbox_path or not os.path.exists(sandbox_path):
            return

        try:
            import shutil
            shutil.rmtree(sandbox_path)
            logger.debug(f"Cleaned up sandbox: {sandbox_path}")
        except Exception as e:
            logger.error(f"Failed to cleanup sandbox {sandbox_path}: {e}")
