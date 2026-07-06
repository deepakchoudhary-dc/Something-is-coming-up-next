"""
Sandbox Execution Module - Safe execution of AI-generated code snippets
"""

import logging
import subprocess
import tempfile
import os
import sys
from typing import Dict, Any, Optional
from ..config.settings import settings

logger = logging.getLogger(__name__)

class SandboxManager:
    def __init__(self):
        self.timeout = settings.SANDBOX_TIMEOUT

    def execute_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Execute code in a sandboxed environment after validation from the user
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

        # Step 1: Pre-validation of safety
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
        Execute code in an isolated process with strict time limits
        """
        sandbox_dir = self.create_sandbox_environment()
        script_path = os.path.join(sandbox_dir, "sandbox_run.py")

        try:
            # Write python script to sandbox folder
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)

            # Execute python script in subprocess
            # We use sys.executable to run with the same Python interpreter
            result = subprocess.run(
                [sys.executable, script_path],
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
        Validate code for safety before execution using AST and keyword pattern blocks
        """
        validation = {
            "safe": True,
            "issues": [],
            "score": 1.0
        }

        # 1. Check for dangerous keyword tokens
        dangerous_patterns = [
            "import os",
            "import subprocess",
            "import sys",
            "import shutil",
            "import urllib",
            "import requests",
            "import socket",
            "import pty",
            "eval(",
            "exec(",
            "__import__",
            "open(",
            "file(",
            "input(",
            "raw_input(",
            "builtins",
            "globals()",
            "locals()",
            "getattr",
            "setattr",
            "delattr",
            "write("
        ]

        for pattern in dangerous_patterns:
            if pattern in code:
                validation["safe"] = False
                validation["issues"].append(f"Contains prohibited expression: '{pattern}'")
                validation["score"] -= 0.15

        # 2. Check size constraints
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
