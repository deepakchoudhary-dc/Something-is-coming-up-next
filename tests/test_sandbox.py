import unittest
from src.sandbox.sandbox_manager import SandboxManager

class TestSandboxSafety(unittest.TestCase):
    def setUp(self):
        self.sandbox = SandboxManager()

    def test_benign_code(self):
        """Verify that harmless calculations and logic can execute successfully"""
        code = """
def calculate_factorial(n):
    if n <= 1:
        return 1
    return n * calculate_factorial(n - 1)

print(calculate_factorial(5))
"""
        res = self.sandbox.execute_code(code)
        self.assertTrue(res["success"], f"Failed benign execution: {res.get('error')}")
        self.assertEqual(res["output"].strip(), "120")

    def test_block_os_import(self):
        """Verify that importing blocked modules is stopped by static AST validation"""
        code = "import os\nos.system('whoami')"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])
        self.assertIn("Blocked by Security Gateway", res["error"])

    def test_block_subprocess_import(self):
        """Verify that importing subprocess is stopped"""
        code = "import subprocess\nsubprocess.run(['echo', 'hello'])"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])
        self.assertIn("Blocked by Security Gateway", res["error"])

    def test_block_dunder_access(self):
        """Verify that accessing double-underscore attributes is blocked"""
        code = "print(().__class__.__mro__[1].__subclasses__())"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])
        self.assertIn("Blocked by Security Gateway", res["error"])

    def test_block_eval_exec(self):
        """Verify that using eval or exec is blocked"""
        code = "eval('1 + 1')"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])
        self.assertIn("Blocked by Security Gateway", res["error"])

        code = "exec('x = 10')"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])
        self.assertIn("Blocked by Security Gateway", res["error"])

    def test_block_open(self):
        """Verify that opening files is blocked"""
        code = "with open('test.txt', 'w') as f:\n    f.write('hello')"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])
        self.assertIn("Blocked by Security Gateway", res["error"])

    def test_block_getattr(self):
        """Verify that using getattr is blocked"""
        code = "getattr(object, '__subclasses__')"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])
        self.assertIn("Blocked by Security Gateway", res["error"])

    def test_runtime_isolation_fallback(self):
        """Verify that if some dynamic call gets past static checking, the runtime wrapper blocks it"""
        # A obfuscated command that might bypass a basic static check if we aren't careful,
        # but will definitely get caught by the custom __import__ override or name checking
        code = "sys = __import__('s' + 'ys')\nprint(sys.modules)"
        res = self.sandbox.execute_code(code)
        self.assertFalse(res["success"])

if __name__ == "__main__":
    unittest.main()
