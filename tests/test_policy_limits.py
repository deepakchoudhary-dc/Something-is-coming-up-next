import unittest
from datetime import datetime, timedelta
from src.policy.policy_manager import PolicyManager
from src.monitoring.database import SessionLocal, SecurityLog, init_db

# Ensure schema is up-to-date
init_db()

class TestPolicyLimits(unittest.TestCase):
    def setUp(self):
        self.pm = PolicyManager()
        self.session = SessionLocal()
        # Cleanup test logs
        self.session.query(SecurityLog).filter(SecurityLog.user_id.like("test_%")).delete()
        self.session.commit()

        # Reset default policy settings for testing
        self.original_policies = self.pm.get_policies()
        
        # Save test-specific policies
        test_policies = self.pm.get_policies()
        test_policies["rate_limiting"]["rules"]["requests_per_minute"] = 3
        test_policies["rate_limiting"]["rules"]["requests_per_hour"] = 5
        test_policies["rate_limiting"]["enabled"] = True
        
        test_policies["user_access"]["rules"]["roles"]["guest"]["max_requests"] = 2
        test_policies["user_access"]["rules"]["roles"]["guest"]["restricted_models"] = True
        test_policies["user_access"]["enabled"] = True
        
        self.pm.update_policies(test_policies)

    def tearDown(self):
        # Restore original policies
        self.pm.update_policies(self.original_policies)
        # Cleanup test logs
        self.session.query(SecurityLog).filter(SecurityLog.user_id.like("test_%")).delete()
        self.session.commit()
        self.session.close()

    def test_rate_limiting_rpm(self):
        user_id = "test_user_rpm"
        
        # Under limit (0 requests)
        res = self.pm.check_rate_limit(user_id)
        self.assertTrue(res["allowed"])

        # Write 3 allowed requests
        for _ in range(3):
            log = SecurityLog(
                user_id=user_id,
                prompt="test prompt",
                response="test response",
                action_taken="allowed",
                timestamp=datetime.utcnow()
            )
            self.session.add(log)
        self.session.commit()

        # Exceeds limit (4th request should block)
        res = self.pm.check_rate_limit(user_id)
        self.assertFalse(res["allowed"])
        self.assertIn("Rate limit exceeded", res["reason"])

        # Blocked requests should NOT count towards rate limit (anti-lockout filter check)
        blocked_log = SecurityLog(
            user_id=user_id,
            prompt="test prompt",
            response="test response",
            action_taken="blocked_rate_limit",
            timestamp=datetime.utcnow()
        )
        self.session.add(blocked_log)
        self.session.commit()

        # Count should still be 3 (non-blocked)
        # The block should still stand
        res = self.pm.check_rate_limit(user_id)
        self.assertFalse(res["allowed"])

    def test_user_access_guest_quota(self):
        guest_id = "test_guest_user"
        
        # Under daily limit (0 requests)
        res = self.pm.check_user_access(guest_id, "gpt-3.5-turbo")
        self.assertTrue(res["allowed"])

        # Write 2 requests
        for _ in range(2):
            log = SecurityLog(
                user_id=guest_id,
                prompt="test prompt",
                response="test response",
                action_taken="allowed",
                timestamp=datetime.utcnow()
            )
            self.session.add(log)
        self.session.commit()

        # 3rd request should exceed daily quota of 2
        res = self.pm.check_user_access(guest_id, "gpt-3.5-turbo")
        self.assertFalse(res["allowed"])
        self.assertIn("quota exceeded", res["reason"].lower())

    def test_user_access_guest_model_restriction(self):
        guest_id = "test_guest_user"
        
        # Allowed model
        res = self.pm.check_user_access(guest_id, "gpt-3.5-turbo")
        self.assertTrue(res["allowed"])

        # Premium/Restricted models should block
        restricted_models = ["gpt-4", "gpt-4-turbo", "claude-3-opus", "gemini-1.5-pro"]
        for model in restricted_models:
            res = self.pm.check_user_access(guest_id, model)
            self.assertFalse(res["allowed"])
            self.assertIn("restricted", res["reason"].lower())

    def test_admin_bypass(self):
        admin_id = "test_admin_user"
        
        # Set rate limits and access rules extremely restrictive
        # Write many logs
        for _ in range(10):
            log = SecurityLog(
                user_id=admin_id,
                prompt="test prompt",
                response="test response",
                action_taken="allowed",
                timestamp=datetime.utcnow()
            )
            self.session.add(log)
        self.session.commit()

        # Admin rate check should pass
        res_rate = self.pm.check_rate_limit(admin_id)
        self.assertTrue(res_rate["allowed"])

        # Admin access check with premium model should pass
        res_access = self.pm.check_user_access(admin_id, "gpt-4")
        self.assertTrue(res_access["allowed"])

if __name__ == "__main__":
    unittest.main()
