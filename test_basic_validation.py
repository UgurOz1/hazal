# Basic validation tests

import unittest
from validation import InputValidator, InputSanitizer

class TestBasicValidation(unittest.TestCase):
    """Test basic validation functions"""
    
    def test_email_validation_basic(self):
        """Test basic email validation"""
        # Valid emails
        self.assertTrue(InputValidator.validate_email('test@example.com'))
        self.assertTrue(InputValidator.validate_email('user.name@domain.co.uk'))
        
        # Invalid emails
        self.assertFalse(InputValidator.validate_email('invalid-email'))
        self.assertFalse(InputValidator.validate_email('@domain.com'))
        self.assertFalse(InputValidator.validate_email('test@'))
    
    def test_password_validation_basic(self):
        """Test basic password validation"""
        # Valid passwords
        is_valid, message = InputValidator.validate_password('password123')
        self.assertTrue(is_valid, f"Password should be valid: {message}")
        
        is_valid, message = InputValidator.validate_password('MySecure1')
        self.assertTrue(is_valid, f"Password should be valid: {message}")
        
        # Invalid passwords
        is_valid, message = InputValidator.validate_password('short')
        self.assertFalse(is_valid, "Short password should be invalid")
        
        is_valid, message = InputValidator.validate_password('NoNumbers')
        self.assertFalse(is_valid, "Password without numbers should be invalid")
        
        is_valid, message = InputValidator.validate_password('12345678')
        self.assertFalse(is_valid, "Password without letters should be invalid")
    
    def test_sql_injection_detection_basic(self):
        """Test basic SQL injection detection"""
        # SQL injection attempts
        self.assertTrue(InputSanitizer.detect_sql_injection("'; DROP TABLE users; --"))
        self.assertTrue(InputSanitizer.detect_sql_injection("admin'--"))
        self.assertTrue(InputSanitizer.detect_sql_injection("1; DELETE FROM users"))
        
        # Safe inputs
        self.assertFalse(InputSanitizer.detect_sql_injection("normal text"))
        self.assertFalse(InputSanitizer.detect_sql_injection("user@example.com"))
        self.assertFalse(InputSanitizer.detect_sql_injection("password123"))
    
    def test_xss_detection_basic(self):
        """Test basic XSS detection"""
        # XSS attempts
        self.assertTrue(InputSanitizer.detect_xss("<script>alert('xss')</script>"))
        self.assertTrue(InputSanitizer.detect_xss("javascript:alert('xss')"))
        
        # Safe inputs
        self.assertFalse(InputSanitizer.detect_xss("normal text"))
        self.assertFalse(InputSanitizer.detect_xss("user@example.com"))

if __name__ == '__main__':
    unittest.main(verbosity=2)