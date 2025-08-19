# Test file for middleware validation implementation

import unittest
import json
from unittest.mock import patch, MagicMock
from flask import Flask, request, g
from werkzeug.test import Client
from werkzeug.wrappers import Response

# Import the modules we want to test
from middleware import (
    RequestValidationMiddleware, validate_endpoint_data, get_validated_data,
    validate_path_parameter, DatabaseValidationMiddleware
)
from validation import InputValidator, InputSanitizer, RequestValidator
from security import SQLSecurityManager
from exceptions import ValidationError

class TestInputValidation(unittest.TestCase):
    """Test input validation functions"""
    
    def test_email_validation(self):
        """Test email validation"""
        # Valid emails
        valid_emails = [
            'test@example.com',
            'user.name@domain.co.uk',
            'test123@test-domain.com'
        ]
        
        for email in valid_emails:
            self.assertTrue(InputValidator.validate_email(email), f"Email {email} should be valid")
        
        # Invalid emails
        invalid_emails = [
            'invalid-email',
            '@domain.com',
            'test@',
            'test..test@domain.com',
            'test@domain..com',
            'test@.domain.com'
        ]
        
        for email in invalid_emails:
            self.assertFalse(InputValidator.validate_email(email), f"Email {email} should be invalid")
    
    def test_password_validation(self):
        """Test password validation"""
        # Valid passwords
        valid_passwords = [
            'password123',
            'MySecure1',
            'Test1234'
        ]
        
        for password in valid_passwords:
            is_valid, message = InputValidator.validate_password(password)
            self.assertTrue(is_valid, f"Password {password} should be valid: {message}")
        
        # Invalid passwords
        invalid_passwords = [
            'short',  # Too short
            'nouppercase123',  # No uppercase (actually this should be valid based on requirements)
            'NoNumbers',  # No numbers
            'password',  # No numbers
            '12345678'  # No letters
        ]
        
        for password in invalid_passwords:
            is_valid, message = InputValidator.validate_password(password)
            if password in ['nouppercase123']:  # This should actually be valid
                continue
            self.assertFalse(is_valid, f"Password {password} should be invalid: {message}")
    
    def test_username_validation(self):
        """Test username validation"""
        # Valid usernames
        valid_usernames = [
            'testuser',
            'user123',
            'test_user',
            'User_123'
        ]
        
        for username in valid_usernames:
            is_valid, message = InputValidator.validate_username(username)
            self.assertTrue(is_valid, f"Username {username} should be valid: {message}")
        
        # Invalid usernames
        invalid_usernames = [
            'ab',  # Too short
            'test-user',  # Contains dash
            'test user',  # Contains space
            'admin',  # Reserved
            'test@user'  # Contains @
        ]
        
        for username in invalid_usernames:
            is_valid, message = InputValidator.validate_username(username)
            self.assertFalse(is_valid, f"Username {username} should be invalid: {message}")

class TestInputSanitization(unittest.TestCase):
    """Test input sanitization functions"""
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        # SQL injection attempts
        sql_injections = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM users",
            "UNION SELECT * FROM users"
        ]
        
        for injection in sql_injections:
            self.assertTrue(
                InputSanitizer.detect_sql_injection(injection),
                f"Should detect SQL injection in: {injection}"
            )
        
        # Safe inputs
        safe_inputs = [
            "normal text",
            "user@example.com",
            "password123",
            "John Doe"
        ]
        
        for safe_input in safe_inputs:
            self.assertFalse(
                InputSanitizer.detect_sql_injection(safe_input),
                f"Should not detect SQL injection in: {safe_input}"
            )
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        # XSS attempts
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        for xss in xss_attempts:
            self.assertTrue(
                InputSanitizer.detect_xss(xss),
                f"Should detect XSS in: {xss}"
            )
        
        # Safe inputs
        safe_inputs = [
            "normal text",
            "user@example.com",
            "This is a normal message",
            "HTML is not always XSS"
        ]
        
        for safe_input in safe_inputs:
            self.assertFalse(
                InputSanitizer.detect_xss(safe_input),
                f"Should not detect XSS in: {safe_input}"
            )
    
    def test_string_sanitization(self):
        """Test string sanitization"""
        # Test HTML escaping
        html_input = "<script>alert('test')</script>"
        sanitized = InputSanitizer.sanitize_string(html_input)
        self.assertNotIn("<script>", sanitized)
        self.assertNotIn("</script>", sanitized)
        
        # Test length limiting
        long_input = "a" * 200
        sanitized = InputSanitizer.sanitize_string(long_input, max_length=50)
        self.assertEqual(len(sanitized), 50)

class TestRequestValidation(unittest.TestCase):
    """Test request validation functions"""
    
    def test_user_data_validation(self):
        """Test user data validation"""
        # Valid user data
        valid_data = {
            'username': 'testuser',
            'firstname': 'John',
            'lastname': 'Doe',
            'email': 'john@example.com',
            'password': 'password123',
            'birthdate': '1990-01-01'
        }
        
        try:
            result = RequestValidator.validate_and_sanitize_user_data(valid_data)
            self.assertIsInstance(result, dict)
            self.assertEqual(result['username'], 'testuser')
        except ValidationError:
            self.fail("Valid user data should not raise ValidationError")
        
        # Invalid user data - SQL injection
        invalid_data = {
            'username': "admin'; DROP TABLE users; --",
            'firstname': 'John',
            'lastname': 'Doe',
            'email': 'john@example.com',
            'password': 'password123',
            'birthdate': '1990-01-01'
        }
        
        with self.assertRaises(ValidationError):
            RequestValidator.validate_and_sanitize_user_data(invalid_data)
    
    def test_login_data_validation(self):
        """Test login data validation"""
        # Valid login data
        valid_data = {
            'username': 'testuser',
            'password': 'password123'
        }
        
        try:
            result = RequestValidator.validate_login_data(valid_data)
            self.assertIsInstance(result, dict)
            self.assertEqual(result['username'], 'testuser')
        except ValidationError:
            self.fail("Valid login data should not raise ValidationError")
        
        # Missing username
        invalid_data = {
            'password': 'password123'
        }
        
        with self.assertRaises(ValidationError):
            RequestValidator.validate_login_data(invalid_data)

class TestPathParameterValidation(unittest.TestCase):
    """Test path parameter validation"""
    
    def test_integer_validation(self):
        """Test integer path parameter validation"""
        # Valid integers
        self.assertEqual(validate_path_parameter('id', '123', 'integer'), 123)
        self.assertEqual(validate_path_parameter('id', 456, 'integer'), 456)
        
        # Invalid integers
        with self.assertRaises(ValidationError):
            validate_path_parameter('id', 'abc', 'integer')
        
        with self.assertRaises(ValidationError):
            validate_path_parameter('id', '0', 'integer')  # Must be positive
        
        with self.assertRaises(ValidationError):
            validate_path_parameter('id', '-1', 'integer')  # Must be positive
    
    def test_username_validation(self):
        """Test username path parameter validation"""
        # Valid username
        result = validate_path_parameter('username', 'testuser', 'username')
        self.assertEqual(result, 'testuser')
        
        # Invalid username with SQL injection
        with self.assertRaises(ValidationError):
            validate_path_parameter('username', "admin'; DROP TABLE users; --", 'username')
    
    def test_email_validation(self):
        """Test email path parameter validation"""
        # Valid email
        result = validate_path_parameter('email', 'test@example.com', 'email')
        self.assertEqual(result, 'test@example.com')
        
        # Invalid email
        with self.assertRaises(ValidationError):
            validate_path_parameter('email', 'invalid-email', 'email')

class TestSQLSecurityManager(unittest.TestCase):
    """Test SQL security manager"""
    
    def test_dangerous_sql_detection(self):
        """Test dangerous SQL pattern detection"""
        # Create a mock SQLSecurityManager instance to test private method
        manager = SQLSecurityManager()
        
        # Dangerous queries
        dangerous_queries = [
            "DROP TABLE users",
            "DELETE FROM users WHERE 1=1",
            "SELECT * FROM users; DROP TABLE users;",
            "UNION SELECT password FROM users",
            "'; INSERT INTO users VALUES ('hacker', 'pass'); --"
        ]
        
        for query in dangerous_queries:
            self.assertTrue(
                manager._contains_dangerous_sql(query),
                f"Should detect dangerous SQL in: {query}"
            )
        
        # Safe queries
        safe_queries = [
            "SELECT * FROM users WHERE id = ?",
            "INSERT INTO users (name, email) VALUES (?, ?)",
            "UPDATE users SET name = ? WHERE id = ?"
        ]
        
        for query in safe_queries:
            self.assertFalse(
                manager._contains_dangerous_sql(query),
                f"Should not detect dangerous SQL in: {query}"
            )

class TestMiddlewareIntegration(unittest.TestCase):
    """Test middleware integration"""
    
    def setUp(self):
        """Set up test Flask app"""
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.middleware = RequestValidationMiddleware(self.app)
        
        # Add a test route
        @self.app.route('/test', methods=['POST'])
        @validate_endpoint_data(validation_type='generic', required_fields=['name'])
        def test_route():
            data = get_validated_data()
            return {'success': True, 'data': data}
        
        self.client = self.app.test_client()
    
    def test_valid_request(self):
        """Test valid request processing"""
        with self.app.test_request_context('/test', method='POST', 
                                         json={'name': 'test'},
                                         content_type='application/json'):
            # This should not raise an exception
            try:
                self.middleware.before_request()
            except Exception as e:
                self.fail(f"Valid request should not raise exception: {e}")
    
    def test_invalid_content_type(self):
        """Test invalid content type rejection"""
        with self.app.test_request_context('/test', method='POST', 
                                         data='test data',
                                         content_type='text/plain'):
            with self.assertRaises(ValidationError):
                self.middleware.before_request()
    
    def test_suspicious_json_data(self):
        """Test suspicious JSON data rejection"""
        suspicious_data = {
            'name': "'; DROP TABLE users; --"
        }
        
        with self.app.test_request_context('/test', method='POST', 
                                         json=suspicious_data,
                                         content_type='application/json'):
            with self.assertRaises(ValidationError):
                self.middleware.before_request()

if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)