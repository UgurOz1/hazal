# Unit tests for database models
# Requirements: 4.5, 6.3

import unittest
from datetime import datetime, date, timedelta
import hashlib
import secrets
from unittest.mock import patch, MagicMock

# Import Flask and SQLAlchemy for testing
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Import models and related modules
from models import db, User, OnlineUser, UserLog
from exceptions import ValidationError


class TestUserModel(unittest.TestCase):
    """Test cases for User model validation and functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        
        db.init_app(self.app)
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_user_creation_valid_data(self):
        """Test creating user with valid data - Requirement 4.5"""
        with self.app.app_context():
            user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            
            self.assertEqual(user.username, 'testuser')
            self.assertEqual(user.firstname, 'John')
            self.assertEqual(user.lastname, 'Doe')
            self.assertEqual(user.email, 'john.doe@example.com')
            self.assertIsNotNone(user.password_hash)
            self.assertIsNotNone(user.salt)
            self.assertTrue(user.verify_password('password123'))
    
    def test_user_password_hashing(self):
        """Test password hashing functionality - Requirement 4.5"""
        with self.app.app_context():
            user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            
            # Test that password is hashed
            self.assertNotEqual(user.password_hash, 'password123')
            self.assertEqual(len(user.password_hash), 64)  # SHA256 hex length
            self.assertEqual(len(user.salt), 32)  # 16 bytes hex = 32 chars
            
            # Test password verification
            self.assertTrue(user.verify_password('password123'))
            self.assertFalse(user.verify_password('wrongpassword'))
    
    def test_password_validation_requirements(self):
        """Test password validation requirements - Requirement 4.5, 6.3"""
        with self.app.app_context():
            # Test minimum length requirement
            with self.assertRaises(ValueError) as context:
                User(
                    username='testuser',
                    firstname='John',
                    lastname='Doe',
                    birthdate=date(1990, 1, 1),
                    email='john.doe@example.com',
                    password='short'  # Less than 8 characters
                )
            self.assertIn("Password does not meet requirements", str(context.exception))
            
            # Test letter requirement
            with self.assertRaises(ValueError):
                User(
                    username='testuser',
                    firstname='John',
                    lastname='Doe',
                    birthdate=date(1990, 1, 1),
                    email='john.doe@example.com',
                    password='12345678'  # Only numbers
                )
            
            # Test number requirement
            with self.assertRaises(ValueError):
                User(
                    username='testuser',
                    firstname='John',
                    lastname='Doe',
                    birthdate=date(1990, 1, 1),
                    email='john.doe@example.com',
                    password='abcdefgh'  # Only letters
                )
    
    def test_email_validation(self):
        """Test email validation - Requirement 4.5"""
        with self.app.app_context():
            # Test invalid email format
            with self.assertRaises(ValueError) as context:
                User(
                    username='testuser',
                    firstname='John',
                    lastname='Doe',
                    birthdate=date(1990, 1, 1),
                    email='invalid-email',
                    password='password123'
                )
            self.assertIn("Invalid email format", str(context.exception))
            
            # Test valid email formats
            valid_emails = [
                'test@example.com',
                'user.name@domain.co.uk',
                'user+tag@example.org'
            ]
            
            for email in valid_emails:
                user = User(
                    username=f'user_{email.split("@")[0]}',
                    firstname='John',
                    lastname='Doe',
                    birthdate=date(1990, 1, 1),
                    email=email,
                    password='password123'
                )
                self.assertEqual(user.email, email)
    
    def test_static_password_validation(self):
        """Test static password validation method"""
        # Valid passwords
        self.assertTrue(User.validate_password('password123'))
        self.assertTrue(User.validate_password('abc12345'))
        self.assertTrue(User.validate_password('Test1234'))
        
        # Invalid passwords
        self.assertFalse(User.validate_password('short'))  # Too short
        self.assertFalse(User.validate_password('12345678'))  # No letters
        self.assertFalse(User.validate_password('abcdefgh'))  # No numbers
        self.assertFalse(User.validate_password(''))  # Empty
    
    def test_static_email_validation(self):
        """Test static email validation method"""
        # Valid emails
        self.assertTrue(User.validate_email('test@example.com'))
        self.assertTrue(User.validate_email('user.name@domain.co.uk'))
        self.assertTrue(User.validate_email('user+tag@example.org'))
        
        # Invalid emails
        self.assertFalse(User.validate_email('invalid-email'))
        self.assertFalse(User.validate_email('test@'))
        self.assertFalse(User.validate_email('@example.com'))
        self.assertFalse(User.validate_email('test..test@example.com'))
        self.assertFalse(User.validate_email(''))
    
    def test_user_to_dict(self):
        """Test user serialization to dictionary"""
        with self.app.app_context():
            user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            
            # Test without sensitive data
            user_dict = user.to_dict()
            expected_keys = {'id', 'username', 'firstname', 'lastname', 'birthdate', 'email', 'created_at'}
            self.assertEqual(set(user_dict.keys()), expected_keys)
            self.assertNotIn('password_hash', user_dict)
            self.assertNotIn('salt', user_dict)
            
            # Test with sensitive data
            user_dict_sensitive = user.to_dict(include_sensitive=True)
            self.assertIn('password_hash', user_dict_sensitive)
            self.assertIn('salt', user_dict_sensitive)
    
    @patch('models.User.query')
    def test_email_uniqueness_validation(self, mock_query):
        """Test email uniqueness validation methods"""
        with self.app.app_context():
            # Mock existing user
            existing_user = MagicMock()
            existing_user.id = 1
            existing_user.email = 'existing@example.com'
            
            # Test email uniqueness for creation
            mock_query.filter_by.return_value.first.return_value = existing_user
            is_valid, message = User.validate_email_for_creation('existing@example.com')
            self.assertFalse(is_valid)
            self.assertEqual(message, "Email already exists")
            
            # Test email uniqueness for creation with new email
            mock_query.filter_by.return_value.first.return_value = None
            is_valid, message = User.validate_email_for_creation('new@example.com')
            self.assertTrue(is_valid)
            self.assertEqual(message, "Email is valid")


class TestOnlineUserModel(unittest.TestCase):
    """Test cases for OnlineUser model"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        
        db.init_app(self.app)
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_online_user_creation(self):
        """Test creating online user record"""
        with self.app.app_context():
            online_user = OnlineUser(
                username='testuser',
                ip_address='192.168.1.1',
                user_id=1
            )
            
            self.assertEqual(online_user.username, 'testuser')
            self.assertEqual(online_user.ip_address, '192.168.1.1')
            self.assertEqual(online_user.user_id, 1)
            self.assertIsNotNone(online_user.login_datetime)
    
    def test_online_user_custom_datetime(self):
        """Test creating online user with custom datetime"""
        with self.app.app_context():
            custom_time = datetime(2023, 1, 1, 12, 0, 0)
            online_user = OnlineUser(
                username='testuser',
                ip_address='192.168.1.1',
                user_id=1,
                login_datetime=custom_time
            )
            
            self.assertEqual(online_user.login_datetime, custom_time)
    
    def test_ip_address_validation(self):
        """Test IP address validation"""
        # Valid IPv4 addresses
        valid_ipv4 = ['192.168.1.1', '10.0.0.1', '127.0.0.1', '255.255.255.255']
        for ip in valid_ipv4:
            self.assertTrue(OnlineUser.validate_ip_address(ip))
        
        # Valid IPv6 addresses
        valid_ipv6 = ['::1', '2001:0db8:85a3:0000:0000:8a2e:0370:7334']
        for ip in valid_ipv6:
            self.assertTrue(OnlineUser.validate_ip_address(ip))
        
        # Invalid IP addresses
        invalid_ips = ['invalid', '256.256.256.256', '192.168.1', '']
        for ip in invalid_ips:
            self.assertFalse(OnlineUser.validate_ip_address(ip))
    
    def test_online_user_to_dict(self):
        """Test online user serialization"""
        with self.app.app_context():
            online_user = OnlineUser(
                username='testuser',
                ip_address='192.168.1.1',
                user_id=1
            )
            
            user_dict = online_user.to_dict()
            expected_keys = {'id', 'username', 'ip_address', 'login_datetime', 'user_id'}
            self.assertEqual(set(user_dict.keys()), expected_keys)


class TestUserLogModel(unittest.TestCase):
    """Test cases for UserLog model"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        
        db.init_app(self.app)
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_user_log_creation_valid_action(self):
        """Test creating user log with valid action"""
        with self.app.app_context():
            log_entry = UserLog(
                username='testuser',
                action='login',
                ip_address='192.168.1.1',
                user_id=1
            )
            
            self.assertEqual(log_entry.username, 'testuser')
            self.assertEqual(log_entry.action, 'login')
            self.assertEqual(log_entry.ip_address, '192.168.1.1')
            self.assertEqual(log_entry.user_id, 1)
            self.assertIsNotNone(log_entry.timestamp)
    
    def test_user_log_invalid_action(self):
        """Test creating user log with invalid action"""
        with self.app.app_context():
            with self.assertRaises(ValueError) as context:
                UserLog(
                    username='testuser',
                    action='invalid_action',
                    ip_address='192.168.1.1',
                    user_id=1
                )
            self.assertIn("Invalid action", str(context.exception))
    
    def test_action_validation(self):
        """Test action validation method"""
        # Valid actions
        self.assertTrue(UserLog.validate_action('login'))
        self.assertTrue(UserLog.validate_action('logout'))
        
        # Invalid actions
        self.assertFalse(UserLog.validate_action('invalid'))
        self.assertFalse(UserLog.validate_action(''))
        self.assertFalse(UserLog.validate_action('LOGIN'))  # Case sensitive
    
    def test_user_log_to_dict(self):
        """Test user log serialization"""
        with self.app.app_context():
            log_entry = UserLog(
                username='testuser',
                action='login',
                ip_address='192.168.1.1',
                user_id=1
            )
            
            log_dict = log_entry.to_dict()
            expected_keys = {'id', 'username', 'action', 'ip_address', 'timestamp', 'user_id'}
            self.assertEqual(set(log_dict.keys()), expected_keys)


class TestModelRelationships(unittest.TestCase):
    """Test model relationships and cascading operations"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        
        db.init_app(self.app)
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_user_online_sessions_relationship(self):
        """Test User to OnlineUser relationship"""
        with self.app.app_context():
            # Create user
            user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            db.session.add(user)
            db.session.commit()
            
            # Create online session
            online_user = OnlineUser(
                username='testuser',
                ip_address='192.168.1.1',
                user_id=user.id
            )
            db.session.add(online_user)
            db.session.commit()
            
            # Test relationship
            self.assertEqual(len(user.online_sessions), 1)
            self.assertEqual(user.online_sessions[0].username, 'testuser')
            self.assertEqual(online_user.user, user)
    
    def test_user_logs_relationship(self):
        """Test User to UserLog relationship"""
        with self.app.app_context():
            # Create user
            user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            db.session.add(user)
            db.session.commit()
            
            # Create log entries
            log1 = UserLog(
                username='testuser',
                action='login',
                ip_address='192.168.1.1',
                user_id=user.id
            )
            log2 = UserLog(
                username='testuser',
                action='logout',
                ip_address='192.168.1.1',
                user_id=user.id
            )
            db.session.add_all([log1, log2])
            db.session.commit()
            
            # Test relationship
            self.assertEqual(len(user.logs), 2)
            self.assertEqual(log1.user, user)
            self.assertEqual(log2.user, user)
    
    def test_cascade_delete_operations(self):
        """Test cascade delete operations"""
        with self.app.app_context():
            # Create user with related records
            user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            db.session.add(user)
            db.session.commit()
            
            # Create related records
            online_user = OnlineUser(
                username='testuser',
                ip_address='192.168.1.1',
                user_id=user.id
            )
            log_entry = UserLog(
                username='testuser',
                action='login',
                ip_address='192.168.1.1',
                user_id=user.id
            )
            db.session.add_all([online_user, log_entry])
            db.session.commit()
            
            # Verify records exist
            self.assertEqual(OnlineUser.query.count(), 1)
            self.assertEqual(UserLog.query.count(), 1)
            
            # Delete user
            db.session.delete(user)
            db.session.commit()
            
            # Verify cascade delete worked
            self.assertEqual(OnlineUser.query.count(), 0)
            self.assertEqual(UserLog.query.count(), 0)


if __name__ == '__main__':
    unittest.main()