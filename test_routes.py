# Unit tests for API routes
# Requirements: 1.1, 1.2, 2.1, 3.1, 4.1, 5.1, 6.1, 7.1

import unittest
import json
from datetime import datetime, date
from unittest.mock import patch, MagicMock

# Import Flask and testing utilities
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Import application modules
from models import db, User, OnlineUser, UserLog
from routes import api
from exceptions import ValidationError, AuthenticationError, ResourceNotFoundError, ConflictError


class TestAuthenticationRoutes(unittest.TestCase):
    """Test cases for authentication endpoints"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        
        db.init_app(self.app)
        self.app.register_blueprint(api)
        
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
            
            # Create test user
            self.test_user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            db.session.add(self.test_user)
            db.session.commit()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_login_success(self):
        """Test successful login - Requirement 1.1"""
        with self.app.app_context():
            response = self.client.post('/login', 
                json={
                    'username': 'testuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data['success'])
            self.assertEqual(data['message'], 'Login successful')
            self.assertIn('user_id', data)
            
            # Verify user is added to online users
            online_user = OnlineUser.query.filter_by(username='testuser').first()
            self.assertIsNotNone(online_user)
            
            # Verify login is logged
            log_entry = UserLog.query.filter_by(username='testuser', action='login').first()
            self.assertIsNotNone(log_entry)
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials - Requirement 1.2"""
        with self.app.app_context():
            response = self.client.post('/login',
                json={
                    'username': 'testuser',
                    'password': 'wrongpassword'
                },
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 401)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
            self.assertIn('Invalid credentials', data['error']['message'])
    
    def test_login_missing_username(self):
        """Test login with missing username"""
        with self.app.app_context():
            response = self.client.post('/login',
                json={
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 400)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
    
    def test_login_missing_password(self):
        """Test login with missing password"""
        with self.app.app_context():
            response = self.client.post('/login',
                json={
                    'username': 'testuser'
                },
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 400)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
    
    def test_logout_success(self):
        """Test successful logout - Requirement 2.1"""
        with self.app.app_context():
            # First login the user
            self.client.post('/login',
                json={
                    'username': 'testuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            # Then logout
            response = self.client.post('/logout',
                json={
                    'username': 'testuser'
                },
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data['success'])
            self.assertEqual(data['message'], 'Logout successful')
            
            # Verify user is removed from online users
            online_user = OnlineUser.query.filter_by(username='testuser').first()
            self.assertIsNone(online_user)
            
            # Verify logout is logged
            log_entry = UserLog.query.filter_by(username='testuser', action='logout').first()
            self.assertIsNotNone(log_entry)
    
    def test_logout_nonexistent_user(self):
        """Test logout with nonexistent user"""
        with self.app.app_context():
            response = self.client.post('/logout',
                json={
                    'username': 'nonexistent'
                },
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 404)
            data = json.loads(response.data)
            self.assertFalse(data['success'])


class TestUserManagementRoutes(unittest.TestCase):
    """Test cases for user management endpoints"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        
        db.init_app(self.app)
        self.app.register_blueprint(api)
        
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
            
            # Create test users
            self.test_user1 = User(
                username='testuser1',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            self.test_user2 = User(
                username='testuser2',
                firstname='Jane',
                lastname='Smith',
                birthdate=date(1985, 5, 15),
                email='jane.smith@example.com',
                password='password456'
            )
            db.session.add_all([self.test_user1, self.test_user2])
            db.session.commit()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_list_users_success(self):
        """Test successful user listing - Requirement 3.1"""
        with self.app.app_context():
            response = self.client.get('/user/list')
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertIn('users', data)
            self.assertEqual(len(data['users']), 2)
            
            # Verify user data structure and no sensitive data
            user_data = data['users'][0]
            expected_keys = {'id', 'username', 'firstname', 'lastname', 'birthdate', 'email', 'created_at'}
            self.assertEqual(set(user_data.keys()), expected_keys)
            self.assertNotIn('password_hash', user_data)
            self.assertNotIn('salt', user_data)
    
    def test_create_user_success(self):
        """Test successful user creation - Requirement 4.1"""
        with self.app.app_context():
            new_user_data = {
                'username': 'newuser',
                'firstname': 'Alice',
                'lastname': 'Johnson',
                'birthdate': '1992-03-10',
                'email': 'alice.johnson@example.com',
                'password': 'newpassword123'
            }
            
            response = self.client.post('/user/create',
                json=new_user_data,
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 201)
            data = json.loads(response.data)
            self.assertTrue(data['success'])
            self.assertEqual(data['message'], 'User created successfully')
            self.assertIn('user_id', data)
            
            # Verify user was created in database
            created_user = User.query.filter_by(username='newuser').first()
            self.assertIsNotNone(created_user)
            self.assertEqual(created_user.firstname, 'Alice')
            self.assertEqual(created_user.email, 'alice.johnson@example.com')
    
    def test_create_user_duplicate_username(self):
        """Test user creation with duplicate username"""
        with self.app.app_context():
            duplicate_user_data = {
                'username': 'testuser1',  # Already exists
                'firstname': 'Alice',
                'lastname': 'Johnson',
                'birthdate': '1992-03-10',
                'email': 'alice.johnson@example.com',
                'password': 'newpassword123'
            }
            
            response = self.client.post('/user/create',
                json=duplicate_user_data,
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 409)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
            self.assertIn('Username already exists', data['error']['message'])
    
    def test_create_user_duplicate_email(self):
        """Test user creation with duplicate email"""
        with self.app.app_context():
            duplicate_user_data = {
                'username': 'newuser',
                'firstname': 'Alice',
                'lastname': 'Johnson',
                'birthdate': '1992-03-10',
                'email': 'john.doe@example.com',  # Already exists
                'password': 'newpassword123'
            }
            
            response = self.client.post('/user/create',
                json=duplicate_user_data,
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 409)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
            self.assertIn('Email already exists', data['error']['message'])
    
    def test_create_user_invalid_password(self):
        """Test user creation with invalid password"""
        with self.app.app_context():
            invalid_user_data = {
                'username': 'newuser',
                'firstname': 'Alice',
                'lastname': 'Johnson',
                'birthdate': '1992-03-10',
                'email': 'alice.johnson@example.com',
                'password': 'short'  # Too short
            }
            
            response = self.client.post('/user/create',
                json=invalid_user_data,
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 400)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
    
    def test_delete_user_success(self):
        """Test successful user deletion - Requirement 5.1"""
        with self.app.app_context():
            user_id = self.test_user1.id
            
            response = self.client.delete(f'/user/delete/{user_id}')
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data['success'])
            self.assertEqual(data['message'], 'User deleted successfully')
            
            # Verify user was deleted from database
            deleted_user = User.query.get(user_id)
            self.assertIsNone(deleted_user)
    
    def test_delete_user_not_found(self):
        """Test user deletion with nonexistent user"""
        with self.app.app_context():
            response = self.client.delete('/user/delete/999')
            
            self.assertEqual(response.status_code, 404)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
    
    def test_update_user_success(self):
        """Test successful user update - Requirement 6.1"""
        with self.app.app_context():
            user_id = self.test_user1.id
            update_data = {
                'firstname': 'Johnny',
                'lastname': 'Updated',
                'email': 'johnny.updated@example.com'
            }
            
            response = self.client.put(f'/user/update/{user_id}',
                json=update_data,
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data['success'])
            self.assertEqual(data['message'], 'User updated successfully')
            
            # Verify user was updated in database
            updated_user = User.query.get(user_id)
            self.assertEqual(updated_user.firstname, 'Johnny')
            self.assertEqual(updated_user.lastname, 'Updated')
            self.assertEqual(updated_user.email, 'johnny.updated@example.com')
    
    def test_update_user_not_found(self):
        """Test user update with nonexistent user"""
        with self.app.app_context():
            update_data = {
                'firstname': 'Johnny'
            }
            
            response = self.client.put('/user/update/999',
                json=update_data,
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 404)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
    
    def test_update_user_duplicate_email(self):
        """Test user update with duplicate email"""
        with self.app.app_context():
            user_id = self.test_user1.id
            update_data = {
                'email': 'jane.smith@example.com'  # Already exists for user2
            }
            
            response = self.client.put(f'/user/update/{user_id}',
                json=update_data,
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 409)
            data = json.loads(response.data)
            self.assertFalse(data['success'])
            self.assertIn('Email already exists', data['error']['message'])


class TestOnlineUsersRoute(unittest.TestCase):
    """Test cases for online users endpoint"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        
        db.init_app(self.app)
        self.app.register_blueprint(api)
        
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
            
            # Create test user and online session
            self.test_user = User(
                username='testuser',
                firstname='John',
                lastname='Doe',
                birthdate=date(1990, 1, 1),
                email='john.doe@example.com',
                password='password123'
            )
            db.session.add(self.test_user)
            db.session.commit()
            
            # Create online user record
            self.online_user = OnlineUser(
                username='testuser',
                ip_address='192.168.1.1',
                user_id=self.test_user.id,
                login_datetime=datetime.utcnow()
            )
            db.session.add(self.online_user)
            db.session.commit()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_online_users_success(self):
        """Test successful online users retrieval - Requirement 7.1"""
        with self.app.app_context():
            response = self.client.get('/onlusers')
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertIn('online_users', data)
            self.assertEqual(len(data['online_users']), 1)
            
            # Verify online user data structure
            online_user_data = data['online_users'][0]
            expected_keys = {'username', 'ip_address', 'login_datetime'}
            self.assertEqual(set(online_user_data.keys()), expected_keys)
            self.assertEqual(online_user_data['username'], 'testuser')
            self.assertEqual(online_user_data['ip_address'], '192.168.1.1')
    
    def test_online_users_empty_list(self):
        """Test online users endpoint with no online users"""
        with self.app.app_context():
            # Remove the online user
            db.session.delete(self.online_user)
            db.session.commit()
            
            response = self.client.get('/onlusers')
            
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertIn('online_users', data)
            self.assertEqual(len(data['online_users']), 0)


class TestErrorHandling(unittest.TestCase):
    """Test cases for error handling in routes"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        
        db.init_app(self.app)
        self.app.register_blueprint(api)
        
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_invalid_json_request(self):
        """Test handling of invalid JSON requests"""
        with self.app.app_context():
            response = self.client.post('/login',
                data='invalid json',
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 400)
    
    def test_missing_content_type(self):
        """Test handling of requests without proper content type"""
        with self.app.app_context():
            response = self.client.post('/login',
                data=json.dumps({'username': 'test', 'password': 'test'})
            )
            
            # Should handle missing content type gracefully
            self.assertIn(response.status_code, [400, 415])
    
    def test_empty_request_body(self):
        """Test handling of empty request body"""
        with self.app.app_context():
            response = self.client.post('/login',
                json={},
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 400)
    
    def test_invalid_user_id_parameter(self):
        """Test handling of invalid user ID parameters"""
        with self.app.app_context():
            response = self.client.delete('/user/delete/invalid')
            
            self.assertEqual(response.status_code, 404)  # Flask converts invalid int to 404


class TestSecurityValidation(unittest.TestCase):
    """Test cases for security validation in routes"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-key'
        
        db.init_app(self.app)
        self.app.register_blueprint(api)
        
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_sql_injection_prevention(self):
        """Test SQL injection prevention in user input"""
        with self.app.app_context():
            malicious_data = {
                'username': "admin'; DROP TABLE user; --",
                'password': 'password123'
            }
            
            response = self.client.post('/login',
                json=malicious_data,
                content_type='application/json'
            )
            
            # Should be handled by validation, not cause database error
            self.assertIn(response.status_code, [400, 401])
    
    def test_xss_prevention(self):
        """Test XSS prevention in user input"""
        with self.app.app_context():
            malicious_data = {
                'username': 'testuser',
                'firstname': '<script>alert("xss")</script>',
                'lastname': 'Doe',
                'birthdate': '1990-01-01',
                'email': 'test@example.com',
                'password': 'password123'
            }
            
            response = self.client.post('/user/create',
                json=malicious_data,
                content_type='application/json'
            )
            
            # Should be handled by validation
            self.assertIn(response.status_code, [400, 401])


if __name__ == '__main__':
    unittest.main()