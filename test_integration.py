# Integration tests for Flask User Management Application
# Requirements: 1.1, 1.3, 1.4, 2.1, 2.2, 2.3

import unittest
import json
from datetime import datetime, date
from unittest.mock import patch

# Import Flask and testing utilities
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Import application modules
from models import db, User, OnlineUser, UserLog
from routes import api


class TestDatabaseCRUDOperations(unittest.TestCase):
    """Integration tests for database CRUD operations"""
    
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
    
    def test_user_crud_operations(self):
        """Test complete user CRUD operations"""
        with self.app.app_context():
            # CREATE - Create a new user
            user_data = {
                'username': 'integrationuser',
                'firstname': 'Integration',
                'lastname': 'Test',
                'birthdate': '1990-01-01',
                'email': 'integration@test.com',
                'password': 'password123'
            }
            
            create_response = self.client.post('/user/create',
                json=user_data,
                content_type='application/json'
            )
            
            self.assertEqual(create_response.status_code, 201)
            create_data = json.loads(create_response.data)
            user_id = create_data['user_id']
            
            # READ - Verify user exists in database
            user = User.query.get(user_id)
            self.assertIsNotNone(user)
            self.assertEqual(user.username, 'integrationuser')
            self.assertEqual(user.email, 'integration@test.com')
            
            # READ - List users via API
            list_response = self.client.get('/user/list')
            self.assertEqual(list_response.status_code, 200)
            list_data = json.loads(list_response.data)
            self.assertEqual(len(list_data['users']), 1)
            
            # UPDATE - Update user information
            update_data = {
                'firstname': 'Updated',
                'email': 'updated@test.com'
            }
            
            update_response = self.client.put(f'/user/update/{user_id}',
                json=update_data,
                content_type='application/json'
            )
            
            self.assertEqual(update_response.status_code, 200)
            
            # Verify update in database
            updated_user = User.query.get(user_id)
            self.assertEqual(updated_user.firstname, 'Updated')
            self.assertEqual(updated_user.email, 'updated@test.com')
            
            # DELETE - Delete the user
            delete_response = self.client.delete(f'/user/delete/{user_id}')
            self.assertEqual(delete_response.status_code, 200)
            
            # Verify deletion in database
            deleted_user = User.query.get(user_id)
            self.assertIsNone(deleted_user)
    
    def test_online_user_crud_operations(self):
        """Test online user CRUD operations"""
        with self.app.app_context():
            # Create a user first
            user = User(
                username='onlineuser',
                firstname='Online',
                lastname='User',
                birthdate=date(1990, 1, 1),
                email='online@test.com',
                password='password123'
            )
            db.session.add(user)
            db.session.commit()
            
            # CREATE - Add user to online list via login
            login_response = self.client.post('/login',
                json={
                    'username': 'onlineuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            self.assertEqual(login_response.status_code, 200)
            
            # READ - Verify online user exists
            online_user = OnlineUser.query.filter_by(username='onlineuser').first()
            self.assertIsNotNone(online_user)
            self.assertEqual(online_user.user_id, user.id)
            
            # READ - Get online users via API
            online_response = self.client.get('/onlusers')
            self.assertEqual(online_response.status_code, 200)
            online_data = json.loads(online_response.data)
            self.assertEqual(len(online_data['online_users']), 1)
            self.assertEqual(online_data['online_users'][0]['username'], 'onlineuser')
            
            # DELETE - Remove user from online list via logout
            logout_response = self.client.post('/logout',
                json={
                    'username': 'onlineuser'
                },
                content_type='application/json'
            )
            
            self.assertEqual(logout_response.status_code, 200)
            
            # Verify removal from online list
            online_user_after_logout = OnlineUser.query.filter_by(username='onlineuser').first()
            self.assertIsNone(online_user_after_logout)
    
    def test_user_log_operations(self):
        """Test user log CRUD operations"""
        with self.app.app_context():
            # Create a user first
            user = User(
                username='loguser',
                firstname='Log',
                lastname='User',
                birthdate=date(1990, 1, 1),
                email='log@test.com',
                password='password123'
            )
            db.session.add(user)
            db.session.commit()
            
            # CREATE - Generate login log via login
            login_response = self.client.post('/login',
                json={
                    'username': 'loguser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            self.assertEqual(login_response.status_code, 200)
            
            # READ - Verify login log exists
            login_log = UserLog.query.filter_by(username='loguser', action='login').first()
            self.assertIsNotNone(login_log)
            self.assertEqual(login_log.user_id, user.id)
            
            # CREATE - Generate logout log via logout
            logout_response = self.client.post('/logout',
                json={
                    'username': 'loguser'
                },
                content_type='application/json'
            )
            
            self.assertEqual(logout_response.status_code, 200)
            
            # READ - Verify logout log exists
            logout_log = UserLog.query.filter_by(username='loguser', action='logout').first()
            self.assertIsNotNone(logout_log)
            self.assertEqual(logout_log.user_id, user.id)
            
            # READ - Verify both logs exist
            all_logs = UserLog.query.filter_by(username='loguser').all()
            self.assertEqual(len(all_logs), 2)
            
            # Verify log actions
            actions = [log.action for log in all_logs]
            self.assertIn('login', actions)
            self.assertIn('logout', actions)


class TestEndToEndAPIWorkflows(unittest.TestCase):
    """End-to-end API workflow tests"""
    
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
    
    def test_complete_user_lifecycle(self):
        """Test complete user lifecycle from creation to deletion"""
        with self.app.app_context():
            # Step 1: Create user
            user_data = {
                'username': 'lifecycleuser',
                'firstname': 'Lifecycle',
                'lastname': 'Test',
                'birthdate': '1990-01-01',
                'email': 'lifecycle@test.com',
                'password': 'password123'
            }
            
            create_response = self.client.post('/user/create',
                json=user_data,
                content_type='application/json'
            )
            
            self.assertEqual(create_response.status_code, 201)
            user_id = json.loads(create_response.data)['user_id']
            
            # Step 2: Login user
            login_response = self.client.post('/login',
                json={
                    'username': 'lifecycleuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            self.assertEqual(login_response.status_code, 200)
            
            # Step 3: Verify user is online
            online_response = self.client.get('/onlusers')
            online_data = json.loads(online_response.data)
            self.assertEqual(len(online_data['online_users']), 1)
            self.assertEqual(online_data['online_users'][0]['username'], 'lifecycleuser')
            
            # Step 4: Update user information
            update_response = self.client.put(f'/user/update/{user_id}',
                json={'firstname': 'UpdatedLifecycle'},
                content_type='application/json'
            )
            
            self.assertEqual(update_response.status_code, 200)
            
            # Step 5: Logout user
            logout_response = self.client.post('/logout',
                json={'username': 'lifecycleuser'},
                content_type='application/json'
            )
            
            self.assertEqual(logout_response.status_code, 200)
            
            # Step 6: Verify user is no longer online
            online_response_after = self.client.get('/onlusers')
            online_data_after = json.loads(online_response_after.data)
            self.assertEqual(len(online_data_after['online_users']), 0)
            
            # Step 7: Verify logs were created
            logs = UserLog.query.filter_by(username='lifecycleuser').all()
            self.assertEqual(len(logs), 2)  # login and logout
            
            # Step 8: Delete user
            delete_response = self.client.delete(f'/user/delete/{user_id}')
            self.assertEqual(delete_response.status_code, 200)
            
            # Step 9: Verify user and related data are deleted
            user = User.query.get(user_id)
            self.assertIsNone(user)
            
            # Verify cascade deletion worked
            remaining_logs = UserLog.query.filter_by(user_id=user_id).all()
            self.assertEqual(len(remaining_logs), 0)
    
    def test_multiple_user_sessions(self):
        """Test multiple users with concurrent sessions"""
        with self.app.app_context():
            # Create multiple users
            users_data = [
                {
                    'username': 'user1',
                    'firstname': 'User',
                    'lastname': 'One',
                    'birthdate': '1990-01-01',
                    'email': 'user1@test.com',
                    'password': 'password123'
                },
                {
                    'username': 'user2',
                    'firstname': 'User',
                    'lastname': 'Two',
                    'birthdate': '1991-02-02',
                    'email': 'user2@test.com',
                    'password': 'password456'
                },
                {
                    'username': 'user3',
                    'firstname': 'User',
                    'lastname': 'Three',
                    'birthdate': '1992-03-03',
                    'email': 'user3@test.com',
                    'password': 'password789'
                }
            ]
            
            user_ids = []
            
            # Create all users
            for user_data in users_data:
                response = self.client.post('/user/create',
                    json=user_data,
                    content_type='application/json'
                )
                self.assertEqual(response.status_code, 201)
                user_ids.append(json.loads(response.data)['user_id'])
            
            # Login all users
            for user_data in users_data:
                response = self.client.post('/login',
                    json={
                        'username': user_data['username'],
                        'password': user_data['password']
                    },
                    content_type='application/json'
                )
                self.assertEqual(response.status_code, 200)
            
            # Verify all users are online
            online_response = self.client.get('/onlusers')
            online_data = json.loads(online_response.data)
            self.assertEqual(len(online_data['online_users']), 3)
            
            online_usernames = [user['username'] for user in online_data['online_users']]
            for user_data in users_data:
                self.assertIn(user_data['username'], online_usernames)
            
            # Logout one user
            logout_response = self.client.post('/logout',
                json={'username': 'user2'},
                content_type='application/json'
            )
            self.assertEqual(logout_response.status_code, 200)
            
            # Verify only 2 users are online
            online_response_after = self.client.get('/onlusers')
            online_data_after = json.loads(online_response_after.data)
            self.assertEqual(len(online_data_after['online_users']), 2)
            
            # Verify correct users are still online
            remaining_usernames = [user['username'] for user in online_data_after['online_users']]
            self.assertIn('user1', remaining_usernames)
            self.assertIn('user3', remaining_usernames)
            self.assertNotIn('user2', remaining_usernames)


class TestAuthenticationFlows(unittest.TestCase):
    """Integration tests for authentication flows"""
    
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
                username='authuser',
                firstname='Auth',
                lastname='User',
                birthdate=date(1990, 1, 1),
                email='auth@test.com',
                password='password123'
            )
            db.session.add(self.test_user)
            db.session.commit()
    
    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
    
    def test_login_logout_flow(self):
        """Test complete login-logout flow - Requirements 1.1, 1.3, 1.4, 2.1, 2.2, 2.3"""
        with self.app.app_context():
            # Initial state - no online users
            online_response = self.client.get('/onlusers')
            online_data = json.loads(online_response.data)
            self.assertEqual(len(online_data['online_users']), 0)
            
            # Step 1: Login user - Requirement 1.1
            login_response = self.client.post('/login',
                json={
                    'username': 'authuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            self.assertEqual(login_response.status_code, 200)
            login_data = json.loads(login_response.data)
            self.assertTrue(login_data['success'])
            self.assertEqual(login_data['user_id'], self.test_user.id)
            
            # Step 2: Verify user is added to online list - Requirement 1.3
            online_response_after_login = self.client.get('/onlusers')
            online_data_after_login = json.loads(online_response_after_login.data)
            self.assertEqual(len(online_data_after_login['online_users']), 1)
            self.assertEqual(online_data_after_login['online_users'][0]['username'], 'authuser')
            
            # Step 3: Verify login is logged - Requirement 1.4
            login_log = UserLog.query.filter_by(username='authuser', action='login').first()
            self.assertIsNotNone(login_log)
            self.assertEqual(login_log.user_id, self.test_user.id)
            self.assertIsNotNone(login_log.ip_address)
            self.assertIsNotNone(login_log.timestamp)
            
            # Step 4: Logout user - Requirement 2.1
            logout_response = self.client.post('/logout',
                json={'username': 'authuser'},
                content_type='application/json'
            )
            
            self.assertEqual(logout_response.status_code, 200)
            logout_data = json.loads(logout_response.data)
            self.assertTrue(logout_data['success'])
            
            # Step 5: Verify user is removed from online list - Requirement 2.2
            online_response_after_logout = self.client.get('/onlusers')
            online_data_after_logout = json.loads(online_response_after_logout.data)
            self.assertEqual(len(online_data_after_logout['online_users']), 0)
            
            # Step 6: Verify logout is logged - Requirement 2.3
            logout_log = UserLog.query.filter_by(username='authuser', action='logout').first()
            self.assertIsNotNone(logout_log)
            self.assertEqual(logout_log.user_id, self.test_user.id)
            self.assertIsNotNone(logout_log.ip_address)
            self.assertIsNotNone(logout_log.timestamp)
            
            # Verify both logs exist
            all_logs = UserLog.query.filter_by(username='authuser').all()
            self.assertEqual(len(all_logs), 2)
    
    def test_multiple_login_attempts(self):
        """Test multiple login attempts and session management"""
        with self.app.app_context():
            # First login
            login_response1 = self.client.post('/login',
                json={
                    'username': 'authuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            self.assertEqual(login_response1.status_code, 200)
            
            # Verify user is online
            online_response1 = self.client.get('/onlusers')
            online_data1 = json.loads(online_response1.data)
            self.assertEqual(len(online_data1['online_users']), 1)
            
            # Second login (should replace existing session)
            login_response2 = self.client.post('/login',
                json={
                    'username': 'authuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            self.assertEqual(login_response2.status_code, 200)
            
            # Verify still only one online session
            online_response2 = self.client.get('/onlusers')
            online_data2 = json.loads(online_response2.data)
            self.assertEqual(len(online_data2['online_users']), 1)
            
            # Verify multiple login logs
            login_logs = UserLog.query.filter_by(username='authuser', action='login').all()
            self.assertEqual(len(login_logs), 2)
    
    def test_failed_authentication_flow(self):
        """Test failed authentication scenarios"""
        with self.app.app_context():
            # Test wrong password
            wrong_password_response = self.client.post('/login',
                json={
                    'username': 'authuser',
                    'password': 'wrongpassword'
                },
                content_type='application/json'
            )
            
            self.assertEqual(wrong_password_response.status_code, 401)
            
            # Verify no online session created
            online_response = self.client.get('/onlusers')
            online_data = json.loads(online_response.data)
            self.assertEqual(len(online_data['online_users']), 0)
            
            # Verify no login log created
            login_logs = UserLog.query.filter_by(username='authuser', action='login').all()
            self.assertEqual(len(login_logs), 0)
            
            # Test nonexistent user
            nonexistent_response = self.client.post('/login',
                json={
                    'username': 'nonexistent',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            self.assertEqual(nonexistent_response.status_code, 401)


class TestDataConsistency(unittest.TestCase):
    """Integration tests for data consistency across operations"""
    
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
    
    def test_cascade_delete_consistency(self):
        """Test that cascade deletes maintain data consistency"""
        with self.app.app_context():
            # Create user
            user_data = {
                'username': 'cascadeuser',
                'firstname': 'Cascade',
                'lastname': 'Test',
                'birthdate': '1990-01-01',
                'email': 'cascade@test.com',
                'password': 'password123'
            }
            
            create_response = self.client.post('/user/create',
                json=user_data,
                content_type='application/json'
            )
            user_id = json.loads(create_response.data)['user_id']
            
            # Login user (creates online session and log)
            self.client.post('/login',
                json={
                    'username': 'cascadeuser',
                    'password': 'password123'
                },
                content_type='application/json'
            )
            
            # Logout user (creates logout log)
            self.client.post('/logout',
                json={'username': 'cascadeuser'},
                content_type='application/json'
            )
            
            # Verify related records exist
            online_users_before = OnlineUser.query.filter_by(user_id=user_id).count()
            logs_before = UserLog.query.filter_by(user_id=user_id).count()
            
            self.assertEqual(logs_before, 2)  # login and logout logs
            
            # Delete user
            self.client.delete(f'/user/delete/{user_id}')
            
            # Verify cascade deletion
            online_users_after = OnlineUser.query.filter_by(user_id=user_id).count()
            logs_after = UserLog.query.filter_by(user_id=user_id).count()
            
            self.assertEqual(online_users_after, 0)
            self.assertEqual(logs_after, 0)
    
    def test_transaction_rollback_consistency(self):
        """Test that failed operations maintain database consistency"""
        with self.app.app_context():
            # Create user
            user_data = {
                'username': 'rollbackuser',
                'firstname': 'Rollback',
                'lastname': 'Test',
                'birthdate': '1990-01-01',
                'email': 'rollback@test.com',
                'password': 'password123'
            }
            
            create_response = self.client.post('/user/create',
                json=user_data,
                content_type='application/json'
            )
            self.assertEqual(create_response.status_code, 201)
            
            # Count initial records
            initial_user_count = User.query.count()
            initial_online_count = OnlineUser.query.count()
            initial_log_count = UserLog.query.count()
            
            # Attempt to create duplicate user (should fail)
            duplicate_response = self.client.post('/user/create',
                json=user_data,
                content_type='application/json'
            )
            self.assertEqual(duplicate_response.status_code, 409)
            
            # Verify no additional records were created
            final_user_count = User.query.count()
            final_online_count = OnlineUser.query.count()
            final_log_count = UserLog.query.count()
            
            self.assertEqual(final_user_count, initial_user_count)
            self.assertEqual(final_online_count, initial_online_count)
            self.assertEqual(final_log_count, initial_log_count)


if __name__ == '__main__':
    unittest.main()