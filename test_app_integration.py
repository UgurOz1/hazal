# Test application integration with middleware

import unittest
import json
from app import create_app
from models import db

class TestAppIntegration(unittest.TestCase):
    """Test application integration with middleware"""
    
    def setUp(self):
        """Set up test environment"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
    
    def tearDown(self):
        """Clean up test environment"""
        with self.app.app_context():
            db.drop_all()
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['status'], 'healthy')
    
    def test_create_user_with_valid_data(self):
        """Test user creation with valid data"""
        user_data = {
            'username': 'testuser',
            'firstname': 'John',
            'lastname': 'Doe',
            'email': 'john@example.com',
            'password': 'password123',
            'birthdate': '1990-01-01'
        }
        
        response = self.client.post('/user/create', 
                                  json=user_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 201)
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('user_id', data)
    
    def test_create_user_with_sql_injection(self):
        """Test user creation with SQL injection attempt"""
        user_data = {
            'username': "admin'; DROP TABLE users; --",
            'firstname': 'John',
            'lastname': 'Doe',
            'email': 'john@example.com',
            'password': 'password123',
            'birthdate': '1990-01-01'
        }
        
        response = self.client.post('/user/create', 
                                  json=user_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('error', data)
    
    def test_create_user_with_invalid_content_type(self):
        """Test user creation with invalid content type"""
        response = self.client.post('/user/create', 
                                  data='invalid data',
                                  content_type='text/plain')
        
        self.assertEqual(response.status_code, 400)
        
        data = json.loads(response.data)
        self.assertFalse(data['success'])
    
    def test_login_with_valid_credentials(self):
        """Test login with valid credentials"""
        # First create a user
        user_data = {
            'username': 'testuser',
            'firstname': 'John',
            'lastname': 'Doe',
            'email': 'john@example.com',
            'password': 'password123',
            'birthdate': '1990-01-01'
        }
        
        create_response = self.client.post('/user/create', 
                                         json=user_data,
                                         content_type='application/json')
        self.assertEqual(create_response.status_code, 201)
        
        # Now try to login
        login_data = {
            'username': 'testuser',
            'password': 'password123'
        }
        
        response = self.client.post('/login', 
                                  json=login_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIn('user_id', data)

if __name__ == '__main__':
    unittest.main(verbosity=2)