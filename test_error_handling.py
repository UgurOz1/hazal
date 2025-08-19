#!/usr/bin/env python3
"""
Test script for error handling system
This script tests various error scenarios to ensure proper HTTP status codes and response formats
"""

import json
import requests
from datetime import datetime

# Configuration
BASE_URL = 'http://localhost:5000'
TEST_USER = {
    'username': 'testuser_error',
    'firstname': 'Test',
    'lastname': 'User',
    'birthdate': '1990-01-01',
    'email': 'test.error@example.com',
    'password': 'TestPass123'
}

def test_error_response_format(response, expected_status):
    """Test that error response has correct format"""
    print(f"Status Code: {response.status_code} (expected: {expected_status})")
    
    if response.status_code != expected_status:
        print(f"❌ Wrong status code! Expected {expected_status}, got {response.status_code}")
        return False
    
    try:
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        # Check response structure
        if 'success' not in data:
            print("❌ Missing 'success' field")
            return False
        
        if data['success'] != False:
            print("❌ 'success' should be False for error responses")
            return False
        
        if 'error' not in data:
            print("❌ Missing 'error' field")
            return False
        
        error = data['error']
        if 'code' not in error or 'message' not in error:
            print("❌ Error object missing 'code' or 'message'")
            return False
        
        print("✅ Error response format is correct")
        return True
        
    except json.JSONDecodeError:
        print("❌ Response is not valid JSON")
        return False

def test_validation_errors():
    """Test validation error scenarios"""
    print("\n=== Testing Validation Errors ===")
    
    # Test 1: Missing required fields
    print("\n1. Testing missing required fields...")
    response = requests.post(f"{BASE_URL}/user/create", json={})
    test_error_response_format(response, 400)
    
    # Test 2: Invalid email format
    print("\n2. Testing invalid email format...")
    invalid_user = TEST_USER.copy()
    invalid_user['email'] = 'invalid-email'
    response = requests.post(f"{BASE_URL}/user/create", json=invalid_user)
    test_error_response_format(response, 400)
    
    # Test 3: Weak password
    print("\n3. Testing weak password...")
    weak_password_user = TEST_USER.copy()
    weak_password_user['password'] = '123'
    response = requests.post(f"{BASE_URL}/user/create", json=weak_password_user)
    test_error_response_format(response, 400)
    
    # Test 4: Invalid birthdate format
    print("\n4. Testing invalid birthdate format...")
    invalid_date_user = TEST_USER.copy()
    invalid_date_user['birthdate'] = 'invalid-date'
    response = requests.post(f"{BASE_URL}/user/create", json=invalid_date_user)
    test_error_response_format(response, 400)

def test_authentication_errors():
    """Test authentication error scenarios"""
    print("\n=== Testing Authentication Errors ===")
    
    # Test 1: Invalid credentials
    print("\n1. Testing invalid credentials...")
    response = requests.post(f"{BASE_URL}/login", json={
        'username': 'nonexistent',
        'password': 'wrongpassword'
    })
    test_error_response_format(response, 401)
    
    # Test 2: Missing login credentials
    print("\n2. Testing missing login credentials...")
    response = requests.post(f"{BASE_URL}/login", json={})
    test_error_response_format(response, 400)

def test_not_found_errors():
    """Test resource not found error scenarios"""
    print("\n=== Testing Not Found Errors ===")
    
    # Test 1: Delete non-existent user
    print("\n1. Testing delete non-existent user...")
    response = requests.delete(f"{BASE_URL}/user/delete/99999")
    test_error_response_format(response, 404)
    
    # Test 2: Update non-existent user
    print("\n2. Testing update non-existent user...")
    response = requests.put(f"{BASE_URL}/user/update/99999", json={'firstname': 'Updated'})
    test_error_response_format(response, 404)
    
    # Test 3: Logout non-existent user
    print("\n3. Testing logout non-existent user...")
    response = requests.post(f"{BASE_URL}/logout", json={'username': 'nonexistent'})
    test_error_response_format(response, 404)

def test_conflict_errors():
    """Test resource conflict error scenarios"""
    print("\n=== Testing Conflict Errors ===")
    
    # First, create a test user
    print("\n1. Creating test user for conflict tests...")
    response = requests.post(f"{BASE_URL}/user/create", json=TEST_USER)
    if response.status_code == 201:
        print("✅ Test user created successfully")
    elif response.status_code == 409:
        print("ℹ️ Test user already exists, continuing with tests...")
    else:
        print(f"❌ Failed to create test user: {response.status_code}")
        return
    
    # Test 2: Duplicate username
    print("\n2. Testing duplicate username...")
    duplicate_user = TEST_USER.copy()
    duplicate_user['email'] = 'different@example.com'
    response = requests.post(f"{BASE_URL}/user/create", json=duplicate_user)
    test_error_response_format(response, 409)
    
    # Test 3: Duplicate email
    print("\n3. Testing duplicate email...")
    duplicate_email_user = TEST_USER.copy()
    duplicate_email_user['username'] = 'different_username'
    response = requests.post(f"{BASE_URL}/user/create", json=duplicate_email_user)
    test_error_response_format(response, 409)

def test_method_not_allowed():
    """Test method not allowed errors"""
    print("\n=== Testing Method Not Allowed Errors ===")
    
    # Test 1: Wrong HTTP method
    print("\n1. Testing wrong HTTP method...")
    response = requests.get(f"{BASE_URL}/login")  # Should be POST
    test_error_response_format(response, 405)

def test_invalid_json():
    """Test invalid JSON handling"""
    print("\n=== Testing Invalid JSON Handling ===")
    
    # Test 1: Invalid JSON content
    print("\n1. Testing invalid JSON content...")
    response = requests.post(
        f"{BASE_URL}/user/create",
        data="invalid json content",
        headers={'Content-Type': 'application/json'}
    )
    test_error_response_format(response, 400)

def cleanup():
    """Clean up test data"""
    print("\n=== Cleaning up test data ===")
    
    # Try to find and delete the test user
    response = requests.get(f"{BASE_URL}/user/list")
    if response.status_code == 200:
        users = response.json().get('users', [])
        test_user = next((u for u in users if u['username'] == TEST_USER['username']), None)
        if test_user:
            delete_response = requests.delete(f"{BASE_URL}/user/delete/{test_user['id']}")
            if delete_response.status_code == 200:
                print("✅ Test user cleaned up successfully")
            else:
                print(f"❌ Failed to clean up test user: {delete_response.status_code}")

def main():
    """Run all error handling tests"""
    print("🧪 Starting Error Handling Tests")
    print("=" * 50)
    
    try:
        # Test if server is running
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code != 200:
            print("❌ Server is not running or not healthy")
            return
        print("✅ Server is running and healthy")
        
        # Run all tests
        test_validation_errors()
        test_authentication_errors()
        test_not_found_errors()
        test_conflict_errors()
        test_method_not_allowed()
        test_invalid_json()
        
        print("\n" + "=" * 50)
        print("🎉 Error handling tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the Flask app is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Unexpected error during testing: {str(e)}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()