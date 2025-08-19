#!/usr/bin/env python3
"""
Comprehensive Integration Test Runner
Tests the complete Flask User Management Application end-to-end
"""

import os
import sys
import time
import json
import requests
import subprocess
import threading
from datetime import datetime

class IntegrationTestRunner:
    def __init__(self):
        self.base_url = "http://localhost:5000"
        self.app_process = None
        self.test_results = []
        
    def start_application(self):
        """Start the Flask application in a separate process"""
        print("Starting Flask application...")
        
        # Set environment variables for testing
        env = os.environ.copy()
        env['FLASK_ENV'] = 'development'
        env['TESTING'] = 'True'
        
        try:
            self.app_process = subprocess.Popen(
                [sys.executable, 'app.py'],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for application to start
            time.sleep(3)
            
            # Check if application is running
            if self.app_process.poll() is None:
                print("✓ Flask application started successfully")
                return True
            else:
                stdout, stderr = self.app_process.communicate()
                print(f"✗ Flask application failed to start")
                print(f"STDOUT: {stdout.decode()}")
                print(f"STDERR: {stderr.decode()}")
                return False
                
        except Exception as e:
            print(f"✗ Failed to start Flask application: {e}")
            return False
    
    def stop_application(self):
        """Stop the Flask application"""
        if self.app_process:
            print("Stopping Flask application...")
            self.app_process.terminate()
            self.app_process.wait()
            print("✓ Flask application stopped")
    
    def test_health_check(self):
        """Test application health check"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('status') == 'healthy':
                    self.test_results.append(("Health Check", True, "Application is healthy"))
                    return True
                else:
                    self.test_results.append(("Health Check", False, f"Unhealthy response: {data}"))
                    return False
            else:
                self.test_results.append(("Health Check", False, f"HTTP {response.status_code}"))
                return False
        except Exception as e:
            self.test_results.append(("Health Check", False, f"Connection failed: {e}"))
            return False
    
    def test_user_creation(self):
        """Test user creation endpoint"""
        test_user = {
            "username": "integrationtest",
            "firstname": "Integration",
            "lastname": "Test",
            "birthdate": "1990-01-01",
            "email": "integration@test.com",
            "password": "TestPass123"
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/user/create",
                json=test_user,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 201:
                data = response.json()
                if data.get('success'):
                    self.test_results.append(("User Creation", True, f"User created with ID: {data.get('user_id')}"))
                    return data.get('user_id')
                else:
                    self.test_results.append(("User Creation", False, f"Creation failed: {data}"))
                    return None
            else:
                self.test_results.append(("User Creation", False, f"HTTP {response.status_code}: {response.text}"))
                return None
                
        except Exception as e:
            self.test_results.append(("User Creation", False, f"Request failed: {e}"))
            return None
    
    def test_user_login(self, username="integrationtest", password="TestPass123"):
        """Test user login endpoint"""
        login_data = {
            "username": username,
            "password": password
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/login",
                json=login_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.test_results.append(("User Login", True, f"Login successful for {username}"))
                    return True
                else:
                    self.test_results.append(("User Login", False, f"Login failed: {data}"))
                    return False
            else:
                self.test_results.append(("User Login", False, f"HTTP {response.status_code}: {response.text}"))
                return False
                
        except Exception as e:
            self.test_results.append(("User Login", False, f"Request failed: {e}"))
            return False
    
    def test_user_list(self):
        """Test user list endpoint"""
        try:
            response = requests.get(f"{self.base_url}/user/list", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'users' in data:
                    user_count = len(data['users'])
                    self.test_results.append(("User List", True, f"Retrieved {user_count} users"))
                    return True
                else:
                    self.test_results.append(("User List", False, f"Invalid response format: {data}"))
                    return False
            else:
                self.test_results.append(("User List", False, f"HTTP {response.status_code}: {response.text}"))
                return False
                
        except Exception as e:
            self.test_results.append(("User List", False, f"Request failed: {e}"))
            return False
    
    def test_online_users(self):
        """Test online users endpoint"""
        try:
            response = requests.get(f"{self.base_url}/onlusers", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'online_users' in data:
                    online_count = len(data['online_users'])
                    self.test_results.append(("Online Users", True, f"Retrieved {online_count} online users"))
                    return True
                else:
                    self.test_results.append(("Online Users", False, f"Invalid response format: {data}"))
                    return False
            else:
                self.test_results.append(("Online Users", False, f"HTTP {response.status_code}: {response.text}"))
                return False
                
        except Exception as e:
            self.test_results.append(("Online Users", False, f"Request failed: {e}"))
            return False
    
    def test_user_logout(self, username="integrationtest"):
        """Test user logout endpoint"""
        logout_data = {
            "username": username
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/logout",
                json=logout_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.test_results.append(("User Logout", True, f"Logout successful for {username}"))
                    return True
                else:
                    self.test_results.append(("User Logout", False, f"Logout failed: {data}"))
                    return False
            else:
                self.test_results.append(("User Logout", False, f"HTTP {response.status_code}: {response.text}"))
                return False
                
        except Exception as e:
            self.test_results.append(("User Logout", False, f"Request failed: {e}"))
            return False
    
    def test_error_handling(self):
        """Test error handling scenarios"""
        # Test invalid login
        try:
            response = requests.post(
                f"{self.base_url}/login",
                json={"username": "nonexistent", "password": "wrongpass"},
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 401:
                self.test_results.append(("Error Handling - Invalid Login", True, "Correctly returned 401"))
            else:
                self.test_results.append(("Error Handling - Invalid Login", False, f"Expected 401, got {response.status_code}"))
        except Exception as e:
            self.test_results.append(("Error Handling - Invalid Login", False, f"Request failed: {e}"))
        
        # Test invalid JSON
        try:
            response = requests.post(
                f"{self.base_url}/login",
                data="invalid json",
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 400:
                self.test_results.append(("Error Handling - Invalid JSON", True, "Correctly returned 400"))
            else:
                self.test_results.append(("Error Handling - Invalid JSON", False, f"Expected 400, got {response.status_code}"))
        except Exception as e:
            self.test_results.append(("Error Handling - Invalid JSON", False, f"Request failed: {e}"))
    
    def run_performance_tests(self):
        """Run basic performance tests"""
        print("\nRunning performance tests...")
        
        # Test response times
        endpoints = [
            ("/health", "GET"),
            ("/user/list", "GET"),
            ("/onlusers", "GET")
        ]
        
        for endpoint, method in endpoints:
            times = []
            for i in range(5):
                start_time = time.time()
                try:
                    if method == "GET":
                        response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                    else:
                        response = requests.post(f"{self.base_url}{endpoint}", timeout=10)
                    
                    end_time = time.time()
                    response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                    times.append(response_time)
                    
                except Exception as e:
                    self.test_results.append((f"Performance - {endpoint}", False, f"Request failed: {e}"))
                    break
            
            if times:
                avg_time = sum(times) / len(times)
                max_time = max(times)
                min_time = min(times)
                
                # Consider response time acceptable if average is under 1000ms
                acceptable = avg_time < 1000
                
                self.test_results.append((
                    f"Performance - {endpoint}",
                    acceptable,
                    f"Avg: {avg_time:.2f}ms, Min: {min_time:.2f}ms, Max: {max_time:.2f}ms"
                ))
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("=" * 60)
        print("FLASK USER MANAGEMENT - INTEGRATION TESTS")
        print("=" * 60)
        
        # Start application
        if not self.start_application():
            print("✗ Cannot start application. Aborting tests.")
            return False
        
        try:
            # Wait a bit more for full startup
            time.sleep(2)
            
            # Test health check first
            if not self.test_health_check():
                print("✗ Health check failed. Application may not be ready.")
                return False
            
            print("\nRunning functional tests...")
            
            # Test user creation
            user_id = self.test_user_creation()
            
            # Test user login
            if user_id:
                self.test_user_login()
            
            # Test user list
            self.test_user_list()
            
            # Test online users
            self.test_online_users()
            
            # Test user logout
            if user_id:
                self.test_user_logout()
            
            # Test error handling
            self.test_error_handling()
            
            # Run performance tests
            self.run_performance_tests()
            
            return True
            
        finally:
            # Always stop the application
            self.stop_application()
    
    def print_results(self):
        """Print test results summary"""
        print("\n" + "=" * 60)
        print("INTEGRATION TEST RESULTS")
        print("=" * 60)
        
        passed = 0
        failed = 0
        
        for test_name, success, details in self.test_results:
            status = "✓ PASS" if success else "✗ FAIL"
            print(f"{status:<8} {test_name:<30} {details}")
            
            if success:
                passed += 1
            else:
                failed += 1
        
        print("\n" + "-" * 60)
        print(f"Total Tests: {passed + failed}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed / (passed + failed) * 100):.1f}%" if (passed + failed) > 0 else "0%")
        
        if failed == 0:
            print("\n🎉 ALL INTEGRATION TESTS PASSED!")
            return True
        else:
            print(f"\n❌ {failed} INTEGRATION TESTS FAILED")
            return False

def main():
    """Main function to run integration tests"""
    runner = IntegrationTestRunner()
    
    try:
        success = runner.run_all_tests()
        runner.print_results()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        runner.stop_application()
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error during testing: {e}")
        runner.stop_application()
        sys.exit(1)

if __name__ == '__main__':
    main()