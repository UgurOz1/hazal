#!/usr/bin/env python3
"""
Performance Testing Script for Flask User Management Application
Tests response times, throughput, and resource usage
"""

import os
import sys
import time
import json
import requests
import threading
import statistics
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class PerformanceTestRunner:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.results = {}
        self.app_process = None
        
    def start_application(self):
        """Start the Flask application for testing"""
        print("Starting Flask application for performance testing...")
        
        env = os.environ.copy()
        env['FLASK_ENV'] = 'production'  # Use production mode for performance testing
        env['TESTING'] = 'False'
        
        try:
            self.app_process = subprocess.Popen(
                [sys.executable, 'app.py'],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for application to start
            time.sleep(5)
            
            # Check if application is running
            if self.app_process.poll() is None:
                print("✓ Flask application started successfully")
                return True
            else:
                stdout, stderr = self.app_process.communicate()
                print(f"✗ Flask application failed to start")
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
    
    def measure_response_time(self, endpoint, method="GET", data=None, headers=None):
        """Measure response time for a single request"""
        start_time = time.time()
        
        try:
            if method == "GET":
                response = requests.get(f"{self.base_url}{endpoint}", timeout=30)
            elif method == "POST":
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=data,
                    headers=headers or {'Content-Type': 'application/json'},
                    timeout=30
                )
            elif method == "PUT":
                response = requests.put(
                    f"{self.base_url}{endpoint}",
                    json=data,
                    headers=headers or {'Content-Type': 'application/json'},
                    timeout=30
                )
            elif method == "DELETE":
                response = requests.delete(f"{self.base_url}{endpoint}", timeout=30)
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            return {
                'response_time': response_time,
                'status_code': response.status_code,
                'success': 200 <= response.status_code < 300
            }
            
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            return {
                'response_time': response_time,
                'status_code': 0,
                'success': False,
                'error': str(e)
            }
    
    def test_endpoint_performance(self, endpoint, method="GET", data=None, num_requests=50, concurrent_users=5):
        """Test performance of a specific endpoint"""
        print(f"\nTesting {method} {endpoint} with {num_requests} requests, {concurrent_users} concurrent users...")
        
        results = []
        
        def make_request():
            return self.measure_response_time(endpoint, method, data)
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            # Submit all requests
            futures = [executor.submit(make_request) for _ in range(num_requests)]
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        'response_time': 0,
                        'status_code': 0,
                        'success': False,
                        'error': str(e)
                    })
        
        # Analyze results
        response_times = [r['response_time'] for r in results if r['success']]
        success_count = sum(1 for r in results if r['success'])
        error_count = len(results) - success_count
        
        if response_times:
            analysis = {
                'endpoint': f"{method} {endpoint}",
                'total_requests': num_requests,
                'successful_requests': success_count,
                'failed_requests': error_count,
                'success_rate': (success_count / num_requests) * 100,
                'avg_response_time': statistics.mean(response_times),
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'median_response_time': statistics.median(response_times),
                'p95_response_time': statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times),
                'p99_response_time': statistics.quantiles(response_times, n=100)[98] if len(response_times) > 100 else max(response_times),
                'requests_per_second': success_count / (max(response_times) / 1000) if response_times else 0
            }
        else:
            analysis = {
                'endpoint': f"{method} {endpoint}",
                'total_requests': num_requests,
                'successful_requests': 0,
                'failed_requests': error_count,
                'success_rate': 0,
                'error': 'All requests failed'
            }
        
        return analysis
    
    def test_load_scenarios(self):
        """Test various load scenarios"""
        print("\n" + "=" * 60)
        print("LOAD TESTING SCENARIOS")
        print("=" * 60)
        
        scenarios = [
            # Light load
            {
                'name': 'Light Load',
                'endpoint': '/health',
                'method': 'GET',
                'requests': 20,
                'concurrent': 2
            },
            # Medium load
            {
                'name': 'Medium Load - User List',
                'endpoint': '/user/list',
                'method': 'GET',
                'requests': 50,
                'concurrent': 5
            },
            # Heavy load
            {
                'name': 'Heavy Load - Health Check',
                'endpoint': '/health',
                'method': 'GET',
                'requests': 100,
                'concurrent': 10
            },
            # API endpoint load
            {
                'name': 'API Load - Online Users',
                'endpoint': '/onlusers',
                'method': 'GET',
                'requests': 30,
                'concurrent': 3
            }
        ]
        
        results = []
        
        for scenario in scenarios:
            print(f"\nRunning {scenario['name']}...")
            result = self.test_endpoint_performance(
                scenario['endpoint'],
                scenario['method'],
                num_requests=scenario['requests'],
                concurrent_users=scenario['concurrent']
            )
            result['scenario'] = scenario['name']
            results.append(result)
        
        return results
    
    def test_stress_scenarios(self):
        """Test stress scenarios with high load"""
        print("\n" + "=" * 60)
        print("STRESS TESTING SCENARIOS")
        print("=" * 60)
        
        # Create a test user first for login stress testing
        test_user = {
            "username": "stresstest",
            "firstname": "Stress",
            "lastname": "Test",
            "birthdate": "1990-01-01",
            "email": "stress@test.com",
            "password": "StressTest123"
        }
        
        print("Creating test user for stress testing...")
        create_result = self.measure_response_time('/user/create', 'POST', test_user)
        
        if not create_result['success']:
            print("⚠️  Could not create test user for stress testing")
        
        stress_scenarios = [
            # High concurrency on read endpoints
            {
                'name': 'High Concurrency - Health Check',
                'endpoint': '/health',
                'method': 'GET',
                'requests': 200,
                'concurrent': 20
            },
            # Stress test user list
            {
                'name': 'Stress Test - User List',
                'endpoint': '/user/list',
                'method': 'GET',
                'requests': 100,
                'concurrent': 15
            },
            # Login stress test
            {
                'name': 'Login Stress Test',
                'endpoint': '/login',
                'method': 'POST',
                'data': {"username": "stresstest", "password": "StressTest123"},
                'requests': 50,
                'concurrent': 10
            }
        ]
        
        results = []
        
        for scenario in stress_scenarios:
            print(f"\nRunning {scenario['name']}...")
            result = self.test_endpoint_performance(
                scenario['endpoint'],
                scenario['method'],
                data=scenario.get('data'),
                num_requests=scenario['requests'],
                concurrent_users=scenario['concurrent']
            )
            result['scenario'] = scenario['name']
            results.append(result)
        
        return results
    
    def run_all_performance_tests(self):
        """Run all performance tests"""
        print("=" * 60)
        print("FLASK USER MANAGEMENT - PERFORMANCE TESTS")
        print("=" * 60)
        
        # Start application
        if not self.start_application():
            print("✗ Cannot start application. Aborting performance tests.")
            return False
        
        try:
            # Wait for application to be fully ready
            time.sleep(3)
            
            # Test basic connectivity
            health_result = self.measure_response_time('/health')
            if not health_result['success']:
                print("✗ Health check failed. Application may not be ready.")
                return False
            
            print(f"✓ Application is ready (health check: {health_result['response_time']:.2f}ms)")
            
            # Run load tests
            load_results = self.test_load_scenarios()
            
            # Run stress tests
            stress_results = self.test_stress_scenarios()
            
            # Store all results
            self.results = {
                'load_tests': load_results,
                'stress_tests': stress_results,
                'timestamp': datetime.now().isoformat()
            }
            
            return True
            
        finally:
            # Always stop the application
            self.stop_application()
    
    def print_results(self):
        """Print performance test results"""
        print("\n" + "=" * 60)
        print("PERFORMANCE TEST RESULTS")
        print("=" * 60)
        
        def print_test_results(results, category):
            print(f"\n{category.upper()} RESULTS:")
            print("-" * 40)
            
            for result in results:
                if 'error' in result:
                    print(f"❌ {result['scenario']}: {result['error']}")
                    continue
                
                print(f"\n📊 {result['scenario']}")
                print(f"   Requests: {result['total_requests']} | Success Rate: {result['success_rate']:.1f}%")
                print(f"   Avg Response: {result['avg_response_time']:.2f}ms")
                print(f"   Min/Max: {result['min_response_time']:.2f}ms / {result['max_response_time']:.2f}ms")
                print(f"   P95: {result.get('p95_response_time', 0):.2f}ms | P99: {result.get('p99_response_time', 0):.2f}ms")
                
                # Performance assessment
                avg_time = result['avg_response_time']
                success_rate = result['success_rate']
                
                if success_rate >= 99 and avg_time < 100:
                    status = "🟢 EXCELLENT"
                elif success_rate >= 95 and avg_time < 500:
                    status = "🟡 GOOD"
                elif success_rate >= 90 and avg_time < 1000:
                    status = "🟠 ACCEPTABLE"
                else:
                    status = "🔴 NEEDS IMPROVEMENT"
                
                print(f"   Performance: {status}")
        
        # Print load test results
        if 'load_tests' in self.results:
            print_test_results(self.results['load_tests'], 'Load Test')
        
        # Print stress test results
        if 'stress_tests' in self.results:
            print_test_results(self.results['stress_tests'], 'Stress Test')
        
        # Overall assessment
        print("\n" + "=" * 60)
        print("OVERALL PERFORMANCE ASSESSMENT")
        print("=" * 60)
        
        all_results = []
        if 'load_tests' in self.results:
            all_results.extend(self.results['load_tests'])
        if 'stress_tests' in self.results:
            all_results.extend(self.results['stress_tests'])
        
        if all_results:
            successful_tests = [r for r in all_results if 'error' not in r and r['success_rate'] >= 90]
            total_tests = len(all_results)
            
            avg_response_times = [r['avg_response_time'] for r in successful_tests]
            overall_avg = statistics.mean(avg_response_times) if avg_response_times else 0
            
            print(f"Total Tests: {total_tests}")
            print(f"Successful Tests: {len(successful_tests)}")
            print(f"Overall Average Response Time: {overall_avg:.2f}ms")
            
            if len(successful_tests) == total_tests and overall_avg < 500:
                print("\n🎉 PERFORMANCE TESTS PASSED - Application performs well under load!")
                return True
            elif len(successful_tests) >= total_tests * 0.8:
                print("\n⚠️  PERFORMANCE TESTS PARTIALLY PASSED - Some performance issues detected")
                return True
            else:
                print("\n❌ PERFORMANCE TESTS FAILED - Significant performance issues detected")
                return False
        else:
            print("No performance test results available")
            return False
    
    def save_results_to_file(self, filename="performance_results.json"):
        """Save performance test results to a JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n📄 Performance results saved to {filename}")
        except Exception as e:
            print(f"❌ Failed to save results: {e}")

def main():
    """Main function to run performance tests"""
    runner = PerformanceTestRunner()
    
    try:
        success = runner.run_all_performance_tests()
        overall_success = runner.print_results()
        
        # Save results to file
        runner.save_results_to_file()
        
        # Exit with appropriate code
        sys.exit(0 if success and overall_success else 1)
        
    except KeyboardInterrupt:
        print("\n\nPerformance tests interrupted by user")
        runner.stop_application()
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error during performance testing: {e}")
        runner.stop_application()
        sys.exit(1)

if __name__ == '__main__':
    main()