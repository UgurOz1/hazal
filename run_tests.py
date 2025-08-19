#!/usr/bin/env python3
"""
Test runner for Flask User Management Application
Runs all unit and integration tests
"""

import unittest
import sys
import os

def run_all_tests():
    """Run all test suites"""
    # Discover and run all tests
    loader = unittest.TestLoader()
    
    # Load test suites
    test_suites = []
    
    # Model tests
    try:
        from test_models import (
            TestUserModel, TestOnlineUserModel, TestUserLogModel, TestModelRelationships
        )
        test_suites.extend([
            loader.loadTestsFromTestCase(TestUserModel),
            loader.loadTestsFromTestCase(TestOnlineUserModel),
            loader.loadTestsFromTestCase(TestUserLogModel),
            loader.loadTestsFromTestCase(TestModelRelationships)
        ])
        print("✓ Model tests loaded")
    except ImportError as e:
        print(f"✗ Failed to load model tests: {e}")
    
    # Route tests
    try:
        from test_routes import (
            TestAuthenticationRoutes, TestUserManagementRoutes, 
            TestOnlineUsersRoute, TestErrorHandling, TestSecurityValidation
        )
        test_suites.extend([
            loader.loadTestsFromTestCase(TestAuthenticationRoutes),
            loader.loadTestsFromTestCase(TestUserManagementRoutes),
            loader.loadTestsFromTestCase(TestOnlineUsersRoute),
            loader.loadTestsFromTestCase(TestErrorHandling),
            loader.loadTestsFromTestCase(TestSecurityValidation)
        ])
        print("✓ Route tests loaded")
    except ImportError as e:
        print(f"✗ Failed to load route tests: {e}")
    
    # Integration tests
    try:
        from test_integration import (
            TestDatabaseCRUDOperations, TestEndToEndAPIWorkflows,
            TestAuthenticationFlows, TestDataConsistency
        )
        test_suites.extend([
            loader.loadTestsFromTestCase(TestDatabaseCRUDOperations),
            loader.loadTestsFromTestCase(TestEndToEndAPIWorkflows),
            loader.loadTestsFromTestCase(TestAuthenticationFlows),
            loader.loadTestsFromTestCase(TestDataConsistency)
        ])
        print("✓ Integration tests loaded")
    except ImportError as e:
        print(f"✗ Failed to load integration tests: {e}")
    
    if not test_suites:
        print("No test suites loaded. Exiting.")
        return False
    
    # Combine all test suites
    combined_suite = unittest.TestSuite(test_suites)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(combined_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print(f"\nFAILURES ({len(result.failures)}):")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip() if 'AssertionError:' in traceback else 'See details above'}")
    
    if result.errors:
        print(f"\nERRORS ({len(result.errors)}):")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Exception:')[-1].strip() if 'Exception:' in traceback else 'See details above'}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nResult: {'PASSED' if success else 'FAILED'}")
    
    return success

def run_specific_test_suite(suite_name):
    """Run a specific test suite"""
    suite_map = {
        'models': 'test_models',
        'routes': 'test_routes', 
        'integration': 'test_integration'
    }
    
    if suite_name not in suite_map:
        print(f"Unknown test suite: {suite_name}")
        print(f"Available suites: {', '.join(suite_map.keys())}")
        return False
    
    module_name = suite_map[suite_name]
    
    try:
        # Import and run specific test module
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(module_name)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return len(result.failures) == 0 and len(result.errors) == 0
    except ImportError as e:
        print(f"Failed to load test suite '{suite_name}': {e}")
        return False

if __name__ == '__main__':
    print("Flask User Management Application - Test Runner")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        # Run specific test suite
        suite_name = sys.argv[1].lower()
        success = run_specific_test_suite(suite_name)
    else:
        # Run all tests
        success = run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)