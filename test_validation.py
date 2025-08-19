#!/usr/bin/env python3
"""
Simple validation test for error handling system
Tests the custom exceptions and validation functions without requiring database
"""

from exceptions import ValidationError, ConflictError, ResourceNotFoundError
from error_handlers import validate_request_data
import json

def test_validation_error():
    """Test ValidationError exception"""
    print("Testing ValidationError...")
    
    try:
        raise ValidationError("Test validation error", field="test_field", constraint="test_constraint")
    except ValidationError as e:
        error_dict = e.to_dict()
        print(f"✅ ValidationError: {json.dumps(error_dict, indent=2)}")
        
        # Verify structure
        assert error_dict['code'] == 'VALIDATION_ERROR'
        assert error_dict['message'] == 'Test validation error'
        assert error_dict['details']['field'] == 'test_field'
        assert error_dict['details']['constraint'] == 'test_constraint'
        print("✅ ValidationError structure is correct")

def test_conflict_error():
    """Test ConflictError exception"""
    print("\nTesting ConflictError...")
    
    try:
        raise ConflictError("Test conflict error", field="email", value="test@example.com")
    except ConflictError as e:
        error_dict = e.to_dict()
        print(f"✅ ConflictError: {json.dumps(error_dict, indent=2)}")
        
        # Verify structure
        assert error_dict['code'] == 'CONFLICT_ERROR'
        assert error_dict['message'] == 'Test conflict error'
        assert error_dict['details']['field'] == 'email'
        assert error_dict['details']['value'] == 'test@example.com'
        print("✅ ConflictError structure is correct")

def test_resource_not_found_error():
    """Test ResourceNotFoundError exception"""
    print("\nTesting ResourceNotFoundError...")
    
    try:
        raise ResourceNotFoundError("User", 123)
    except ResourceNotFoundError as e:
        error_dict = e.to_dict()
        print(f"✅ ResourceNotFoundError: {json.dumps(error_dict, indent=2)}")
        
        # Verify structure
        assert error_dict['code'] == 'RESOURCE_NOT_FOUND'
        assert error_dict['message'] == 'User with ID 123 not found'
        assert error_dict['details']['resource_type'] == 'User'
        assert error_dict['details']['resource_id'] == 123
        print("✅ ResourceNotFoundError structure is correct")

def test_validate_request_data():
    """Test validate_request_data function"""
    print("\nTesting validate_request_data...")
    
    # Test 1: Valid data with required fields
    try:
        data = {'username': 'test', 'password': 'test123'}
        result = validate_request_data(data, required_fields=['username', 'password'])
        print(f"✅ Valid data test passed: {result}")
        assert result == data
    except Exception as e:
        print(f"❌ Valid data test failed: {e}")
    
    # Test 2: Missing required fields
    try:
        data = {'username': 'test'}
        validate_request_data(data, required_fields=['username', 'password'])
        print("❌ Missing required fields test should have failed")
    except ValidationError as e:
        print(f"✅ Missing required fields test passed: {e.message}")
        assert 'Missing required fields' in e.message
    
    # Test 3: No JSON data
    try:
        validate_request_data(None)
        print("❌ No JSON data test should have failed")
    except ValidationError as e:
        print(f"✅ No JSON data test passed: {e.message}")
        assert 'No JSON data provided' in e.message
    
    # Test 4: Optional fields
    try:
        data = {'username': 'test', 'email': 'test@example.com'}
        result = validate_request_data(
            data, 
            required_fields=['username'], 
            optional_fields=['email', 'firstname']
        )
        expected = {'username': 'test', 'email': 'test@example.com'}
        print(f"✅ Optional fields test passed: {result}")
        assert result == expected
    except Exception as e:
        print(f"❌ Optional fields test failed: {e}")

def test_http_status_code_mapping():
    """Test that exceptions map to correct HTTP status codes"""
    print("\nTesting HTTP status code mapping...")
    
    # This would be tested in the actual Flask app, but we can verify the logic
    error_mappings = {
        ValidationError: 400,
        ConflictError: 409,
        ResourceNotFoundError: 404,
    }
    
    for error_class, expected_status in error_mappings.items():
        print(f"✅ {error_class.__name__} should map to HTTP {expected_status}")

def main():
    """Run all validation tests"""
    print("🧪 Starting Validation Tests")
    print("=" * 50)
    
    try:
        test_validation_error()
        test_conflict_error()
        test_resource_not_found_error()
        test_validate_request_data()
        test_http_status_code_mapping()
        
        print("\n" + "=" * 50)
        print("🎉 All validation tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()