# Input validation and sanitization utilities for Flask User Management Application

import re
import html
import bleach
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from exceptions import ValidationError

class InputValidator:
    """Comprehensive input validation class"""
    
    # Validation patterns
    EMAIL_PATTERN = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    USERNAME_PATTERN = r'^[a-zA-Z0-9_]{3,80}$'
    NAME_PATTERN = r'^[a-zA-ZÀ-ÿ\s\-\'\.]{1,100}$'
    DATE_PATTERN = r'^\d{4}-\d{2}-\d{2}$'
    IP_V4_PATTERN = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    IP_V6_PATTERN = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    
    # Dangerous patterns for SQL injection detection
    SQL_INJECTION_PATTERNS = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)',
        r'(--|#|/\*|\*/)',
        r'(\bOR\b\s*[\'"]?\s*[\'"]?\s*=\s*[\'"]?\s*[\'"]?)',
        r'(\bAND\b\s*[\'"]?\s*[\'"]?\s*=\s*[\'"]?\s*[\'"]?)',
        r'([\'"][^\'\"]*[\'\"]\s*=\s*[\'"][^\'\"]*[\'"])',
        r'(\;.*\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
        r'([\'"].*[\'"].*OR.*[\'"].*[\'"])',
        r'(1\s*=\s*1)',
        r'([\'"].*[\'"].*=.*[\'"].*[\'"])',
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
    ]
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format with comprehensive checks
        Requirements: 4.4, 6.4
        """
        if not email or not isinstance(email, str):
            return False
        
        # Basic format check
        if not re.match(InputValidator.EMAIL_PATTERN, email):
            return False
        
        # Additional security checks
        email = email.strip().lower()
        
        # Check for dangerous patterns
        if '..' in email or email.startswith('.') or email.endswith('.'):
            return False
        if email.startswith('@') or email.endswith('@'):
            return False
        if '@.' in email or '.@' in email:
            return False
        
        # Check length constraints
        if len(email) > 120 or len(email) < 5:
            return False
        
        # Check for multiple @ symbols
        if email.count('@') != 1:
            return False
        
        return True
    
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """
        Validate password with comprehensive security checks
        Requirements: 4.2, 4.3, 6.5
        """
        if not password or not isinstance(password, str):
            return False, "Password is required"
        
        # Length check (4.2)
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password cannot exceed 128 characters"
        
        # Complexity check (4.3)
        has_letter = bool(re.search(r'[a-zA-Z]', password))
        has_number = bool(re.search(r'\d', password))
        
        if not has_letter:
            return False, "Password must contain at least one letter"
        
        if not has_number:
            return False, "Password must contain at least one number"
        
        # Additional security checks for very weak patterns only
        # Check for common weak patterns (but be less strict)
        weak_patterns = [
            r'(.)\1{4,}',  # Repeated characters (aaaaa - 5 or more)
            r'(01234|12345|23456|34567|45678|56789)',  # Sequential numbers (5+ chars)
            r'(abcde|bcdef|cdefg|defgh|efghi|fghij|ghijk|hijkl|ijklm|jklmn|klmno|lmnop|mnopq|nopqr|opqrs|pqrst|qrstu|rstuv|stuvw|tuvwx|uvwxy|vwxyz)',  # Sequential letters (5+ chars)
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, password.lower()):
                return False, "Password contains very weak patterns"
        
        return True, "Password is valid"
    
    @staticmethod
    def validate_username(username: str) -> tuple[bool, str]:
        """Validate username format and security"""
        if not username or not isinstance(username, str):
            return False, "Username is required"
        
        username = username.strip()
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username) > 80:
            return False, "Username cannot exceed 80 characters"
        
        if not re.match(InputValidator.USERNAME_PATTERN, username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        # Check for reserved usernames
        reserved_usernames = [
            'admin', 'administrator', 'root', 'system', 'user', 'guest',
            'api', 'www', 'mail', 'ftp', 'test', 'demo', 'null', 'undefined'
        ]
        
        if username.lower() in reserved_usernames:
            return False, "Username is reserved"
        
        return True, "Username is valid"
    
    @staticmethod
    def validate_name(name: str, field_name: str = "Name") -> tuple[bool, str]:
        """Validate first name and last name"""
        if not name or not isinstance(name, str):
            return False, f"{field_name} is required"
        
        name = name.strip()
        
        if len(name) < 1:
            return False, f"{field_name} cannot be empty"
        
        if len(name) > 100:
            return False, f"{field_name} cannot exceed 100 characters"
        
        if not re.match(InputValidator.NAME_PATTERN, name):
            return False, f"{field_name} contains invalid characters"
        
        return True, f"{field_name} is valid"
    
    @staticmethod
    def validate_date(date_str: str, field_name: str = "Date") -> tuple[bool, str]:
        """Validate date format and value"""
        if not date_str or not isinstance(date_str, str):
            return False, f"{field_name} is required"
        
        # Check format
        if not re.match(InputValidator.DATE_PATTERN, date_str):
            return False, f"{field_name} must be in YYYY-MM-DD format"
        
        # Try to parse the date
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return False, f"Invalid {field_name.lower()}"
        
        # Additional validation for birthdate
        if field_name.lower() == "birthdate":
            today = datetime.now().date()
            
            # Check if date is in the future
            if date_obj > today:
                return False, "Birthdate cannot be in the future"
            
            # Check if date is too old (more than 150 years ago)
            if (today - date_obj).days > 150 * 365:
                return False, "Birthdate is too old"
        
        return True, f"{field_name} is valid"
    
    @staticmethod
    def validate_ip_address(ip_address: str) -> tuple[bool, str]:
        """Validate IP address format"""
        if not ip_address or not isinstance(ip_address, str):
            return False, "IP address is required"
        
        ip_address = ip_address.strip()
        
        # Check IPv4
        if re.match(InputValidator.IP_V4_PATTERN, ip_address):
            return True, "Valid IPv4 address"
        
        # Check IPv6
        if re.match(InputValidator.IP_V6_PATTERN, ip_address):
            return True, "Valid IPv6 address"
        
        return False, "Invalid IP address format"

class InputSanitizer:
    """Input sanitization utilities"""
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: int = None) -> str:
        """Sanitize string input to prevent XSS and other attacks"""
        if not input_str or not isinstance(input_str, str):
            return ""
        
        # HTML escape
        sanitized = html.escape(input_str.strip())
        
        # Use bleach for additional XSS protection
        sanitized = bleach.clean(sanitized, tags=[], attributes={}, strip=True)
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate if max_length is specified
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    @staticmethod
    def sanitize_email(email: str) -> str:
        """Sanitize email input"""
        if not email or not isinstance(email, str):
            return ""
        
        # Basic sanitization
        email = email.strip().lower()
        
        # Remove dangerous characters
        email = re.sub(r'[<>"\'\\\x00-\x1f\x7f-\x9f]', '', email)
        
        return email
    
    @staticmethod
    def sanitize_username(username: str) -> str:
        """Sanitize username input"""
        if not username or not isinstance(username, str):
            return ""
        
        # Remove whitespace and convert to lowercase
        username = username.strip().lower()
        
        # Remove any characters that aren't alphanumeric or underscore
        username = re.sub(r'[^a-z0-9_]', '', username)
        
        return username
    
    @staticmethod
    def detect_sql_injection(input_str: str) -> bool:
        """Detect potential SQL injection attempts"""
        if not input_str or not isinstance(input_str, str):
            return False
        
        input_lower = input_str.lower()
        
        for pattern in InputValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_lower, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def detect_xss(input_str: str) -> bool:
        """Detect potential XSS attempts"""
        if not input_str or not isinstance(input_str, str):
            return False
        
        input_lower = input_str.lower()
        
        for pattern in InputValidator.XSS_PATTERNS:
            if re.search(pattern, input_lower, re.IGNORECASE):
                return True
        
        return False

class RequestValidator:
    """Request-level validation middleware"""
    
    @staticmethod
    def validate_json_request(data: Any) -> Dict[str, Any]:
        """Validate that request contains valid JSON data"""
        if data is None:
            raise ValidationError("No JSON data provided")
        
        if not isinstance(data, dict):
            raise ValidationError("Invalid JSON data format - expected object")
        
        return data
    
    @staticmethod
    def validate_and_sanitize_user_data(data: Dict[str, Any], is_update: bool = False) -> Dict[str, Any]:
        """
        Comprehensive validation and sanitization for user data
        Used in user creation and update endpoints
        """
        validated_data = {}
        
        # Username validation (required for creation, optional for update)
        if 'username' in data:
            username = data['username']
            
            # Security checks
            if InputSanitizer.detect_sql_injection(str(username)):
                raise ValidationError("Invalid username - contains suspicious patterns", field='username')
            
            if InputSanitizer.detect_xss(str(username)):
                raise ValidationError("Invalid username - contains suspicious patterns", field='username')
            
            # Sanitize and validate
            sanitized_username = InputSanitizer.sanitize_username(str(username))
            is_valid, message = InputValidator.validate_username(sanitized_username)
            
            if not is_valid:
                raise ValidationError(message, field='username')
            
            validated_data['username'] = sanitized_username
        
        # First name validation
        if 'firstname' in data:
            firstname = data['firstname']
            
            # Security checks
            if InputSanitizer.detect_xss(str(firstname)):
                raise ValidationError("Invalid first name - contains suspicious patterns", field='firstname')
            
            # Sanitize and validate
            sanitized_firstname = InputSanitizer.sanitize_string(str(firstname), 100)
            is_valid, message = InputValidator.validate_name(sanitized_firstname, "First name")
            
            if not is_valid:
                raise ValidationError(message, field='firstname')
            
            validated_data['firstname'] = sanitized_firstname
        
        # Last name validation
        if 'lastname' in data:
            lastname = data['lastname']
            
            # Security checks
            if InputSanitizer.detect_xss(str(lastname)):
                raise ValidationError("Invalid last name - contains suspicious patterns", field='lastname')
            
            # Sanitize and validate
            sanitized_lastname = InputSanitizer.sanitize_string(str(lastname), 100)
            is_valid, message = InputValidator.validate_name(sanitized_lastname, "Last name")
            
            if not is_valid:
                raise ValidationError(message, field='lastname')
            
            validated_data['lastname'] = sanitized_lastname
        
        # Email validation
        if 'email' in data:
            email = data['email']
            
            # Security checks
            if InputSanitizer.detect_sql_injection(str(email)):
                raise ValidationError("Invalid email - contains suspicious patterns", field='email')
            
            if InputSanitizer.detect_xss(str(email)):
                raise ValidationError("Invalid email - contains suspicious patterns", field='email')
            
            # Sanitize and validate
            sanitized_email = InputSanitizer.sanitize_email(str(email))
            
            if not InputValidator.validate_email(sanitized_email):
                raise ValidationError("Invalid email format", field='email', constraint='format')
            
            validated_data['email'] = sanitized_email
        
        # Password validation
        if 'password' in data:
            password = str(data['password'])
            
            # Security checks
            if InputSanitizer.detect_sql_injection(password):
                raise ValidationError("Invalid password - contains suspicious patterns", field='password')
            
            # Validate password (no sanitization for passwords to preserve exact input)
            is_valid, message = InputValidator.validate_password(password)
            
            if not is_valid:
                raise ValidationError(message, field='password', constraint='complexity')
            
            validated_data['password'] = password
        
        # Birthdate validation
        if 'birthdate' in data:
            birthdate = data['birthdate']
            
            # Sanitize and validate
            sanitized_birthdate = InputSanitizer.sanitize_string(str(birthdate), 10)
            is_valid, message = InputValidator.validate_date(sanitized_birthdate, "Birthdate")
            
            if not is_valid:
                raise ValidationError(message, field='birthdate', constraint='format')
            
            validated_data['birthdate'] = sanitized_birthdate
        
        return validated_data
    
    @staticmethod
    def validate_login_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate login request data"""
        validated_data = {}
        
        # Username validation
        if 'username' not in data:
            raise ValidationError("Username is required", field='username', constraint='required')
        
        username = data['username']
        
        # Security checks
        if InputSanitizer.detect_sql_injection(str(username)):
            raise ValidationError("Invalid username", field='username')
        
        if InputSanitizer.detect_xss(str(username)):
            raise ValidationError("Invalid username", field='username')
        
        # Sanitize
        sanitized_username = InputSanitizer.sanitize_username(str(username))
        
        if not sanitized_username:
            raise ValidationError("Username cannot be empty", field='username')
        
        validated_data['username'] = sanitized_username
        
        # Password validation
        if 'password' not in data:
            raise ValidationError("Password is required", field='password', constraint='required')
        
        password = str(data['password'])
        
        # Basic security check (don't sanitize passwords)
        if InputSanitizer.detect_sql_injection(password):
            raise ValidationError("Invalid password", field='password')
        
        if not password:
            raise ValidationError("Password cannot be empty", field='password')
        
        validated_data['password'] = password
        
        return validated_data

def validate_request_data_enhanced(data: Any, required_fields: List[str] = None, 
                                 optional_fields: List[str] = None, 
                                 validation_type: str = 'generic') -> Dict[str, Any]:
    """
    Enhanced request data validation middleware
    Replaces the basic validate_request_data function with comprehensive security checks
    """
    # Basic JSON validation
    validated_data = RequestValidator.validate_json_request(data)
    
    # Apply specific validation based on type
    if validation_type == 'user_data':
        return RequestValidator.validate_and_sanitize_user_data(validated_data)
    elif validation_type == 'login':
        return RequestValidator.validate_login_data(validated_data)
    
    # Generic validation with field requirements
    result = {}
    
    # Check required fields
    if required_fields:
        missing_fields = []
        for field in required_fields:
            if field not in validated_data or validated_data[field] is None:
                missing_fields.append(field)
            else:
                # Basic sanitization for required fields
                value = validated_data[field]
                if isinstance(value, str):
                    # Security checks
                    if InputSanitizer.detect_sql_injection(value):
                        raise ValidationError(f"Invalid {field} - contains suspicious patterns", field=field)
                    if InputSanitizer.detect_xss(value):
                        raise ValidationError(f"Invalid {field} - contains suspicious patterns", field=field)
                    
                    # Sanitize
                    result[field] = InputSanitizer.sanitize_string(value)
                else:
                    result[field] = value
        
        if missing_fields:
            raise ValidationError(
                f"Missing required fields: {', '.join(missing_fields)}",
                field='multiple',
                constraint='required'
            )
    
    # Add optional fields if present
    if optional_fields:
        for field in optional_fields:
            if field in validated_data and validated_data[field] is not None:
                value = validated_data[field]
                if isinstance(value, str):
                    # Security checks
                    if InputSanitizer.detect_sql_injection(value):
                        raise ValidationError(f"Invalid {field} - contains suspicious patterns", field=field)
                    if InputSanitizer.detect_xss(value):
                        raise ValidationError(f"Invalid {field} - contains suspicious patterns", field=field)
                    
                    # Sanitize
                    result[field] = InputSanitizer.sanitize_string(value)
                else:
                    result[field] = value
    
    return result