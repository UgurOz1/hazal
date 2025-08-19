# Request validation middleware for Flask User Management Application

import logging
from functools import wraps
from flask import request, current_app, g
from werkzeug.exceptions import BadRequest
from exceptions import ValidationError, DatabaseError
from validation import (
    validate_request_data_enhanced, InputSanitizer, InputValidator,
    RequestValidator
)
from security import SecurityMiddleware, SQLSecurityManager

class RequestValidationMiddleware:
    """
    Comprehensive request validation middleware
    Implements security controls and input validation for all API endpoints
    """
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
    
    def before_request(self):
        """Execute before each request"""
        try:
            # Skip validation for certain endpoints
            if self._should_skip_validation():
                return
            
            # Validate request size
            self._validate_request_size()
            
            # Validate content type for POST/PUT requests
            self._validate_content_type()
            
            # Validate request headers
            self._validate_request_headers()
            
            # Validate and sanitize JSON payload
            if request.is_json and request.get_json(silent=True) is not None:
                self._validate_json_payload()
            
            # Log request for security monitoring
            self._log_request()
            
        except Exception as e:
            current_app.logger.error(f"Request validation failed: {str(e)}")
            raise
    
    def after_request(self, response):
        """Execute after each request"""
        try:
            # Add security headers
            self._add_security_headers(response)
            
            # Log response for security monitoring
            self._log_response(response)
            
            return response
        except Exception as e:
            current_app.logger.error(f"Response processing failed: {str(e)}")
            return response
    
    def _should_skip_validation(self):
        """Check if validation should be skipped for this endpoint"""
        # Skip validation for health checks, static files, etc.
        skip_endpoints = ['/health', '/static']
        return any(request.path.startswith(endpoint) for endpoint in skip_endpoints)
    
    def _validate_request_size(self):
        """Validate request size to prevent DoS attacks"""
        max_size = current_app.config.get('MAX_CONTENT_LENGTH', 1024 * 1024)  # 1MB default
        
        if request.content_length is not None and max_size is not None and request.content_length > max_size:
            SecurityMiddleware.log_security_event(
                'REQUEST_TOO_LARGE',
                f"Request size {request.content_length} exceeds limit {max_size}",
                'WARNING'
            )
            raise ValidationError("Request payload too large", constraint='size')
    
    def _validate_content_type(self):
        """Validate content type for requests with body"""
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.content_type
            
            if not content_type:
                raise ValidationError("Content-Type header is required", field='content_type')
            
            # Only allow JSON for API endpoints
            if not content_type.startswith('application/json'):
                SecurityMiddleware.log_security_event(
                    'INVALID_CONTENT_TYPE',
                    f"Invalid content type: {content_type}",
                    'WARNING'
                )
                raise ValidationError(
                    "Only application/json content type is supported",
                    field='content_type',
                    constraint='format'
                )
    
    def _validate_request_headers(self):
        """Validate request headers for security"""
        # Check for suspicious headers
        for header_name, header_value in request.headers:
            if isinstance(header_value, str):
                # Check for SQL injection patterns in headers
                if InputSanitizer.detect_sql_injection(header_value):
                    SecurityMiddleware.log_security_event(
                        'SUSPICIOUS_HEADER_SQL',
                        f"SQL injection pattern in header {header_name}: {header_value}",
                        'ERROR'
                    )
                    raise ValidationError("Suspicious request headers detected")
                
                # Check for XSS patterns in headers
                if InputSanitizer.detect_xss(header_value):
                    SecurityMiddleware.log_security_event(
                        'SUSPICIOUS_HEADER_XSS',
                        f"XSS pattern in header {header_name}: {header_value}",
                        'ERROR'
                    )
                    raise ValidationError("Suspicious request headers detected")
        
        # Validate User-Agent if present
        user_agent = request.headers.get('User-Agent', '')
        if user_agent and len(user_agent) > 500:
            SecurityMiddleware.log_security_event(
                'SUSPICIOUS_USER_AGENT',
                f"Unusually long User-Agent: {user_agent[:100]}...",
                'WARNING'
            )
    
    def _validate_json_payload(self):
        """Validate and sanitize JSON payload"""
        try:
            json_data = request.get_json()
            
            if json_data is None:
                return
            
            # Validate JSON structure
            if not isinstance(json_data, dict):
                raise ValidationError("JSON payload must be an object")
            
            # Check JSON depth to prevent deeply nested attacks
            self._validate_json_depth(json_data)
            
            # Validate and sanitize all string values in JSON
            sanitized_data = self._sanitize_json_data(json_data)
            
            # Store sanitized data for use in routes
            g.validated_json = sanitized_data
            
        except ValueError as e:
            raise ValidationError(f"Invalid JSON format: {str(e)}")
    
    def _validate_json_depth(self, data, current_depth=0, max_depth=10):
        """Validate JSON nesting depth to prevent attacks"""
        if current_depth > max_depth:
            SecurityMiddleware.log_security_event(
                'JSON_TOO_DEEP',
                f"JSON nesting depth exceeds {max_depth}",
                'WARNING'
            )
            raise ValidationError("JSON nesting too deep", constraint='depth')
        
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, (dict, list)):
                    self._validate_json_depth(value, current_depth + 1, max_depth)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._validate_json_depth(item, current_depth + 1, max_depth)
    
    def _sanitize_json_data(self, data):
        """Recursively sanitize JSON data"""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Sanitize key
                if isinstance(key, str):
                    sanitized_key = InputSanitizer.sanitize_string(key, 100)
                    
                    # Check for suspicious patterns in keys
                    if InputSanitizer.detect_sql_injection(key):
                        SecurityMiddleware.log_security_event(
                            'SUSPICIOUS_JSON_KEY',
                            f"SQL injection pattern in JSON key: {key}",
                            'ERROR'
                        )
                        raise ValidationError("Suspicious data detected in request")
                    
                    if InputSanitizer.detect_xss(key):
                        SecurityMiddleware.log_security_event(
                            'SUSPICIOUS_JSON_KEY',
                            f"XSS pattern in JSON key: {key}",
                            'ERROR'
                        )
                        raise ValidationError("Suspicious data detected in request")
                else:
                    sanitized_key = key
                
                # Recursively sanitize value
                sanitized[sanitized_key] = self._sanitize_json_data(value)
            return sanitized
        
        elif isinstance(data, list):
            return [self._sanitize_json_data(item) for item in data]
        
        elif isinstance(data, str):
            # Check for suspicious patterns in string values
            if InputSanitizer.detect_sql_injection(data):
                SecurityMiddleware.log_security_event(
                    'SUSPICIOUS_JSON_VALUE',
                    f"SQL injection pattern in JSON value: {data[:100]}",
                    'ERROR'
                )
                raise ValidationError("Suspicious data detected in request")
            
            if InputSanitizer.detect_xss(data):
                SecurityMiddleware.log_security_event(
                    'SUSPICIOUS_JSON_VALUE',
                    f"XSS pattern in JSON value: {data[:100]}",
                    'ERROR'
                )
                raise ValidationError("Suspicious data detected in request")
            
            # Return original string for passwords, sanitize others based on context
            # This will be handled by specific validators later
            return data
        
        else:
            # Return non-string values as-is (numbers, booleans, null)
            return data
    
    def _log_request(self):
        """Log request for security monitoring"""
        SecurityMiddleware.log_security_event(
            'REQUEST_RECEIVED',
            f"{request.method} {request.path} from {request.remote_addr}"
        )
    
    def _log_response(self, response):
        """Log response for security monitoring"""
        if response.status_code >= 400:
            SecurityMiddleware.log_security_event(
                'ERROR_RESPONSE',
                f"HTTP {response.status_code} for {request.method} {request.path}",
                'WARNING'
            )
    
    def _add_security_headers(self, response):
        """Add security headers to response"""
        # Prevent XSS attacks
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Content Security Policy
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        
        # Prevent information disclosure
        response.headers.pop('Server', None)
        
        return response

def validate_endpoint_data(validation_type='generic', required_fields=None, optional_fields=None):
    """
    Decorator for endpoint-specific data validation
    Integrates with the middleware for comprehensive validation
    
    Args:
        validation_type: Type of validation ('user_data', 'login', 'generic')
        required_fields: List of required fields for generic validation
        optional_fields: List of optional fields for generic validation
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get JSON data (use sanitized version from middleware if available)
                json_data = getattr(g, 'validated_json', None) or request.get_json()
                
                if json_data is None and request.method in ['POST', 'PUT', 'PATCH']:
                    raise ValidationError("JSON data is required for this endpoint")
                
                # Apply specific validation based on type
                if json_data:
                    validated_data = validate_request_data_enhanced(
                        json_data,
                        required_fields=required_fields,
                        optional_fields=optional_fields,
                        validation_type=validation_type
                    )
                    
                    # Store validated data for use in the endpoint
                    g.validated_data = validated_data
                
                return f(*args, **kwargs)
                
            except ValidationError:
                raise
            except Exception as e:
                current_app.logger.error(f"Endpoint validation failed: {str(e)}")
                raise ValidationError(f"Request validation failed: {str(e)}")
        
        return decorated_function
    return decorator

def get_validated_data():
    """
    Helper function to get validated data in route handlers
    Returns the validated and sanitized request data
    """
    return getattr(g, 'validated_data', {})

def validate_path_parameter(param_name, param_value, param_type='string', max_length=None):
    """
    Validate path parameters for security
    
    Args:
        param_name: Name of the parameter
        param_value: Value of the parameter
        param_type: Expected type ('string', 'integer', 'email', 'username')
        max_length: Maximum length for string parameters
    """
    try:
        if param_value is None:
            raise ValidationError(f"Path parameter {param_name} is required")
        
        # Convert to string for validation
        str_value = str(param_value)
        
        # Check for suspicious patterns
        if InputSanitizer.detect_sql_injection(str_value):
            SecurityMiddleware.log_security_event(
                'SUSPICIOUS_PATH_PARAM',
                f"SQL injection pattern in path parameter {param_name}: {str_value}",
                'ERROR'
            )
            raise ValidationError(f"Invalid path parameter: {param_name}")
        
        if InputSanitizer.detect_xss(str_value):
            SecurityMiddleware.log_security_event(
                'SUSPICIOUS_PATH_PARAM',
                f"XSS pattern in path parameter {param_name}: {str_value}",
                'ERROR'
            )
            raise ValidationError(f"Invalid path parameter: {param_name}")
        
        # Type-specific validation
        if param_type == 'integer':
            try:
                int_value = int(param_value)
                if int_value < 1:
                    raise ValidationError(f"Path parameter {param_name} must be positive")
                return int_value
            except ValueError:
                raise ValidationError(f"Path parameter {param_name} must be an integer")
        
        elif param_type == 'email':
            if not InputValidator.validate_email(str_value):
                raise ValidationError(f"Path parameter {param_name} must be a valid email")
            return InputSanitizer.sanitize_email(str_value)
        
        elif param_type == 'username':
            sanitized = InputSanitizer.sanitize_username(str_value)
            is_valid, message = InputValidator.validate_username(sanitized)
            if not is_valid:
                raise ValidationError(f"Path parameter {param_name}: {message}")
            return sanitized
        
        else:  # string type
            if max_length and len(str_value) > max_length:
                raise ValidationError(f"Path parameter {param_name} exceeds maximum length")
            
            return InputSanitizer.sanitize_string(str_value, max_length)
    
    except ValidationError:
        raise
    except Exception as e:
        # Handle case where we're outside application context (e.g., in tests)
        try:
            current_app.logger.error(f"Path parameter validation failed: {str(e)}")
        except RuntimeError:
            # We're outside application context, just continue
            pass
        raise ValidationError(f"Invalid path parameter: {param_name}")

class DatabaseValidationMiddleware:
    """
    Middleware for database operation validation
    Implements SQLAlchemy best practices and security controls
    """
    
    @staticmethod
    def validate_before_insert(model_instance):
        """Validate model before database insert"""
        try:
            # Use SQLSecurityManager for validation
            SQLSecurityManager.validate_model_data(model_instance)
            
            # Additional model-specific validation
            if hasattr(model_instance, 'validate'):
                model_instance.validate()
            
            return True
        except Exception as e:
            current_app.logger.error(f"Database insert validation failed: {str(e)}")
            raise ValidationError(f"Data validation failed: {str(e)}")
    
    @staticmethod
    def validate_before_update(model_instance, updated_fields=None):
        """Validate model before database update"""
        try:
            # Use SQLSecurityManager for validation
            SQLSecurityManager.validate_model_data(model_instance)
            
            # Additional validation for updated fields
            if updated_fields and hasattr(model_instance, 'validate_update'):
                model_instance.validate_update(updated_fields)
            
            return True
        except Exception as e:
            current_app.logger.error(f"Database update validation failed: {str(e)}")
            raise ValidationError(f"Data validation failed: {str(e)}")
    
    @staticmethod
    def safe_query_execution(query_func, *args, **kwargs):
        """
        Safely execute database queries with validation
        Wraps query execution with security checks
        """
        try:
            # Log query execution for monitoring
            SecurityMiddleware.log_security_event(
                'DATABASE_QUERY',
                f"Executing database query: {query_func.__name__}"
            )
            
            # Execute query
            result = query_func(*args, **kwargs)
            
            return result
        except Exception as e:
            current_app.logger.error(f"Database query execution failed: {str(e)}")
            raise DatabaseError(f"Database operation failed: {str(e)}")

# Global middleware instance
request_validation_middleware = RequestValidationMiddleware()