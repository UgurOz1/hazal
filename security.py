# Security utilities and SQLAlchemy best practices for Flask User Management Application

import logging
from functools import wraps
from flask import request, current_app
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from models import db
from exceptions import ValidationError, DatabaseError
from validation import InputSanitizer

class SQLSecurityManager:
    """SQLAlchemy security best practices implementation"""
    
    @staticmethod
    def safe_query_filter(model_class, **filters):
        """
        Safe query filtering with parameter binding to prevent SQL injection
        Always use this instead of string concatenation in queries
        """
        try:
            query = model_class.query
            
            for field, value in filters.items():
                # Validate field name to prevent injection
                if not hasattr(model_class, field):
                    raise ValidationError(f"Invalid field: {field}")
                
                # Additional security: validate field name format
                if not field.replace('_', '').isalnum():
                    raise ValidationError(f"Invalid field name format: {field}")
                
                # Validate value for suspicious patterns
                if isinstance(value, str):
                    if InputSanitizer.detect_sql_injection(value):
                        raise ValidationError(f"Suspicious value detected for field {field}")
                    if InputSanitizer.detect_xss(value):
                        raise ValidationError(f"Suspicious value detected for field {field}")
                
                # Use SQLAlchemy's parameter binding
                query = query.filter(getattr(model_class, field) == value)
            
            return query
        except SQLAlchemyError as e:
            current_app.logger.error(f"Safe query filter error: {str(e)}")
            raise DatabaseError(f"Query failed: {str(e)}")
    
    @staticmethod
    def safe_raw_query(query_string, parameters=None):
        """
        Execute raw SQL queries safely with parameter binding
        Only use when ORM queries are not sufficient
        """
        try:
            if parameters is None:
                parameters = {}
            
            # Validate that query doesn't contain dangerous patterns
            if SQLSecurityManager._contains_dangerous_sql(query_string):
                raise ValidationError("Query contains potentially dangerous SQL patterns")
            
            # Validate parameters for suspicious content
            for param_name, param_value in parameters.items():
                if isinstance(param_value, str):
                    if InputSanitizer.detect_sql_injection(param_value):
                        raise ValidationError(f"Suspicious parameter value: {param_name}")
                    if InputSanitizer.detect_xss(param_value):
                        raise ValidationError(f"Suspicious parameter value: {param_name}")
            
            # Log raw query execution for security monitoring
            current_app.logger.info(f"Executing raw SQL query: {query_string[:100]}...")
            
            # Use SQLAlchemy's text() with parameter binding
            result = db.session.execute(text(query_string), parameters)
            return result
        except SQLAlchemyError as e:
            current_app.logger.error(f"Safe raw query error: {str(e)}")
            raise DatabaseError(f"Raw query failed: {str(e)}")
    
    @staticmethod
    def _contains_dangerous_sql(query_string):
        """Check if query contains dangerous SQL patterns"""
        dangerous_patterns = [
            'drop table', 'delete from', 'truncate table', 'alter table',
            'create table', 'insert into', 'update.*set',
            '--', '/*', '*/', 'xp_', 'sp_', 'exec ', 'execute ',
            'union select', 'information_schema', 'sys.', 'master.',
            'pg_', 'mysql.', 'sqlite_master', 'dual', 'waitfor delay',
            'benchmark(', 'sleep(', 'load_file(', 'into outfile',
            'into dumpfile', 'load data', ';select', ';insert',
            ';update', ';delete', ';drop', ';create', ';alter'
        ]
        
        query_lower = query_string.lower()
        
        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if pattern in query_lower:
                return True
        
        # Check for SQL injection patterns using regex
        import re
        injection_patterns = [
            r'\b(union)\s+(select)\b',
            r'[\'\"]\s*(or|and)\s*[\'\"]\s*=\s*[\'\"]\s*(or|and)',
            r'[\'\"]\s*(or|and)\s*\d+\s*=\s*\d+',
            r';\s*(select|insert|update|delete|drop|create|alter)\b',
            r'\b(drop|delete|truncate|alter)\s+(table|from)\b',
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, query_lower, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def validate_model_data(model_instance):
        """
        Validate model data before database operations
        Ensures data integrity and prevents malicious data
        """
        try:
            # Check if model has validation methods
            if hasattr(model_instance, 'validate'):
                model_instance.validate()
            
            # Additional security checks for common fields
            for attr_name in dir(model_instance):
                if not attr_name.startswith('_'):
                    attr_value = getattr(model_instance, attr_name)
                    
                    if isinstance(attr_value, str):
                        # Check for SQL injection patterns
                        if InputSanitizer.detect_sql_injection(attr_value):
                            raise ValidationError(f"Field {attr_name} contains suspicious patterns")
                        
                        # Check for XSS patterns
                        if InputSanitizer.detect_xss(attr_value):
                            raise ValidationError(f"Field {attr_name} contains suspicious patterns")
            
            return True
        except Exception as e:
            current_app.logger.warning(f"Model validation failed: {str(e)}")
            raise ValidationError(f"Data validation failed: {str(e)}")

class DatabaseConnectionManager:
    """Secure database connection management"""
    
    @staticmethod
    def execute_transaction(operations):
        """
        Execute multiple database operations in a secure transaction
        Automatically handles rollback on errors
        """
        try:
            db.session.begin()
            
            results = []
            for operation in operations:
                result = operation()
                results.append(result)
            
            db.session.commit()
            return results
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Transaction failed: {str(e)}")
            raise DatabaseError(f"Transaction failed: {str(e)}")
    
    @staticmethod
    def safe_bulk_insert(model_class, data_list):
        """
        Safely insert multiple records with validation
        """
        try:
            validated_instances = []
            
            for data in data_list:
                instance = model_class(**data)
                SQLSecurityManager.validate_model_data(instance)
                validated_instances.append(instance)
            
            db.session.bulk_save_objects(validated_instances)
            db.session.commit()
            
            return len(validated_instances)
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Bulk insert failed: {str(e)}")
            raise DatabaseError(f"Bulk insert failed: {str(e)}")

class SecurityMiddleware:
    """Security middleware for request processing"""
    
    @staticmethod
    def log_security_event(event_type, details, severity='INFO'):
        """Log security-related events"""
        logger = current_app.logger
        
        log_message = f"SECURITY EVENT [{event_type}]: {details}"
        
        if severity == 'ERROR':
            logger.error(log_message)
        elif severity == 'WARNING':
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    @staticmethod
    def validate_request_source(request):
        """Validate request source and headers"""
        # Check for suspicious headers
        suspicious_headers = [
            'x-forwarded-for', 'x-real-ip', 'x-originating-ip',
            'x-remote-ip', 'x-remote-addr'
        ]
        
        for header in suspicious_headers:
            if header in request.headers:
                value = request.headers.get(header)
                if InputSanitizer.detect_sql_injection(value) or InputSanitizer.detect_xss(value):
                    SecurityMiddleware.log_security_event(
                        'SUSPICIOUS_HEADER',
                        f"Suspicious header {header}: {value}",
                        'WARNING'
                    )
                    raise ValidationError("Suspicious request headers detected")
        
        return True

def security_required(f):
    """
    Decorator to add security checks to route functions
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Validate request source
            SecurityMiddleware.validate_request_source(request)
            
            # Log request for security monitoring
            SecurityMiddleware.log_security_event(
                'API_REQUEST',
                f"Request to {request.endpoint} from {request.remote_addr}"
            )
            
            return f(*args, **kwargs)
        except Exception as e:
            SecurityMiddleware.log_security_event(
                'SECURITY_VIOLATION',
                f"Security check failed for {request.endpoint}: {str(e)}",
                'ERROR'
            )
            raise
    
    return decorated_function

def rate_limit_check(max_requests=100, window_minutes=60):
    """
    Simple rate limiting decorator (basic implementation)
    In production, use Redis or similar for distributed rate limiting
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Basic rate limiting logic would go here
            # For now, just log the request
            SecurityMiddleware.log_security_event(
                'RATE_LIMIT_CHECK',
                f"Rate limit check for {request.remote_addr}"
            )
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class QuerySecurityHelper:
    """Helper class for secure database queries"""
    
    @staticmethod
    def safe_user_lookup(username=None, email=None, user_id=None):
        """
        Safely lookup user by various criteria
        Uses parameter binding to prevent SQL injection
        """
        from models import User
        
        try:
            query = User.query
            
            if user_id is not None:
                # Validate user_id is integer
                try:
                    user_id = int(user_id)
                except (ValueError, TypeError):
                    raise ValidationError("Invalid user ID format")
                
                return query.filter(User.id == user_id).first()
            
            if username is not None:
                # Sanitize username
                username = InputSanitizer.sanitize_username(str(username))
                if not username:
                    raise ValidationError("Invalid username")
                
                return query.filter(User.username == username).first()
            
            if email is not None:
                # Sanitize email
                email = InputSanitizer.sanitize_email(str(email))
                if not email:
                    raise ValidationError("Invalid email")
                
                return query.filter(User.email == email).first()
            
            raise ValidationError("No valid lookup criteria provided")
        
        except SQLAlchemyError as e:
            current_app.logger.error(f"User lookup failed: {str(e)}")
            raise DatabaseError(f"User lookup failed: {str(e)}")
    
    @staticmethod
    def safe_online_user_operations(username, operation='get'):
        """
        Safely perform operations on online users table
        """
        from models import OnlineUser
        
        try:
            # Sanitize username
            username = InputSanitizer.sanitize_username(str(username))
            if not username:
                raise ValidationError("Invalid username")
            
            if operation == 'get':
                return OnlineUser.query.filter(OnlineUser.username == username).first()
            elif operation == 'delete':
                online_user = OnlineUser.query.filter(OnlineUser.username == username).first()
                if online_user:
                    db.session.delete(online_user)
                return online_user
            else:
                raise ValidationError(f"Invalid operation: {operation}")
        
        except SQLAlchemyError as e:
            current_app.logger.error(f"Online user operation failed: {str(e)}")
            raise DatabaseError(f"Online user operation failed: {str(e)}")

# Configuration for security settings
SECURITY_CONFIG = {
    'MAX_REQUEST_SIZE': 1024 * 1024,  # 1MB
    'MAX_JSON_PAYLOAD_SIZE': 16 * 1024,  # 16KB
    'ALLOWED_CONTENT_TYPES': ['application/json'],
    'RATE_LIMIT_REQUESTS': 100,
    'RATE_LIMIT_WINDOW': 3600,  # 1 hour in seconds
    'LOG_SECURITY_EVENTS': True,
    'STRICT_VALIDATION': True
}