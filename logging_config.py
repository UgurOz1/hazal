# Comprehensive logging configuration for Flask User Management Application

import os
import logging
import logging.handlers
from datetime import datetime
from flask import request, g, current_app
from functools import wraps
import json
import time

class LoggingConfig:
    """Centralized logging configuration"""
    
    @staticmethod
    def setup_application_logging(app):
        """Setup comprehensive application logging"""
        
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        # Remove default Flask handler to avoid duplicate logs
        app.logger.handlers.clear()
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s - '
            '[%(filename)s:%(lineno)d] - [%(funcName)s]'
        )
        
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Setup file handlers
        LoggingConfig._setup_file_handlers(app, detailed_formatter)
        
        # Setup console handler for development
        if app.config.get('DEBUG'):
            LoggingConfig._setup_console_handler(app, simple_formatter)
        
        # Set logging levels
        if app.config.get('DEBUG'):
            app.logger.setLevel(logging.DEBUG)
        else:
            app.logger.setLevel(logging.INFO)
        
        # Log application startup
        app.logger.info(f'Flask User Management Application started - Environment: {app.config.get("ENV", "unknown")}')
    
    @staticmethod
    def _setup_file_handlers(app, formatter):
        """Setup file-based logging handlers"""
        
        # Main application log
        app_handler = logging.handlers.RotatingFileHandler(
            'logs/application.log',
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        app_handler.setFormatter(formatter)
        app_handler.setLevel(logging.INFO)
        app.logger.addHandler(app_handler)
        
        # Error log (errors and above)
        error_handler = logging.handlers.RotatingFileHandler(
            'logs/errors.log',
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10
        )
        error_handler.setFormatter(formatter)
        error_handler.setLevel(logging.ERROR)
        app.logger.addHandler(error_handler)
        
        # Security log for security-related events
        security_handler = logging.handlers.RotatingFileHandler(
            'logs/security.log',
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=10
        )
        security_handler.setFormatter(formatter)
        security_handler.setLevel(logging.WARNING)
        
        # Create security logger
        security_logger = logging.getLogger('security')
        security_logger.addHandler(security_handler)
        security_logger.setLevel(logging.WARNING)
        
        # Request/Response log
        request_handler = logging.handlers.RotatingFileHandler(
            'logs/requests.log',
            maxBytes=20 * 1024 * 1024,  # 20MB
            backupCount=5
        )
        request_formatter = logging.Formatter(
            '%(asctime)s - %(message)s'
        )
        request_handler.setFormatter(request_formatter)
        request_handler.setLevel(logging.INFO)
        
        # Create request logger
        request_logger = logging.getLogger('requests')
        request_logger.addHandler(request_handler)
        request_logger.setLevel(logging.INFO)
    
    @staticmethod
    def _setup_console_handler(app, formatter):
        """Setup console logging for development"""
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.DEBUG)
        app.logger.addHandler(console_handler)

class RequestResponseLogger:
    """Middleware for logging HTTP requests and responses"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize request/response logging middleware"""
        app.before_request(self.log_request)
        app.after_request(self.log_response)
        app.teardown_appcontext(self.log_request_completion)
    
    def log_request(self):
        """Log incoming HTTP requests"""
        g.start_time = time.time()
        
        # Get client information
        client_ip = self._get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Prepare request data (excluding sensitive information)
        request_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'method': request.method,
            'url': request.url,
            'path': request.path,
            'client_ip': client_ip,
            'user_agent': user_agent,
            'content_type': request.content_type,
            'content_length': request.content_length
        }
        
        # Add query parameters (if any)
        if request.args:
            request_data['query_params'] = dict(request.args)
        
        # Add request body for POST/PUT requests (excluding sensitive data)
        if request.method in ['POST', 'PUT'] and request.is_json:
            try:
                json_data = request.get_json()
                if json_data:
                    # Remove sensitive fields
                    safe_data = self._sanitize_request_data(json_data)
                    request_data['body'] = safe_data
            except Exception:
                request_data['body'] = 'Invalid JSON'
        
        # Log the request
        request_logger = logging.getLogger('requests')
        request_logger.info(f"REQUEST: {json.dumps(request_data, default=str)}")
        
        # Store request data for response logging
        g.request_data = request_data
    
    def log_response(self, response):
        """Log HTTP responses"""
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
        else:
            duration = 0
        
        # Prepare response data
        response_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'status_code': response.status_code,
            'status': response.status,
            'content_type': response.content_type,
            'content_length': response.content_length,
            'duration_ms': round(duration * 1000, 2)
        }
        
        # Add request context if available
        if hasattr(g, 'request_data'):
            response_data['request'] = {
                'method': g.request_data['method'],
                'path': g.request_data['path'],
                'client_ip': g.request_data['client_ip']
            }
        
        # Log response body for errors (excluding sensitive data)
        if response.status_code >= 400:
            try:
                if response.is_json:
                    response_json = response.get_json()
                    if response_json:
                        response_data['body'] = response_json
            except Exception:
                pass
        
        # Log the response
        request_logger = logging.getLogger('requests')
        request_logger.info(f"RESPONSE: {json.dumps(response_data, default=str)}")
        
        return response
    
    def log_request_completion(self, exception=None):
        """Log request completion and any exceptions"""
        if exception:
            request_logger = logging.getLogger('requests')
            request_logger.error(f"REQUEST_EXCEPTION: {str(exception)}")
    
    def _get_client_ip(self):
        """Get client IP address from request"""
        # Check for forwarded IP first (in case of proxy/load balancer)
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr or '127.0.0.1'
    
    def _sanitize_request_data(self, data):
        """Remove sensitive information from request data"""
        if not isinstance(data, dict):
            return data
        
        sensitive_fields = ['password', 'token', 'secret', 'key', 'auth']
        sanitized = {}
        
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_request_data(value)
            else:
                sanitized[key] = value
        
        return sanitized

class SecurityLogger:
    """Specialized logger for security events"""
    
    @staticmethod
    def log_authentication_attempt(username, success, ip_address, details=None):
        """Log authentication attempts"""
        security_logger = logging.getLogger('security')
        
        event_data = {
            'event_type': 'authentication_attempt',
            'username': username,
            'success': success,
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat(),
            'details': details or {}
        }
        
        if success:
            security_logger.info(f"SECURITY_EVENT: {json.dumps(event_data)}")
        else:
            security_logger.warning(f"SECURITY_EVENT: {json.dumps(event_data)}")
    
    @staticmethod
    def log_authorization_failure(username, resource, ip_address, details=None):
        """Log authorization failures"""
        security_logger = logging.getLogger('security')
        
        event_data = {
            'event_type': 'authorization_failure',
            'username': username,
            'resource': resource,
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat(),
            'details': details or {}
        }
        
        security_logger.warning(f"SECURITY_EVENT: {json.dumps(event_data)}")
    
    @staticmethod
    def log_suspicious_activity(event_type, details, ip_address=None):
        """Log suspicious activities"""
        security_logger = logging.getLogger('security')
        
        event_data = {
            'event_type': f'suspicious_activity_{event_type}',
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat(),
            'details': details
        }
        
        security_logger.error(f"SECURITY_EVENT: {json.dumps(event_data)}")
    
    @staticmethod
    def log_data_access(username, action, resource, ip_address, success=True):
        """Log data access events"""
        security_logger = logging.getLogger('security')
        
        event_data = {
            'event_type': 'data_access',
            'username': username,
            'action': action,
            'resource': resource,
            'ip_address': ip_address,
            'success': success,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if success:
            security_logger.info(f"SECURITY_EVENT: {json.dumps(event_data)}")
        else:
            security_logger.warning(f"SECURITY_EVENT: {json.dumps(event_data)}")

class ErrorLogger:
    """Specialized logger for application errors"""
    
    @staticmethod
    def log_application_error(error, context=None, request_info=None):
        """Log application errors with context"""
        error_data = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'timestamp': datetime.utcnow().isoformat(),
            'context': context or {},
            'request_info': request_info or {}
        }
        
        # Add request information if available
        try:
            from flask import request
            if request:
                error_data['request_info'].update({
                    'method': request.method,
                    'path': request.path,
                    'client_ip': RequestResponseLogger()._get_client_ip()
                })
        except RuntimeError:
            # No request context available
            pass
        
        current_app.logger.error(f"APPLICATION_ERROR: {json.dumps(error_data, default=str)}")
    
    @staticmethod
    def log_database_error(error, operation, context=None):
        """Log database-related errors"""
        error_data = {
            'error_type': 'database_error',
            'error_class': type(error).__name__,
            'error_message': str(error),
            'operation': operation,
            'timestamp': datetime.utcnow().isoformat(),
            'context': context or {}
        }
        
        current_app.logger.error(f"DATABASE_ERROR: {json.dumps(error_data, default=str)}")
    
    @staticmethod
    def log_validation_error(error, field=None, value=None, context=None):
        """Log validation errors"""
        error_data = {
            'error_type': 'validation_error',
            'error_message': str(error),
            'field': field,
            'value': '[REDACTED]' if field and 'password' in field.lower() else value,
            'timestamp': datetime.utcnow().isoformat(),
            'context': context or {}
        }
        
        current_app.logger.warning(f"VALIDATION_ERROR: {json.dumps(error_data, default=str)}")

def log_user_activity(action):
    """Decorator to log user activities"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Log successful activity
                activity_data = {
                    'action': action,
                    'function': func.__name__,
                    'duration_ms': round(duration * 1000, 2),
                    'success': True,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                current_app.logger.info(f"USER_ACTIVITY: {json.dumps(activity_data)}")
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Log failed activity
                activity_data = {
                    'action': action,
                    'function': func.__name__,
                    'duration_ms': round(duration * 1000, 2),
                    'success': False,
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                current_app.logger.error(f"USER_ACTIVITY: {json.dumps(activity_data)}")
                raise
        
        return wrapper
    return decorator