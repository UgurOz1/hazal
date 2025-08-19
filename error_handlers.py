# Error handling utilities for Flask User Management Application

import logging
from flask import jsonify, current_app
from werkzeug.exceptions import HTTPException
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from exceptions import (
    ValidationError, AuthenticationError, AuthorizationError,
    ResourceNotFoundError, ConflictError, DatabaseError, BusinessLogicError
)

def create_error_response(error_code, message, details=None, status_code=500):
    """Create a standardized error response"""
    response_data = {
        'success': False,
        'error': {
            'code': error_code,
            'message': message
        }
    }
    
    if details:
        response_data['error']['details'] = details
    
    return jsonify(response_data), status_code

def log_error(error, context=None):
    """Log error with appropriate level and context"""
    logger = current_app.logger
    
    # Import here to avoid circular imports
    try:
        from logging_config import ErrorLogger
        
        # Use the enhanced error logger
        if isinstance(error, (ValidationError, AuthenticationError, ResourceNotFoundError)):
            ErrorLogger.log_validation_error(error, context=context)
        elif isinstance(error, DatabaseError):
            ErrorLogger.log_database_error(error, 'unknown', context=context)
        else:
            ErrorLogger.log_application_error(error, context=context)
    except ImportError:
        # Fallback to basic logging if enhanced logger is not available
        # Determine log level based on error type
        if isinstance(error, (ValidationError, AuthenticationError, ResourceNotFoundError)):
            log_level = logging.WARNING
        elif isinstance(error, (ConflictError, BusinessLogicError)):
            log_level = logging.INFO
        else:
            log_level = logging.ERROR
        
        # Create log message
        log_message = f"Error occurred: {str(error)}"
        if context:
            log_message += f" | Context: {context}"
        
        # Log with appropriate level
        if log_level == logging.ERROR:
            logger.error(log_message, exc_info=True)
        elif log_level == logging.WARNING:
            logger.warning(log_message)
        else:
            logger.info(log_message)

def handle_validation_error(error):
    """Handle validation errors"""
    log_error(error, "Validation failed")
    
    if hasattr(error, 'to_dict'):
        error_dict = error.to_dict()
        return create_error_response(
            error_dict['code'],
            error_dict['message'],
            error_dict.get('details'),
            400
        )
    else:
        return create_error_response(
            'VALIDATION_ERROR',
            str(error),
            status_code=400
        )

def handle_authentication_error(error):
    """Handle authentication errors"""
    log_error(error, "Authentication failed")
    
    if hasattr(error, 'to_dict'):
        error_dict = error.to_dict()
        return create_error_response(
            error_dict['code'],
            error_dict['message'],
            error_dict.get('details'),
            401
        )
    else:
        return create_error_response(
            'AUTHENTICATION_ERROR',
            str(error),
            status_code=401
        )

def handle_authorization_error(error):
    """Handle authorization errors"""
    log_error(error, "Authorization failed")
    
    if hasattr(error, 'to_dict'):
        error_dict = error.to_dict()
        return create_error_response(
            error_dict['code'],
            error_dict['message'],
            error_dict.get('details'),
            403
        )
    else:
        return create_error_response(
            'AUTHORIZATION_ERROR',
            str(error),
            status_code=403
        )

def handle_not_found_error(error):
    """Handle resource not found errors"""
    log_error(error, "Resource not found")
    
    if hasattr(error, 'to_dict'):
        error_dict = error.to_dict()
        return create_error_response(
            error_dict['code'],
            error_dict['message'],
            error_dict.get('details'),
            404
        )
    else:
        return create_error_response(
            'RESOURCE_NOT_FOUND',
            str(error),
            status_code=404
        )

def handle_conflict_error(error):
    """Handle resource conflict errors"""
    log_error(error, "Resource conflict")
    
    if hasattr(error, 'to_dict'):
        error_dict = error.to_dict()
        return create_error_response(
            error_dict['code'],
            error_dict['message'],
            error_dict.get('details'),
            409
        )
    else:
        return create_error_response(
            'CONFLICT_ERROR',
            str(error),
            status_code=409
        )

def handle_database_error(error):
    """Handle database errors"""
    log_error(error, "Database operation failed")
    
    # Check if it's an integrity error (constraint violation)
    if isinstance(error, IntegrityError):
        # Try to extract meaningful information from the error
        error_message = str(error.orig) if hasattr(error, 'orig') else str(error)
        
        if 'unique constraint' in error_message.lower():
            return create_error_response(
                'CONFLICT_ERROR',
                'Resource already exists',
                {'constraint': 'unique'},
                409
            )
        elif 'foreign key constraint' in error_message.lower():
            return create_error_response(
                'VALIDATION_ERROR',
                'Invalid reference to related resource',
                {'constraint': 'foreign_key'},
                400
            )
        elif 'not null constraint' in error_message.lower():
            return create_error_response(
                'VALIDATION_ERROR',
                'Required field is missing',
                {'constraint': 'not_null'},
                400
            )
    
    # Generic database error
    if hasattr(error, 'to_dict'):
        error_dict = error.to_dict()
        return create_error_response(
            error_dict['code'],
            error_dict['message'],
            error_dict.get('details'),
            500
        )
    else:
        return create_error_response(
            'DATABASE_ERROR',
            'Database operation failed',
            status_code=500
        )

def handle_business_logic_error(error):
    """Handle business logic errors"""
    log_error(error, "Business logic violation")
    
    if hasattr(error, 'to_dict'):
        error_dict = error.to_dict()
        return create_error_response(
            error_dict['code'],
            error_dict['message'],
            error_dict.get('details'),
            422
        )
    else:
        return create_error_response(
            'BUSINESS_LOGIC_ERROR',
            str(error),
            status_code=422
        )

def handle_http_exception(error):
    """Handle HTTP exceptions from Flask/Werkzeug"""
    log_error(error, f"HTTP {error.code} error")
    
    return create_error_response(
        f'HTTP_{error.code}',
        error.description or error.name,
        status_code=error.code
    )

def handle_generic_exception(error):
    """Handle unexpected exceptions"""
    log_error(error, "Unexpected error occurred")
    
    # Don't expose internal error details in production
    if current_app.config.get('DEBUG'):
        error_message = str(error)
        details = {'type': type(error).__name__}
    else:
        error_message = 'An unexpected error occurred'
        details = None
    
    return create_error_response(
        'INTERNAL_ERROR',
        error_message,
        details,
        500
    )

def register_error_handlers(app):
    """Register all error handlers with the Flask app"""
    
    # Custom exception handlers
    @app.errorhandler(ValidationError)
    def validation_error_handler(error):
        return handle_validation_error(error)
    
    @app.errorhandler(AuthenticationError)
    def authentication_error_handler(error):
        return handle_authentication_error(error)
    
    @app.errorhandler(AuthorizationError)
    def authorization_error_handler(error):
        return handle_authorization_error(error)
    
    @app.errorhandler(ResourceNotFoundError)
    def not_found_error_handler(error):
        return handle_not_found_error(error)
    
    @app.errorhandler(ConflictError)
    def conflict_error_handler(error):
        return handle_conflict_error(error)
    
    @app.errorhandler(DatabaseError)
    def database_error_handler(error):
        return handle_database_error(error)
    
    @app.errorhandler(BusinessLogicError)
    def business_logic_error_handler(error):
        return handle_business_logic_error(error)
    
    # SQLAlchemy error handlers
    @app.errorhandler(IntegrityError)
    def integrity_error_handler(error):
        return handle_database_error(error)
    
    @app.errorhandler(SQLAlchemyError)
    def sqlalchemy_error_handler(error):
        return handle_database_error(DatabaseError(str(error), 'sqlalchemy'))
    
    # HTTP exception handlers
    @app.errorhandler(400)
    def bad_request_handler(error):
        return handle_http_exception(error)
    
    @app.errorhandler(401)
    def unauthorized_handler(error):
        return handle_http_exception(error)
    
    @app.errorhandler(403)
    def forbidden_handler(error):
        return handle_http_exception(error)
    
    @app.errorhandler(404)
    def not_found_handler(error):
        return handle_http_exception(error)
    
    @app.errorhandler(405)
    def method_not_allowed_handler(error):
        return handle_http_exception(error)
    
    @app.errorhandler(409)
    def conflict_handler(error):
        return handle_http_exception(error)
    
    @app.errorhandler(422)
    def unprocessable_entity_handler(error):
        return handle_http_exception(error)
    
    @app.errorhandler(500)
    def internal_server_error_handler(error):
        return handle_http_exception(error)
    
    # Generic exception handler (catch-all)
    @app.errorhandler(Exception)
    def generic_exception_handler(error):
        # Don't handle HTTP exceptions here, let them be handled by specific handlers
        if isinstance(error, HTTPException):
            return handle_http_exception(error)
        
        return handle_generic_exception(error)

def validate_request_data(data, required_fields=None, optional_fields=None):
    """
    Legacy validation function - kept for backward compatibility
    Use validate_request_data_enhanced for new implementations
    """
    # Import here to avoid circular imports
    from validation import validate_request_data_enhanced
    
    return validate_request_data_enhanced(
        data, 
        required_fields=required_fields, 
        optional_fields=optional_fields,
        validation_type='generic'
    )

def validate_pagination_params(page=1, per_page=20, max_per_page=100):
    """Validate pagination parameters"""
    try:
        page = int(page) if page else 1
        per_page = int(per_page) if per_page else 20
    except (ValueError, TypeError):
        raise ValidationError("Invalid pagination parameters", constraint='integer')
    
    if page < 1:
        raise ValidationError("Page number must be positive", field='page', constraint='min_value')
    
    if per_page < 1:
        raise ValidationError("Per page value must be positive", field='per_page', constraint='min_value')
    
    if per_page > max_per_page:
        raise ValidationError(
            f"Per page value cannot exceed {max_per_page}",
            field='per_page',
            constraint='max_value'
        )
    
    return page, per_page