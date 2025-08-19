# Custom exceptions for Flask User Management Application

class ValidationError(Exception):
    """Exception raised for validation errors"""
    
    def __init__(self, message, field=None, constraint=None):
        self.message = message
        self.field = field
        self.constraint = constraint
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary format"""
        error_dict = {
            'code': 'VALIDATION_ERROR',
            'message': self.message
        }
        
        if self.field or self.constraint:
            error_dict['details'] = {}
            if self.field:
                error_dict['details']['field'] = self.field
            if self.constraint:
                error_dict['details']['constraint'] = self.constraint
        
        return error_dict

class AuthenticationError(Exception):
    """Exception raised for authentication failures"""
    
    def __init__(self, message="Authentication failed"):
        self.message = message
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary format"""
        return {
            'code': 'AUTHENTICATION_ERROR',
            'message': self.message
        }

class AuthorizationError(Exception):
    """Exception raised for authorization failures"""
    
    def __init__(self, message="Access denied"):
        self.message = message
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary format"""
        return {
            'code': 'AUTHORIZATION_ERROR',
            'message': self.message
        }

class ResourceNotFoundError(Exception):
    """Exception raised when a requested resource is not found"""
    
    def __init__(self, resource_type="Resource", resource_id=None):
        if resource_id:
            self.message = f"{resource_type} with ID {resource_id} not found"
        else:
            self.message = f"{resource_type} not found"
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary format"""
        error_dict = {
            'code': 'RESOURCE_NOT_FOUND',
            'message': self.message
        }
        
        if self.resource_type or self.resource_id:
            error_dict['details'] = {}
            if self.resource_type:
                error_dict['details']['resource_type'] = self.resource_type
            if self.resource_id:
                error_dict['details']['resource_id'] = self.resource_id
        
        return error_dict

class ConflictError(Exception):
    """Exception raised for resource conflicts (e.g., duplicate data)"""
    
    def __init__(self, message, field=None, value=None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary format"""
        error_dict = {
            'code': 'CONFLICT_ERROR',
            'message': self.message
        }
        
        if self.field or self.value:
            error_dict['details'] = {}
            if self.field:
                error_dict['details']['field'] = self.field
            if self.value:
                error_dict['details']['value'] = self.value
        
        return error_dict

class DatabaseError(Exception):
    """Exception raised for database-related errors"""
    
    def __init__(self, message="Database operation failed", operation=None):
        self.message = message
        self.operation = operation
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary format"""
        error_dict = {
            'code': 'DATABASE_ERROR',
            'message': self.message
        }
        
        if self.operation:
            error_dict['details'] = {
                'operation': self.operation
            }
        
        return error_dict

class BusinessLogicError(Exception):
    """Exception raised for business logic violations"""
    
    def __init__(self, message, rule=None):
        self.message = message
        self.rule = rule
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dictionary format"""
        error_dict = {
            'code': 'BUSINESS_LOGIC_ERROR',
            'message': self.message
        }
        
        if self.rule:
            error_dict['details'] = {
                'rule': self.rule
            }
        
        return error_dict