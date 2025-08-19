# Error Handling System Documentation

## Overview

This Flask User Management application implements a comprehensive error handling system that provides consistent error responses, proper HTTP status codes, and detailed logging. The system is designed to handle various types of errors gracefully while maintaining security and providing useful feedback to API consumers.

## Architecture

The error handling system consists of three main components:

1. **Custom Exceptions** (`exceptions.py`) - Domain-specific exception classes
2. **Error Handlers** (`error_handlers.py`) - Error processing and response formatting
3. **Global Registration** (`app.py`) - Flask error handler registration

## Custom Exception Classes

### ValidationError
- **Purpose**: Input validation failures
- **HTTP Status**: 400 (Bad Request)
- **Use Cases**: Invalid email format, weak passwords, missing required fields
- **Example**:
  ```python
  raise ValidationError("Invalid email format", field='email', constraint='format')
  ```

### AuthenticationError
- **Purpose**: Authentication failures
- **HTTP Status**: 401 (Unauthorized)
- **Use Cases**: Invalid credentials, missing authentication
- **Example**:
  ```python
  raise AuthenticationError("Invalid credentials")
  ```

### AuthorizationError
- **Purpose**: Authorization failures
- **HTTP Status**: 403 (Forbidden)
- **Use Cases**: Insufficient permissions, access denied
- **Example**:
  ```python
  raise AuthorizationError("Access denied")
  ```

### ResourceNotFoundError
- **Purpose**: Resource not found
- **HTTP Status**: 404 (Not Found)
- **Use Cases**: User not found, endpoint not found
- **Example**:
  ```python
  raise ResourceNotFoundError("User", user_id)
  ```

### ConflictError
- **Purpose**: Resource conflicts
- **HTTP Status**: 409 (Conflict)
- **Use Cases**: Duplicate username, duplicate email
- **Example**:
  ```python
  raise ConflictError("Username already exists", field='username', value=username)
  ```

### DatabaseError
- **Purpose**: Database operation failures
- **HTTP Status**: 500 (Internal Server Error)
- **Use Cases**: Connection failures, query errors
- **Example**:
  ```python
  raise DatabaseError("User creation failed", "create_user")
  ```

### BusinessLogicError
- **Purpose**: Business rule violations
- **HTTP Status**: 422 (Unprocessable Entity)
- **Use Cases**: Complex validation rules, business constraints
- **Example**:
  ```python
  raise BusinessLogicError("Cannot delete active user", rule='active_user_deletion')
  ```

## Error Response Format

All error responses follow a consistent JSON structure:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "field_name",
      "constraint": "constraint_type",
      "additional_info": "value"
    }
  }
}
```

### Response Fields

- **success**: Always `false` for error responses
- **error.code**: Machine-readable error code (e.g., "VALIDATION_ERROR")
- **error.message**: Human-readable error description
- **error.details**: Optional additional information about the error

## HTTP Status Code Mapping

| Exception Type | HTTP Status | Code | Description |
|----------------|-------------|------|-------------|
| ValidationError | 400 | Bad Request | Invalid input data |
| AuthenticationError | 401 | Unauthorized | Authentication required |
| AuthorizationError | 403 | Forbidden | Access denied |
| ResourceNotFoundError | 404 | Not Found | Resource not found |
| ConflictError | 409 | Conflict | Resource already exists |
| BusinessLogicError | 422 | Unprocessable Entity | Business rule violation |
| DatabaseError | 500 | Internal Server Error | Database operation failed |
| Generic Exception | 500 | Internal Server Error | Unexpected error |

## Error Handler Functions

### Core Handler Functions

- `handle_validation_error()` - Processes validation errors
- `handle_authentication_error()` - Processes authentication errors
- `handle_not_found_error()` - Processes resource not found errors
- `handle_conflict_error()` - Processes resource conflict errors
- `handle_database_error()` - Processes database errors
- `handle_generic_exception()` - Processes unexpected errors

### Utility Functions

- `create_error_response()` - Creates standardized error responses
- `log_error()` - Logs errors with appropriate levels
- `validate_request_data()` - Validates and cleans request data
- `validate_pagination_params()` - Validates pagination parameters

## Logging Strategy

The error handling system implements intelligent logging based on error severity:

### Log Levels

- **INFO**: Business logic errors, conflicts (expected errors)
- **WARNING**: Validation errors, authentication failures
- **ERROR**: Database errors, unexpected exceptions (with stack traces)

### Log Format

```
ERROR:app:Error occurred: ValidationError message | Context: validation_context
```

## Usage Examples

### In Route Handlers

```python
@api.route('/user/create', methods=['POST'])
def create_user():
    try:
        # Validate request data
        data = validate_request_data(
            request.get_json(),
            required_fields=['username', 'email', 'password']
        )
        
        # Business logic
        if not User.validate_password(data['password']):
            raise ValidationError(
                "Password must be at least 8 characters",
                field='password',
                constraint='complexity'
            )
        
        # Check for conflicts
        if User.query.filter_by(email=data['email']).first():
            raise ConflictError(
                "Email already exists",
                field='email',
                value=data['email']
            )
        
        # Create user
        user = User(**data)
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'user_id': user.id}), 201
        
    except (ValidationError, ConflictError):
        db.session.rollback()
        raise  # Re-raise to be handled by error handlers
    except Exception as e:
        db.session.rollback()
        raise DatabaseError(f"User creation failed: {str(e)}", "create_user")
```

### Request Data Validation

```python
# Validate required fields
data = validate_request_data(
    request.get_json(),
    required_fields=['username', 'password']
)

# Validate with optional fields
data = validate_request_data(
    request.get_json(),
    required_fields=['username'],
    optional_fields=['email', 'firstname']
)
```

## Database Error Handling

The system provides special handling for SQLAlchemy errors:

### Integrity Constraint Violations

- **Unique Constraint**: Converted to ConflictError (409)
- **Foreign Key Constraint**: Converted to ValidationError (400)
- **Not Null Constraint**: Converted to ValidationError (400)

### Example

```python
try:
    db.session.add(user)
    db.session.commit()
except IntegrityError as e:
    # Automatically handled by error handlers
    # Unique constraint → 409 Conflict
    # Foreign key constraint → 400 Bad Request
    # Not null constraint → 400 Bad Request
    raise
```

## Security Considerations

### Information Disclosure

- **Production Mode**: Generic error messages, no stack traces
- **Debug Mode**: Detailed error information for development
- **Sensitive Data**: Never expose passwords or internal system details

### Example

```python
# Production response
{
  "success": false,
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "An unexpected error occurred"
  }
}

# Debug response
{
  "success": false,
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "psycopg2.OperationalError: connection refused",
    "details": {
      "type": "OperationalError"
    }
  }
}
```

## Testing

### Unit Tests

Test individual exception classes and utility functions:

```bash
python test_validation.py
```

### Integration Tests

Test error handling in API endpoints:

```bash
python test_error_handling.py
```

### Test Coverage

The error handling system covers:

- ✅ Custom exception creation and formatting
- ✅ Request data validation
- ✅ HTTP status code mapping
- ✅ Error response formatting
- ✅ Database error handling
- ✅ Logging functionality

## Best Practices

### 1. Use Specific Exceptions

```python
# Good
raise ValidationError("Invalid email format", field='email')

# Avoid
raise Exception("Invalid email")
```

### 2. Provide Context

```python
# Good
raise ConflictError("Username already exists", field='username', value=username)

# Avoid
raise ConflictError("Conflict")
```

### 3. Handle Database Sessions

```python
try:
    # Database operations
    db.session.commit()
except Exception:
    db.session.rollback()
    raise
```

### 4. Log Appropriately

```python
# The error handlers automatically log with appropriate levels
# No need to manually log in route handlers
```

### 5. Re-raise Known Exceptions

```python
try:
    # Business logic
    pass
except (ValidationError, ConflictError):
    # Let error handlers deal with these
    raise
except Exception as e:
    # Convert unexpected errors to domain exceptions
    raise DatabaseError(f"Operation failed: {str(e)}")
```

## Configuration

### Environment Variables

- `FLASK_ENV=development` - Enables debug mode with detailed errors
- `FLASK_ENV=production` - Enables production mode with generic errors

### Flask Configuration

```python
# In config.py
class Config:
    DEBUG = False  # Controls error detail level
    
class DevelopmentConfig(Config):
    DEBUG = True   # Shows detailed error information
```

## Monitoring and Alerting

### Error Metrics

The system logs errors that can be monitored:

- Error count by type
- Error rate trends
- Response time impact
- Database error frequency

### Log Analysis

```bash
# Find validation errors
grep "VALIDATION_ERROR" app.log

# Find database errors
grep "DATABASE_ERROR" app.log

# Find unexpected errors
grep "ERROR:app:" app.log
```

## Future Enhancements

### Planned Improvements

1. **Rate Limiting**: Add rate limiting for error-prone endpoints
2. **Error Metrics**: Implement error counting and alerting
3. **Custom Error Pages**: Add HTML error pages for web interface
4. **Error Recovery**: Implement automatic retry mechanisms
5. **Error Aggregation**: Group similar errors for better monitoring

### Integration Points

- **Monitoring**: Integrate with Prometheus/Grafana
- **Alerting**: Connect to PagerDuty/Slack for critical errors
- **Analytics**: Send error data to analytics platforms
- **Documentation**: Auto-generate API error documentation