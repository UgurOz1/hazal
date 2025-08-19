# API routes for Flask User Management Application

from flask import Blueprint, request, jsonify, abort
from datetime import datetime
from models import db, User, OnlineUser, UserLog
from exceptions import (
    ValidationError, AuthenticationError, ResourceNotFoundError,
    ConflictError, DatabaseError
)
from error_handlers import validate_request_data
from validation import validate_request_data_enhanced, RequestValidator
from security import security_required, QuerySecurityHelper, SQLSecurityManager
from middleware import (
    validate_endpoint_data, get_validated_data, validate_path_parameter,
    DatabaseValidationMiddleware
)
from logging_config import SecurityLogger, ErrorLogger, log_user_activity

# Create blueprint for API routes
api = Blueprint('api', __name__)

def get_client_ip():
    """Get client IP address from request"""
    # Check for forwarded IP first (in case of proxy/load balancer)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or '127.0.0.1'

# Authentication endpoints
@api.route('/login', methods=['POST'])
@security_required
@validate_endpoint_data(validation_type='login')
@log_user_activity('user_login')
def login():
    """User login endpoint"""
    client_ip = get_client_ip()
    username = None
    
    try:
        # Get validated data from middleware
        data = get_validated_data()
        
        username = data['username']
        password = data['password']
        
        # Find user by username using secure lookup
        user = QuerySecurityHelper.safe_user_lookup(username=username)
        
        if not user or not user.verify_password(password):
            # Log failed authentication attempt
            SecurityLogger.log_authentication_attempt(
                username=username,
                success=False,
                ip_address=client_ip,
                details={'reason': 'invalid_credentials'}
            )
            raise AuthenticationError("Invalid credentials")
        
        # Check if user is already online (remove existing session)
        existing_online = QuerySecurityHelper.safe_online_user_operations(username, 'get')
        if existing_online:
            QuerySecurityHelper.safe_online_user_operations(username, 'delete')
        
        # Add user to online users list
        online_user = OnlineUser(
            username=username,
            ip_address=client_ip,
            user_id=user.id,
            login_datetime=datetime.utcnow()
        )
        
        # Validate before database insert
        DatabaseValidationMiddleware.validate_before_insert(online_user)
        db.session.add(online_user)
        
        # Log the login action
        user_log = UserLog(
            username=username,
            action='login',
            ip_address=client_ip,
            user_id=user.id,
            timestamp=datetime.utcnow()
        )
        
        # Validate before database insert
        DatabaseValidationMiddleware.validate_before_insert(user_log)
        db.session.add(user_log)
        
        # Commit all changes
        db.session.commit()
        
        # Log successful authentication
        SecurityLogger.log_authentication_attempt(
            username=username,
            success=True,
            ip_address=client_ip,
            details={'user_id': user.id}
        )
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user_id': user.id
        }), 200
        
    except (ValidationError, AuthenticationError) as e:
        db.session.rollback()
        ErrorLogger.log_validation_error(e, context={'endpoint': 'login', 'username': username})
        raise
    except Exception as e:
        db.session.rollback()
        ErrorLogger.log_database_error(e, 'login', context={'username': username})
        raise DatabaseError(f"Login failed: {str(e)}", "login")

@api.route('/logout', methods=['POST'])
@security_required
@validate_endpoint_data(validation_type='generic', required_fields=['username'])
@log_user_activity('user_logout')
def logout():
    """User logout endpoint"""
    client_ip = get_client_ip()
    username = None
    
    try:
        # Get validated data from middleware
        data = get_validated_data()
        
        username = data['username']
        
        # Find user by username using secure lookup
        user = QuerySecurityHelper.safe_user_lookup(username=username)
        
        if not user:
            # Log data access failure
            SecurityLogger.log_data_access(
                username=username,
                action='logout',
                resource='user',
                ip_address=client_ip,
                success=False
            )
            raise ResourceNotFoundError("User", username)
        
        # Remove user from online users list using secure operations
        online_user = QuerySecurityHelper.safe_online_user_operations(username, 'delete')
        
        # Log the logout action
        user_log = UserLog(
            username=username,
            action='logout',
            ip_address=client_ip,
            user_id=user.id,
            timestamp=datetime.utcnow()
        )
        
        # Validate before database insert
        DatabaseValidationMiddleware.validate_before_insert(user_log)
        db.session.add(user_log)
        
        # Commit all changes
        db.session.commit()
        
        # Log successful logout
        SecurityLogger.log_data_access(
            username=username,
            action='logout',
            resource='user',
            ip_address=client_ip,
            success=True
        )
        
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        }), 200
        
    except (ValidationError, ResourceNotFoundError) as e:
        db.session.rollback()
        ErrorLogger.log_validation_error(e, context={'endpoint': 'logout', 'username': username})
        raise
    except Exception as e:
        db.session.rollback()
        ErrorLogger.log_database_error(e, 'logout', context={'username': username})
        raise DatabaseError(f"Logout failed: {str(e)}", "logout")

# User management endpoints
@api.route('/user/list', methods=['GET'])
@log_user_activity('list_users')
def list_users():
    """List all users endpoint"""
    client_ip = get_client_ip()
    
    try:
        # Get all users from database
        users = User.query.all()
        
        # Convert users to dictionary format, excluding sensitive data
        users_list = [user.to_dict() for user in users]
        
        # Log data access
        SecurityLogger.log_data_access(
            username='system',  # No specific user for list operation
            action='list',
            resource='users',
            ip_address=client_ip,
            success=True
        )
        
        return jsonify({
            'users': users_list
        }), 200
        
    except Exception as e:
        ErrorLogger.log_database_error(e, 'list_users', context={'endpoint': 'user/list'})
        raise DatabaseError(f"Failed to retrieve users: {str(e)}", "list_users")

@api.route('/user/create', methods=['POST'])
@security_required
@validate_endpoint_data(validation_type='user_data', required_fields=['username', 'firstname', 'lastname', 'birthdate', 'email', 'password'])
@log_user_activity('create_user')
def create_user():
    """Create new user endpoint"""
    client_ip = get_client_ip()
    username = None
    
    try:
        # Get validated data from middleware
        data = get_validated_data()
        
        username = data['username']
        firstname = data['firstname']
        lastname = data['lastname']
        birthdate_str = data['birthdate']
        email = data['email']
        password = data['password']
        
        # Check username uniqueness using secure lookup
        existing_user_by_username = QuerySecurityHelper.safe_user_lookup(username=username)
        if existing_user_by_username:
            raise ConflictError("Username already exists", field='username', value=username)
        
        # Check email uniqueness using secure lookup
        existing_user_by_email = QuerySecurityHelper.safe_user_lookup(email=email)
        if existing_user_by_email:
            raise ConflictError("Email already exists", field='email', value=email)
        
        # Parse birthdate
        try:
            from datetime import datetime
            birthdate = datetime.strptime(birthdate_str, '%Y-%m-%d').date()
        except ValueError:
            raise ValidationError(
                "Invalid birthdate format. Use YYYY-MM-DD",
                field='birthdate',
                constraint='format'
            )
        
        # Create new user
        new_user = User(
            username=username,
            firstname=firstname,
            lastname=lastname,
            birthdate=birthdate,
            email=email,
            password=password  # Password will be hashed in User.__init__
        )
        
        # Validate before database insert using middleware
        DatabaseValidationMiddleware.validate_before_insert(new_user)
        
        # Add user to database
        db.session.add(new_user)
        db.session.commit()
        
        # Log successful user creation
        SecurityLogger.log_data_access(
            username='admin',  # Assuming admin creates users
            action='create',
            resource='user',
            ip_address=client_ip,
            success=True
        )
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user_id': new_user.id
        }), 201
        
    except (ValidationError, ConflictError) as e:
        db.session.rollback()
        ErrorLogger.log_validation_error(e, context={'endpoint': 'user/create', 'username': username})
        raise
    except ValueError as e:
        db.session.rollback()
        ErrorLogger.log_validation_error(e, context={'endpoint': 'user/create', 'username': username})
        raise ValidationError(str(e))
    except Exception as e:
        db.session.rollback()
        ErrorLogger.log_database_error(e, 'create_user', context={'username': username})
        raise DatabaseError(f"User creation failed: {str(e)}", "create_user")

@api.route('/user/delete/<int:user_id>', methods=['DELETE'])
@security_required
@log_user_activity('delete_user')
def delete_user(user_id):
    """Delete user endpoint"""
    client_ip = get_client_ip()
    username = None
    
    try:
        # Validate path parameter
        validated_user_id = validate_path_parameter('user_id', user_id, 'integer')
        
        # Find user by ID using secure lookup
        user = QuerySecurityHelper.safe_user_lookup(user_id=validated_user_id)
        
        if not user:
            SecurityLogger.log_data_access(
                username='admin',
                action='delete',
                resource='user',
                ip_address=client_ip,
                success=False
            )
            raise ResourceNotFoundError("User", validated_user_id)
        
        username = user.username
        
        # Remove user from online users list if they are online
        online_user = OnlineUser.query.filter_by(user_id=validated_user_id).first()
        if online_user:
            db.session.delete(online_user)
        
        # Delete the user (cascade will handle related records)
        db.session.delete(user)
        db.session.commit()
        
        # Log successful user deletion
        SecurityLogger.log_data_access(
            username='admin',
            action='delete',
            resource='user',
            ip_address=client_ip,
            success=True
        )
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        }), 200
        
    except ResourceNotFoundError as e:
        db.session.rollback()
        ErrorLogger.log_validation_error(e, context={'endpoint': 'user/delete', 'user_id': user_id})
        raise
    except Exception as e:
        db.session.rollback()
        ErrorLogger.log_database_error(e, 'delete_user', context={'user_id': user_id, 'username': username})
        raise DatabaseError(f"User deletion failed: {str(e)}", "delete_user")

@api.route('/user/update/<int:user_id>', methods=['PUT'])
@security_required
@validate_endpoint_data(validation_type='user_data', optional_fields=['firstname', 'lastname', 'birthdate', 'email', 'password'])
@log_user_activity('update_user')
def update_user(user_id):
    """Update user endpoint"""
    client_ip = get_client_ip()
    username = None
    
    try:
        # Validate path parameter
        validated_user_id = validate_path_parameter('user_id', user_id, 'integer')
        
        # Find user by ID using secure lookup
        user = QuerySecurityHelper.safe_user_lookup(user_id=validated_user_id)
        
        if not user:
            SecurityLogger.log_data_access(
                username='admin',
                action='update',
                resource='user',
                ip_address=client_ip,
                success=False
            )
            raise ResourceNotFoundError("User", validated_user_id)
        
        username = user.username
        
        # Get validated data from middleware
        data = get_validated_data()
        
        # Track if any changes were made
        changes_made = False
        
        # Update firstname if provided
        if 'firstname' in data:
            user.firstname = data['firstname']
            changes_made = True
        
        # Update lastname if provided
        if 'lastname' in data:
            user.lastname = data['lastname']
            changes_made = True
        
        # Update birthdate if provided
        if 'birthdate' in data:
            try:
                from datetime import datetime
                user.birthdate = datetime.strptime(data['birthdate'], '%Y-%m-%d').date()
                changes_made = True
            except ValueError:
                raise ValidationError(
                    "Invalid birthdate format. Use YYYY-MM-DD",
                    field='birthdate',
                    constraint='format'
                )
        
        # Update email if provided
        if 'email' in data:
            new_email = data['email']
            
            # Check email uniqueness (excluding current user) using secure lookup
            existing_user = QuerySecurityHelper.safe_user_lookup(email=new_email)
            if existing_user and existing_user.id != validated_user_id:
                raise ConflictError("Email already exists", field='email', value=new_email)
            
            user.email = new_email
            changes_made = True
        
        # Update password if provided
        if 'password' in data:
            new_password = data['password']
            
            # Set new password (will be hashed automatically)
            user.set_password(new_password)
            changes_made = True
        
        # If no changes were made, return appropriate message
        if not changes_made:
            return jsonify({
                'success': True,
                'message': 'No changes were made'
            }), 200
        
        # Validate before database update using middleware
        DatabaseValidationMiddleware.validate_before_update(user, list(data.keys()))
        
        # Commit changes to database
        db.session.commit()
        
        # Log successful user update
        SecurityLogger.log_data_access(
            username='admin',
            action='update',
            resource='user',
            ip_address=client_ip,
            success=True
        )
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully'
        }), 200
        
    except (ValidationError, ResourceNotFoundError, ConflictError) as e:
        db.session.rollback()
        ErrorLogger.log_validation_error(e, context={'endpoint': 'user/update', 'user_id': user_id, 'username': username})
        raise
    except ValueError as e:
        db.session.rollback()
        ErrorLogger.log_validation_error(e, context={'endpoint': 'user/update', 'user_id': user_id, 'username': username})
        raise ValidationError(str(e))
    except Exception as e:
        db.session.rollback()
        ErrorLogger.log_database_error(e, 'update_user', context={'user_id': user_id, 'username': username})
        raise DatabaseError(f"User update failed: {str(e)}", "update_user")

@api.route('/onlusers', methods=['GET'])
@log_user_activity('list_online_users')
def online_users():
    """Get online users endpoint"""
    client_ip = get_client_ip()
    
    try:
        # Get all online users from database
        online_users_list = OnlineUser.query.all()
        
        # Convert online users to dictionary format
        users_data = []
        for online_user in online_users_list:
            user_dict = {
                'username': online_user.username,
                'ip_address': online_user.ip_address,
                'login_datetime': online_user.login_datetime.strftime('%Y-%m-%d %H:%M:%S')
            }
            users_data.append(user_dict)
        
        # Log data access
        SecurityLogger.log_data_access(
            username='system',
            action='list',
            resource='online_users',
            ip_address=client_ip,
            success=True
        )
        
        return jsonify({
            'online_users': users_data
        }), 200
        
    except Exception as e:
        ErrorLogger.log_database_error(e, 'online_users', context={'endpoint': 'onlusers'})
        raise DatabaseError(f"Failed to retrieve online users: {str(e)}", "online_users")