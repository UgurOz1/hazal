# Database models for Flask User Management Application

from datetime import datetime
import hashlib
import secrets
import re
from flask_sqlalchemy import SQLAlchemy

# Initialize db instance - will be initialized in app.py
db = SQLAlchemy()

class User(db.Model):
    """User model for storing user information"""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    birthdate = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    online_sessions = db.relationship('OnlineUser', backref='user', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('UserLog', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __init__(self, username, firstname, lastname, birthdate, email, password):
        """Initialize user with password hashing"""
        if not self.validate_email(email):
            raise ValueError("Invalid email format")
        
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.birthdate = birthdate
        self.email = email
        self.set_password(password)
    
    def validate(self):
        """Comprehensive model validation for security middleware"""
        from validation import InputValidator, InputSanitizer
        
        # Validate username
        if not self.username:
            raise ValueError("Username is required")
        
        # Check for suspicious patterns in username
        if InputSanitizer.detect_sql_injection(self.username):
            raise ValueError("Username contains suspicious patterns")
        
        if InputSanitizer.detect_xss(self.username):
            raise ValueError("Username contains suspicious patterns")
        
        is_valid, message = InputValidator.validate_username(self.username)
        if not is_valid:
            raise ValueError(f"Username validation failed: {message}")
        
        # Validate names
        for field_name, field_value in [('firstname', self.firstname), ('lastname', self.lastname)]:
            if not field_value:
                raise ValueError(f"{field_name.capitalize()} is required")
            
            if InputSanitizer.detect_xss(field_value):
                raise ValueError(f"{field_name.capitalize()} contains suspicious patterns")
            
            is_valid, message = InputValidator.validate_name(field_value, field_name.capitalize())
            if not is_valid:
                raise ValueError(f"{field_name.capitalize()} validation failed: {message}")
        
        # Validate email
        if not self.email:
            raise ValueError("Email is required")
        
        if InputSanitizer.detect_sql_injection(self.email):
            raise ValueError("Email contains suspicious patterns")
        
        if InputSanitizer.detect_xss(self.email):
            raise ValueError("Email contains suspicious patterns")
        
        if not self.validate_email(self.email):
            raise ValueError("Invalid email format")
        
        # Validate birthdate
        if not self.birthdate:
            raise ValueError("Birthdate is required")
        
        # Additional birthdate validation
        from datetime import date
        today = date.today()
        if self.birthdate > today:
            raise ValueError("Birthdate cannot be in the future")
        
        if (today - self.birthdate).days > 150 * 365:
            raise ValueError("Birthdate is too old")
        
        return True
    
    def set_password(self, password):
        """Hash password with salt and store"""
        if not self.validate_password(password):
            raise ValueError("Password does not meet requirements")
        
        self.salt = secrets.token_hex(16)  # 32 character hex string
        self.password_hash = hashlib.sha256((password + self.salt).encode()).hexdigest()
    
    def verify_password(self, password):
        """Verify password against stored hash"""
        return hashlib.sha256((password + self.salt).encode()).hexdigest() == self.password_hash
    
    @staticmethod
    def validate_password(password):
        """Validate password requirements: minimum 8 characters, contains letters and numbers"""
        if len(password) < 8:
            return False
        
        has_letter = bool(re.search(r'[a-zA-Z]', password))
        has_number = bool(re.search(r'\d', password))
        
        return has_letter and has_number
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        # More strict email validation pattern
        email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        
        # Additional checks to prevent edge cases
        if not email or '..' in email or email.startswith('.') or email.endswith('.'):
            return False
        if email.startswith('@') or email.endswith('@'):
            return False
        if '@.' in email or '.@' in email:
            return False
        
        return bool(re.match(email_pattern, email))
    
    def validate_unique_username(self):
        """Check if username is unique"""
        existing_user = User.query.filter_by(username=self.username).first()
        return existing_user is None or existing_user.id == self.id
    
    def validate_unique_email(self):
        """Check if email is unique"""
        existing_user = User.query.filter_by(email=self.email).first()
        return existing_user is None or existing_user.id == self.id
    
    @classmethod
    def validate_email_for_creation(cls, email):
        """Validate email format and uniqueness for new user creation"""
        # Check format first
        if not cls.validate_email(email):
            return False, "Invalid email format"
        
        # Check uniqueness
        existing_user = cls.query.filter_by(email=email).first()
        if existing_user:
            return False, "Email already exists"
        
        return True, "Email is valid"
    
    def validate_email_for_update(self, new_email):
        """Validate email format and uniqueness for user update"""
        # Check format first
        if not self.validate_email(new_email):
            return False, "Invalid email format"
        
        # Check uniqueness (excluding current user)
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != self.id:
            return False, "Email already exists"
        
        return True, "Email is valid"
    
    @classmethod
    def is_email_unique(cls, email, exclude_user_id=None):
        """Check if email is unique in the database"""
        query = cls.query.filter_by(email=email)
        if exclude_user_id:
            query = query.filter(cls.id != exclude_user_id)
        return query.first() is None
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary, excluding sensitive data by default"""
        user_dict = {
            'id': self.id,
            'username': self.username,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'birthdate': self.birthdate.isoformat() if self.birthdate else None,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        if include_sensitive:
            user_dict.update({
                'password_hash': self.password_hash,
                'salt': self.salt
            })
        
        return user_dict
    
    def __repr__(self):
        return f'<User {self.username}>'

class OnlineUser(db.Model):
    """Model for tracking online users"""
    __tablename__ = 'online_user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 support
    login_datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __init__(self, username, ip_address, user_id, login_datetime=None):
        """Initialize online user record"""
        self.username = username
        self.ip_address = ip_address
        self.user_id = user_id
        self.login_datetime = login_datetime or datetime.utcnow()
    
    def validate(self):
        """Comprehensive model validation for security middleware"""
        from validation import InputValidator, InputSanitizer
        
        # Validate username
        if not self.username:
            raise ValueError("Username is required")
        
        if InputSanitizer.detect_sql_injection(self.username):
            raise ValueError("Username contains suspicious patterns")
        
        if InputSanitizer.detect_xss(self.username):
            raise ValueError("Username contains suspicious patterns")
        
        is_valid, message = InputValidator.validate_username(self.username)
        if not is_valid:
            raise ValueError(f"Username validation failed: {message}")
        
        # Validate IP address
        if not self.ip_address:
            raise ValueError("IP address is required")
        
        if InputSanitizer.detect_sql_injection(self.ip_address):
            raise ValueError("IP address contains suspicious patterns")
        
        if InputSanitizer.detect_xss(self.ip_address):
            raise ValueError("IP address contains suspicious patterns")
        
        is_valid, message = InputValidator.validate_ip_address(self.ip_address)
        if not is_valid:
            raise ValueError(f"IP address validation failed: {message}")
        
        # Validate user_id
        if not self.user_id or not isinstance(self.user_id, int) or self.user_id <= 0:
            raise ValueError("Valid user ID is required")
        
        return True
    
    @staticmethod
    def validate_ip_address(ip_address):
        """Basic IP address format validation"""
        # Simple validation for IPv4 and IPv6
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        
        return bool(re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address))
    
    def to_dict(self):
        """Convert online user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'ip_address': self.ip_address,
            'login_datetime': self.login_datetime.isoformat() if self.login_datetime else None,
            'user_id': self.user_id
        }
    
    @classmethod
    def get_online_users(cls):
        """Get all currently online users"""
        return cls.query.all()
    
    @classmethod
    def remove_user_from_online(cls, username):
        """Remove user from online list"""
        online_user = cls.query.filter_by(username=username).first()
        if online_user:
            db.session.delete(online_user)
            db.session.commit()
            return True
        return False
    
    def __repr__(self):
        return f'<OnlineUser {self.username} from {self.ip_address}>'

class UserLog(db.Model):
    """Model for logging user login/logout activities"""
    __tablename__ = 'user_log'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # 'login' or 'logout'
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Valid actions
    VALID_ACTIONS = ['login', 'logout']
    
    def __init__(self, username, action, ip_address, user_id, timestamp=None):
        """Initialize user log entry"""
        if not self.validate_action(action):
            raise ValueError(f"Invalid action. Must be one of: {', '.join(self.VALID_ACTIONS)}")
        
        self.username = username
        self.action = action
        self.ip_address = ip_address
        self.user_id = user_id
        self.timestamp = timestamp or datetime.utcnow()
    
    def validate(self):
        """Comprehensive model validation for security middleware"""
        from validation import InputValidator, InputSanitizer
        
        # Validate username
        if not self.username:
            raise ValueError("Username is required")
        
        if InputSanitizer.detect_sql_injection(self.username):
            raise ValueError("Username contains suspicious patterns")
        
        if InputSanitizer.detect_xss(self.username):
            raise ValueError("Username contains suspicious patterns")
        
        is_valid, message = InputValidator.validate_username(self.username)
        if not is_valid:
            raise ValueError(f"Username validation failed: {message}")
        
        # Validate action
        if not self.action:
            raise ValueError("Action is required")
        
        if not self.validate_action(self.action):
            raise ValueError(f"Invalid action. Must be one of: {', '.join(self.VALID_ACTIONS)}")
        
        # Validate IP address
        if not self.ip_address:
            raise ValueError("IP address is required")
        
        if InputSanitizer.detect_sql_injection(self.ip_address):
            raise ValueError("IP address contains suspicious patterns")
        
        if InputSanitizer.detect_xss(self.ip_address):
            raise ValueError("IP address contains suspicious patterns")
        
        is_valid, message = InputValidator.validate_ip_address(self.ip_address)
        if not is_valid:
            raise ValueError(f"IP address validation failed: {message}")
        
        # Validate user_id
        if not self.user_id or not isinstance(self.user_id, int) or self.user_id <= 0:
            raise ValueError("Valid user ID is required")
        
        return True
    
    @staticmethod
    def validate_action(action):
        """Validate that action is either 'login' or 'logout'"""
        return action in UserLog.VALID_ACTIONS
    
    @staticmethod
    def validate_ip_address(ip_address):
        """Basic IP address format validation"""
        # Simple validation for IPv4 and IPv6
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        
        return bool(re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address))
    
    def to_dict(self):
        """Convert user log to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'action': self.action,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': self.user_id
        }
    
    @classmethod
    def log_user_action(cls, username, action, ip_address, user_id):
        """Create a new log entry for user action"""
        log_entry = cls(username=username, action=action, ip_address=ip_address, user_id=user_id)
        db.session.add(log_entry)
        db.session.commit()
        return log_entry
    
    @classmethod
    def get_user_logs(cls, username=None, action=None, limit=None):
        """Get user logs with optional filtering"""
        query = cls.query
        
        if username:
            query = query.filter_by(username=username)
        
        if action:
            query = query.filter_by(action=action)
        
        query = query.order_by(cls.timestamp.desc())
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    def __repr__(self):
        return f'<UserLog {self.username} {self.action} at {self.timestamp}>'