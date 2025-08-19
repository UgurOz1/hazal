# Configuration settings for Flask User Management Application

import os
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class with common settings"""
    
    # Security settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Database settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_timeout': 20,
        'max_overflow': 0
    }
    
    # Application settings
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # Security headers
    SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year for static files
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        pass

class DevelopmentConfig(Config):
    """Development environment configuration"""
    
    DEBUG = True
    TESTING = False
    
    # Database configuration for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'postgresql://username:password@localhost/flask_user_management_dev'
    
    # Development-specific settings
    SQLALCHEMY_ECHO = os.environ.get('SQLALCHEMY_ECHO', 'False').lower() == 'true'
    
    @classmethod
    def init_app(cls, app):
        """Initialize development-specific settings"""
        Config.init_app(app)
        
        # Development logging will be handled by LoggingConfig
        pass

class ProductionConfig(Config):
    """Production environment configuration"""
    
    DEBUG = False
    TESTING = False
    
    # Database configuration for production
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Production-specific settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        **Config.SQLALCHEMY_ENGINE_OPTIONS,
        'pool_size': 10,
        'max_overflow': 20
    }
    
    @classmethod
    def init_app(cls, app):
        """Initialize production-specific settings"""
        Config.init_app(app)
        
        # Production logging will be handled by LoggingConfig
        pass

class TestingConfig(Config):
    """Testing environment configuration"""
    
    DEBUG = True
    TESTING = True
    
    # Use in-memory SQLite for testing
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///:memory:'
    
    # SQLite-specific engine options (remove PostgreSQL-specific options)
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True
    }
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    @classmethod
    def init_app(cls, app):
        """Initialize testing-specific settings"""
        Config.init_app(app)

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment variable"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])