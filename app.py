# Flask User Management Application
# Main application file

import os
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from config import get_config
from models import db
from error_handlers import register_error_handlers
from logging_config import LoggingConfig, RequestResponseLogger

def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config_class = get_config()
    app.config.from_object(config_class)
    
    # Initialize configuration
    config_class.init_app(app)
    
    # Setup comprehensive logging system
    LoggingConfig.setup_application_logging(app)
    
    # Initialize extensions with app
    db.init_app(app)
    
    # Initialize middleware
    from middleware import request_validation_middleware
    request_validation_middleware.init_app(app)
    
    # Initialize request/response logging middleware
    request_response_logger = RequestResponseLogger()
    request_response_logger.init_app(app)
    
    # Initialize database
    from database import db_manager
    db_manager.init_app(app)
    
    with app.app_context():
        try:
            # Test database connection
            if db_manager.check_database_connection():
                app.logger.info('Database connection successful')
                
                # Check if tables exist, create if missing
                tables_exist, missing_tables = db_manager.check_tables_exist()
                if not tables_exist:
                    app.logger.info(f'Missing tables detected: {missing_tables}')
                    app.logger.info('Initializing database...')
                    db_manager.initialize_database()
                    app.logger.info('Database initialization completed')
                else:
                    app.logger.info('Database tables already exist')
            else:
                app.logger.error('Database connection failed')
                if app.config.get('DEBUG') and not app.config.get('TESTING'):
                    raise Exception('Database connection failed')
            
        except Exception as e:
            app.logger.error(f'Database initialization failed: {str(e)}')
            # Don't raise exception in production, just log it
            if app.config.get('DEBUG'):
                raise
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register health check endpoint
    register_health_check(app)
    
    # Register routes
    from routes import api
    app.register_blueprint(api)
    
    return app



def register_health_check(app):
    """Register health check endpoint"""
    
    @app.route('/health')
    def health_check():
        """Health check endpoint to verify application and database status"""
        try:
            # Test database connection
            db.engine.connect()
            
            return jsonify({
                'success': True,
                'status': 'healthy',
                'database': 'connected',
                'timestamp': 'connected'  # Using string instead of db.func.now() for compatibility
            }), 200
            
        except Exception as e:
            app.logger.error(f'Health check failed: {str(e)}')
            
            return jsonify({
                'success': False,
                'status': 'unhealthy',
                'database': 'disconnected',
                'error': str(e) if app.config.get('DEBUG') else 'Database connection failed'
            }), 503

if __name__ == '__main__':
    app = create_app()
    
    # Run the application
    app.run(
        debug=app.config.get('DEBUG', True),
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000))
    )