# Database migration and initialization system
# Handles database table creation, indexes, constraints, and initialization

import os
import logging
from datetime import datetime
from flask import current_app
from sqlalchemy import text, inspect
from sqlalchemy.exc import SQLAlchemyError, ProgrammingError
from models import db, User, OnlineUser, UserLog

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database migration and initialization manager"""
    
    def __init__(self, app=None):
        """Initialize database manager"""
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
    
    def create_all_tables(self):
        """Create all database tables"""
        try:
            logger.info("Creating database tables...")
            
            # Create all tables defined in models
            db.create_all()
            
            logger.info("Database tables created successfully")
            return True
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to create database tables: {str(e)}")
            raise
    
    def create_indexes(self):
        """Create database indexes for performance optimization"""
        try:
            logger.info("Creating database indexes...")
            
            # Get database engine
            engine = db.engine
            
            # Check database type
            is_sqlite = 'sqlite' in str(engine.url)
            
            # Define indexes to create (adjust for SQLite)
            if is_sqlite:
                indexes = [
                    # User table indexes (SQLite doesn't need quotes around table names)
                    "CREATE INDEX IF NOT EXISTS idx_user_username ON user(username)",
                    "CREATE INDEX IF NOT EXISTS idx_user_email ON user(email)",
                    "CREATE INDEX IF NOT EXISTS idx_user_created_at ON user(created_at)",
                    
                    # OnlineUser table indexes
                    "CREATE INDEX IF NOT EXISTS idx_online_user_username ON online_user(username)",
                    "CREATE INDEX IF NOT EXISTS idx_online_user_user_id ON online_user(user_id)",
                    "CREATE INDEX IF NOT EXISTS idx_online_user_login_datetime ON online_user(login_datetime)",
                    
                    # UserLog table indexes
                    "CREATE INDEX IF NOT EXISTS idx_user_log_username ON user_log(username)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_user_id ON user_log(user_id)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_timestamp ON user_log(timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_action ON user_log(action)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_ip_address ON user_log(ip_address)"
                ]
            else:
                # PostgreSQL indexes
                indexes = [
                    # User table indexes
                    "CREATE INDEX IF NOT EXISTS idx_user_username ON \"user\"(username)",
                    "CREATE INDEX IF NOT EXISTS idx_user_email ON \"user\"(email)",
                    "CREATE INDEX IF NOT EXISTS idx_user_created_at ON \"user\"(created_at)",
                    
                    # OnlineUser table indexes
                    "CREATE INDEX IF NOT EXISTS idx_online_user_username ON online_user(username)",
                    "CREATE INDEX IF NOT EXISTS idx_online_user_user_id ON online_user(user_id)",
                    "CREATE INDEX IF NOT EXISTS idx_online_user_login_datetime ON online_user(login_datetime)",
                    
                    # UserLog table indexes
                    "CREATE INDEX IF NOT EXISTS idx_user_log_username ON user_log(username)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_user_id ON user_log(user_id)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_timestamp ON user_log(timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_action ON user_log(action)",
                    "CREATE INDEX IF NOT EXISTS idx_user_log_ip_address ON user_log(ip_address)"
                ]
            
            # Create each index
            with engine.connect() as connection:
                for index_sql in indexes:
                    try:
                        connection.execute(text(index_sql))
                        logger.debug(f"Created index: {index_sql}")
                    except ProgrammingError as e:
                        # Index might already exist, log but continue
                        logger.warning(f"Index creation warning: {str(e)}")
                
                # Commit the transaction
                connection.commit()
            
            logger.info("Database indexes created successfully")
            return True
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to create database indexes: {str(e)}")
            raise
    
    def create_constraints(self):
        """Create database constraints for data integrity"""
        try:
            logger.info("Creating database constraints...")
            
            # Get database engine
            engine = db.engine
            
            # Check database type
            is_sqlite = 'sqlite' in str(engine.url)
            is_postgresql = 'postgresql' in str(engine.url)
            
            if is_sqlite:
                # SQLite has limited constraint support, skip complex constraints
                logger.info("SQLite detected - skipping advanced constraints")
                return True
            
            # Define PostgreSQL constraints
            constraints = []
            
            if is_postgresql:
                constraints = [
                    # User table constraints
                    """ALTER TABLE "user" ADD CONSTRAINT IF NOT EXISTS chk_user_email_format 
                       CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')""",
                    
                    """ALTER TABLE "user" ADD CONSTRAINT IF NOT EXISTS chk_user_username_length 
                       CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 80)""",
                    
                    """ALTER TABLE "user" ADD CONSTRAINT IF NOT EXISTS chk_user_firstname_length 
                       CHECK (LENGTH(firstname) >= 1 AND LENGTH(firstname) <= 100)""",
                    
                    """ALTER TABLE "user" ADD CONSTRAINT IF NOT EXISTS chk_user_lastname_length 
                       CHECK (LENGTH(lastname) >= 1 AND LENGTH(lastname) <= 100)""",
                    
                    # UserLog table constraints
                    """ALTER TABLE user_log ADD CONSTRAINT IF NOT EXISTS chk_user_log_action_type 
                       CHECK (action IN ('login', 'logout'))""",
                    
                    """ALTER TABLE user_log ADD CONSTRAINT IF NOT EXISTS chk_user_log_username_length 
                       CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 80)""",
                    
                    # OnlineUser table constraints
                    """ALTER TABLE online_user ADD CONSTRAINT IF NOT EXISTS chk_online_user_username_length 
                       CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 80)""",
                    
                    """ALTER TABLE online_user ADD CONSTRAINT IF NOT EXISTS chk_online_user_ip_length 
                       CHECK (LENGTH(ip_address) >= 7 AND LENGTH(ip_address) <= 45)"""
                ]
            
            if not constraints:
                logger.info("No constraints to create for this database type")
                return True
            
            # Create each constraint
            with engine.connect() as connection:
                for constraint_sql in constraints:
                    try:
                        connection.execute(text(constraint_sql))
                        logger.debug(f"Created constraint: {constraint_sql}")
                    except ProgrammingError as e:
                        # Constraint might already exist, log but continue
                        logger.warning(f"Constraint creation warning: {str(e)}")
                
                # Commit the transaction
                connection.commit()
            
            logger.info("Database constraints created successfully")
            return True
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to create database constraints: {str(e)}")
            raise
    
    def check_database_connection(self):
        """Check if database connection is working"""
        try:
            # Test database connection
            with db.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            
            logger.info("Database connection successful")
            return True
            
        except SQLAlchemyError as e:
            logger.error(f"Database connection failed: {str(e)}")
            return False
    
    def check_tables_exist(self):
        """Check if all required tables exist"""
        try:
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            required_tables = ['user', 'online_user', 'user_log']
            missing_tables = [table for table in required_tables if table not in existing_tables]
            
            if missing_tables:
                logger.warning(f"Missing tables: {missing_tables}")
                return False, missing_tables
            
            logger.info("All required tables exist")
            return True, []
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to check table existence: {str(e)}")
            return False, []
    
    def initialize_database(self, force_recreate=False):
        """Complete database initialization process"""
        try:
            logger.info("Starting database initialization...")
            
            # Check database connection first
            if not self.check_database_connection():
                raise Exception("Database connection failed")
            
            # Check if tables exist
            tables_exist, missing_tables = self.check_tables_exist()
            
            if force_recreate or not tables_exist:
                logger.info("Creating database schema...")
                
                # Drop all tables if force recreate
                if force_recreate:
                    logger.warning("Force recreate enabled - dropping all tables")
                    db.drop_all()
                
                # Create all tables
                self.create_all_tables()
                
                # Create indexes
                self.create_indexes()
                
                # Create constraints
                self.create_constraints()
                
                logger.info("Database schema created successfully")
            else:
                logger.info("Database tables already exist, skipping creation")
                
                # Still try to create indexes and constraints in case they're missing
                try:
                    self.create_indexes()
                    self.create_constraints()
                except Exception as e:
                    logger.warning(f"Failed to create indexes/constraints: {str(e)}")
            
            # Verify database integrity
            self.verify_database_integrity()
            
            logger.info("Database initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise
    
    def verify_database_integrity(self):
        """Verify database integrity and structure"""
        try:
            logger.info("Verifying database integrity...")
            
            # Check table structure
            inspector = inspect(db.engine)
            
            # Verify User table structure
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            required_user_columns = ['id', 'username', 'firstname', 'lastname', 'birthdate', 
                                   'email', 'password_hash', 'salt', 'created_at']
            
            missing_user_columns = [col for col in required_user_columns if col not in user_columns]
            if missing_user_columns:
                raise Exception(f"Missing columns in user table: {missing_user_columns}")
            
            # Verify OnlineUser table structure
            online_user_columns = [col['name'] for col in inspector.get_columns('online_user')]
            required_online_columns = ['id', 'username', 'ip_address', 'login_datetime', 'user_id']
            
            missing_online_columns = [col for col in required_online_columns if col not in online_user_columns]
            if missing_online_columns:
                raise Exception(f"Missing columns in online_user table: {missing_online_columns}")
            
            # Verify UserLog table structure
            user_log_columns = [col['name'] for col in inspector.get_columns('user_log')]
            required_log_columns = ['id', 'username', 'action', 'ip_address', 'timestamp', 'user_id']
            
            missing_log_columns = [col for col in required_log_columns if col not in user_log_columns]
            if missing_log_columns:
                raise Exception(f"Missing columns in user_log table: {missing_log_columns}")
            
            # Test basic CRUD operations
            self._test_basic_operations()
            
            logger.info("Database integrity verification completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Database integrity verification failed: {str(e)}")
            raise
    
    def _test_basic_operations(self):
        """Test basic database operations"""
        try:
            # Test connection with a simple query
            with db.engine.connect() as connection:
                result = connection.execute(text("SELECT COUNT(*) FROM \"user\""))
                user_count = result.scalar()
                logger.debug(f"Current user count: {user_count}")
            
            logger.debug("Basic database operations test passed")
            
        except Exception as e:
            logger.error(f"Basic database operations test failed: {str(e)}")
            raise
    
    def create_sample_data(self):
        """Create sample data for testing (development only)"""
        if not current_app.config.get('DEBUG'):
            logger.warning("Sample data creation is only allowed in debug mode")
            return False
        
        try:
            logger.info("Creating sample data...")
            
            # Check if sample data already exists
            existing_users = User.query.count()
            if existing_users > 0:
                logger.info("Sample data already exists, skipping creation")
                return True
            
            # Create sample users
            sample_users = [
                {
                    'username': 'admin',
                    'firstname': 'Admin',
                    'lastname': 'User',
                    'birthdate': datetime(1990, 1, 1).date(),
                    'email': 'admin@example.com',
                    'password': 'admin123456'  # Meets requirements: 8+ chars, letters and numbers
                },
                {
                    'username': 'testuser',
                    'firstname': 'Test',
                    'lastname': 'User',
                    'birthdate': datetime(1995, 5, 15).date(),
                    'email': 'test@example.com',
                    'password': 'test123456'  # Meets requirements: 8+ chars, letters and numbers
                }
            ]
            
            for user_data in sample_users:
                user = User(**user_data)
                db.session.add(user)
            
            db.session.commit()
            
            logger.info("Sample data created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create sample data: {str(e)}")
            db.session.rollback()
            raise
    
    def get_database_info(self):
        """Get database information and statistics"""
        try:
            info = {
                'connection_status': 'connected' if self.check_database_connection() else 'disconnected',
                'tables': {},
                'indexes': [],
                'constraints': []
            }
            
            # Get table information
            inspector = inspect(db.engine)
            
            for table_name in ['user', 'online_user', 'user_log']:
                try:
                    columns = inspector.get_columns(table_name)
                    with db.engine.connect() as connection:
                        result = connection.execute(text(f'SELECT COUNT(*) FROM {table_name}'))
                        count = result.scalar()
                    
                    info['tables'][table_name] = {
                        'columns': len(columns),
                        'row_count': count
                    }
                except Exception as e:
                    info['tables'][table_name] = {'error': str(e)}
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get database info: {str(e)}")
            return {'error': str(e)}

# Global database manager instance
db_manager = DatabaseManager()

def init_database(app, force_recreate=False):
    """Initialize database with Flask app"""
    db_manager.init_app(app)
    return db_manager.initialize_database(force_recreate=force_recreate)

def create_database_tables():
    """Create all database tables"""
    return db_manager.create_all_tables()

def create_database_indexes():
    """Create all database indexes"""
    return db_manager.create_indexes()

def create_database_constraints():
    """Create all database constraints"""
    return db_manager.create_constraints()

def verify_database():
    """Verify database integrity"""
    return db_manager.verify_database_integrity()

def get_database_status():
    """Get current database status"""
    return db_manager.get_database_info()