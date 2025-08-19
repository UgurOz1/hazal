#!/usr/bin/env python3
# Database management CLI script
# Provides command-line interface for database operations

import sys
import os
import argparse
import logging
from datetime import datetime

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from database import db_manager
from models import db

def setup_logging(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def init_database(args):
    """Initialize database with tables, indexes, and constraints"""
    print("Initializing database...")
    
    app = create_app()
    with app.app_context():
        try:
            success = db_manager.initialize_database(force_recreate=args.force)
            if success:
                print("✓ Database initialization completed successfully")
                
                if args.sample_data:
                    print("Creating sample data...")
                    db_manager.create_sample_data()
                    print("✓ Sample data created successfully")
                
                return 0
            else:
                print("✗ Database initialization failed")
                return 1
                
        except Exception as e:
            print(f"✗ Database initialization failed: {str(e)}")
            return 1

def create_tables(args):
    """Create database tables only"""
    print("Creating database tables...")
    
    app = create_app()
    with app.app_context():
        try:
            success = db_manager.create_all_tables()
            if success:
                print("✓ Database tables created successfully")
                return 0
            else:
                print("✗ Failed to create database tables")
                return 1
                
        except Exception as e:
            print(f"✗ Failed to create database tables: {str(e)}")
            return 1

def create_indexes(args):
    """Create database indexes only"""
    print("Creating database indexes...")
    
    app = create_app()
    with app.app_context():
        try:
            success = db_manager.create_indexes()
            if success:
                print("✓ Database indexes created successfully")
                return 0
            else:
                print("✗ Failed to create database indexes")
                return 1
                
        except Exception as e:
            print(f"✗ Failed to create database indexes: {str(e)}")
            return 1

def create_constraints(args):
    """Create database constraints only"""
    print("Creating database constraints...")
    
    app = create_app()
    with app.app_context():
        try:
            success = db_manager.create_constraints()
            if success:
                print("✓ Database constraints created successfully")
                return 0
            else:
                print("✗ Failed to create database constraints")
                return 1
                
        except Exception as e:
            print(f"✗ Failed to create database constraints: {str(e)}")
            return 1

def verify_database(args):
    """Verify database integrity"""
    print("Verifying database integrity...")
    
    app = create_app()
    with app.app_context():
        try:
            success = db_manager.verify_database_integrity()
            if success:
                print("✓ Database integrity verification passed")
                return 0
            else:
                print("✗ Database integrity verification failed")
                return 1
                
        except Exception as e:
            print(f"✗ Database integrity verification failed: {str(e)}")
            return 1

def check_status(args):
    """Check database status and information"""
    print("Checking database status...")
    
    app = create_app()
    with app.app_context():
        try:
            # Check connection
            if db_manager.check_database_connection():
                print("✓ Database connection: OK")
            else:
                print("✗ Database connection: FAILED")
                return 1
            
            # Check tables
            tables_exist, missing_tables = db_manager.check_tables_exist()
            if tables_exist:
                print("✓ Required tables: OK")
            else:
                print(f"✗ Missing tables: {missing_tables}")
            
            # Get database info
            info = db_manager.get_database_info()
            
            print("\nDatabase Information:")
            print(f"Connection Status: {info.get('connection_status', 'unknown')}")
            
            if 'tables' in info:
                print("\nTable Information:")
                for table_name, table_info in info['tables'].items():
                    if 'error' in table_info:
                        print(f"  {table_name}: ERROR - {table_info['error']}")
                    else:
                        print(f"  {table_name}: {table_info['row_count']} rows, {table_info['columns']} columns")
            
            return 0
            
        except Exception as e:
            print(f"✗ Failed to check database status: {str(e)}")
            return 1

def drop_tables(args):
    """Drop all database tables"""
    if not args.confirm:
        print("This will drop ALL database tables and data!")
        confirm = input("Are you sure? Type 'yes' to confirm: ")
        if confirm.lower() != 'yes':
            print("Operation cancelled")
            return 0
    
    print("Dropping all database tables...")
    
    app = create_app()
    with app.app_context():
        try:
            db.drop_all()
            print("✓ All database tables dropped successfully")
            return 0
            
        except Exception as e:
            print(f"✗ Failed to drop database tables: {str(e)}")
            return 1

def reset_database(args):
    """Reset database (drop and recreate)"""
    if not args.confirm:
        print("This will RESET the entire database, destroying all data!")
        confirm = input("Are you sure? Type 'yes' to confirm: ")
        if confirm.lower() != 'yes':
            print("Operation cancelled")
            return 0
    
    print("Resetting database...")
    
    app = create_app()
    with app.app_context():
        try:
            # Drop all tables
            db.drop_all()
            print("✓ Dropped all tables")
            
            # Initialize database
            success = db_manager.initialize_database(force_recreate=False)
            if success:
                print("✓ Database reset completed successfully")
                
                if args.sample_data:
                    print("Creating sample data...")
                    db_manager.create_sample_data()
                    print("✓ Sample data created successfully")
                
                return 0
            else:
                print("✗ Database reset failed")
                return 1
                
        except Exception as e:
            print(f"✗ Database reset failed: {str(e)}")
            return 1

def create_sample_data(args):
    """Create sample data for testing"""
    print("Creating sample data...")
    
    app = create_app()
    with app.app_context():
        try:
            success = db_manager.create_sample_data()
            if success:
                print("✓ Sample data created successfully")
                return 0
            else:
                print("✗ Failed to create sample data")
                return 1
                
        except Exception as e:
            print(f"✗ Failed to create sample data: {str(e)}")
            return 1

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='Database management CLI for Flask User Management Application',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python manage_db.py init                    # Initialize database
  python manage_db.py init --force            # Force recreate database
  python manage_db.py init --sample-data      # Initialize with sample data
  python manage_db.py status                  # Check database status
  python manage_db.py verify                  # Verify database integrity
  python manage_db.py reset --confirm         # Reset database (dangerous!)
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize database')
    init_parser.add_argument('--force', action='store_true',
                           help='Force recreate all tables')
    init_parser.add_argument('--sample-data', action='store_true',
                           help='Create sample data after initialization')
    init_parser.set_defaults(func=init_database)
    
    # Create tables command
    tables_parser = subparsers.add_parser('create-tables', help='Create database tables')
    tables_parser.set_defaults(func=create_tables)
    
    # Create indexes command
    indexes_parser = subparsers.add_parser('create-indexes', help='Create database indexes')
    indexes_parser.set_defaults(func=create_indexes)
    
    # Create constraints command
    constraints_parser = subparsers.add_parser('create-constraints', help='Create database constraints')
    constraints_parser.set_defaults(func=create_constraints)
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify database integrity')
    verify_parser.set_defaults(func=verify_database)
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check database status')
    status_parser.set_defaults(func=check_status)
    
    # Drop tables command
    drop_parser = subparsers.add_parser('drop', help='Drop all database tables')
    drop_parser.add_argument('--confirm', action='store_true',
                           help='Skip confirmation prompt')
    drop_parser.set_defaults(func=drop_tables)
    
    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Reset database (drop and recreate)')
    reset_parser.add_argument('--confirm', action='store_true',
                            help='Skip confirmation prompt')
    reset_parser.add_argument('--sample-data', action='store_true',
                            help='Create sample data after reset')
    reset_parser.set_defaults(func=reset_database)
    
    # Sample data command
    sample_parser = subparsers.add_parser('sample-data', help='Create sample data')
    sample_parser.set_defaults(func=create_sample_data)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Execute command
    if hasattr(args, 'func'):
        try:
            return args.func(args)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return 1
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    else:
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())