#!/usr/bin/env python3
# Database migration script for deployment
# Simple migration system for Flask User Management Application

import os
import sys
import logging
from datetime import datetime

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from database import db_manager
from models import db

# Migration tracking table SQL
MIGRATION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS migration_history (
    id SERIAL PRIMARY KEY,
    migration_name VARCHAR(255) NOT NULL UNIQUE,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT
)
"""

class MigrationManager:
    """Simple migration manager for database schema changes"""
    
    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger(__name__)
    
    def ensure_migration_table(self):
        """Ensure migration tracking table exists"""
        try:
            with db.engine.connect() as connection:
                connection.execute(db.text(MIGRATION_TABLE_SQL))
                connection.commit()
            return True
        except Exception as e:
            self.logger.error(f"Failed to create migration table: {str(e)}")
            return False
    
    def is_migration_applied(self, migration_name):
        """Check if migration has been applied"""
        try:
            with db.engine.connect() as connection:
                result = connection.execute(
                    db.text("SELECT COUNT(*) FROM migration_history WHERE migration_name = :name"),
                    {"name": migration_name}
                )
                return result.scalar() > 0
        except Exception as e:
            self.logger.error(f"Failed to check migration status: {str(e)}")
            return False
    
    def record_migration(self, migration_name, description=""):
        """Record that a migration has been applied"""
        try:
            with db.engine.connect() as connection:
                connection.execute(
                    db.text("""
                        INSERT INTO migration_history (migration_name, description) 
                        VALUES (:name, :desc)
                    """),
                    {"name": migration_name, "desc": description}
                )
                connection.commit()
            return True
        except Exception as e:
            self.logger.error(f"Failed to record migration: {str(e)}")
            return False
    
    def get_applied_migrations(self):
        """Get list of applied migrations"""
        try:
            with db.engine.connect() as connection:
                result = connection.execute(
                    db.text("SELECT migration_name, applied_at, description FROM migration_history ORDER BY applied_at")
                )
                return result.fetchall()
        except Exception as e:
            self.logger.error(f"Failed to get migration history: {str(e)}")
            return []

def run_initial_migration():
    """Run initial database setup migration"""
    print("Running initial database migration...")
    
    app = create_app()
    migration_manager = MigrationManager(app)
    
    with app.app_context():
        try:
            # Ensure migration table exists
            if not migration_manager.ensure_migration_table():
                print("✗ Failed to create migration tracking table")
                return False
            
            migration_name = "001_initial_setup"
            
            # Check if already applied
            if migration_manager.is_migration_applied(migration_name):
                print("✓ Initial migration already applied")
                return True
            
            # Run database initialization
            print("Creating database schema...")
            success = db_manager.initialize_database()
            
            if success:
                # Record migration
                migration_manager.record_migration(
                    migration_name,
                    "Initial database setup with tables, indexes, and constraints"
                )
                print("✓ Initial migration completed successfully")
                return True
            else:
                print("✗ Initial migration failed")
                return False
                
        except Exception as e:
            print(f"✗ Initial migration failed: {str(e)}")
            return False

def run_all_migrations():
    """Run all pending migrations"""
    print("Running all database migrations...")
    
    # For now, we only have the initial migration
    # Future migrations can be added here
    migrations = [
        ("001_initial_setup", run_initial_migration, "Initial database setup")
    ]
    
    app = create_app()
    migration_manager = MigrationManager(app)
    
    with app.app_context():
        try:
            # Ensure migration table exists
            if not migration_manager.ensure_migration_table():
                print("✗ Failed to create migration tracking table")
                return False
            
            applied_count = 0
            
            for migration_name, migration_func, description in migrations:
                if not migration_manager.is_migration_applied(migration_name):
                    print(f"Applying migration: {migration_name}")
                    if migration_name == "001_initial_setup":
                        # Special handling for initial migration
                        success = db_manager.initialize_database()
                        if success:
                            migration_manager.record_migration(migration_name, description)
                            applied_count += 1
                            print(f"✓ Applied migration: {migration_name}")
                        else:
                            print(f"✗ Failed to apply migration: {migration_name}")
                            return False
                    else:
                        # Future migrations would be handled here
                        pass
                else:
                    print(f"✓ Migration already applied: {migration_name}")
            
            if applied_count > 0:
                print(f"✓ Applied {applied_count} migrations successfully")
            else:
                print("✓ All migrations are up to date")
            
            return True
            
        except Exception as e:
            print(f"✗ Migration failed: {str(e)}")
            return False

def show_migration_status():
    """Show current migration status"""
    print("Migration Status:")
    print("-" * 50)
    
    app = create_app()
    migration_manager = MigrationManager(app)
    
    with app.app_context():
        try:
            # Check if migration table exists
            if not migration_manager.ensure_migration_table():
                print("Migration tracking table does not exist")
                return False
            
            applied_migrations = migration_manager.get_applied_migrations()
            
            if applied_migrations:
                print("Applied Migrations:")
                for migration in applied_migrations:
                    print(f"  ✓ {migration[0]} - {migration[1]} - {migration[2]}")
            else:
                print("No migrations have been applied yet")
            
            return True
            
        except Exception as e:
            print(f"✗ Failed to get migration status: {str(e)}")
            return False

def main():
    """Main migration script"""
    if len(sys.argv) < 2:
        print("Usage: python migrate.py [init|migrate|status]")
        print("  init    - Run initial database setup")
        print("  migrate - Run all pending migrations")
        print("  status  - Show migration status")
        return 1
    
    command = sys.argv[1]
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        if command == "init":
            success = run_initial_migration()
        elif command == "migrate":
            success = run_all_migrations()
        elif command == "status":
            success = show_migration_status()
        else:
            print(f"Unknown command: {command}")
            return 1
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return 1

if __name__ == '__main__':
    sys.exit(main())