#!/usr/bin/env python3
# Test script for database initialization system
# Uses in-memory SQLite for testing without requiring PostgreSQL

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from database import DatabaseManager, db_manager
from models import db, User, OnlineUser, UserLog

class TestDatabaseInitialization(unittest.TestCase):
    """Test database initialization functionality"""
    
    def setUp(self):
        """Set up test environment"""
        # Set environment to testing to use SQLite
        os.environ['FLASK_ENV'] = 'testing'
        
        # Create test app with in-memory SQLite
        self.app = create_app('testing')
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}
        
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Initialize database manager
        self.db_manager = DatabaseManager(self.app)
    
    def tearDown(self):
        """Clean up test environment"""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    def test_database_connection(self):
        """Test database connection check"""
        result = self.db_manager.check_database_connection()
        self.assertTrue(result, "Database connection should succeed")
    
    def test_create_tables(self):
        """Test table creation"""
        # Drop tables first to test creation
        db.drop_all()
        
        # Now no tables should exist
        tables_exist, missing_tables = self.db_manager.check_tables_exist()
        self.assertFalse(tables_exist, "Tables should not exist after drop")
        self.assertEqual(set(missing_tables), {'user', 'online_user', 'user_log'})
        
        # Create tables
        result = self.db_manager.create_all_tables()
        self.assertTrue(result, "Table creation should succeed")
        
        # Now tables should exist
        tables_exist, missing_tables = self.db_manager.check_tables_exist()
        self.assertTrue(tables_exist, "Tables should exist after creation")
        self.assertEqual(missing_tables, [])
    
    def test_create_indexes(self):
        """Test index creation"""
        # Create tables first
        self.db_manager.create_all_tables()
        
        # Create indexes (should not fail even if some already exist)
        result = self.db_manager.create_indexes()
        self.assertTrue(result, "Index creation should succeed")
    
    def test_create_constraints(self):
        """Test constraint creation"""
        # Create tables first
        self.db_manager.create_all_tables()
        
        # Create constraints (should not fail even if some already exist)
        result = self.db_manager.create_constraints()
        self.assertTrue(result, "Constraint creation should succeed")
    
    def test_full_initialization(self):
        """Test complete database initialization"""
        result = self.db_manager.initialize_database()
        self.assertTrue(result, "Database initialization should succeed")
        
        # Verify tables exist
        tables_exist, missing_tables = self.db_manager.check_tables_exist()
        self.assertTrue(tables_exist, "Tables should exist after initialization")
        
        # Verify integrity
        result = self.db_manager.verify_database_integrity()
        self.assertTrue(result, "Database integrity verification should pass")
    
    def test_database_info(self):
        """Test database information retrieval"""
        # Initialize database first
        self.db_manager.initialize_database()
        
        info = self.db_manager.get_database_info()
        self.assertIn('connection_status', info)
        self.assertIn('tables', info)
        self.assertEqual(info['connection_status'], 'connected')
        
        # Check table info
        for table_name in ['user', 'online_user', 'user_log']:
            self.assertIn(table_name, info['tables'])
            self.assertIn('row_count', info['tables'][table_name])
    
    def test_sample_data_creation(self):
        """Test sample data creation"""
        # Initialize database first
        self.db_manager.initialize_database()
        
        # Create sample data
        result = self.db_manager.create_sample_data()
        self.assertTrue(result, "Sample data creation should succeed")
        
        # Verify sample data exists
        user_count = User.query.count()
        self.assertGreater(user_count, 0, "Sample users should be created")
        
        # Verify sample user properties
        admin_user = User.query.filter_by(username='admin').first()
        self.assertIsNotNone(admin_user, "Admin user should exist")
        self.assertEqual(admin_user.email, 'admin@example.com')
        self.assertTrue(admin_user.verify_password('admin123456'), "Admin password should be correct")
    
    def test_model_validation(self):
        """Test that models work correctly with initialized database"""
        # Initialize database
        self.db_manager.initialize_database()
        
        # Test User model
        from datetime import date
        user = User(
            username='testuser',
            firstname='Test',
            lastname='User',
            birthdate=date(1990, 1, 1),
            email='test@example.com',
            password='testpass123'
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Verify user was created
        retrieved_user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(retrieved_user)
        self.assertEqual(retrieved_user.email, 'test@example.com')
        self.assertTrue(retrieved_user.verify_password('testpass123'))
    
    def test_force_recreate(self):
        """Test force recreate functionality"""
        # Initialize database first
        self.db_manager.initialize_database()
        
        # Add some data
        user = User(
            username='testuser',
            firstname='Test',
            lastname='User',
            birthdate=date(1990, 1, 1),
            email='test@example.com',
            password='testpass123'
        )
        db.session.add(user)
        db.session.commit()
        
        # Verify data exists
        self.assertEqual(User.query.count(), 1)
        
        # Force recreate
        result = self.db_manager.initialize_database(force_recreate=True)
        self.assertTrue(result, "Force recreate should succeed")
        
        # Verify data is gone
        self.assertEqual(User.query.count(), 0)

def run_tests():
    """Run all database initialization tests"""
    print("Running database initialization tests...")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestDatabaseInitialization)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✓ All database initialization tests passed!")
        return True
    else:
        print(f"✗ {len(result.failures)} test(s) failed, {len(result.errors)} error(s)")
        return False

if __name__ == '__main__':
    # Import required for date usage in tests
    from datetime import date
    
    success = run_tests()
    sys.exit(0 if success else 1)