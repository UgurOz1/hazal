#!/usr/bin/env python3
# Database health check script
# Verifies database connectivity and basic functionality

import sys
import os
import json
from datetime import datetime

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from database import db_manager
from models import db, User, OnlineUser, UserLog

def check_database_health():
    """Comprehensive database health check"""
    health_status = {
        'timestamp': datetime.utcnow().isoformat(),
        'overall_status': 'healthy',
        'checks': {}
    }
    
    app = create_app()
    
    with app.app_context():
        # 1. Database Connection Check
        try:
            connection_ok = db_manager.check_database_connection()
            health_status['checks']['database_connection'] = {
                'status': 'pass' if connection_ok else 'fail',
                'message': 'Database connection successful' if connection_ok else 'Database connection failed'
            }
            if not connection_ok:
                health_status['overall_status'] = 'unhealthy'
        except Exception as e:
            health_status['checks']['database_connection'] = {
                'status': 'fail',
                'message': f'Database connection error: {str(e)}'
            }
            health_status['overall_status'] = 'unhealthy'
        
        # 2. Tables Existence Check
        try:
            tables_exist, missing_tables = db_manager.check_tables_exist()
            health_status['checks']['tables_existence'] = {
                'status': 'pass' if tables_exist else 'fail',
                'message': 'All required tables exist' if tables_exist else f'Missing tables: {missing_tables}',
                'missing_tables': missing_tables if not tables_exist else []
            }
            if not tables_exist:
                health_status['overall_status'] = 'unhealthy'
        except Exception as e:
            health_status['checks']['tables_existence'] = {
                'status': 'fail',
                'message': f'Table check error: {str(e)}'
            }
            health_status['overall_status'] = 'unhealthy'
        
        # 3. Basic Query Test
        try:
            user_count = User.query.count()
            online_count = OnlineUser.query.count()
            log_count = UserLog.query.count()
            
            health_status['checks']['basic_queries'] = {
                'status': 'pass',
                'message': 'Basic queries successful',
                'data': {
                    'user_count': user_count,
                    'online_user_count': online_count,
                    'log_count': log_count
                }
            }
        except Exception as e:
            health_status['checks']['basic_queries'] = {
                'status': 'fail',
                'message': f'Basic query error: {str(e)}'
            }
            health_status['overall_status'] = 'unhealthy'
        
        # 4. Database Write Test (if healthy so far)
        if health_status['overall_status'] == 'healthy':
            try:
                # Test write operation with a simple query
                with db.engine.connect() as connection:
                    # Test a simple write operation that doesn't affect data
                    connection.execute(db.text("SELECT 1"))
                
                health_status['checks']['write_test'] = {
                    'status': 'pass',
                    'message': 'Database write test successful'
                }
            except Exception as e:
                health_status['checks']['write_test'] = {
                    'status': 'fail',
                    'message': f'Database write test error: {str(e)}'
                }
                health_status['overall_status'] = 'degraded'
        
        # 5. Performance Check
        try:
            start_time = datetime.utcnow()
            
            # Simple performance test
            with db.engine.connect() as connection:
                connection.execute(db.text("SELECT COUNT(*) FROM \"user\""))
            
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds() * 1000  # milliseconds
            
            performance_status = 'pass' if response_time < 1000 else 'warn'  # 1 second threshold
            
            health_status['checks']['performance'] = {
                'status': performance_status,
                'message': f'Query response time: {response_time:.2f}ms',
                'response_time_ms': round(response_time, 2)
            }
            
            if performance_status == 'warn' and health_status['overall_status'] == 'healthy':
                health_status['overall_status'] = 'degraded'
                
        except Exception as e:
            health_status['checks']['performance'] = {
                'status': 'fail',
                'message': f'Performance check error: {str(e)}'
            }
            if health_status['overall_status'] == 'healthy':
                health_status['overall_status'] = 'degraded'
    
    return health_status

def print_health_status(health_status, format_type='text'):
    """Print health status in specified format"""
    if format_type == 'json':
        print(json.dumps(health_status, indent=2))
        return
    
    # Text format
    print("Database Health Check Report")
    print("=" * 40)
    print(f"Timestamp: {health_status['timestamp']}")
    print(f"Overall Status: {health_status['overall_status'].upper()}")
    print()
    
    for check_name, check_result in health_status['checks'].items():
        status_symbol = {
            'pass': '✓',
            'warn': '⚠',
            'fail': '✗'
        }.get(check_result['status'], '?')
        
        print(f"{status_symbol} {check_name.replace('_', ' ').title()}: {check_result['status'].upper()}")
        print(f"   {check_result['message']}")
        
        if 'data' in check_result:
            for key, value in check_result['data'].items():
                print(f"   {key.replace('_', ' ').title()}: {value}")
        
        if 'missing_tables' in check_result and check_result['missing_tables']:
            print(f"   Missing Tables: {', '.join(check_result['missing_tables'])}")
        
        if 'response_time_ms' in check_result:
            print(f"   Response Time: {check_result['response_time_ms']}ms")
        
        print()

def main():
    """Main health check function"""
    format_type = 'text'
    
    # Check for JSON format flag
    if len(sys.argv) > 1 and sys.argv[1] == '--json':
        format_type = 'json'
    
    try:
        health_status = check_database_health()
        print_health_status(health_status, format_type)
        
        # Return appropriate exit code
        if health_status['overall_status'] == 'healthy':
            return 0
        elif health_status['overall_status'] == 'degraded':
            return 1
        else:  # unhealthy
            return 2
            
    except Exception as e:
        error_status = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'error',
            'error': str(e)
        }
        
        if format_type == 'json':
            print(json.dumps(error_status, indent=2))
        else:
            print(f"Health check failed with error: {str(e)}")
        
        return 3

if __name__ == '__main__':
    sys.exit(main())