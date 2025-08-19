# Database Setup and Migration Guide

This document describes the database initialization and migration system for the Flask User Management Application.

## Overview

The database system includes:
- Automatic table creation with proper indexes and constraints
- Migration tracking system
- Health check utilities
- Command-line management tools

## Database Schema

### Tables

1. **user** - Main user information table
   - Primary key: `id`
   - Unique constraints: `username`, `email`
   - Indexes: `username`, `email`, `created_at`

2. **online_user** - Tracks currently online users
   - Primary key: `id`
   - Foreign key: `user_id` → `user.id`
   - Indexes: `username`, `user_id`, `login_datetime`

3. **user_log** - Logs user login/logout activities
   - Primary key: `id`
   - Foreign key: `user_id` → `user.id`
   - Indexes: `username`, `user_id`, `timestamp`, `action`, `ip_address`

4. **migration_history** - Tracks applied database migrations
   - Primary key: `id`
   - Unique constraint: `migration_name`

### Constraints

- Email format validation
- Username length constraints (3-80 characters)
- Name length constraints (1-100 characters)
- Action type validation for user_log ('login' or 'logout')

## Quick Start

### 1. Environment Setup

Create a `.env` file with your database configuration:

```bash
# Development database
DEV_DATABASE_URL=postgresql://username:password@localhost/flask_user_management_dev

# Production database
DATABASE_URL=postgresql://username:password@localhost/flask_user_management_prod

# Optional: Enable SQL query logging in development
SQLALCHEMY_ECHO=true
```

### 2. Initialize Database

```bash
# Initialize database with tables, indexes, and constraints
python manage_db.py init

# Initialize with sample data for testing
python manage_db.py init --sample-data

# Force recreate (WARNING: destroys existing data)
python manage_db.py init --force
```

### 3. Check Database Status

```bash
# Check database connection and table status
python manage_db.py status

# Verify database integrity
python manage_db.py verify

# Health check with JSON output
python db_health_check.py --json
```

## Command Line Tools

### manage_db.py

Main database management tool with the following commands:

```bash
# Initialize database (recommended for first setup)
python manage_db.py init [--force] [--sample-data]

# Create only tables
python manage_db.py create-tables

# Create only indexes
python manage_db.py create-indexes

# Create only constraints
python manage_db.py create-constraints

# Verify database integrity
python manage_db.py verify

# Check database status
python manage_db.py status

# Drop all tables (dangerous!)
python manage_db.py drop [--confirm]

# Reset database (drop and recreate)
python manage_db.py reset [--confirm] [--sample-data]

# Create sample data
python manage_db.py sample-data
```

### migrate.py

Migration management tool:

```bash
# Run initial migration
python migrate.py init

# Run all pending migrations
python migrate.py migrate

# Show migration status
python migrate.py status
```

### db_health_check.py

Database health monitoring:

```bash
# Text format health check
python db_health_check.py

# JSON format health check
python db_health_check.py --json
```

## Deployment

### Development Environment

1. Set up PostgreSQL database
2. Configure `.env` file with database URL
3. Run initialization:
   ```bash
   python manage_db.py init --sample-data
   ```

### Production Environment

1. Set up PostgreSQL database
2. Set `DATABASE_URL` environment variable
3. Set `FLASK_ENV=production`
4. Run migration:
   ```bash
   python migrate.py migrate
   ```

### Docker Deployment

If using Docker, add to your Dockerfile:

```dockerfile
# Copy database scripts
COPY manage_db.py migrate.py db_health_check.py ./

# Run database initialization
RUN python migrate.py migrate
```

## Automatic Initialization

The Flask application automatically checks database status on startup:

- If tables are missing, they are created automatically
- Indexes and constraints are applied
- Connection is verified before starting

This behavior can be controlled in `app.py` and is safe for production use.

## Database Configuration

### Connection Pooling

The application uses SQLAlchemy connection pooling:

```python
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_pre_ping': True,      # Verify connections before use
    'pool_recycle': 300,        # Recycle connections every 5 minutes
    'pool_timeout': 20,         # Connection timeout
    'max_overflow': 0,          # No overflow connections in development
    'pool_size': 10,            # Production pool size
    'max_overflow': 20          # Production overflow
}
```

### Environment-Specific Settings

- **Development**: SQLite or PostgreSQL with debug logging
- **Production**: PostgreSQL with connection pooling and file logging
- **Testing**: In-memory SQLite database

## Monitoring and Maintenance

### Health Checks

Use the health check script for monitoring:

```bash
# Basic health check
python db_health_check.py

# Automated monitoring (returns exit codes)
python db_health_check.py --json
# Exit codes: 0=healthy, 1=degraded, 2=unhealthy, 3=error
```

### Performance Monitoring

The health check includes:
- Connection time measurement
- Query response time testing
- Table row count statistics

### Backup Recommendations

1. **Regular Backups**: Use `pg_dump` for PostgreSQL
2. **Migration History**: Keep migration_history table in backups
3. **Test Restores**: Regularly test backup restoration

## Troubleshooting

### Common Issues

1. **Connection Failed**
   ```bash
   # Check database is running
   python db_health_check.py
   
   # Verify connection string
   python manage_db.py status
   ```

2. **Missing Tables**
   ```bash
   # Reinitialize database
   python manage_db.py init
   ```

3. **Permission Errors**
   ```bash
   # Check database user permissions
   # Ensure user can CREATE, ALTER, DROP tables
   ```

4. **Migration Issues**
   ```bash
   # Check migration status
   python migrate.py status
   
   # Force reinitialize if needed
   python manage_db.py reset --confirm
   ```

### Debug Mode

Enable verbose logging:

```bash
python manage_db.py -v status
```

Set environment variable:

```bash
export SQLALCHEMY_ECHO=true
```

## Security Considerations

1. **Database Credentials**: Store in environment variables, not code
2. **Connection Encryption**: Use SSL for production databases
3. **User Permissions**: Use dedicated database user with minimal permissions
4. **Backup Security**: Encrypt database backups
5. **Network Security**: Restrict database network access

## API Integration

The database system integrates with the Flask application:

```python
from database import db_manager, init_database

# In your Flask app
app = create_app()
with app.app_context():
    init_database(app)
```

## Future Enhancements

Planned improvements:
- Automatic schema migrations
- Database versioning
- Performance optimization tools
- Backup automation
- Monitoring dashboard integration