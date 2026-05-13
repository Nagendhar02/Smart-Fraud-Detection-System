#!/usr/bin/env python3
"""
Database migration script to add new fraud detection features
"""

import sqlite3
import os
from app import create_app
from extensions import db

def migrate_database():
    """Add new columns for enhanced fraud detection"""
    
    app = create_app()
    
    with app.app_context():
        print("Starting database migration...")
        
        db_url = app.config['SQLALCHEMY_DATABASE_URI']
        if db_url.startswith('sqlite:///'):
            filename = db_url.replace('sqlite:///', '')
            if not os.path.isabs(filename):
                db_path = os.path.join(app.instance_path, filename)
            else:
                db_path = filename
        else:
            print("This migration is only for SQLite databases")
            return False

        print(f"Using SQLite database at: {db_path}")
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        if not os.path.exists(db_path):
            print(f"Database file not found: {db_path}")
            print("Creating new database with all columns...")
            db.create_all()
            print("✓ New database created successfully!")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("PRAGMA table_info(user_profile)")
            existing_columns = [column[1] for column in cursor.fetchall()]
            
            print(f"Existing user_profile columns: {existing_columns}")
            
            new_columns = [
                ('device_fingerprints', 'TEXT'),
                ('login_attempts', 'TEXT'),
                ('failed_login_count', 'INTEGER DEFAULT 0'),
                ('last_password_reset', 'DATETIME'),
                ('velocity_flags', 'TEXT'),
                ('password_reset_attempts', 'TEXT'),
                ('known_payment_methods', 'TEXT')
            ]
            
            for column_name, column_type in new_columns:
                if column_name not in existing_columns:
                    try:
                        cursor.execute(f"ALTER TABLE user_profile ADD COLUMN {column_name} {column_type}")
                        print(f"✓ Added column: {column_name}")
                    except sqlite3.Error as e:
                        print(f"⚠ Could not add {column_name}: {e}")
            
            cursor.execute("PRAGMA table_info(transaction)")
            existing_tx_columns = [column[1] for column in cursor.fetchall()]
            
            print(f"Existing transaction columns: {existing_tx_columns}")
            
            if 'card_type' not in existing_tx_columns:
                try:
                    cursor.execute('ALTER TABLE "transaction" ADD COLUMN card_type VARCHAR(20)')
                    print("✓ Added card_type column to transaction table")
                except sqlite3.Error as e1:
                    print(f"⚠ Could not add card_type with double quotes: {e1}")
                    try:
                        cursor.execute('ALTER TABLE [transaction] ADD COLUMN card_type VARCHAR(20)')
                        print("✓ Added card_type column to transaction table (bracket quoting)")
                    except sqlite3.Error as e2:
                        print(f"⚠ Could not add card_type with bracket quoting: {e2}")
            
            conn.commit()
            print("✓ Database migration completed successfully!")
            
        except sqlite3.Error as e:
            print(f"❌ Migration failed: {e}")
            conn.rollback()
            return False
            
        finally:
            conn.close()
    
    return True

def verify_migration():
    
    app = create_app()
    
    with app.app_context():
        try:
            from models import User, UserProfile
            
            test_user = User(username="migration_test", email="test@migration.com")
            test_user.set_password("test123")
            db.session.add(test_user)
            db.session.flush()
            
            profile = UserProfile(user_id=test_user.id)
            profile.device_fingerprints = '[]'
            profile.login_attempts = '[]'
            profile.failed_login_count = 0
            profile.velocity_flags = '[]'
            
            db.session.add(profile)
            db.session.commit()
            
            db.session.delete(test_user)
            db.session.commit()
            
            print("✓ Migration verification successful!")
            return True
            
        except Exception as e:
            print(f"❌ Migration verification failed: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    print("Fraud Detection Database Migration")
    print("=" * 40)
    
    if migrate_database():
        print("\n" + "=" * 40)
        print("Verifying migration...")
        
        if verify_migration():
            print("\n🎉 Migration completed successfully!")
            print("Your fraud detection system now supports:")
            print("- Payment method risk analysis")
            print("- Device fingerprinting")
            print("- Velocity tracking")
            print("- Login attempt monitoring")
        else:
            print("\n💥 Migration verification failed!")
    else:
        print("\n💥 Migration failed!")