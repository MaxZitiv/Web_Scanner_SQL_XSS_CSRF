import os
import sys
import sqlite3

# Add the project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from utils.database import db
from utils.logger import logger

def migrate_avatar_column():
    """Add avatar_path column to users table if it doesn't exist"""
    conn = None
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        # Check if avatar_path column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'avatar_path' not in columns:
            logger.info("Adding avatar_path column to users table...")
            cursor.execute('''
                ALTER TABLE users 
                ADD COLUMN avatar_path TEXT 
                DEFAULT "default_avatar.png"
            ''')
            conn.commit()
            logger.info("Avatar path column added successfully")
        else:
            logger.info("Avatar path column already exists")
            
    except sqlite3.Error as e:
        logger.error(f"Database error during avatar migration: {e}")
        raise
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    migrate_avatar_column()