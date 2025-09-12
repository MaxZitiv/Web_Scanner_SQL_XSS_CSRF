import os
import sqlite3
from utils.logger import logger

def fix_database():
    db_path = 'scanner.db'
    conn = None
    try:
        # Check if database exists
        if not os.path.exists(db_path):
            logger.error(f"Database file not found: {db_path}")
            return False

        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if avatar_path column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        
        # Add avatar_path if it doesn't exist
        if 'avatar_path' not in columns:
            logger.info("Adding avatar_path column...")
            cursor.execute('ALTER TABLE users ADD COLUMN avatar_path TEXT DEFAULT "default_avatar.png"')
            logger.info("Avatar path column added successfully")

        # Commit changes
        conn.commit()
        return True

    except Exception as e:
        logger.error(f"Error fixing database: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    if fix_database():
        print("Database fixed successfully")
    else:
        print("Error fixing database")