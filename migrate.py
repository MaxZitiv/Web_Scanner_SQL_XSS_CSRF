import sqlite3 
from utils.init_db import migrate_database
from utils.logger import logger
from utils.database import db
from utils.logger import logger

def add_avatar_path_column():
    conn = None
    try:
        # Connect to the database    
        conn = sqlite3.connect('scanner.db')        
        logger.info("Starting database migration...")
        cursor = conn.cursor()        
        migrate_database()

        logger.info("Database migration completed successfully")

        # Add the avatar_path column if it doesn't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]

        if 'avatar_path' not in columns:
            logger.info("Adding avatar_path column to users table...")
            cursor.execute('ALTER TABLE users ADD COLUMN avatar_path TEXT DEFAULT "default_avatar.png"')
            conn.commit()
            logger.info("Successfully added avatar_path column")
        else:
            logger.info("avatar_path column already exists")

    except Exception as e:
        logger.error(f"Error adding avatar_path column: {e}")
        raise
    finally:
        if conn:
            conn.close()

def main():
    try:
        logger.info("Starting database migration...")
        add_avatar_path_column()
        logger.info("Database migration completed successfully")
    except Exception as e:
        logger.error(f"Error during migration: {e}")

if __name__ == "__main__":
    main()