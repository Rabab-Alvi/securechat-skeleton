#!/usr/bin/env python3
"""
Setup MySQL database and tables for SecureChat
"""

import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

load_dotenv()

def create_database():
    """Create the database if it doesn't exist"""
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD')
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Create database
            db_name = os.getenv('DB_NAME', 'securechat')
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            print(f"[✓] Database '{db_name}' created/verified")
            
            cursor.close()
            connection.close()
            return True
            
    except Error as e:
        print(f"[ERROR] Database creation failed: {e}")
        return False

def setup_tables():
    """Create necessary tables"""
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME', 'securechat')
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Create users table
            create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(100) UNIQUE NOT NULL,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
            
            cursor.execute(create_users_table)
            print("[✓] Users table created/verified")
            
            cursor.close()
            connection.close()
            
            print("\n[SUCCESS] Database setup complete!")
            return True
            
    except Error as e:
        print(f"[ERROR] Table creation failed: {e}")
        return False

def dump_schema(filename="schema.sql"):
    """Dump database schema for submission"""
    try:
        import subprocess
        db_name = os.getenv('DB_NAME', 'securechat')
        db_user = os.getenv('DB_USER', 'root')
        db_pass = os.getenv('DB_PASSWORD')
        
        cmd = f"mysqldump -u {db_user} -p{db_pass} --no-data {db_name} > {filename}"
        subprocess.run(cmd, shell=True, check=True)
        print(f"[✓] Schema dumped to {filename}")
        
    except Exception as e:
        print(f"[WARNING] Schema dump failed: {e}")
        print("You can manually export schema from MySQL Workbench")

if __name__ == "__main__":
    print("=" * 60)
    print("SecureChat Database Setup")
    print("=" * 60)
    
    if create_database():
        if setup_tables():
            print("\nGenerating schema dump for submission...")
            dump_schema()