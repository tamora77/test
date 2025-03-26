import pymysql

# Connect to MySQL server
connection = pymysql.connect(
    host='localhost',
    user='root',
    password=''  # If you have a password, add it here
)

try:
    with connection.cursor() as cursor:
        # Create database
        cursor.execute('CREATE DATABASE IF NOT EXISTS flask_auth_db')
        print("Database 'flask_auth_db' created successfully!")
        
        # Switch to the database
        cursor.execute('USE flask_auth_db')
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(120) NOT NULL,
                two_fa_secret VARCHAR(32),
                is_verified BOOLEAN DEFAULT FALSE
            )
        ''')
        print("Table 'users' created successfully!")
        
        # Create products table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                price FLOAT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("Table 'products' created successfully!")
        
    connection.commit()
    print("All database operations completed successfully!")

except Exception as e:
    print(f"An error occurred: {str(e)}")
finally:
    connection.close() 