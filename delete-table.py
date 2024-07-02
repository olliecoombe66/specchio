import sqlite3

# Database setup
def init_sqlite_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        DROP TABLE users
    ''')
    cursor.execute('''
        DROP TABLE sessions
    ''')
    cursor.execute('''
        DROP TABLE conversations
    ''')
    conn.commit()
    conn.close()

init_sqlite_db()
