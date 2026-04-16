import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def init_db():
    conn = sqlite3.connect(os.path.join(BASE_DIR, 'database.db'))
    cursor = conn.cursor()

    # Create Employees table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Employees (
        id TEXT PRIMARY KEY,
        f_name TEXT,
        l_name TEXT,
        password TEXT,
        has_registered INTEGER DEFAULT 0
    )
    ''')

    # Create Candidate table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS Candidate (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        position TEXT,
        vote_count INTEGER DEFAULT 0
    )
    ''')

    # Seed some sample employees (who can register)
    sample_employees = [
        ('1234', 'John', 'Doe', None, 0),
        ('5678', 'Jane', 'Smith', None, 0),
        ('1111', 'Admin', 'User', None, 0)
    ]
    
    # We clear the tables if they exist to start fresh
    cursor.execute('DELETE FROM Employees')
    cursor.execute('DELETE FROM Candidate')
    
    cursor.executemany('''
    INSERT INTO Employees (id, f_name, l_name, password, has_registered) 
    VALUES (?, ?, ?, ?, ?)
    ''', sample_employees)

    # Seed candidates
    sample_candidates = [
        ('Alice', 'Johnson', 'President'),
        ('Bob', 'Williams', 'President'),
        ('Charlie', 'Brown', 'Secretary'),
        ('Diana', 'Prince', 'Secretary')
    ]
    cursor.executemany('''
    INSERT INTO Candidate (first_name, last_name, position) 
    VALUES (?, ?, ?)
    ''', sample_candidates)

    conn.commit()
    conn.close()
    print("Database initialized successfully with mock data.")

if __name__ == "__main__":
    init_db()
