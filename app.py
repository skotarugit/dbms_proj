from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = "dbms_proj_flask"
# Database initialization
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # This enables name-based access to columns
    return conn

def init_db():
    with app.app_context():
        conn = get_db()
        c = conn.cursor()
        
        # Create users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')       
        conn.commit()
        conn.close()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
@login_required
def home():
    return render_template('home.html', 
                         username=session.get('username'), 
                         role=session.get('role'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if username already exists
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        if c.fetchone():
            flash('Username already exists. Please choose another.')
            conn.close()
            return render_template('register.html')
        
        try:
            c.execute('''
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            ''', (username, generate_password_hash(password), role))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except:
            flash('Registration failed. Please try again.')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Initialize database when starting the app
    init_db()
    app.run(debug=True)