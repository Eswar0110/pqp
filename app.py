import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # NEW: For secure file handling
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_dev_secret_key_if_needed')

# --- Database & Uploads Configuration ---
DATABASE = 'database.db'
UPLOAD_FOLDER = 'uploads' # Folder to store uploaded papers

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Max upload size: 16MB (adjust as needed)
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'} # Allowed file types for papers
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS # Store in app.config for easy access

# Ensure the upload folder exists when the app starts
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Database Helper Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database by creating tables and adding a default admin user/branches."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS branches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS papers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                branch_id INTEGER NOT NULL,
                year INTEGER NOT NULL,
                subject TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                FOREIGN KEY (branch_id) REFERENCES branches (id)
            )
        ''')
        db.commit()

        try:
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                # IMPORTANT: Keep this password consistent with what you use for login!
                hashed_password = generate_password_hash("admin@0474")
                cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                               ('admin', hashed_password, 'admin'))
                db.commit()
                print("Default admin user created: username='admin', password='admin@0474'")
        except sqlite3.IntegrityError:
            pass

        branches_to_add = ['CSE', 'ECE', 'EEE', 'CIVIL', 'MECH', 'CSE-AI', 'CSD']
        for branch_name in branches_to_add:
            try:
                cursor.execute("INSERT OR IGNORE INTO branches (name) VALUES (?)", (branch_name,))
                db.commit()
            except sqlite3.IntegrityError:
                pass
        print("Database tables and default branches created/checked.")

# --- Utility Functions ---
def allowed_file(filename):
    """Checks if a file's extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS'] # Use app.config for ALLOWED_EXTENSIONS

# --- Routes (Existing) ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message=''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password.')
    return render_template('login.html', message=message)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    # Fetch all branches to display on the dashboard
    branches = db.execute("SELECT * FROM branches ORDER BY name").fetchall()

    return render_template('dashboard.html',
                           username=session['username'],
                           role=session['role'],
                           branches=branches) # Make sure branches are passed@app.route('/branch_papers/<int:branch_id>')
@app.route('/dashboard/branch/<int:branch_id>')
def branch_papers(branch_id):
    """Displays papers for a specific branch."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()

    # Fetch branch name
    branch = db.execute("SELECT name FROM branches WHERE id = ?", (branch_id,)).fetchone()
    if not branch:
        flash("Branch not found.", "danger")
        return redirect(url_for('dashboard')) # Redirect back if branch doesn't exist

    branch_name = branch['name']

    # Fetch papers for the given branch
    papers = db.execute("SELECT * FROM papers WHERE branch_id = ? ORDER BY year DESC, subject ASC",
                        (branch_id,)).fetchall()

    return render_template('branch_papers.html',
                           username=session['username'],
                           branch_name=branch_name,
                           papers=papers)

@app.route('/download/<filename>')
def download_file(filename):
    # Security check: Make sure filename doesn't contain path traversal
    if not allowed_file(filename): # rudimentary check to prevent serving non-allowed types
        return "File type not allowed.", 403
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- NEW: Admin Panel Routes ---

@app.route('/admin')
def admin_panel():
    """Admin panel entry point. Fetches data for all tabs."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied: Admin privileges required.", 403

    db = get_db()

    # --- Fetch all necessary data for ALL admin tabs ---
    users = db.execute("SELECT * FROM users").fetchall()
    
    papers_with_branch_names = db.execute('''
        SELECT p.*, b.name AS branch_name
        FROM papers p
        JOIN branches b ON p.branch_id = b.id
        ORDER BY b.name, p.year DESC, p.subject ASC
    ''').fetchall()
    
    branches = db.execute("SELECT * FROM branches ORDER BY name").fetchall()

    # --- DEBUG PRINTS for branches (will now show on /admin load) ---
    print("\n--- DEBUG: Inside admin_panel route (fetching all data) ---")
    print(f"Number of branches fetched for dropdown: {len(branches)}")
    if len(branches) > 0:
        print("First branch fetched:", dict(branches[0]))
        print("All branches fetched:")
        for b in branches:
            print(f"  ID: {b['id']}, Name: {b['name']}")
    else:
        print("No branches were fetched from the database for admin panel.")
    print("--- END DEBUG ---\n")
    # --- END DEBUG PRINTS ---

    # Get error/success messages and active tab from query parameters if redirected
    user_message = request.args.get('user_message')
    paper_message = request.args.get('paper_message')
    active_tab = request.args.get('active_tab', 'users-tab') # Default to users tab

    return render_template('admin_panel.html',
                           username=session['username'],
                           users=users,        # Pass users data
                           papers=papers_with_branch_names, # Pass papers data
                           branches=branches,  # Pass branches data
                           user_message=user_message,
                           paper_message=paper_message,
                           active_tab=active_tab)

@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users(): # Renamed to indicate action
    """Handles user management actions (add, delete, update). Redirects to /admin."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403

    db = get_db()
    message = None # To display messages back to the user

    action = request.form.get('action')

    if action == 'add':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')
        hashed_password = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (username, hashed_password, role))
            db.commit()
            message = "User added successfully!"
        except sqlite3.IntegrityError:
            message = "Username already exists. Please choose a different one."
        except Exception as e:
            message = f"Error adding user: {e}"

    elif action == 'delete':
        user_id = request.form['user_id']
        if int(user_id) == session['user_id']:
            message = "You cannot delete your own admin account!"
        else:
            db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            db.commit()
            message = "User deleted successfully!"

    elif action == 'update':
        user_id = request.form['user_id']
        new_username = request.form['new_username']
        new_role = request.form['new_role']

        try:
            if 'new_password' in request.form and request.form['new_password']:
                new_password_hash = generate_password_hash(request.form['new_password'])
                db.execute("UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?",
                           (new_username, new_password_hash, new_role, user_id))
            else:
                db.execute("UPDATE users SET username = ?, role = ? WHERE id = ?",
                           (new_username, new_role, user_id))
            db.commit()
            message = "User updated successfully!"
        except sqlite3.IntegrityError:
            message = "Username already exists for another user."
        except Exception as e:
            message = f"Error updating user: {e}"

    # Redirect back to the admin_panel with the user_message and active tab
    return redirect(url_for('admin_panel', active_tab='users-tab', user_message=message))

@app.route('/admin/papers', methods=['GET', 'POST'])
def admin_papers(): # Renamed to indicate action
    """Handles paper management actions (upload, delete, update). Redirects to /admin."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return "Access Denied", 403

    db = get_db()
    message = None # To display messages back to the user

    action = request.form.get('action')

    if action == 'upload':
        branch_id = request.form['branch_id']
        year = request.form['year']
        subject = request.form['subject']

        if 'file' not in request.files:
            message = "No file part in the request."
        else:
            file = request.files['file']
            if file.filename == '':
                message = "No selected file."
            elif file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    db.execute("INSERT INTO papers (branch_id, year, subject, filename, file_path) VALUES (?, ?, ?, ?, ?)",
                               (branch_id, year, subject, filename, file_path))
                    db.commit()
                    message = "Paper uploaded successfully!"
                except Exception as e:
                    message = f"Error saving file or database entry: {e}"
                    if os.path.exists(file_path):
                        os.remove(file_path)
            else:
                message = "File type not allowed. Allowed types: PDF, DOC, DOCX, JPG, JPEG, PNG."
    elif action == 'delete':
        paper_id = request.form['paper_id']
        paper = db.execute("SELECT file_path FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if paper:
            if os.path.exists(paper['file_path']):
                try:
                    os.remove(paper['file_path'])
                except Exception as e:
                    message = f"Error deleting file from disk: {e}"
            db.execute("DELETE FROM papers WHERE id = ?", (paper_id,))
            db.commit()
            message = "Paper deleted successfully!"
        else:
            message = "Paper not found."

    elif action == 'update':
        paper_id = request.form['paper_id']
        new_branch_id = request.form['new_branch_id']
        new_year = request.form['new_year']
        new_subject = request.form['new_subject']
        try:
            db.execute("UPDATE papers SET branch_id = ?, year = ?, subject = ? WHERE id = ?",
                       (new_branch_id, new_year, new_subject, paper_id))
            db.commit()
            message = "Paper updated successfully!"
        except Exception as e:
            message = f"Error updating paper: {e}"

    # Redirect back to the admin_panel with the paper_message and active tab
    return redirect(url_for('admin_panel', active_tab='papers-tab', paper_message=message))
# --- NEW: Change Password Route ---
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    message = '' # Initialize message

    if request.method == 'POST':
        old_password = request.form['old_password'].strip()
        new_password = request.form['new_password'].strip()
        confirm_new_password = request.form['confirm_new_password'].strip()

        db = get_db()
        
        # --- DEBUGGING PRINTS START ---
        print(f"\n--- Change Password Attempt --- Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
        print(f"Attempting to change password for user_id: {session.get('user_id')}")
        
        user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        
        if user:
            print(f"User found in DB: {user}")
            print(f"Type of user: {type(user)}")
            print(f"Keys available in user object: {user.keys()}")
            
            print(f"Old password entered by user (stripped): '{old_password}'")
            print(f"Hashed password from DB (user['password_hash']): '{user['password_hash']}'")
            
            is_old_password_correct = check_password_hash(user['password_hash'], old_password)
            print(f"Result of check_password_hash: {is_old_password_correct}")

            print(f"New password entered: '{new_password}'")
            print(f"Confirm new password entered: '{confirm_new_password}'")
            print(f"New password matches confirmation: {new_password == confirm_new_password}")
            
        else:
            print("User not found in DB with the session ID. This path should not be reached if logged in.")
            message = 'User session invalid. Please log in again.'
            return render_template('change_password.html', message=message)

        # --- CORE LOGIC AFTER DEBUGGING ---
        # This is the simplified condition. If is_old_password_correct is True, this 'if' must pass.
        if is_old_password_correct:
            print("EXECUTION PATH: Old password is correct. Proceeding to new password check.")
            if new_password == confirm_new_password:
                print("EXECUTION PATH: New passwords match. Attempting to update password.")
                if len(new_password) < 6: # Basic password policy
                    message = 'New password must be at least 6 characters long.'
                    print(f"EXECUTION PATH: New password too short. Message: {message}")
                else:
                    hashed_new_hash = generate_password_hash(new_password)
                    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", # Ensure password_hash here
                               (hashed_new_hash, session['user_id']))
                    db.commit()
                    message = 'Password changed successfully!'
                    print(f"EXECUTION PATH: Password updated successfully. Message: {message}")
                    return redirect(url_for('dashboard', message=message)) # Redirect with message for toast
            else:
                message = 'New password and confirm password do not match.'
                print(f"EXECUTION PATH: New passwords do NOT match. Message: {message}")
        else:
            # This 'else' block will only be hit if is_old_password_correct was False
            message = 'Incorrect old password.'
            print(f"EXECUTION PATH: Old password check failed. Message: {message}")

    return render_template('change_password.html', message=message)
if __name__ == '__main__':
    # Ensure init_db() is ONLY called for initial setup, not every time the app runs
    # You should have run it once in Step 1 to create database.db
    # If database.db is missing, uncomment init_db() then run this file once, then re-comment it.
    # init_db() # ONLY uncomment for initial setup or if database.db is deleted
    port = int(os.environ.get('PORT', 10000))  # Default to 10000 for Render
    app.run(host='0.0.0.0', port=port, debug=False)
