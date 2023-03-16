import sqlite3
import bcrypt
import os
from flask import Flask, render_template, request, redirect, url_for, session


# Please ensure your security is proper before implementing this, I do not claim mine is.


app = Flask(__name__, template_folder='./templates')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    print("inside login()")
    if request.method == 'POST':
        # Get form values
        username = request.form['username']
        password = request.form['password']

        if os.path.isfile(f"{username}.db"):
            print(f"Accessing database for user: {username}")
            conn = sqlite3.connect(f"{username}.db")
            print(f"Accessed database for user: {username}")
            print(f"Username: {username} Password: {password}")
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=?", (username,))
            result = c.fetchone()

            if result:
                print("inside IF")
                # Verify password using the stored hash
                if bcrypt.checkpw(password.encode('utf-8'), result[3]):
                    print("inside IF IF")
                    # If username and password are correct, redirect to dashboard page
                    session['user_id'] = username  # Save username in session
                    return redirect(url_for('dashboard'))
            else:
                # If username and password are incorrect, display error message
                error = "Incorrect username or password. Please try again."
                print(f"Error should display: {error}")
                return redirect(url_for('wrongUser', error='Incorrect username or password. Please try again.'))

            # Close the cursor and the connection
            c.close()
            conn.close()
        else:
            error = "User does not exist."
            return redirect(url_for('wrongUser', error=error))

    # If request method is GET, display login form
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    print("In register()")
    print(os.getcwd())
    # Get the IP address of the user's browser
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    print(f"ip address: {ip_address}")

    if request.method == 'POST':
        # Get form values
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']

        # for troubleshooting purposes only:
        # print(name, username, email, password, ip_address, confirm_password)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        # print(hashed_password)
        # print(name, username, email, hashed_password, ip_address)
        # print(f"{username}.db")

        db_file = f"{username}.db"

        # Check if the user database file already exists
        if os.path.exists(db_file):
            error = "Username already exists. Please choose a different username."
            print("Should show error for username existing:", error)
            return render_template('register.html', error=error)

        else:
            # If user database file does not exist, create a new one for the user
            print(f"Creating database for user: {username}")
            conn = sqlite3.connect(db_file)
            print(f"Database in progress for user: {username}")

            # Create the users table in the database
            conn.execute('''CREATE TABLE IF NOT EXISTS users 
                          (name text, username text, email text, password blob, ip_address integer)''')
            conn.commit()
            print(f"Database still in progress for user: {username}")
            # Insert new user into database
            conn.execute("INSERT INTO users (name, username, email, password, ip_address) VALUES (?, ?, ?, ?, ?)",
                         (name, username, email, hashed_password, ip_address))
            conn.commit()
            print(f"Database assembled for user: {username}")
            # Close the cursor and the connection
            # c.close()
            conn.close()
            print(f"Database created for user: {username}")
            # Redirect to login page
            return redirect(url_for('login'))

    # If request method is GET, display register form
    return render_template('register.html')


if __name__ == '__main__':
    app.run(debug=True)