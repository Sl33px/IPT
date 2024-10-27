from flask import Flask, render_template, request, redirect, url_for, session
from cryptography.fernet import Fernet
import datetime
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Function for loading a key from a file
def load_key():
    return open("key.key", "rb").read()

# Function to generate and save a new key
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key

# Loading the key or generating a new one if the file does not exist
if os.path.exists("key.key"):
    encryption_key = load_key()
else:
    encryption_key = generate_key()

cipher_suite = Fernet(encryption_key)

# Function for creating a database
def init_db():
    conn = sqlite3.connect('traffic_data.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY,
            user_id TEXT,
            ip_address TEXT,
            traffic_data BLOB,
            timestamp DATETIME
        )
    ''')
    conn.commit()
    conn.close()

# Initializing the database
init_db()

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Add traffic record
@app.route('/add_traffic', methods=['POST'])
def add_traffic():
    user_id = request.form['user_id']
    ip_address = request.form['ip_address']
    traffic_data = request.form['traffic_data']

    # Encryption of traffic data
    encrypted_data = cipher_suite.encrypt(traffic_data.encode())

    # Saving data to the database
    conn = sqlite3.connect('traffic_data.db')
    c = conn.cursor()
    c.execute('INSERT INTO traffic_logs (user_id, ip_address, traffic_data, timestamp) VALUES (?, ?, ?, ?)',
              (user_id, ip_address, encrypted_data, datetime.datetime.now()))
    conn.commit()
    conn.close()
    return redirect(url_for('view_traffic'))

# View traffic data
@app.route('/view_traffic')
def view_traffic():
    conn = sqlite3.connect('traffic_data.db')
    c = conn.cursor()
    c.execute('SELECT * FROM traffic_logs')
    data = c.fetchall()
    conn.close()

    # Decoding data for display
    decrypted_data = [(log[0], log[1], log[2], cipher_suite.decrypt(log[3]).decode(), log[4]) for log in data]
    return render_template('view_traffic.html', data=decrypted_data)

if __name__ == '__main__':
    app.run(debug=True)
