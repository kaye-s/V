import os
import sqlite3
import hashlib

API_KEY = os.getenv("API_KEY")

def safe_lookup(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()

def unsafe_lookup(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def weak_hash(password):
    return hashlib.sha1(password.encode()).hexdigest()

def safe_echo(text):
    return text