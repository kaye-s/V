import eel
from db import engine
from sqlalchemy import text
#sofia
#jacob
#tim
eel.init('front-end')

try:
    with engine.connect() as conn:
        # Run a simple query to test
        result = conn.execute(text("SELECT NOW();"))
        print("Connected! Server time:", result.fetchone()[0])
except Exception as e:
    print("Connection failed:", e)

@eel.expose
def add(num1, num2):
    return int(num1) + int(num2)

@eel.expose
def subtract(num1, num2):
    return int(num1) - int(num2)

@eel.expose
def showUsers():
     with engine.connect() as conn:
         result = conn.execute(text("SELECT * FROM users;"))
         users = result.fetchall()
         return [dict(row._mapping) for row in users]

@eel.expose
def addUsers(email, password):
    #hashing logic here

    with engine.begin() as conn:   # auto-commit
        conn.execute(
            text("INSERT INTO users (email, password_hash) VALUES (:email, :password)"),
            {"email": email, "password": password}
        )
    return "User added successfully"


eel.start('index.html', size=(1000, 600))
