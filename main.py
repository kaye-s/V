import eel
from db import engine
from sqlalchemy import text
import bcrypt
import os
from dotenv import load_dotenv
from openai import OpenAI
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
load_dotenv()
print("API key loaded:", bool(os.getenv("OPENAI_API_KEY")))
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

@eel.expose
def ask_api(user_text):
    print("ask_api received:", user_text)

    resp = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[{"role": "user", "content": str(user_text)}],
        )

    answer = resp.choices[0].message.content
    print("ask_api answer:", answer)
    return answer





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
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    with engine.begin() as conn:   # auto-commit
        conn.execute(
            text("INSERT INTO users (email, password_hash) VALUES (:email, :password)"),
            {"email": email, "password": hashed}
        )
    return "User added successfully"


if __name__ == "__main__":
    eel.start('index.html', size=(1000, 600), mode='safari')
