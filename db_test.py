from sqlalchemy import text
from db import engine

try:
    with engine.connect() as conn:
        # Run a simple query to test
        result = conn.execute(text("SELECT NOW();"))
        print("Connected! Server time:", result.fetchone()[0])
except Exception as e:
    print("Connection failed:", e)

with engine.connect() as conn:
    #conn.execute(text("INSERT INTO users(email, password_hash) VALUES ('test2@example.com', '1A2B3C');"))
    result = conn.execute(text("SELECT * FROM users;"))
    print(result.fetchall())