from sqlalchemy import create_engine, text

# Replace these with your Supabase info
USER = "postgres"
PASSWORD = "CapstoneVSecurity123"
HOST = "db.zzraywtbowpotrqbevkz.supabase.co"
PORT = "5432"
DATABASE = "postgres"

# This is the connection URL SQLAlchemy needs
DB_URL = f"postgresql+psycopg2://{USER}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}"

# Create a connection
engine = create_engine(DB_URL)

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