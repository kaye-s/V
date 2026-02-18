import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

DB_URL = f"postgresql://" \
         f"{os.getenv('DB_USER')}:" \
         f"{os.getenv('DB_PASS')}@" \
         f"{os.getenv('DB_HOST')}:" \
         f"{os.getenv('DB_PORT')}/" \
         f"{os.getenv('DB_NAME')}"

engine = create_engine(
    DB_URL,
    echo=True,
    connect_args={"sslmode": "require"}
)

SessionLocal = sessionmaker(bind=engine)