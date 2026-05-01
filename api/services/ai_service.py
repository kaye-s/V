import os
from openai import OpenAI
from decouple import config

client = OpenAI(api_key=config("OPENAI_API_KEY"))

def ask_ai(user_text, model=None):
    resp = client.chat.completions.create(
        model=model or "gpt-4.1-mini",
        messages=[{"role": "user", "content": str(user_text)}],
    )

    return resp.choices[0].message.content