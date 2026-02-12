import eel
import os
from dotenv import load_dotenv
from openai import OpenAI
#sofia
#jacob
#tim
eel.init('front-end')

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def test_openai():
    if not os.getenv("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not found. Put it in .env (same folder as main.py).")
        return

    resp = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[{"role": "user", "content": "Say hello in one sentence."}],
    )
    print("OpenAI test reply:", resp.choices[0].message.content)

@eel.expose
def add(num1, num2):
    return int(num1) + int(num2)


@eel.expose
def subtract(num1, num2):
    return int(num1) - int(num2)


eel.start('index.html', size=(1000, 600))
