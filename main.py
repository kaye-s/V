import eel
import os
from dotenv import load_dotenv
from openai import OpenAI
#sofia
#jacob
#tim
eel.init('front-end')

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


if __name__ == "__main__":
    eel.start('index.html', size=(1000, 600), mode='safari')
