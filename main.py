import eel
from db import SessionLocal
#sofia
#jacob
#tim
eel.init('front-end')

session = SessionLocal()

print("Connected successfully!")


@eel.expose
def add(num1, num2):
    return int(num1) + int(num2)


@eel.expose
def subtract(num1, num2):
    return int(num1) - int(num2)


eel.start('index.html', size=(1000, 600))
