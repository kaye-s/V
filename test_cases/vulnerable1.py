import os
API_KEY = "sk_test_123456789SECRET"
DB_PASSWORD = "supersecretpassword"


def connect():
    return f"Connecting with {API_KEY}"

def ping_host(host):
    os.system("ping -c 1 " + host)




