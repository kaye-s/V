from django.contrib.auth.models import User

def create_user(email, password):
    user = User.objects.create_user(
        username=email,
        email=email,
        password=password
    )
    return user