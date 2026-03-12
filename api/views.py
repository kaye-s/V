#all id related lines are noted and can be deleted or changed if user id is skipped or substituted
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from rest_framework.permissions import AllowAny, IsAuthenticated #for user id
from api.models import AnalysisTask
from api.serializers import AnalysisRequestSerializer
from .tasks import run_analysis_async
from django.shortcuts import render

class AnalysisView(APIView):
    permission_classes = [AllowAny]

    #analysis task endpoint
    def post(self, request):

        #assign user to test
        test_user = User.objects.first()
        if not test_user:
            return Response({"error": "No user exists in database."}, status=500)

        serializer = AnalysisRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True) #deserialize, check correct input and format, raises 400 Bad Request on fail

        task = AnalysisTask.objects.create(
            user=test_user, #request.user, change back once user implemented further
            input_code=serializer.validated_data["code"],
            #uncomment when language fully implemented, currently hardcoded python
            language="python", #serializer.validated_data["language"],
            status="QUEUED"
        )

        run_analysis_async(str(task.id))

        return Response({
            "task_id": str(task.id),
            "status": task.status
        })

class StatusView(APIView):
    permission_classes = [AllowAny] #change to IsAuthenticated
    #status endpoint
    def get(self, request, task_id):
        task = AnalysisTask.objects.get(id=task_id) #readd --, user=request.user

        return Response({
            "status": task.status,
            "summary": task.results if task.status == "COMPLETED" else None
        })

#user registration. Along with login and logout below, use django.contrib.auth login, logout and authenticate for user handling and creation
class RegisterView(APIView):
    permission_classes = [AllowAny] #change to IsAuthenticated

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"Error": "Enter Username and Password"}, status=400)

        if User.objects.filter(username=username).exists():
            return Response({"Error": "Username Taken"}, status=400)

        user = User.objects.create_user(username=username, password=password)
        login(request, user)

        return Response({
            "message": "User created successfully.",
            "username": user.username
        }, status=status.HTTP_201_CREATED)

#Login
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(request, username=username, password=password)

        if user is None:
            return Response({"Error": "Login Failed"}, status=401)

        login(request, user)

        return Response({
            "message": "Login Successful",
            "username": user.username
        })

#logout
class LogoutView(APIView):

    def post(self, request):
        logout(request)
        return Response({"message": "Logout Successful"})

#current user
class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "id": request.user.id,
            "username": request.user.username
        })


def index(request):
    return render(request, "index.html")

def login_view(request):
    return render(request, "login.html")

def register_view(request):
    return render(request, "register.html")