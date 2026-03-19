#all id related lines are noted and can be deleted or changed if user id is skipped or substituted
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated #for user id
from api.models import AnalysisTask
from api.serializers import AnalysisRequestSerializer
from .tasks import run_analysis_async

class AnalysisView(APIView):
    permission_classes = [IsAuthenticated]

    #analysis task endpoint
    def post(self, request):
        serializer = AnalysisRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True) #deserialize, check correct input and format, raises 400 Bad Request on fail

        task = AnalysisTask.objects.create(
            user=request.user, #user
            input_code=serializer.validated_data["code"],
            language=serializer.validated_data["language"],
            status="QUEUED"
        )

        run_analysis_async(str(task.id))

        return Response({
            "task_id": str(task.id),
            "status": task.status
        })

class StatusView(APIView):
    permission_classes = [IsAuthenticated]
    #status endpoint
    def get(self, request, task_id):
        task = AnalysisTask.objects.get(id=task_id, user=request.user) #user

        return Response({
            "status": task.status,
            "summary": task.results if task.status == "COMPLETED" else None
        })

