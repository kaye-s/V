#from celery import shared_task #task queue to handle simultaneous requests, making testing annoying for now can readd later when necessary
from api.models import AnalysisTask
from .dummy_analysis import run_dummy

#@shared_task --from celery, readd later
def run_analysis_async(task_id):

    #instance of analysisTask
    task = AnalysisTask.objects.get(id=task_id)
    task.status = "RUNNING" #update status
    task.save() #save instance task

    try:
        #call ai api rather than dummy
        results = run_dummy(task.input_code, task.language)

        task.results = results #store results
        task.status = "COMPLETED" #update status
    except Exception(BaseException) as e:
        task.status = "FAILED"

    task.save()