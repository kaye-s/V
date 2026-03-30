from .models import CodeSubmission, File, Threat
from .services.dummy_analysis import run_dummy

def run_analysis_sync(submission_id):
    """
    Runs code analysis on a given CodeSubmission.
    Updates submission with dummy results and creates Threat records.
    """

    submission = CodeSubmission.objects.get(submission_id=submission_id)

    # For status tracking, we could add a 'status' field if desired
    # submission.status = "RUNNING"
    # submission.save()

    try:
        # Assume analyzing the first file for simplicity
        file_obj = submission.files.first()
        code_text = ""  # replace with actual file reading if needed

        # Call dummy analysis
        results = run_dummy(code_text, "python")  # language can be dynamic

        # Save results in submission (simplified summary + detailed)
        submission.simplified_summary = results.get("summary", "")
        submission.detailed_summary = str(results.get("findings", []))
        submission.save()

        # Create Threat objects from findings
        for finding in results.get("findings", []):
            Threat.objects.create(
                submission=submission,
                file=file_obj,
                title=finding.get("description", "Unnamed Threat"),
                description=finding.get("description", ""),
                severity_level=finding.get("severity", "Low"),
                recommendation=finding.get("fix", ""),
            )

    except Exception as e:
        # handle failures, e.g., logging
        print(f"Analysis failed for submission {submission_id}: {e}")
        # optionally mark submission as failed