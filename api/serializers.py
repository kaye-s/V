from rest_framework import serializers
from .models import CodeSubmission, File, Threat

# -------------------
# Serializer for submitting new code
# -------------------
class CodeSubmissionSerializer(serializers.ModelSerializer):
    code = serializers.CharField(write_only=True)  # user input code
    submission_name = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = CodeSubmission
        fields = ['submission_name', 'code']

    def create(self, validated_data):
        # We'll store the "code" as a single File for simplicity
        code_text = validated_data.pop('code')
        submission = CodeSubmission.objects.create(**validated_data)
        File.objects.create(
            submission=submission,
            file_name=validated_data.get('submission_name', 'unnamed.py'),
            file_path='',
            file_type='code',
        )
        # Optionally, you can attach code_text somewhere (DB or AI service)
        return submission