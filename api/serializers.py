#this file uses serializers to define what information we add to our AnalysisTask model from user
from rest_framework import serializers

class AnalysisRequestSerializer(serializers.Serializer):
    code = serializers.CharField() #for input code
    #language definition of input code, can be commented out if language distinction added later
    language = serializers.CharField()
