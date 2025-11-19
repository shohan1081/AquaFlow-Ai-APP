from rest_framework import serializers
from .models import WaterGoal

class WaterGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = WaterGoal
        fields = ['active_goal', 'calculated_goal', 'manual_goal']
        read_only_fields = ['calculated_goal']

class ManualWaterGoalSerializer(serializers.ModelSerializer):
    class Meta:
        model = WaterGoal
        fields = ['manual_goal']
