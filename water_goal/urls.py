from django.urls import path
from .views import WaterGoalView

app_name = 'water_goal'

urlpatterns = [
    path('goal/', WaterGoalView.as_view(), name='water_goal'),
]
