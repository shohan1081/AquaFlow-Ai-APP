from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import WaterGoal
from .serializers import WaterGoalSerializer, ManualWaterGoalSerializer
from .utils import calculate_water_goal

class WaterGoalView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'GET':
            return WaterGoalSerializer
        return ManualWaterGoalSerializer

    def get_object(self):
        user = self.request.user
        # Get or create a water goal object for the user
        water_goal, created = WaterGoal.objects.get_or_create(user=user)

        # If the object was just created, or if there's no manual goal,
        # calculate the goal and save it.
        if created or water_goal.manual_goal is None:
            calculated_goal = calculate_water_goal(user)
            water_goal.calculated_goal = calculated_goal
            water_goal.save()
            
        return water_goal