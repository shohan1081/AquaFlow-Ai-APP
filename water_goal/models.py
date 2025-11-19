from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _

class WaterGoal(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='water_goal',
        help_text=_("The user this water goal belongs to")
    )
    calculated_goal = models.IntegerField(
        null=True,
        blank=True,
        help_text=_("The goal calculated based on user's metrics, in milliliters")
    )
    manual_goal = models.IntegerField(
        null=True,
        blank=True,
        help_text=_("The goal manually set by the user, in milliliters")
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def active_goal(self):
        return self.manual_goal if self.manual_goal is not None else self.calculated_goal

    def __str__(self):
        return f"{self.user.email}'s Water Goal"