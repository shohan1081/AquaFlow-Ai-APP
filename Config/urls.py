from django.contrib import admin
from django.urls import path , include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/users/', include('users.urls')),
    path('api/legal/', include('legal_pages.urls')),
    path('api/water/', include('water_goal.urls')),
]
