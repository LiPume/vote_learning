from django.contrib import admin
from django.urls import path

from polls.views import show_subjects, show_teachers

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', show_subjects),
    path('teachers/', show_teachers),
]