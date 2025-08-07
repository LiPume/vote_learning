from django.contrib import admin
from django.urls import path, include

from polls import views
from vote import settings

urlpatterns = [
    path('', views.show_subjects),
    path('teachers/', views.show_teachers),
    path('praise/', views.praise_or_criticize),
    path('criticize/', views.praise_or_criticize),
    path('login/',views.login),
    path('logout/',views.logout),
    path('captcha/', views.get_captcha),
    path('register/',views.register),
    path('admin/', admin.site.urls),
    path('excel/', views.export_teachers_excel),
    path('export-page/', views.show_export_excel_page),
    path('teachers_data/', views.get_teachers_data),
    path('stats/', views.show_stats_page),
]

if settings.DEBUG:

    import debug_toolbar

    urlpatterns.insert(0, path('__debug__/', include(debug_toolbar.urls)))