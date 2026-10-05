"""Every URL is handled by the application's own router (school.core / app.py's 300 @app.route rules), so Django's
URLconf is deliberately a single catch-all that hands the request to school.django_glue.handle().
"""
from django.urls import re_path

from school.django_glue import handle

urlpatterns = [re_path(r"^.*$", handle)]
