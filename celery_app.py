from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'brokerBackend.settings')

app = Celery('brokerBackend')
# Read config from Django settings, using CELERY_ prefix for config keys
app.config_from_object('django.conf:settings', namespace='CELERY')
# Autodiscover tasks from installed apps
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
