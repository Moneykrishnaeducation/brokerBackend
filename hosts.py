from django_hosts import patterns, host
from django.conf import settings

host_patterns = patterns('',
    host(r'www', 'brokerBackend.urls', name='www', prefix=''),
    host(r'admin', 'adminPanel.urls', name='admin', prefix=''),  # Changed from admin_urls to urls for full API access
    host(r'client', 'clientPanel.urls_new', name='client', prefix=''),  # Using urls_new.py with CSRF exemptions
    host(r'localhost', 'brokerBackend.urls', name='localhost', prefix=''),
    host(r'.*', 'clientPanel.urls_new', name='wildcard', prefix=''),  # Using urls_new.py with CSRF exemptions
)
