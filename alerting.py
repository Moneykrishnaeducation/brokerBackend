import logging
import json
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

# Import model lazily to avoid app registry issues at import time

def record_alert(alert_type, ip, path=None, details=None):
    try:
        from .models_alerts import Alert
        a = Alert.objects.create(
            alert_type=alert_type,
            ip=ip,
            path=path or '',
            details=details or {},
        )
        return a
    except Exception:
        logger.exception('Failed to persist alert to DB')
        return None


def notify_webhook(alert_type, ip, path=None, details=None):
    """Send alert to configured webhook (Slack/HTTP) if provided in settings.

    Settings:
      - ALERT_WEBHOOK_URL (single URL) or ALERT_WEBHOOK_URLS (list)
      - ALERT_WEBHOOK_USERNAME (optional)
    """
    try:
        webhook = getattr(settings, 'ALERT_WEBHOOK_URL', None)
        webhooks = getattr(settings, 'ALERT_WEBHOOK_URLS', None) or []
        if webhook:
            webhooks = [webhook] + list(webhooks)

        if not webhooks:
            return False

        payload = {
            'text': f"[{alert_type}] {ip} - {path or ''}",
            'attachments': [
                {
                    'title': f'Alert: {alert_type}',
                    'text': json.dumps(details or {}, indent=2),
                    'ts': int(timezone.now().timestamp()),
                }
            ]
        }

        # prefer requests if available
        try:
            import requests
            for url in webhooks:
                try:
                    headers = {'Content-Type': 'application/json'}
                    r = requests.post(url, json=payload, headers=headers, timeout=5)
                    if r.status_code >= 400:
                        logger.warning('Webhook notify returned %s for %s', r.status_code, url)
                except Exception:
                    logger.exception('Failed to POST to webhook %s', url)
        except Exception:
            # fallback to urllib
            import urllib.request
            from urllib.error import URLError, HTTPError
            data = json.dumps(payload).encode('utf-8')
            for url in webhooks:
                try:
                    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if resp.status >= 400:
                            logger.warning('Webhook notify returned %s for %s', resp.status, url)
                except Exception:
                    logger.exception('Failed to POST to webhook %s', url)

        return True
    except Exception:
        logger.exception('Error in notify_webhook')
        return False