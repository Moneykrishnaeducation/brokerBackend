from django.db import models

class Alert(models.Model):
    ALERT_TYPE_CHOICES = [
        ('ENUM', 'Enumeration'),
        ('AUTH_ABUSE', 'Auth Abuse'),
        ('OTHER', 'Other'),
    ]

    alert_type = models.CharField(max_length=32, choices=ALERT_TYPE_CHOICES)
    ip = models.CharField(max_length=64, db_index=True)
    path = models.CharField(max_length=512, blank=True, null=True)
    details = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'brokerbackend_alert'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.alert_type} {self.ip} @ {self.created_at.isoformat()}"