import logging
import re


class ExcludeStatusFilter(logging.Filter):
    """Filter out access log records with specific HTTP status codes.

    The filter looks for a three-digit status code in the log message
    (pattern like '" HTTP/1.1" 200' or '"GET /path HTTP/1.1" 200 <bytes>').
    If the captured status code is in `status_codes`, the record is
    suppressed (filter returns False).
    """

    STATUS_RE = re.compile(r'"\s(?P<status>\d{3})\s')

    def __init__(self, status_codes=None):
        super().__init__()
        if status_codes is None:
            status_codes = [200, 301, 302]
        self.status_codes = set(int(c) for c in status_codes)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True

        m = self.STATUS_RE.search(msg)
        if m:
            try:
                code = int(m.group('status'))
            except Exception:
                return True
            if code in self.status_codes:
                return False

        return True


class ScrubFilter(logging.Filter):
    """Redact IP addresses and email addresses from log messages.

    This filter rewrites the formatted message text (calls `record.getMessage()`
    to obtain the rendered message) and replaces IPv4, IPv6-ish, and simple
    email patterns with placeholders. It then updates `record.msg` and clears
    `record.args` to avoid double-formatting.
    """

    IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            return True

        # Replace IPs and emails with placeholders
        scrubbed = self.IPV4_RE.sub('<REDACTED_IP>', rendered)
        scrubbed = self.EMAIL_RE.sub('<REDACTED_EMAIL>', scrubbed)

        # Update record so handlers/formatters write the scrubbed text
        try:
            record.msg = scrubbed
            record.args = ()
        except Exception:
            pass

        return True
