import json
import logging
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """Formatter that emits a compact JSON object per log record.

    It collects common record attributes and any extra fields (like
    `ip`, `user_email`, `method`, `path`, `status`, `length`, `duration`) and
    serializes them to a single-line JSON string.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            'timestamp': datetime.utcfromtimestamp(record.created).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Include extra fields if present on the record
        extras = ('ip', 'user_email', 'method', 'path', 'protocol', 'status', 'length', 'duration')
        for k in extras:
            v = getattr(record, k, None)
            if v is not None:
                payload[k] = v

        # Include stack/exception if present
        if record.exc_info:
            payload['exc_info'] = self.formatException(record.exc_info)

        try:
            return json.dumps(payload, ensure_ascii=False)
        except Exception:
            # Fallback to plain message on serialization error
            return json.dumps({'timestamp': payload.get('timestamp'), 'level': payload.get('level'), 'logger': payload.get('logger'), 'message': record.getMessage()})
