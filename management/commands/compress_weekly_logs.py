import tarfile
from pathlib import Path
from datetime import datetime
import re
import logging

from django.core.management.base import BaseCommand
from django.conf import settings

LOG = logging.getLogger(__name__)


DATE_RE = re.compile(r'app\.log\.(\d{4}-\d{2}-\d{2})$')


class Command(BaseCommand):
    help = 'Compress the last N daily app.log.* files into one tar.gz archive and remove originals.'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=7, help='Number of recent daily log files to include (default: 7)')
        parser.add_argument('--dry-run', action='store_true', help="Don't compress or remove; just show what would be done")

    def handle(self, *args, **options):
        days = options['days']
        dry_run = options['dry_run']

        log_dir = Path(getattr(settings, 'LOG_DIR', Path(settings.BASE_DIR) / 'logs'))
        if not log_dir.exists():
            self.stdout.write(self.style.ERROR(f'Log directory does not exist: {log_dir}'))
            return

        files = []
        for p in sorted(log_dir.iterdir()):
            m = DATE_RE.search(p.name)
            if m and p.is_file():
                try:
                    dt = datetime.strptime(m.group(1), '%Y-%m-%d').date()
                    files.append((dt, p))
                except Exception:
                    continue

        if not files:
            self.stdout.write('No archived daily log files found (pattern app.log.YYYY-MM-DD).')
            return

        # Exclude today's file if present
        today = datetime.utcnow().date()
        files = [f for f in files if f[0] < today]
        if not files:
            self.stdout.write('No dated archived files older than today to compress.')
            return

        # Take the most recent N files
        files.sort(reverse=True)
        selected = files[:days]
        selected_dates = [d for d, p in selected]
        selected_paths = [p for d, p in selected]

        start = selected_dates[-1].strftime('%Y%m%d')
        end = selected_dates[0].strftime('%Y%m%d')
        weekly_dir = log_dir / 'weekly'
        weekly_dir.mkdir(exist_ok=True)

        archive_name = weekly_dir / f'app_logs_{start}_{end}.tar.gz'

        self.stdout.write(f'Compressing {len(selected_paths)} files into {archive_name}...')
        if dry_run:
            for p in selected_paths:
                self.stdout.write(f'  {p.name}')
            self.stdout.write('Dry run: no files were modified.')
            return

        try:
            with tarfile.open(archive_name, 'w:gz') as tar:
                for p in selected_paths:
                    tar.add(p, arcname=p.name)

            # Remove original files after successful archive
            for p in selected_paths:
                try:
                    p.unlink()
                except Exception as e:
                    LOG.exception('Failed to remove archived file %s: %s', p, e)

            self.stdout.write(self.style.SUCCESS(f'Compressed and removed {len(selected_paths)} files -> {archive_name}'))
        except Exception as e:
            LOG.exception('Failed to create archive: %s', e)
            self.stdout.write(self.style.ERROR(f'Failed to create archive: {e}'))
