import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
import zipfile
import logging

from django.conf import settings

LOG = logging.getLogger(__name__)


def _ensure_dirs(log_dir: Path):
    (log_dir / 'weekly').mkdir(parents=True, exist_ok=True)
    (log_dir / 'monthly').mkdir(parents=True, exist_ok=True)
    (log_dir / 'yearly').mkdir(parents=True, exist_ok=True)


def _daily_log_name(d: datetime.date) -> str:
    return f'app.log.{d.strftime("%Y-%m-%d")}'


def _weekly_zip_name(start_date: datetime.date, end_date: datetime.date) -> str:
    return f'app_logs_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.zip'


def _monthly_zip_name(start_date: datetime.date, end_date: datetime.date) -> str:
    return f'app_logs_month_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.zip'


def compress_week(log_dir: Path, week_start: datetime.date, week_end: datetime.date) -> Path | None:
    """Compress daily log files for the given week (inclusive). Returns archive Path or None."""
    _ensure_dirs(log_dir)
    files = []
    for i in range((week_end - week_start).days + 1):
        d = week_start + timedelta(days=i)
        p = log_dir / _daily_log_name(d)
        if p.exists():
            files.append(p)

    if not files:
        return None

    archive = log_dir / 'weekly' / _weekly_zip_name(week_start, week_end)
    try:
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for p in files:
                zf.write(p, arcname=p.name)
        # remove original daily files after successful archive
        for p in files:
            try:
                p.unlink()
            except Exception:
                LOG.exception('Failed to remove daily log %s', p)
        return archive
    except Exception:
        LOG.exception('Failed to create weekly archive %s', archive)
        return None


def compress_month_if_needed(log_dir: Path, keep_weekly=False):
    """If there are 4 or more weekly zips, compress the oldest 4 into a monthly zip and remove them."""
    weekly_dir = log_dir / 'weekly'
    if not weekly_dir.exists():
        return
    zips = sorted([p for p in weekly_dir.iterdir() if p.is_file() and p.suffix == '.zip'])
    if len(zips) < 4:
        return
    # take the oldest 4
    selected = zips[:4]
    starts = []
    ends = []
    for p in selected:
        # filename like app_logs_YYYYMMDD_YYYYMMDD.zip
        parts = p.stem.split('_')
        if len(parts) >= 3:
            starts.append(parts[2])
            ends.append(parts[3] if len(parts) > 3 else parts[-1])
    try:
        start_date = datetime.strptime(starts[0], '%Y%m%d').date()
        end_date = datetime.strptime(ends[-1], '%Y%m%d').date()
    except Exception:
        # fallback: use file mtimes
        start_date = datetime.utcfromtimestamp(selected[0].stat().st_mtime).date()
        end_date = datetime.utcfromtimestamp(selected[-1].stat().st_mtime).date()

    monthly_dir = log_dir / 'monthly'
    monthly_dir.mkdir(exist_ok=True)
    archive = monthly_dir / _monthly_zip_name(start_date, end_date)
    try:
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for p in selected:
                zf.write(p, arcname=p.name)
        # remove weekly zips after successful archive
        for p in selected:
            try:
                p.unlink()
            except Exception:
                LOG.exception('Failed to remove weekly zip %s', p)
        return archive
    except Exception:
        LOG.exception('Failed to create monthly archive %s', archive)
        return None


def compress_year_if_needed(log_dir: Path):
    """Compress monthly zips into a yearly zip when there are >=12 monthly zips for a calendar year."""
    monthly_dir = log_dir / 'monthly'
    if not monthly_dir.exists():
        return
    zips = sorted([p for p in monthly_dir.iterdir() if p.is_file() and p.suffix == '.zip'])
    if not zips:
        return

    # Group monthly zips by year using the end date parsed from filename
    groups = {}
    for p in zips:
        # expected: app_logs_month_YYYYMMDD_YYYYMMDD.zip
        parts = p.stem.split('_')
        if len(parts) >= 4:
            end_str = parts[-1]
            try:
                end_date = datetime.strptime(end_str, '%Y%m%d').date()
                year = end_date.year
            except Exception:
                year = None
        else:
            year = None
        if year is None:
            # fallback to file mtime year
            try:
                year = datetime.utcfromtimestamp(p.stat().st_mtime).year
            except Exception:
                continue
        groups.setdefault(year, []).append(p)

    for year, files in groups.items():
        if len(files) >= 12:
            files.sort()
            yearly_dir = log_dir / 'yearly'
            yearly_dir.mkdir(exist_ok=True)
            archive = yearly_dir / f'app_logs_year_{year}.zip'
            try:
                with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                    for p in files:
                        zf.write(p, arcname=p.name)
                # remove monthly zips after successful archive
                for p in files:
                    try:
                        p.unlink()
                    except Exception:
                        LOG.exception('Failed to remove monthly zip %s', p)
                LOG.info('Created yearly archive %s', archive)
            except Exception:
                LOG.exception('Failed to create yearly archive %s', archive)


class LogRotationThread:
    def __init__(self, interval_seconds=3600, run_hour_utc=0, run_minute=5):
        self.interval = interval_seconds
        self.run_hour = run_hour_utc
        self.run_minute = run_minute
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name='log-rotation-thread', daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        log_dir = Path(getattr(settings, 'LOG_DIR', Path(settings.BASE_DIR) / 'logs'))
        _ensure_dirs(log_dir)

        while not self._stop.is_set():
            try:
                now = datetime.utcnow()
                # If it's the scheduled time window (minute after run_minute), attempt weekly compression for previous week
                if now.hour == self.run_hour and now.minute >= self.run_minute and now.weekday() == 0:
                    # previous week's Monday
                    last_monday = (now.date() - timedelta(days=7))
                    # compute previous week's Monday and Sunday
                    week_start = last_monday - timedelta(days=last_monday.weekday())
                    week_end = week_start + timedelta(days=6)
                    archive = compress_week(log_dir, week_start, week_end)
                    if archive:
                        LOG.info('Created weekly archive %s', archive)
                        # After weekly archive, check monthly
                        compress_month_if_needed(log_dir)
                # Sleep until next check
            except Exception:
                LOG.exception('Unexpected error in log rotation thread')
            # Sleep interval
            time.sleep(self.interval)


log_rotation_thread = LogRotationThread()
