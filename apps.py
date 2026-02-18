from django.apps import AppConfig
import threading
import logging


class BrokerBackendConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'brokerBackend'

    def ready(self):
        """
        Initialize background threads after Django apps are fully loaded.
        This ensures models can be imported safely.
        Threads will start for any server process (runserver, daphne, etc.),
        but not during migrations or management commands.
        """
        import sys
        import os
    # no logging per user request
        # List of management commands that should NOT start threads
        skip_commands = [
            'makemigrations', 'migrate', 'collectstatic', 'shell', 'test', 'createsuperuser',
            'loaddata', 'dumpdata', 'check', 'inspectdb', 'dbshell', 'flush', 'showmigrations',
        ]
        # If any skip command is present in sys.argv, do not start threads
        if any(cmd in sys.argv for cmd in skip_commands):
            return
        # Start threads for any server process (runserver, daphne, waitress, etc.)
        # Add a small delay to ensure full initialization
        
        # COMMISSION DETECTION: Re-enabled with optimized smart filtering
        # Uses same logic as external script but runs inside Django
        # Detection time: 50-200ms (vs old 5-15 seconds)
        threading.Timer(1.0, self.start_commission_sync).start()
        
        threading.Timer(2.0, self.start_mt5_balance_refresher).start()
        threading.Timer(3.0, self.start_monthly_reports_thread).start()
        threading.Timer(4.0, self.start_log_rotation_thread).start()
        # Ensure periodic Celery tasks are registered in DB (if django-celery-beat is installed)
        threading.Timer(5.0, self.ensure_periodic_tasks).start()
        
    def start_commission_sync(self):
        """Start the commission synchronization thread.
        
        TEMPORARY BACKUP: Polling re-enabled until MT5 EA webhook is properly configured.
        
        TO DISABLE AFTER EA IS WORKING:
        1. Verify MT5 EA is running and sending webhooks successfully
        2. Comment out threading.Timer(1.0, self.start_commission_sync).start() in ready()
        3. Restart Django server
        
        The webhook system (/api/v1/commission-creation/) is superior:
        - 10-50ms detection vs 100ms+ polling
        - Lower database load
        - No race conditions
        """
        try:
            from adminPanel.commission_sync import commission_sync_thread
            # Set to 0 seconds for near real-time detection
            commission_sync_thread.interval = 0
            commission_sync_thread.start()
        except Exception:
            # Silently ignore start failures
            pass

    def ensure_periodic_tasks(self):
        """Create the daily trading report PeriodicTask/CrontabSchedule if missing.
        Runs shortly after startup to avoid interfering with migrations.
        """
        try:
            # Import locally to avoid import-time side effects
            from django.conf import settings
            # Delay if running management commands that should skip background init
            import sys
            skip_commands = [
                'makemigrations', 'migrate', 'collectstatic', 'shell', 'test', 'createsuperuser',
                'loaddata', 'dumpdata', 'check', 'inspectdb', 'dbshell', 'flush', 'showmigrations',
            ]
            if any(cmd in sys.argv for cmd in skip_commands):
                return

            # Create CrontabSchedule and PeriodicTask
            try:
                from django_celery_beat.models import CrontabSchedule, PeriodicTask
            except Exception:
                return

            tz = getattr(settings, 'TIME_ZONE', 'UTC')
            # Create or get crontab for 02:00
            schedule, _ = CrontabSchedule.objects.get_or_create(
                minute='0', hour='2', day_of_week='*', day_of_month='*', month_of_year='*', timezone=tz
            )

            task_name = 'daily-trading-report-2am'
            task_path = 'adminPanel.tasks.daily_reports.daily_trading_report_runner'

            PeriodicTask.objects.get_or_create(
                name=task_name,
                defaults={
                    'crontab': schedule,
                    'task': task_path,
                    'enabled': True,
                    'description': 'Runs daily trading report runner at 02:00 (server time) for previous day',
                }
            )
        except Exception:
            # Fail silently; this is best-effort convenience
            pass

    def start_monthly_reports_thread(self):
        """Start the monthly reports thread."""
        try:
            from adminPanel.monthly_reports_thread import monthly_reports_thread
            # Check every hour for monthly report scheduling
            monthly_reports_thread.start()
        except Exception:
            # Silently ignore start failures
            pass

    def start_mt5_balance_refresher(self):
        """Start an optimized background thread that refreshes MT5 balances/equity."""
        try:
            def refresher():
                import time
                from django.db import connection
                from django.db import transaction

                # Import here to avoid app-loading issues
                try:
                    from adminPanel.mt5.services import MT5ManagerActions
                    from adminPanel.models import TradingAccount
                except Exception:
                    return

                # Configuration
                REFRESH_INTERVAL = 2  # seconds between refresh cycles
                BATCH_SIZE = 50  # accounts to process in each batch
                ACCOUNT_DELAY = 0.01  # minimal delay between accounts (10ms)
                MAX_RETRIES = 3
                
                logger = logging.getLogger('mt5_refresher')
                logger.info("MT5 Balance Refresher started with optimized performance")

                while True:
                    cycle_start = time.time()
                    processed_count = 0
                    updated_count = 0
                    
                    try:
                        # Ensure DB table exists
                        try:
                            table_names = connection.introspection.table_names()
                            if 'adminPanel_tradingaccount' not in table_names:
                                time.sleep(REFRESH_INTERVAL)
                                continue
                        except Exception:
                            time.sleep(REFRESH_INTERVAL)
                            continue

                        # Initialize MT5 manager with retry logic
                        mt5 = None
                        for retry in range(MAX_RETRIES):
                            try:
                                mt5 = MT5ManagerActions()
                                if getattr(mt5, 'manager', None):
                                    break
                                time.sleep(1)  # Short retry delay
                            except Exception as e:
                                if retry == MAX_RETRIES - 1:
                                    logger.warning(f"Failed to initialize MT5 after {MAX_RETRIES} retries: {e}")
                                time.sleep(1)
                        
                        if not mt5 or not getattr(mt5, 'manager', None):
                            time.sleep(REFRESH_INTERVAL)
                            continue

                        # Process accounts in batches for better performance
                        accounts = TradingAccount.objects.filter(is_enabled=True).only('id', 'account_id', 'balance', 'equity')
                        total_accounts = accounts.count()
                        
                        if total_accounts == 0:
                            time.sleep(REFRESH_INTERVAL)
                            continue

                        # Process in batches
                        for batch_start in range(0, total_accounts, BATCH_SIZE):
                            batch_accounts = accounts[batch_start:batch_start + BATCH_SIZE]
                            updates = []
                            
                            for acc in batch_accounts:
                                try:
                                    login_id = int(acc.account_id)
                                    processed_count += 1
                                    
                                    # Use optimized single API call for both balance and equity
                                    account_data = mt5.get_account_data(login_id, use_cache=True)
                                    bal = account_data['balance']
                                    eq = account_data['equity']
                                    
                                    # Check if values actually changed to minimize DB writes
                                    current_balance = float(getattr(acc, 'balance', 0) or 0)
                                    current_equity = float(getattr(acc, 'equity', 0) or 0)
                                    
                                    balance_changed = abs(current_balance - bal) > 0.01  # More than 1 cent
                                    equity_changed = abs(current_equity - eq) > 0.01
                                    
                                    if balance_changed or equity_changed:
                                        acc.balance = bal
                                        acc.equity = eq
                                        updates.append(acc)
                                        updated_count += 1
                                    
                                except (ValueError, TypeError):
                                    # Invalid account_id, skip
                                    continue
                                except Exception:
                                    # Individual account error, continue with others
                                    continue
                                
                                # Minimal delay to prevent API overload
                                if ACCOUNT_DELAY > 0:
                                    time.sleep(ACCOUNT_DELAY)
                            
                            # Bulk update changed accounts
                            if updates:
                                try:
                                    with transaction.atomic():
                                        TradingAccount.objects.bulk_update(updates, ['balance', 'equity'])
                                except Exception as e:
                                    logger.warning(f"Bulk update failed for batch: {e}")
                                    # Fallback to individual saves
                                    for acc in updates:
                                        try:
                                            acc.save(update_fields=['balance', 'equity'])
                                        except Exception:
                                            pass
                    
                    except Exception as e:
                        logger.error(f"Unexpected error in refresher cycle: {e}")
                    
                    # Performance logging every 50 cycles (approximately every 100 seconds)
                    cycle_end = time.time()
                    cycle_duration = cycle_end - cycle_start
                    
                    if processed_count > 0 and (int(cycle_end) % 100 == 0):  # Log every ~100 seconds
                        logger.info(f"MT5 Refresher: {processed_count} accounts processed, {updated_count} updated in {cycle_duration:.2f}s")
                    
                    # Dynamic sleep to maintain consistent refresh intervals
                    sleep_time = max(0, REFRESH_INTERVAL - cycle_duration)
                    time.sleep(sleep_time)

            t = threading.Thread(target=refresher, name='broker-mt5-refresher-optimized', daemon=True)
            t.start()
        except Exception as e:
            # Failed to start refresher
            try:
                logger = logging.getLogger('mt5_refresher')
                logger.error(f"Failed to start MT5 balance refresher: {e}")
            except:
                pass

    def start_log_rotation_thread(self):
        """Start the weekly/monthly log rotation thread."""
        try:
            from brokerBackend.log_rotation_thread import log_rotation_thread
            log_rotation_thread.start()
        except Exception:
            # Silently ignore start failures
            pass
