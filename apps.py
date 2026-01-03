from django.apps import AppConfig
import threading


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
        """Start a background thread that refreshes MT5 balances/equity every 5 seconds."""
        try:
            def refresher():
                import time
                from django.db import connection

                # Import here to avoid app-loading issues
                try:
                    from adminPanel.mt5.services import MT5ManagerActions
                    from adminPanel.models import TradingAccount
                except Exception:
                    # import failed, exit thread
                    return

                while True:
                    try:
                        # Ensure DB table exists before proceeding
                        try:
                            table_names = connection.introspection.table_names()
                            if 'adminPanel_tradingaccount' not in table_names:
                                time.sleep(5)
                                continue
                        except Exception:
                            time.sleep(5)
                            continue

                        mt5 = MT5ManagerActions()
                        if not getattr(mt5, 'manager', None):
                            time.sleep(5)
                            continue

                        qs = TradingAccount.objects.all().only('id', 'account_id')
                        for acc in qs.iterator():
                            try:
                                login_id = int(acc.account_id)
                            except Exception:
                                continue
                            try:
                                bal = mt5.get_balance(login_id)
                                eq = mt5.get_equity(login_id)
                                changed = False
                                if bal is not None and float(getattr(acc, 'balance', 0)) != float(bal):
                                    acc.balance = bal
                                    changed = True
                                if eq is not None and float(getattr(acc, 'equity', 0)) != float(eq):
                                    acc.equity = eq
                                    changed = True
                                if changed:
                                    acc.save(update_fields=['balance', 'equity'])
                            except Exception:
                                # per-account error ignored
                                pass
                            time.sleep(0.05)
                    except Exception:
                        # unexpected error; sleep then continue
                        time.sleep(5)

            t = threading.Thread(target=refresher, name='broker-mt5-refresher', daemon=True)
            t.start()
        except Exception:
            # Failed to start refresher; silently ignore
            pass

    def start_log_rotation_thread(self):
        """Start the weekly/monthly log rotation thread."""
        try:
            from brokerBackend.log_rotation_thread import log_rotation_thread
            log_rotation_thread.start()
        except Exception:
            # Silently ignore start failures
            pass
