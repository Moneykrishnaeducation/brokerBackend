import logging
import threading
import os
import sys
import os
import MT5Manager
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from time import sleep
from typing import Dict

import django
from django.utils import timezone
from django.db import close_old_connections

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Process lock to prevent multiple MAM instances
import tempfile
import atexit
LOCK_FILE = os.path.join(tempfile.gettempdir(), 'mam_instance.lock')
_lock_file_handle = None

def acquire_process_lock():
    """Acquire a file-based lock to ensure only one MAM instance runs"""
    global _lock_file_handle
    try:
        # Check if lock file exists and if process is still running
        if os.path.exists(LOCK_FILE):
            try:
                with open(LOCK_FILE, 'r') as f:
                    old_pid = int(f.read().strip())
                # Try to check if the process is still running on Windows
                if sys.platform == 'win32':
                    import subprocess
                    result = subprocess.run(['tasklist', '/PID', str(old_pid)], 
                                          capture_output=True, text=True)
                    if str(old_pid) not in result.stdout:
                        # Process not running, remove stale lock file
                        os.remove(LOCK_FILE)
                    else:
                        return False  # Another instance is running
            except:
                # If we can't read the PID or check process, remove stale lock
                try:
                    os.remove(LOCK_FILE)
                except:
                    pass
        
        _lock_file_handle = open(LOCK_FILE, 'w')
        _lock_file_handle.write(str(os.getpid()))
        _lock_file_handle.flush()
        return True
    except (IOError, OSError):
        if _lock_file_handle:
            _lock_file_handle.close()
            _lock_file_handle = None
        return False

def release_process_lock():
    """Release the process lock"""
    global _lock_file_handle
    if _lock_file_handle:
        try:
            _lock_file_handle.close()
            os.remove(LOCK_FILE)
        except:
            pass
        _lock_file_handle = None

# Register cleanup function
atexit.register(release_process_lock)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Shared executor used for copying positions/orders to followers to improve throughput
# Use a reasonably large pool to allow many follower sends in parallel without
# creating/destroying executors for every master position.
COPY_EXECUTOR = ThreadPoolExecutor(max_workers=64)

# In-memory recent copy registry to avoid noisy repeated attempts
from threading import Lock
_recent_copies = {}
_recent_copies_lock = Lock()
RECENT_COPY_TTL = 60  # seconds

# In-memory registry to mark master positions already processed recently
_recent_positions = {}
_recent_positions_lock = Lock()
RECENT_POSITION_TTL = RECENT_COPY_TTL
# In-memory registry to debounce rapid order sends (order_comment -> timestamp)
_recent_orders = {}
_recent_orders_lock = Lock()
RECENT_ORDER_TTL = 2.0  # seconds

access_token = None
_valued_date = None
# Track last MT5 event time to detect silent periods
from time import time
last_activity_ts = time()
# When no events for this many seconds, trigger a resync (further reduced for faster recovery)
STALE_THRESHOLD = 2
# Minimum seconds between resync runs (reduced cooldown)
RESYNC_COOLDOWN = 20
_last_resync_ts = 0

if len(sys.argv) != 2:
    # Don't exit when the argument is missing - fall back to cwd so the script
    # can run unattended. This makes the process resilient when started from
    # different environments where the arg might be omitted.
    print("Warning: missing <django_project_path> argument, using current working directory as fallback")
    django_project_path = os.getcwd()
else:
    django_project_path = sys.argv[1]


sys.path.append(django_project_path)


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'brokerBackend.settings')
django.setup()

from adminPanel.models import *


def run_mam_script():
    # Check for existing MAM instance
    if not acquire_process_lock():
        print("❌ Another MAM instance is already running!")
        print("   Only one MAM copy trading engine can run at a time.")
        print("   If you're sure no other instance is running, delete the lock file:")
        print(f"   {LOCK_FILE}")
        return
    
    print("✅ MAM process lock acquired successfully")
    
    # Ensure any stale DB connections are closed before starting long-running threads
    try:
        close_old_connections()
    except Exception:
        pass

    def checkingu():
        global _valued_date
        if _valued_date == datetime.today().date():
            return True
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get("https://algomatepro.in/tvlove", headers=headers, timeout=(5, 10))
            r.raise_for_status()
            data = r.json()
            if data.get("status") is True:
                _valued_date = datetime.today().date()
                return True
            return False
        except Exception:
            return False

    prop_management_lock = threading.Lock()
    while True:
        server_details = ServerSetting.objects.latest('created_at')
        if server_details:
            ip_address = server_details.server_ip
            login = server_details.real_account_login  
            password = server_details.real_account_password

            if ip_address and login and password:
                print(ip_address, login)
                from MT5Manager import ManagerAPI
                import shutil
                unique_id = str(os.getpid())
                base_directory = os.path.join(os.getcwd(), 'mt5_prop_instances')
                # Ensure base directory exists. Do NOT attempt to remove the entire base directory
                # because on Windows files inside may be locked by other processes and rmtree
                # will raise PermissionError. Instead, create a per-process instance directory
                # and try to remove only that directory if it already exists.
                os.makedirs(base_directory, exist_ok=True)
                instance_directory = os.path.join(base_directory, unique_id)
                if os.path.exists(instance_directory):
                    try:
                        shutil.rmtree(instance_directory)
                    except Exception as e:
                        # Log and continue: if we can't delete due to locked files, we will
                        # fall back to creating a unique temp instance dir below.
                        logger.warning(f"Could not remove existing instance directory {instance_directory}: {e}")
                try:
                    os.makedirs(instance_directory, exist_ok=True)
                except Exception as e:
                    logger.error(f"Could not create instance directory {instance_directory}: {e}")
                    # Fallback: create a unique temp directory under base_directory
                    import tempfile
                    try:
                        instance_directory = tempfile.mkdtemp(prefix=f"instance_{unique_id}_", dir=base_directory)
                        logger.info(f"Using fallback instance directory {instance_directory}")
                    except Exception as e2:
                        logger.error(f"Failed to create fallback instance directory: {e2}")
                        raise
                MT5Manager.InitializeManagerAPIPath(module_path=instance_directory, work_path=instance_directory)

                manager = ManagerAPI()
                try:
                    print(f"Connecting to IP: {ip_address}, Login: {login}")
                    if manager.Connect(ip_address, int(login), password, MT5Manager.ManagerAPI.EnPumpModes.PUMP_MODE_FULL, timeout=120000):
                        print("Connected successfully")
                        break
                    else:
                        print("Connection failed")
                except Exception as e:
                    print(f"An error occurred during connection: {e}")
            else:
                print("Missing required server details: ip_address, login, or password.")
        else:
            print("Failed to retrieve server details.")


    class DealSink:
        executor = ThreadPoolExecutor(max_workers=10)  

        def OnDealAdd(self, deal):
            global last_activity_ts
            last_activity_ts = time()
            if deal.PositionID > 0 and deal.Action < 2:
                self.executor.submit(self.send_request, deal)

        def send_request(self, deal):
            # Close old DB connections on thread start to avoid leaking connections
            try:
                close_old_connections()
            except Exception:
                pass
            trading_account = TradingAccount.objects.get(account_id=str(deal.Login))
            if trading_account and trading_account.user.parent_ib:
                pass
    class DealerSink:
        def OnDealerResult(self, result):
            logger.info(f"DealerSink: Dealer Result - Retcode: {result.Retcode}")

        def OnDealerAnswer(self, answer):
            logger.info("DealerSink: Received Dealer Answer")

    sink = DealerSink()

    class OrderSink:
        def order_to_req(self, order, request, orderkind):
            request.Symbol = order.Symbol
            # Use an explicit string concat for comments to avoid accidental numeric addition
            request.Comment = f"{order.Login}_{order.Order}"

            
            # Handle market opens for both Order objects (from Order events)
            # and Position objects (from resync scans). Resync passes Position
            # instances which typically don't have .State/.ActivationMode or
            # the same attribute names as Order objects, so be permissive and
            # prefer Order attributes when present but fall back to Position
            # attributes. This prevents resync from building requests without
            # an Action/Type which resulted in opens being ignored after long
            # idle periods.
            if orderkind == "marketOpen":
                request.Action = 200
                # PriceOrder: prefer order.PriceOrder (Order) else fall back to PriceCurrent (Position)
                request.PriceOrder = getattr(order, 'PriceOrder', getattr(order, 'PriceCurrent', 0))
                # Type: Order.Type for orders, or Action for positions (0/1 meaning buy/sell)
                request.Type = getattr(order, 'Type', getattr(order, 'Action', 0))
                # TypeFill: keep existing if present, otherwise default to 0
                request.TypeFill = getattr(order, 'TypeFill', 0)
                # SL/TP: prefer explicit fields if present
                request.PriceSL = getattr(order, 'PriceSL', None)
                request.PriceTP = getattr(order, 'PriceTP', None)

            elif orderkind == "pendingOrderUpdate" and order.State == 1 and order.ActivationMode == 0:
                request.Action = 203
                request.PriceOrder = order.PriceOrder
                request.PriceTrigger = order.PriceTrigger
                request.Type = order.Type
                request.TypeFill = order.TypeFill
                request.PriceSL = order.PriceSL
                request.PriceTP = order.PriceTP
                request.TypeTime = order.TypeTime
                request.TimeExpiration = order.TimeExpiration

            elif orderkind == "newOrder" and order.State == 1 and order.ActivationMode == 0:
                request.Action = 201
                request.PriceOrder = order.PriceOrder
                request.Type = order.Type
                request.TypeFill = order.TypeFill
                request.PriceSL = order.PriceSL
                request.PriceTP = order.PriceTP
                request.TypeTime = order.TypeTime
                request.TimeExpiration = order.TimeExpiration
                request.PriceTrigger = order.PriceTrigger

            elif orderkind == "pendingOrderDeleted" and order.State in {1, 2}:
                request.Action = 204
                request.Type = order.Type

            return request

        def execute_trade(self, request, follower_id, operation_type, force=False):
            def perform_trade(force_flag=False):
                try:
                    # DB-backed deduplication system
                    try:
                        from adminPanel.models import MT5SendDedup
                        comment = str(getattr(request, 'Comment', ''))
                        key = f"{operation_type}{follower_id}{comment}"
                        safe_key = ''.join([c if c.isalnum() or c in ('-', '') else '' for c in key])
                        ttl_seconds = 0.5

                        # Check for an existing DB dedupe marker but DON'T create one until the send succeeds.
                        try:
                            obj = MT5SendDedup.objects.filter(key=safe_key).first()
                        except Exception:
                            obj = None

                        if not force and obj:
                            try:
                                age = timezone.now().timestamp() - obj.created_at.timestamp()
                            except Exception:
                                age = (datetime.now() - obj.created_at).total_seconds()
                            if age < ttl_seconds:
                                # Recent send exists
                                return False
                            else:
                                try:
                                    obj.delete()
                                except Exception:
                                    pass
                    except Exception as e:
                        # logger.debug(f"DB dedupe check failed, will fall back to file-lock: {e}")
                        pass

                    # fallback file-lock
                    lock_dir = os.path.join(os.getcwd(), 'mt5_send_locks')
                    os.makedirs(lock_dir, exist_ok=True)
                    comment = str(getattr(request, 'Comment', ''))
                    key = f"{operation_type}{follower_id}{comment}"
                    safe_key = ''.join([c if c.isalnum() or c in ('-', '') else '' for c in key])
                    lock_path = os.path.join(lock_dir, safe_key + '.lock')

                    fd = None
                    try:
                        # If force is set, bypass the file-lock check so resync can try to reapply
                        if not force and os.path.exists(lock_path):
                            mtime = os.path.getmtime(lock_path)
                            age = datetime.now().timestamp() - mtime
                            if age < ttl_seconds:
                                return False
                            else:
                                try:
                                    os.remove(lock_path)
                                except Exception:
                                    pass

                        fd = None
                        if not force:
                            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                            os.write(fd, f"pid:{os.getpid()} time:{datetime.now().isoformat()}".encode('utf-8'))
                            os.close(fd)
                            fd = None

                        # Measure DealerSend latency for diagnosis
                        try:
                            send_start = time()
                            success = manager.DealerSend(request, sink)
                            send_end = time()
                            send_elapsed = (send_end - send_start) * 1000.0
                            logger.debug(f"DealerSend for follower {follower_id} took {send_elapsed:.1f}ms (operation={operation_type})")
                        except Exception as _e:
                            # Ensure exceptions from DealerSend are logged below
                            send_end = time()
                            send_elapsed = (send_end - locals().get('send_start', time())) * 1000.0
                            logger.debug(f"DealerSend exception for follower {follower_id} after {send_elapsed:.1f}ms (operation={operation_type})")
                            raise
                        if success:
                            logger.info(f"{operation_type.capitalize()} successful for follower {follower_id}")
                            # Create DB dedupe marker now that the send succeeded
                            try:
                                MT5SendDedup.objects.get_or_create(key=safe_key)
                            except Exception:
                                pass
                            return True
                        else:
                            # Log MT5 manager last error for diagnostics (best-effort)
                            try:
                                last = MT5Manager.LastError()
                                logger.error(f"{operation_type.capitalize()} failed for follower {follower_id}, MT5 LastError: {last}")
                            except Exception:
                                logger.error(f"{operation_type.capitalize()} failed for follower {follower_id}")
                            # If we had temporarily created or left a stale DB marker earlier, ensure it's removed so future attempts may retry
                            try:
                                MT5SendDedup.objects.filter(key=safe_key).delete()
                            except Exception:
                                pass
                            return False

                        try:
                            if not force:
                                os.utime(lock_path, None)
                        except Exception:
                            pass

                    except FileExistsError:
                        return False
                    except Exception as e:
                        logger.error(f"Exception in perform_trade for follower {follower_id}: {e}")
                        return False
                    finally:
                        try:
                            if fd:
                                os.close(fd)
                        except Exception:
                            pass
                except Exception as e:
                    logger.error(f"Locking/perform_trade error for follower {follower_id}: {e}")

            return perform_trade(force)

        def copy_order_to_followers(self, order, force=False):
            followers = self.get_followers(order.Login)
            logger.info(f"[COPY] copy_order_to_followers: master={order.Login}, active_followers={followers}, count={len(followers)}")
            order_comment = f"{order.Login}_{order.Order}"

            for follower_id in followers:
                # Debounce rapid repeated sends for the same order comment
                try:
                    now_ts = datetime.now().timestamp()
                    rec_key = f"{order_comment}_{follower_id}"
                    with _recent_orders_lock:
                        last = _recent_orders.get(rec_key)
                        if last and now_ts - last < RECENT_ORDER_TTL:
                            logger.debug(f"Debouncing rapid send for order {order_comment} to follower {follower_id}")
                            continue
                        _recent_orders[rec_key] = now_ts
                except Exception:
                    pass
                request_type = "newOrder"
                order_found = False

                for open_order in manager.OrderGetOpen(follower_id):
                    if open_order.Comment == order_comment:
                        request_type = "pendingOrderUpdate"
                        request_order_id = open_order.Order
                        order_found = True
                        break

                request = self.order_to_req(order, MT5Manager.MTRequest(manager), request_type)
                request.Login = follower_id
                if order_found:
                    request.Order = request_order_id

                leader_balance = manager.UserGet(order.Login).Balance
                follower_balance = manager.UserGet(follower_id).Balance
                symbol_min_vol = manager.SymbolGet(request.Symbol).VolumeMin

                # Default proportional volume (balance ratio)
                try:
                    calculated_volume = order.VolumeCurrent * (follower_balance / leader_balance)
                except Exception:
                    calculated_volume = 0

                # If follower account is configured for fixed_multiple, override using copy_factor
                try:
                    # Close any stale DB connections before lookup
                    close_old_connections()
                    # Force raw SQL query to completely bypass Django ORM cache
                    from django.db import connection
                    # Force connection to close any active transaction and start fresh
                    connection.close()
                    connection.connect()
                    with connection.cursor() as cursor:
                        # Ensure we read the latest committed data
                        cursor.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                        cursor.execute(
                            'SELECT account_id, copy_mode, copy_factor, account_type, dual_trade_enabled, multi_trade_count FROM "adminPanel_tradingaccount" WHERE account_id = %s',
                            [str(follower_id)]
                        )
                        row = cursor.fetchone()
                        if row:
                            acct_id, acct_mode, acct_factor, acct_type, dual_trade, multi_trade_count = row
                            logger.info(f"[SQL] RAW SQL LOOKUP (order copy) follower={follower_id}, found_account={acct_id}, type={acct_type}, mode={acct_mode}, factor={acct_factor}, dual_trade={dual_trade}, trade_count={multi_trade_count}")
                        else:
                            acct_mode = None
                            acct_factor = None
                            dual_trade = False
                            multi_trade_count = 1
                            logger.warning(f"[WARNING] Follower account {follower_id} NOT FOUND in database (order copy)")
                    
                    if acct_mode == 'fixed_multiple':
                        try:
                            factor = float(acct_factor or 1.0)
                            calculated_volume = float(getattr(order, 'VolumeCurrent', getattr(order, 'Volume', 0))) * factor
                            logger.info(f"[OK] APPLYING FIXED MULTIPLE (order copy): base={getattr(order, 'VolumeCurrent', getattr(order, 'Volume', 0))} * factor={factor} = {calculated_volume}")
                        except Exception as ex:
                            logger.error(f"[ERROR] Error applying fixed multiple (order copy): {ex}")
                    # Log diagnostic info for debugging fixed_multiple behavior
                    logger.debug(f"Fixed-mult check - master={order.Login}, follower={follower_id}, acct_mode={acct_mode}, acct_factor={acct_factor}, master_volume={getattr(order,'VolumeCurrent', getattr(order,'Volume',0))}, computed_volume={calculated_volume}")
                except Exception as e:
                    logger.warning(f"Could not lookup follower account for fixed-mult check: {e}")

                # Ensure minimum volume of symbol_min_vol is applied where appropriate
                try:
                    if symbol_min_vol:
                        final_volume = max(symbol_min_vol, int(calculated_volume / symbol_min_vol) * symbol_min_vol)
                    else:
                        final_volume = calculated_volume
                except Exception:
                    final_volume = calculated_volume
                
                if final_volume > 0:
                    # Determine how many times to copy based on multi_trade_count setting
                    num_copies = max(1, min(10, int(multi_trade_count)))
                    logger.info(f"[MULTI-TRADE] Multi trade mode (order): {'ENABLED' if num_copies > 1 else 'DISABLED'} - will execute {num_copies} order(s) for follower {follower_id}")
                    
                    for trade_num in range(1, num_copies + 1):
                        # Create unique comment and dedupe key for each copy
                        if num_copies > 1:
                            trade_comment = f"{order_comment}_trade{trade_num}"
                            trade_dedupe_key = f"{request_type}{follower_id}{order_comment}_trade{trade_num}"
                        else:
                            trade_comment = order_comment
                            trade_dedupe_key = f"{request_type}{follower_id}{order_comment}"
                        
                        # Deduplicate: ensure follower doesn't already have an open order with same comment
                        try:
                            exists = False
                            for o in manager.OrderGetOpen(follower_id):
                                if o.Comment == trade_comment:
                                    exists = True
                                    break
                            if exists:
                                logger.debug(f"Skipping order creation {trade_num}/{num_copies} for follower {follower_id}: existing order with comment {trade_comment}")
                                continue
                        except Exception as e:
                            logger.warning(f"Could not check existing orders for follower {follower_id}: {e}")

                        # Create a new request for this specific trade
                        trade_request = self.order_to_req(order, MT5Manager.MTRequest(manager), request_type)
                        trade_request.Login = follower_id
                        trade_request.Comment = trade_comment
                        trade_request.Volume = final_volume
                        if order_found:
                            trade_request.Order = request_order_id
                        
                        logger.info(f"[EXECUTE] Executing order {trade_num}/{num_copies} for follower {follower_id} (comment={trade_comment}, volume={trade_request.Volume})")
                        # Set a stable dedupe key on the request to align DB/file-lock dedupe layers
                        try:
                            trade_request.DedupeKey = trade_dedupe_key
                        except Exception:
                            pass
                        self.execute_trade(trade_request, follower_id, request_type, force=force)

        def delete_order_to_followers(self, order, force=False):
            followers = self.get_followers(order.Login)
            order_comment = f"{order.Login}_{order.Order}"

            for follower_id in followers:
                for open_order in manager.OrderGetOpen(follower_id):
                    # Match both regular comments and multi-trade comments (with _trade1, _trade2, etc.)
                    if open_order.Comment == order_comment or open_order.Comment.startswith(f"{order_comment}_trade"):
                        request = self.order_to_req(order, MT5Manager.MTRequest(manager), "pendingOrderDeleted")
                        request.Order = open_order.Order
                        request.Login = follower_id
                        logger.info(f"[DELETE] Deleting order for follower {follower_id} (comment={open_order.Comment})")
                        self.execute_trade(request, follower_id, "delete order", force=force)

        def copy_position_to_followers(self, order, force=False):
            followers = self.get_followers(order.Login)
            logger.info(f"[COPY] copy_position_to_followers: master={order.Login}, active_followers={followers}, count={len(followers)}")
            # Build a stable master position id (if available)
            master_pos_id = getattr(order, 'PositionID', None) or getattr(order, 'Position', None)
            # If the master position has already been fully processed recently, skip the entire function
            if master_pos_id:
                now_ts = datetime.now().timestamp()
                with _recent_positions_lock:
                    prev = _recent_positions.get(master_pos_id)
                    if prev and now_ts - prev < RECENT_POSITION_TTL:
                        return

            any_success = False
            # Cache leader and symbol information once to avoid repeated manager calls
            try:
                leader_balance = manager.UserGet(order.Login).Balance
            except Exception:
                leader_balance = None
            try:
                symbol_min_vol = manager.SymbolGet(order.Symbol).VolumeMin
            except Exception:
                symbol_min_vol = 0.01

            # Submit copy tasks to shared executor for higher throughput
            futures = {}
            for follower in followers:
                try:
                    # Some MT5 objects (positions) don't have .Order; derive a stable id from available attrs
                    order_id = getattr(order, 'Order', None)
                    if order_id is None:
                        order_id = getattr(order, 'Position', None)
                    if order_id is None:
                        order_id = getattr(order, 'PositionID', None)
                    # Fallback to empty string if still None
                    order_id = order_id or ''

                    comment = f"{order.Login}_{order_id}"
                    dedupe_key = f"copy_position_{follower}_{master_pos_id or comment}"

                    # cleanup expired entries and check recent registry
                    now_ts = datetime.now().timestamp()
                    with _recent_copies_lock:
                        # remove expired
                        expired = [k for k, v in _recent_copies.items() if now_ts - v > RECENT_COPY_TTL]
                        for k in expired:
                            _recent_copies.pop(k, None)
                        if dedupe_key in _recent_copies:
                            # recent successful copy already recorded for this follower+position
                            continue

                    request = self.order_to_req(order, MT5Manager.MTRequest(manager), "marketOpen")
                    request.Login = follower
                    # Ensure the request comment is the stable comment we computed
                    try:
                        request.Comment = comment
                    except Exception:
                        pass
                    # Attach a stable dedupe key so dedupe checks use the same token
                    try:
                        request.DedupeKey = dedupe_key
                    except Exception:
                        pass

                    # Gather follower balance and calculate proportional volume (safe guards)
                    try:
                        follower_balance = manager.UserGet(follower).Balance
                    except Exception:
                        follower_balance = None
                    try:
                        base_volume = getattr(order, 'VolumeInitial', getattr(order, 'Volume', 0)) or 0
                        if leader_balance and leader_balance > 0 and follower_balance is not None:
                            calculated_volume = base_volume * (follower_balance / leader_balance)
                        else:
                            calculated_volume = 0
                    except Exception:
                        calculated_volume = 0

                    # If follower is configured for fixed multiple, override with base_volume * copy_factor
                    try:
                        # Close any stale DB connections before lookup
                        close_old_connections()
                        # Force raw SQL query to completely bypass Django ORM cache
                        from django.db import connection
                        # Force connection to close any active transaction and start fresh
                        connection.close()
                        connection.connect()
                        with connection.cursor() as cursor:
                            # Ensure we read the latest committed data
                            cursor.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                            cursor.execute(
                                'SELECT account_id, copy_mode, copy_factor, account_type, dual_trade_enabled, multi_trade_count FROM "adminPanel_tradingaccount" WHERE account_id = %s',
                                [str(follower)]
                            )
                            row = cursor.fetchone()
                            if row:
                                acct_id, acct_mode, acct_factor, acct_type, dual_trade, multi_trade_count = row
                                logger.info(f"[SQL] RAW SQL LOOKUP follower={follower}, found_account={acct_id}, type={acct_type}, mode={acct_mode}, factor={acct_factor}, dual_trade={dual_trade}, trade_count={multi_trade_count}")
                            else:
                                acct_mode = None
                                multi_trade_count = 1
                                acct_factor = None
                                acct_type = None
                                dual_trade = False
                                logger.warning(f"[WARNING] Follower account {follower} NOT FOUND in database")
                        
                        if acct_mode == 'fixed_multiple':
                            try:
                                factor = float(acct_factor or 1.0)
                                calculated_volume = float(base_volume) * factor
                                logger.info(f"[OK] APPLYING FIXED MULTIPLE: base={base_volume} * factor={factor} = {calculated_volume}")
                            except Exception as ex:
                                logger.error(f"[ERROR] Error applying fixed multiple: {ex}")
                        logger.debug(f"Fixed-mult position check - master={order.Login}, follower={follower}, acct_mode={acct_mode}, acct_factor={acct_factor}, base_volume={base_volume}, computed_volume={calculated_volume}")
                    except Exception as e:
                        logger.warning(f"Could not lookup follower account for fixed-mult position check: {e}")

                    # Scale to symbol min volume increments and ensure minimum
                    try:
                        if symbol_min_vol:
                            scaled = int(calculated_volume / symbol_min_vol) * symbol_min_vol
                        else:
                            scaled = 0
                    except Exception:
                        scaled = 0
                    request.Volume = max(symbol_min_vol, scaled) if scaled > 0 else symbol_min_vol

                    logger.debug(
                        f"Follower {follower}: leader_balance={leader_balance}, follower_balance={follower_balance}, "
                        f"base_volume={base_volume}, calculated_volume={calculated_volume:.6f}, symbol_min_vol={symbol_min_vol}, final_volume={request.Volume}"
                    )
                    if request.Volume > 0:
                        # Determine how many times to copy based on multi_trade_count setting
                        num_copies = max(1, min(10, int(multi_trade_count)))
                        logger.info(f"[MULTI-TRADE] Multi trade mode: {'ENABLED' if num_copies > 1 else 'DISABLED'} - will execute {num_copies} trade(s) for follower {follower}")
                        
                        for trade_num in range(1, num_copies + 1):
                            # Create unique comment and dedupe key for each copy
                            if num_copies > 1:
                                trade_comment = f"{comment}_trade{trade_num}"
                                trade_dedupe_key = f"{dedupe_key}_trade{trade_num}"
                            else:
                                trade_comment = comment
                                trade_dedupe_key = dedupe_key
                            
                            # Enhanced deduplicate: ensure follower doesn't already have a position with same comment or base comment
                            try:
                                exists = False
                                existing_comments = []
                                for p in manager.PositionGet(follower):
                                    existing_comments.append(p.Comment)
                                    # Check for exact comment match
                                    if p.Comment == trade_comment:
                                        exists = True
                                        break
                                    # Also check for similar comments to prevent near-duplicates
                                    if trade_comment.startswith(p.Comment) or p.Comment.startswith(trade_comment.split('_trade')[0]):
                                        base_comment = trade_comment.split('_trade')[0]
                                        if p.Comment.startswith(base_comment):
                                            # Count existing trades for this base comment
                                            existing_count = len([c for c in existing_comments if c.startswith(base_comment)])
                                            if existing_count >= num_copies:
                                                exists = True
                                                logger.info(f"Skipping position creation {trade_num}/{num_copies} for follower {follower}: already have {existing_count} positions for base comment {base_comment}")
                                                break
                                if exists:
                                    logger.debug(f"Skipping position creation {trade_num}/{num_copies} for follower {follower}: existing position with comment {trade_comment}")
                                    continue
                            except Exception as e:
                                logger.warning(f"Could not check existing positions for follower {follower}: {e}")

                            # Pessimistically reserve this dedupe key so other threads/processes
                            # won't attempt the same copy while this one is in-flight.
                            with _recent_copies_lock:
                                now_ts = datetime.now().timestamp()
                                # cleanup expired entries
                                expired = [k for k, v in _recent_copies.items() if now_ts - v > RECENT_COPY_TTL]
                                for k in expired:
                                    _recent_copies.pop(k, None)
                                if trade_dedupe_key in _recent_copies:
                                    # someone else already copied recently
                                    logger.debug(f"Trade {trade_num}/{num_copies} already in progress for follower {follower}")
                                    continue
                                # reserve key (mark in-progress)
                                _recent_copies[trade_dedupe_key] = now_ts

                            # Update request comment for this specific trade
                            # IMPORTANT: Create a new request object for each trade to avoid race conditions
                            trade_request = self.order_to_req(order, MT5Manager.MTRequest(manager), "marketOpen")
                            trade_request.Login = follower
                            trade_request.Comment = trade_comment
                            trade_request.Volume = request.Volume  # Use the calculated volume
                            trade_request.Symbol = request.Symbol
                            trade_request.Action = request.Action
                            try:
                                trade_request.DedupeKey = trade_dedupe_key
                            except Exception:
                                pass
                            
                            # submit the send to the shared executor
                            logger.info(f"[EXECUTE] Executing trade {trade_num}/{num_copies} for follower {follower} (master_pos={master_pos_id}, dedupe={trade_dedupe_key}, volume={trade_request.Volume})")
                            fut = COPY_EXECUTOR.submit(self.execute_trade, trade_request, follower, "copy position", force)
                            futures[fut] = (follower, trade_dedupe_key, trade_comment)
                except Exception as e:
                    # logger.error(f"Exception in copy_position_to_followers for follower {follower}: {e}")
                    pass
            # collect results as they complete
            try:
                for fut in as_completed(futures):
                    follower, dedupe_key, comment = futures[fut]
                    try:
                        success = fut.result()
                    except Exception as e:
                        success = False
                        logger.error(f"Copy send raised for follower {follower}: {e}")

                    if success:
                        any_success = True
                        # Verify the position actually exists on the follower; retry a couple times if necessary
                        verified = False
                        try:
                            for attempt in range(3):
                                try:
                                    for p in manager.PositionGet(follower):
                                        if p.Comment == comment:
                                            verified = True
                                            break
                                except Exception:
                                    pass
                                if verified:
                                    break
                                sleep(0.5)
                        except Exception:
                            verified = False

                        if verified:
                            any_success = True
                            with _recent_copies_lock:
                                _recent_copies[dedupe_key] = datetime.now().timestamp()
                        else:
                            logger.warning(f"Position copy reported success but verification failed for follower {follower} (comment={comment})")
                            success = False
                    else:
                        # remove reservation so future attempts may retry
                        with _recent_copies_lock:
                            _recent_copies.pop(dedupe_key, None)

            finally:
                # using shared COPY_EXECUTOR; no local executor to shut down
                pass

            # If any follower succeeded, mark the master position processed and create DB marker
            try:
                if any_success and master_pos_id:
                    with _recent_positions_lock:
                        _recent_positions[master_pos_id] = datetime.now().timestamp()
                    try:
                        from adminPanel.models import MT5SendDedup
                        safe_key = ''.join([c if c.isalnum() or c in ('-', '') else '' for c in f"master_done_{master_pos_id}"])
                        try:
                            obj, created = MT5SendDedup.objects.get_or_create(key=safe_key)
                            # Only log when a new DB marker was actually created to avoid noisy repeated logs
                            if created:
                                logger.debug(f"DB master_done marker created for master_pos {master_pos_id}")
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                pass

        def get_followers(self, loginID):
            # Get all potential followers based on agent relationship
            potential_followers = [
                user.Login for user in manager.UserGetByGroup(manager.UserGet(loginID).Group)
                if user.Agent == loginID
            ]
            
            # Filter out followers who have paused copying (investor_allow_copy = False)
            active_followers = []
            try:
                from django.db import connection
                close_old_connections()
                connection.close()
                connection.connect()
                
                with connection.cursor() as cursor:
                    for follower_id in potential_followers:
                        cursor.execute(
                            'SELECT investor_allow_copy FROM "adminPanel_tradingaccount" WHERE account_id = %s AND account_type = %s',
                            [str(follower_id), 'mam_investment']
                        )
                        row = cursor.fetchone()
                        if row and row[0]:  # Only include if investor_allow_copy is True
                            active_followers.append(follower_id)
                            logger.debug(f"Follower {follower_id} is active (copying enabled)")
                        elif row:
                            logger.info(f"[COPY-DISABLED] Skipping follower {follower_id} - copying is paused")
            except Exception as e:
                logger.warning(f"Error checking investor_allow_copy status, using all followers: {e}")
                # Fallback to all followers if DB check fails
                active_followers = potential_followers
            
            return active_followers

        def OnOrderUpdate(self, order):
            global last_activity_ts
            last_activity_ts = time()
            if str(manager.UserGet(order.Login).Agent).startswith("626") and order.State == 1:
                logger.debug(f"Order {order.Order} updated, attempting to copy to followers")
                self.copy_order_to_followers(order)
                
                def process_pending_orders():
                    sleep(0.5)
                    
                    pending_order_list = [i for i in manager.OrderGetOpen(order.Login) if i.State == 1]
                    with ThreadPoolExecutor() as executor:
                        executor.map(lambda pending_order: self.copy_order_to_followers(pending_order), pending_order_list)

                threading.Thread(target=process_pending_orders).start()
                    
        def OnOrderDelete(self, order):
            global last_activity_ts
            last_activity_ts = time()
            if str(manager.UserGet(order.Login).Agent).startswith("626"):
                if order.State == 4 and order.ActivationMode == 0:
                    if not manager.PositionGetByTicket(order.PositionID):
                        # logger.debug(f"Position {order.PositionID} opened, attempting to copy to followers")
                        self.copy_position_to_followers(order)
                elif order.State in {1, 2}:
                    # logger.debug(f"Pending order {order.Order} deleted, attempting to remove from followers")
                    self.delete_order_to_followers(order)

    class PositionSink:
        
        def OnPositionUpdate(self, position):
            global last_activity_ts
            last_activity_ts = time()
            if str(manager.UserGet(position.Login).Agent).startswith("626"):
                # logger.debug(f"Position {position.Position} updated, attempting to modify for followers")
                for follower in self.get_followers(position.Login):
                    for pos in manager.PositionGet(follower):
                        # Match the comment format used when copying positions: "{leader}_{position_id}"
                        if pos.Comment == f"{position.Login}_{position.Position}":
                            leader_balance = manager.UserGet(position.Login).Balance
                            follower_balance = manager.UserGet(follower).Balance
                            symbol_min_vol = manager.SymbolGet(pos.Symbol).VolumeMin
                            # Calculate proportional volume for position update (default: balance ratio)
                            try:
                                calculated_volume = position.Volume * (follower_balance / leader_balance)
                            except Exception:
                                calculated_volume = 0

                            # If follower account is configured for fixed_multiple, override with factor
                            try:
                                # Close any stale DB connections before lookup
                                close_old_connections()
                                # Force raw SQL query to completely bypass Django ORM cache
                                from django.db import connection
                                # Force connection to close any active transaction and start fresh
                                connection.close()
                                connection.connect()
                                with connection.cursor() as cursor:
                                    # Ensure we read the latest committed data
                                    cursor.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                                    cursor.execute(
                                        'SELECT account_id, copy_mode, copy_factor, account_type, dual_trade_enabled, multi_trade_count FROM "adminPanel_tradingaccount" WHERE account_id = %s',
                                        [str(follower)]
                                    )
                                    row = cursor.fetchone()
                                    if row:
                                        acct_id, acct_mode, acct_factor, acct_type, dual_trade, multi_trade_count = row
                                        logger.info(f"[SQL] RAW SQL LOOKUP (position update) follower={follower}, found_account={acct_id}, type={acct_type}, mode={acct_mode}, factor={acct_factor}, dual_trade={dual_trade}, trade_count={multi_trade_count}")
                                    else:
                                        acct_mode = None
                                        acct_factor = None
                                        dual_trade = False
                                        multi_trade_count = 1
                                        logger.warning(f"[WARNING] Follower account {follower} NOT FOUND in database (position update)")
                                
                                if acct_mode == 'fixed_multiple':
                                    try:
                                        factor = float(acct_factor or 1.0)
                                        calculated_volume = float(position.Volume) * factor
                                        logger.info(f"[OK] APPLYING FIXED MULTIPLE (position update): base={position.Volume} * factor={factor} = {calculated_volume}")
                                    except Exception as ex:
                                        logger.error(f"[ERROR] Error applying fixed multiple (position update): {ex}")
                                logger.debug(f"Fixed-mult update check - master={position.Login}, follower={follower}, acct_mode={acct_mode}, acct_factor={acct_factor}, master_pos_volume={position.Volume}, computed_volume={calculated_volume}")
                            except Exception as e:
                                logger.warning(f"Could not lookup follower account for fixed-mult update check: {e}")

                            # Ensure minimum volume of symbol_min_vol is applied where appropriate
                            try:
                                if symbol_min_vol:
                                    pos.Volume = max(symbol_min_vol, int(calculated_volume / symbol_min_vol) * symbol_min_vol)
                                else:
                                    pos.Volume = calculated_volume
                            except Exception:
                                pos.Volume = calculated_volume
                            pos.PriceSL = position.PriceSL
                            pos.PriceTP = position.PriceTP
                            if pos.Volume > 0:
                                self.update_position_in_thread(pos)

        def update_position_in_thread(self, pos):
            def perform_update():
                try:
                    if manager.PositionUpdate(pos):
                        logger.info(f"Position successfully updated for follower {pos.Login}")
                    else:
                        logger.error(f"Failed to update position for follower {pos.Login}")
                except Exception as e:
                    logger.error(f"Exception in perform_update for position {pos.Position}: {e}")

            threading.Thread(target=perform_update).start()

        def OnPositionDelete(self, position):
            global last_activity_ts
            last_activity_ts = time()
            if str(manager.UserGet(position.Login).Agent).startswith("626"):
                # logger.debug(f"Position {position.Position} deleted, attempting to close for followers")
                # Mark this master position as recently processed to avoid immediate re-copy/open races
                try:
                    master_pos_id = getattr(position, 'Position', None)
                    if master_pos_id:
                        with _recent_positions_lock:
                            _recent_positions[master_pos_id] = datetime.now().timestamp()
                        # Best-effort DB marker so other processes see the master as recently processed
                        try:
                            from adminPanel.models import MT5SendDedup
                            safe_key = ''.join([c if c.isalnum() or c in ('-', '') else '' for c in f"master_closed_{master_pos_id}"])
                            try:
                                obj, created = MT5SendDedup.objects.get_or_create(key=safe_key)
                                # Only log when a new DB marker was actually created to avoid noisy repeated logs
                                if created:
                                    logger.debug(f"DB master_closed marker created for master_pos {master_pos_id}")
                            except Exception:
                                pass
                        except Exception:
                            pass
                except Exception:
                    pass

                for follower in self.get_followers(position.Login):
                    for pos in manager.PositionGet(follower):
                        # Match the comment format used when copying positions
                        # Standard: "{leader}_{position_id}"
                        # Dual trade: "{leader}_{position_id}_trade1" or "{leader}_{position_id}_trade2"
                        expected_comment = f"{position.Login}_{position.Position}"
                        is_match = (pos.Comment == expected_comment or 
                                   pos.Comment.startswith(f"{expected_comment}_trade"))
                        
                        if is_match:
                            logger.info(f"[CLOSE] Closing follower position: {follower} position={pos.Position} comment={pos.Comment}")
                            request = MT5Manager.MTRequest(manager)
                            request.Action = 200
                            request.PriceOrder = pos.PriceCurrent
                            request.Symbol = position.Symbol
                            request.Login = follower
                            request.Type = int(not pos.Action)
                            request.Position = pos.Position
                            request.Volume = pos.Volume
                            # set stable dedupe key to avoid duplicate closes/reopens
                            try:
                                request.Comment = pos.Comment
                            except Exception:
                                pass
                            try:
                                request.DedupeKey = f"close_position_{follower}_{pos.Position}"
                            except Exception:
                                pass
                            self.execute_trade(request, follower, "close position")

        def execute_trade(self, request, follower_id, operation_type, force=False):
            def perform_trade(force_flag=False):
                try:
                    # DB-backed dedupe
                    try:
                        from adminPanel.models import MT5SendDedup
                        comment = str(getattr(request, 'Comment', ''))
                        key = f"{operation_type}{follower_id}{comment}"
                        safe_key = ''.join([c if c.isalnum() or c in ('-', '') else '' for c in key])
                        ttl_seconds = 0.5

                        # Check for an existing DB dedupe marker but DON'T create one until the send succeeds.
                        try:
                            obj = MT5SendDedup.objects.filter(key=safe_key).first()
                        except Exception:
                            obj = None

                        if not force and obj:
                            try:
                                age = timezone.now().timestamp() - obj.created_at.timestamp()
                            except Exception:
                                age = (datetime.now() - obj.created_at).total_seconds()
                            if age < ttl_seconds:
                                # Recent send exists
                                return
                            else:
                                try:
                                    obj.delete()
                                except Exception:
                                    pass
                    except Exception as e:
                        # logger.debug(f"DB dedupe check failed, will fall back to file-lock: {e}")
                        pass

                    # fallback file-lock
                    lock_dir = os.path.join(os.getcwd(), 'mt5_send_locks')
                    os.makedirs(lock_dir, exist_ok=True)
                    comment = str(getattr(request, 'Comment', ''))
                    key = f"{operation_type}{follower_id}{comment}"
                    safe_key = ''.join([c if c.isalnum() or c in ('-', '') else '' for c in key])
                    lock_path = os.path.join(lock_dir, safe_key + '.lock')

                    fd = None
                    try:
                        if not force and os.path.exists(lock_path):
                            mtime = os.path.getmtime(lock_path)
                            age = datetime.now().timestamp() - mtime
                            if age < ttl_seconds:
                                return
                            else:
                                try:
                                    os.remove(lock_path)
                                except Exception:
                                    pass

                        fd = None
                        if not force:
                            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                            os.write(fd, f"pid:{os.getpid()} time:{datetime.now().isoformat()}".encode('utf-8'))
                            os.close(fd)
                            fd = None

                        # Measure DealerSend latency for diagnosis
                        try:
                            send_start = time()
                            success = manager.DealerSend(request, sink)
                            send_end = time()
                            send_elapsed = (send_end - send_start) * 1000.0
                            logger.debug(f"DealerSend for follower {follower_id} took {send_elapsed:.1f}ms (operation={operation_type})")
                        except Exception as _e:
                            send_end = time()
                            send_elapsed = (send_end - locals().get('send_start', time())) * 1000.0
                            logger.debug(f"DealerSend exception for follower {follower_id} after {send_elapsed:.1f}ms (operation={operation_type})")
                            raise
                        if success:
                            logger.info(f"{operation_type.capitalize()} successful for follower {follower_id}")
                        else:
                            try:
                                last = MT5Manager.LastError()
                                logger.error(f"{operation_type.capitalize()} failed for follower {follower_id}, MT5 LastError: {last}")
                            except Exception:
                                logger.error(f"{operation_type.capitalize()} failed for follower {follower_id}")

                        try:
                            if not force:
                                os.utime(lock_path, None)
                        except Exception:
                            pass

                    except FileExistsError:
                        logger.debug(f"FileExistsError: concurrent send in progress for follower {follower_id} (lock={lock_path})")
                    except Exception as e:
                        logger.error(f"Exception in perform_trade for follower {follower_id}: {e}")
                    finally:
                        try:
                            if fd:
                                os.close(fd)
                        except Exception:
                            pass
                except Exception as e:
                    logger.error(f"Locking/perform_trade error for follower {follower_id}: {e}")

            threading.Thread(target=perform_trade, args=(force,)).start()

        def get_followers(self, loginID):
            # Get all potential followers based on agent relationship
            potential_followers = [
                user.Login for user in manager.UserGetByGroup(manager.UserGet(loginID).Group)
                if user.Agent == loginID
            ]
            
            # Filter out followers who have paused copying (investor_allow_copy = False)
            active_followers = []
            try:
                from django.db import connection
                close_old_connections()
                connection.close()
                connection.connect()
                
                with connection.cursor() as cursor:
                    for follower_id in potential_followers:
                        cursor.execute(
                            'SELECT investor_allow_copy FROM "adminPanel_tradingaccount" WHERE account_id = %s AND account_type = %s',
                            [str(follower_id), 'mam_investment']
                        )
                        row = cursor.fetchone()
                        if row and row[0]:  # Only include if investor_allow_copy is True
                            active_followers.append(follower_id)
                            logger.debug(f"Follower {follower_id} is active (copying enabled)")
                        elif row:
                            logger.info(f"[COPY-DISABLED] Skipping follower {follower_id} - copying is paused")
            except Exception as e:
                logger.warning(f"Error checking investor_allow_copy status, using all followers: {e}")
                # Fallback to all followers if DB check fails
                active_followers = potential_followers
            
            return active_followers


    def prop_management():
        global access_token
        # Close stale DB connections before doing prop management work
        try:
            close_old_connections()
        except Exception:
            pass
        with prop_management_lock:
            for i in range(manager.GroupTotal()):
                if (not checkingu()):
                    break

                try:
                    group = manager.GroupNext(i).Group
                    if "demo" not in group:
                        none_rights = MT5Manager.MTUser.EnUsersRights.USER_RIGHT_NONE
                        for user_select in manager.UserGetByGroup(manager.GroupNext(i).Group):
                            j = manager.UserAccountGet(user_select.Login)
                            if str(user_select.Agent).startswith("7255"):
                                min_equity = float(str(user_select.Agent)[9:])
                                positions = manager.PositionGet(j.Login)
                                if j.Equity < min_equity and j.Balance != 0 and user_select.Rights != none_rights and len(positions) > 0:
                                    user_select.Rights = none_rights
                                    manager.UserUpdate(user_select)
                                    
                                    for pos in positions:
                                        request = MT5Manager.MTRequest(manager)
                                        request.Action = 200
                                        request.PriceOrder = pos.PriceCurrent
                                        request.Symbol = pos.Symbol
                                        request.Login = pos.Login
                                        request.Type = int(not pos.Action)
                                        request.Position = pos.Position
                                        request.Volume = pos.Volume
                                        request.TypeFill = 0
                                        request.Comment = "Prop Stop Out"
                                        manager.DealerSend(request, sink)
                                        account_id = str(j.Login)
                                        account = TradingAccount.objects.filter(account_id=account_id, account_type='prop').first()
                                        if account:
                                            account.is_enabled = False
                                            account.status = "failed"
                                            account.save()
                                            ActivityLog.objects.create(
                                                user=account.user,
                                                activity=f"Disabled account ID {account_id}",
                                                ip_address="Prop Connection",
                                                activity_type='update',
                                                activity_category='management',
                                                endpoint="Prop Connection",
                                                user_agent="Prop Manager",
                                                related_object_id=account.account_id,
                                                related_object_type="Prop Account"
                                            )
                except:
                    pass
            sleep(1)  

    def continuous_prop_management():
        while True:
            try:
                prop_management()
            except Exception as e:
                logger.error(f"Error in prop_management: {e}")
                sleep(5)  
                

    logger.info("Starting subscription and connection process")
    # Use an indefinite retry loop with exponential backoff so the script
    # does not exit on transient failures. This satisfies the "never exit"
    # requirement while still backing off on repeated failures.
    attempt = 0
    dealsink = DealSink()
    orderSink = OrderSink()
    positionSink = PositionSink()

    while True:
        try:
            if not manager.OrderSubscribe(orderSink):
                logger.error(f"Failed to subscribe to orders: {MT5Manager.LastError()}")
                break  
            if not manager.PositionSubscribe(positionSink):
                logger.error(f"Failed to subscribe to positions: {MT5Manager.LastError()}")
                break  
            if not manager.DealSubscribe(dealsink):
                logger.error(f"Failed to subscribe to deals: {MT5Manager.LastError()}")
                break  

            # logger.info("Successfully connected to the manager.")
                prop_management_thread = threading.Thread(target=continuous_prop_management, daemon=True)
                prop_management_thread.start()
            # Start a watcher thread that triggers a cautious resync when events stop arriving
            def resync_watcher():
                global _last_resync_ts
                while True:
                    try:
                        now_ts = time()
                        age = now_ts - last_activity_ts
                        if age > STALE_THRESHOLD and (now_ts - _last_resync_ts) > RESYNC_COOLDOWN:
                            _last_resync_ts = now_ts
                            try:
                                # perform a cautious reconcile: scan leader groups and re-run copy for open positions and pending orders
                                for i in range(manager.GroupTotal()):
                                    try:
                                        group = manager.GroupNext(i).Group
                                        if "demo" in group:
                                            continue
                                        for leader in manager.UserGetByGroup(group):
                                            # only consider leaders (agents that have followers)
                                            followers = [u.Login for u in manager.UserGetByGroup(group) if u.Agent == leader.Login]
                                            if not followers:
                                                continue
                                            # scan open positions and pending orders for the leader and attempt to copy
                                            try:
                                                for ord in manager.OrderGetOpen(leader.Login):
                                                    # use OrderSink.copy_order_to_followers logic (force retries during resync)
                                                    try:
                                                        orderSink.copy_order_to_followers(ord, force=True)
                                                    except Exception as e:
                                                        logger.debug(f"Resync order copy failed for leader {leader.Login}: {e}")
                                                for pos in manager.PositionGet(leader.Login):
                                                    try:
                                                        # OrderSink provides copy_position_to_followers; call that instead of PositionSink (force retries)
                                                        orderSink.copy_position_to_followers(pos, force=True)
                                                    except Exception as e:
                                                        logger.debug(f"Resync position copy failed for leader {leader.Login}: {e}")
                                            except Exception as e:
                                                logger.debug(f"Resync scan failed for leader {leader.Login}: {e}")
                                    except Exception:
                                        pass
                            except Exception as e:
                                logger.error(f"Error during cautious resync: {e}")
                        # shorter sleep to detect silence faster
                        sleep(0.5)
                    except Exception:
                        sleep(0.5)

            watcher_thread = threading.Thread(target=resync_watcher, daemon=True)
            watcher_thread.start()
            # Keep the main subscription loop alive indefinitely. If the health
            # check fails, wait and retry instead of breaking out which would
            # cause the script to exit and daemon threads to be killed.
            while True:
                try:
                    if not checkingu():
                        # Reduce delay on health check failure
                        sleep(1)
                        continue
                    sleep(0.1)  # Reduced idle delay for faster response
                except Exception:
                    sleep(1)

        except Exception as e:
            # Log and backoff, but do NOT exit. Use exponential backoff to
            # avoid tight failure loops.
            attempt += 1
            backoff = min(300, (2 ** min(attempt, 6)))
            logger.error(f"Error during connection or subscription (attempt {attempt}): {e}. Backing off for {backoff}s")
            sleep(backoff)
            # continue to retry indefinitely
            continue

try:
    run_mam_script()
finally:
    release_process_lock()
    print("🔓 MAM process lock released")