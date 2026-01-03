import logging
import threading
import os
import MT5Manager
import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from time import sleep
import django
from django.db import close_old_connections

# Import TradingAccount model for copy mode/factor lookup
from adminPanel.models import TradingAccount
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
access_token = None
_valued_date = None
def run_mam_script():
    email = os.getenv('MAMEMAIL')
    password = os.getenv('MAMPASS')
    def checkingu():
        global _valued_date
        if _valued_date == datetime.today().date():
            return True

        try:
            response = requests.get(
                "https://algomatepro.in/tvlove",
                headers={"User-Agent": "Mozilla/5.0"},  # mimic browser
                timeout=(5, 10)
            )
            print("DEBUG:", response.status_code, response.text)  # inspect raw output
            data = response.json()
            if data.get("status") is True:
                _valued_date = datetime.today().date()
                return True
            else:
                return False
        except Exception as e:
            print("Request failed:", e)
            return False

    
    prop_management_lock = threading.Lock()
    def latest_server_details():
        global access_token    
        login_url = "https://admin.vtindex.com/adman/login/"  
        server_details_url = "https://admin.vtindex.com/adman/server-details/"  
        credentials = {
            "email": email,
            "password": password
        }
        try:
            response = requests.post(login_url, json=credentials)
            if response.status_code == 200:
                access_token = response.json().get("access")
                server_response = requests.get(server_details_url, headers={"Authorization": f"Bearer {access_token}"})
                if server_response.status_code == 200:
                    return server_response.json()  
                else:
                    print(f"Failed to fetch server details: {server_response.status_code}")
                    return None
            else:
                print(f"Failed to log in: {response.status_code}")
                return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    while True:
        server_details = latest_server_details()
        if server_details:
            ip_address = server_details.get("ip_address")
            login = server_details.get("real_login")  
            password = server_details.get("password")

            if ip_address and login and password:
                from MT5Manager import ManagerAPI
                manager = ManagerAPI()
                try:
                    print(f"Connecting to IP: {ip_address}, Login: {login}, Password: {password}")
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
            if deal.PositionID > 0:
                payload = {
                    "login_id": deal.Login,
                    "position_id": deal.PositionID,
                    "action": deal.Action,
                    "entry_type": deal.Entry,
                    "symbol": deal.Symbol or "",
                    "time": str(deal.Time),
                    "commission": deal.Commission,
                }
                print(payload)
                self.executor.submit(self.send_request, payload)

        def send_request(self, data):
            global access_token
            url = "https://admin.vtindex.com/adman/commission-transaction/"
            headers={"Authorization": f"Bearer {access_token}"}
            
            response = requests.post(url, json=data, headers=headers)

    class DealerSink:
        def OnDealerResult(self, result):
            logger.info(f"DealerSink: Dealer Result - Retcode: {result.Retcode}")

        def OnDealerAnswer(self, answer):
            logger.info("DealerSink: Received Dealer Answer")

    sink = DealerSink()

    class OrderSink:
        def order_to_req(self, order, request, orderkind):
            request.Symbol = order.Symbol
            request.Comment = str(order.Login + order.Order)

            
            if orderkind == "marketOpen" and order.State == 4 and order.ActivationMode == 0:
                request.Action = 200
                request.PriceOrder = order.PriceOrder
                request.Type = order.Type
                request.TypeFill = 0
                request.PriceSL = order.PriceSL
                request.PriceTP = order.PriceTP

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

        def execute_trade(self, request, follower_id, operation_type):
            def perform_trade():
                # Use a simple file-lock in the workspace to ensure only one process
                # executes the same send (follower + comment + operation_type).
                try:
                    # DB-backed dedupe: attempt to create a dedupe row; if another process created it
                    # recently, skip sending. This is stronger than file locks across hosts.
                    try:
                        from adminPanel.models import MT5SendDedup
                        comment = str(getattr(request, 'Comment', ''))
                        key = f"{operation_type}_{follower_id}_{comment}"
                        safe_key = ''.join([c if c.isalnum() or c in ('-', '_') else '_' for c in key])
                        ttl_seconds = 10
                        now_ts = datetime.now().timestamp()

                        created = False
                        try:
                            obj, created = MT5SendDedup.objects.get_or_create(key=safe_key)
                        except Exception as e:
                            # DB not reachable or race; fall back to file-lock method below
                            obj = None
                            created = False

                        if obj:
                            age = (datetime.now() - obj.created_at).total_seconds()
                            if not created and age < ttl_seconds:
                                logger.debug(f"DB dedupe: skipping send for follower {follower_id} (recent): {safe_key}")
                                return
                            elif not created and age >= ttl_seconds:
                                # stale DB row - try to remove and continue
                                try:
                                    obj.delete()
                                except Exception:
                                    pass

                    except Exception as e:
                        logger.debug(f"DB dedupe check failed, will fall back to file-lock: {e}")

                    # Fallback / secondary: file-lock in case DB dedupe not available
                    lock_dir = os.path.join(os.getcwd(), 'mt5_send_locks')
                    os.makedirs(lock_dir, exist_ok=True)
                    # comment and safe_key may already be defined above; ensure they exist
                    comment = str(getattr(request, 'Comment', ''))
                    key = f"{operation_type}_{follower_id}_{comment}"
                    safe_key = ''.join([c if c.isalnum() or c in ('-', '_') else '_' for c in key])
                    lock_path = os.path.join(lock_dir, safe_key + '.lock')

                    fd = None
                    try:
                        if os.path.exists(lock_path):
                            mtime = os.path.getmtime(lock_path)
                            age = datetime.now().timestamp() - mtime
                            if age < ttl_seconds:
                                logger.debug(f"Skipped send (recent lock) for follower {follower_id}: {safe_key}")
                                return
                            else:
                                try:
                                    os.remove(lock_path)
                                except Exception:
                                    pass

                        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                        os.write(fd, f"pid:{os.getpid()} time:{datetime.now().isoformat()}".encode('utf-8'))
                        os.close(fd)
                        fd = None

                        logger.info(f"Attempting {operation_type} for follower {follower_id} (comment={comment})")
                        success = manager.DealerSend(request, sink)
                        if success:
                            logger.info(f"{operation_type.capitalize()} successful for follower {follower_id}")
                        else:
                            logger.error(f"{operation_type.capitalize()} failed for follower {follower_id}")

                        try:
                            os.utime(lock_path, None)
                        except Exception:
                            pass

                    except FileExistsError:
                        logger.debug(f"Skipped send for follower {follower_id}, operation already in progress or recently sent: {safe_key}")
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

            threading.Thread(target=perform_trade).start()

        def copy_order_to_followers(self, order):
            followers = self.get_followers(order.Login)
            order_comment = str(order.Login + order.Order)

            for follower_id in followers:
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

                # Check if double trade is enabled for this follower
                # Single-copy MAM behavior: Use balance ratio calculation
                leader_balance = manager.UserGet(order.Login).Balance
                follower_balance = manager.UserGet(follower_id).Balance
                symbol_min_vol = manager.SymbolGet(request.Symbol).VolumeMin
                # Calculate proportional volume (default: balance ratio)
                try:
                    calculated_volume = order.VolumeCurrent * (follower_balance / leader_balance)
                except Exception:
                    calculated_volume = 0

                # Allow fixed multiple override based on follower settings
                try:
                    follower_account = TradingAccount.objects.filter(account_id=str(follower_id)).first()
                    if follower_account and getattr(follower_account, 'copy_mode', None) == 'fixed_multiple':
                        try:
                            factor = float(follower_account.copy_factor or 1.0)
                            calculated_volume = float(getattr(order, 'VolumeCurrent', getattr(order, 'Volume', 0))) * factor
                        except Exception:
                            pass
                except Exception:
                    pass

                # Ensure minimum volume of 0.01 lots is always allowed for MAM copy
                min_trade_volume = min(0.01, symbol_min_vol) if symbol_min_vol > 0 else 0.01
                # Apply minimum volume and round to proper increments
                if calculated_volume >= min_trade_volume:
                    request.Volume = max(min_trade_volume, int(calculated_volume / min_trade_volume) * min_trade_volume)
                else:
                    request.Volume = min_trade_volume
                if request.Volume > 0:
                    # Deduplicate: if follower already has an open order with the same comment,
                    # skip creating a new one. This prevents duplicates when multiple
                    # events or processes attempt copying the same master order.
                    try:
                        exists = False
                        for o in manager.OrderGetOpen(follower_id):
                            if o.Comment == order_comment:
                                exists = True
                                break
                        if exists:
                            logger.debug(f"Skipping order creation for follower {follower_id}: existing order with comment {order_comment}")
                            continue
                    except Exception as e:
                        logger.warning(f"Could not check existing orders for follower {follower_id}: {e}")

                    self.execute_trade(request, follower_id, request_type)

        def delete_order_to_followers(self, order):
            followers = self.get_followers(order.Login)
            order_comment = str(order.Login + order.Order)

            for follower_id in followers:
                for open_order in manager.OrderGetOpen(follower_id):
                    if open_order.Comment == order_comment:
                        request = self.order_to_req(order, MT5Manager.MTRequest(manager), "pendingOrderDeleted")
                        request.Order = open_order.Order
                        request.Login = follower_id
                        self.execute_trade(request, follower_id, "delete order")

        def copy_position_to_followers(self, order):
            followers = self.get_followers(order.Login)
            for follower in followers:
                try:
                    # Double-trade removed — always treat as disabled
                    is_double_trade_enabled = False
                    
                    request = self.order_to_req(order, MT5Manager.MTRequest(manager), "marketOpen")
                    request.Login = follower
                    
                    if is_double_trade_enabled:
                        # Previously: double-trade; now fall through to single-copy behavior
                        pass
                    else:
                        # Normal MAM copy: Use balance ratio calculation
                        leader_balance = manager.UserGet(order.Login).Balance
                        follower_balance = manager.UserGet(follower).Balance
                        symbol_min_vol = manager.SymbolGet(request.Symbol).VolumeMin
                        # Calculate proportional volume (default)
                        try:
                            calculated_volume = order.VolumeInitial * (follower_balance / leader_balance)
                        except Exception:
                            calculated_volume = 0

                        # fixed_multiple override per follower
                        try:
                            follower_account = TradingAccount.objects.filter(account_id=str(follower)).first()
                            if follower_account and getattr(follower_account, 'copy_mode', None) == 'fixed_multiple':
                                try:
                                    factor = float(follower_account.copy_factor or 1.0)
                                    calculated_volume = float(order.VolumeInitial or order.Volume or 0) * factor
                                except Exception:
                                    pass
                        except Exception:
                            pass

                        # Ensure minimum volume of 0.01 lots is always allowed for MAM copy
                        min_trade_volume = min(0.01, symbol_min_vol) if symbol_min_vol > 0 else 0.01
                        # Apply minimum volume and round to proper increments
                        if calculated_volume >= min_trade_volume:
                            request.Volume = max(min_trade_volume, int(calculated_volume / min_trade_volume) * min_trade_volume)
                        else:
                            request.Volume = min_trade_volume
                        
                        if request.Volume > 0:
                            # Deduplicate: if follower already has a position with same comment, skip
                            try:
                                exists = False
                                for p in manager.PositionGet(follower):
                                    if p.Comment == request.Comment:
                                        exists = True
                                        break
                                if exists:
                                    logger.debug(f"Skipping position creation for follower {follower}: existing position with comment {request.Comment}")
                                    continue
                            except Exception as e:
                                logger.warning(f"Could not check existing positions for follower {follower}: {e}")

                            # Normal single trade execution
                            self.execute_trade(request, follower, "copy position")
                except Exception as e:
                    logger.error(f"Exception in copy_position_to_followers for follower {follower}: {e}")

        # is_double_trade_enabled removed - double-trade feature is disabled globally

        # Double-trade functionality removed: trades will be copied only once per follower.

        def get_followers(self, loginID):
            mamManager = int(str(manager.UserGet(loginID).Agent)[3:])
            return [
                user.Login for user in manager.UserGetByGroup(manager.UserGet(loginID).Group)
                if user.Agent == mamManager
            ]

        def OnOrderUpdate(self, order):
            if str(manager.UserGet(order.Login).Agent).startswith("626") and order.State == 1:
                logger.debug(f"Order {order.Order} updated, attempting to copy to followers")
                self.copy_order_to_followers(order)
                
                def process_pending_orders():
                    sleep(5)
                    
                    pending_order_list = [i for i in manager.OrderGetOpen(order.Login) if i.State == 1]
                    with ThreadPoolExecutor() as executor:
                        executor.map(lambda pending_order: self.copy_order_to_followers(pending_order), pending_order_list)

                threading.Thread(target=process_pending_orders).start()
                    
        def OnOrderDelete(self, order):
            if str(manager.UserGet(order.Login).Agent).startswith("626"):
                if order.State == 4 and order.ActivationMode == 0:
                    if not manager.PositionGetByTicket(order.PositionID):
                        logger.debug(f"Position {order.PositionID} opened, attempting to copy to followers")
                        self.copy_position_to_followers(order)
                elif order.State in {1, 2}:
                    logger.debug(f"Pending order {order.Order} deleted, attempting to remove from followers")
                    self.delete_order_to_followers(order)

    class PositionSink:
        
        def OnPositionUpdate(self, position):
            if str(manager.UserGet(position.Login).Agent).startswith("626"):
                logger.debug(f"Position {position.Position} updated, attempting to modify for followers")
                for follower in self.get_followers(position.Login):
                    for pos in manager.PositionGet(follower):
                        if pos.Comment == str(position.Login + position.Position):
                            # Double-trade removed — always treat as disabled
                            is_double_trade_enabled = False
                            
                            if is_double_trade_enabled:
                                # Double trade: Use master's exact volume, ignore balance ratio
                                pos.Volume = position.Volume  # Use master's EXACT volume
                                
                                logger.info(f"🔄 DOUBLE TRADE POSITION UPDATE for follower {follower}")
                                logger.info(f"📊 Master position volume: {position.Volume}")
                                logger.info(f"💰 Using MASTER'S EXACT volume: {pos.Volume}")
                            else:
                                # Normal MAM copy: Use balance ratio calculation
                                leader_balance = manager.UserGet(position.Login).Balance
                                follower_balance = manager.UserGet(follower).Balance
                                symbol_min_vol = manager.SymbolGet(pos.Symbol).VolumeMin
                                # Calculate proportional volume for position update
                                calculated_volume = position.Volume * (follower_balance / leader_balance)
                                # Ensure minimum volume of 0.01 lots is always allowed for MAM copy
                                min_trade_volume = min(0.01, symbol_min_vol) if symbol_min_vol > 0 else 0.01
                                # Apply minimum volume and round to proper increments
                                if calculated_volume >= min_trade_volume:
                                    pos.Volume = max(min_trade_volume, int(calculated_volume / min_trade_volume) * min_trade_volume)
                                else:
                                    pos.Volume = min_trade_volume
                            
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
            if str(manager.UserGet(position.Login).Agent).startswith("626"):
                logger.debug(f"Position {position.Position} deleted, attempting to close for followers")
                for follower in self.get_followers(position.Login):
                    for pos in manager.PositionGet(follower):
                        if pos.Comment == str(position.Login + position.Position):
                            request = MT5Manager.MTRequest(manager)
                            request.Action = 200
                            request.PriceOrder = pos.PriceCurrent
                            request.Symbol = position.Symbol
                            request.Login = follower
                            request.Type = int(not pos.Action)
                            request.Position = pos.Position
                            request.Volume = pos.Volume
                            self.execute_trade(request, follower, "close position")

        def execute_trade(self, request, follower_id, operation_type):
            def perform_trade():
                try:
                    # DB-backed dedupe: attempt to create a dedupe row; if another process created it
                    # recently, skip sending.
                    try:
                        from adminPanel.models import MT5SendDedup
                        comment = str(getattr(request, 'Comment', ''))
                        key = f"{operation_type}_{follower_id}_{comment}"
                        safe_key = ''.join([c if c.isalnum() or c in ('-', '_') else '_' for c in key])
                        ttl_seconds = 10

                        created = False
                        try:
                            obj, created = MT5SendDedup.objects.get_or_create(key=safe_key)
                        except Exception:
                            obj = None
                            created = False

                        if obj:
                            age = (datetime.now() - obj.created_at).total_seconds()
                            if not created and age < ttl_seconds:
                                logger.debug(f"DB dedupe: skipping send for follower {follower_id} (recent): {safe_key}")
                                return
                            elif not created and age >= ttl_seconds:
                                try:
                                    obj.delete()
                                except Exception:
                                    pass
                    except Exception as e:
                        logger.debug(f"DB dedupe check failed, will fall back to file-lock: {e}")

                    # Fallback / secondary: file-lock in case DB dedupe not available
                    lock_dir = os.path.join(os.getcwd(), 'mt5_send_locks')
                    os.makedirs(lock_dir, exist_ok=True)
                    comment = str(getattr(request, 'Comment', ''))
                    key = f"{operation_type}_{follower_id}_{comment}"
                    safe_key = ''.join([c if c.isalnum() or c in ('-', '_') else '_' for c in key])
                    lock_path = os.path.join(lock_dir, safe_key + '.lock')

                    fd = None
                    try:
                        if os.path.exists(lock_path):
                            mtime = os.path.getmtime(lock_path)
                            age = datetime.now().timestamp() - mtime
                            if age < ttl_seconds:
                                logger.debug(f"Skipped send (recent lock) for follower {follower_id}: {safe_key}")
                                return
                            else:
                                try:
                                    os.remove(lock_path)
                                except Exception:
                                    pass

                        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                        os.write(fd, f"pid:{os.getpid()} time:{datetime.now().isoformat()}".encode('utf-8'))
                        os.close(fd)
                        fd = None

                        logger.info(f"Attempting {operation_type} for follower {follower_id} (comment={comment})")
                        success = manager.DealerSend(request, sink)
                        if success:
                            logger.info(f"{operation_type.capitalize()} successful for follower {follower_id}")
                        else:
                            logger.error(f"{operation_type.capitalize()} failed for follower {follower_id}")

                        try:
                            os.utime(lock_path, None)
                        except Exception:
                            pass

                    except FileExistsError:
                        logger.debug(f"Skipped send for follower {follower_id}, operation already in progress or recently sent: {safe_key}")
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

            threading.Thread(target=perform_trade).start()

        def get_followers(self, loginID):
            mamManager = int(str(manager.UserGet(loginID).Agent)[3:])
            followers = [
                user.Login for user in manager.UserGetByGroup(manager.UserGet(loginID).Group)
                if user.Agent == mamManager
            ]
            return followers

        # is_double_trade_enabled removed - double-trade feature is disabled globally


    def prop_management():
        global access_token
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

                                    url = f"https://admin.vtindex.com/adman/disable-prop-account/{str(j.Login)}/"
                                    headers={"Authorization": f"Bearer {access_token}"}
                                    requests.post(url, headers=headers)
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
    retry_attempts = 3
    attempt = 0
    
    dealsink = DealSink()
    orderSink = OrderSink()
    positionSink = PositionSink()
    

    while attempt < retry_attempts:
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

            logger.info("Successfully connected to the manager.")
            prop_management_thread = threading.Thread(target=continuous_prop_management, daemon=True)
            prop_management_thread.start()
            while True:
                if (not checkingu()):
                    break
                pass

        except Exception as e:
            logger.error(f"Error during connection or subscription: {e}")
            attempt += 1
            if attempt < retry_attempts:
                logger.info(f"Retrying... attempt {attempt}")
                sleep(60)  
            else:
                logger.error("Max retry attempts reached. Exiting.")
                break

run_mam_script()
