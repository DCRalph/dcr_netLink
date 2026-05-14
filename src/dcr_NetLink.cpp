#include "dcr_NetLink.h"

#include <dcr_Files.h>
#include <dcr_IFileStorage.h>
#include <dcr_FatalHandler.h>
#include <dcr_TaskManager.h>
#include <dcr_taskManager/FreeRtosRaii.h>
#include <dcr_taskManager/MutexRegistry.h>
#include <dcr_Logger.h>
#include "esp_netif.h"
#include "esp_wifi.h"
#include <ArduinoJson.h>
#include <algorithm>
#include <atomic>

#undef LOG_TAG
#define LOG_TAG "WIFI"

extern bool wifiConnectedAtSomePoint;

namespace
{
  FreeRtosRaii::Mutex &wifiLoopMutex()
  {
    static FreeRtosRaii::Mutex m;
    return m;
  }
}

// =============================================================================
// File-scope helpers
// =============================================================================
namespace
{
  constexpr uint8_t WIFI_BSSID_ATTEMPTS_PER_AP = 2;
  constexpr uint32_t WIFI_DISCONNECT_EVENT_GRACE_MS = 750;
  constexpr uint32_t WIFI_SCAN_TASK_STACK_SIZE = 6144;
  constexpr UBaseType_t WIFI_SCAN_TASK_PRIORITY = 1;
  constexpr BaseType_t WIFI_SCAN_TASK_CORE = tskNO_AFFINITY;
  constexpr uint32_t WIFI_SCAN_RETRY_MS = 1000;
  constexpr uint32_t WIFI_CONNECT_RETRY_MS = 1000;

  // DNS handling runs once per association. GOT_IP can fire again on DHCP
  // renew without an intervening STA_DISCONNECTED, so this flag is cleared on
  // every connect, disconnect, and lost-IP event.
  bool s_dnsOverrideApplied = false;

  // Monotonic counter of STA_DISCONNECTED events. Used to detect "association
  // dropped during a connect attempt" without polling status. Atomic so the
  // HTTP connection pool (HTTP::ConnectionPool) can read it from other tasks
  // to detect a stale cached socket fd after a WiFi blip.
  std::atomic<uint32_t> s_disconnectEventSeq{0};

  String formatBssid(const uint8_t *bssid)
  {
    if (!bssid)
      return "";
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return String(buf);
  }

  bool hasUsableDns(const IPAddress &dns)
  {
    return dns != IPAddress(0, 0, 0, 0);
  }

  bool applyFallbackDns()
  {
    esp_netif_t *staNetif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!staNetif)
    {
      debugW("Public DNS fallback failed; WIFI_STA_DEF netif unavailable");
      return false;
    }

    esp_netif_dns_info_t dns = {};
    dns.ip.type = ESP_IPADDR_TYPE_V4;

    dns.ip.u_addr.ip4.addr = static_cast<uint32_t>(IPAddress(1, 0, 0, 1));
    const esp_err_t mainErr = esp_netif_set_dns_info(staNetif, ESP_NETIF_DNS_MAIN, &dns);
    if (mainErr != ESP_OK)
    {
      debugW("Public DNS fallback failed; main DNS set error: %s", esp_err_to_name(mainErr));
      return false;
    }

    dns.ip.u_addr.ip4.addr = static_cast<uint32_t>(IPAddress(8, 8, 4, 4));
    const esp_err_t backupErr = esp_netif_set_dns_info(staNetif, ESP_NETIF_DNS_BACKUP, &dns);
    if (backupErr != ESP_OK)
    {
      debugW("Public DNS fallback failed; backup DNS set error: %s", esp_err_to_name(backupErr));
      return false;
    }

    return true;
  }

  const char *wifiDisconnectReasonToString(uint8_t reason)
  {
    switch (reason)
    {
    case WIFI_REASON_UNSPECIFIED:
      return "UNSPECIFIED";
    case WIFI_REASON_AUTH_EXPIRE:
      return "AUTH_EXPIRE";
    case WIFI_REASON_AUTH_LEAVE:
      return "AUTH_LEAVE";
    case WIFI_REASON_ASSOC_EXPIRE:
      return "ASSOC_EXPIRE";
    case WIFI_REASON_ASSOC_TOOMANY:
      return "ASSOC_TOOMANY";
    case WIFI_REASON_NOT_AUTHED:
      return "NOT_AUTHED";
    case WIFI_REASON_NOT_ASSOCED:
      return "NOT_ASSOCED";
    case WIFI_REASON_ASSOC_LEAVE:
      return "ASSOC_LEAVE";
    case WIFI_REASON_ASSOC_NOT_AUTHED:
      return "ASSOC_NOT_AUTHED";
    case WIFI_REASON_DISASSOC_PWRCAP_BAD:
      return "DISASSOC_PWRCAP_BAD";
    case WIFI_REASON_DISASSOC_SUPCHAN_BAD:
      return "DISASSOC_SUPCHAN_BAD";
    case WIFI_REASON_BSS_TRANSITION_DISASSOC:
      return "BSS_TRANSITION_DISASSOC";
    case WIFI_REASON_IE_INVALID:
      return "IE_INVALID";
    case WIFI_REASON_MIC_FAILURE:
      return "MIC_FAILURE";
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
      return "4WAY_HANDSHAKE_TIMEOUT";
    case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT:
      return "GROUP_KEY_UPDATE_TIMEOUT";
    case WIFI_REASON_IE_IN_4WAY_DIFFERS:
      return "IE_IN_4WAY_DIFFERS";
    case WIFI_REASON_GROUP_CIPHER_INVALID:
      return "GROUP_CIPHER_INVALID";
    case WIFI_REASON_PAIRWISE_CIPHER_INVALID:
      return "PAIRWISE_CIPHER_INVALID";
    case WIFI_REASON_AKMP_INVALID:
      return "AKMP_INVALID";
    case WIFI_REASON_UNSUPP_RSN_IE_VERSION:
      return "UNSUPP_RSN_IE_VERSION";
    case WIFI_REASON_INVALID_RSN_IE_CAP:
      return "INVALID_RSN_IE_CAP";
    case WIFI_REASON_802_1X_AUTH_FAILED:
      return "802_1X_AUTH_FAILED";
    case WIFI_REASON_CIPHER_SUITE_REJECTED:
      return "CIPHER_SUITE_REJECTED";
    case WIFI_REASON_BEACON_TIMEOUT:
      return "BEACON_TIMEOUT";
    case WIFI_REASON_NO_AP_FOUND:
      return "NO_AP_FOUND";
    case WIFI_REASON_AUTH_FAIL:
      return "AUTH_FAIL";
    case WIFI_REASON_ASSOC_FAIL:
      return "ASSOC_FAIL";
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
      return "HANDSHAKE_TIMEOUT";
    case WIFI_REASON_CONNECTION_FAIL:
      return "CONNECTION_FAIL";
    case WIFI_REASON_AP_TSF_RESET:
      return "AP_TSF_RESET";
    case WIFI_REASON_ROAMING:
      return "ROAMING";
    default:
      return "UNKNOWN";
    }
  }

  String stateToString(WiFiState s)
  {
    switch (s)
    {
    case WiFiState::WiFiOff:
      return "WiFi Off";
    case WiFiState::WiFiConnecting:
      return "WiFi Connecting";
    case WiFiState::WiFiConnected:
      return "WiFi Connected";
    case WiFiState::WiFiDisconnected:
      return "WiFi Disconnected";
    case WiFiState::WiFiError:
      return "WiFi Error";
    }
    return "Unknown";
  }

  void registerWiFiEventsOnce()
  {
    static bool registered = false;
    if (registered)
      return;

    WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info)
                 {
            switch (event)
            {
            case ARDUINO_EVENT_WIFI_STA_CONNECTED:
                s_dnsOverrideApplied = false;
                debugI("Connected to %s | channel %d | BSSID %s",
                       reinterpret_cast<const char *>(info.wifi_sta_connected.ssid),
                       info.wifi_sta_connected.channel,
                       formatBssid(info.wifi_sta_connected.bssid).c_str());
                break;

            case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
                s_dnsOverrideApplied = false;
                s_disconnectEventSeq.fetch_add(1, std::memory_order_relaxed);
                debugW("Disconnected | reason %d (%s) | BSSID %s | last RSSI %d",
                       info.wifi_sta_disconnected.reason,
                       wifiDisconnectReasonToString(info.wifi_sta_disconnected.reason),
                       formatBssid(info.wifi_sta_disconnected.bssid).c_str(),
                       WiFi.RSSI());
                break;

            case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            {
                IPAddress dns1 = WiFi.dnsIP(0);
                IPAddress dns2 = WiFi.dnsIP(1);
                debugI("GOT_IP | IP %s | GW %s | DNS(dhcp) %s, %s",
                       WiFi.localIP().toString().c_str(),
                       WiFi.gatewayIP().toString().c_str(),
                       dns1.toString().c_str(),
                       dns2.toString().c_str());

                if (s_dnsOverrideApplied) break;

                if (hasUsableDns(dns1) || hasUsableDns(dns2))
                {
                    debugI("DHCP DNS present; keeping provider DNS");
                    s_dnsOverrideApplied = true;
                    break;
                }

                const bool ok = applyFallbackDns();
                if (ok)
                  debugI("DHCP DNS missing; applied public fallback DNS (1.0.0.1, 8.8.4.4)");
                else
                  debugW("Public DNS fallback failed; leaving DNS unchanged");
                s_dnsOverrideApplied = true;
                break;
            }

            case ARDUINO_EVENT_WIFI_STA_LOST_IP:
                s_dnsOverrideApplied = false;
                debugW("LOST_IP | DHCP renewal failed");
                break;

            default:
                break;
            } });
    registered = true;
  }

  // Configure STA mode and disable flash persistence. Idempotent.
  void configureStationMode()
  {
    WiFi.persistent(false);
    WiFi.mode(WIFI_STA);

    const esp_err_t err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK)
    {
      debugE("esp_wifi_set_storage(WIFI_STORAGE_RAM) failed: %s", esp_err_to_name(err));
    }

    registerWiFiEventsOnce();
  }
} // namespace

uint32_t NetLink::globalDisconnectEventSeq()
{
  return s_disconnectEventSeq.load(std::memory_order_relaxed);
}

uint32_t NetLink::disconnectEventSeq() const
{
  return s_disconnectEventSeq.load(std::memory_order_relaxed);
}

bool NetLink::isConnected() const
{
  return WiFi.isConnected();
}

int NetLink::rssi() const
{
  return WiFi.RSSI();
}

// =============================================================================
// Construction & lifecycle
// =============================================================================

NetLink::NetLink()
{
  wifiLoopMutex().ensureCreated();
}

void NetLink::setCallbacks(const NetLinkCallbacks &callbacks)
{
  std::lock_guard<FreeRtosRaii::Mutex> lock(wifiLoopMutex());
  _cb = callbacks;
}

void NetLink::setFactoryCredentials(const char *ssid, const char *password)
{
  _factorySsid = ssid ? String(ssid) : String();
  _factoryPassword = password ? String(password) : String();
}

bool NetLink::_isFactoryNetworkSsid(const String &ssid) const
{
  return !_factorySsid.isEmpty() && ssid == _factorySsid;
}

void NetLink::init()
{
  debugI("NetLink: Initialising...");
  RtosUtils::registerMutex(wifiLoopMutex(), "wifiLoop");
  _migrateLegacyCredentialsIfNeeded();
  configureStationMode();
  WiFi.setSleep(_cb.isBleActive && _cb.isBleActive());

  if (_cb.isCellularPreferred && _cb.isCellularPreferred())
  {
    _doOff();
    debugI("Cellular is preferred transport. Skipping WiFi auto-connect at boot.");
    return;
  }

  _state = WiFiState::WiFiDisconnected;
  _usingFactoryCreds = false;
  _bootAutoConnectPending = true;
  _bootAutoConnectAt = millis() + WIFI_BOOT_CONNECT_DELAY_MS;
  debugD("Delaying boot auto-connect by 10 seconds.");
}

void NetLink::loop()
{
  bool playConnectedBuzzer = false;

  auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(5000));
  if (!lock)
  {
    debugE("loop: mutex timeout");
    return;
  }

  // 1. Process pending commands.
  if (_pending & PendingTurnOn)
  {
    _doOn();
    if (_cb.onClosePopup) _cb.onClosePopup("wifi_turn_on");
  }
  if (_pending & PendingTurnOff)
  {
    _doOff();
    if (_cb.onClosePopup) _cb.onClosePopup("wifi_turn_off");
  }
  if (_pending & PendingDisconnect)
  {
    _doDisconnect();
    if (_cb.onClosePopup) _cb.onClosePopup("wifi_disconnect");
  }
  if ((_pending & PendingConnect) && !_scanInProgress)
  {
    _doConnect();
    if (_cb.onClosePopup) _cb.onClosePopup("wifi_connect");
    _pending &= ~PendingConnect;
  }
  _pending &= ~(PendingTurnOn | PendingTurnOff | PendingDisconnect);

  // 2. Boot delay and connection state machine.
  if (!_scanInProgress)
  {
    _serviceBootAutoConnect();
    _serviceConnectionAttempt();
  }

  // 3. Refresh derived state, run timers.
  _refreshConnectionState();
  _checkTimeouts();

  if (!wifiConnectedAtSomePoint && WiFi.isConnected())
  {
    wifiConnectedAtSomePoint = true;
  }

  // 4. Detect changes for logging and connected callbacks.
  WiFiDetails current = _buildStatus();
  const bool changed = (current.state != _cachedDetails.state ||
                        current.ssid != _cachedDetails.ssid ||
                        current.ip != _cachedDetails.ip);

  if (changed)
  {
    debugI("WiFi details updated:");
    debugI("         State: %s", stateToString(current.state).c_str());
    if (current.state == WiFiState::WiFiConnected)
    {
      debugI("         SSID: %s", current.ssid.c_str());
      debugI("         IP  : %s", current.ip.toString().c_str());
      debugI("         RSSI: %d", current.rssi);
      debugI("         Time Connected (ms): %d", current.timeConnected);
    }
    else if (!current.offMessage.isEmpty())
    {
      debugI("         %s", current.offMessage.c_str());
    }
  }

  if (current.state == WiFiState::WiFiConnected &&
      _cachedDetails.state != WiFiState::WiFiConnected)
  {
    playConnectedBuzzer = true;
  }

  // 5. Recovery: cycle the radio after prolonged disconnection.
  if (!_scanInProgress)
    _serviceDisconnectRecovery();
  _cachedDetails = current;

  if (playConnectedBuzzer)
  {
    if (_cb.onBuzz) _cb.onBuzz();
  }
}

// =============================================================================
// Public commands
// =============================================================================

void NetLink::on()
{
  _pending |= PendingTurnOn;
  if (_cb.onShowPopup)
    _cb.onShowPopup("wifi_turn_on", "WiFi Turn On", "Please Wait...");
}

void NetLink::off()
{
  _pending |= PendingTurnOff;
  if (_cb.onShowPopup)
    _cb.onShowPopup("wifi_turn_off", "WiFi Turn Off", "Please Wait...");
}

void NetLink::connect()
{
  _pending |= PendingConnect;
  if (_cb.onShowPopup)
    _cb.onShowPopup("wifi_connect", "WiFi Connect", "Please Wait...");
  debugI("WiFi connection requested");
}

void NetLink::disconnect()
{
  _pending |= PendingDisconnect;
  if (_cb.onShowPopup)
    _cb.onShowPopup("wifi_disconnect", "WiFi Disconnect", "Please Wait...");
  debugI("WiFi disconnect requested");
}

void NetLink::requestSilentReconnect()
{
  _pending |= (PendingDisconnect | PendingConnect);
  debugI("WiFi silent reconnect requested");
}

void NetLink::resetConfig()
{
  Files::deleteFile(WIFI_NETWORKS_FILE);
  if (auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(3000)))
  {
    _resetScheduler();
  }
  debugI("WiFi configuration reset.");
  off();
}

void NetLink::prepareForExternalTransport()
{
  // Take the mutex defensively; if it isn't available the caller is racing
  // against loop(). The timeout path is last-resort only and may still overlap
  // an in-flight ESP-IDF WiFi call.
  if (auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(3000)))
  {
    _turnOnAfterMs = 0;
    _disconnectionStartTime = 0;
    _pending = PendingNone;
    _doOff();
    return;
  }

  debugE("prepareForExternalTransport: mutex timeout; forcing radio off.");
  _pending = PendingNone;
  vTaskDelay(pdMS_TO_TICKS(50));
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  _state = WiFiState::WiFiOff;
}

WiFiDetails NetLink::getStatus()
{
  if (auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(50)))
  {
    WiFiDetails d = _buildStatus();
    return d;
  }
  // Fallback: return last known cached details rather than reading torn state.
  return _cachedDetails;
}

void NetLink::beginScan()
{
  auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(6000));
  if (!lock)
  {
    debugE("beginScan: mutex timeout");
    return;
  }

  _scanInProgress = true;
  _pending = PendingNone;
  _bootAutoConnectPending = false;
  _bootAutoConnectAt = 0;
  _resetScheduler();
  _connectInProgress = false;
  if (_cb.onClosePopup) _cb.onClosePopup("wifi_turn_on");

  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(100);
  configureStationMode();
  WiFi.setSleep(_cb.isBleActive && _cb.isBleActive());
  _state = WiFiState::WiFiDisconnected;
  _disconnectionStartTime = 0;
}

void NetLink::endScan()
{
  auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(6000));
  if (!lock)
  {
    debugE("endScan: mutex timeout");
    return;
  }
  if (_scanInProgress)
  {
    _scanInProgress = false;
    _pending |= PendingConnect;
  }
}

// =============================================================================
// Internal transitions (mutex must be held)
// =============================================================================

void NetLink::_doOn()
{
  WiFi.enableSTA(true);
  configureStationMode();
  WiFi.setSleep(_cb.isBleActive && _cb.isBleActive());
  _bootAutoConnectPending = false;
  _bootAutoConnectAt = 0;
  _doConnect();
}

void NetLink::_doOff()
{
  _bootAutoConnectPending = false;
  _bootAutoConnectAt = 0;
  _resetScheduler();
  _connectInProgress = false;
  _retryConnectAt = 0;
  WiFi.disconnect(false, false);
  WiFi.mode(WIFI_OFF);
  _state = WiFiState::WiFiOff;
  debugI("WiFi turned off");
}

void NetLink::_doConnect()
{
  _bootAutoConnectPending = false;
  _bootAutoConnectAt = 0;
  _resetScheduler();
  _attemptStartMs = 0;
  _retryConnectAt = 0;
  _state = WiFiState::WiFiConnecting;
  _connectInProgress = true;
  configureStationMode();
  WiFi.setSleep(_cb.isBleActive && _cb.isBleActive());

  std::vector<SavedWiFiNetwork> networks;
  _loadSavedNetworks(networks, true);
  if (networks.empty())
  {
    debugI("No WiFi credentials available for the scheduler.");
    _state = WiFiState::WiFiDisconnected;
    _connectInProgress = false;
    return;
  }

  debugI("Starting WiFi scheduler with %d candidate SSIDs.", networks.size());
  _startScan();
}

void NetLink::_doDisconnect()
{
  _bootAutoConnectPending = false;
  _bootAutoConnectAt = 0;
  _resetScheduler();
  _connectInProgress = false;
  _retryConnectAt = 0;
  WiFi.disconnect(false, false);
  _state = WiFiState::WiFiDisconnected;
  _disconnectionStartTime = millis();
  _usingFactoryCreds = false;
  debugI("WiFi disconnected");
}

// =============================================================================
// Connection scheduler (mutex must be held)
// =============================================================================
//
// Stages:
//   1. _startScan() notifies a dedicated scan worker task which calls
//      WiFi.scanNetworks() and publishes the result.
//   2. _serviceScanIfReady() reads the result and builds an AttemptPlan:
//      for each saved SSID, the list of matching BSSIDs found in the scan,
//      sorted by remembered-good first then RSSI.
//   3. _startNextAttempt() picks the next BSSID and calls WiFi.begin().
//      Each BSSID is tried up to WIFI_BSSID_ATTEMPTS_PER_AP times.
//   4. _failCurrentAttempt() advances on failure (timeout, WL_CONNECT_FAILED,
//      WL_NO_SSID_AVAIL, or a STA_DISCONNECTED event during association).
//   5. When all candidates and SSIDs are exhausted, _doConnect() restarts the
//      full scheduler loop.
//

void NetLink::_resetScheduler()
{
  const bool scanWasPending = _scanPending;
  _plan.clear();
  _planIdx = 0;
  _candidateIdx = 0;
  _scanPending = false;
  _scanResultReady = false;
  _scanResult = WIFI_SCAN_FAILED;
  ++_scanRequestId; // Invalidate any in-flight worker result.
  _attemptDisconnectBaselineSeq = s_disconnectEventSeq.load(std::memory_order_relaxed);
  _attemptStartMs = 0;
  if (!scanWasPending)
  {
    WiFi.scanDelete();
  }
}

bool NetLink::_ensureScanTaskStarted()
{
  if (_scanTask != nullptr)
    return true;

  const bool created = taskManager.createTaskPinnedToCore(
      _scanTaskEntry,
      "wifi_saved_scan",
      WIFI_SCAN_TASK_STACK_SIZE,
      this,
      WIFI_SCAN_TASK_PRIORITY,
      &_scanTask,
      WIFI_SCAN_TASK_CORE);
  if (!created)
  {
    _scanTask = nullptr;
    return false;
  }
  return true;
}

void NetLink::_scanTaskEntry(void *param)
{
  NetLink *self = static_cast<NetLink *>(param);
  FatalHandler::runGuardedTask("wifi_saved_scan", [self]()
                               {
    while (true)
    {
      taskManager.noteHeartbeat();

      uint32_t requestId = 0;
      if (xTaskNotifyWait(0, 0xFFFFFFFFu, &requestId, portMAX_DELAY) != pdTRUE)
        continue;

      taskManager.noteHeartbeat();
      const int8_t result = WiFi.scanNetworks();

      if (result == 0)
      {
        debugI("No networks found");
      }
      else if (result > 0)
      {
        debugD("Found %d networks:", result);
        debugD("%s", "");
        debugD("%s", "SSID                             | MAC Address       | RSSI");
        debugD("%s", "---------------------------------|-------------------|------");

        for (int i = 0; i < result; i++)
        {
          String ssid = WiFi.SSID(i);
          String bssid = WiFi.BSSIDstr(i);
          int32_t rssi = WiFi.RSSI(i);

          if (ssid.length() > 32)
            ssid = ssid.substring(0, 29) + "...";

          while (ssid.length() < 32)
            ssid += " ";

          debugD("%s", String(ssid + " | " + bssid + " | " + String(rssi) + " dBm").c_str());
        }
      }
      else
      {
        debugW("WiFi scan failed with result %d", result);
      }

      const bool currentRequest = (requestId == self->_scanRequestId);
      auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(2000));
      if (lock)
      {
        if (currentRequest)
        {
          self->_scanResult = result;
          self->_scanCompletedRequestId = requestId;
          self->_scanResultReady = true;
        }
        else
        {
          debugD("Ignoring stale WiFi scan result for request %lu (current %lu)",
                 static_cast<unsigned long>(requestId),
                 static_cast<unsigned long>(self->_scanRequestId));
        }
      }
      else if (currentRequest)
      {
        self->_scanResult = result;
        self->_scanCompletedRequestId = requestId;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        self->_scanResultReady = true;
      }
    } });
}

void NetLink::_scheduleConnectRetry(const char *reason, uint32_t delayMs)
{
  _connectInProgress = false;
  _scanPending = false;
  _scanResultReady = false;
  _attemptStartMs = 0;
  _retryConnectAt = millis() + delayMs;
  WiFi.disconnect(false, false);
  debugW("%s Retrying WiFi connect loop in %lu ms.", reason,
         static_cast<unsigned long>(delayMs));
}

void NetLink::_startScan()
{
  _resetScheduler();
  debugI("Starting saved-network scan task.");

  if (!_ensureScanTaskStarted())
  {
    _scheduleConnectRetry("Failed to start scan task.", WIFI_SCAN_RETRY_MS);
    return;
  }

  _scanPending = true;
  _scanResultReady = false;
  _scanResult = WIFI_SCAN_FAILED;
  const uint32_t requestId = ++_scanRequestId;
  if (xTaskNotify(_scanTask, requestId, eSetValueWithOverwrite) != pdPASS)
  {
    _scheduleConnectRetry("Failed to notify scan task.", WIFI_SCAN_RETRY_MS);
  }
}

void NetLink::_serviceScanIfReady()
{
  if (!_scanPending || !_scanResultReady)
    return;

  _scanPending = false;
  _scanResultReady = false;
  const int8_t result = _scanResult;

  if (result < 0)
  {
    _scheduleConnectRetry("Saved-network scan failed.", WIFI_SCAN_RETRY_MS);
    return;
  }

  debugI("Saved-network scan completed with %d result(s).", result);

  if (!_buildPlanFromScan(result))
  {
    _scheduleConnectRetry("WiFi scan produced no usable attempts.", WIFI_CONNECT_RETRY_MS);
    return;
  }

  _startNextAttempt();
}

bool NetLink::_buildPlanFromScan(int8_t scanResult)
{
  std::vector<SavedWiFiNetwork> networks;
  if (!_loadSavedNetworks(networks) || networks.empty() || scanResult < 0)
  {
    WiFi.scanDelete();
    return false;
  }

  _plan.clear();
  _planIdx = 0;
  _candidateIdx = 0;

  bool anyCandidates = false;
  for (const SavedWiFiNetwork &net : networks)
  {
    AttemptPlan plan;
    plan.ssid = net.ssid;
    plan.password = net.password;
    plan.preferredBssid = net.lastSuccessfulBssid;

    for (int8_t i = 0; i < scanResult; ++i)
    {
      String ssidScan;
      int32_t rssiScan = 0;
      uint8_t secScan = 0;
      uint8_t *bssidScan = nullptr;
      int32_t channelScan = 0;
      WiFi.getNetworkInfo(i, ssidScan, secScan, rssiScan, bssidScan, channelScan);

      if (!bssidScan)
        continue;
      if (ssidScan != net.ssid)
        continue;
      if (secScan != WIFI_AUTH_OPEN && net.password.isEmpty())
        continue;

      bool dup = false;
      for (const auto &c : plan.candidates)
      {
        if (memcmp(c.bssid, bssidScan, 6) == 0)
        {
          dup = true;
          break;
        }
      }
      if (dup)
        continue;

      BssidCandidate cand;
      memcpy(cand.bssid, bssidScan, 6);
      cand.channel = channelScan;
      cand.rssi = rssiScan;
      plan.candidates.push_back(cand);
    }

    std::stable_sort(plan.candidates.begin(), plan.candidates.end(),
                     [&plan](const BssidCandidate &a, const BssidCandidate &b)
                     {
                       const bool aPref = !plan.preferredBssid.isEmpty() &&
                                          formatBssid(a.bssid).equalsIgnoreCase(plan.preferredBssid);
                       const bool bPref = !plan.preferredBssid.isEmpty() &&
                                          formatBssid(b.bssid).equalsIgnoreCase(plan.preferredBssid);
                       if (aPref != bPref)
                         return aPref;
                       return a.rssi > b.rssi;
                     });

    if (!plan.candidates.empty())
    {
      anyCandidates = true;
      debugI("Built BSSID queue for %s with %d candidate(s).", plan.ssid.c_str(), plan.candidates.size());
    }
    else
    {
      debugI("Scan produced no usable BSSIDs for SSID %s.", plan.ssid.c_str());
      continue;
    }

    _plan.push_back(plan);
  }

  WiFi.scanDelete();
  return anyCandidates;
}

bool NetLink::_startNextAttempt()
{
  while (_planIdx < _plan.size())
  {
    AttemptPlan &p = _plan[_planIdx];
    while (_candidateIdx < p.candidates.size())
    {
      BssidCandidate &c = p.candidates[_candidateIdx];
      if (c.attempts >= WIFI_BSSID_ATTEMPTS_PER_AP)
      {
        ++_candidateIdx;
        continue;
      }

      ++c.attempts;
      _attemptStartMs = millis();
      _attemptDisconnectBaselineSeq = s_disconnectEventSeq.load(std::memory_order_relaxed);

      debugI("Attempting SSID %s via BSSID %s on channel %d (%d/%d, RSSI %d)", p.ssid.c_str(), formatBssid(c.bssid).c_str(), c.channel, c.attempts, WIFI_BSSID_ATTEMPTS_PER_AP, c.rssi);

      const char *pw = p.password.isEmpty() ? nullptr : p.password.c_str();
      WiFi.disconnect(false, false);
      WiFi.begin(p.ssid.c_str(), pw, c.channel, c.bssid);
      return true;
    }

    debugI("Exhausted BSSID queue for SSID %s.", p.ssid.c_str());
    ++_planIdx;
    _candidateIdx = 0;
  }

  _connectInProgress = false;
  _scanPending = false;
  debugI("Exhausted all WiFi candidates.");
  _scheduleConnectRetry("All WiFi candidates exhausted.", WIFI_CONNECT_RETRY_MS);
  return false;
}

bool NetLink::_failCurrentAttempt(const char *reason)
{
  if (!_connectInProgress)
    return false;
  if (_planIdx >= _plan.size())
    return _startNextAttempt();

  AttemptPlan &p = _plan[_planIdx];
  if (_candidateIdx >= p.candidates.size())
    return _startNextAttempt();

  BssidCandidate &c = p.candidates[_candidateIdx];
  debugI("Failed SSID %s via BSSID %s attempt %d/%d: %s", p.ssid.c_str(), formatBssid(c.bssid).c_str(), c.attempts, WIFI_BSSID_ATTEMPTS_PER_AP, reason);

  if (c.attempts >= WIFI_BSSID_ATTEMPTS_PER_AP)
    ++_candidateIdx;
  return _startNextAttempt();
}

void NetLink::_serviceConnectionAttempt()
{
  if (_state != WiFiState::WiFiConnecting)
    return;

  const unsigned long now = millis();
  if (!_connectInProgress)
  {
    if (_retryConnectAt != 0 && now >= _retryConnectAt)
    {
      _retryConnectAt = 0;
      _doConnect();
    }
    return;
  }

  if (_scanPending)
  {
    _serviceScanIfReady();
    return;
  }

  if (_plan.empty())
  {
    if (_retryConnectAt != 0 && now < _retryConnectAt)
      return;

    // Defensive: if we ended up here without a plan or pending scan,
    // restart the scan.
    _startScan();
    return;
  }

  const wl_status_t status = WiFi.status();
  if (status == WL_CONNECT_FAILED)
  {
    _failCurrentAttempt("WiFi driver reported WL_CONNECT_FAILED");
    return;
  }
  if (status == WL_NO_SSID_AVAIL)
  {
    _failCurrentAttempt("WiFi driver reported WL_NO_SSID_AVAIL");
    return;
  }

  if (_attemptStartMs > 0 &&
      s_disconnectEventSeq.load(std::memory_order_relaxed) > _attemptDisconnectBaselineSeq &&
      now - _attemptStartMs >= WIFI_DISCONNECT_EVENT_GRACE_MS)
  {
    _attemptDisconnectBaselineSeq = s_disconnectEventSeq.load(std::memory_order_relaxed);
    _failCurrentAttempt("Disconnected during association");
  }
}

// =============================================================================
// Status, timeouts, recovery (mutex must be held)
// =============================================================================

void NetLink::_refreshConnectionState()
{
  if (WiFi.status() == WL_CONNECTED)
  {
    if (_state != WiFiState::WiFiConnected)
    {
      const bool wasFactory = _isFactoryNetworkSsid(WiFi.SSID());
      _state = WiFiState::WiFiConnected;
      _timeConnectedMs = millis();
      _disconnectionStartTime = 0;
      _usingFactoryCreds = wasFactory;
      _connectInProgress = false;
      _plan.clear();
      _planIdx = 0;
      _candidateIdx = 0;
      _scanPending = false;

      debugI(wasFactory
                 ? "Successfully connected to factory network"
                 : "Connected to WiFi network");
      debugI("IP Address: %s", WiFi.localIP().toString().c_str());

      _touchLastConnected();
    }
  }
  else if (_state == WiFiState::WiFiConnected)
  {
    _state = WiFiState::WiFiDisconnected;
    _disconnectionStartTime = millis();
    _usingFactoryCreds = false;
  }
}

void NetLink::_checkTimeouts()
{
  const unsigned long now = millis();

  if (_state == WiFiState::WiFiConnecting)
  {
    const bool attemptTimedOut = _connectInProgress && _attemptStartMs > 0 &&
                                 (now - _attemptStartMs >= CONNECT_TIMEOUT);
    if (attemptTimedOut)
    {
      _failCurrentAttempt("Connection attempt timed out");
    }
  }

  if (_state == WiFiState::WiFiDisconnected ||
      _state == WiFiState::WiFiConnecting ||
      _state == WiFiState::WiFiError)
  {
    if (_disconnectionStartTime == 0)
    {
      _disconnectionStartTime = now;
      debugI("Started tracking disconnection at %d", now);
    }
  }
  else if (_state == WiFiState::WiFiConnected || _state == WiFiState::WiFiOff)
  {
    _disconnectionStartTime = 0;
  }
}

void NetLink::_serviceDisconnectRecovery()
{
  const unsigned long now = millis();
  const bool disconnectedTooLong =
      _state == WiFiState::WiFiDisconnected &&
      _disconnectionStartTime > 0 &&
      now - _disconnectionStartTime > WIFI_DISCONNECT_RECOVERY_GRACE_MS;
  const bool connectingTooLong =
      _state == WiFiState::WiFiConnecting &&
      _connectInProgress &&
      _disconnectionStartTime > 0 &&
      now - _disconnectionStartTime > WIFI_CONNECTING_RECOVERY_GRACE_MS;

  if (disconnectedTooLong || connectingTooLong)
  {
    _turnOnAfterMs = now + WIFI_RECONNECT_POWER_CYCLE_DELAY_MS;
    _doOff();
    if (connectingTooLong)
      debugI("WiFi connecting state stuck too long. Cycling radio.");
    else
      debugI("WiFi disconnected for too long. Cycling radio.");
  }

  if (_turnOnAfterMs > 0 && now > _turnOnAfterMs)
  {
    _turnOnAfterMs = 0;
    _doOn();
    debugI("WiFi turned back on after recovery delay.");
  }
}

void NetLink::_serviceBootAutoConnect()
{
  if (!_bootAutoConnectPending)
    return;
  if (_bootAutoConnectAt == 0)
    return;
  if (millis() < _bootAutoConnectAt)
    return;

  _bootAutoConnectPending = false;
  _bootAutoConnectAt = 0;
  _doConnect();
}

WiFiDetails NetLink::_buildStatus() const
{
  WiFiDetails d;
  d.state = _state;
  d.usingFactoryCreds = _usingFactoryCreds;

  switch (_state)
  {
  case WiFiState::WiFiOff:
    d.offMessage = "WiFi is turned off.";
    break;
  case WiFiState::WiFiConnected:
    d.ssid = _usingFactoryCreds ? "Factory network" : WiFi.SSID();
    d.ip = WiFi.localIP();
    d.timeConnected = millis() - _timeConnectedMs;
    d.rssi = WiFi.RSSI();
    break;
  case WiFiState::WiFiConnecting:
    d.offMessage = "Connecting to WiFi...";
    break;
  case WiFiState::WiFiDisconnected:
    d.offMessage = "WiFi is disconnected.";
    break;
  case WiFiState::WiFiError:
    // Reserved; not currently entered.
    break;
  }
  return d;
}

// =============================================================================
// Credential storage
// =============================================================================
//
// Saved networks live in LittleFS at WIFI_NETWORKS_FILE as JSON. Legacy
// credentials stored in the ESP-IDF NVS-backed wifi_config_t are migrated
// once on first boot then ignored.
//

bool NetLink::_loadSavedNetworks(std::vector<SavedWiFiNetwork> &out, bool includeFactory) const
{
  out.clear();
  SavedWiFiNetwork factoryNetwork;
  bool haveFactoryNetwork = false;
  char *raw = Files::getFileAsString(WIFI_NETWORKS_FILE);
  if (!raw)
  {
    if (includeFactory)
      _ensureFactoryNetwork(out);
    return !out.empty();
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, raw);
  free(raw);

  if (err)
  {
    debugE("Failed to parse saved WiFi networks JSON");
    if (includeFactory)
      _ensureFactoryNetwork(out);
    return !out.empty();
  }

  JsonArray arr = doc["networks"].as<JsonArray>();
  if (arr.isNull())
  {
    if (includeFactory)
      _ensureFactoryNetwork(out);
    return !out.empty();
  }

  for (JsonObject obj : arr)
  {
    String ssid = obj["ssid"] | "";
    if (ssid.isEmpty())
      continue;

    SavedWiFiNetwork n;
    n.ssid = ssid;
    n.password = obj["password"] | "";
    n.lastConnectedUnix = obj["lastConnected"] | 0U;
    n.lastSuccessfulBssid = obj["lastSuccessfulBssid"] | "";

    if (_isFactoryNetworkSsid(ssid))
    {
      factoryNetwork = n;
      haveFactoryNetwork = true;
      continue;
    }

    if (out.size() >= MAX_SAVED_NETWORKS)
      continue;
    out.push_back(n);
  }

  if (includeFactory)
  {
    if (haveFactoryNetwork)
    {
      factoryNetwork.ssid = _factorySsid;
      factoryNetwork.password = _factoryPassword;
      out.push_back(factoryNetwork);
    }
    else
    {
      _ensureFactoryNetwork(out);
    }
  }
  return !out.empty();
}

bool NetLink::_saveSavedNetworks(const std::vector<SavedWiFiNetwork> &networks) const
{
  std::vector<SavedWiFiNetwork> persisted;
  persisted.reserve(networks.size() + 1);

  for (const SavedWiFiNetwork &n : networks)
  {
    if (n.ssid.isEmpty() || _isFactoryNetworkSsid(n.ssid))
      continue;
    if (persisted.size() >= MAX_SAVED_NETWORKS)
      break;
    persisted.push_back(n);
  }

  std::vector<SavedWiFiNetwork> existing;
  SavedWiFiNetwork factoryNetwork;
  if (_loadSavedNetworks(existing, true))
  {
    for (const SavedWiFiNetwork &n : existing)
    {
      if (_isFactoryNetworkSsid(n.ssid))
      {
        factoryNetwork = n;
        break;
      }
    }
  }

  factoryNetwork.ssid = _factorySsid;
  factoryNetwork.password = _factoryPassword;
  persisted.push_back(factoryNetwork);

  JsonDocument doc;
  JsonArray arr = doc["networks"].to<JsonArray>();

  for (const SavedWiFiNetwork &n : persisted)
  {
    if (n.ssid.isEmpty())
      continue;
    JsonObject obj = arr.add<JsonObject>();
    obj["ssid"] = n.ssid;
    obj["password"] = n.password;
    if (n.lastConnectedUnix != 0U)
      obj["lastConnected"] = n.lastConnectedUnix;
    if (!n.lastSuccessfulBssid.isEmpty())
      obj["lastSuccessfulBssid"] = n.lastSuccessfulBssid;
  }

  String s;
  serializeJson(doc, s);
  Files::writeToFile(WIFI_NETWORKS_FILE, s);
  return true;
}

void NetLink::_ensureFactoryNetwork(std::vector<SavedWiFiNetwork> &networks) const
{
  SavedWiFiNetwork factoryNetwork;
  factoryNetwork.ssid = _factorySsid;
  factoryNetwork.password = _factoryPassword;
  networks.push_back(factoryNetwork);
}

void NetLink::_migrateLegacyCredentialsIfNeeded()
{
  char *raw = Files::getFileAsString(WIFI_NETWORKS_FILE);
  if (raw)
  {
    JsonDocument doc;
    const DeserializationError err = deserializeJson(doc, raw);
    free(raw);

    if (err)
    {
      debugE("Failed to parse saved WiFi networks JSON during startup check");
      return;
    }

    bool hasFactoryNetwork = false;
    JsonArray arr = doc["networks"].as<JsonArray>();
    if (!arr.isNull())
    {
      for (JsonObject obj : arr)
      {
        const String ssid = obj["ssid"] | "";
        if (_isFactoryNetworkSsid(ssid))
        {
          hasFactoryNetwork = true;
          break;
        }
      }
    }

    if (!hasFactoryNetwork)
    {
      std::vector<SavedWiFiNetwork> networks;
      _loadSavedNetworks(networks, false);
      _saveSavedNetworks(networks);
      debugI("Added factory network to saved WiFi list.");
    }
    return;
  }

  std::vector<SavedWiFiNetwork> networks;

  debugI("Checking legacy credentials");

  WiFi.mode(WIFI_STA);
  if (esp_wifi_set_storage(WIFI_STORAGE_FLASH) != ESP_OK)
  {
    debugE("Failed to select flash storage for legacy config");
    return;
  }

  wifi_config_t cfg{};
  if (esp_wifi_get_config(WIFI_IF_STA, &cfg) != ESP_OK)
  {
    debugE("Failed to read legacy config");
    return;
  }

  if (cfg.sta.ssid[0] == '\0')
    return;

  SavedWiFiNetwork n;
  n.ssid = String(reinterpret_cast<const char *>(cfg.sta.ssid));
  n.password = String(reinterpret_cast<const char *>(cfg.sta.password));
  networks.push_back(n);

  debugI("Migrating legacy credentials: %s", n.ssid.c_str());
  _saveSavedNetworks(networks);
  debugI("Migration complete.");
}

void NetLink::_touchLastConnected()
{
  const String ssid = WiFi.SSID();
  if (ssid.isEmpty())
    return;

  const String bssid = formatBssid(WiFi.BSSID());
  bool timeOk = false;
  const uint32_t ts = _cb.currentUnixTime ? _cb.currentUnixTime(timeOk) : 0;

  std::vector<SavedWiFiNetwork> networks;
  if (!_loadSavedNetworks(networks))
    return;

  bool changed = false;
  for (auto &n : networks)
  {
    if (n.ssid != ssid)
      continue;
    if (!bssid.isEmpty() && !n.lastSuccessfulBssid.equalsIgnoreCase(bssid))
    {
      n.lastSuccessfulBssid = bssid;
      changed = true;
    }
    if (timeOk && ts != 0U && n.lastConnectedUnix != ts)
    {
      n.lastConnectedUnix = ts;
      changed = true;
    }
    break;
  }
  if (changed)
    _saveSavedNetworks(networks);
}

bool NetLink::hasSavedCredentials() const
{
  std::vector<SavedWiFiNetwork> networks;
  return _loadSavedNetworks(networks, false);
}

std::vector<SavedWiFiNetwork> NetLink::getSavedNetworks() const
{
  std::vector<SavedWiFiNetwork> networks;
  _loadSavedNetworks(networks, false);
  return networks;
}

bool NetLink::saveCredentials(const char *ssid, const char *password)
{
  if (!ssid || strlen(ssid) == 0)
    return false;
  if (_isFactoryNetworkSsid(ssid))
    return false;

  std::vector<SavedWiFiNetwork> networks;
  _loadSavedNetworks(networks, false);

  const String target = ssid;
  uint32_t lastConn = 0;
  String lastBssid;

  networks.erase(std::remove_if(networks.begin(), networks.end(),
                                [&](const SavedWiFiNetwork &n)
                                {
                                  if (n.ssid == target)
                                  {
                                    lastConn = n.lastConnectedUnix;
                                    lastBssid = n.lastSuccessfulBssid;
                                    return true;
                                  }
                                  return false;
                                }),
                 networks.end());

  SavedWiFiNetwork n;
  n.ssid = ssid;
  n.password = password ? password : "";
  n.lastConnectedUnix = lastConn;
  n.lastSuccessfulBssid = lastBssid;
  networks.insert(networks.begin(), n);

  if (networks.size() > MAX_SAVED_NETWORKS)
    networks.resize(MAX_SAVED_NETWORKS);

  if (!_saveSavedNetworks(networks))
  {
    debugE("Failed to save WiFi networks JSON");
    return false;
  }

  if (auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(3000)))
  {
    _resetScheduler();

    const bool skipReconnect = (_cb.isCellularPreferred && _cb.isCellularPreferred());

    if (!skipReconnect && !_scanInProgress &&
        _state != WiFiState::WiFiOff && !WiFi.isConnected())
    {
      debugI("Restarting WiFi connect loop after new credentials.");
      _doConnect();
    }
  }
  else
  {
    debugE("saveCredentials: mutex timeout; will refresh on next connect.");
  }
  return true;
}

bool NetLink::forgetNetwork(const char *ssid)
{
  if (!ssid || strlen(ssid) == 0)
    return false;
  if (_isFactoryNetworkSsid(ssid))
    return false;

  std::vector<SavedWiFiNetwork> networks;
  _loadSavedNetworks(networks, false);
  const String target = ssid;
  const size_t before = networks.size();

  networks.erase(std::remove_if(networks.begin(), networks.end(),
                                [&](const SavedWiFiNetwork &n)
                                { return n.ssid == target; }),
                 networks.end());

  if (networks.size() == before)
    return false;

  _saveSavedNetworks(networks);

  const bool wasConnected = WiFi.isConnected() && WiFi.SSID() == target;

  if (auto lock = FreeRtosRaii::tryLock(wifiLoopMutex(), pdMS_TO_TICKS(3000)))
  {
    _resetScheduler();
    if (wasConnected)
    {
      // BUG FIX vs original: previously we only flagged disconnect, then
      // sat in WiFiDisconnected for the full 3-minute recovery grace
      // before ever trying any remaining saved networks. Now we
      // disconnect and immediately queue a fresh connect cycle, which
      // will use the remaining saved SSIDs (or fall through to factory).
      _doDisconnect();
      if (!networks.empty())
      {
        _pending |= PendingConnect;
      }
    }
  }
  else
  {
    debugE("forgetNetwork: mutex timeout.");
  }
  return true;
}

NetLink netLink;
