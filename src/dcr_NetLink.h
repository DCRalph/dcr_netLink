#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <vector>

#include "dcr_INetLink.h"
#include "dcr_NetLinkEvents.h"

// =============================================================================
// Timing
// =============================================================================
// Per-attempt connect timeout (saved-network attempts and factory attempts).
#define CONNECT_TIMEOUT 60000UL
// Reserved (not currently used).
#define CONFIG_PORTAL_TIMEOUT 600000UL
// Cycle the radio after this long without an IP.
#define WIFI_DISCONNECT_RECOVERY_GRACE_MS 180000UL
// If association gets stuck in WiFiConnecting, use a longer backstop before
// cycling the radio to avoid interrupting slow but still-progressing joins.
#define WIFI_CONNECTING_RECOVERY_GRACE_MS 300000UL
// After turning the radio off for recovery, wait this long before turning back on.
#define WIFI_RECONNECT_POWER_CYCLE_DELAY_MS 10000UL
// Delay first auto-connect at boot by this long (lets other tasks settle).
#define WIFI_BOOT_CONNECT_DELAY_MS 3000UL

// =============================================================================
// Public types
// =============================================================================

struct WiFiDetails
{
    WiFiState state = WiFiState::WiFiOff;

    // Human-readable status message used when not connected.
    String offMessage;
    // Reserved for future error reporting; currently always empty.
    String errorMessage;

    // Connected-state fields.
    String ssid;
    IPAddress ip;
    unsigned long timeConnected = 0; // ms since association established
    int rssi = 0;

    // True when the active association is the factory (commissioning) network.
    bool usingFactoryCreds = false;
};

struct SavedWiFiNetwork
{
    String ssid;
    String password;
    uint32_t lastConnectedUnix = 0;
    String lastSuccessfulBssid;
};

// =============================================================================
// NetLink
// =============================================================================
//
// Threading model
// ---------------
//   - Public methods may be called from any task.
//   - Public command methods (on/off/connect/disconnect) queue an action
//     that is processed inside loop(). They do not block on WiFi state changes.
//   - The internal _doX() methods require the wifi-loop mutex to be held; they are private.
//   - loop() holds the wifi-loop mutex for its entire body.
//
class NetLink : public INetLink
{
public:
    static constexpr size_t MAX_SAVED_NETWORKS = 8;
    static constexpr size_t MAX_CALLBACKS = 10;

    NetLink();

    // === Lifecycle ===
    void init();
    void loop();

    // Configure the commissioning / factory network used as a fallback when no
    // user-saved credentials are present. Must be called before init().
    void setFactoryCredentials(const char *ssid, const char *password);

    // Register UI / sleep-arbitration callbacks. Safe to call any time; the
    // library reads the callbacks under its private mutex.
    void setCallbacks(const NetLinkCallbacks &callbacks);

    // === Commands (queue an action; processed inside loop()) ===
    void on();
    void off();
    void connect();
    void disconnect();
    // Queue a disconnect+connect cycle without surfacing user-facing
    // popups. Intended for background recovery (e.g. low-heap reset)
    // where popping a "Please Wait" dialog over the user's current
    // screen would be unexpected.
    void requestSilentReconnect();
    void resetConfig();

    // Synchronous shutdown for cellular handover. Caller must ensure no
    // concurrent loop() is running; the timeout fallback is last-resort only.
    void prepareForExternalTransport();

    // === Saved credentials ===
    bool saveCredentials(const char *ssid, const char *password);
    bool forgetNetwork(const char *ssid);
    bool hasSavedCredentials() const;
    std::vector<SavedWiFiNetwork> getSavedNetworks() const;

    // === Status ===
    WiFiDetails getStatus();
    unsigned long getDisconnectionStartTime() const { return _disconnectionStartTime; }

    // === INetLink overrides ===
    bool isConnected() const override;
    uint32_t disconnectEventSeq() const override;
    int rssi() const override;
    WiFiState state() const override { return _state; }

    // Monotonic counter of WiFi STA disconnect events (static accessor kept
    // for code that does not have a NetLink instance handy).
    static uint32_t globalDisconnectEventSeq();

    // === External (UI-driven) scan flow ===
    // Pause auto-reconnect, cycle the radio, hand control to the UI for
    // WiFi.scanNetworks(). endScan() resumes auto-reconnect.
    void beginScan();
    void endScan();


private:
    // === Internal types ===
    struct BssidCandidate
    {
        uint8_t bssid[6] = {0, 0, 0, 0, 0, 0};
        int32_t channel = 0;
        int32_t rssi = -127;
        uint8_t attempts = 0;
    };

    struct AttemptPlan
    {
        String ssid;
        String password;
        String preferredBssid;
        std::vector<BssidCandidate> candidates;
    };

    enum PendingFlag : uint8_t
    {
        PendingNone = 0,
        PendingTurnOn = 1 << 0,
        PendingTurnOff = 1 << 1,
        PendingConnect = 1 << 2,
        PendingDisconnect = 1 << 3,
    };

    // === Internal transitions (mutex must be held) ===
    void _doOn();
    void _doOff();
    void _doConnect();
    void _doDisconnect();
    // === Connection scheduler (mutex must be held) ===
    void _resetScheduler();
    bool _ensureScanTaskStarted();
    void _startScan();
    void _scheduleConnectRetry(const char *reason, uint32_t delayMs);
    void _serviceScanIfReady();
    bool _buildPlanFromScan(int8_t scanResult);
    bool _startNextAttempt();
    bool _failCurrentAttempt(const char *reason);
    void _serviceConnectionAttempt();

    // === Status, timeouts, recovery (mutex must be held) ===
    void _refreshConnectionState();
    void _checkTimeouts();
    void _serviceDisconnectRecovery();
    void _serviceBootAutoConnect();
    WiFiDetails _buildStatus() const;

    // === Credential storage (file I/O; safe without mutex) ===
    bool _loadSavedNetworks(std::vector<SavedWiFiNetwork> &out, bool includeFactory = true) const;
    bool _saveSavedNetworks(const std::vector<SavedWiFiNetwork> &networks) const;
    void _ensureFactoryNetwork(std::vector<SavedWiFiNetwork> &networks) const;
    bool _isFactoryNetworkSsid(const String &ssid) const;
    void _migrateLegacyCredentialsIfNeeded();
    void _touchLastConnected();

    // === Scan task entry ===
    static void _scanTaskEntry(void *param);

    // === Members ===
    WiFiState _state = WiFiState::WiFiOff;
    WiFiDetails _cachedDetails;

    NetLinkCallbacks _cb;

    String _factorySsid;
    String _factoryPassword;

    // Bitmask of PendingFlag values.
    uint8_t _pending = PendingNone;

    // Connection attempt state.
    std::vector<AttemptPlan> _plan;
    size_t _planIdx = 0;
    size_t _candidateIdx = 0;
    unsigned long _attemptStartMs = 0;
    uint32_t _attemptDisconnectBaselineSeq = 0;
    bool _connectInProgress = false;

    // Async scan task lifecycle.
    TaskHandle_t _scanTask = nullptr;
    volatile bool _scanResultReady = false;
    volatile int8_t _scanResult = WIFI_SCAN_FAILED;
    volatile uint32_t _scanRequestId = 0;
    volatile uint32_t _scanCompletedRequestId = 0;
    bool _scanPending = false;
    unsigned long _retryConnectAt = 0;

    // Connection timing.
    unsigned long _timeConnectedMs = 0;
    unsigned long _disconnectionStartTime = 0;
    unsigned long _turnOnAfterMs = 0;

    // External (UI-driven) scan flag.
    bool _scanInProgress = false;

    bool _usingFactoryCreds = false;

    // Boot auto-connect delay.
    bool _bootAutoConnectPending = false;
    unsigned long _bootAutoConnectAt = 0;

    static constexpr const char *WIFI_NETWORKS_FILE = "/wifi_networks.json";
};

extern NetLink netLink;
