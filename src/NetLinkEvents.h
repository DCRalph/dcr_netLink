#pragma once

#include <Arduino.h>
#include <IPAddress.h>
#include <functional>

struct WiFiDetails;

// Callbacks the application registers with NetLink to integrate UI / sleep
// arbitration without the library taking compile-time dependencies on those
// project headers.
struct NetLinkCallbacks
{
  std::function<void(const WiFiDetails &)> onConnected;
  std::function<void(const WiFiDetails &)> onDisconnected;
  std::function<void(const String &reason)> onConnectFailed;
  std::function<void()> onScanStarted;
  std::function<void()> onScanCompleted;

  // Replaces direct Popups::showPopup / closePopup calls. The id can be used
  // by the UI to match a later onClosePopup against the popup created by an
  // earlier onShowPopup.
  std::function<void(const String &id, const String &title, const String &message)> onShowPopup;
  std::function<void(const String &id)> onClosePopup;

  // Replaces direct Buzzer::play call when a connection comes up.
  std::function<void()> onBuzz;

  // Replaces BLE::bleManager.isStarted() poll. Returning true tells NetLink
  // it should keep WiFi awake for an active BLE session.
  std::function<bool()> isBleActive;

  // Returns true when the cellular modem is the preferred transport.
  // NetLink skips WiFi auto-connect at boot and after credential saves when
  // this is true.
  std::function<bool()> isCellularPreferred;

  // Returns the current Unix timestamp. Out-param `timeOk` is set to true
  // when the timestamp is valid. NetLink uses this to record per-network
  // last-connected timestamps in /wifi_networks.json.
  std::function<uint32_t(bool &timeOk)> currentUnixTime;
};
