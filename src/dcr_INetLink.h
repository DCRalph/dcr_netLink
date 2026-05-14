#pragma once

#include <cstdint>

enum class WiFiState
{
  WiFiOff,
  WiFiConnecting,
  WiFiConnected,
  WiFiDisconnected,
  WiFiError,
};

class INetLink
{
public:
  virtual ~INetLink() = default;
  virtual bool isConnected() const = 0;
  virtual uint32_t disconnectEventSeq() const = 0;
  virtual int rssi() const = 0;
  virtual WiFiState state() const = 0;
};
