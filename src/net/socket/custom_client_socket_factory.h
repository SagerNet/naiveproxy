// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_CUSTOM_CLIENT_SOCKET_FACTORY_H_
#define NET_SOCKET_CUSTOM_CLIENT_SOCKET_FACTORY_H_

#include <memory>

#include "base/functional/callback.h"
#include "net/base/net_export.h"
#include "net/socket/client_socket_factory.h"

namespace net {

// A ClientSocketFactory that uses a custom dialer callback for TCP connections.
// When the dialer is set, CreateTransportClientSocket will call the callback
// to get a connected socket file descriptor instead of creating a new socket.
class NET_EXPORT CustomClientSocketFactory : public ClientSocketFactory {
 public:
  // Callback type for custom TCP dialer.
  // Parameters:
  //   - address: IP address string (e.g. "1.2.3.4" or "::1")
  //   - port: Port number
  // Returns:
  //   - On success: connected socket file descriptor (>= 0)
  //   - On failure: negative net error code (e.g. ERR_CONNECTION_REFUSED)
  using DialerCallback =
      base::RepeatingCallback<int(const std::string& address, uint16_t port)>;

  // Callback type for custom UDP dialer.
  // Parameters:
  //   - address: IP address string (e.g. "1.2.3.4" or "::1")
  //   - port: Port number
  //   - out_local_address: Output buffer for local IP (caller provides buffer)
  //   - out_local_port: Output pointer for local port
  // Returns:
  //   - On success: socket file descriptor (>= 0)
  //   - On failure: negative net error code
  // The returned socket can be AF_INET/AF_INET6 SOCK_DGRAM, AF_UNIX SOCK_DGRAM,
  // or AF_UNIX SOCK_STREAM (for Windows, with length-prefix framing).
  using UdpDialerCallback = base::RepeatingCallback<int(
      const std::string& address,
      uint16_t port,
      char* out_local_address,
      uint16_t* out_local_port)>;

  CustomClientSocketFactory(DialerCallback tcp_dialer,
                            UdpDialerCallback udp_dialer);
  ~CustomClientSocketFactory() override;

  CustomClientSocketFactory(const CustomClientSocketFactory&) = delete;
  CustomClientSocketFactory& operator=(const CustomClientSocketFactory&) =
      delete;

  // ClientSocketFactory implementation:
  std::unique_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType bind_type,
      NetLog* net_log,
      const NetLogSource& source) override;

  std::unique_ptr<TransportClientSocket> CreateTransportClientSocket(
      const AddressList& addresses,
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      NetworkQualityEstimator* network_quality_estimator,
      NetLog* net_log,
      const NetLogSource& source) override;

  std::unique_ptr<SSLClientSocket> CreateSSLClientSocket(
      SSLClientContext* context,
      std::unique_ptr<StreamSocket> stream_socket,
      const HostPortPair& host_and_port,
      const SSLConfig& ssl_config) override;

 private:
  DialerCallback tcp_dialer_;
  UdpDialerCallback udp_dialer_;
};

}  // namespace net

#endif  // NET_SOCKET_CUSTOM_CLIENT_SOCKET_FACTORY_H_
