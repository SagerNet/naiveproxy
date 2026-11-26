// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_CUSTOM_CLIENT_SOCKET_FACTORY_H_
#define NET_SOCKET_CUSTOM_CLIENT_SOCKET_FACTORY_H_

#include <stdint.h>

#include <memory>
#include <set>

#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "net/base/net_export.h"
#include "net/socket/client_socket_factory.h"

namespace net {

// A ClientSocketFactory that uses custom dialer callbacks for TCP and UDP
// sockets. Asynchronous connects run the callbacks on a blocking ThreadPool
// worker and adopt the returned socket file descriptor on the calling sequence.
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
      base::RepeatingCallback<intptr_t(const std::string& address,
                                       uint16_t port)>;

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
  using UdpDialerCallback =
      base::RepeatingCallback<intptr_t(const std::string& address,
                                       uint16_t port,
                                       char* out_local_address,
                                       uint16_t* out_local_port,
                                       base::OnceClosure* on_close)>;

  class PendingConnect {
   public:
    virtual void CancelPendingConnect() = 0;

   protected:
    virtual ~PendingConnect() = default;
  };

  class DialQueue;

  CustomClientSocketFactory(DialerCallback tcp_dialer,
                            UdpDialerCallback udp_dialer);
  ~CustomClientSocketFactory() override;

  CustomClientSocketFactory(const CustomClientSocketFactory&) = delete;
  CustomClientSocketFactory& operator=(const CustomClientSocketFactory&) =
      delete;

  // ClientSocketFactory implementation:
  std::unique_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType bind_type,
      handles::NetworkHandle target_network,
      NetLog* net_log,
      const NetLogSource& source) override;

  std::unique_ptr<TransportClientSocket> CreateTransportClientSocket(
      const AddressList& addresses,
      handles::NetworkHandle target_network,
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      NetworkQualityEstimator* network_quality_estimator,
      NetLog* net_log,
      const NetLogSource& source) override;

  std::unique_ptr<SSLClientSocket> CreateSSLClientSocket(
      SSLClientContext* context,
      std::unique_ptr<StreamSocket> stream_socket,
      const HostPortPair& host_and_port,
      const SSLConfig& ssl_config) override;

  void AddPendingConnect(PendingConnect* pending_connect);
  void RemovePendingConnect(PendingConnect* pending_connect);

 private:
  DialerCallback tcp_dialer_;
  UdpDialerCallback udp_dialer_;
  scoped_refptr<DialQueue> dial_queue_;
  std::set<raw_ptr<PendingConnect>> pending_connects_;

  base::WeakPtrFactory<CustomClientSocketFactory> weak_factory_{this};
};

}  // namespace net

#endif  // NET_SOCKET_CUSTOM_CLIENT_SOCKET_FACTORY_H_
