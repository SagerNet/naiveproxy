// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/custom_client_socket_factory.h"

#include <memory>
#include <utility>

#include "base/logging.h"
#include "build/build_config.h"

#if BUILDFLAG(IS_WIN)
#include <winsock2.h>
#else
#include <unistd.h>
#endif
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/log/net_log.h"
#include "net/log/net_log_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/tcp_socket.h"
#include "net/socket/udp_client_socket.h"

namespace net {

namespace {

// A TransportClientSocket that immediately fails with a predetermined error.
// Used when the custom dialer returns an error code.
class FailingTransportClientSocket : public TransportClientSocket {
 public:
  explicit FailingTransportClientSocket(int error_code,
                                        const AddressList& addresses,
                                        class NetLog* net_log,
                                        const NetLogSource& source)
      : error_code_(error_code),
        addresses_(addresses),
        net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::SOCKET)) {}

  ~FailingTransportClientSocket() override = default;

  // TransportClientSocket implementation:
  int Bind(const IPEndPoint& local_addr) override {
    return ERR_FAILED;
  }

  bool SetNoDelay(bool no_delay) override { return false; }

  bool SetKeepAlive(bool enable, int delay_secs) override { return false; }

  // StreamSocket implementation:
  int Connect(CompletionOnceCallback callback) override {
    return error_code_;
  }

  void Disconnect() override {}

  bool IsConnected() const override { return false; }

  bool IsConnectedAndIdle() const override { return false; }

  int GetPeerAddress(IPEndPoint* address) const override {
    return ERR_SOCKET_NOT_CONNECTED;
  }

  int GetLocalAddress(IPEndPoint* address) const override {
    return ERR_SOCKET_NOT_CONNECTED;
  }

  const NetLogWithSource& NetLog() const override { return net_log_; }

  bool WasEverUsed() const override { return false; }

  NextProto GetNegotiatedProtocol() const override { return NextProto::kProtoUnknown; }

  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }

  int64_t GetTotalReceivedBytes() const override { return 0; }

  void ApplySocketTag(const SocketTag& tag) override {}

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override {
    return error_code_;
  }

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    return error_code_;
  }

  int SetReceiveBufferSize(int32_t size) override { return ERR_FAILED; }

  int SetSendBufferSize(int32_t size) override { return ERR_FAILED; }

 private:
  const int error_code_;
  const AddressList addresses_;
  NetLogWithSource net_log_;
};

// A TransportClientSocket that wraps an already-connected socket.
// The Connect() method will return OK immediately since the socket is already
// connected.
class ConnectedTransportClientSocket : public TransportClientSocket {
 public:
  ConnectedTransportClientSocket(std::unique_ptr<TCPSocket> socket,
                                 const IPEndPoint& peer_address,
                                 class NetLog* net_log,
                                 const NetLogSource& source)
      : socket_(std::move(socket)),
        peer_address_(peer_address),
        net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::SOCKET)) {}

  ~ConnectedTransportClientSocket() override {
    Disconnect();
  }

  // TransportClientSocket implementation:
  int Bind(const IPEndPoint& local_addr) override {
    // Already connected, cannot bind.
    return ERR_SOCKET_IS_CONNECTED;
  }

  bool SetNoDelay(bool no_delay) override {
    return socket_ && socket_->SetNoDelay(no_delay);
  }

  bool SetKeepAlive(bool enable, int delay_secs) override {
    return socket_ && socket_->SetKeepAlive(enable, delay_secs);
  }

  // StreamSocket implementation:
  int Connect(CompletionOnceCallback callback) override {
    // Already connected.
    return OK;
  }

  void Disconnect() override {
    if (socket_) {
      socket_->Close();
      socket_.reset();
    }
  }

  bool IsConnected() const override {
    return socket_ && socket_->IsConnected();
  }

  bool IsConnectedAndIdle() const override {
    return socket_ && socket_->IsConnectedAndIdle();
  }

  int GetPeerAddress(IPEndPoint* address) const override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    *address = peer_address_;
    return OK;
  }

  int GetLocalAddress(IPEndPoint* address) const override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->GetLocalAddress(address);
  }

  const NetLogWithSource& NetLog() const override { return net_log_; }

  bool WasEverUsed() const override { return was_ever_used_; }

  NextProto GetNegotiatedProtocol() const override { return NextProto::kProtoUnknown; }

  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }

  int64_t GetTotalReceivedBytes() const override { return total_received_bytes_; }

  void ApplySocketTag(const SocketTag& tag) override {
    if (socket_) {
      socket_->ApplySocketTag(tag);
    }
  }

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    int result = socket_->Read(buf, buf_len, std::move(callback));
    if (result > 0) {
      was_ever_used_ = true;
      total_received_bytes_ += result;
    }
    return result;
  }

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    int result =
        socket_->Write(buf, buf_len, std::move(callback), traffic_annotation);
    if (result > 0) {
      was_ever_used_ = true;
    }
    return result;
  }

  int SetReceiveBufferSize(int32_t size) override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->SetReceiveBufferSize(size);
  }

  int SetSendBufferSize(int32_t size) override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->SetSendBufferSize(size);
  }

 private:
  std::unique_ptr<TCPSocket> socket_;
  IPEndPoint peer_address_;
  NetLogWithSource net_log_;
  bool was_ever_used_ = false;
  int64_t total_received_bytes_ = 0;
};

}  // namespace

CustomClientSocketFactory::CustomClientSocketFactory(DialerCallback dialer)
    : dialer_(std::move(dialer)) {
  DCHECK(dialer_);
}

CustomClientSocketFactory::~CustomClientSocketFactory() = default;

std::unique_ptr<DatagramClientSocket>
CustomClientSocketFactory::CreateDatagramClientSocket(
    DatagramSocket::BindType bind_type,
    NetLog* net_log,
    const NetLogSource& source) {
  // Use the default implementation for UDP sockets.
  return std::make_unique<UDPClientSocket>(bind_type, net_log, source);
}

std::unique_ptr<TransportClientSocket>
CustomClientSocketFactory::CreateTransportClientSocket(
    const AddressList& addresses,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetworkQualityEstimator* network_quality_estimator,
    NetLog* net_log,
    const NetLogSource& source) {
  // Try each address until one succeeds.
  int last_error = ERR_NAME_NOT_RESOLVED;
  for (const auto& endpoint : addresses) {
    std::string address_string = endpoint.ToStringWithoutPort();
    uint16_t port = endpoint.port();

    int result = dialer_.Run(address_string, port);

    if (result >= 0) {
      // Success - we got a connected socket fd.
      SocketDescriptor socket_fd = static_cast<SocketDescriptor>(result);

      auto tcp_socket = TCPSocket::Create(std::move(socket_performance_watcher),
                                          net_log, source);

      int adopt_result = tcp_socket->AdoptConnectedSocket(socket_fd, endpoint);
      if (adopt_result != OK) {
        LOG(ERROR) << "Failed to adopt connected socket: " << adopt_result;
        // Close the fd since we couldn't adopt it.
#if BUILDFLAG(IS_WIN)
        closesocket(socket_fd);
#else
        close(socket_fd);
#endif
        return std::make_unique<FailingTransportClientSocket>(
            adopt_result, addresses, net_log, source);
      }

      // Set default options for client socket.
      tcp_socket->SetDefaultOptionsForClient();

      return std::make_unique<ConnectedTransportClientSocket>(
          std::move(tcp_socket), endpoint, net_log, source);
    }

    // Dialer returned an error for this address. Store the error and try the
    // next address in the list.
    last_error = result;
  }

  // All addresses failed (or no addresses to try).
  return std::make_unique<FailingTransportClientSocket>(
      last_error, addresses, net_log, source);
}

std::unique_ptr<SSLClientSocket> CustomClientSocketFactory::CreateSSLClientSocket(
    SSLClientContext* context,
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config) {
  // Use the default implementation for SSL sockets.
  return ClientSocketFactory::GetDefaultFactory()->CreateSSLClientSocket(
      context, std::move(stream_socket), host_and_port, ssl_config);
}

}  // namespace net
