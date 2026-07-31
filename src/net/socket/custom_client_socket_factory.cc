// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/custom_client_socket_factory.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "build/build_config.h"

#if BUILDFLAG(IS_WIN)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
#include "base/numerics/byte_conversions.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
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
#include "net/traffic_annotation/network_traffic_annotation.h"
#if !BUILDFLAG(IS_WIN)
#include "net/socket/socket_posix.h"
#endif

namespace net {

namespace {

// INET6_ADDRSTRLEN is 46 which is enough for any IPv4 or IPv6 address string.
constexpr size_t kLocalAddressBufferSize = 46;

// A DatagramClientSocket that wraps a socket fd returned by a custom dialer.
// This socket can be:
// - AF_INET/AF_INET6 SOCK_DGRAM: Standard UDP socket (may be connected)
// - AF_UNIX SOCK_DGRAM: Unix domain datagram socket (Unix/macOS/Linux)
// - AF_UNIX SOCK_STREAM: Unix domain stream socket (Windows, with framing)
//
// The socket is NOT connected by Chromium - the dialer is expected to return
// a ready-to-use socket. For AF_UNIX SOCK_STREAM, length-prefix framing is used
// to preserve datagram boundaries.
class ConnectedDatagramClientSocket : public DatagramClientSocket {
 public:
  ConnectedDatagramClientSocket(
      CustomClientSocketFactory::UdpDialerCallback dialer,
      net::NetLog* net_log,
      const NetLogSource& source)
      : dialer_(std::move(dialer)),
        net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::UDP_SOCKET)),
        read_length_buffer_(base::MakeRefCounted<IOBufferWithSize>(2)),
        write_length_buffer_(base::MakeRefCounted<IOBufferWithSize>(2)) {
    DCHECK(dialer_);
  }

  ~ConnectedDatagramClientSocket() override { Close(); }

  int Connect(const IPEndPoint& address) override { return DoConnect(address); }

  int ConnectUsingNetwork(handles::NetworkHandle network,
                          const IPEndPoint& address) override {
    if (network != handles::kInvalidNetworkHandle) {
      return ERR_NOT_IMPLEMENTED;
    }
    return DoConnect(address);
  }

  int ConnectUsingDefaultNetwork(const IPEndPoint& address) override {
    return DoConnect(address);
  }

  int ConnectAsync(const IPEndPoint& address,
                   CompletionOnceCallback callback) override {
    return DoConnect(address);
  }

  int ConnectUsingNetworkAsync(handles::NetworkHandle network,
                               const IPEndPoint& address,
                               CompletionOnceCallback callback) override {
    if (network != handles::kInvalidNetworkHandle) {
      return ERR_NOT_IMPLEMENTED;
    }
    return DoConnect(address);
  }

  int ConnectUsingDefaultNetworkAsync(
      const IPEndPoint& address,
      CompletionOnceCallback callback) override {
    return DoConnect(address);
  }

  handles::NetworkHandle GetBoundNetwork() const override {
    return handles::kInvalidNetworkHandle;
  }

  void ApplySocketTag(const SocketTag& tag) override {}

  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override {
    if (!connected_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    if (is_framed_stream_) {
      return DoFramedRead(buf, buf_len, std::move(callback));
    }
#if BUILDFLAG(IS_WIN)
    return socket_->Read(buf, buf_len, std::move(callback));
#else
    return socket_->Read(buf, buf_len, std::move(callback));
#endif
  }

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    if (!connected_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    if (is_framed_stream_) {
      return DoFramedWrite(buf, buf_len, std::move(callback),
                           traffic_annotation);
    }
#if BUILDFLAG(IS_WIN)
    return socket_->Write(buf, buf_len, std::move(callback),
                          traffic_annotation);
#else
    return socket_->Write(buf, buf_len, std::move(callback),
                          traffic_annotation);
#endif
  }

  void Close() override {
    if (connected_) {
#if BUILDFLAG(IS_WIN)
      if (socket_) {
        socket_->Close();
        socket_.reset();
      }
#else
      if (socket_) {
        socket_->Close();
        socket_.reset();
      }
#endif
      connected_ = false;
    }
  }

  int GetPeerAddress(IPEndPoint* address) const override {
    if (!connected_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    *address = peer_address_;
    return OK;
  }

  int GetLocalAddress(IPEndPoint* address) const override {
    if (!connected_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    *address = local_address_;
    return OK;
  }

  void UseNonBlockingIO() override {}

  int SetReceiveBufferSize(int32_t size) override { return OK; }
  int SetSendBufferSize(int32_t size) override { return OK; }
  int SetDoNotFragment() override { return OK; }
  int SetRecvTos() override { return OK; }
  int SetTos(DiffServCodePoint dscp, EcnCodePoint ecn) override { return OK; }
  void SetMsgConfirm(bool confirm) override {}
  DscpAndEcn GetLastTos() const override { return {DSCP_DEFAULT, ECN_NOT_ECT}; }
  const NetLogWithSource& NetLog() const override { return net_log_; }
  void EnableRecvOptimization() override {}
  int SetMulticastInterface(uint32_t interface_index) override { return OK; }
  void SetIOSNetworkServiceType(int ios_network_service_type) override {}
  void RegisterQuicConnectionClosePayload(
      base::span<uint8_t> payload) override {}
  void UnregisterQuicConnectionClosePayload() override {}

 private:
  enum ReadState {
    READ_STATE_NONE,
    READ_STATE_READ_LENGTH,
    READ_STATE_READ_LENGTH_COMPLETE,
    READ_STATE_READ_PAYLOAD,
    READ_STATE_READ_PAYLOAD_COMPLETE,
  };

  enum WriteState {
    WRITE_STATE_NONE,
    WRITE_STATE_WRITE_LENGTH,
    WRITE_STATE_WRITE_LENGTH_COMPLETE,
    WRITE_STATE_WRITE_PAYLOAD,
    WRITE_STATE_WRITE_PAYLOAD_COMPLETE,
  };

  int DoConnect(const IPEndPoint& address) {
    if (connected_) {
      return OK;
    }

    const std::string address_string = address.ToStringWithoutPort();
    const uint16_t port = address.port();

    char local_addr_buf[kLocalAddressBufferSize] = {0};
    uint16_t local_port = 0;

    intptr_t result =
        dialer_.Run(address_string, port, local_addr_buf, &local_port);
    if (result < 0) {
      return static_cast<int>(result);
    }

    SocketDescriptor socket_fd = static_cast<SocketDescriptor>(result);

#if BUILDFLAG(IS_WIN)
    WSAPROTOCOL_INFOW protocol_info;
    int info_size = sizeof(protocol_info);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_PROTOCOL_INFO,
                   reinterpret_cast<char*>(&protocol_info), &info_size) == 0) {
      is_unix_socket_ = (protocol_info.iAddressFamily == AF_UNIX);
      is_framed_stream_ =
          is_unix_socket_ && (protocol_info.iSocketType == SOCK_STREAM);
    }
#else
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    if (getsockname(socket_fd, reinterpret_cast<struct sockaddr*>(&ss),
                    &ss_len) == 0) {
      is_unix_socket_ = (ss.ss_family == AF_UNIX);
    }
    int sock_type = 0;
    socklen_t type_len = sizeof(sock_type);
    getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &sock_type, &type_len);
    is_framed_stream_ = is_unix_socket_ && (sock_type == SOCK_STREAM);
#endif

#if BUILDFLAG(IS_WIN)
    socket_ = TCPSocket::Create(nullptr, net_log_.net_log(), net_log_.source());
    int rv = socket_->AdoptConnectedSocket(socket_fd, IPEndPoint());
#else
    socket_ = std::make_unique<SocketPosix>();
    int rv = socket_->AdoptUnconnectedSocket(socket_fd);
#endif
    if (rv != OK) {
      return rv;
    }

    if (local_addr_buf[0] != '\0') {
      IPAddress ip;
      if (ip.AssignFromIPLiteral(local_addr_buf)) {
        local_address_ = IPEndPoint(ip, local_port);
      }
    }
    if (!local_address_.address().IsValid()) {
      local_address_ = IPEndPoint(address.address(), 0);
    }

    peer_address_ = address;
    connected_ = true;
    return OK;
  }

  int DoFramedRead(IOBuffer* buf,
                   int buf_len,
                   CompletionOnceCallback callback) {
    DCHECK_EQ(read_state_, READ_STATE_NONE);
    DCHECK(!read_callback_);

    read_user_buffer_ = base::WrapRefCounted(buf);
    read_user_buffer_len_ = buf_len;
    read_callback_ = std::move(callback);

    read_buffer_ = base::MakeRefCounted<DrainableIOBuffer>(
        read_length_buffer_, read_length_buffer_->size());
    read_state_ = READ_STATE_READ_LENGTH;

    int rv = DoReadLoop(OK);
    if (rv != ERR_IO_PENDING) {
      read_state_ = READ_STATE_NONE;
      read_callback_.Reset();
      read_user_buffer_ = nullptr;
      read_buffer_ = nullptr;
    }
    return rv;
  }

  int DoReadLoop(int result) {
    DCHECK_NE(read_state_, READ_STATE_NONE);
    int rv = result;
    do {
      ReadState state = read_state_;
      read_state_ = READ_STATE_NONE;
      switch (state) {
        case READ_STATE_READ_LENGTH:
          rv = DoReadLength();
          break;
        case READ_STATE_READ_LENGTH_COMPLETE:
          rv = DoReadLengthComplete(rv);
          break;
        case READ_STATE_READ_PAYLOAD:
          rv = DoReadPayload();
          break;
        case READ_STATE_READ_PAYLOAD_COMPLETE:
          rv = DoReadPayloadComplete(rv);
          break;
        default:
          NOTREACHED();
      }
    } while (rv != ERR_IO_PENDING && read_state_ != READ_STATE_NONE);
    return rv;
  }

  int DoReadLength() {
    read_state_ = READ_STATE_READ_LENGTH_COMPLETE;
    return socket_->Read(
        read_buffer_.get(), read_buffer_->BytesRemaining(),
        base::BindOnce(&ConnectedDatagramClientSocket::OnReadComplete,
                       base::Unretained(this)));
  }

  int DoReadLengthComplete(int rv) {
    if (rv <= 0) {
      return rv == 0 ? ERR_CONNECTION_CLOSED : rv;
    }
    read_buffer_->DidConsume(rv);
    if (read_buffer_->BytesRemaining() > 0) {
      read_state_ = READ_STATE_READ_LENGTH;
      return OK;
    }
    uint16_t payload_length =
        base::U16FromBigEndian(read_length_buffer_->span().first<2u>());
    if (static_cast<int>(payload_length) > read_user_buffer_len_) {
      return ERR_MSG_TOO_BIG;
    }
    read_payload_length_ = payload_length;
    if (payload_length == 0) {
      return 0;
    }
    read_buffer_ = base::MakeRefCounted<DrainableIOBuffer>(read_user_buffer_,
                                                           payload_length);
    read_state_ = READ_STATE_READ_PAYLOAD;
    return OK;
  }

  int DoReadPayload() {
    read_state_ = READ_STATE_READ_PAYLOAD_COMPLETE;
    return socket_->Read(
        read_buffer_.get(), read_buffer_->BytesRemaining(),
        base::BindOnce(&ConnectedDatagramClientSocket::OnReadComplete,
                       base::Unretained(this)));
  }

  int DoReadPayloadComplete(int rv) {
    if (rv <= 0) {
      return rv == 0 ? ERR_CONNECTION_CLOSED : rv;
    }
    read_buffer_->DidConsume(rv);
    if (read_buffer_->BytesRemaining() > 0) {
      read_state_ = READ_STATE_READ_PAYLOAD;
      return OK;
    }
    return read_payload_length_;
  }

  void OnReadComplete(int rv) {
    rv = DoReadLoop(rv);
    if (rv != ERR_IO_PENDING) {
      read_state_ = READ_STATE_NONE;
      read_user_buffer_ = nullptr;
      read_buffer_ = nullptr;
      std::move(read_callback_).Run(rv);
    }
  }

  int DoFramedWrite(IOBuffer* buf,
                    int buf_len,
                    CompletionOnceCallback callback,
                    const NetworkTrafficAnnotationTag& traffic_annotation) {
    DCHECK_EQ(write_state_, WRITE_STATE_NONE);
    DCHECK(!write_callback_);
    if (buf_len > 65535) {
      return ERR_MSG_TOO_BIG;
    }
    write_user_buffer_ = base::WrapRefCounted(buf);
    write_user_buffer_len_ = buf_len;
    write_callback_ = std::move(callback);
    write_traffic_annotation_ =
        MutableNetworkTrafficAnnotationTag(traffic_annotation);
    auto length_bytes = base::U16ToBigEndian(static_cast<uint16_t>(buf_len));
    write_length_buffer_->span().copy_from(length_bytes);
    write_buffer_ = base::MakeRefCounted<DrainableIOBuffer>(
        write_length_buffer_, write_length_buffer_->size());
    write_state_ = WRITE_STATE_WRITE_LENGTH;
    int rv = DoWriteLoop(OK);
    if (rv != ERR_IO_PENDING) {
      write_state_ = WRITE_STATE_NONE;
      write_callback_.Reset();
      write_user_buffer_ = nullptr;
      write_buffer_ = nullptr;
    }
    return rv;
  }

  int DoWriteLoop(int result) {
    DCHECK_NE(write_state_, WRITE_STATE_NONE);
    int rv = result;
    do {
      WriteState state = write_state_;
      write_state_ = WRITE_STATE_NONE;
      switch (state) {
        case WRITE_STATE_WRITE_LENGTH:
          rv = DoWriteLength();
          break;
        case WRITE_STATE_WRITE_LENGTH_COMPLETE:
          rv = DoWriteLengthComplete(rv);
          break;
        case WRITE_STATE_WRITE_PAYLOAD:
          rv = DoWritePayload();
          break;
        case WRITE_STATE_WRITE_PAYLOAD_COMPLETE:
          rv = DoWritePayloadComplete(rv);
          break;
        default:
          NOTREACHED();
      }
    } while (rv != ERR_IO_PENDING && write_state_ != WRITE_STATE_NONE);
    return rv;
  }

  int DoWriteLength() {
    write_state_ = WRITE_STATE_WRITE_LENGTH_COMPLETE;
    return socket_->Write(
        write_buffer_.get(), write_buffer_->BytesRemaining(),
        base::BindOnce(&ConnectedDatagramClientSocket::OnWriteComplete,
                       base::Unretained(this)),
        static_cast<NetworkTrafficAnnotationTag>(write_traffic_annotation_));
  }

  int DoWriteLengthComplete(int rv) {
    if (rv <= 0) {
      return rv;
    }
    write_buffer_->DidConsume(rv);
    if (write_buffer_->BytesRemaining() > 0) {
      write_state_ = WRITE_STATE_WRITE_LENGTH;
      return OK;
    }
    if (write_user_buffer_len_ == 0) {
      return 0;
    }
    write_buffer_ = base::MakeRefCounted<DrainableIOBuffer>(
        write_user_buffer_, write_user_buffer_len_);
    write_state_ = WRITE_STATE_WRITE_PAYLOAD;
    return OK;
  }

  int DoWritePayload() {
    write_state_ = WRITE_STATE_WRITE_PAYLOAD_COMPLETE;
    return socket_->Write(
        write_buffer_.get(), write_buffer_->BytesRemaining(),
        base::BindOnce(&ConnectedDatagramClientSocket::OnWriteComplete,
                       base::Unretained(this)),
        static_cast<NetworkTrafficAnnotationTag>(write_traffic_annotation_));
  }

  int DoWritePayloadComplete(int rv) {
    if (rv <= 0) {
      return rv;
    }
    write_buffer_->DidConsume(rv);
    if (write_buffer_->BytesRemaining() > 0) {
      write_state_ = WRITE_STATE_WRITE_PAYLOAD;
      return OK;
    }
    return write_user_buffer_len_;
  }

  void OnWriteComplete(int rv) {
    rv = DoWriteLoop(rv);
    if (rv != ERR_IO_PENDING) {
      write_state_ = WRITE_STATE_NONE;
      write_user_buffer_ = nullptr;
      write_buffer_ = nullptr;
      std::move(write_callback_).Run(rv);
    }
  }

  CustomClientSocketFactory::UdpDialerCallback dialer_;
  NetLogWithSource net_log_;

#if BUILDFLAG(IS_WIN)
  std::unique_ptr<TCPSocket> socket_;
#else
  std::unique_ptr<SocketPosix> socket_;
#endif

  IPEndPoint peer_address_;
  IPEndPoint local_address_;
  bool connected_ = false;
  bool is_unix_socket_ = false;
  bool is_framed_stream_ = false;

  scoped_refptr<IOBufferWithSize> read_length_buffer_;
  scoped_refptr<IOBufferWithSize> write_length_buffer_;

  ReadState read_state_ = READ_STATE_NONE;
  CompletionOnceCallback read_callback_;
  scoped_refptr<IOBuffer> read_user_buffer_;
  int read_user_buffer_len_ = 0;
  scoped_refptr<DrainableIOBuffer> read_buffer_;
  uint16_t read_payload_length_ = 0;

  WriteState write_state_ = WRITE_STATE_NONE;
  CompletionOnceCallback write_callback_;
  scoped_refptr<IOBuffer> write_user_buffer_;
  int write_user_buffer_len_ = 0;
  scoped_refptr<DrainableIOBuffer> write_buffer_;
  MutableNetworkTrafficAnnotationTag write_traffic_annotation_;
};

// A TransportClientSocket that immediately fails with a predetermined error.
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

  int Bind(const IPEndPoint& local_addr) override { return ERR_FAILED; }
  bool SetNoDelay(bool no_delay) override { return false; }
  bool SetKeepAlive(bool enable, int delay_secs) override { return false; }
  int Connect(CompletionOnceCallback callback) override { return error_code_; }
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
  NextProto GetNegotiatedProtocol() const override {
    return NextProto::kProtoUnknown;
  }
  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }
  int64_t GetTotalReceivedBytes() const override { return 0; }
  void ApplySocketTag(const SocketTag& tag) override {}
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

}  // namespace

CustomClientSocketFactory::CustomClientSocketFactory(
    DialerCallback tcp_dialer,
    UdpDialerCallback udp_dialer)
    : tcp_dialer_(std::move(tcp_dialer)), udp_dialer_(std::move(udp_dialer)) {
  DCHECK(tcp_dialer_ || udp_dialer_);
}

CustomClientSocketFactory::~CustomClientSocketFactory() = default;

std::unique_ptr<DatagramClientSocket>
CustomClientSocketFactory::CreateDatagramClientSocket(
    DatagramSocket::BindType bind_type,
    NetLog* net_log,
    const NetLogSource& source) {
  if (udp_dialer_) {
    return std::make_unique<ConnectedDatagramClientSocket>(udp_dialer_, net_log,
                                                           source);
  }
  return ClientSocketFactory::GetDefaultFactory()->CreateDatagramClientSocket(
      bind_type, net_log, source);
}

std::unique_ptr<TransportClientSocket>
CustomClientSocketFactory::CreateTransportClientSocket(
    const AddressList& addresses,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetworkQualityEstimator* network_quality_estimator,
    NetLog* net_log,
    const NetLogSource& source) {
  if (!tcp_dialer_) {
    return ClientSocketFactory::GetDefaultFactory()
        ->CreateTransportClientSocket(
            addresses, std::move(socket_performance_watcher),
            network_quality_estimator, net_log, source);
  }

  int last_error = ERR_NAME_NOT_RESOLVED;
  for (const auto& endpoint : addresses) {
    std::string address_string = endpoint.ToStringWithoutPort();
    uint16_t port = endpoint.port();
    intptr_t result = tcp_dialer_.Run(address_string, port);
    if (result >= 0) {
      SocketDescriptor socket_fd = static_cast<SocketDescriptor>(result);
      auto tcp_socket = TCPSocket::Create(std::move(socket_performance_watcher),
                                          net_log, source);
      int adopt_result = tcp_socket->AdoptConnectedSocket(socket_fd, endpoint);
      if (adopt_result != OK) {
        return std::make_unique<FailingTransportClientSocket>(
            adopt_result, addresses, net_log, source);
      }
      return std::make_unique<TCPClientSocket>(std::move(tcp_socket), endpoint);
    }
    last_error = static_cast<int>(result);
  }
  return std::make_unique<FailingTransportClientSocket>(last_error, addresses,
                                                        net_log, source);
}

std::unique_ptr<SSLClientSocket>
CustomClientSocketFactory::CreateSSLClientSocket(
    SSLClientContext* context,
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config) {
  return ClientSocketFactory::GetDefaultFactory()->CreateSSLClientSocket(
      context, std::move(stream_socket), host_and_port, ssl_config);
}

}  // namespace net
