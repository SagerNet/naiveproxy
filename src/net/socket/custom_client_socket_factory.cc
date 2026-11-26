// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/custom_client_socket_factory.h"

#include <memory>
#include <string>
#include <utility>

#include "base/containers/circular_deque.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/thread_annotations.h"
#include "base/threading/scoped_blocking_call.h"
#include "build/build_config.h"

#if BUILDFLAG(IS_WIN)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "base/posix/eintr_wrapper.h"
#endif
#if BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_BSD)
#include <sys/event.h>

#include "base/files/scoped_file.h"
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
#include "net/socket/read_multiple_emulator.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/tcp_socket.h"
#include "net/socket/udp_client_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#if !BUILDFLAG(IS_WIN)
#include "net/socket/socket_posix.h"
#endif

namespace net {

class CustomClientSocketFactory::DialQueue
    : public base::RefCountedThreadSafe<DialQueue> {
 public:
  DialQueue() = default;
  DialQueue(const DialQueue&) = delete;
  DialQueue& operator=(const DialQueue&) = delete;

  void Post(base::OnceClosure task, bool limited) {
    {
      base::AutoLock lock(lock_);
      if (limited) {
        if (limited_workers_ == kMaxConcurrentDials) {
          tasks_.push_back(std::move(task));
          return;
        }
        ++limited_workers_;
      }
      ++workers_;
    }
    if (!base::ThreadPool::PostTask(
            FROM_HERE,
            {base::MayBlock(), base::TaskPriority::USER_BLOCKING,
             base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
            base::BindOnce(&DialQueue::Run, base::WrapRefCounted(this),
                           std::move(task), limited))) {
      base::AutoLock lock(lock_);
      FinishWorkerLocked(limited);
    }
  }

  void WaitForIdle() {
    base::AutoLock lock(lock_);
    while (workers_ != 0) {
      idle_.Wait();
    }
  }

 private:
  friend class base::RefCountedThreadSafe<DialQueue>;
  ~DialQueue() = default;

  static constexpr size_t kMaxConcurrentDials = 16;

  void Run(base::OnceClosure task, bool limited) {
    while (true) {
      std::move(task).Run();
      base::AutoLock lock(lock_);
      if (!limited || tasks_.empty()) {
        FinishWorkerLocked(limited);
        return;
      }
      task = std::move(tasks_.front());
      tasks_.pop_front();
    }
  }

  void FinishWorkerLocked(bool limited) EXCLUSIVE_LOCKS_REQUIRED(lock_) {
    if (limited) {
      --limited_workers_;
    }
    if (--workers_ == 0) {
      idle_.Broadcast();
    }
  }

  base::Lock lock_;
  base::ConditionVariable idle_{&lock_};
  size_t workers_ GUARDED_BY(lock_) = 0;
  size_t limited_workers_ GUARDED_BY(lock_) = 0;
  base::circular_deque<base::OnceClosure> tasks_ GUARDED_BY(lock_);
};

namespace {

// INET6_ADDRSTRLEN is 46 which is enough for any IPv4 or IPv6 address string.
constexpr size_t kLocalAddressBufferSize = 46;

class DialResult {
 public:
  DialResult() = default;
  DialResult(const DialResult&) = delete;
  DialResult& operator=(const DialResult&) = delete;
  DialResult(DialResult&& other) { *this = std::move(other); }
  DialResult& operator=(DialResult&& other) {
    Reset();
    rv = std::exchange(other.rv, ERR_FAILED);
    socket = std::exchange(other.socket, kInvalidSocket);
    local_address = std::move(other.local_address);
    local_port = std::exchange(other.local_port, 0);
    on_close = std::move(other.on_close);
    return *this;
  }
  ~DialResult() { Reset(); }

  void SetDialerResult(intptr_t result) {
    if (result >= 0) {
      rv = OK;
      socket = static_cast<SocketDescriptor>(result);
    } else {
      rv = static_cast<int>(result);
    }
  }

  SocketDescriptor TakeSocket() {
    return std::exchange(socket, kInvalidSocket);
  }

  void Reset() {
    if (socket != kInvalidSocket) {
#if BUILDFLAG(IS_WIN)
      closesocket(socket);
#else
      IGNORE_EINTR(close(socket));
#endif
      socket = kInvalidSocket;
    }
    if (on_close) {
      std::move(on_close).Run();
    }
  }

  int rv = ERR_FAILED;
  SocketDescriptor socket = kInvalidSocket;
  std::string local_address;
  uint16_t local_port = 0;
  base::OnceClosure on_close;
};

class PendingDial : public base::RefCountedThreadSafe<PendingDial> {
 public:
  using DialCallback = base::OnceCallback<DialResult()>;

  static scoped_refptr<PendingDial> Start(
      CustomClientSocketFactory::DialQueue* dial_queue,
      const IPEndPoint& address,
      DialCallback dial,
      base::OnceClosure reply) {
    auto pending_dial = base::MakeRefCounted<PendingDial>();
    dial_queue->Post(
        base::BindOnce(&PendingDial::Run, pending_dial, std::move(dial),
                       base::SequencedTaskRunner::GetCurrentDefault(),
                       std::move(reply)),
        !address.address().IsLoopback() || address.port() != 53);
    return pending_dial;
  }

  PendingDial() = default;
  PendingDial(const PendingDial&) = delete;
  PendingDial& operator=(const PendingDial&) = delete;

  DialResult Take() {
    base::AutoLock lock(lock_);
    return std::move(result_);
  }

  void Abandon() {
    DialResult result;
    base::AutoLock lock(lock_);
    abandoned_ = true;
    result = std::move(result_);
  }

 private:
  friend class base::RefCountedThreadSafe<PendingDial>;
  ~PendingDial() = default;

  void Run(DialCallback dial,
           scoped_refptr<base::SequencedTaskRunner> reply_task_runner,
           base::OnceClosure reply) {
    {
      base::AutoLock lock(lock_);
      if (abandoned_) {
        return;
      }
    }
    DialResult result;
    {
      base::ScopedBlockingCall scoped_blocking_call(
          FROM_HERE, base::BlockingType::WILL_BLOCK);
      result = std::move(dial).Run();
    }
    {
      base::AutoLock lock(lock_);
      if (abandoned_) {
        return;
      }
      result_ = std::move(result);
    }
    reply_task_runner->PostTask(FROM_HERE, std::move(reply));
  }

  base::Lock lock_;
  bool abandoned_ GUARDED_BY(lock_) = false;
  DialResult result_ GUARDED_BY(lock_);
};

DialResult DialTCP(CustomClientSocketFactory::DialerCallback dialer,
                   const IPEndPoint& address) {
  DialResult result;
  result.SetDialerResult(
      dialer.Run(address.ToStringWithoutPort(), address.port()));
  return result;
}

DialResult DialUDP(CustomClientSocketFactory::UdpDialerCallback dialer,
                   const IPEndPoint& address) {
  DialResult result;
  char local_address[kLocalAddressBufferSize] = {0};
  result.SetDialerResult(dialer.Run(address.ToStringWithoutPort(),
                                    address.port(), local_address,
                                    &result.local_port, &result.on_close));
  result.local_address = local_address;
  return result;
}

// A DatagramClientSocket that wraps a socket fd returned by a custom dialer.
// This socket can be:
// - AF_INET/AF_INET6 SOCK_DGRAM: Standard UDP socket (may be connected)
// - AF_UNIX SOCK_DGRAM: Unix domain datagram socket (Unix/macOS/Linux)
// - AF_UNIX SOCK_STREAM: Unix domain stream socket (Windows, with framing)
//
// The socket is NOT connected by Chromium - the dialer is expected to return
// a ready-to-use socket. For AF_UNIX SOCK_STREAM, length-prefix framing is used
// to preserve datagram boundaries.
class ConnectedDatagramClientSocket
    : public DatagramClientSocket,
      public CustomClientSocketFactory::PendingConnect {
 public:
  ConnectedDatagramClientSocket(
      CustomClientSocketFactory::UdpDialerCallback dialer,
      base::WeakPtr<CustomClientSocketFactory> factory,
      scoped_refptr<CustomClientSocketFactory::DialQueue> dial_queue,
      net::NetLog* net_log,
      const NetLogSource& source)
      : dialer_(std::move(dialer)),
        factory_(std::move(factory)),
        dial_queue_(std::move(dial_queue)),
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
    return DoConnectAsync(address, std::move(callback));
  }

  int ConnectUsingNetworkAsync(handles::NetworkHandle network,
                               const IPEndPoint& address,
                               CompletionOnceCallback callback) override {
    if (network != handles::kInvalidNetworkHandle) {
      return ERR_NOT_IMPLEMENTED;
    }
    return DoConnectAsync(address, std::move(callback));
  }

  int ConnectUsingDefaultNetworkAsync(
      const IPEndPoint& address,
      CompletionOnceCallback callback) override {
    return DoConnectAsync(address, std::move(callback));
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
#if BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_BSD)
    return CheckReceiveShutdown(socket_->Read(
        buf, buf_len,
        base::BindOnce(&ConnectedDatagramClientSocket::OnDatagramReadComplete,
                       base::Unretained(this), std::move(callback))));
#else
    return socket_->Read(buf, buf_len, std::move(callback));
#endif
  }

  base::expected<DatagramsMetadata, Error> ReadMultiple(
      IOBuffer* buf,
      size_t buf_len,
      size_t max_message_size,
      base::OnceCallback<void(base::expected<DatagramsMetadata, Error>)>
          callback) override {
    return read_multiple_emulator_.ReadMultiple(buf, buf_len, max_message_size,
                                                std::move(callback));
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
    AbandonPendingConnect();
    connect_callback_.Reset();
    connected_ = false;
    socket_.reset();
    if (on_close_) {
      std::move(on_close_).Run();
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

  void CancelPendingConnect() override {
    AbandonPendingConnect();
    CompletionOnceCallback callback = std::move(connect_callback_);
  }

  int DoConnect(const IPEndPoint& address) {
    if (connected_) {
      return OK;
    }
    return AdoptDialResult(DialUDP(dialer_, address), address);
  }

  int DoConnectAsync(const IPEndPoint& address,
                     CompletionOnceCallback callback) {
    if (connected_) {
      return OK;
    }
    connect_callback_ = std::move(callback);
    pending_dial_ = PendingDial::Start(
        dial_queue_.get(), address, base::BindOnce(&DialUDP, dialer_, address),
        base::BindOnce(&ConnectedDatagramClientSocket::OnDialComplete,
                       weak_factory_.GetWeakPtr(), address));
    if (factory_) {
      factory_->AddPendingConnect(this);
    }
    return ERR_IO_PENDING;
  }

  void OnDialComplete(const IPEndPoint& address) {
    if (factory_) {
      factory_->RemovePendingConnect(this);
    }
    DialResult result = pending_dial_->Take();
    pending_dial_ = nullptr;
    std::move(connect_callback_)
        .Run(AdoptDialResult(std::move(result), address));
  }

  void AbandonPendingConnect() {
    if (factory_) {
      factory_->RemovePendingConnect(this);
    }
    if (pending_dial_) {
      pending_dial_->Abandon();
      pending_dial_ = nullptr;
    }
    weak_factory_.InvalidateWeakPtrs();
  }

  int AdoptDialResult(DialResult result, const IPEndPoint& address) {
    if (result.rv != OK) {
      return result.rv;
    }

    SocketDescriptor socket_fd = result.TakeSocket();

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
      socket_.reset();
      return rv;
    }

    local_address_ = IPEndPoint();
    if (!result.local_address.empty()) {
      IPAddress ip;
      if (ip.AssignFromIPLiteral(result.local_address)) {
        local_address_ = IPEndPoint(ip, result.local_port);
      }
    }
    if (!local_address_.address().IsValid()) {
      local_address_ = IPEndPoint(address.address(), 0);
    }

    on_close_ = std::move(result.on_close);
    peer_address_ = address;
    connected_ = true;
    return OK;
  }

#if BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_BSD)
  // After shutdown(SHUT_RD) or a NetworkExtension flow-divert close, XNU and
  // the BSDs complete every read on a datagram socket with 0 bytes instead of
  // blocking; EVFILT_READ reporting EV_EOF is what distinguishes this from an
  // empty datagram.
  int CheckReceiveShutdown(int rv) {
    if (rv != 0) {
      return rv;
    }
    base::ScopedFD kqueue_fd(kqueue());
    if (!kqueue_fd.is_valid()) {
      return rv;
    }
    struct kevent change;
    EV_SET(&change, socket_->socket_fd(), EVFILT_READ, EV_ADD, 0, 0, nullptr);
    struct kevent event;
    const struct timespec timeout = {};
    if (HANDLE_EINTR(kevent(kqueue_fd.get(), &change, 1, &event, 1,
                            &timeout)) == 1 &&
        (event.flags & EV_EOF)) {
      return ERR_CONNECTION_CLOSED;
    }
    return rv;
  }

  void OnDatagramReadComplete(CompletionOnceCallback callback, int rv) {
    std::move(callback).Run(CheckReceiveShutdown(rv));
  }
#endif

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
  base::WeakPtr<CustomClientSocketFactory> factory_;
  scoped_refptr<CustomClientSocketFactory::DialQueue> dial_queue_;
  scoped_refptr<PendingDial> pending_dial_;
  CompletionOnceCallback connect_callback_;
  base::OnceClosure on_close_;
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

  ReadMultipleEmulator read_multiple_emulator_{this};

  base::WeakPtrFactory<ConnectedDatagramClientSocket> weak_factory_{this};
};

class CustomTransportClientSocket
    : public TransportClientSocket,
      public CustomClientSocketFactory::PendingConnect {
 public:
  CustomTransportClientSocket(
      CustomClientSocketFactory::DialerCallback dialer,
      base::WeakPtr<CustomClientSocketFactory> factory,
      scoped_refptr<CustomClientSocketFactory::DialQueue> dial_queue,
      const AddressList& addresses,
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      class NetLog* net_log,
      const NetLogSource& source)
      : dialer_(std::move(dialer)),
        factory_(std::move(factory)),
        dial_queue_(std::move(dial_queue)),
        addresses_(addresses),
        net_log_(net_log),
        source_(source),
        unconnected_socket_(TCPSocket::Create(
            std::move(socket_performance_watcher), net_log, source)) {}

  ~CustomTransportClientSocket() override { AbandonPendingConnect(); }

  void CancelPendingConnect() override {
    AbandonPendingConnect();
    CompletionOnceCallback callback = std::move(connect_callback_);
  }

  int Bind(const IPEndPoint& local_addr) override {
    return ERR_NOT_IMPLEMENTED;
  }

  bool SetNoDelay(bool no_delay) override {
    return socket_ && socket_->SetNoDelay(no_delay);
  }

  bool SetKeepAlive(bool enable, int delay_secs) override {
    return socket_ && socket_->SetKeepAlive(enable, delay_secs);
  }

  int Connect(CompletionOnceCallback callback) override {
    if (socket_) {
      return OK;
    }
    if (addresses_.empty()) {
      return ERR_NAME_NOT_RESOLVED;
    }
    connect_callback_ = std::move(callback);
    address_index_ = 0;
    DialCurrentAddress();
    if (factory_) {
      factory_->AddPendingConnect(this);
    }
    return ERR_IO_PENDING;
  }

  void Disconnect() override {
    AbandonPendingConnect();
    connect_callback_.Reset();
    if (socket_) {
      socket_.reset();
      unconnected_socket_ = TCPSocket::Create(nullptr, net_log_, source_);
      unconnected_socket_->ApplySocketTag(socket_tag_);
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
    return socket_->GetPeerAddress(address);
  }

  int GetLocalAddress(IPEndPoint* address) const override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->GetLocalAddress(address);
  }

  const NetLogWithSource& NetLog() const override {
    if (socket_) {
      return socket_->NetLog();
    }
    return unconnected_socket_->net_log();
  }

  bool WasEverUsed() const override {
    return socket_ && socket_->WasEverUsed();
  }

  NextProto GetNegotiatedProtocol() const override {
    return NextProto::kProtoUnknown;
  }

  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }

  int64_t GetTotalReceivedBytes() const override {
    return socket_ ? socket_->GetTotalReceivedBytes() : 0;
  }

  void ApplySocketTag(const SocketTag& tag) override {
    socket_tag_ = tag;
    if (socket_) {
      socket_->ApplySocketTag(tag);
    } else {
      unconnected_socket_->ApplySocketTag(tag);
    }
  }

  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->Read(buf, buf_len, std::move(callback));
  }

  int ReadIfReady(IOBuffer* buf,
                  int buf_len,
                  CompletionOnceCallback callback) override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->ReadIfReady(buf, buf_len, std::move(callback));
  }

  int CancelReadIfReady() override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->CancelReadIfReady();
  }

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    if (!socket_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_->Write(buf, buf_len, std::move(callback),
                          traffic_annotation);
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
  void DialCurrentAddress() {
    const IPEndPoint& address = addresses_[address_index_];
    pending_dial_ = PendingDial::Start(
        dial_queue_.get(), address, base::BindOnce(&DialTCP, dialer_, address),
        base::BindOnce(&CustomTransportClientSocket::OnDialComplete,
                       weak_factory_.GetWeakPtr()));
  }

  void OnDialComplete() {
    DialResult result = pending_dial_->Take();
    pending_dial_ = nullptr;
    int rv = result.rv;
    if (rv == OK) {
      const IPEndPoint& endpoint = addresses_[address_index_];
      rv = unconnected_socket_->AdoptConnectedSocket(result.TakeSocket(),
                                                     endpoint);
      if (rv == OK) {
        socket_ = std::make_unique<TCPClientSocket>(
            std::move(unconnected_socket_), endpoint);
      }
    }
    if (rv != OK && ++address_index_ < addresses_.size()) {
      DialCurrentAddress();
      return;
    }
    if (factory_) {
      factory_->RemovePendingConnect(this);
    }
    std::move(connect_callback_).Run(rv);
  }

  void AbandonPendingConnect() {
    if (factory_) {
      factory_->RemovePendingConnect(this);
    }
    if (pending_dial_) {
      pending_dial_->Abandon();
      pending_dial_ = nullptr;
    }
    weak_factory_.InvalidateWeakPtrs();
  }

  const CustomClientSocketFactory::DialerCallback dialer_;
  const base::WeakPtr<CustomClientSocketFactory> factory_;
  const scoped_refptr<CustomClientSocketFactory::DialQueue> dial_queue_;
  const AddressList addresses_;
  const raw_ptr<class NetLog> net_log_;
  const NetLogSource source_;
  SocketTag socket_tag_;
  std::unique_ptr<TCPSocket> unconnected_socket_;
  std::unique_ptr<TCPClientSocket> socket_;
  scoped_refptr<PendingDial> pending_dial_;
  CompletionOnceCallback connect_callback_;
  size_t address_index_ = 0;

  base::WeakPtrFactory<CustomTransportClientSocket> weak_factory_{this};
};

}  // namespace

CustomClientSocketFactory::CustomClientSocketFactory(
    DialerCallback tcp_dialer,
    UdpDialerCallback udp_dialer)
    : tcp_dialer_(std::move(tcp_dialer)),
      udp_dialer_(std::move(udp_dialer)),
      dial_queue_(base::MakeRefCounted<DialQueue>()) {
  DCHECK(tcp_dialer_ || udp_dialer_);
}

CustomClientSocketFactory::~CustomClientSocketFactory() {
  while (!pending_connects_.empty()) {
    (*pending_connects_.begin())->CancelPendingConnect();
  }
  dial_queue_->WaitForIdle();
}

void CustomClientSocketFactory::AddPendingConnect(
    PendingConnect* pending_connect) {
  pending_connects_.insert(pending_connect);
}

void CustomClientSocketFactory::RemovePendingConnect(
    PendingConnect* pending_connect) {
  pending_connects_.erase(pending_connect);
}

std::unique_ptr<DatagramClientSocket>
CustomClientSocketFactory::CreateDatagramClientSocket(
    DatagramSocket::BindType bind_type,
    handles::NetworkHandle target_network,
    NetLog* net_log,
    const NetLogSource& source) {
  if (udp_dialer_) {
    return std::make_unique<ConnectedDatagramClientSocket>(
        udp_dialer_, weak_factory_.GetWeakPtr(), dial_queue_, net_log, source);
  }
  return ClientSocketFactory::GetDefaultFactory()->CreateDatagramClientSocket(
      bind_type, target_network, net_log, source);
}

std::unique_ptr<TransportClientSocket>
CustomClientSocketFactory::CreateTransportClientSocket(
    const AddressList& addresses,
    handles::NetworkHandle target_network,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetworkQualityEstimator* network_quality_estimator,
    NetLog* net_log,
    const NetLogSource& source) {
  if (!tcp_dialer_) {
    return ClientSocketFactory::GetDefaultFactory()
        ->CreateTransportClientSocket(
            addresses, target_network, std::move(socket_performance_watcher),
            network_quality_estimator, net_log, source);
  }

  return std::make_unique<CustomTransportClientSocket>(
      tcp_dialer_, weak_factory_.GetWeakPtr(), dial_queue_, addresses,
      std::move(socket_performance_watcher), net_log, source);
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
