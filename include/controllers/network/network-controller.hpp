#ifndef NETWORKCONTROLLER_H_INCLUDED
#define NETWORKCONTROLLER_H_INCLUDED

#include <thread>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <algorithm>
#include "trillek.hpp"
#include "controllers/network/io-poller.hpp"
#include "atomic-queue.hpp"
#include <network>
#include "controllers/network/message-unauthenticated.hpp"
#include "controllers/network/reliable-udp-message.hpp"
#include "controllers/network/tcp-message.hpp"
#include "controllers/network/udp-message.hpp"
#include "controllers/network/authentication-handler.hpp"
#include "controllers/network/frame-request.hpp"
#include "controllers/network/packet-handler-templates.hpp"
#include "controllers/network/connection-data.hpp"

// the maximum number of bytes a message can contain
#define MAX_MESSAGE_SIZE    65535

// the number of events we get at each call of the event handler
#define EVENT_LIST_SIZE     32

// the maximum number of bytes we will process from each authenticated socket
// at each call of the event handler
#define MAX_AUTHENTICATED_FRAME_SIZE    1460L

// the maximum number of bytes in an UDP datagram
#define MAX_UDP_DATAGRAM_SIZE           1480L

// the maximum number of bytes we will process from each unauthenticated socket
// at each call of the event handler
#define MAX_UNAUTHENTICATED_FRAME_SIZE  128L

namespace trillek {

namespace memory {
    template<size_t size> class StreamAllocator;
}

namespace network {

using net::socket_t;
using net::recv;
using net::TCPConnection;
using net::UDPSocket;

class IOPoller;
class GetSaltTaskRequest;

namespace packet_handler {
class PacketHandler;
}

class NetworkController final {

public:
    friend void packet_handler::PacketHandler::Process<NET_MSG,AUTH_SEND_SALT>() const;
    friend void Authentication::CheckKeyExchange(const trillek_list<std::shared_ptr<Message>>& req_list);
    friend void Authentication::CreateSecureKey(const trillek_list<std::shared_ptr<Message>>& req_list);
    friend void TCPMessage::Send(uint8_t major, uint8_t minor);
    friend void UDPMessage::Send(uint8_t major, uint8_t minor, uint64_t timestamp);
    friend void UDPReliableMessage::Send(uint8_t major, uint8_t minor, uint64_t timestamp);
    friend UDPReliableMessage::allocator_type UDPReliableMessage::GetAllocator();

    NetworkController();
    ~NetworkController() {}

    /** \brief Initialize the network controller
     *
     * \param host const std::string& the local address to bind to
     * \param port uint16_t the port to bind
     */
    void Initialize(const std::string& host, uint16_t port);

    /** \brief Connect a client to a server
     *
     * \param host const std::string& the host to connect to
     * \param port the port to connect to
     * \param login the login to use
     * \param password the password to use
     * \return bool true if connected, false otherwise
     */
    bool Connect(const std::string& host, uint16_t port,
                 const std::string& login, const std::string& password) const;

    /** \brief Return the entity ID given by the server
     *
     * To be used only on the client side
     *
     * \return const std::vector<unsigned char>* the entity id
     */
    id_t EntityID() const { return entity_id; }

    /** \brief Return the verifier functor used to check the tag of each packet received
     *
     * \return the verifier functor
     */
    std::function<bool(const uint8_t*, const uint8_t*, size_t)>& ESIGNVerifier() {
        return esign_verifier;
    }

    /** \brief Return the verifier functor used to check the tag of each packet received by TCP
     *
     * \return the verifier functor
     */
    std::function<bool(const uint8_t*, const uint8_t*, size_t, uint64_t)>& VMACVerifierTCP() {
        return vmac_verifier_tcp;
    }

    /** \brief Return the verifier functor used to check the tag of each packet received by UDP
     *
     * \return the verifier functor
     */
    std::function<bool(const uint8_t*, const uint8_t*, size_t, uint64_t)>& VMACVerifierUDP() {
        return vmac_verifier_udp;
    }

    /** \brief Initialize the TCP handler
     */
    void SetTCPHandler() {
        handle_events = chain_t({
            [&] () { return HandleEvents(); },
            [&] () { return UDPFrameProcessing(&auth_checked_frame_req); },
            [&] () { return AuthenticatedDispatch(); }
        });

        tcp_recv_data = chain_t({
            [&] () { return ReassembleFrame<TCPMessage>(&auth_rawframe_req, &auth_checked_frame_req); },
            [&] () { return AuthenticatedDispatch(); }
        });

        unauthenticated_recv_data = chain_t({
            [&] () { return ReassembleFrame<MessageUnauthenticated,false>(&pub_rawframe_req, &pub_frame_req); },
            [&] () { return UnauthenticatedDispatch(); }
        });
    }

    /** \brief Return the instance of the packet handler
     *
     * \return const network_packet_handler::PacketHandler& the instance
     */
    const packet_handler::PacketHandler& GetPacketHandler() const {
        return packet_handler;
    }

private:

    /** \brief Set the public key that will be used to authenticate packets
     * received from the server.
     *
     * This function is used by the client when it receives the key from the server
     *
     * \param key the public key (32 bytes)
     */
    void SetServerPublicKey(std::vector<uint8_t>&& key) {
        serverPublicKey = std::move(key);
    }

    /** \brief Set the hasher functor that will be used to add a tag to each TCP packet sent
     *
     * \param hasher the hasher functor
     */
    void SetHasherTCP(std::function<void(uint8_t*, const uint8_t*, size_t, uint64_t)>&& hasher) {
        this->hasher_tcp = std::move(hasher);
    }

    /** \brief Return the hasher functor used to add a tag to each TCP packet sent
     *
     * \return the hasher functor
     */
    std::function<void(uint8_t*, const uint8_t*, size_t, uint64_t)>& HasherTCP() {
        return hasher_tcp;
    }

    /** \brief Set the hasher functor that will be used to add a tag to each UDP packet sent
     *
     * \param hasher the hasher functor
     */
    void SetHasherUDP(std::function<void(uint8_t*, const uint8_t*, size_t, uint64_t)>&& hasher) {
        this->hasher_udp = std::move(hasher);
    }

    /** \brief Return the hasher functor used to add a tag to each UDP packet sent
     *
     * \return the hasher functor
     */
    std::function<void(uint8_t*, const uint8_t*, size_t, uint64_t)>& HasherUDP() {
        return hasher_udp;
    }

    /** \brief Set the verifier functor that will be used to check the tag of each packet received
     *
     * \param verifier the verifier functor
     */
    void SetESIGNVerifier(std::function<bool(const uint8_t*, const uint8_t*, size_t)>&& verifier) {
        this->esign_verifier = std::move(verifier);
    }

    /** \brief Set the verifier functor that will be used to check the tag of each packet received
     *
     * \param verifier the verifier functor
     */
    void SetVMACVerifierTCP(std::function<bool(const uint8_t*, const uint8_t*, size_t, int64_t)>&& verifier) {
        this->vmac_verifier_tcp = std::move(verifier);
    }

    /** \brief Set the verifier functor that will be used to check the tag of each packet received
     *
     * \param verifier the verifier functor
     */
    void SetVMACVerifierUDP(std::function<bool(const uint8_t*, const uint8_t*, size_t, int64_t)>&& verifier) {
        this->vmac_verifier_udp = std::move(verifier);
    }

    /** \brief Set the authentication state
     *
     * \param state the state
     */
    bool SetAuthState(uint32_t state) const {
        return session_state->SetAuthState(state);
    }

    /** \brief Get the authentication state
     *
     * \return uint32_t the state
     */
    uint32_t AuthState() const {
        return session_state ? session_state->AuthState() : AUTH_NONE;
    };

    const AtomicQueue<std::shared_ptr<Frame_req>>* const GetAuthenticatedRawFrameReqQueue() const {
        return &auth_rawframe_req;
    }
    const AtomicQueue<std::shared_ptr<Message>>* const GetAuthenticatedCheckedFrameQueue() const {
        return &auth_checked_frame_req;
    }
    const AtomicQueue<std::shared_ptr<Frame_req>>* const GetPublicRawFrameReqQueue() const {
        return &pub_rawframe_req;
    }
    const AtomicQueue<std::shared_ptr<Message>>* const GetPublicReassembledFrameQueue() const {
        return &pub_frame_req;
    }

    const IOPoller* const Poller() const { return &poller; }

    /** \brief Handle the network events in a non-blocking way
     *
     * \return int return code for the scheduler
     */
    int HandleEvents() const;

    /** \brief Close the connection
     *
     * \return void
     */
    void CloseConnection() const;

    /** \brief Dispatch the unauthenticated frames to the packet handlers
     *
     * Specialized in Networktemplates.cpp
     *
     * \return int return code for the scheduler
     */
    int UnauthenticatedDispatch() const;

    /** \brief Dispatch the authenticated frames to the packet handlers
     *
     * Specialized in Networktemplates.cpp
     *
     * \return int return code for the scheduler
     */
    int AuthenticatedDispatch() const;

    /** \brief Process UDP datagrams
     *
     * \param output const AtomicQueue<std::shared_ptr<Message>>*const the queue where to put the messages
     * \return int thez return code for the scheduler
     */
    int UDPFrameProcessing(const AtomicQueue<std::shared_ptr<Message>>* const output) const;

    /** \brief Return the public key used to check packets received from the server
     *
     * To be used only on client side
     *
     * \return const std::vector<unsigned char>* the key
     */
    const std::vector<uint8_t>* ServerPublicKey() const { return &serverPublicKey; }

    /** \brief Set the entity ID given by the server
     *
     * Used only by the client
     *
     * \param eid the entity ID given as a vector
     */
    void SetEntityID(id_t eid) { entity_id = eid; }

    /** \brief Increment and return the counter value
     *
     * \return std::uint_least16_t the counter
     */
    std::uint_least16_t UDPCounter() const {
        return ++udp_counter;
    }

    /** \brief Return the allocator for the send buffer of UDP reliable
     * messages.
     *
     * \return a copy of the allocator
     */
    UDPReliableMessage::allocator_type ReliableUDPBufferAllocator() {
        return UDPReliableMessage::allocator_type(reliable_udp_buffer_alloc.get());
    }

    socket_t GetTCPHandle() const { return TCP_server_handle; }
    socket_t GetUDPHandle() const { return UDP_server_handle; }

    TCPConnection* GetTCPConnection() const { return TCP_server_socket.get(); };
    UDPSocket* GetUDPSocket() const { return udp_socket.get(); }

    // instance of the kqueue
    const IOPoller poller;

    // instance of the authentication handler
    const Authentication authentication;

    // instance of the packet_handler
    const packet_handler::PacketHandler packet_handler;

    // chain of block functions
    chain_t tcp_recv_data;
    chain_t unauthenticated_recv_data;
    chain_t handle_events;

    // The queues that will contain the work to do for each block
    const AtomicQueue<std::shared_ptr<Frame_req>> auth_rawframe_req;     // raw frame request, to be authenticated
    const AtomicQueue<std::shared_ptr<Message>> auth_checked_frame_req;  // reassembled frame request, authenticated
    const AtomicQueue<std::shared_ptr<Frame_req>> pub_rawframe_req;      // raw frame requests
    const AtomicQueue<std::shared_ptr<Message>> pub_frame_req;           // reassembled frame request

    std::vector<uint8_t> serverPublicKey;
    std::function<bool(const uint8_t*, const uint8_t*, size_t)> esign_verifier;
    std::function<bool(const uint8_t*, const uint8_t*, size_t, uint64_t)> vmac_verifier_tcp;
    std::function<bool(const uint8_t*, const uint8_t*, size_t, uint64_t)> vmac_verifier_udp;
    std::function<void(uint8_t*, const uint8_t*, size_t, uint64_t)> hasher_tcp;
    std::function<void(uint8_t*, const uint8_t*, size_t, uint64_t)> hasher_udp;

    mutable std::unique_ptr<ConnectionData> session_state;

    // the listening socket, static because all threads must read it
    static std::unique_ptr<TCPConnection> TCP_server_socket;
    static socket_t TCP_server_handle;

    mutable std::unique_ptr<UDPSocket> udp_socket;
    socket_t UDP_server_handle;
    // counter added to the timestamp to produce a unique ID
    mutable std::atomic_uint_least16_t udp_counter;

    mutable std::mutex m_connection_data_tcp;

    // used to observe the connection process result from another thread
    mutable std::condition_variable is_connected;
    // mutex associated with the unique_lock
    mutable std::mutex connecting;
    // the entity ID provided by the server
    id_t entity_id;
    // the allocator for reliable UDP buffer
    std::unique_ptr<UDPReliableMessage::raw_allocator_type> reliable_udp_buffer_alloc;

    /** \brief Process the frame requests of input and put the reassembled messages in output
     *
     * T is the mode type (client, server, etc.)
     * checkAuth is the authentification tag to check, by default same as T
     *
     * The input may still have uncomplete frame requests when the function returns.
     *
     * \param input const AtomicQueue<std::shared_ptr<Frame_req>>*const the input queue
     * \param output const AtomicQueue<std::shared_ptr<Message>>*const the output queue
     * \return int return code
     */
    template<class M, bool checkAuth = true>
    int ReassembleFrame(const AtomicQueue<std::shared_ptr<Frame_req>>* const input,
            const AtomicQueue<std::shared_ptr<Message>>* const output) const {
        auto req_list = input->Poll();
        trillek_list<std::shared_ptr<Frame_req>> temp_input;
        trillek_list<std::shared_ptr<Message>> temp_output;
        if (req_list.empty()) {
            return STOP;
        }
        auto ret = CONTINUE;
//      LOG_DEBUG << "(" << sched_getcpu() << ") got " << req_list->size() << " Reassemble events";
        for (auto& req : req_list) {
            // Remember that each socket is locked to the current thread
            auto target_size = req->length_requested;
//          LOG_DEBUG << "(" << sched_getcpu() << ")  Reassembling " << target_size << " bytes";
            auto frame = req->reassembled_frames_list.back().get();
            char* buffer = reinterpret_cast<char*>(frame->FrameHeader());

            auto current_size = req->length_got;
            int len;
            len = recv(req->fd, reinterpret_cast<char*>(buffer) + current_size, target_size - current_size);
            if(len < 0) {
//              LOG_ERROR << "(" << sched_getcpu() << ") Could not read data";
                continue;
            }

            current_size += len;
            req->length_got = current_size;

            if (current_size == sizeof(Frame_hdr) && target_size == sizeof(Frame_hdr)) {
                // We now have the length
                target_size = frame->FrameHeader()->length + sizeof(Frame_hdr);
                if (target_size < sizeof(Frame_hdr)) {
                    LOGMSG(WARNING) << "Integer overflow attempt in packet header. Closing.";
                    CloseConnection();
                    continue;
                }
                // we check that the frame will  enter in the alllocated buffer and is under the maximum size allowed
                if (target_size > frame->BufferSize()) {
                    LOGMSG(DEBUG) << "Message of size " << std::hex << target_size
                        << " bigger than buffer size of " << frame->BufferSize();
                    CloseConnection();
                    continue;
                }
//              LOG_DEBUG << "(" << sched_getcpu() << ")  Completing message to " << target_size << " bytes in a frame of " << req->length_total << " bytes";
                req->length_requested = target_size;
                frame->SetIndexPosition(target_size);
                buffer = reinterpret_cast<char*>(frame->FrameHeader());
                len = recv(req->fd, reinterpret_cast<char*>(buffer) + current_size, target_size - current_size);
                if (len < 0) {
//                  LOG_ERROR << "(" << sched_getcpu() << ") Could not read data";
                    continue;
                }
                current_size += len;
                req->length_got = current_size;
            }

            if (current_size < target_size) {
                // missing bytes
                if (req->HasExpired()) {
                    // Frame reassembly is stopped after 3 seconds if message is uncomplete
//                  LOG_DEBUG << "(" << sched_getcpu() << ") Dropping all frames and closing (timeout)";
                    CloseConnection();
                    continue;
                }
                // we put again the request in the queue
//              LOG_DEBUG << "(" << sched_getcpu() << ") got only " << current_size << " bytes, waiting " << target_size << " bytes";
                temp_input.push_back(std::move(req));
                if (ret == CONTINUE) {
                    ret = REPEAT;
                }
            }
            else {
                if ( current_size < req->length_total ) {
                    // message retrieved, but there are still bytes to read
//                  LOG_DEBUG << "(" << sched_getcpu() << ") Packet of " << current_size << " put in frame queue.";
                    req->length_total -= current_size;
                    req->length_got = 0;
                    req->length_requested = sizeof(Frame_hdr);
//                  LOG_DEBUG << "(" << sched_getcpu() << ") Get another packet #" << req->reassembled_frames_list.size() << " from fd #" << frame->fd << " frome same frame.";

                    req->reassembled_frames_list.push_back(Message::New<M>(MAX_MESSAGE_SIZE, req->CxData(), req->fd));
                    // reset the timestamp to now
                    req->UpdateTimestamp();
                    // requeue the frame request for next message
                    temp_input.push_back(std::move(req));
                    ret = REPEAT;
                }
                else {
                    // request completed
                    // check integrity
                    req->CheckIntegrityTag<checkAuth>();
                    // We allow again events on this socket
                    poller.Watch(req->fd);

//                  LOG_DEBUG << "(" << sched_getcpu() << ") Moving " << req->reassembled_frames_list.size() << " messages with a total of " << req->length_got << " bytes to queue";
                    // Put the messages in the queue for next step
                    temp_output.splice(temp_output.end(), std::move(req->reassembled_frames_list));
                    if(ret == REPEAT) {
                        // there are still uncomplete frames, so we requeue the current block
                        ret = SPLIT;
                    }
                }
            }
        }
        // we reinject the undone work for the next job
        input->PushList(std::move(temp_input));
        // we push the result of the current job
        output->PushList(std::move(temp_output));
        return ret;
    }
};
} // network
} // trillek

#endif // NETWORKCONTROLLER_H_INCLUDED
