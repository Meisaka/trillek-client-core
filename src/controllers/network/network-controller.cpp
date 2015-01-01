#include "controllers/network/network-controller.hpp"

#include <chrono>
#include <cstring>
#include <typeinfo>
#include <iostream>
#include "controllers/network/ESIGN-signature.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"
#include <thread>

namespace trillek { namespace network {

std::unique_ptr<TCPConnection> NetworkController::TCP_server_socket;
socket_t NetworkController::TCP_server_handle;

NetworkController::NetworkController() {};

void NetworkController::Initialize(const std::string& host, uint16_t port) {
    if (! poller.Initialize()) {
        LOGMSG(ERROR) << "FATAL : Could not initialize kqueue !";
        TrillekGame::NotifyCloseWindow();
    }
    // Open UDP socket
    auto cnx_udp = make_unique<UDPSocket>();
    if (! cnx_udp->init(NETA_IPv4)) {
        LOGMSG(ERROR) << "FATAL : Could not initialize socket.";
        return;
    }
    auto fd = cnx_udp->get_handle();
    set_nonblocking(fd, true);
    NetworkAddress listen_address(host, port);
    if (! cnx_udp->bind(listen_address)) {
        LOGMSG(ERROR) << "FATAL : Invalid address/port";
        return;
    }
    poller.Create(fd);
    this->udp_socket = std::move(cnx_udp);
    this->UDP_server_handle = fd;
}

bool NetworkController::Connect(const std::string& host, uint16_t port,
                        const std::string& login, const std::string& password) const {
    NetworkAddress myaddress(host, port);
    {
        std::unique_lock<std::mutex> locker(m_connection_data_tcp);
        if (TCP_server_socket) {
            // already connected
            return false;
        }
        auto tr = std::make_shared<TaskRequest<chain_t>>(handle_events);
        TrillekGame::GetScheduler().Queue(tr);

        authentication.SetPassword(password);

        auto cnx = make_unique<TCPConnection>();
        if (! cnx->init(myaddress)) {
            LOGMSG(ERROR) << "FATAL : Invalid address/port";
            return false;
        }

        if (! cnx->connect(myaddress)) {
            LOGMSG(ERROR) << "FATAL : No network";
            return false;
        }
        auto fd = cnx->get_handle();
        poller.Create(fd);
        auto node_data = std::allocate_shared<NetworkNodeData>(TrillekAllocator<NetworkNodeData>(), cnx->remote());
        auto cd = make_unique<ConnectionData>(AUTH_INIT,std::move(node_data));
        this->session_state = std::move(cd);
        this->TCP_server_socket = std::move(cnx);

        auto msg_buffer = std::make_shared<std::vector<char,TrillekAllocator<char>>>(TrillekAllocator<char>());
        msg_buffer->resize(sizeof(AuthInitPacket) + sizeof(Frame) + 8);
        Message packet(msg_buffer);
        std::strncpy(packet.Content<AuthInitPacket, char>(), login.c_str(), LOGIN_FIELD_SIZE - 1);
        packet.SendMessageNoVMAC(fd, NET_MSG, AUTH_INIT);
    }
    std::unique_lock<std::mutex> locker(connecting);
    while (AuthState() != AUTH_SHARE_KEY && AuthState() != AUTH_NONE) {
        is_connected.wait_for(locker, std::chrono::seconds(5),
            [&]() {
                return (AuthState() == AUTH_SHARE_KEY || AuthState() == AUTH_NONE);
            });
    }
    if (AuthState() == AUTH_SHARE_KEY) {
        return this->GetUDPSocket()->connect(myaddress);
    }
    {
        std::unique_lock<std::mutex> locker(m_connection_data_tcp);
        TCP_server_socket.reset();
    }
    return false;
}

// This function is the 1st element of the handle_events chain.
int NetworkController::HandleEvents() const {
    trillek_list<std::shared_ptr<Frame_req>> temp_public;
    trillek_list<std::shared_ptr<Frame_req>> temp_auth;
    trillek_list<std::shared_ptr<Frame_req>> temp_udp;

    bool a = false, b = false, c = false;

    std::vector<struct kevent> evList(EVENT_LIST_SIZE);
    auto nev = Poller()->Poll(evList);
    if (nev < 0) {
        std::cout << "(" << std::this_thread::get_id() << ") Error when polling event" << std::endl;
    }

    for (auto i=0; i<nev; i++) {
//        LOGMSG(DEBUG) << "(" << std::this_thread::get_id() << ") loop on " << nev << " events.";
        auto fd = evList[i].ident;
        if (evList[i].flags & EV_EOF) {
            // connection closed
            CloseConnection();
            continue;
        }
        if (evList[i].flags & EV_ERROR) {
            std::cout << "EV_ERROR: " << evList[i].data << std::endl;
            continue;
        }
        if (evList[i].flags & EVFILT_READ) {
            if (fd == GetUDPHandle()) {
                // data received by UDP
                c = true;
            }
            else {
                // TCP Data received
                // the socket is only accessed by the current thread
                auto buffer = std::make_shared<std::vector<char,TrillekAllocator<char>>>(TrillekAllocator<char>());
                if (! this->session_state->CompareAuthState(AUTH_SHARE_KEY)) {
                    // Data received, not authenticated
                    // Request the frame header
                    // queue the task to reassemble the frame
                    auto max_size = std::min(evList[i].data, static_cast<intptr_t>(MAX_UNAUTHENTICATED_FRAME_SIZE));
                    buffer->resize(MAX_MESSAGE_SIZE);
                    auto msg = std::allocate_shared<MessageUnauthenticated>
                                            (TrillekAllocator<MessageUnauthenticated>(), buffer, 0, MAX_MESSAGE_SIZE, this->session_state.get(), fd);
                    auto f = std::allocate_shared<Frame_req,TrillekAllocator<Frame_req>>
                                            (TrillekAllocator<Frame_req>(),fd, max_size, this->session_state.get(), std::move(msg));
                    temp_public.push_back(std::move(f));
                    a = true;
                }
                else {
                    // Data received from authenticated client
                    auto max_size = std::min(evList[i].data, static_cast<intptr_t>(MAX_AUTHENTICATED_FRAME_SIZE));
                    buffer->resize(MAX_MESSAGE_SIZE);
                    auto msg = std::allocate_shared<Message>
                                            (TrillekAllocator<Message>(), buffer, 0, MAX_MESSAGE_SIZE, this->session_state.get());
                    auto f = std::allocate_shared<Frame_req,TrillekAllocator<Frame_req>>
                                            (TrillekAllocator<Frame_req>(),fd, max_size, this->session_state.get(), std::move(msg));
                    temp_auth.push_back(std::move(f));
                    b = true;
                }
            }
        }
    }

    if (c) {
        TrillekGame::GetScheduler().Queue(std::make_shared<TaskRequest<chain_t>>(udp_recv_data));
    }
    if (a) {
        // if we got data from unauthenticated clients, push the public reassemble task
        GetPublicRawFrameReqQueue()->PushList(std::move(temp_public));
        TrillekGame::GetScheduler().Queue(std::make_shared<TaskRequest<chain_t>>(unauthenticated_recv_data));
    }
    if (b) {
        // if we got data from authenticated clients, push the data
        GetAuthenticatedRawFrameReqQueue()->PushList(std::move(temp_auth));
        // continue on private reassemble, and requeue the present block
        return SPLIT;
    }
    else {
        // Queue a task to wait another event
        return REQUEUE;
    }
}

int NetworkController::UDPFrameProcessing(const AtomicQueue<std::shared_ptr<Message>>* const output) const {
    auto fd = GetUDPHandle();
    std::list<std::shared_ptr<Message>,TrillekAllocator<std::shared_ptr<Message>>> reassembled_frames_list;
    auto msg_buffer = std::make_shared<std::vector<char,TrillekAllocator<char>>>(TrillekAllocator<char>());
    msg_buffer->resize(static_cast<intptr_t>(MAX_UDP_FRAME_SIZE));
    auto frame = std::allocate_shared<Message>(TrillekAllocator<Message>(),msg_buffer);
    char* buffer = reinterpret_cast<char*>(frame->FrameHeader());
    int len;
    while ((len = recv(fd, buffer, static_cast<intptr_t>(MAX_UDP_FRAME_SIZE))) > 0) {
//        LOGMSG(DEBUG) << "(" << std::this_thread::get_id() << ") Read " << len << " bytes from network";
        // request completed
        frame->SetIndexPosition(len);
        reassembled_frames_list.push_back(std::move(frame));
        msg_buffer = std::make_shared<std::vector<char,TrillekAllocator<char>>>(TrillekAllocator<char>());
        msg_buffer->resize(static_cast<intptr_t>(MAX_UDP_FRAME_SIZE));
        frame = std::allocate_shared<Message>(TrillekAllocator<Message>(),msg_buffer,0);
        buffer = reinterpret_cast<char*>(frame->FrameHeader());
    }
    // check integrity
//    LOGMSG(DEBUG) << "(" << std::this_thread::get_id() << ") Checking integrity for " << reassembled_frames_list.size() << " messages.";
    reassembled_frames_list.remove_if(
        [](const std::shared_ptr<Message>& message) {
            auto size_to_check = message->PacketSize() - ESIGN_SIZE;
            message->RemoveTailClient();
            auto tail = message->Tail<msg_tail*>();
            return tail->entity_id !=
                TrillekGame::GetNetworkSystem().EntityID() ||
                ! (TrillekGame::GetNetworkSystem().Verifier())(
                    tail->tag, reinterpret_cast<uint8_t*>(message->FrameHeader()),
                    size_to_check);
        });
    // We unlock the socket
    poller.Watch(fd);

//    LOGMSG(DEBUG) << "(" << std::this_thread::get_id() << ") Moving " << reassembled_frames_list.size() << " messages.";
    // we push the result of the current job
    output->PushList(std::move(reassembled_frames_list));
    return CONTINUE;
}

void NetworkController::CloseConnection() const {
    auto fd = GetTCPHandle();
    poller.Delete(fd);
    close(fd);
    SetAuthState(AUTH_NONE);
    is_connected.notify_all();
}

int NetworkController::UnauthenticatedDispatch() const {
    auto req_list = GetPublicReassembledFrameQueue()->Poll();
    if (req_list.empty()) {
        return STOP;
    }
    trillek_list<std::shared_ptr<Message>> temp_send_salt;
    trillek_list<std::shared_ptr<Message>> temp_key_reply;
//					LOG_DEBUG << "(" << sched_getcpu() << ") got " << req_list->size() << " PublicDispatchReq events";
    for (auto& req : req_list) {
        msg_hdr* header = req->Header();
        auto major = header->type_major;
        if (IS_RESTRICTED(major)) {
//                LOG_DEBUG << "restricted";
            CloseConnection();
            break;
        }
        switch(major) {
        case NET_MSG:
            {
                auto minor = header->type_minor;
                switch(minor) {
                    case AUTH_SEND_SALT:
                        {
                            temp_send_salt.push_back(std::move(req));
                            break;
                        }
                    case AUTH_KEY_REPLY:
                        {
                            temp_key_reply.push_back(std::move(req));
                            break;
                        }
                    default:
                        {
//                                LOG_DEBUG << "(" << sched_getcpu() << ") invalid minor code, closing";
                            CloseConnection();
                        }
                }
                break;
            }
        default:
            {
//                    LOG_DEBUG << "(" << sched_getcpu() << ") invalid major code in unauthenticated chain, packet of " << req->PacketSize() << " bytes, closing";
                CloseConnection();
            }
        }
    }
    if(! temp_send_salt.empty()) {
        packet_handler.GetQueue<NET_MSG,AUTH_SEND_SALT>().PushList(std::move(temp_send_salt));
        packet_handler.Process<NET_MSG,AUTH_SEND_SALT>();
    }
    if(! temp_key_reply.empty()) {
        packet_handler.GetQueue<NET_MSG,AUTH_KEY_REPLY>().PushList(std::move(temp_key_reply));
        packet_handler.Process<NET_MSG,AUTH_KEY_REPLY>();
    }
    return STOP;

}

int NetworkController::AuthenticatedDispatch() const {
    auto req_list = NetworkController::GetAuthenticatedCheckedFrameQueue()->Poll();
    if (req_list.empty()) {
        return STOP;
    }
    trillek_list<std::shared_ptr<Message>> test_msg_tcp_list;
    trillek_list<std::shared_ptr<Message>> test_msg_udp_list;
//					LOG_DEBUG << "(" << sched_getcpu() << ") got " << req_list->size() << " AuthenticatedCheckedDispatchReq events";
    for (auto& req : req_list) {
        msg_hdr* header = req->Header();
        auto major = header->type_major;
        switch(major) {
            // select handlers
        case TEST_MSG:
            {
                auto minor = header->type_minor;
                switch(minor) {
                    case TEST_MSG_TCP:
                        {
                            test_msg_tcp_list.push_back(std::move(req));
                            break;
                        }
                    case TEST_MSG_UDP:
                        {
                            test_msg_udp_list.push_back(std::move(req));
                            break;
                        }
                    default:
                        {
//                                LOG_ERROR << "(" << sched_getcpu() << ") TEST: closing";
                            CloseConnection();
                        }
                }
                break;
            }

        default:
            {
//                    LOG_ERROR << "(" << sched_getcpu() << ") Authenticated switch: closing";
                CloseConnection();
            }
        }
    }
    if (! test_msg_tcp_list.empty()) {
        packet_handler.GetQueue<TEST_MSG,TEST_MSG_TCP>().PushList(std::move(test_msg_tcp_list));
    }
    if (! test_msg_udp_list.empty()) {
        packet_handler.GetQueue<TEST_MSG,TEST_MSG_UDP>().PushList(std::move(test_msg_udp_list));
    }
    return STOP;
}

} // network
} // trillek
