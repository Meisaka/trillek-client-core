#include "controllers/network/network-controller.hpp"

#include <chrono>
#include <cstring>
#include <typeinfo>
#include <iostream>
#include "composites/network-node.hpp"
#include "controllers/network/ESIGN-signature.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek { namespace network {

TCPConnection NetworkController::server_socket;

NetworkController::NetworkController() {};

void NetworkController::Initialize() {
    if (! poller.Initialize()) {
        LOGMSG(ERROR) << "FATAL : Could not initialize kqueue !";
        TrillekGame::NotifyCloseWindow();
    }
}

bool NetworkController::Connect(const std::string& host, uint16_t port,
                        const std::string& login, const std::string& password) {
    auto tr = std::make_shared<TaskRequest<chain_t>>(handle_events);
    TrillekGame::GetScheduler().Queue(tr);

    authentication.SetPassword(password);

    cnx = TCPConnection();
    NetworkAddress address(host, port);
    if (! cnx.init(address)) {
        return false;
    }

    if (! cnx.connect(address)) {
        return false;
    }
    auto fd = cnx.get_handle();
    poller.Create(fd, reinterpret_cast<void*>(new ConnectionData(AUTH_INIT, TCPConnection())));

    Message packet{};
    std::strncpy(packet.Content<AuthInitPacket, char>(), login.c_str(), LOGIN_FIELD_SIZE - 1);
    packet.SendMessageNoVMAC(fd, NET_MSG, AUTH_INIT);
    SetAuthState(AUTH_INIT);
    std::unique_lock<std::mutex> locker(connecting);
    while (AuthState() != AUTH_SHARE_KEY && AuthState() != AUTH_NONE) {
        is_connected.wait_for(locker, std::chrono::seconds(5),
            [&]() {
                return (AuthState() == AUTH_SHARE_KEY || AuthState() == AUTH_NONE);
            });
    }
    if (AuthState() == AUTH_SHARE_KEY) {
        return true;
    }
    return false;
}

// This function is the 1st element of the handle_events chain.
int NetworkController::HandleEvents() const {
    trillek_list<std::shared_ptr<Frame_req>> temp_public;
    trillek_list<std::shared_ptr<Frame_req>> temp_auth;
    bool a = false, b = false;

    std::vector<struct kevent> evList(EVENT_LIST_SIZE);
    auto nev = Poller()->Poll(evList);
    if (nev < 0) {
        std::cout << "(" << sched_getcpu() << ") Error when polling event" << std::endl;
    }

    for (auto i=0; i<nev; i++) {
        auto fd = evList[i].ident;
        if (evList[i].flags & EV_EOF) {
            // connection closed
            if(evList[i].udata) {
                CloseConnection(fd, reinterpret_cast<ConnectionData*>(evList[i].udata));
            }
            else {
                RemoveConnection(fd);
            }
            continue;
        }
        if (evList[i].flags & EV_ERROR) {
            std::cout << "EV_ERROR: " << evList[i].data << std::endl;
            continue;
        }

        if (fd == server_handle) {
            // new connection
            auto client = server_socket.accept();
            auto chandle = client.get_handle();
            set_nonblocking(chandle, true);
            poller.Create(chandle, reinterpret_cast<void*>(new ConnectionData(AUTH_INIT, std::move(client))));
        }
        else if (evList[i].flags & EVFILT_READ) {
            // Data received
            // we retrieve the ConnectionData instance
            auto cx_data = reinterpret_cast<ConnectionData*>(evList[i].udata);
            if (! cx_data || ! cx_data->TryLockConnection()) {
                // no instance or another thread is already on this socket ? leave
                continue;
            }
            // now the socket is locked to the current thread
            if (! cx_data->CompareAuthState(AUTH_SHARE_KEY)) {
                // Data received, not authenticated
                // Request the frame header
                // queue the task to reassemble the frame
                auto max_size = std::min(evList[i].data, static_cast<intptr_t>(MAX_UNAUTHENTICATED_FRAME_SIZE));
                auto f = std::allocate_shared<Frame_req,TrillekAllocator<Frame_req>>
                                        (TrillekAllocator<Frame_req>(),fd, max_size, cx_data);
                temp_public.push_back(std::move(f));
                a = true;
            }
            else {
                // Data received from authenticated client
                auto max_size = std::min(evList[i].data, static_cast<intptr_t>(MAX_AUTHENTICATED_FRAME_SIZE));
                auto f = std::allocate_shared<Frame_req,TrillekAllocator<Frame_req>>
                                        (TrillekAllocator<Frame_req>(),fd, max_size, cx_data);
                temp_auth.push_back(std::move(f));
                b = true;
            }
        }
    }

    if(a) {
        // if we got data from unauthenticated clients, push the public reassemble task
        GetPublicRawFrameReqQueue()->PushList(std::move(temp_public));
        TrillekGame::GetScheduler().Queue(std::make_shared<TaskRequest<chain_t>>(unauthenticated_recv_data));
    }
    if(b) {
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

void NetworkController::RemoveClientConnection() const {
    auto fd = cnx.get_handle();
    poller.Delete(fd);
    close(fd);
    SetAuthState(AUTH_NONE);
    is_connected.notify_all();
}

void NetworkController::CloseConnection(const Message* frame) const {
    delete frame->CxData();
    RemoveClientConnection();
}

void NetworkController::RemoveConnection(socket_t fd) const {
    poller.Delete(fd);
    std::cout << "closing" << std::endl;
    close(fd);
    SetAuthState(AUTH_NONE);
    is_connected.notify_all();
}

void NetworkController::CloseConnection(const socket_t fd, const ConnectionData* cx_data) const {
    RemoveConnection(fd);
    NetworkNode::RemoveEntity(cx_data->Id());
    delete cx_data;
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
            CloseConnection(req.get());
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
                            CloseConnection(req.get());
                        }
                }
                break;
            }
        default:
            {
//                    LOG_DEBUG << "(" << sched_getcpu() << ") invalid major code in unauthenticated chain, packet of " << req->PacketSize() << " bytes, closing";
                CloseConnection(req.get());
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
    trillek_list<std::shared_ptr<Message>> temp_list;
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
                    case TEST_MSG:
                        {
                            temp_list.push_back(std::move(req));
                            break;
                        }
                    default:
                        {
//                                LOG_ERROR << "(" << sched_getcpu() << ") TEST: closing";
                            CloseConnection(req.get());
                        }
                }
                break;
            }

        default:
            {
//                    LOG_ERROR << "(" << sched_getcpu() << ") Authenticated switch: closing";
                CloseConnection(req.get());
            }
        }
    }
    if (! temp_list.empty()) {
        packet_handler.GetQueue<TEST_MSG,TEST_MSG>().PushList(std::move(temp_list));
        //packet_handler.Process<TEST_MSG,TEST_MSG>();
    }
    return STOP;
}

} // network
} // trillek
