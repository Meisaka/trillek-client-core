#include "controllers/network/message.hpp"

#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek {
namespace network {

using net::send;

Message::Message(char* buffer, size_t size, const ConnectionData* cnxd, socket_t fd) :
        index(sizeof(Frame)), data(buffer), data_size(size) {
    node_data = cnxd ? cnxd->GetNodeData() : std::shared_ptr<NetworkNodeData>();
}

void Message::Send(socket_t fd, uint8_t major, uint8_t minor,
        const std::function<void(uint8_t*,const uint8_t*,size_t,uint64_t)>& hasher,
        uint8_t* tagptr, uint32_t tag_size) {
    Prepare(major, minor);
    SendNow(fd, hasher, tagptr, tag_size);
}

void Message::Prepare(uint8_t major, uint8_t minor) {
    auto header = Header();
    header->type_major = major;
    header->type_minor = minor;
}

void Message::SendNow(socket_t fd,
        const std::function<void(uint8_t*, const uint8_t*, size_t, uint64_t)>& hasher,
        uint8_t* tagptr, uint32_t tag_size) {
    // The VMAC Hasher has been put under id #1 for client
    FrameHeader()->length = index + tag_size - sizeof(Frame_hdr);
    assert(index + tag_size <= data_size);
    (hasher)(tagptr,
        reinterpret_cast<const uint8_t*>(data), index, Timestamp());
//  LOGMSG(DEBUG) << "Bytes to send : " << index;
    if (send(fd, reinterpret_cast<char*>(FrameHeader()), index + tag_size) <= 0) {
        LOGMSG(ERROR) << "could not send authenticated frame" ;
    };
}

id_t Message::GetId() const { return node_data->Id(); }

template<>
Message& Message::operator<<(const std::string& in) {
    append(in.c_str(), in.size() + 1);
    return *this;
}

template<>
Message& Message::operator<<(const std::vector<uint8_t>& in) {
    append(in.data(), in.size());
    return *this;
}

} // network
} // trillek
