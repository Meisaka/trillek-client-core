#include "controllers/network/message.hpp"

#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek { namespace network {

Message::Message(const std::shared_ptr<std::vector<char,TrillekAllocator<char>>>& buffer, size_t index,
                    size_t size, const ConnectionData* cnxd, const int fd) :
        fd(fd), index(sizeof(Frame)), data(buffer, buffer->data() + index) {
    node_data = cnxd ? cnxd->GetNodeData() : std::shared_ptr<NetworkNodeData>();
    if (size) {
        if (buffer->size() < index + size) {
            buffer->resize(index + size);
        }
        data_size = size;
    }
    else {
        assert(buffer->size() > index);
        data_size = buffer->size() - index;
    }
}

void Message::Send(
            int fd,
            uint8_t major, uint8_t minor,
            const std::function<void(uint8_t*,const uint8_t*,size_t)>& hasher,
            uint8_t* tagptr,
            uint32_t tag_size) {
    auto header = Header();
    header->type_major = major;
    header->type_minor = minor;
    FrameHeader()->length = index + tag_size - sizeof(Frame_hdr);
    assert(index + tag_size <= data_size);
    // The VMAC Hasher has been put under id #1 for client
    (hasher)(tagptr,
        reinterpret_cast<const uint8_t*>(data.get()), index);
//    LOGMSG(DEBUG) << "Bytes to send : " << index;
    if (send(fd, reinterpret_cast<char*>(FrameHeader()),
            index + tag_size) <= 0) {
		LOGMSG(ERROR) << "could not send authenticated frame" ;
    };

}

void Message::SendUDP(uint8_t major, uint8_t minor) {
    auto fd = TrillekGame::GetNetworkSystem().GetUDPHandle();
    Send(fd, major, minor, TrillekGame::GetNetworkSystem().HasherUDP(),
        Tail<unsigned char*>(), VMAC_SIZE);
}

void Message::SendTCP(uint8_t major, uint8_t minor) {
    auto fd = TrillekGame::GetNetworkSystem().GetTCPHandle();
    Send(fd, major, minor, TrillekGame::GetNetworkSystem().HasherTCP(),
        Tail<unsigned char*>(), VMAC_SIZE);
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
