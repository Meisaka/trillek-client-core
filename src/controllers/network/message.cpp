#include "controllers/network/message.hpp"

#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek { namespace network {

Message::Message(const ConnectionData* cnxd, const int fd) :
        fd(fd), packet_size(sizeof(Frame)) {
    node_data = cnxd ? cnxd->GetNodeData() : std::shared_ptr<NetworkNodeData>();
    data.resize(sizeof(Frame) + sizeof(msg_tail));
}

void Message::Send(
            int fd,
            uint8_t major, uint8_t minor,
            const std::function<void(uint8_t*,const uint8_t*,size_t)>& hasher,
            uint8_t* tagptr,
            uint32_t tag_size,
            uint32_t tail_size) {
    auto header = Header();
    header->type_major = major;
    header->type_minor = minor;
    FrameHeader()->length = packet_size - sizeof(Frame_hdr) + tail_size;
    // The VMAC Hasher has been put under id #1 for client
    (hasher)(tagptr,
        reinterpret_cast<const uint8_t*>(data.data()), packet_size + tail_size - tag_size);
//		LOG_DEBUG << "Bytes to send : " << packet_size << " with tag of " << taglen << " bytes";

    if (send(fd, reinterpret_cast<char*>(FrameHeader()),
            packet_size + tail_size) <= 0) {
		LOGMSG(ERROR) << "could not send authenticated frame" ;
    };

}

void Message::SendUDP(uint8_t major, uint8_t minor) {
    auto fd = TrillekGame::GetNetworkSystem().GetUDPHandle();
    Send(fd, major, minor, TrillekGame::GetNetworkSystem().HasherUDP(),
        Tail<unsigned char*>(), VMAC_SIZE, VMAC_SIZE);
}

void Message::SendTCP(uint8_t major, uint8_t minor) {
    auto fd = TrillekGame::GetNetworkSystem().GetTCPHandle();
    Send(fd, major, minor, TrillekGame::GetNetworkSystem().HasherTCP(),
        Tail<unsigned char*>(), VMAC_SIZE, VMAC_SIZE);
}

void Message::SendMessageNoVMAC(int fd, uint8_t major, uint8_t minor) {
    if(fd < 0) {
        return;
    }
    auto header = Header();
    header->type_major = major;
    header->type_minor = minor;
    FrameHeader()->length = packet_size - sizeof(Frame_hdr);
    // TODO: Replace by raknet

    if (send(fd, reinterpret_cast<char*>(FrameHeader()), packet_size) <= 0) {
		LOGMSG(ERROR)  << "could not send frame with no tag" ;
    }

}

void Message::append(const void* in, std::size_t sizeBytes) {
    Resize(BodySize() + sizeBytes);
    std::memcpy(Tail<unsigned char*>() - sizeBytes, in, sizeBytes);
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

void Message::Resize(size_t new_size) {
    packet_size = new_size + sizeof(Frame);
    data.resize(packet_size + VMAC_SIZE);
};

void Message::ResizeNoTag(size_t new_size) {
    packet_size = new_size + sizeof(Frame);
    data.resize(packet_size);
}
} // network
} // trillek
