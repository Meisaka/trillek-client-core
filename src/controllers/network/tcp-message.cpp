#include "controllers/network/tcp-message.hpp"


#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek { namespace network {

void TCPMessage::Send(uint8_t major, uint8_t minor) {
    auto fd = TrillekGame::GetNetworkSystem().GetTCPHandle();
    Message::Send(fd, major, minor, TrillekGame::GetNetworkSystem().HasherTCP(),
        Tail<unsigned char*>(), VMAC_SIZE);
}
} // network
} // trillek
