#include "controllers/network/tcp-message.hpp"

#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek {
namespace network {

void TCPMessage::Send(uint8_t major, uint8_t minor) {
    auto &netsys = game.GetNetworkSystem();
    auto fd = netsys.GetTCPHandle();
    Message::Send(fd, major, minor, netsys.HasherTCP(),
        Tail<uint8_t*>(), VMAC_SIZE);
}

} // network
} // trillek
