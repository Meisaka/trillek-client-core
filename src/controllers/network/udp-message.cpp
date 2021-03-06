#include "controllers/network/udp-message.hpp"

#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek {
namespace network {

void UDPMessage::Send(uint8_t major, uint8_t minor, uint64_t timestamp) {
    auto &netsys = game.GetNetworkSystem();
    auto fd = netsys.GetUDPHandle();
    SetTimestamp(timestamp + netsys.UDPCounter());
    Message::Send(fd, major, minor, netsys.HasherUDP(),
        Tail<uint8_t*>(), VMAC_SIZE);
}

} // network
} // trillek
