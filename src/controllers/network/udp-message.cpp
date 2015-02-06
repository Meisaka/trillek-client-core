#include "controllers/network/udp-message.hpp"


#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek { namespace network {

void UDPMessage::Send(uint8_t major, uint8_t minor, uint64_t timestamp) {
    auto fd = TrillekGame::GetNetworkSystem().GetUDPHandle();
    SetTimestamp(timestamp + TrillekGame::GetNetworkSystem().UDPCounter());
    Message::Send(fd, major, minor, TrillekGame::GetNetworkSystem().HasherUDP(),
        Tail<unsigned char*>(), VMAC_SIZE);
}
} // network
} // trillek
