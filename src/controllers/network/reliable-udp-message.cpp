#include "controllers/network/reliable-udp-message.hpp"

#include "controllers/network/network-controller.hpp"
#include "controllers/network/network-node-data.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek {
namespace network {

void UDPReliableMessage::Send(uint8_t major, uint8_t minor, uint64_t timestamp) {
    SetTimestamp(timestamp + TrillekGame::GetNetworkSystem().UDPCounter());
    Prepare(major, minor);
}

UDPReliableMessage::allocator_type UDPReliableMessage::GetAllocator() {
    return TrillekGame::GetNetworkSystem().ReliableUDPBufferAllocator();
}

} // network
} // trillek
