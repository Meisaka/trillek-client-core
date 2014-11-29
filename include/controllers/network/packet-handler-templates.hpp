#ifndef PACKETHANDLERTEMPLATES_H_INCLUDED
#define PACKETHANDLERTEMPLATES_H_INCLUDED

namespace trillek { namespace network { namespace packet_handler {
extern template void PacketHandler::Process<NET_MSG,AUTH_SEND_SALT>() const;
extern template void PacketHandler::Process<NET_MSG,AUTH_KEY_REPLY>() const;
} // packet_handler
} // network
} // trillek

#endif // PACKETHANDLERTEMPLATES_H_INCLUDED
