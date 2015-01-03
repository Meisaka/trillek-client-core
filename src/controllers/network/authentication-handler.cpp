#include "controllers/network/authentication-handler.hpp"
#include "controllers/network/network-controller.hpp"
#include <cstring>
#include "controllers/network/connection-data.hpp"
#include "controllers/network/VMAC-stream-hasher.hpp"
#include "controllers/network/VMAC-datagram-hasher.hpp"
#include "controllers/network/ESIGN-signature.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek { namespace network {

std::shared_ptr<chain_t> Authentication::auth_init_handler;
std::string Authentication::password;
std::shared_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> Authentication::secret_key = std::make_shared<CryptoPP::FixedSizeAlignedSecBlock<byte,16>>();

void Authentication::CreateSecureKey(const trillek_list<std::shared_ptr<Message>>& req_list) {
    // client side
    for(auto& req : req_list) {
        // We received reply
        req->RemoveVMACTag();
        auto msg = reinterpret_cast<unsigned char*>(req->FrameHeader());
        NetworkController &client = TrillekGame::GetNetworkSystem();
        auto v = client.VMACVerifier();
        if ((v)(req->Tail<const unsigned char*>(), msg, req->PacketSize(), 0) && client.SetAuthState(AUTH_SHARE_KEY)) {
            auto pkt = req->Content<KeyReplyPacket>();
            auto key = make_unique<std::vector<unsigned char>>(PUBLIC_KEY_SIZE);
            std::memcpy(key->data(), &pkt->challenge, PUBLIC_KEY_SIZE);
            client.SetEntityID(pkt->entity_id);
            //Authentication::GetNetworkSystem<CLIENT>()->SetServerPublicKey(std::move(key));
            auto esign = std::make_shared<cryptography::ESIGN_Signature>();
            esign->SetPublicKey(std::move(key));
            esign->Initialize();
            client.SetESIGNVerifier(esign->Verifier());
			LOGMSG(DEBUG) << "Authentication OK";
            client.is_connected.notify_all();
        }
        else {
			LOGMSG(ERROR) << "Authentification failed: Could not authenticate the server";
            client.SetAuthState(AUTH_NONE);
            client.CloseConnection();
            client.is_connected.notify_all();
        }
    }
}

Message SendSaltPacket::GetKeyExchangePacket() {
    // Client received salt
    auto buffer = std::make_shared<std::vector<char,TrillekAllocator<char>>>(TrillekAllocator<char>());
    buffer->resize(sizeof(Frame)+sizeof(KeyExchangePacket)+8);
    Message frame(buffer);
    auto packet = frame.Content<KeyExchangePacket>();
    // Derive password and salt to get key
    Crypto::PBKDF(Authentication::GetSecretKey()->data(),
            reinterpret_cast<const byte*>(Authentication::Password().data()),
            Authentication::Password().size(), salt, SALT_SIZE);
    std::memcpy(packet->salt, salt, SALT_SIZE);
    Crypto::GetRandom64(packet->nonce);
    Crypto::GetRandom128(packet->nonce2);
    Crypto::GetRandom128(packet->nonce3);
    Crypto::GetRandom128(packet->alea);
    Crypto::GetRandom128(packet->alea2);
    return std::move(frame);
}

std::unique_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> KeyExchangePacket::VMAC_BuildHasher1() const {
    // client side
    // The variable that will hold the hasher key for this session
    auto checker_key = make_unique<CryptoPP::FixedSizeAlignedSecBlock<byte,16>>();
    // We derive the player key using the alea given by the player
    Crypto::VMAC128(checker_key->data(), alea, ALEA_SIZE, Authentication::GetSecretKey()->data(), nonce2);
    return std::move(checker_key);
}

std::unique_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> KeyExchangePacket::VMAC_BuildHasher2() const {
    // client side
    // The variable that will hold the hasher key for this session
    auto checker_key = make_unique<CryptoPP::FixedSizeAlignedSecBlock<byte,16>>();
    // We derive the player key using the alea given by the player
    Crypto::VMAC128(checker_key->data(), alea2, ALEA_SIZE, Authentication::GetSecretKey()->data(), nonce3);
    return std::move(checker_key);
}

namespace packet_handler {
template<>
void PacketHandler::Process<NET_MSG,AUTH_SEND_SALT>() const {
    auto req_list = GetQueue<NET_MSG,AUTH_SEND_SALT>().Poll();
    if (req_list.empty()) {
        return;
    }
    NetworkController &client = TrillekGame::GetNetworkSystem();
    for(auto& msg : req_list) {
        auto req = std::static_pointer_cast<MessageUnauthenticated>(msg);
        if (client.SetAuthState(AUTH_KEY_EXCHANGE)) {
            // We must send keys
            auto frame = req->Content<SendSaltPacket>()->GetKeyExchangePacket();
            auto packet = frame.Content<KeyExchangePacket>();
            // TCP hasher
            auto hasher_key = std::move(packet->VMAC_BuildHasher1());
            auto authentifier = std::allocate_shared<cryptography::VMAC_StreamHasher>
                            (TrillekAllocator<cryptography::VMAC_StreamHasher>(),
                             std::move(hasher_key),
                             packet->nonce2);
            client.SetHasherTCP(authentifier->Hasher());
            client.SetVMACVerifier(authentifier->Verifier());
            // UDP hasher
            hasher_key = std::move(packet->VMAC_BuildHasher2());
            auto authentifier_udp = std::allocate_shared<cryptography::VMAC_DatagramHasher>
                            (TrillekAllocator<cryptography::VMAC_DatagramHasher>(),
                             std::move(hasher_key));
            client.SetHasherUDP(authentifier_udp->Hasher());
            // set the same timestamp as the packet received.
            frame.SetTimestamp(req->Timestamp());
            auto header = frame.Header();
            header->type_major = NET_MSG;
            header->type_minor = AUTH_KEY_EXCHANGE;
            frame.FrameHeader()->length = frame.PacketSize() - sizeof(Frame_hdr) + VMAC_SIZE;
            Crypto::VMAC64(frame.Tail<byte*>(), reinterpret_cast<byte*>(frame.FrameHeader()), frame.PacketSize(),
                                                                    Authentication::GetSecretKey()->data(), packet->nonce);

            frame.SetIndexPosition(frame.PacketSize() + VMAC_SIZE);
            if (send(req->FileDescriptor(), reinterpret_cast<char*>(frame.FrameHeader()), frame.PacketSize()) <= 0) {
                LOGMSG(ERROR) << "could not send frame with no tag to fd = " << req->FileDescriptor();
            }

        }
    }
}

template<>
void PacketHandler::Process<NET_MSG,AUTH_KEY_REPLY>() const {
    auto req_list = GetQueue<NET_MSG,AUTH_KEY_REPLY>().Poll();
    if (req_list.empty()) {
        return;
    }
    Authentication::CreateSecureKey(req_list);
}
} // packet_handler
} // network

namespace reflection {
template <> inline const char* GetNetworkHandler<NET_MSG,AUTH_INIT>(void) {
    return "AuthenticationHandler";
}

template <> inline const char* GetNetworkHandler<NET_MSG,AUTH_KEY_EXCHANGE>(void) {
    return "AuthenticationHandler";
}
} // reflection
} // trillek
