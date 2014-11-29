#include "controllers/network/authentication-handler.hpp"
#include "controllers/network/network-controller.hpp"
#include <cstring>
#include "controllers/network/connection-data.hpp"
#include "composites/network-node.hpp"
#include "controllers/network/VMAC-stream-hasher.hpp"
#include "controllers/network/ESIGN-signature.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek { namespace network {

std::shared_ptr<chain_t> Authentication::auth_init_handler;
std::string Authentication::password;
CryptoPP::FixedSizeAlignedSecBlock<byte,16> Authentication::secret_key;

void Authentication::CreateSecureKey(const trillek_list<std::shared_ptr<Message>>& req_list) {
    // client side
    for(auto& req : req_list) {
        // We received reply
        req->RemoveVMACTag();
        auto msg = reinterpret_cast<unsigned char*>(req->FrameHeader());
        NetworkController &client = TrillekGame::GetNetworkSystem();
        auto v = client.Verifier();
        if ((v)(req->Tail<const unsigned char*>(), msg, req->PacketSize()) && req->CxData()->SetAuthState(AUTH_SHARE_KEY)) {
            auto pkt = req->Content<KeyReplyPacket>();
            auto key = make_unique<std::vector<unsigned char>>(PUBLIC_KEY_SIZE);
            std::memcpy(key->data(), &pkt->challenge, PUBLIC_KEY_SIZE);
            client.SetEntityID(pkt->entity_id);
            //Authentication::GetNetworkSystem<CLIENT>()->SetServerPublicKey(std::move(key));
            auto esign = std::make_shared<cryptography::ESIGN_Signature>();
            esign->SetPublicKey(std::move(key));
            esign->Initialize();
            client.SetVerifier(esign->Verifier());
            client.SetAuthState(AUTH_SHARE_KEY);
			LOGMSG(DEBUG) << "Authentication OK";
            client.is_connected.notify_all();
        }
        else {
			LOGMSG(ERROR) << "Authentification failed: Could not authenticate the server";
            req->CxData()->SetAuthState(AUTH_NONE);
            client.SetAuthState(AUTH_NONE);
            client.CloseConnection(req.get());
            client.is_connected.notify_all();
        }
    }
}

Message SendSaltPacket::GetKeyExchangePacket() {
    // Client received salt
    Message frame{};
    auto packet = frame.Content<KeyExchangePacket>();
    // Derive password and salt to get key
    Crypto::PBKDF(Authentication::GetSecretKey(),
            reinterpret_cast<const byte*>(Authentication::Password().data()),
            Authentication::Password().size(), salt, SALT_SIZE);
    std::memcpy(packet->salt, salt, SALT_SIZE);
    Crypto::GetRandom64(packet->nonce);
    Crypto::GetRandom128(packet->nonce2);
    Crypto::GetRandom128(packet->alea);
    Crypto::VMAC64(packet->vmac, frame.Content<KeyExchangePacket,const byte>(),
             VMAC_MSG_SIZE, Authentication::GetSecretKey(), packet->nonce);
    return std::move(frame);
}

std::unique_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> KeyExchangePacket::VMAC_BuildHasher() const {
    // client side
    // The variable that will hold the hasher key for this session
    auto checker_key = make_unique<CryptoPP::FixedSizeAlignedSecBlock<byte,16>>();
    // We derive the player key using the alea given by the player
    Crypto::VMAC128(checker_key->data(), alea, ALEA_SIZE, Authentication::GetSecretKey(), nonce2);
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
    for(auto& req : req_list) {
        if (req->CxData()->SetAuthState(AUTH_KEY_EXCHANGE)) {
            // We must send keys
            auto frame = req->Content<SendSaltPacket>()->GetKeyExchangePacket();
            auto packet = frame.Content<KeyExchangePacket>();
            // TODO !!!!!
            auto hasher_key = std::move(packet->VMAC_BuildHasher());
            LOGMSG(DEBUG) << "Sending keys : " << frame.PacketSize()
                    << " bytes, key is " << std::hex << (uint64_t) hasher_key->data();
            auto authentifier = std::allocate_shared<cryptography::VMAC_StreamHasher>
                            (TrillekAllocator<cryptography::VMAC_StreamHasher>(),
                             std::move(hasher_key),
                             packet->nonce2, 8);
            client.SetHasher(authentifier->Hasher());
            client.SetVerifier(authentifier->Verifier());
            client.SetAuthState(AUTH_KEY_EXCHANGE);
            frame.SendMessageNoVMAC(req->fd, NET_MSG, AUTH_KEY_EXCHANGE);
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
