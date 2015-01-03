#ifndef AUTHENTICATIONHANDLER_H_INCLUDED
#define AUTHENTICATIONHANDLER_H_INCLUDED

#include <cstdint>
#include <memory>
#include "trillek.hpp"
#include "atomic-map.hpp"
#include "atomic-queue.hpp"
#include "controllers/network/crypto.hpp"
#include "controllers/network/message.hpp"
#include "trillek-scheduler.hpp"
#include "controllers/network/packet-handler.hpp"
//#include <utmpx.h>

#define LOGIN_FIELD_SIZE	16
#define SALT_SIZE			8
#define ALEA_SIZE			16
#define NONCE2_SIZE			16
#define	NONCE_SIZE			8
#define PUBLIC_KEY_SIZE     32

#define AUTH_NONE			0
#define AUTH_INIT			1
#define AUTH_KEY_EXCHANGE	2
#define AUTH_SHARE_KEY		3
#define AUTHENTICATED		4
#define AUTH_SEND_SALT		5
#define AUTH_KEY_REPLY		6

// The server stores salt and SHA-256(salt,SHA-256(login|":"|password)), salt being chosen randomly

namespace trillek { namespace network {

struct GetSaltTaskRequest;
struct KeyExchangePacket;
class Message;

namespace cryptography {
class VMAC_StreamHasher;
}

struct SendSaltPacket {
    byte salt[SALT_SIZE];								// the stored number used as salt for password
    Message GetKeyExchangePacket();
};

struct KeyExchangePacket;

struct KeyReplyPacket {
    friend KeyExchangePacket;
    byte challenge[PUBLIC_KEY_SIZE]; // the challenge is also the public key of the server
    id_t entity_id;
};

struct KeyExchangePacket {
    byte salt[SALT_SIZE];
    byte alea[ALEA_SIZE];								// Random number used to derive the shared secret for TCP
    byte alea2[ALEA_SIZE];								// Random number used to derive the shared secret for UDP
    byte nonce2[NONCE2_SIZE];							// A random number used as nonce for the TCP VMAC hasher to build
    byte nonce3[NONCE2_SIZE];							// A random number used as nonce for the UDP VMAC hasher to build
    byte nonce[NONCE_SIZE];								// a random number used as nonce for the VMAC of this packet

    std::unique_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> VMAC_BuildHasher1() const;
    std::unique_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> VMAC_BuildHasher2() const;
};

class Authentication final {
    friend Message SendSaltPacket::GetKeyExchangePacket();
    friend std::unique_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> KeyExchangePacket::VMAC_BuildHasher1() const;
    friend std::unique_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> KeyExchangePacket::VMAC_BuildHasher2() const;

public:
    Authentication() {};

    static void SetPassword(const std::string& password) { Authentication::password = password; };

    static void CheckKeyExchange(const trillek_list<std::shared_ptr<Message>>& req_list);
    static void CreateSecureKey(const trillek_list<std::shared_ptr<Message>>& req_list);
    static std::shared_ptr<chain_t> GetAuthInitHandler() { return auth_init_handler; };

    static const std::string& Password() { return password; };

    static std::shared_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> GetSecretKey() { return secret_key; };

    static std::shared_ptr<chain_t> auth_init_handler;
    static std::string password;
    static std::shared_ptr<CryptoPP::FixedSizeAlignedSecBlock<byte,16>> secret_key;
};

struct AuthInitPacket {
    msg_hdr header;
    char login[LOGIN_FIELD_SIZE];
};

struct GetSaltTaskRequest {
    GetSaltTaskRequest(int fd, char login[LOGIN_FIELD_SIZE]) : fd(fd), login(login) {};
    SendSaltPacket packet;
    char* login;
    int fd;
};

namespace packet_handler {
    template<>
    void PacketHandler::Process<NET_MSG,AUTH_SEND_SALT>() const;

    template<>
    void PacketHandler::Process<NET_MSG,AUTH_KEY_REPLY>() const;
} // packet_handler
} // network
} // trillek

#endif // AUTHENTICATIONHANDLER_H_INCLUDED
