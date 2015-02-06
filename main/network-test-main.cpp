#include "trillek-game.hpp"
#include "controllers/network/network-controller.hpp"
#include <queue>
#include <thread>

#if defined(_MSC_VER)
// Visual Studio implements steady_clock as system_clock
// We need GLFW to geta decent clock
// TODO : wait for the fix from Microsoft
#include "os.hpp"
#endif

#include <cstddef>
#include <iostream>

size_t gAllocatedSize = 0;

int main(int argCount, char **argValues) {
    trillek::TrillekGame::Initialize();
    std::cout << "Starting Trillek network layer test (client)..." << std::endl;

#if defined(_MSC_VER)
    // Visual C++ rely on GLFW clock
    // create the window
    auto& os = trillek::TrillekGame::GetOS();
    os.InitializeWindow(800, 600, "Trillek Client Network Test", 3, 0);
    glGetError(); // clear errors
#endif

    // we register the systems in this queue
    std::queue<trillek::SystemBase*> systems;

    // register the fake system. Comment this to cancel
//  systems.push(&trillek::TrillekGame::GetFakeSystem());


    // start the scheduler in another thread
    std::thread tp(
                   &trillek::TrillekScheduler::Initialize,
                   &trillek::TrillekGame::GetScheduler(),
                   5,
                   std::ref(systems));
    // Start the client network layer
    trillek::TrillekGame::GetNetworkSystem().Initialize("localhost", 7778);
    trillek::TrillekGame::GetNetworkSystem().SetTCPHandler();


    // Try a bad password
    if (trillek::TrillekGame::GetNetworkSystem().Connect("localhost", 7777, "my_login", "bad password")) {
        std::cout << "Error : could login with wrong password" << std::endl;
    }

    // Try a good password
    if(trillek::TrillekGame::GetNetworkSystem().Connect("localhost", 7777, "my_login", "secret password")) {
        auto entity_id = trillek::TrillekGame::GetNetworkSystem().EntityID();
        for(auto i = 0; i < 10; ++i) {
                auto packet = trillek::network::Message::New<trillek::network::TCPMessage>(entity_id, 100);
                std::string str("This is a big very big TCP text ! #");
                *packet << str.append(std::to_string(i));
                packet->Send(TEST_MSG, TEST_MSG_TCP);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        auto pkt = trillek::TrillekGame::GetNetworkSystem().GetPacketHandler().GetQueue<TEST_MSG,TEST_MSG_TCP>().Poll();
        if (pkt.size() == 10) {
            std::cout << "TCP Test successful." << std::endl;
        }
        else {
            std::cout << "TCP test failed." << pkt.size() << std::endl;
        }

        auto timestamp = trillek::TrillekGame::Now().time_since_epoch().count();
        for(auto i = 0; i < 10; ++i) {
                auto packet = trillek::network::Message::New<trillek::network::UDPMessage>(entity_id, 100);
                std::string str("This is a big very big UDP text ! #");
                *packet << str.append(std::to_string(i));
                packet->Send(TEST_MSG, TEST_MSG_UDP, ++timestamp);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        pkt = trillek::TrillekGame::GetNetworkSystem().GetPacketHandler().GetQueue<TEST_MSG,TEST_MSG_UDP>().Poll();
        if (pkt.size() == 10) {
            std::cout << "UDP Test successful." << std::endl;
        }
        else {
            std::cout << "UDP test failed." << pkt.size() << std::endl;
        }

        timestamp = trillek::TrillekGame::Now().time_since_epoch().count();
        for(auto i = 0; i < 10; ++i) {
                auto packet = trillek::network::Message::New<trillek::network::UDPReliableMessage>(entity_id, 100);
                std::string str("This is a big very big UDP Reliable text ! #");
                *packet << str.append(std::to_string(i));
                packet->Send(TEST_MSG, TEST_MSG_UDP, ++timestamp);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        pkt = trillek::TrillekGame::GetNetworkSystem().GetPacketHandler().GetQueue<TEST_MSG,TEST_MSG_UDP>().Poll();
        if (pkt.size() == 10) {
            std::cout << "UDP Reliable Test successful." << std::endl;
        }
        else {
            std::cout << "UDP Reliable test failed." << pkt.size() << std::endl;
        }

        auto load_task = [&entity_id]() {
            auto packet_ptr = trillek::network::Message::New<trillek::network::UDPMessage>(entity_id, 100);
            auto& packet = *packet_ptr;
            std::string str("Load test");
            packet << str;
            auto timestamp = trillek::TrillekGame::Now().time_since_epoch().count();
            while(1) {
                packet.Send(TEST_MSG,UDP_ECHO, timestamp);
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        };
        std::thread load_thread(std::move(load_task));
        while(1) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::cout << "Echo reply received: " << trillek::TrillekGame::GetNetworkSystem().GetPacketHandler().GetQueue<TEST_MSG,TEST_MSG_UDP>().Poll().size() << std::endl;
        }
    }
    trillek::TrillekGame::NotifyCloseWindow();

#if defined(_MSC_VER)
    while (! os.Closing()) {
        os.OSMessageLoop();
    }
    tp.join();
    os.Terminate();
#else
    tp.join();
#endif

    return 0;
}
