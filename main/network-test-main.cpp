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
        for(auto i = 0; i < 10; ++i) {
                auto msg_buffer = std::make_shared<std::vector<char,trillek::TrillekAllocator<char>>>(trillek::TrillekAllocator<char>());
                msg_buffer->resize(100);
                trillek::network::Message packet(msg_buffer, 0);
                std::string str("This is a big very big text ! #");
                packet << str.append(std::to_string(i));
                packet.SendTCP(TEST_MSG, TEST_MSG_TCP);
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
        for (auto& message : pkt) {
            message->SendUDP(TEST_MSG, TEST_MSG_UDP, timestamp);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        pkt = trillek::TrillekGame::GetNetworkSystem().GetPacketHandler().GetQueue<TEST_MSG,TEST_MSG_UDP>().Poll();
        if (pkt.size() == 10) {
            std::cout << "UDP Test successful." << std::endl;
        }
        else {
            std::cout << "UDP test failed." << pkt.size() << std::endl;
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
