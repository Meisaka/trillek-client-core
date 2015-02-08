#include "trillek-game.hpp"
#include "systems/gui.hpp"
#include "trillek-scheduler.hpp"
#include "os.hpp"
#include "systems/fake-system.hpp"
#include "controllers/network/network-controller.hpp"
#include "systems/physics.hpp"
#include "systems/meta-engine-system.hpp"
#include "systems/sound-system.hpp"
#include "systems/graphics.hpp"
#include "systems/lua-system.hpp"
#include "systems/gui.hpp"
#include "systems/vcomputer-system.hpp"
#include "interaction.hpp"
#include "components/component.hpp"

namespace trillek {

TrillekGame game;

TrillekGame::TrillekGame() {
    close_window = false;
}
TrillekGame::~TrillekGame() {}

void TrillekGame::Terminate() {
    vcomputer_system.reset();
    engine_sys.reset();
    gui_system.reset();
    lua_sys.reset();
    gl_sys_ptr.reset();
    fake_system.reset();
    glfw_os.reset();
    phys_sys.reset();
    network_system.reset();
    scheduler.reset();
}

void TrillekGame::Initialize() {
    ActionText::RegisterStatic();
    scheduler.reset(new TrillekScheduler);
    fake_system.reset(new FakeSystem);
    network_system.reset(new network::NetworkController);
    phys_sys.reset(new physics::PhysicsSystem);
    glfw_os.reset(new OS);
    lua_sys.reset(new script::LuaSystem());
    gl_sys_ptr.reset(new graphics::RenderSystem());
    gl_sys_ptr->RegisterTypes();
    gui_system.reset(new gui::GuiSystem(GetOS(), *gl_sys_ptr.get()));
    close_window = false;
    engine_sys.reset(new MetaEngineSystem);
    vcomputer_system.reset(new VComputerSystem);
}

scheduler_tp TrillekGame::Now() {
    return TaskRequestBase::Now();
}

sound::System& TrillekGame::GetSoundSystem() {
    return *sound::System::GetInstance();
}

graphics::RenderSystem& TrillekGame::GetGraphicSystem() {
    return *gl_sys_ptr.get();
}

OS& TrillekGame::GetOS() {
    return *glfw_os.get();
}

id_t TrillekGame::GetCameraEntity() {
    return gl_sys_ptr->GetActiveCameraID();
}

gui::GuiSystem& TrillekGame::GetGUISystem() {
    return *gui_system.get();
}

std::shared_ptr<graphics::RenderSystem> TrillekGame::GetGraphicsInstance() {
    return std::shared_ptr<graphics::RenderSystem>(gl_sys_ptr);
}

} // End of namespace trillek
