#include "trillek-game.hpp"
#include "graphics/renderable.hpp"
#include "graphics/camera.hpp"
#include "graphics/six-dof-camera.hpp"
#include "graphics/shader.hpp"
#include "graphics/light.hpp"
#include "graphics/render-layer.hpp"
#include "graphics/render-list.hpp"
#include "systems/graphics.hpp"
#include "systems/gui.hpp"
#include "systems/sound-system.hpp"
#include "systems/lua-system.hpp"
#include "resources/md5anim.hpp"
#include "resources/pixel-buffer.hpp"
#include "hardware/cpu.hpp"
#include "interaction.hpp"

#include "components/component-factory.hpp"
#include "components/component-templates.hpp"
#include "physics/collidable.hpp"
#include "resources/md5mesh.hpp"
#include "resources/md5anim.hpp"
#include "resources/obj.hpp"
#include "resources/pixel-buffer.hpp"
#include "resources/text-file.hpp"

#include "systems/physics.hpp"
#include "systems/resource-system.hpp"
#include "systems/transform-system.hpp"
#include "util/json-parser.hpp"

namespace trillek {
/** \brief Type of component
 *
 * Dynamic: The component is passed to the system and then stored in the
 * ComponentFactory container
 * System : The component is passed to SystemComponent and is stored there
 * Shared : The component is passed to SharedComponent and is stored there
 *
 * SystemValue is like system, but for primitive values that don't need a pointer
 * to be passed as argument of a function (bool, uint32_t).
 *
 * Only Shared components can be shared between systems in different threads.
 * By default, Dynamic components are registered.
 *
 * The preferred choice is System.
 */

using component::Component;

void graphics::RenderSystem::RegisterTypes() {
    // textures are implicitly instanced most of the time
    RegisterClassGenParser<graphics::Texture>();
    RegisterClassGenParser<graphics::Shader>();
    RegisterClassGenParser<graphics::RenderAttachment>();
    RegisterClassGenParser<graphics::RenderLayer>();
    RegisterClassGenParser<graphics::RenderList>();
    RegisterStaticParsers();
    RegisterListResolvers();
}

void ComponentFactory::RegisterTypes() {
    RegisterComponentType(ComponentAdder<System,Component::Collidable>());
    RegisterComponentType(ComponentAdder<Shared,Component::Velocity>());
    RegisterComponentType(ComponentAdder<Shared,Component::VelocityMax>());
    RegisterComponentType(ComponentAdder<SystemValue,Component::ReferenceFrame>());
    RegisterComponentType(ComponentAdder<SystemValue,Component::IsReferenceFrame>());
    RegisterComponentType(ComponentAdder<System,Component::CombinedVelocity>());
    RegisterComponentType(ComponentAdder<SystemValue, Component::OxygenRate>());
    RegisterComponentType(ComponentAdder<SystemValue, Component::Health>());
    RegisterComponentType(ComponentAdder<SystemValue,Component::Movable>());
    RegisterComponentType(ComponentAdder<Shared,Component::GraphicTransform>());
    RegisterComponentType(ComponentAdder<Shared,Component::GameTransform>());
    RegisterComponentType(ComponentAdder<System,Component::VComputer>());
    RegisterComponentType(ComponentAdder<System,Component::VDisplay>());
    RegisterComponentType(ComponentAdder<System,Component::VKeyboard>());
    RegisterComponentType(ComponentAdder<System,Component::Renderable>());
    RegisterComponentType(ComponentAdder<System,Component::Light>());
    RegisterComponentType(ComponentAdder<System,Component::Camera>());
}

void gui::GuiSystem::RegisterTypes() {
    RegisterHandler("lua", &game.GetLuaSystem());
}

void util::JSONPasrser::RegisterTypes() {
    RegisterParser(game.GetGraphicsInstance());
    RegisterParser(sound::System::GetInstance());
    RegisterParser(resource::ResourceMap::GetInstance());
    RegisterParser(TransformMap::GetInstance());
    RegisterParser(ComponentFactory::GetInstance());
}

void resource::ResourceMap::RegisterTypes() {
    RegisterResourceType<resource::TextFile>();
    RegisterResourceType<resource::MD5Mesh>();
    RegisterResourceType<resource::OBJ>();
    RegisterResourceType<resource::PixelBuffer>();
    RegisterResourceType<resource::MD5Anim>();
}

} // End of trillek
