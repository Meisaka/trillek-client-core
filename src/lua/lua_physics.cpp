#include "systems/lua-system.hpp"

#include <luawrapper/luawrapper.hpp>
#include <luawrapper/luawrapperutil.hpp>

#include "lua/lua_velocity.hpp"
#include "lua/lua_glm.hpp"

#include "components/component.hpp"
#include "systems/physics.hpp"
#include "transform.hpp"
#include "trillek-game.hpp"
#include "logging.hpp"

namespace trillek {
namespace script {

static int Physics_get(lua_State* L) {
    luaW_push<physics::PhysicsSystem>(L, &game.GetPhysicsSystem());
    return 1;
}

static int SetMovable(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    int entity_id = luaL_checkint(L, 2);
    int b = lua_toboolean(L, 3);
    auto v_ptr = component::Create<component::Component::Movable>((b != 0));
    physSys->AddCommand(entity_id, std::move(v_ptr));
    return 0;
}
static int GetMovable(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    int entity_id = luaL_checkint(L, 2);
    bool m = component::Get<component::Component::Movable>(entity_id);
    lua_pushboolean(L, m? 1 : 0);
    return 1;
}

static int SetMoving(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    int entity_id = luaL_checkint(L, 2);
    int b = lua_toboolean(L, 3);
    auto v_ptr = component::Create<component::Component::Moving>((b != 0));
    physSys->AddCommand(entity_id, std::move(v_ptr));
    return 0;
}
static int GetMoving(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    int entity_id = luaL_checkint(L, 2);
    bool m = component::Get<component::Component::Moving>(entity_id);
    lua_pushboolean(L, m? 1 : 0);
    return 1;
}

static int SetVelocity(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    int entity_id = luaL_checkint(L, 2);
    physics::VelocityStruct f = luaU_check<physics::VelocityStruct>(L, 3);
    auto player_orientation = component::Get<component::Component::GraphicTransform>(entity_id).GetOrientation();
    auto camera_orientation = glm::toMat4(std::move(player_orientation));
    physics::VelocityStruct g(camera_orientation * f.linear, camera_orientation * f.angular);
    std::shared_ptr<component::Container> v_ptr = component::Create<component::Component::Velocity>(std::move(g));
    physSys->AddCommand(entity_id, std::move(v_ptr));

    return 0;
}

static int PhysRayDist(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    lua_pushnumber(L, physSys->GetLastRayDistance());
    return 1;
}

static int PhysRayPos(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    glm::vec3 const lpos = physSys->GetLastRayPos();
    luaU_push<glm::vec3>(L, lpos);
    return 1;
}

static int PhysRayInval(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    physSys->RaySetInvalid();
    return 0;
}

static int PhysRayCast(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    id_t entity = physSys->RayCast();
    lua_pushinteger(L, entity);
    return 1;
}

static int PhysRayCastIg(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    id_t entity_id = luaL_checkunsigned(L, 2);
    id_t entity = physSys->RayCastIgnore(entity_id);
    lua_pushinteger(L, entity);
    return 1;
}

static int SetGravity(lua_State* L) {
    auto physSys = luaW_check<physics::PhysicsSystem>(L, 1);
    int entity_id = luaL_checkint(L, 2);
    if (lua_type(L, 3) == LUA_TNIL) {
        physSys->SetNormalGravity(entity_id);
    }
    else {
        physics::VelocityStruct f = luaU_check<physics::VelocityStruct>(L, 3);
        physSys->SetGravity(entity_id, f.GetLinear());
    }

    return 0;
}

static luaL_Reg Physics_table[] =
{
    { "Get", Physics_get },
    { nullptr, nullptr } // table end marker
};

static luaL_Reg Physics_metatable[] =
{
    { "set_velocity", SetVelocity },
    { "set_movable", SetMovable },
    { "get_movable", GetMovable },
    { "set_moving", SetMoving },
    { "get_moving", GetMoving },
    { "set_gravity", SetGravity },
    { "ray_cast", PhysRayCast },
    { "ray_casti", PhysRayCastIg },
    { "ray_dist", PhysRayDist },
    { "ray_pos", PhysRayPos },
    { "ray_invalidate", PhysRayInval },
    { nullptr, nullptr } // table end marker
};

int luaopen_PhysSys(lua_State* L) {
    luaW_register<physics::PhysicsSystem>(L,
        "Physics",
        Physics_table,
        Physics_metatable,
        nullptr // If your class has a default constructor you can omit this argument,
        // LuaWrapper will generate a default allocator for you.
        );
    return 1;
}

} // End of script
} // End of trillek
