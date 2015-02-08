#include "trillek-game.hpp"
#include "components/component.hpp"
#include "physics/collidable.hpp"
#include "systems/transform-system.hpp"
#include "systems/physics.hpp"
#include <bullet/BulletCollision/Gimpact/btGImpactShape.h>
#include <bullet/BulletCollision/Gimpact/btGImpactCollisionAlgorithm.h>
#include "logging.hpp"
#include "user-command.hpp"

namespace trillek {
namespace physics {

using namespace component;

PhysicsSystem::PhysicsSystem() {
    last_rayvalid = false;
}
PhysicsSystem::~PhysicsSystem() { }

void PhysicsSystem::Start() {
    this->collisionConfiguration = new btDefaultCollisionConfiguration();
    this->dispatcher = new btCollisionDispatcher(this->collisionConfiguration);
    this->broadphase = new btDbvtBroadphase();
    this->solver = new btSequentialImpulseConstraintSolver();
    this->dynamicsWorld = new btDiscreteDynamicsWorld(this->dispatcher, this->broadphase, this->solver, this->collisionConfiguration);
    this->dynamicsWorld->setGravity(btVector3(0, -6.7, 0));

    // Register the collision dispatcher with the GImpact algorithm for dynamic meshes.
    btCollisionDispatcher * dispatcher = static_cast<btCollisionDispatcher *>(this->dynamicsWorld->getDispatcher());
    btGImpactCollisionAlgorithm::registerAlgorithm(dispatcher);
}

void PhysicsSystem::HandleEvents(frame_tp timepoint) {
    // Execute the commands
    auto iterator_pair = this->usercommands.GetAndTagCommandsFrom(timepoint);
    for (auto& v = iterator_pair.first; v != iterator_pair.second; ++v) {
        usercommand::Execute(v->second.first, std::move(v->second.second));
    }
    // commit velocity updates
    Commit<Component::Velocity>(timepoint);

    static frame_tp last_tp;
    this->delta = timepoint - last_tp;
    last_tp = timepoint;

    // Set the rigid bodies linear velocity. Must be done each frame otherwise,
    // other forces will stop the linear velocity.
    // We use the published list

    // First moving entities that have no combined velocity
    OnTrue(GetLastPositiveBitMap<Component::Velocity>()
            & ~Bitmap<Component::ReferenceFrame>(),
        [](id_t entity_id) {
            // first inject velocity of entities that have no reference frame
            auto& body = *Get<Component::Collidable>(entity_id).GetRigidBody();
            const auto& v = Get<Component::Velocity>(entity_id);

            body.applyCentralImpulse(v.GetLinear());
            body.setAngularVelocity(v.GetAngular());
        }
    );
    // Second moving entities with a combined velocity
    OnTrue(GetLastPositiveBitMap<Component::Velocity>()
            & Bitmap<Component::ReferenceFrame>(),
        [](id_t entity_id) {
            // combine velocity
            auto reference_id = Get<Component::ReferenceFrame>(entity_id);
            const auto& v = Get<Component::Velocity>(entity_id);
            const auto& ref_v = Get<Component::Velocity>(reference_id);
            auto& body = *Get<Component::Collidable>(reference_id).GetRigidBody();
            auto& transform = body.getCenterOfMassTransform();
            auto combined_l = transform * v.GetLinear();
            combined_l += ref_v.GetLinear();
            body.setLinearVelocity(combined_l + body.getGravity());
            auto combined_a = transform * v.GetAngular();
            combined_a += ref_v.GetAngular();
            body.setAngularVelocity(combined_a);
        }
    );

    id_t cam = game.GetCameraEntity();
    OnTrue(Bitmap<Component::Moving>(),
        [&](id_t entity_id) {
            auto& body = *Get<Component::Collidable>(entity_id).GetRigidBody();
            auto& rbody = *Get<Component::Collidable>(cam).GetRigidBody();
            auto& reftransform = rbody.getWorldTransform();
            auto npq = reftransform * btQuaternion(0,0,0,1.);
            auto npl = reftransform * btVector3(0,0,-1.5);
            if(last_rayvalid) {
                npl = last_raypos;
            }
            npl = btVector3(
                ((long)(npl.x() * 20.0)) * 0.05,
                ((long)(npl.y() * 20.0)) * 0.05,
                ((long)(npl.z() * 20.0)) * 0.05
            );
            auto ts = btTransform(btQuaternion(0,0,0,1.), npl);
            body.setWorldTransform(ts);
        }
    );

    // Third, entities with reference frame that have moved
    OnTrue(GetLastPositiveBitMap<Component::Velocity>()
            & Bitmap<Component::IsReferenceFrame>(),
        [&](id_t entity_id) {
            // todo
        }
    );

    auto not_immune = ~Bitmap<Component::Immune>();

    // display a message for entities with health < 10
    OnTrue(Lower<Component::Health>(10) & not_immune,
        [](id_t id) {
            LOGMSG(INFO) << "Entity #" << id << " health under 10 (" << Get<Component::Health>(id) << ")";
        }
    );

    // Kill entities with health and whose health is 0 and are not immune
    OnTrue(Bitmap<Component::Health>() & not_immune,
        [](id_t entity_id) {
            // this function is executed only on entitities that has a health component
            auto health = Get<Component::Health>(entity_id);
            if (health == 0) {
                //kill entity
                LOGMSG(INFO) << "Entity #" << entity_id << " should die now";
                //Remove<Component::Renderable>(entity_id);
                // set helth to 300
                Update<Component::Health>(entity_id, 300);
                // set immunity
                Insert<Component::Immune>(entity_id, true);
            }
        }
    );

    // Substract 1 to health of all entities that have not 0
    Add<Component::Health>(-1, NotEqual<Component::Health>(0) & not_immune);

    dynamicsWorld->stepSimulation(delta * 1.0E-9, 10);
    // Set out transform updates.
    auto& bodymap = GetRawContainer<Component::Collidable>().Map();
    for (auto& shape : bodymap) {
        btTransform transform =
            Get<Component::Collidable>(shape.second)->GetRigidBody()->getWorldTransform();

        auto pos = transform.getOrigin();
        glm::vec3 vpos = glm::vec3(pos.x(), pos.y(), pos.z());
        auto rot = transform.getRotation();
        glm::quat vori = glm::quat(rot.w(), rot.x(), rot.y(), rot.z());
        GraphicTransform_type entity_transform(Get<Component::GraphicTransform>(shape.first));
        entity_transform.SetTranslation(vpos);
        entity_transform.SetOrientation(vori);
        Update<Component::GraphicTransform>(shape.first, std::move(entity_transform));
    }

    // Publish the new updated transforms map
    {
        std::lock_guard<std::mutex> tslock(game.transforms_lock);
        Commit<Component::GraphicTransform>(timepoint);
    }
}

id_t PhysicsSystem::RayCast() {
    id_t cam = game.GetCameraEntity();
    last_rayvalid = false;
    if(!Has<Component::GraphicTransform>(cam)) {
        return 0;
    }
    auto& ctransform = Get<Component::GraphicTransform>(cam);
    auto q = ctransform.GetOrientation();
    auto orig = ctransform.GetTranslation();
    auto fv = orig + glm::rotate(q, FORWARD_VECTOR * 300.f);
    btVector3 from(orig.x, orig.y, orig.z), to(fv.x, fv.y, fv.z);
    last_rayfrom = from;
    btDynamicsWorld::AllHitsRayResultCallback cr(from, to);
    this->dynamicsWorld->rayTest(from, to, cr);
    if(cr.hasHit()) {
        int mx = cr.m_collisionObjects.size();
        double lastfrac = 1.1;
        int hc = mx;
        id_t entity_hit = 0;
        for(int i = 0; i < mx; i++) {
            id_t entity = 0;
            double frc = cr.m_hitFractions.at(i);
            const Collidable* coll = (const Collidable*)cr.m_collisionObjects.at(i)->getUserPointer();
            if(!coll) continue;
            entity = coll->GetEntityID();
            if(entity && entity != cam) {
                if(frc < lastfrac) {
                    entity_hit = entity;
                    hc = i;
                    lastfrac = frc;
                }
            }
        }
        if(hc < mx) {
            last_raypos = cr.m_hitPointWorld.at(hc);
            last_raynorm = cr.m_hitNormalWorld.at(hc);
            last_raydist = last_rayfrom.distance(last_raypos);
            last_rayvalid = true;
            return entity_hit;
        }
    }
    return 0;
}

id_t PhysicsSystem::RayCastIgnore(id_t ign) {
    id_t cam = game.GetCameraEntity();
    last_rayvalid = false;
    if(!Has<Component::GraphicTransform>(cam)) {
        return 0;
    }
    auto& ctransform = Get<Component::GraphicTransform>(cam);
    auto q = ctransform.GetOrientation();
    auto orig = ctransform.GetTranslation();
    auto fv = orig + glm::rotate(q, FORWARD_VECTOR * 300.f);
    btVector3 from(orig.x, orig.y, orig.z), to(fv.x, fv.y, fv.z);
    last_rayfrom = from;
    btDynamicsWorld::AllHitsRayResultCallback cr(from, to);
    this->dynamicsWorld->rayTest(from, to, cr);
    if(cr.hasHit()) {
        int mx = cr.m_collisionObjects.size();
        double lastfrac = 1.1;
        int hc = mx;
        id_t entity_hit = 0;
        for(int i = 0; i < mx; i++) {
            id_t entity = 0;
            double frc = cr.m_hitFractions.at(i);
            const Collidable* coll = (const Collidable*)cr.m_collisionObjects.at(i)->getUserPointer();
            if(!coll) continue;
            entity = coll->GetEntityID();
            if(entity && entity != cam && entity != ign) {
                if(frc < lastfrac) {
                    entity_hit = entity;
                    hc = i;
                    lastfrac = frc;
                }
            }
        }
        if(hc < mx) {
            last_raypos = cr.m_hitPointWorld.at(hc);
            last_raynorm = cr.m_hitNormalWorld.at(hc);
            last_raydist = last_rayfrom.distance(last_raypos);
            last_rayvalid = true;
            return entity_hit;
        }
    }
    return 0;
}

void PhysicsSystem::AddDynamicComponent(const unsigned int entity_id, std::shared_ptr<Container> component) {
    if (component->Is<Component::Collidable>()) {
        AddBodyToWorld(component::Get<Component::Collidable>(component)->GetRigidBody());
    }
}

void PhysicsSystem::AddBodyToWorld(btRigidBody* body) {
    this->dynamicsWorld->addRigidBody(body);
}

void PhysicsSystem::Terminate() {
    if (this->dynamicsWorld != nullptr) {
        delete this->dynamicsWorld;
    }
    if (this->solver != nullptr) {
        delete this->solver;
    }
    if (this->collisionConfiguration != nullptr) {
        delete this->collisionConfiguration;
    }
    if (this->dispatcher != nullptr) {
        delete this->dispatcher;
    }
    if (this->broadphase != nullptr) {
        delete this->broadphase;
    }
}

void PhysicsSystem::SetGravity(const unsigned int entity_id, const btVector3& f) {
    if (Has<Component::Collidable>(entity_id)) {
        Get<Component::Collidable>(entity_id).GetRigidBody()->setGravity(f);
    }
}

void PhysicsSystem::SetNormalGravity(const unsigned int entity_id) {
    if (Has<Component::Collidable>(entity_id)) {
        Get<Component::Collidable>(entity_id).GetRigidBody()->setGravity(this->dynamicsWorld->getGravity());
    }
}

} // End of physics
} // End of trillek
