#ifndef PHYSICS_HPP_INCLUDED
#define PHYSICS_HPP_INCLUDED

#include <bullet/btBulletDynamicsCommon.h>

#include <memory>
#include <map>

#include "trillek.hpp"
#include "systems/async-data.hpp"
#include "trillek-scheduler.hpp"
#include "user-command-queue.hpp"
#include "systems/system-base.hpp"

namespace trillek {
namespace physics {

struct VelocityStruct {
    VelocityStruct() : linear(0,0,0,0), angular(0,0,0,0) {};

    template<class T>
    VelocityStruct(T&& linear, T&& angular)
        :   linear(std::forward<T>(linear)),
            angular(std::forward<T>(angular)) {};

    glm::vec4 linear;
    glm::vec4 angular;
    btVector3 GetLinear() const {
        return btVector3(linear.x, linear.y, linear.z);
    }
    btVector3 GetAngular() const {
        return btVector3(angular.x, angular.y, angular.z);
    }
};

struct VelocityMaxStruct {
    VelocityMaxStruct() : linear(0,0,0), angular(0,0,0) {};

    template<class T>
    VelocityMaxStruct(T&& linear, T&& angular)
        :   linear(std::forward<T>(linear)),
            angular(std::forward<T>(angular)) {};

    glm::vec3 linear;
    glm::vec3 angular;
};

class PhysicsSystem final : public SystemBase {
    typedef std::pair<btVector3,btVector3> velocity;

public:
    PhysicsSystem();
    ~PhysicsSystem();
    /**
     * \brief Starts the Simple Physics system.
     *
     * \return bool Returns false on startup failure.
     */
    void Start();

    void ThreadInit() override {}

    /**
     * \brief Causes an update in the system based on the change in time.
     *
     * Updates the state of the system based off how much time has elapsed since the last update.
     */
    void RunBatch() const override {};

    /**
     * \brief Adds a Shape component to the system.
     *
     * A dynamic_pointer_case is applied to the component shared_ptr to cast it to
     * a Shape component. If the cast results in a nullptr the method returns
     * without adding the Shape component.
     * \param const unsigned int entity_id The entity ID the compoennt belongs to.
     * \param std::shared_ptr<T> component The component to add.
     */
    void AddDynamicComponent(const unsigned int entity_id, std::shared_ptr<component::Container> shape) override;

    void AddBodyToWorld(btRigidBody* body);

    /** \brief Handle incoming events to update data
     *
     * This function is called once every frame. It is the only
     * function that can write data. This function is in the critical
     * path, job done here must be simple.
     *
     * If event handling need some batch processing, a task list must be
     * prepared and stored temporarily to be retrieved by RunBatch().
     */
    void HandleEvents(frame_tp timepoint) override;

    /** \brief Save the data and terminate the system
     *
     * This function is called when the program is closing
     */
    void Terminate() override;

    template<class T>
    void AddCommand(id_t entity_id, T&& v) const {
        this->usercommands.AddCommand(entity_id, std::forward<T>(v));
    }

    /** \brief Set a rigid body's gravity.
     *
     * \param const unsigned int entity_id The entity ID of the rigid body.
     * \param btVector3 f The rigid body's new gravity.
     */
    void SetGravity(const unsigned int entity_id, const btVector3& f);

    /** \brief Set a rigid body's gravity to the world's gravity.
     *
     * \param const unsigned int entity_id The entity ID of the rigid body.
     */
    void SetNormalGravity(const unsigned int entity_id);

    id_t RayCast();
    id_t RayCastIgnore(id_t);
    glm::vec3 GetLastRayPos() const {
        btVector3 tmp = last_raypos; // grab a copy
        return glm::vec3(tmp.getX(), tmp.getY(), tmp.getZ());
    }
    double GetLastRayDistance() const {
        return last_raydist;
    }
    void RaySetInvalid() {
        last_rayvalid = false;
    }
private:

    btBroadphaseInterface* broadphase;
    btCollisionConfiguration* collisionConfiguration;
    btCollisionDispatcher* dispatcher;
    btSequentialImpulseConstraintSolver* solver;
    btDynamicsWorld* dynamicsWorld;
    btVector3 last_rayfrom;
    double last_raydist;
    btVector3 last_raypos;
    btVector3 last_raynorm;
    bool last_rayvalid;

    UserCommandQueue usercommands;

    btCollisionShape* groundShape;
    btMotionState* groundMotionState;
    btRigidBody* groundRigidBody;

    frame_tp delta; // The time since the last HandleEvents was called.
};

} // End of physcics
} // End of trillek
#endif
