#include "systems/resource-system.hpp"
#include "systems/graphics.hpp"
#include "trillek-game.hpp"

#include "resources/mesh.hpp"
#include "resources/md5anim.hpp"

#include "graphics/renderable.hpp"
#include "graphics/texture.hpp"
#include "graphics/shader.hpp"
#include "graphics/animation.hpp"

#include "logging.hpp"

#include <sstream>

namespace trillek {
namespace graphics {

Renderable::Renderable() { }
Renderable::~Renderable() { }

void Renderable::SetMesh(std::shared_ptr<resource::Mesh> m) {
    this->mesh = m;
}

std::shared_ptr<resource::Mesh> Renderable::GetMesh() const {
    return this->mesh;
}

void Renderable::SetAnimation(std::shared_ptr<Animation> a) {
    this->animation = a;
}

std::shared_ptr<Animation> Renderable::GetAnimation() const {
    return this->animation;
}

bool Renderable::Initialize(const id_t entity_id, const std::vector<Property> &properties) {
    std::string mesh_name;
    std::string animation_name;
    this->entity_id = entity_id;
    for (const Property& p : properties) {
        std::string name = p.GetName();
        if (name == "mesh") {
            mesh_name = p.Get<std::string>();
        }
        else if (name == "shader") {
            shader_name = p.Get<std::string>();
        }
        else if (name == "animation") {
            animation_name = p.Get<std::string>();
        }
        else if (name == "instanced_textures") {
            this->set_inst_textures = p.Get<std::vector<bool>>();
        }
    }

    for(auto is_inst : this->set_inst_textures) {
        if(is_inst) {
            this->inst_textures.push_back(
                std::shared_ptr<resource::PixelBuffer>(new resource::PixelBuffer())
                );
        }
    }
    this->mesh = resource::ResourceMap::Get<resource::Mesh>(mesh_name);
    if (!this->mesh) {
        return false;
    }

    auto animation_file = resource::ResourceMap::Get<resource::MD5Anim>(animation_name);
    if (animation_file) {
        // Make sure the mesh is valid for the animation file.
        if (animation_file->CheckMesh(this->mesh)) {
            this->animation = std::make_shared<Animation>();
            this->animation->SetAnimationFile(animation_file);
        }
        else {
            return false;
        }
    }

    return true;
}

} // End of graphics
} // End of trillek
