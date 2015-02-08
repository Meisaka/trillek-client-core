#include "transform.hpp"
#include "type-id.hpp"
#include "trillek-game.hpp"
#include "components/component.hpp"
#include "systems/graphics.hpp"
#include "systems/resource-system.hpp"
#include "systems/gui.hpp"
#include "resources/text-file.hpp"
#include "resources/mesh.hpp"
#include "graphics/shader.hpp"
#include "graphics/material.hpp"
#include "graphics/renderable.hpp"
#include "graphics/six-dof-camera.hpp"
#include "graphics/animation.hpp"
#include "graphics/light.hpp"
#include "graphics/render-list.hpp"
#include "logging.hpp"

namespace trillek {
namespace graphics {

RenderSystem::RenderSystem()
        : Parser("graphics") {
    this->multisample = false;
    this->frame_drop = false;
    this->current_ref = 1;
    this->camera_id = 0;
    this->debugmode = 0;
    this->debugid = 0;
    this->window_height = 480;
    this->window_width = 640;
    this->frame_drop_count = 0;
    this->transformsvalid = false;
    this->scene_rebuild = false;
    this->gui_interface.reset(new RenderSystem::GuiRenderInterface(this));

    Shader::InitializeTypes();
}

const int* RenderSystem::Start(const unsigned int width, const unsigned int height) {
    // Use the GL3 way to get the version number
    glGetIntegerv(GL_MAJOR_VERSION, &this->gl_version[0]);
    glGetIntegerv(GL_MINOR_VERSION, &this->gl_version[1]);
    std::string glsl_string((char*)glGetString(GL_SHADING_LANGUAGE_VERSION));
    std::string glren_string((char*)glGetString(GL_RENDERER));
    std::string glver_string((char*)glGetString(GL_VERSION));
    //glGetIntegerv(GL_SHADING_LANGUAGE_VERSION, &this->gl_version[3]);
    CheckGLError();
    int opengl_version = gl_version[0] * 100 + gl_version[1] * 10;
    debugmode = 0;

    // Subscribe to events
    event::Dispatcher<KeyboardEvent>::GetInstance()->Subscribe(this);

    LOGMSGC(INFO) << "GLSL version " << glsl_string;
    LOGMSGC(INFO) << "OpenGL renderer " << glren_string;
    LOGMSGC(INFO) << "OpenGL version " << glver_string;
    if(opengl_version < 300) {
        LOGMSGC(FATAL) << "OpenGL context (" << opengl_version << ") less than required minimum (300)";
        assert(opengl_version >= 300);
    }
    if(opengl_version < 330) {
        LOGMSGC(WARNING) << "OpenGL context (" << opengl_version << ") less than recommended (330)";
    }
    else {
        LOGMSGC(INFO) << "OpenGL context (" << opengl_version << ')';
    }

    SetViewportSize(width, height);

    // copy the game transforms as graphic transforms
    component::OnTrue(component::Bitmap<component::Component::GameTransform>(),
        [&](id_t entity_id) {
            auto cp = component::Get<component::Component::GameTransform>(entity_id);
            glm::mat4 model_matrix = glm::translate(cp.GetTranslation()) *
                glm::mat4_cast(cp.GetOrientation()) *
                glm::scale(cp.GetScale());
            component::Insert<component::Component::GraphicTransform>(entity_id, std::move(cp));
            this->model_matrices[entity_id] = std::move(model_matrix);
            LOGMSGC(INFO) << "Copying transform of entity " << entity_id;
        }
    );

    // Activate the lowest ID or first camera and get the initial view matrix.
    auto &bits = component::GetRawContainer<Component::Camera>().Bitmap();
    size_t endc = bits.size();
    for (auto cam = bits.enumerator(endc); *cam < endc; ++cam) {
        this->camera_id = *cam;
        this->camera = component::Get<Component::Camera>(component::GetContainer<Component::Camera>(*cam));
        break;
    }

    if(!this->camera) {
        LOGMSGC(INFO) << "No camera found, creating a camera id #0";
        // make one if none found
        this->camera_id = 0;
        this->camera = std::make_shared<SixDOFCamera>();
    }
    if (this->camera) {
        this->camera->Activate(this->camera_id);
        this->vp_center.view_matrix = this->camera->GetViewMatrix();
    }

    float quaddata[] = {
        -1,  1, 0, 1,
         1,  1, 1, 1,
        -1, -1, 0, 0,
         1, -1, 1, 0
    };
    uint16_t quadindicies[] = { 0, 2, 1, 1, 2, 3 };
    const unsigned QUADVERTSIZE = sizeof(float) * 4;

    screen_quad.SetFormat(VertexList::VEC4D);
    screen_quad.Generate();
    screen_quad.LoadVertexData(quaddata, QUADVERTSIZE, 4);
    screen_quad.Configure();
    screen_quad.LoadIndexData((uint32_t*)quadindicies, 3);

    glBindVertexArray(0); CheckGLError(); // unbind VAO when done

    std::list<Property> settings;
    settings.push_back(Property("version", opengl_version));
    settings.push_back(Property("screen-width", width));
    settings.push_back(Property("screen-height", height));
    settings.push_back(Property("multisample", this->multisample));
    settings.push_back(Property("samples", (int)8));

    for(unsigned int p = 0; p < 3; p++) {
        for(auto& ginstance : this->graphics_instances) {
            for(auto& gobject : ginstance.second) {
                if(gobject.second && gobject.second->initialize_priority == p) {
                    gobject.second->SystemStart(settings);
                }
            }
        }
    }
    return this->gl_version;
}

bool RenderSystem::Parse(rapidjson::Value& node) {
    if(node.IsObject()) {
        // Iterate over types.
        for(auto type_itr = node.MemberBegin(); type_itr != node.MemberEnd(); ++type_itr) {
            std::string section_type(type_itr->name.GetString(), type_itr->name.GetStringLength());

            auto typefunc = parser_functions.find(section_type);
            if(typefunc != parser_functions.end()) {
                if(!typefunc->second(type_itr->value)) {
                    LOGMSGC(ERROR) << "Graphics parsing failed";
                    return false;
                }
            }
            else {
                LOGMSGC(INFO) << "RenderSystem::Parse - skipping \"" << section_type << "\" section";
            }
        }
        return true;
    }
    return false;
}

bool RenderSystem::Serialize(rapidjson::Document& document) {
    rapidjson::Value resource_node(rapidjson::kObjectType);

    document.AddMember("graphics", resource_node, document.GetAllocator());
    return true;
}

void RenderSystem::RegisterListResolvers() {
    std::map<std::string, GLuint> fbo_copytype_map;
    fbo_copytype_map["all"] = GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT;
    fbo_copytype_map["color"] = GL_COLOR_BUFFER_BIT;
    fbo_copytype_map["colour"] = GL_COLOR_BUFFER_BIT; // just because
    fbo_copytype_map["depth"] = GL_DEPTH_BUFFER_BIT;
    fbo_copytype_map["stencil"] = GL_STENCIL_BUFFER_BIT;
    fbo_copytype_map["depth-stencil"] = GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT;

    const RenderSystem& rensys = *this;
    list_resolvers[RenderCmd::CLEAR_SCREEN] = [&rensys] (RenderCommandItem &rlist) -> bool {
        return true;
    };
    list_resolvers[RenderCmd::MODULE_CMD] = [&rensys] (RenderCommandItem &rlist) -> bool {
        return true;
    };
    list_resolvers[RenderCmd::SCRIPT] = [&rensys] (RenderCommandItem &rlist) -> bool {
        return true;
    };
    list_resolvers[RenderCmd::RENDER] = [&rensys] (RenderCommandItem &rlist) -> bool {
        if(rlist.cmdvalue.Is<std::string>()) {
            const std::string &rentype = rlist.cmdvalue.Get<std::string>();
            if(rentype == "all-geometry") {
                rlist.run_values.push_back(Container((long)0));
            }
            else if(rentype == "depth-geometry") {
                rlist.run_values.push_back(Container((long)1));
            }
            else if(rentype == "lighting") {
                rlist.run_values.push_back(Container((long)2));
            }
            else if(rentype == "post") {
                rlist.run_values.push_back(Container((long)3));
                for(auto pitr = rlist.load_properties.begin(); pitr != rlist.load_properties.end(); pitr++) {
                    if(pitr->GetName() == "shader" && pitr->Is<std::string>()) {
                        auto shader_ptr = rensys.Get<Shader>(pitr->Get<std::string>());
                        if(shader_ptr) {
                            rlist.run_values.push_back(Container(shader_ptr));
                        }
                    }
                }
            }
            else if(rentype == "gui") {
                rlist.run_values.push_back(Container((long)4));
            }
            else {
                LOGMSGON(ERROR, rensys) << "Invalid render method";
                return false;
            }
        }
        else {
            return false;
        }
        return true;
    };
    list_resolvers[RenderCmd::SET_PARAM] = [&rensys] (RenderCommandItem &rlist) -> bool {
        return true;
    };
    auto layerresolver = [&rensys] (RenderCommandItem &rlist) -> bool {
        if(rlist.cmdvalue.IsEmpty()) {
            rlist.run_values.push_back(Container(false));
        }
        else if(rlist.cmdvalue.Is<std::string>()) {
            rlist.run_values.push_back(Container(true));
            auto layerptr = rensys.Get<RenderLayer>(rlist.cmdvalue.Get<std::string>());
            if(!layerptr) {
                LOGMSGON(ERROR, rensys) << "Layer not found: " << rlist.cmdvalue.Get<std::string>();
                return false;
            }
            rlist.run_values.push_back(Container(layerptr));
        }
        return true;
    };
    list_resolvers[RenderCmd::READ_LAYER] = layerresolver;
    list_resolvers[RenderCmd::WRITE_LAYER] = layerresolver;
    list_resolvers[RenderCmd::SET_RENDER_LAYER] = layerresolver;
    list_resolvers[RenderCmd::BIND_LAYER_TEXTURES] = layerresolver;
    list_resolvers[RenderCmd::COPY_LAYER] = [fbo_copytype_map, &rensys] (RenderCommandItem &rlist) -> bool {
        if(rlist.cmdvalue.IsEmpty()) {
            rlist.run_values.push_back(Container(false));
        }
        else if(rlist.cmdvalue.Is<std::string>()) {
            rlist.run_values.push_back(Container(true));
            auto layerptr = rensys.Get<RenderLayer>(rlist.cmdvalue.Get<std::string>());
            if(!layerptr) {
                LOGMSGON(ERROR, rensys) << "Layer not found: " << rlist.cmdvalue.Get<std::string>();
                return false;
            }
            rlist.run_values.push_back(Container(layerptr));
        }
        std::shared_ptr<RenderLayer> target;
        GLuint copytypebits = 0;
        for(auto& prop : rlist.load_properties) {
            if(prop.GetName() == "type") {
                if(prop.Is<std::string>()) {
                    const std::string& typestring = prop.Get<std::string>();
                    auto fboct = fbo_copytype_map.find(typestring);
                    if(fboct != fbo_copytype_map.end()) {
                        copytypebits |= fboct->second;
                    }
                    else {
                        return false;
                    }
                }
                else {
                    return false;
                }
            }
            else if(prop.GetName() == "to") {
                if(prop.Is<std::string>()) {
                    target = rensys.Get<RenderLayer>(prop.Get<std::string>());
                    if(!target) {
                        LOGMSGON(ERROR, rensys) << "Layer not found: " << prop.Get<std::string>();
                        return false;
                    }
                }
            }
        }
        if(!target) {
            rlist.run_values.push_back(Container(false));
        }
        else {
            rlist.run_values.push_back(Container(true));
            rlist.run_values.push_back(Container(target));
        }
        rlist.run_values.push_back(Container(copytypebits));
        return true;
    };
    list_resolvers[RenderCmd::BIND_TEXTURE] = [&rensys] (RenderCommandItem &rlist) -> bool {
        return true;
    };
    list_resolvers[RenderCmd::BIND_SHADER] = [&rensys] (RenderCommandItem &rlist) -> bool {
        return true;
    };
}

void RenderSystem::ThreadInit() {
    game.GetOS().MakeCurrent();
}

void RenderSystem::RunBatch() const {

    if(!this->frame_drop) {
        RenderScene();
        game.GetOS().SwapBuffers();
    }
    // If the user closes the window, we notify all the systems
    if (game.GetOS().Closing()) {
        game.NotifyCloseWindow();
    }
}

void RenderSystem::RenderScene() const {

    const ViewMatrixSet *c_view;
    c_view = &vp_center;
    glm::mat4x4 inv_proj = glm::inverse(c_view->projection_matrix);
    glViewport(c_view->viewport.x, c_view->viewport.y, c_view->viewport.z, c_view->viewport.w);

    if(activerender) {
        for(auto texitem = dyn_textures.begin(); texitem != dyn_textures.end(); texitem++) {
            (*texitem)->Update();
            if(!(*texitem)->IsDynamic()) {
                // remove if static or expired
                rem_textures.push_back(*texitem);
            }
        }
        unsigned int bind_point = 0;
        for(auto& cmditem : activerender->render_commands) {
            if(!cmditem.resolved && !cmditem.resolve_error) {
                auto resolve = list_resolvers.find(cmditem.cmd);
                if(resolve != list_resolvers.end()) {
                    cmditem.run_values.clear();
                    if(!resolve->second(cmditem)) {
                        cmditem.resolve_error = true;
                        LOGMSGC(ERROR) << "Parsing render command failed";
                        break;
                    }
                    cmditem.resolved = true;
                }
                else {
                    break;
                }
            }
            switch(cmditem.cmd) {
            case RenderCmd::BIND_TEXTURE:
            case RenderCmd::BIND_LAYER_TEXTURES:
                break;
            default:
                bind_point = 0;
            }
            switch(cmditem.cmd) {
            case RenderCmd::CLEAR_SCREEN:
                glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
                // Clear required buffers
                glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);
                break;
            case RenderCmd::MODULE_CMD:
                break;
            case RenderCmd::SCRIPT:
                break;
            case RenderCmd::RENDER:
            {
                auto val_itr = cmditem.run_values.begin();
                switch(val_itr->Get<long>()) {
                case 0:
                    glPolygonMode(GL_FRONT_AND_BACK, GL_FILL);
                    glEnable(GL_DEPTH_TEST);
                    RenderColorPass(&c_view->view_matrix[0][0], &c_view->projection_matrix[0][0]);
                    break;
                case 1:
                    glPolygonMode(GL_FRONT_AND_BACK, GL_FILL);
                    glEnable(GL_DEPTH_TEST);
                    RenderDepthOnlyPass(&c_view->view_matrix[0][0], &c_view->projection_matrix[0][0]);
                    break;
                case 2:
                    glDisable(GL_MULTISAMPLE);
                    glPolygonMode(GL_FRONT_AND_BACK, GL_FILL);
                    glDisable(GL_DEPTH_TEST);
                    RenderLightingPass(c_view->view_matrix, &inv_proj[0][0]);
                    break;
                case 3:
                {
                    std::shared_ptr<Shader> postshader;
                    glDisable(GL_MULTISAMPLE);
                    glPolygonMode(GL_FRONT_AND_BACK, GL_FILL);
                    glDisable(GL_DEPTH_TEST);

                    for(val_itr++; val_itr != cmditem.run_values.end(); val_itr++) {
                        if(val_itr->Is<std::shared_ptr<Shader>>()) {
                            postshader = val_itr->Get<std::shared_ptr<Shader>>();
                        }
                    }
                    RenderPostPass(postshader);
                }
                    break;
                case 4:
                    RenderGUI();
                    break;
                default:
                    break;
                }
            }
                break;
            case RenderCmd::SET_PARAM:
                break;
            case RenderCmd::READ_LAYER:
            {
                auto run_op = cmditem.run_values.begin();
                if(run_op->Get<bool>()) {
                    run_op++;
                    auto layer = run_op->Get<std::shared_ptr<RenderLayer>>();
                    if(layer) {
                        layer->BindToRead();
                    }
                }
                else {
                    RenderLayer::UnbindFromAll();
                }
            }
                break;
            case RenderCmd::WRITE_LAYER:
            {
                auto run_op = cmditem.run_values.begin();
                if(run_op->Get<bool>()) {
                    run_op++;
                    auto layer = run_op->Get<std::shared_ptr<RenderLayer>>();
                    if(layer) {
                        layer->BindToWrite();
                    }
                }
                else {
                    RenderLayer::UnbindFromAll();
                }
            }
                break;
            case RenderCmd::SET_RENDER_LAYER:
            {
                auto run_op = cmditem.run_values.begin();
                if(run_op->Get<bool>()) {
                    run_op++;
                    auto layer = run_op->Get<std::shared_ptr<RenderLayer>>();
                    if(layer) {
                        layer->BindToRender();
                        if(layer->IsCustomSize()) {
                            ViewRect sizeview;
                            layer->GetRect(sizeview);
                            glViewport(sizeview.x, sizeview.y,
                                sizeview.z, sizeview.w);
                        }
                        else {
                            glViewport(c_view->viewport.x, c_view->viewport.y,
                                c_view->viewport.z, c_view->viewport.w);
                        }
                    }
                }
                else {
                    RenderLayer::UnbindFromAll();
                    glViewport(c_view->viewport.x, c_view->viewport.y, c_view->viewport.z, c_view->viewport.w);
                }
            }
                break;
            case RenderCmd::BIND_LAYER_TEXTURES:
            {
                auto run_op = cmditem.run_values.begin();
                if(run_op->Get<bool>()) {
                    run_op++;
                    auto layer = run_op->Get<std::shared_ptr<RenderLayer>>();
                    if(layer) {
                        bind_point = layer->BindTextures(bind_point);
                    }
                }
                else {
                }
            }
                break;
            case RenderCmd::COPY_LAYER:
            {
                ViewRect src, dest;
                auto run_op = cmditem.run_values.begin();
                if(run_op->Get<bool>()) {
                    run_op++;
                    auto layer = run_op->Get<std::shared_ptr<RenderLayer>>();
                    if(layer) {
                        layer->BindToRead();
                        layer->GetRect(src);
                    }
                }
                else {
                    RenderLayer::UnbindFromRead();
                    src = c_view->viewport;
                }
                run_op++;
                if(run_op->Get<bool>()) {
                    run_op++;
                    auto layer = run_op->Get<std::shared_ptr<RenderLayer>>();
                    if(layer) {
                        layer->BindToWrite();
                        layer->GetRect(dest);
                    }
                }
                else {
                    RenderLayer::UnbindFromWrite();
                    dest = c_view->viewport;
                }
                run_op++;
                GLuint typebits = run_op->Get<GLuint>();
                glBlitFramebuffer(src.x, src.y, src.z, src.w, dest.x, dest.y, dest.z, dest.w, typebits, GL_NEAREST);
            }
                break;
            case RenderCmd::BIND_TEXTURE:
                break;
            case RenderCmd::BIND_SHADER:
                break;
            }
        }
    }
}

void RenderSystem::RenderGUI() const {
    // Make sure we have something to draw
    if(gui_interface->vertlistid) {
        auto vex = Get<VertexList>(gui_interface->vertlistid);
        if(vex) {
            vex->Bind();
        }
        else {
            return;
        }
    }
    glDisable(GL_DEPTH_TEST);
    glDisable(GL_MULTISAMPLE);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    this->guisysshader->Use();
    float pxwidth, pxheight;
    if(!window_width) {
        pxwidth = 1.0f;
    }
    else {
        pxwidth = 1.0f / ((float)window_width);
    }
    if(!window_height) {
        pxheight = 1.0f;
    }
    else {
        pxheight = 1.0f / ((float)window_height);
    }
    glUniform2f(this->guisysshader->Uniform("pxscreen"), pxwidth, pxheight);
    glUniform1i(this->guisysshader->Uniform("in_sampl"), 0);
    GLint tex_active = this->guisysshader->Uniform("on_tex1");
    GLint pxoffset = this->guisysshader->Uniform("pxofs");

    auto rset_itr = gui_interface->gui_renderset.begin();
    auto rset_end = gui_interface->gui_renderset.end();
    uint32_t refid, renid, rcount = 0;

    while(rset_itr != rset_end) {
        if(rcount++ > gui_interface->gui_renderset.size()) {
            LOGMSGC(ERROR) << "Overrun";
        }
        renid = rset_itr->entryref - 1;
        auto &listentry = gui_interface->vertlist[renid];

        if(rset_itr->extension < gui_interface->offsets.size()) {
            auto translation = gui_interface->offsets[rset_itr->extension];
            glUniform2f(pxoffset, translation.x, translation.y);
        }

        refid = listentry.textureref;
        if(refid) {
            auto tex = Get<Texture>(refid);
            if(tex) {
                refid = tex->GetID();
            }
            else {
                refid = 0;
            }
        }
        if(!refid) {
            glUniform1i(tex_active, 0);
        }
        else {
            glUniform1i(tex_active, 1);
        }
        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, refid);
        glBindSampler(0, 0);

        if(listentry.offset < gui_interface->renderindices.size()) {
            glDrawElements(GL_TRIANGLES, listentry.indexcount, GL_UNSIGNED_INT, ((uint32_t*)nullptr)+listentry.offset);
        }

        rset_itr++;
    }
    glDisable(GL_BLEND);
    glBlendFunc(GL_ONE, GL_ZERO);
}

void RenderSystem::RenderColorPass(const float *view_matrix, const float *proj_matrix) const {
    if(!transformsvalid) return;
    GLuint lastshader = 0;
    GLuint lastvao = 0;
    GLint u_model_loc = -1;
    GLint u_istex_loc = -1;
    GLint u_animatrix_loc = -1;
    GLint u_animate_loc = -1;
    for(auto wren_itr = loaded_renderables.begin(); wren_itr != loaded_renderables.end(); wren_itr++) {
        auto ref = mesh_refs.find(wren_itr->meshid);
        if(ref != mesh_refs.end()) {
            const VertexList &vlist = scenebuffers.at(ref->second->listid);
            if(vlist.shader) {
                if(vlist.vao != lastvao) {
                    vlist.Bind();
                    lastvao = vlist.vao;
                }
                if(vlist.shader->GetProgram() != lastshader) {
                    lastshader = vlist.shader->GetProgram();
                    vlist.shader->Use();
                    auto& shader = *vlist.shader;
                    glUniformMatrix4fv(shader.Uniform("view"), 1, GL_FALSE, view_matrix);
                    glUniformMatrix4fv(shader.Uniform("projection"), 1, GL_FALSE, proj_matrix);
                    u_model_loc = shader.Uniform("model");
                    u_istex_loc = shader.Uniform("textured");
                    u_animatrix_loc = shader.Uniform("animation_matrix");
                    u_animate_loc = shader.Uniform("animated");
                }
                glUniformMatrix4fv(u_model_loc, 1, GL_FALSE, &this->model_matrices.at(wren_itr->entity)[0][0]);
                if(wren_itr->anim) {
                    glUniform1i(u_animate_loc, 1);
                    auto animmatricies = wren_itr->anim->animation_matricies.data();
                    glUniformMatrix4fv(u_animatrix_loc, wren_itr->anim->animation_matricies.size(), GL_FALSE, (float*)animmatricies);
                }
                else {
                    glUniform1i(u_animate_loc, 0);
                }

                const RenderEntryList &rel = vlist.meshinfo.at(ref->second->entry_index);
                int h = 0;
                for(auto &entr : rel.vertlists) {
                    h++;
                    if(entr.textureref) {
                    }
                    else {
                        glUniform1i(u_istex_loc, 0);
                    }
                    glDrawElements(GL_TRIANGLES, entr.indexcount, GL_UNSIGNED_INT, ((void*)(entr.offset << 2)) );
                }
            }
        }
    }
}

void RenderSystem::RenderDepthOnlyPass(const float *view_matrix, const float *proj_matrix) const {
    // Similar to color pass but without textures and everything uses a depth shader
    // This is intended for shadow map passes or the like
    if(!transformsvalid) return;
    if(!depthpassshader) {
        return;
    }
    CheckGLError();
    depthpassshader->Use();
    CheckGLError();
    auto &bits = component::GetRawContainer<Component::Light>().Bitmap();
    size_t endc = bits.size();
    std::shared_ptr<LightBase> light;
    id_t lightid;
    for (auto clight = bits.enumerator(endc); *clight < endc; ++clight) {
        lightid = *clight;
        auto light = component::GetSharedPtr<Component::Light>(lightid);
        if(light->shadows) {
            break;
        }
    }
    if(!light) return;
    if(!light->shadows) return;
    auto ltiter = this->model_matrices.find(lightid);
    if(ltiter == this->model_matrices.end()) return;
    const glm::mat4x4& lightmat = ltiter->second;
    glm::vec3 lightpos = glm::vec3(lightmat[3][0], lightmat[3][1], lightmat[3][2]);
    glm::vec4 lightdir = glm::mat3x4(lightmat) * glm::vec3(0.f, 0.f, -1.f);
    glm::mat4x4 light_matrix =
        glm::perspective(3.1415f*0.5f, 1.f, 0.5f, 10000.f)
        * glm::lookAt(lightpos, lightpos-UP_VECTOR, FORWARD_VECTOR);
    glm::mat4x4 invlight_matrix = glm::inverse(light_matrix);
    CheckGLError();
    glUniform3f(depthpassshader->Uniform("light_pos"), lightpos.x, lightpos.y, lightpos.z);
    glUniformMatrix4fv(depthpassshader->Uniform("light_vp"), 1, GL_FALSE, (float*)&light_matrix);
    CheckGLError();
    light->depthmatrix = light_matrix;
    glDrawBuffer(GL_NONE);
    GLint u_model_loc = depthpassshader->Uniform("model");
    GLint u_animatrix_loc = depthpassshader->Uniform("animation_matrix");
    GLint u_animate_loc = depthpassshader->Uniform("animated");
    /* TODO rewrite */
    CheckGLError();
    Shader::UnUse();
    CheckGLError();
}

void RenderSystem::RenderLightingPass(const glm::mat4x4 &view_matrix, const float *inv_proj_matrix) const {
    if(!transformsvalid) return;
    screen_quad.Bind();
    GLint l_pos_loc = 0;
    GLint l_dir_loc = 0;
    GLint l_col_loc = 0;
    GLint l_type_loc = 0;
    GLint l_ushadow_loc = 0;
    GLint l_tshadow_loc = 0;
    GLint l_sshadow_loc = 0;
    if(lightingshader) {
        lightingshader->Use();
        l_pos_loc = lightingshader->Uniform("light_pos");
        l_col_loc = lightingshader->Uniform("light_color");
        l_dir_loc = lightingshader->Uniform("light_dir");
        l_type_loc = lightingshader->Uniform("light_type");
        l_ushadow_loc = lightingshader->Uniform("shadow_enabled");
        l_tshadow_loc = lightingshader->Uniform("shadow_matrix");
        l_sshadow_loc = lightingshader->Uniform("shadow_depth");
        glUniform1i(lightingshader->Uniform("layer0"), 0);
        glUniform1i(lightingshader->Uniform("layer1"), 1);
        glUniform1i(lightingshader->Uniform("layer2"), 2);
        glUniform1i(lightingshader->Uniform("layer3"), 3);
        if(l_sshadow_loc > 0) glUniform1i(l_sshadow_loc, 4);
        glUniformMatrix4fv(lightingshader->Uniform("inv_proj"), 1, GL_FALSE, inv_proj_matrix);
    }
    else {
        return;
    }
    glEnable(GL_BLEND);
    glBlendFunc(GL_ONE, GL_ONE);
    auto &bits = component::GetRawContainer<Component::Light>().Bitmap();
    size_t endc = bits.size();
    for (auto clight = bits.enumerator(endc); *clight < endc; ++clight) {
        auto ltiter = this->model_matrices.find(*clight);
        const LightBase &activelight = component::Get<Component::Light>(*clight);
        if(activelight.enabled && ltiter != this->model_matrices.end()) {
            std::shared_ptr<Texture> shadowbuf;
            GLint useshadow = 0;
            const glm::mat4& lightmat = ltiter->second;
            glm::vec4 lightpos = view_matrix * glm::vec4(lightmat[3][0], lightmat[3][1], lightmat[3][2], 1);
            glm::vec4 lightdir = glm::mat3x4(lightmat) * glm::vec3(0.f, 0.f, -1.f);
            if(l_pos_loc > 0) glUniform3f(l_pos_loc, lightpos.x, lightpos.y, lightpos.z);
            if(l_dir_loc > 0) glUniform3f(l_dir_loc, lightdir.x, lightdir.y, lightdir.z);
            if(l_col_loc > 0) glUniform3fv(l_col_loc, 1, (float*)&activelight.color);
            if(l_type_loc > 0) glUniform1ui(l_type_loc, activelight.lighttype);
            auto lp_itr = activelight.light_props.begin();
            for(;lp_itr != activelight.light_props.end(); lp_itr++) {
                GLint uniformloc = lightingshader->Uniform(lp_itr->GetName().c_str());
                if(uniformloc > 0) {
                    if(lp_itr->Is<float>()) {
                        glUniform1f(uniformloc, lp_itr->Get<float>());
                    }
                    else if(lp_itr->Is<glm::vec3>()) {
                        glm::vec3 val = lp_itr->Get<glm::vec3>();
                        glUniform3f(uniformloc, val.x, val.y, val.z);
                    }
                    else if(lp_itr->Is<glm::vec4>()) {
                        glm::vec4 val = lp_itr->Get<glm::vec4>();
                        glUniform4f(uniformloc, val.x, val.y, val.z, val.w);
                    }
                    else if(lp_itr->Is<glm::vec2>()) {
                        glm::vec2 val = lp_itr->Get<glm::vec2>();
                        glUniform2f(uniformloc, val.x, val.y);
                    }
                }
                else if(activelight.shadows && lp_itr->GetName() == "shadow") {
                    shadowbuf = Get<Texture>(lp_itr->Get<std::string>());
                    if(shadowbuf) {
                        useshadow = 1 + debugmode;
                        glActiveTexture(GL_TEXTURE4);
                        glBindTexture(GL_TEXTURE_2D, shadowbuf->GetID());
                        glm::mat4x4 invviewshadow = activelight.depthmatrix * glm::inverse(view_matrix);
                        if(l_tshadow_loc > 0) glUniformMatrix4fv(l_tshadow_loc, 1, GL_FALSE, &invviewshadow[0][0]);
                    }
                }
            }
            if(l_ushadow_loc > 0) glUniform1i(l_ushadow_loc, useshadow);
            glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, 0); // render quad for each light
        }
    }
    glDisable(GL_BLEND);
    glBlendFunc(GL_ONE, GL_ZERO);
    // unbind when done
    glUseProgram(0);
    glBindVertexArray(0); CheckGLError();
}

inline void RenderSystem::UpdateModelMatrices(const frame_tp& timepoint) {
    auto& transform_container =
        GetRawContainer<Component::GraphicTransform>().Map();
    static frame_tp ltp;
    std::unique_lock<std::mutex> tslock(game.transforms_lock, std::defer_lock);
    if( !tslock.try_lock() ) {
        return;
    }
    //auto hist = transform_container.Pull(timepoint, ltp);
    int i;

    auto& transform_map_head = transform_container.GetLastPositiveCommit();

    transformsvalid = true;
    for (const auto& transform_el : transform_map_head) {
        // for each modified transform in the frame
        const auto id = transform_el.first;
        const auto& transform =
            *component::Get<Component::GraphicTransform>(transform_el.second);
        glm::mat4 model_matrix = glm::translate(transform.GetTranslation()) *
            glm::mat4_cast(transform.GetOrientation()) *
            glm::scale(transform.GetScale());
        this->model_matrices[id] = std::move(model_matrix);
        if(this->GetActiveCameraID() == id) {
            try {
                this->camera->UpdateTransform(component::Get<Component::GraphicTransform>(transform_el.second));
                this->vp_center.view_matrix = this->camera->GetViewMatrix();
            } catch(std::exception& e) {
                LOGMSGC(ERROR) << "Exception: " << e.what();
            }
        }
    }
}

void RenderSystem::RenderPostPass(std::shared_ptr<Shader> postshader) const {
    postshader->Use();
    screen_quad.Bind();
    glUniform4f(postshader->Uniform("pixels"),
        this->window_width, this->window_height,
        1.f / this->window_width, 1.f / this->window_height);CheckGLError();
    glUniform1i(postshader->Uniform("layer0"), 0);CheckGLError();
    glUniform1i(postshader->Uniform("layer1"), 1);CheckGLError();
    glUniform1i(postshader->Uniform("layer2"), 2);CheckGLError();
    glUniform1i(postshader->Uniform("layer3"), 3);CheckGLError();
    glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_SHORT, 0);CheckGLError();
    glBindVertexArray(0); CheckGLError();
    Shader::UnUse();
}

void RenderSystem::RenderMeshes(bool useshaders, uint32_t layermask) const {

}

void RenderSystem::RegisterStaticParsers() {
    RenderSystem &rensys = *this;
    auto aglambda =  [&rensys] (const rapidjson::Value& node) -> bool {
        for(auto settingitr = node.MemberBegin(); settingitr != node.MemberEnd(); settingitr++) {
            std::string settingname = util::MakeString(settingitr->name);
            if(settingitr->value.IsString()) {
                std::string settingval = util::MakeString(settingitr->value);
                if(settingname == "active-graph") {
                    rensys.activerender = rensys.Get<RenderList>(settingval);
                }
                else if(settingname == "lighting-shader") {
                    rensys.lightingshader = rensys.Get<Shader>(settingval);
                }
                else if(settingname == "depth-shader") {
                    rensys.depthpassshader = rensys.Get<Shader>(settingval);
                }
                else if(settingname == "gui-shader") {
                    rensys.guisysshader = rensys.Get<Shader>(settingval);
                }
            }
        }
        return true;
    };
    parser_functions["settings"] = aglambda;
}

void RenderSystem::SetViewportSize(const unsigned int width, const unsigned int height) {
    this->window_height = height;
    this->window_width = width;

    this->vp_center.viewport = ViewRect(0,0,width,height);

    // Determine the aspect ratio and sanity check it to a safe ratio
    float aspect_ratio = static_cast<float>(this->window_width) / static_cast<float>(this->window_height);
    if (aspect_ratio < 1.0f) {
        aspect_ratio = 4.0f / 3.0f;
    }

    // update projection matrix based on new aspect ratio
    this->vp_center.projection_matrix = glm::perspective(
        glm::radians(45.0f),
        aspect_ratio,
        0.1f,
        10000.0f
        );
}

template<>
void RenderSystem::Add(const std::string & instancename, std::shared_ptr<Texture> instanceptr) {
    unsigned int type_id = reflection::GetTypeID<Texture>();
    dyn_textures.push_back(instanceptr);
    graphics_instances[type_id][instancename] = instanceptr;
}

RenderSystem::MeshRefData::~MeshRefData() {
    LOGMSG(DEBUG) << "~MeshRefData()";
}

void RenderSystem::ActivateMesh(std::shared_ptr<resource::Mesh> mesh, SceneEntry& ent, std::shared_ptr<Shader> shade) {
    auto mref = mesh_refs.find(mesh.get());
    if(mref == mesh_refs.end()) {
        LOGMSGC(DEBUG) << "Loading new mesh for " << ent.entity;
        size_t sbindex = 0;

        if(mesh->IsDynamic()) {
            sbindex = scenebuffers.size();
            scenebuffers.push_back(VertexList());
            scenebuffers[sbindex].dynamic = true;
            scenebuffers[sbindex].shader = shade;
        }
        else {
            size_t lim = scenebuffers.size();
            for( ; sbindex < lim; sbindex++) {
                if( (!scenebuffers[sbindex].dynamic) && (scenebuffers[sbindex].shader.get() == shade.get())) {
                    break;
                }
            }
            if(sbindex == lim) {
                scenebuffers.push_back(VertexList());
                scenebuffers[sbindex].shader = shade;
            }
        }
        VertexList& vlist = scenebuffers[sbindex];
        MeshRefData *mrd = new MeshRefData(mesh, sbindex);
        size_t sz = mesh->GetMeshGroupCount();
        size_t vofs = vlist.vertexcount, iofs = vlist.indexcount;
        size_t vcount = 0;
        size_t meindex = vlist.meshinfo.size();
        LOGMSGC(DEBUG) << "Mesh offset V:" << vofs << " I:" << iofs;
        mrd->entry_index = meindex;
        vlist.meshinfo.push_back(RenderEntryList());
        vlist.update = true;
        RenderEntryList& rlist = vlist.meshinfo[meindex];
        rlist.vertexoffset = vofs;
        rlist.indexoffset = iofs;
        rlist.meshptr = mesh;
        for(size_t i = 0; i < sz; i++) {
            std::shared_ptr<resource::MeshGroup> mg = mesh->GetMeshGroup(i).lock();
            size_t x = rlist.vertlists.size();
            rlist.vertlists.push_back(VertexListEntry());
            auto &cvle = rlist.vertlists.at(x);
            cvle.vertexcount = mg->verts.size();
            cvle.indexcount = mg->indicies.size();
            cvle.textureref = 0;
            cvle.offset = iofs;
            LOGMSGC(DEBUG) << "RL #" << rlist.vertlists.size() << " at " << vofs+vcount << ", " << iofs
                << " counts V:" << cvle.vertexcount << " I:" << cvle.indexcount;
            vcount += cvle.vertexcount;
            iofs += cvle.indexcount;
        }
        vlist.vertexcount = vofs + vcount;
        vlist.indexcount = iofs;
        mesh_refs[mesh.get()].reset(mrd);
    }
    else {
        LOGMSGC(DEBUG) << "Reference mesh for " << ent.entity;
    }
    ent.meshid = mesh.get();
}

void RenderSystem::RenderablesUpdate(double fdelta) {
    auto &bits = component::GetRawContainer<Component::Renderable>().Bitmap();
    size_t endc = bits.size();
    for(auto wren_itr = loaded_renderables.begin(); wren_itr != loaded_renderables.end(); wren_itr++) {
        if(wren_itr->status.expired()) {
            LOGMSGC(DEBUG) << "Removed Renderable";
            wren_itr = loaded_renderables.erase(wren_itr);
            scene_rebuild = true;
            continue;
        }
    }
    for(auto ci = bits.enumerator(endc); *ci < endc; ++ci) {
        auto rcon = component::GetContainer<Component::Renderable>(*ci);
        auto rptr = component::Get<Component::Renderable>(rcon);
        if(!rptr) {
            continue;
        }
        if(!rptr->loadstatus) {
            LOGMSGC(DEBUG) << "Loading Renderable: " << *ci;
            auto loader = std::make_shared<LoadStatus>();
            rptr->loadstatus = loader;
            loaded_renderables.push_back(SceneEntry(loader));
            loaded_renderables.back().entity = *ci;
            loaded_renderables.back().anim = rptr->GetAnimation();
            scene_rebuild = true;
        }
        else {
            if( (rptr->loadstatus->flags) == 0 ) {
                scene_rebuild = true;
            }
        }
        auto const &anim = rptr->GetAnimation();
        if(anim) {
            anim->UpdateAnimation(fdelta);
        }
    }
}

void RenderSystem::RebuildScene() {
    LOGMSGC(DEBUG) << "Rebuilding scene";
    scene_rebuild = false;
    for(auto ri = mesh_refs.begin(); ri != mesh_refs.end(); ri++) {
        if((*ri).second->mesh.expired()) {
            ri = mesh_refs.erase(ri);
            LOGMSGC(DEBUG) << "Mesh expired";
            continue;
        }
    }
    for(auto wren_itr = loaded_renderables.begin(); wren_itr != loaded_renderables.end(); wren_itr++) {
        if(wren_itr->status.expired()) {
            LOGMSGC(DEBUG) << "Removed Renderable (LATE)";
            wren_itr = loaded_renderables.erase(wren_itr);
            continue;
        }
        auto lren = wren_itr->status.lock();
        auto& ren = component::Get<Component::Renderable>(wren_itr->entity);
        auto shade = Get<Shader>(ren.shader_name);
        if((lren->flags & 1) == 0) {
            ActivateMesh(ren.mesh, *wren_itr, shade);
            lren->flags |= 1;
        }
    }
    for(auto &vl : this->scenebuffers) {
        vl.Update();
    }
}

void RenderSystem::HandleEvents(frame_tp timepoint) {
    auto now = game.GetOS().GetTime().count();
    static frame_tp last_tp = now;
    auto delta = now - last_tp;
    if(delta > 50000000ll) {
        if(!this->frame_drop) {
            LOGMSGC(INFO) << "Time lag " << (delta - 13333333) * 1.0E-9 << " > 50 milliseconds";
            this->frame_drop_count = 0;
        }
        this->frame_drop = true;
        this->frame_drop_count++;
    }
    else {
        if(this->frame_drop) {
            LOGMSGC(INFO) << "Dropped frames " << this->frame_drop_count;
            this->frame_drop_count = 0;
        }
        this->frame_drop = false;
        game.GetGUISystem().Update();
        gui_interface->CheckClear();
        gui_interface->gui_renderset.clear();
        gui_interface->offsets.clear();
        game.GetGUISystem().InvokeRender(); // rebuilds geometry if needed
        gui_interface->CheckReload();
    }
    last_tp = now;
    auto tex = this->rem_textures.begin();
    for(;tex != this->rem_textures.end(); tex++) {
        this->dyn_textures.remove(*tex);
    }
    this->rem_textures.clear();
    RenderablesUpdate(delta * 1E-9);

    if(scene_rebuild) RebuildScene();

    UpdateModelMatrices(timepoint);
};

void RenderSystem::Terminate() {
    game.GetOS().DetachContext();
}

} // End of graphics
} // End of trillek

