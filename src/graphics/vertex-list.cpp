
#include "graphics/vertex-list.hpp"
#include "resources/mesh.hpp"
#include "logging.hpp"

namespace trillek {
namespace graphics {

VertexList::VertexList()
    : vao(0) {
    format = VEC3D_NCTW;
    buf[0] = 0;
    buf[1] = 0;
    vertexsize = 0;
    indexcount = 0;
    vertexcount = 0;
    update = false;
    dynamic = false;
}
VertexList::VertexList(VertexList&& that) {
    vao = that.vao;
    buf[0] = that.buf[0];
    buf[1] = that.buf[1];
    format = that.format;
    vertexsize = that.vertexsize;
    indexcount = that.indexcount;
    vertexcount = that.vertexcount;
    update = that.update;
    dynamic = that.dynamic;
    shader = std::move(that.shader);
    meshinfo = std::move(that.meshinfo);
    texture_ids = std::move(that.texture_ids);
    texturedata = std::move(that.texturedata);
    that.vao = 0;
    that.buf[0] = 0;
    that.buf[1] = 0;
    that.vertexsize = 0;
    that.vertexcount = 0;
    that.indexcount = 0;
    LOGMSGC(DEBUG) << "move";
}
VertexList& VertexList::operator=(VertexList&& that) {
    vao = that.vao;
    buf[0] = that.buf[0];
    buf[1] = that.buf[1];
    format = that.format;
    vertexsize = that.vertexsize;
    indexcount = that.indexcount;
    vertexcount = that.vertexcount;
    update = that.update;
    dynamic = that.dynamic;
    shader = std::move(that.shader);
    meshinfo = std::move(that.meshinfo);
    texture_ids = std::move(that.texture_ids);
    texturedata = std::move(that.texturedata);
    that.vao = 0;
    that.buf[0] = 0;
    that.buf[1] = 0;
    vertexsize = 0;
    return *this;
}

VertexList::~VertexList() {
    if(vao) LOGMSGC(DEBUG) << "~VertexList()";
    Release();
}

bool VertexList::SystemStart(const std::list<Property> &) {
    return true;
}
bool VertexList::SystemReset(const std::list<Property> &) {
    return true;
}
bool VertexList::Parse(const std::string &object_name, const rapidjson::Value& node) {
    return true;
}
bool VertexList::Serialize(rapidjson::Document& document) {
    return true;
}
void VertexList::Generate() {
    if(!this->vao) {
        glGenVertexArrays(1, &this->vao);
        glGenBuffers(2, this->buf);
        CheckGLError();
    }
    glBindVertexArray(this->vao);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, this->buf[1]); // Bind the index buffer.
}
void VertexList::Release() {
    if(this->vao) {
        glDeleteVertexArrays(1, &this->vao);
        glDeleteBuffers(2, this->buf);
        this->vao = 0;
    }
}
void VertexList::Bind() const {
    glBindVertexArray(this->vao);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, this->buf[1]); // Bind the index buffer.
    CheckGLError();
}
void VertexList::Configure() {
    CheckGLError();

    void *offset = nullptr;
    uint32_t attrnum = 0;

    switch(this->format) {
    case VEC3D_NCT:
        vertexsize = sizeof(float) * (3+3+2) + sizeof(uint32_t) * (1);
        // 3 position, 3 normal, 4 color(byte), 2 texcoord
        glVertexAttribPointer(attrnum, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 3; // move to the next attribute offset
        glVertexAttribPointer(attrnum, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 3;
        glVertexAttribPointer(attrnum, 4, GL_UNSIGNED_BYTE, GL_TRUE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((uint32_t*)offset) + 1;
        glVertexAttribPointer(attrnum, 2, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 2;
        break;
    case VEC3D_NCTW:
        vertexsize = sizeof(float) * (3+3+2+4) + sizeof(uint32_t) * (1+4);
        // 3 position, 3 normal, 4 color(byte), 2 texcoord, 4 Weight index, 4 Weights
        glVertexAttribPointer(attrnum, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 3; // move to the next attribute offset
        glVertexAttribPointer(attrnum, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 3;
        glVertexAttribPointer(attrnum, 4, GL_UNSIGNED_BYTE, GL_TRUE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((uint32_t*)offset) + 1;
        glVertexAttribPointer(attrnum, 2, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 2;
        glVertexAttribIPointer(attrnum, 4, GL_UNSIGNED_INT, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((uint32_t*)offset) + 4;
        glVertexAttribPointer(attrnum, 4, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 4;
        break;
    case VEC3D_NfCT:
        vertexsize = sizeof(float) * (3+3+4+2);
        // 3 position, 3 normal, 4 color(float), 2 texcoord
        glVertexAttribPointer(attrnum, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 3; // move to the next attribute offset
        glVertexAttribPointer(attrnum, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 3;
        glVertexAttribPointer(attrnum, 4, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 4;
        glVertexAttribPointer(attrnum, 2, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(attrnum++);
        offset = ((float*)offset) + 2;
        break;
    case VEC3D_NfCTW:
        vertexsize = sizeof(float) * (3+3+4+2+4) + sizeof(uint32_t) * (4);
        // 3 position, 3 normal, 4 color(float), 2 texcoord, 4 Weight index, 4 Weights
        glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(0);
        offset = ((float*)offset) + 3; // move to the next attribute offset
        glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(1);
        offset = ((float*)offset) + 3;
        glVertexAttribPointer(2, 4, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(2);
        offset = ((float*)offset) + 4;
        glVertexAttribPointer(3, 2, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(3);
        offset = ((float*)offset) + 2;
        glVertexAttribIPointer(4, 4, GL_UNSIGNED_INT, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(4);
        offset = ((uint32_t*)offset) + 4;
        glVertexAttribPointer(5, 4, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(5);
        offset = ((float*)offset) + 4;
        break;
    case VEC2D_CT:
        vertexsize = sizeof(float) * (2+2) + sizeof(uint32_t);
        // 2 position, 4 color(byte), 2 texcoord
        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(0);
        offset = ((float*)offset) + 2; // move to the next attribute offset
        glVertexAttribPointer(1, 4, GL_UNSIGNED_BYTE, GL_TRUE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(1);
        offset = ((uint32_t*)offset) + 1;
        glVertexAttribPointer(2, 2, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(2);
        break;
    case VEC4D_C:
        vertexsize = sizeof(float) * (4) + sizeof(uint32_t);
        // 4 position, 4 color(byte)
        glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(0);
        offset = ((float*)offset) + 4; // move to the next attribute offset
        glVertexAttribPointer(1, 4, GL_UNSIGNED_BYTE, GL_TRUE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(1);
        break;
    case VEC4D:
        vertexsize = sizeof(float) * (4);
        // 4 position
        glVertexAttribPointer(0, 4, GL_FLOAT, GL_FALSE, vertexsize, (GLvoid*)offset);
        glEnableVertexAttribArray(0);
        break;
    default:
        break;
    }
}
void VertexList::LoadVertexData(void * datablock, uint32_t size, uint32_t count) {
    glBindBuffer(GL_ARRAY_BUFFER, this->buf[0]); // Bind the vertex buffer.
    CheckGLError();
    glBufferData(GL_ARRAY_BUFFER, size * count, datablock, GL_DYNAMIC_DRAW); CheckGLError();
}
void VertexList::LoadIndexData(uint32_t * datablock, uint32_t count) {
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, this->buf[1]); // Bind the index buffer.
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(uint32_t) * count, datablock, GL_DYNAMIC_DRAW);
}
void VertexList::Update() {
    if(!update) {
        return;
    }
    if(!this->vao) {
        format = VEC3D_NfCTW;
        Generate();
    }
    if(indexcount == 0 && vertexcount == 0) {
        Release();
        return;
    }
    glBindVertexArray(this->vao);
    glBindBuffer(GL_ARRAY_BUFFER, this->buf[0]); // Bind the vertex buffer.
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, this->buf[1]); // Bind the index buffer.
    CheckGLError();
    glBufferData(GL_ARRAY_BUFFER, sizeof(resource::VertexData) * vertexcount, nullptr, dynamic ? GL_DYNAMIC_DRAW : GL_STATIC_DRAW);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(uint32_t) * indexcount, nullptr, dynamic ? GL_DYNAMIC_DRAW : GL_STATIC_DRAW);
    CheckGLError();
    Configure();
    CheckGLError();

    resource::VertexData *verts = reinterpret_cast<resource::VertexData*>(
        glMapBufferRange(GL_ARRAY_BUFFER, 0,
            sizeof(resource::VertexData) * vertexcount,
            GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT));
    CheckGLError();
    if(verts == nullptr) {
        LOGMSGC(WARNING) << "vertex buffer map failed";
        return;
    }
    uint32_t *inds = reinterpret_cast<uint32_t*>(
        glMapBufferRange(GL_ELEMENT_ARRAY_BUFFER, 0,
            sizeof(uint32_t) * indexcount,
            GL_MAP_WRITE_BIT | GL_MAP_INVALIDATE_BUFFER_BIT));
    CheckGLError();
    if(inds == nullptr) {
        glUnmapBuffer(GL_ARRAY_BUFFER);
        LOGMSGC(WARNING) << "index buffer map failed";
        return;
    }
    LOGMSGC(DEBUG) << "updating buffer";
    resource::VertexData *vbase = verts;
    uint32_t *ibase = inds;
    uint32_t vindex = 0;
    for(auto &mi : this->meshinfo) {
        if(!mi.meshptr.expired()) {
            std::shared_ptr<resource::Mesh> mesh = mi.meshptr.lock();
            for(size_t vli = 0; vli < mi.vertlists.size(); vli++) {
                auto &vl = mi.vertlists[vli];
                auto mg = mesh->GetMeshGroup(vli).lock();
                memcpy(vbase, mg->verts.data(), sizeof(resource::VertexData) * vl.vertexcount);
                vbase += vl.vertexcount;

                uint32_t indexlim = vindex + vl.vertexcount;
                const uint32_t *isrc = mg->indicies.data();
                for(size_t x = 0; x < vl.indexcount; x++) {
                    *ibase = (*isrc) + vindex;
                    if(*isrc > indexlim) LOGMSGC(DEBUG) << "Index#" << x << " > lim, " << (*isrc);
                    ibase++; isrc++;
                }
                vindex += vl.vertexcount;
            }
        }
        else {
            LOGMSGC(WARNING) << "Update to GPU, bad Mesh pointer";
        }
    }
    if(vindex < vertexcount) {
        LOGMSGC(WARNING) << "Load underflow";
    }
    update = false;
    glUnmapBuffer(GL_ARRAY_BUFFER);
    glUnmapBuffer(GL_ELEMENT_ARRAY_BUFFER);
}

} // namespace graphics
} // namespace trillek
