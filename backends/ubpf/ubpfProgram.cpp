/*
Copyright 2019 Orange

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "ubpfProgram.h"

#include "codeGen.h"
#include "ubpfControl.h"
#include "ubpfDeparser.h"
#include "ubpfParser.h"
#include "ubpfType.h"

namespace UBPF {

bool UBPFProgram::build() {
    bool success = true;
    auto pack = toplevel->getMain();
    if (pack->type->name != "ubpf")
        ::warning(ErrorType::WARN_INVALID,
                  "%1%: the main ubpf package should be called ubpf"
                  "; are you using the wrong architecture?",
                  pack->type->name);

    if (pack->getConstructorParameters()->size() != 4) {
        ::error(ErrorType::ERR_MODEL, "Expected toplevel package %1% to have 4 parameters",
                pack->type);
        return false;
    }

    auto pb = pack->getParameterValue(model.pipeline.parser.name)->to<IR::ParserBlock>();
    BUG_CHECK(pb != nullptr, "No parser block found");
    parser = new UBPFParser(this, pb, typeMap);
    success = parser->build();
    if (!success) return success;

    auto cb1 = pack->getParameterValue(model.pipeline.ingress.name)->to<IR::ControlBlock>();
    BUG_CHECK(cb1 != nullptr, "No ingress block found");
    ingress = new UBPFControl(this, cb1, parser->headers, "ingress");
    success = ingress->build();
    if (!success) return success;

    auto cb2 = pack->getParameterValue(model.pipeline.egress.name)->to<IR::ControlBlock>();
    BUG_CHECK(cb2 != nullptr, "No egress block found");
    egress = new UBPFControl(this, cb2, parser->headers, "egress");
    success = egress->build();
    if (!success) return success;

    auto dpb = pack->getParameterValue(model.pipeline.deparser.name)->to<IR::ControlBlock>();
    BUG_CHECK(dpb != nullptr, "No deparser block found");
    deparser = new UBPFDeparser(this, dpb, parser->headers);
    success = deparser->build();

    return success;
}

void UBPFProgram::emitC(UbpfCodeBuilder *builder, cstring headerFile) {
    emitGeneratedComment(builder);

    builder->appendFormat("#include \"%s\"", headerFile);
    builder->newline();

    builder->target->emitIncludes(builder);
    emitPreamble(builder);
    builder->target->emitUbpfHelpers(builder);

    builder->emitIndent();
    ingress->emitTableInstances(builder);
    egress->emitTableInstances(builder);

    builder->emitIndent();
    builder->appendLine("#define member_sizeof(type, member) sizeof(((type *)0)->member)");
    builder->appendLine("using std::vector;");
    builder->appendLine("using std::unordered_map;");
    builder->newline();
    ingress->emitTableMapFunctions(builder);
    egress->emitTableMapFunctions(builder);

    builder->emitIndent();
    builder->target->emitChecksumHelpers(builder);

    builder->appendLine("// MARKER: PARSER BEGIN");
    // PARSER ==================================================================
    builder->emitIndent();
    builder->target->emitMain(builder, "parser", contextVar.c_str(), stdMetadataVar.c_str(), parser->headers->name.name);
    builder->blockStart();

    // emitPktVariable(builder);

    emitPacketLengthVariable(builder);

    // emitHeaderInstances(builder);
    // builder->append(" = ");
    // parser->headerType->emitInitializer(builder);
    // builder->endOfStatement(true);

    // emitMetadataInstance(builder);
    // builder->append(" = ");
    // parser->metadataType->emitInitializer(builder);
    // builder->endOfStatement(true);

    // emitLocalVariables(builder);
    builder->newline();
    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::start.c_str());
    builder->newline();

    parser->emit(builder);

    builder->emitIndent();
    builder->appendFormat("accept: { return %s; }\n", builder->target->forwardReturnCode());
    builder->blockEnd(true);
    builder->appendLine("// MARKER: PARSER END");

    emitPipeline(builder);

    builder->appendLine("// MARKER: DEPARSER BEGIN");
    // DEPARSER ================================================================
    builder->emitIndent();
    builder->target->emitMain(builder, "deparser", contextVar.c_str(), stdMetadataVar.c_str(), parser->headers->name.name);
    builder->blockStart();

    builder->emitIndent();
    builder->appendFormat("%s:\n", endLabel.c_str());
    builder->emitIndent();
    builder->blockStart();
    deparser->emit(builder);
    builder->blockEnd(true);

    builder->emitIndent();
    builder->appendFormat("if (%s && %s)\n", ingress->passVariable, egress->passVariable);
    builder->increaseIndent();
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->forwardReturnCode().c_str());
    builder->decreaseIndent();
    builder->emitIndent();
    builder->appendLine("else");
    builder->increaseIndent();
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->dropReturnCode().c_str());
    builder->decreaseIndent();

    builder->emitIndent();
    builder->appendFormat("reject: { return %s; }\n", builder->target->dropReturnCode());
    builder->blockEnd(true);
    builder->appendLine("// MARKER: DEPARSER END");

    cstring packetContextImpl =
    "PacketContext::PacketContext(uint16_t ingress_port, unsigned long id, const char *buffer, int len)\n"
    "    : id(id), buffer(512 + len)\n"
    "{\n"
    "    pkt = &this->buffer[512];\n"
    "    memcpy(pkt, buffer, len);\n"
    "\n"
    "    standard_metadata.ingress_port = ingress_port;\n"
    "}\n"
    "\n"
    "PacketContext::~PacketContext() {\n"
    "#if PACKET_CONTEXT_LOGGING\n"
    "    if (logfile.is_open()) {\n"
    "        logfile << std::endl;\n"
    "        logfile << \"======================================\" << std::endl;\n"
    "        logfile << \"End packet\" << std::endl;\n"
    "        logfile << \"======================================\" << std::endl;\n"
    "        logfile << std::endl;\n"
    "        logfile.close();\n"
    "    }\n"
    "#endif\n"
    "}\n"
    "\n"
    "void PacketContext::set_log_file(std::string path) {\n"
    "#if PACKET_CONTEXT_LOGGING\n"
    "    logfile.open(path, std::ofstream::app);\n"
    "    auto now = std::chrono::system_clock::now();\n"
    "    std::time_t time = std::chrono::system_clock::to_time_t(now);\n"
    "\n"
    "    logfile << std::endl;\n"
    "    logfile << \"======================================\" << std::endl;\n"
    "    logfile << \"Start packet: \" << std::ctime(&time);\n"
    "    logfile << \"======================================\" << std::endl;\n"
    "    logfile << std::endl;\n"
    "#endif\n"
    "}\n"
    "void PacketContext::log(std::string note) {\n"
    "#if PACKET_CONTEXT_LOGGING\n"
    "    if (!logfile.is_open()) {\n"
    "        return;\n"
    "    }\n"
    "\n"
    "    logfile << \"=== PACKET \" << id << \" (\" << note << \") ===\" << std::endl;\n"
    "    logfile << \"ingress_port = \" << standard_metadata.ingress_port << std::endl;\n"
    "    logfile << \"egress_spec  = \" << standard_metadata.egress_spec << std::endl;\n"
    "    logfile << \"egress_port  = \" << standard_metadata.egress_port << std::endl;\n"
    "    logfile << \"pkt_len      = \" << pkt_len << std::endl;\n"
    "    logfile << \"offset_bits  = \" << packetOffsetInBits << std::endl;\n"
    "\n"
    "    logfile << std::hex;\n"
    "    logfile << \"ethDst = \" << hdr.ethernet.dstAddr << std::endl;\n"
    "    logfile << \"ethSrc = \" << hdr.ethernet.srcAddr << std::endl;\n"
    "    logfile << \"ipDst  = \" << hdr.ipv4.dstAddr << std::endl;\n"
    "    logfile << \"ipSrc  = \" << hdr.ipv4.srcAddr << std::endl;\n"
    "\n"
    "    //   for (int i = 0; i < buffer.size(); i++) {\n"
    "    //     logfile << std::setfill('0') << std::setw(2) << ((int)bytes[i] &\n"
    "    //     0xff) << ' ';\n"
    "    //   }\n"
    "    logfile << std::dec << std::endl;\n"
    "#endif\n"
    "}\n";
    builder->append(packetContextImpl);
}

void UBPFProgram::emitH(EBPF::CodeBuilder *builder, cstring) {
    emitGeneratedComment(builder);
    builder->appendLine("#ifndef _P4_GEN_HEADER_");
    builder->appendLine("#define _P4_GEN_HEADER_");
    builder->target->emitIncludes(builder);
    builder->newline();
    emitTypes(builder);
    builder->newline();
    emitTableDefinition(builder);
    builder->newline();
    ingress->emitTableTypes(builder);
    egress->emitTableTypes(builder);

    // // Initialize tables
    // builder->appendLine("#if CONTROL_PLANE");
    // builder->appendLine("static void init_tables() ");
    // builder->blockStart();
    // builder->emitIndent();
    // builder->appendFormat("uint32_t %s = 0;", zeroKey.c_str());
    // builder->newline();
    // ingress->emitTableInitializers(builder);
    // egress->emitTableInitializers(builder);
    // builder->blockEnd(true);
    // builder->appendLine("#endif");

    cstring packetContextDef =
    "struct PacketContext {\n"
    "    uint8_t *pkt;  // should already be set to a pointer in buffer\n"
    "    uint32_t pkt_len;\n"
    "    struct headers hdr = {};  // this should be passed into the parser/pipelines\n"
    "    struct metadata meta = {};  // this should be passed into the parser/pipelines\n"
    "    struct standard_metadata_t standard_metadata = {};\n"
    "\n"
    "    int packetOffsetInBits = 0;\n"
    "    uint8_t pass = 1;\n"
    "    uint8_t pass_0 = 1;\n"
    "    uint8_t hit = 0;\n"
    "    uint8_t hit_0 = 0;\n"
    "    unsigned char ebpf_byte;\n"
    "    uint32_t ebpf_zero = 0;\n"
    "    int packetTruncatedSize = -1;\n"
    "\n"
    "    std::vector<uint8_t> buffer;  // should alread be set\n"
    "\n"
    "    unsigned long id;\n"
    "    PacketContext(uint16_t ingress_port, unsigned long id, const char *buffer, int len);\n"
    "    ~PacketContext();\n"
    "    std::ofstream logfile;\n"
    "    void set_log_file(std::string path);\n"
    "    void log(std::string note);\n"
    "};\n";
    builder->append(packetContextDef);

    ingress->emitTableMapDeclarations(builder);
    egress->emitTableMapDeclarations(builder);

    auto *ubuilder = static_cast<UbpfCodeBuilder *>(builder);
    ubuilder->target->emitMain(builder, "parser", "", "", "");
    builder->append(";\n");
    ubuilder->target->emitMain(builder, "ingress", "", "", "");
    builder->append(";\n");
    ubuilder->target->emitMain(builder, "egress", "", "", "");
    builder->append(";\n");
    ubuilder->target->emitMain(builder, "deparser", "", "", "");
    builder->append(";\n");

    builder->appendLine("#endif");
}

void UBPFProgram::emitPreamble(EBPF::CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendLine("#define BPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)");
    builder->appendLine("#define BYTES(w) ((w) / 8)");
    builder->newline();
    builder->appendLine("void* memcpy(void* dest, const void* src, size_t num);");
    builder->newline();
}

void UBPFProgram::emitTypes(EBPF::CodeBuilder *builder) {
    for (auto d : program->objects) {
        if (d->is<IR::Type>() && !d->is<IR::IContainer>() && !d->is<IR::Type_Extern>() &&
            !d->is<IR::Type_Parser>() && !d->is<IR::Type_Control>() && !d->is<IR::Type_Typedef>() &&
            !d->is<IR::Type_Error>()) {
            CHECK_NULL(UBPFTypeFactory::instance);
            auto type = UBPFTypeFactory::instance->create(d->to<IR::Type>());
            if (type == nullptr) continue;
            type->emit(builder);
            builder->newline();
        }
    }
}

void UBPFProgram::emitTableDefinition(EBPF::CodeBuilder *builder) const {
    builder->append("enum ");
    builder->append("ubpf_map_type");
    builder->spc();
    builder->blockStart();

    builder->emitIndent();
    builder->append("UBPF_MAP_TYPE_ARRAY = 1,");
    builder->newline();

    builder->emitIndent();
    builder->append("UBPF_MAP_TYPE_HASHMAP = 4,");
    builder->newline();

    builder->emitIndent();
    builder->append("UBPF_MAP_TYPE_LPM_TRIE = 5,");
    builder->newline();

    builder->blockEnd(false);
    builder->endOfStatement(true);

    // definition of ubpf map
    builder->append("struct ");
    builder->append("ubpf_map_def");
    builder->spc();
    builder->blockStart();

    builder->emitIndent();
    builder->append("enum ubpf_map_type type;");
    builder->newline();

    builder->emitIndent();
    builder->append("unsigned int id;");
    builder->newline();

    builder->emitIndent();
    builder->append("unsigned int key_size;");
    builder->newline();

    builder->emitIndent();
    builder->append("unsigned int value_size;");
    builder->newline();

    builder->emitIndent();
    builder->append("unsigned int max_entries;");
    builder->newline();

    // builder->emitIndent();
    // builder->append("unsigned int nb_hash_functions;");
    // builder->newline();

    builder->blockEnd(false);
    builder->endOfStatement(true);
}

void UBPFProgram::emitPktVariable(UbpfCodeBuilder *builder) const {
    builder->emitIndent();
    builder->appendFormat("void *%s = ", packetStartVar.c_str());
    builder->target->emitGetPacketData(builder, contextVar);
    builder->endOfStatement(true);
}

void UBPFProgram::emitPacketLengthVariable(UbpfCodeBuilder *builder) const {
    builder->emitIndent();
    // builder->appendFormat("uint32_t %s = ", lengthVar.c_str());
    builder->appendFormat("%s = ", lengthVar.c_str());
    builder->target->emitGetFromStandardMetadata(builder, stdMetadataVar, "packet_length");
    builder->endOfStatement(true);
}

void UBPFProgram::emitHeaderInstances(EBPF::CodeBuilder *builder) {
    builder->emitIndent();
    parser->headerType->declare(builder, parser->headers->name.name, false);
}

void UBPFProgram::emitMetadataInstance(EBPF::CodeBuilder *builder) const {
    builder->emitIndent();
    parser->metadataType->declare(builder, parser->metadata->name.name, false);
}

void UBPFProgram::emitLocalVariables(EBPF::CodeBuilder *builder) {
    builder->emitIndent();
    builder->appendFormat("int %s = 0;", offsetVar.c_str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("uint8_t %s = 1;", ingress->passVariable);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("uint8_t %s = 1;", egress->passVariable);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("uint8_t %s = 0;", ingress->hitVariable);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("uint8_t %s = 0;", egress->hitVariable);
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("unsigned char %s;", byteVar.c_str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("uint32_t %s = 0;", zeroKey.c_str());
    builder->newline();

    builder->emitIndent();
    builder->appendFormat("int %s = -1;", packetTruncatedSizeVar.c_str());
    builder->newline();
}

void UBPFProgram::emitPipeline(EBPF::CodeBuilder *builder) {
    builder->appendLine("// MARKER: INGRESS BEGIN");
    // INGRESS =================================================================
    builder->emitIndent();
    static_cast<UbpfCodeBuilder *>(builder)->
        target->emitMain(builder, "ingress", contextVar.c_str(), stdMetadataVar.c_str(), ingress->headers->name.name);
    builder->blockStart();

    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(": // ingress");
    builder->newline();
    builder->emitIndent();
    builder->blockStart();
    currentControlBlock = ingress;
    ingress->emit(builder);
    builder->blockEnd(true);
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->forwardReturnCode());
    builder->blockEnd(true);
    builder->appendLine("// MARKER: INGRESS END");

    builder->appendLine("// MARKER: EGRESS BEGIN");
    // EGRESS ==================================================================
    builder->emitIndent();
    static_cast<UbpfCodeBuilder *>(builder)->
        target->emitMain(builder, "egress", contextVar.c_str(), stdMetadataVar.c_str(), ingress->headers->name.name);
    builder->blockStart();

    builder->emitIndent();
    builder->append("egress");
    builder->append(":");
    builder->newline();
    builder->emitIndent();
    builder->blockStart();
    currentControlBlock = egress;
    egress->emit(builder);
    builder->blockEnd(true);
    builder->emitIndent();
    builder->appendFormat("return %s;\n", builder->target->forwardReturnCode());
    builder->blockEnd(true);
    builder->appendLine("// MARKER: EGRESS END");

    currentControlBlock = nullptr;
}

}  // namespace UBPF
