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

    // cstring lookup =
    //     "using std::vector;\n"
    //     "using std::unordered_map;\n"
    //     "vector<bf_lpm_trie_t *> lpm_tables;\n"
    //     "vector<vector<char *>> array_tables_keys;\n"
    //     "vector<vector<void *>> array_tables_vals;\n"
    //     "vector<unordered_map<uint64_t, void *>> hashmap_tables;\n"
    //     "\n"
    //     "void map_create(ubpf_map_def *tbl) {\n"
    //     "    bf_lpm_trie_t *lpm_p;\n"
    //     "    switch (tbl->type) {\n"
    //     "      case UBPF_MAP_TYPE_LPM_TRIE:\n"
    //     "        lpm_p = bf_lpm_trie_create(tbl->key_size, false);\n"
    //     "        lpm_tables.push_back(lpm_p);\n"
    //     "        break;\n"
    //     "      case UBPF_MAP_TYPE_ARRAY:\n"
    //     "        array_tables_keys.emplace_back();\n"
    //     "        break;\n"
    //     "      case UBPF_MAP_TYPE_HASHMAP:\n"
    //     "        array_tables_keys.emplace_back();\n"
    //     "        break;\n"
    //     "    }\n"
    //     "}\n"
    //     "\n"
    //     "uint64_t hashmap_key(void *key, unsigned size) {\n"
    //     "    uint64_t i = 0;\n"
    //     "    memcpy(&i, key, size <= 8 ? size : 8);\n"
    //     "    return i;\n"
    //     "}\n"
    //     "\n"
    //     "void *map_lookup(ubpf_map_def *tbl, void *key) {\n"
    //     "    unsigned id = tbl->id;\n"
    //     "    unsigned key_size = tbl->key_size;\n"
    //     "    void *val = nullptr;\n"
    //     "\n"
    //     "    bf_lpm_trie_t *lpm;\n"
    //     "    value_t lpmval;\n"
    //     "    vector<char *> *keys;\n"
    //     "    vector<void *> *vals;\n"
    //     "    int nkeys;\n"
    //     "    unordered_map<uint64_t, void *> map;\n"
    //     "    uint64_t key_int;\n"
    //     "    switch (tbl->type) {\n"
    //     "      case UBPF_MAP_TYPE_LPM_TRIE:\n"
    //     "        lpm = lpm_tables[id];\n"
    //     "        bf_lpm_trie_lookup(lpm, (char *)key, &lpmval);\n"
    //     "        val = (void *)lpmval;\n"
    //     "        break;\n"
    //     "      case UBPF_MAP_TYPE_ARRAY:\n"
    //     "        keys = &array_tables_keys[id];\n"
    //     "        vals = &array_tables_vals[id];\n"
    //     "        nkeys = keys->size();\n"
    //     "        for (int i = 0; i < nkeys; i++) {\n"
    //     "            if (memcmp((*keys)[i], (char *)key, key_size) == 0) {\n"
    //     "                val = (*vals)[i];\n"
    //     "                break;\n"
    //     "            }\n"
    //     "        }\n"
    //     "        break;\n"
    //     "      case UBPF_MAP_TYPE_HASHMAP:\n"
    //     "        map = hashmap_tables[id];\n"
    //     "        key_int = hashmap_key(key, key_size);\n"
    //     "        if (map.find(key_int) == map.end()) {\n"
    //     "            break;\n"
    //     "        }\n"
    //     "        val = map[key_int];\n"
    //     "        break;\n"
    //     "    }\n"
    //     "    return val;\n"
    //     "}\n";
    // builder->append(lookup);

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

    builder->emitIndent();
    builder->target->emitMain(builder, "entry", contextVar.c_str(), stdMetadataVar.c_str());
    builder->blockStart();

    emitPktVariable(builder);

    emitPacketLengthVariable(builder);

    emitHeaderInstances(builder);
    builder->append(" = ");
    parser->headerType->emitInitializer(builder);
    builder->endOfStatement(true);

    emitMetadataInstance(builder);
    builder->append(" = ");
    parser->metadataType->emitInitializer(builder);
    builder->endOfStatement(true);

    emitLocalVariables(builder);
    builder->newline();
    builder->appendLine("// MARKER: PARSER BEGIN");
    builder->emitIndent();
    builder->appendFormat("goto %s;", IR::ParserState::start.c_str());
    builder->newline();

    parser->emit(builder);
    builder->appendLine("// MARKER: PARSER END");

    emitPipeline(builder);

    builder->appendLine("// MARKER: DEPARSER BEGIN");
    builder->emitIndent();
    builder->appendFormat("%s:\n", endLabel.c_str());
    builder->emitIndent();
    builder->blockStart();
    deparser->emit(builder);
    builder->blockEnd(true);
    builder->appendLine("// MARKER: DEPARSER END");

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
    builder->blockEnd(true);
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
    builder->appendLine("#if CONTROL_PLANE");
    builder->appendLine("static void init_tables() ");
    builder->blockStart();
    builder->emitIndent();
    builder->appendFormat("uint32_t %s = 0;", zeroKey.c_str());
    builder->newline();
    ingress->emitTableInitializers(builder);
    egress->emitTableInitializers(builder);
    builder->blockEnd(true);
    builder->appendLine("#endif");
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
    // builder->appendFormat("void *%s = ", packetStartVar.c_str());
    builder->appendFormat("void *%s = ", packetStartVar.c_str());
    builder->target->emitGetPacketData(builder, contextVar);
    builder->endOfStatement(true);
}

void UBPFProgram::emitPacketLengthVariable(UbpfCodeBuilder *builder) const {
    builder->emitIndent();
    builder->appendFormat("uint32_t %s = ", lengthVar.c_str());
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
    builder->emitIndent();
    builder->append(IR::ParserState::accept);
    builder->append(": // ingress");
    builder->newline();
    builder->emitIndent();
    builder->blockStart();
    currentControlBlock = ingress;
    ingress->emit(builder);
    builder->blockEnd(true);
    builder->appendLine("// MARKER: INGRESS END");

    builder->appendLine("// MARKER: EGRESS BEGIN");
    builder->emitIndent();
    builder->append("egress");
    builder->append(":");
    builder->newline();
    builder->emitIndent();
    builder->blockStart();
    currentControlBlock = egress;
    egress->emit(builder);
    builder->blockEnd(true);
    builder->appendLine("// MARKER: EGRESS END");

    currentControlBlock = nullptr;
}

}  // namespace UBPF
