#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

struct s1_t {
    bit<8> f8;
}

struct choices_t {
    s1_t entry0;
    s1_t entry1;
    s1_t entry2;
    s1_t entry3;
}

struct my_meta_t {
    s1_t entry;
}

struct parsed_packet_t {
}

parser parse(packet_in pk, out parsed_packet_t hdr, inout my_meta_t my_metadata, inout standard_metadata_t standard_metadata) {
    state start {
        transition accept;
    }
}

extern s1_t choose_entry(in choices_t choices);
control ingress(inout parsed_packet_t hdr, inout my_meta_t my_meta, inout standard_metadata_t standard_metadata) {
    @noWarn("unused") @name(".NoAction") action NoAction_1() {
    }
    @name("ingress.select_entry") action select_entry(@name("choices") choices_t choices_1) {
        my_meta.entry = choose_entry(choices_1);
    }
    @name("ingress.t") table t_0 {
        actions = {
            select_entry();
            NoAction_1();
        }
        const default_action = NoAction_1();
    }
    apply {
        t_0.apply();
    }
}

control egress(inout parsed_packet_t hdr, inout my_meta_t my_meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control deparser(packet_out b, in parsed_packet_t hdr) {
    apply {
    }
}

control verify_c(inout parsed_packet_t hdr, inout my_meta_t my_meta) {
    apply {
    }
}

control compute_c(inout parsed_packet_t hdr, inout my_meta_t my_meta) {
    apply {
    }
}

V1Switch<parsed_packet_t, my_meta_t>(parse(), verify_c(), ingress(), egress(), compute_c(), deparser()) main;
