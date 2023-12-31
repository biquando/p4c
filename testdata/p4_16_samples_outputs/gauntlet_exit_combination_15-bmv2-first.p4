#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> eth_type;
}

struct Headers {
    ethernet_t eth_hdr;
}

struct Meta {
}

parser p(packet_in pkt, out Headers hdr, inout Meta m, inout standard_metadata_t sm) {
    state start {
        transition parse_hdrs;
    }
    state parse_hdrs {
        pkt.extract<ethernet_t>(hdr.eth_hdr);
        transition accept;
    }
}

control ingress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    action simple_action() {
        h.eth_hdr.src_addr = 48w1;
    }
    table simple_table {
        key = {
            48w1: exact @name("Vmhbwk");
        }
        actions = {
            simple_action();
            NoAction();
        }
        default_action = NoAction();
    }
    apply {
        switch (simple_table.apply().action_run) {
            simple_action: {
                h.eth_hdr.eth_type = 16w1;
                exit;
            }
            NoAction: {
                h.eth_hdr.eth_type = 16w2;
                exit;
            }
            default: {
                h.eth_hdr.eth_type = 16w3;
                exit;
            }
        }
        h.eth_hdr.eth_type = 16w4;
        exit;
    }
}

control vrfy(inout Headers h, inout Meta m) {
    apply {
    }
}

control update(inout Headers h, inout Meta m) {
    apply {
    }
}

control egress(inout Headers h, inout Meta m, inout standard_metadata_t sm) {
    apply {
    }
}

control deparser(packet_out pkt, in Headers h) {
    apply {
        pkt.emit<Headers>(h);
    }
}

V1Switch<Headers, Meta>(p(), vrfy(), ingress(), egress(), update(), deparser()) main;
