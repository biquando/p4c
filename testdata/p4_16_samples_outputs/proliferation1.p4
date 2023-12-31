#include <core.p4>
#define V1MODEL_VERSION 20180101
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> f;
}

struct headers {
    ethernet_t ethernet;
}

struct metadata {
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action do_round(inout bit<16> x) {
        x = x - 1 & x;
    }
    action do_n_rounds(inout bit<16> x) {
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
        do_round(x);
    }
    apply {
        if (hdr.ethernet.isValid()) {
            do_n_rounds(hdr.ethernet.f);
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
