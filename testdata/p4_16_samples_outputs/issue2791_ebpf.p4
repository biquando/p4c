#include <core.p4>
#include <ebpf_model.p4>

@ethernetaddress typedef bit<48> EthernetAddress;
@ipv4address typedef bit<32> IPv4Address;
header Ethernet_h {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header IPv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    IPv4Address srcAddr;
    IPv4Address dstAddr;
}

struct Headers_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
}

parser prs(packet_in p, out Headers_t headers) {
    state start {
        p.extract(headers.ethernet);
        transition select(headers.ethernet.etherType, 16w1) {
            (16w0x800, 16w1): ip;
            default: reject;
        }
    }
    state ip {
        p.extract(headers.ipv4);
        transition accept;
    }
}

control pipe(inout Headers_t headers, out bool pass) {
    action invalidate() {
        headers.ipv4.setInvalid();
        headers.ethernet.setInvalid();
        pass = true;
    }
    action drop() {
        pass = false;
    }
    table t {
        key = {
            headers.ipv4.srcAddr    : exact;
            headers.ipv4.dstAddr    : exact;
            headers.ethernet.dstAddr: exact;
            headers.ethernet.srcAddr: exact;
        }
        actions = {
            invalidate;
            drop;
        }
        implementation = hash_table(10);
        default_action = drop;
    }
    apply {
        t.apply();
    }
}

ebpfFilter(prs(), pipe()) main;
