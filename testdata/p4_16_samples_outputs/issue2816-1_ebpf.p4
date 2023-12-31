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
        transition select(headers.ethernet.etherType) {
            16w0x800: ip;
            default: reject;
        }
    }
    state ip {
        p.extract(headers.ipv4);
        transition select(headers.ipv4.ihl, headers.ipv4.protocol, headers.ipv4.diffserv) {
            (default, default, default): parse_l4;
            (default, 17, default): parse_l4;
            (default, default, 1): parse_l4;
            default: reject;
        }
    }
    state parse_l4 {
        transition accept;
    }
}

control pipe(inout Headers_t headers, out bool pass) {
    action Reject(IPv4Address add) {
        pass = false;
        headers.ipv4.srcAddr = add;
    }
    table Check_src_ip {
        key = {
            headers.ipv4.srcAddr: exact;
        }
        actions = {
            Reject;
            NoAction;
        }
        implementation = hash_table(1024);
        const default_action = NoAction;
    }
    apply {
        pass = true;
        switch (Check_src_ip.apply().action_run) {
            Reject: {
                pass = false;
            }
            NoAction: {
            }
        }
    }
}

ebpfFilter(prs(), pipe()) main;
