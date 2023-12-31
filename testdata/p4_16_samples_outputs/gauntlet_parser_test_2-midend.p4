#include <core.p4>

header Hdr {
    bit<8> x;
}

struct Headers {
    Hdr[2] h1;
}

parser P(packet_in p, out Headers h) {
    state start {
        p.extract<Hdr>(h.h1.next);
        transition select(h.h1.last.x) {
            8w0: start;
            default: accept;
        }
    }
}

parser Simple<T>(packet_in p, out T t);
package top<T>(Simple<T> prs);
top<Headers>(P()) main;
