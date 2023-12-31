#include <core.p4>

header Header {
    bit<32> data1;
    bit<32> data2;
    bit<32> data3;
}

extern void func(in Header h);
extern bit<32> g(inout bit<32> v, in bit<32> w);
@noWarn("uninitialized_use") parser p1(packet_in p, out Header h) {
    Header[2] stack;
    bool b;
    bool c;
    bool d;
    @noWarn("invalid_header") @noWarn("ordering") state start {
        h.data1 = 0;
        func(h);
        g(h.data2, g(h.data2, h.data2));
        transition next;
    }
    @noWarn("invalid_header") state next {
        h.data2 = h.data3 + 1;
        stack[0] = stack[1];
        b = stack[1].isValid();
        transition select(h.isValid()) {
            true: next1;
            false: next2;
        }
    }
    state next1 {
        d = false;
        transition next3;
    }
    state next2 {
        c = true;
        d = c;
        transition next3;
    }
    state next3 {
        c = !c;
        d = !d;
        transition accept;
    }
}

control c(out bit<32> v) {
    bit<32> b;
    bit<32> d = 1;
    bit<32> setByAction;
    action a1() {
        setByAction = 1;
    }
    action a2() {
        setByAction = 1;
    }
    table t {
        actions = {
            a1;
            a2;
        }
        default_action = a1();
    }
    apply @noWarn("uninitialized_use") {
        b = b + 1;
        d = d + 1;
        bit<32> e;
        bit<32> f;
        if (e > 0) {
            e = 1;
            f = 2;
        } else {
            f = 3;
        }
        e = e + 1;
        bool touched;
        switch (t.apply().action_run) {
            a1: {
                touched = true;
            }
        }
        touched = !touched;
        if (e > 0) {
            t.apply();
        } else {
            a1();
        }
        setByAction = setByAction + 1;
    }
}

parser proto(packet_in p, out Header h);
control cproto(out bit<32> v);
package top(proto _p, cproto _c);
top(p1(), c()) main;
