#include <core.p4>

parser p() {
    @name("p.x") bit<32> x_0;
    state start {
        transition select(x_0) {
            32w0: reject;
            default: noMatch;
        }
    }
    state noMatch {
        verify(false, error.NoMatch);
        transition reject;
    }
}

parser e();
package top(e e);
top(p()) main;
