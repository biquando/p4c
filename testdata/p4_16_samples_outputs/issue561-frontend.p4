header H1 {
    bit<32> f;
}

header H2 {
    bit<32> g;
}

header_union U {
    H1 h1;
    H2 h2;
}

control ct(out bit<32> b);
package top(ct _ct);
control c(out bit<32> x) {
    @name("c.u") U u_0;
    @name("c.u2") U[2] u2_0;
    apply {
        u_0.h1.setInvalid();
        u_0.h2.setInvalid();
        u2_0[0].h1.setInvalid();
        u2_0[0].h2.setInvalid();
        u2_0[1].h1.setInvalid();
        u2_0[1].h2.setInvalid();
        x = u_0.h1.f + u_0.h2.g;
        u_0.h1.setValid();
        u_0.h1.f = 32w0;
        x = x + u_0.h1.f;
        u_0.h2.g = 32w0;
        x = x + u_0.h2.g;
        u2_0[0].h1.setValid();
        u2_0[0].h1.f = 32w2;
        x = x + u2_0[1].h2.g + u2_0[0].h1.f;
    }
}

top(c()) main;
