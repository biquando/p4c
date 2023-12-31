extern E<V> {
    E(V param);
    void run();
}

struct S {
    bit<32> f;
}

control c() {
    E<S>((S){f = 32w5}) e;
    apply {
        e.run();
    }
}

control C();
package top(C _c);
top(c()) main;
