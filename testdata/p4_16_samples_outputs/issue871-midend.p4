extern lpf<I> {
    lpf(I instance_count);
    T execute<T>(in T data, in I index);
}

control c() {
    @name("c.lpf_0") lpf<bit<32>>(32w32) lpf_1;
    @hidden action issue871l11() {
        lpf_1.execute<bit<8>>(8w0, 32w0);
    }
    @hidden table tbl_issue871l11 {
        actions = {
            issue871l11();
        }
        const default_action = issue871l11();
    }
    apply {
        tbl_issue871l11.apply();
    }
}

control e();
package top(e _e);
top(c()) main;
