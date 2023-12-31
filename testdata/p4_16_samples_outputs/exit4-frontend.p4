control ctrl() {
    @name("ctrl.e") action e() {
        exit;
    }
    @name("ctrl.t") table t_0 {
        actions = {
            e();
        }
        default_action = e();
    }
    apply {
        if (t_0.apply().hit) {
            t_0.apply();
        } else {
            t_0.apply();
        }
    }
}

control noop();
package p(noop _n);
p(ctrl()) main;
