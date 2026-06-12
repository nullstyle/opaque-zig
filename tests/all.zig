comptime {
    _ = @import("opaque_root");
    _ = @import("messages_test.zig");
    _ = @import("oprf_test.zig");
    _ = @import("opaque_test.zig");
    _ = @import("opaque_negative_test.zig");
    _ = @import("ksf_test.zig");
    _ = @import("fake_record_test.zig");
    _ = @import("rfc9807_vectors_test.zig");
    _ = @import("runtime_canary_test.zig");
    _ = @import("h2c_map_test.zig");
    _ = @import("loworder_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("wasm_abi_test.zig");
}
