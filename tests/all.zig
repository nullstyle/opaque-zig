comptime {
    _ = @import("opaque_root");
    _ = @import("messages_test.zig");
    _ = @import("oprf_test.zig");
    _ = @import("opaque_test.zig");
    _ = @import("opaque_negative_test.zig");
    _ = @import("wasm_abi_test.zig");
}
