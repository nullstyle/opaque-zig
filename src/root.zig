const builtin = @import("builtin");

pub const constants = @import("constants.zig");
pub const messages = @import("messages.zig");
pub const oprf = @import("oprf.zig");
pub const protocol = @import("opaque.zig");

/// The WASM C ABI. It carries a 32 MiB static buffer and `export`s C symbols
/// (`allocate`, `free`, ...) that have no place in a native library consumer's
/// binary. So it is only surfaced on the wasm32 target (where it is the actual
/// module being built) and in test builds (so tests/all.zig can pull in its
/// tests against the shared library module). Native, non-test consumers that
/// `@import("opaque")` get an empty struct and pay nothing for it.
pub const wasm_abi = if (builtin.target.cpu.arch == .wasm32 or builtin.is_test)
    @import("wasm.zig")
else
    struct {};

test {
    _ = constants;
    _ = messages;
    _ = oprf;
    _ = protocol;
    _ = wasm_abi;
}
