pub const wasm_abi_version: u32 = 3;

pub const Nn: usize = 32;
pub const Nseed: usize = 32;
pub const Nh: usize = 64;
pub const Npk: usize = 32;
pub const Nsk: usize = 32;
pub const Nm: usize = 64;
pub const Nx: usize = 64;
pub const Nok: usize = 32;
pub const Noe: usize = 32;
pub const blind_uniform_len: usize = 64;

pub const envelope_len: usize = Nn + Nm;
pub const masked_response_len: usize = Npk + envelope_len;

pub const registration_request_len: usize = Noe;
pub const registration_response_len: usize = Noe + Npk;
pub const registration_record_len: usize = Npk + Nh + envelope_len;

pub const credential_request_len: usize = Noe;
pub const credential_response_len: usize = Noe + Nn + masked_response_len;

pub const auth_request_len: usize = Nn + Npk;
pub const auth_response_len: usize = Nn + Npk + Nm;
pub const ke1_len: usize = credential_request_len + auth_request_len;
pub const ke2_len: usize = credential_response_len + auth_response_len;
pub const ke3_len: usize = Nm;

pub const client_login_state_len: usize = Nsk + Nsk + ke1_len;
pub const server_login_state_len: usize = Nm + Nx;
