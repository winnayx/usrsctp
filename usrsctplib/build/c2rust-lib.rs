#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(asm)]
#![feature(c_variadic)]
#![feature(const_raw_ptr_to_usize_cast)]
#![feature(core_intrinsics)]
#![feature(extern_types)]
#![feature(label_break_value)]
#![feature(main)]
#![feature(ptr_wrapping_offset_from)]
#![feature(register_tool)]
#![register_tool(c2rust)]

#[macro_use]
extern crate c2rust_bitfields;
#[macro_use]
extern crate c2rust_asm_casts;
extern crate libc;

#[path = "../usrsctplib/netinet6/sctp6_usrreq.rs"]
pub mod sctp6_usrreq;
#[path = "../usrsctplib/netinet/sctp_asconf.rs"]
pub mod sctp_asconf;
#[path = "../usrsctplib/netinet/sctp_auth.rs"]
pub mod sctp_auth;
#[path = "../usrsctplib/netinet/sctp_bsd_addr.rs"]
pub mod sctp_bsd_addr;
#[path = "../usrsctplib/netinet/sctp_callout.rs"]
pub mod sctp_callout;
#[path = "../usrsctplib/netinet/sctp_cc_functions.rs"]
pub mod sctp_cc_functions;
#[path = "../usrsctplib/netinet/sctp_crc32.rs"]
pub mod sctp_crc32;
#[path = "../usrsctplib/netinet/sctp_indata.rs"]
pub mod sctp_indata;
#[path = "../usrsctplib/netinet/sctp_input.rs"]
pub mod sctp_input;
#[path = "../usrsctplib/netinet/sctp_output.rs"]
pub mod sctp_output;
#[path = "../usrsctplib/netinet/sctp_pcb.rs"]
pub mod sctp_pcb;
#[path = "../usrsctplib/netinet/sctp_peeloff.rs"]
pub mod sctp_peeloff;
#[path = "../usrsctplib/netinet/sctp_sha1.rs"]
pub mod sctp_sha1;
#[path = "../usrsctplib/netinet/sctp_ss_functions.rs"]
pub mod sctp_ss_functions;
#[path = "../usrsctplib/netinet/sctp_sysctl.rs"]
pub mod sctp_sysctl;
#[path = "../usrsctplib/netinet/sctp_timer.rs"]
pub mod sctp_timer;
#[path = "../usrsctplib/netinet/sctp_userspace.rs"]
pub mod sctp_userspace;
#[path = "../usrsctplib/netinet/sctp_usrreq.rs"]
pub mod sctp_usrreq;
#[path = "../usrsctplib/netinet/sctputil.rs"]
pub mod sctputil;
#[path = "../usrsctplib/user_environment.rs"]
pub mod user_environment;
#[path = "../usrsctplib/user_mbuf.rs"]
pub mod user_mbuf;
#[path = "../usrsctplib/user_recv_thread.rs"]
pub mod user_recv_thread;
#[path = "../usrsctplib/user_socket.rs"]
pub mod user_socket;
