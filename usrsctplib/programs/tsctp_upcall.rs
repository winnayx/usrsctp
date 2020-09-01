use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    /* Standard TCP Congestion Control */
    /* High Speed TCP Congestion Control (Floyd) */
    /* HTCP Congestion Control */
    /* RTCC Congestion Control - RFC2581 plus */
    /* RS - Supported stream scheduling modules for pluggable
 * stream scheduling
 */
/* Default simple round-robin */
    /* Real round-robin */
    /* Real round-robin per packet */
    /* Priority */
    /* Fair Bandwidth */
    /* First-come, first-serve */
    /* ******************* System calls *************/
    pub type socket;
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn inet_pton(__af: libc::c_int, __cp: *const libc::c_char,
                 __buf: *mut libc::c_void) -> libc::c_int;
    #[no_mangle]
    fn inet_ntop(__af: libc::c_int, __cp: *const libc::c_void,
                 __buf: *mut libc::c_char, __len: socklen_t)
     -> *const libc::c_char;
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t)
     -> libc::c_int;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    static mut optarg: *mut libc::c_char;
    #[no_mangle]
    static mut optind: libc::c_int;
    #[no_mangle]
    fn getopt(___argc: libc::c_int, ___argv: *const *mut libc::c_char,
              __shortopts: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    static mut stdout: *mut FILE;
    #[no_mangle]
    static mut stderr: *mut FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn usrsctp_init(_: uint16_t,
                    _:
                        Option<unsafe extern "C" fn(_: *mut libc::c_void,
                                                    _: *mut libc::c_void,
                                                    _: size_t, _: uint8_t,
                                                    _: uint8_t)
                                   -> libc::c_int>,
                    _:
                        Option<unsafe extern "C" fn(_: *const libc::c_char,
                                                    _: ...) -> ()>);
    #[no_mangle]
    fn usrsctp_socket(domain: libc::c_int, type_0: libc::c_int,
                      protocol: libc::c_int,
                      receive_cb:
                          Option<unsafe extern "C" fn(_: *mut socket,
                                                      _: sctp_sockstore,
                                                      _: *mut libc::c_void,
                                                      _: size_t,
                                                      _: sctp_rcvinfo,
                                                      _: libc::c_int,
                                                      _: *mut libc::c_void)
                                     -> libc::c_int>,
                      send_cb:
                          Option<unsafe extern "C" fn(_: *mut socket,
                                                      _: uint32_t)
                                     -> libc::c_int>, sb_threshold: uint32_t,
                      ulp_info: *mut libc::c_void) -> *mut socket;
    #[no_mangle]
    fn usrsctp_setsockopt(so: *mut socket, level: libc::c_int,
                          option_name: libc::c_int,
                          option_value: *const libc::c_void,
                          option_len: socklen_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_getsockopt(so: *mut socket, level: libc::c_int,
                          option_name: libc::c_int,
                          option_value: *mut libc::c_void,
                          option_len: *mut socklen_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sendv(so: *mut socket, data: *const libc::c_void, len: size_t,
                     to: *mut sockaddr, addrcnt: libc::c_int,
                     info: *mut libc::c_void, infolen: socklen_t,
                     infotype: libc::c_uint, flags: libc::c_int) -> ssize_t;
    #[no_mangle]
    fn usrsctp_recvv(so: *mut socket, dbuf: *mut libc::c_void, len: size_t,
                     from: *mut sockaddr, fromlen: *mut socklen_t,
                     info: *mut libc::c_void, infolen: *mut socklen_t,
                     infotype: *mut libc::c_uint, msg_flags: *mut libc::c_int)
     -> ssize_t;
    #[no_mangle]
    fn usrsctp_bind(so: *mut socket, name: *mut sockaddr, namelen: socklen_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_listen(so: *mut socket, backlog: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_accept(so: *mut socket, aname: *mut sockaddr,
                      anamelen: *mut socklen_t) -> *mut socket;
    #[no_mangle]
    fn usrsctp_connect(so: *mut socket, name: *mut sockaddr,
                       namelen: socklen_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_close(so: *mut socket);
    #[no_mangle]
    fn usrsctp_finish() -> libc::c_int;
    #[no_mangle]
    fn usrsctp_set_non_blocking(_: *mut socket, _: libc::c_int)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_set_upcall(so: *mut socket,
                          upcall:
                              Option<unsafe extern "C" fn(_: *mut socket,
                                                          _:
                                                              *mut libc::c_void,
                                                          _: libc::c_int)
                                         -> ()>, arg: *mut libc::c_void)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_get_events(so: *mut socket) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_no_csum_on_loopback(value: uint32_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_enable_sack_immediately(value: uint32_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_blackhole(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_debug_on(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn debug_printf_stack(format: *const libc::c_char, _: ...);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
pub type socklen_t = __socklen_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
pub type C2RustUnnamed = libc::c_uint;
pub const MSG_CMSG_CLOEXEC: C2RustUnnamed = 1073741824;
pub const MSG_FASTOPEN: C2RustUnnamed = 536870912;
pub const MSG_ZEROCOPY: C2RustUnnamed = 67108864;
pub const MSG_BATCH: C2RustUnnamed = 262144;
pub const MSG_WAITFORONE: C2RustUnnamed = 65536;
pub const MSG_MORE: C2RustUnnamed = 32768;
pub const MSG_NOSIGNAL: C2RustUnnamed = 16384;
pub const MSG_ERRQUEUE: C2RustUnnamed = 8192;
pub const MSG_RST: C2RustUnnamed = 4096;
pub const MSG_CONFIRM: C2RustUnnamed = 2048;
pub const MSG_SYN: C2RustUnnamed = 1024;
pub const MSG_FIN: C2RustUnnamed = 512;
pub const MSG_WAITALL: C2RustUnnamed = 256;
pub const MSG_EOR: C2RustUnnamed = 128;
pub const MSG_DONTWAIT: C2RustUnnamed = 64;
pub const MSG_TRUNC: C2RustUnnamed = 32;
pub const MSG_PROXY: C2RustUnnamed = 16;
pub const MSG_CTRUNC: C2RustUnnamed = 8;
pub const MSG_TRYHARD: C2RustUnnamed = 4;
pub const MSG_DONTROUTE: C2RustUnnamed = 4;
pub const MSG_PEEK: C2RustUnnamed = 2;
pub const MSG_OOB: C2RustUnnamed = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
pub type uint64_t = __uint64_t;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_1 = 256;
pub const IPPROTO_RAW: C2RustUnnamed_1 = 255;
pub const IPPROTO_MPLS: C2RustUnnamed_1 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_1 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_1 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_1 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_1 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_1 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_1 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_1 = 92;
pub const IPPROTO_AH: C2RustUnnamed_1 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_1 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_1 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_1 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_1 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_1 = 33;
pub const IPPROTO_TP: C2RustUnnamed_1 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_1 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_1 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_1 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_1 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_1 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_1 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_1 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_1 = 1;
pub const IPPROTO_IP: C2RustUnnamed_1 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}
pub type __timezone_ptr_t = *mut timezone;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type sctp_assoc_t = uint32_t;
/* The definition of struct sockaddr_conn MUST be in
 * tune with other sockaddr_* structures.
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_conn {
    pub sconn_family: uint16_t,
    pub sconn_port: uint16_t,
    pub sconn_addr: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union sctp_sockstore {
    pub sin: sockaddr_in,
    pub sin6: sockaddr_in6,
    pub sconn: sockaddr_conn,
    pub sa: sockaddr,
}
/* **  Structures and definitions to use the socket API  ***/
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_rcvinfo {
    pub rcv_sid: uint16_t,
    pub rcv_ssn: uint16_t,
    pub rcv_flags: uint16_t,
    pub rcv_ppid: uint32_t,
    pub rcv_tsn: uint32_t,
    pub rcv_cumtsn: uint32_t,
    pub rcv_context: uint32_t,
    pub rcv_assoc_id: sctp_assoc_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_nxtinfo {
    pub nxt_sid: uint16_t,
    pub nxt_flags: uint16_t,
    pub nxt_ppid: uint32_t,
    pub nxt_length: uint32_t,
    pub nxt_assoc_id: sctp_assoc_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_recvv_rn {
    pub recvv_rcvinfo: sctp_rcvinfo,
    pub recvv_nxtinfo: sctp_nxtinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_sndinfo {
    pub snd_sid: uint16_t,
    pub snd_flags: uint16_t,
    pub snd_ppid: uint32_t,
    pub snd_context: uint32_t,
    pub snd_assoc_id: sctp_assoc_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_udpencaps {
    pub sue_address: sockaddr_storage,
    pub sue_assoc_id: uint32_t,
    pub sue_port: uint16_t,
}
/* notification event structures */
/* association change event */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_assoc_change {
    pub sac_type: uint16_t,
    pub sac_flags: uint16_t,
    pub sac_length: uint32_t,
    pub sac_state: uint16_t,
    pub sac_error: uint16_t,
    pub sac_outbound_streams: uint16_t,
    pub sac_inbound_streams: uint16_t,
    pub sac_assoc_id: sctp_assoc_t,
    pub sac_info: [uint8_t; 0],
}
/* not available yet */
/* sac_state values */
/* sac_info values */
/* Address event */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_paddr_change {
    pub spc_type: uint16_t,
    pub spc_flags: uint16_t,
    pub spc_length: uint32_t,
    pub spc_aaddr: sockaddr_storage,
    pub spc_state: uint32_t,
    pub spc_error: uint32_t,
    pub spc_assoc_id: sctp_assoc_t,
    pub spc_padding: [uint8_t; 4],
}
/* paddr state values */
/* remote error events */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_remote_error {
    pub sre_type: uint16_t,
    pub sre_flags: uint16_t,
    pub sre_length: uint32_t,
    pub sre_error: uint16_t,
    pub sre_assoc_id: sctp_assoc_t,
    pub sre_data: [uint8_t; 0],
}
/* shutdown event */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_shutdown_event {
    pub sse_type: uint16_t,
    pub sse_flags: uint16_t,
    pub sse_length: uint32_t,
    pub sse_assoc_id: sctp_assoc_t,
}
/* Adaptation layer indication */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_adaptation_event {
    pub sai_type: uint16_t,
    pub sai_flags: uint16_t,
    pub sai_length: uint32_t,
    pub sai_adaptation_ind: uint32_t,
    pub sai_assoc_id: sctp_assoc_t,
}
/* Partial delivery event */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_pdapi_event {
    pub pdapi_type: uint16_t,
    pub pdapi_flags: uint16_t,
    pub pdapi_length: uint32_t,
    pub pdapi_indication: uint32_t,
    pub pdapi_stream: uint32_t,
    pub pdapi_seq: uint32_t,
    pub pdapi_assoc_id: sctp_assoc_t,
}
/* indication values */
/* SCTP authentication event */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_authkey_event {
    pub auth_type: uint16_t,
    pub auth_flags: uint16_t,
    pub auth_length: uint32_t,
    pub auth_keynumber: uint16_t,
    pub auth_indication: uint32_t,
    pub auth_assoc_id: sctp_assoc_t,
}
/* indication values */
/* SCTP sender dry event */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_sender_dry_event {
    pub sender_dry_type: uint16_t,
    pub sender_dry_flags: uint16_t,
    pub sender_dry_length: uint32_t,
    pub sender_dry_assoc_id: sctp_assoc_t,
}
/* Stream reset event - subscribe to SCTP_STREAM_RESET_EVENT */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_stream_reset_event {
    pub strreset_type: uint16_t,
    pub strreset_flags: uint16_t,
    pub strreset_length: uint32_t,
    pub strreset_assoc_id: sctp_assoc_t,
    pub strreset_stream_list: [uint16_t; 0],
}
/* flags in stream_reset_event (strreset_flags) */
/* SCTP_STRRESET_FAILED */
/* SCTP_STRRESET_FAILED */
/* Assoc reset event - subscribe to SCTP_ASSOC_RESET_EVENT */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_assoc_reset_event {
    pub assocreset_type: uint16_t,
    pub assocreset_flags: uint16_t,
    pub assocreset_length: uint32_t,
    pub assocreset_assoc_id: sctp_assoc_t,
    pub assocreset_local_tsn: uint32_t,
    pub assocreset_remote_tsn: uint32_t,
}
/* Stream change event - subscribe to SCTP_STREAM_CHANGE_EVENT */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_stream_change_event {
    pub strchange_type: uint16_t,
    pub strchange_flags: uint16_t,
    pub strchange_length: uint32_t,
    pub strchange_assoc_id: sctp_assoc_t,
    pub strchange_instrms: uint16_t,
    pub strchange_outstrms: uint16_t,
}
/* SCTP send failed event */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_send_failed_event {
    pub ssfe_type: uint16_t,
    pub ssfe_flags: uint16_t,
    pub ssfe_length: uint32_t,
    pub ssfe_error: uint32_t,
    pub ssfe_info: sctp_sndinfo,
    pub ssfe_assoc_id: sctp_assoc_t,
    pub ssfe_data: [uint8_t; 0],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union sctp_notification {
    pub sn_header: sctp_tlv,
    pub sn_assoc_change: sctp_assoc_change,
    pub sn_paddr_change: sctp_paddr_change,
    pub sn_remote_error: sctp_remote_error,
    pub sn_shutdown_event: sctp_shutdown_event,
    pub sn_adaptation_event: sctp_adaptation_event,
    pub sn_pdapi_event: sctp_pdapi_event,
    pub sn_auth_event: sctp_authkey_event,
    pub sn_sender_dry_event: sctp_sender_dry_event,
    pub sn_send_failed_event: sctp_send_failed_event,
    pub sn_strreset_event: sctp_stream_reset_event,
    pub sn_assocreset_event: sctp_assoc_reset_event,
    pub sn_strchange_event: sctp_stream_change_event,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_tlv {
    pub sn_type: uint16_t,
    pub sn_flags: uint16_t,
    pub sn_length: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_setadaptation {
    pub ssb_adaptation_ind: uint32_t,
}
/* Used for SCTP_MAXSEG, SCTP_MAX_BURST, SCTP_ENABLE_STREAM_RESET, and SCTP_CONTEXT */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_assoc_value {
    pub assoc_id: sctp_assoc_t,
    pub assoc_value: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tsctp_meta {
    pub par_role: uint8_t,
    pub par_stats_human: uint8_t,
    pub par_ordered: uint8_t,
    pub par_messages: uint64_t,
    pub par_message_length: uint64_t,
    pub par_runtime: uint64_t,
    pub stat_messages: uint64_t,
    pub stat_message_length: uint64_t,
    pub stat_notifications: uint64_t,
    pub stat_recv_calls: uint64_t,
    pub stat_start: timeval,
    pub stat_fragment_sum: uint64_t,
    pub buffer: *mut libc::c_char,
}
static mut par_verbose: libc::c_int = 0 as libc::c_int;
static mut par_very_verbose: libc::c_int = 0 as libc::c_int;
static mut done: libc::c_uint = 0 as libc::c_int as libc::c_uint;
#[no_mangle]
pub static mut Usage: [libc::c_char; 769] =
    [85, 115, 97, 103, 101, 58, 32, 116, 115, 99, 116, 112, 32, 91, 111, 112,
     116, 105, 111, 110, 115, 93, 32, 91, 97, 100, 100, 114, 101, 115, 115,
     93, 10, 79, 112, 116, 105, 111, 110, 115, 58, 10, 32, 32, 32, 32, 32, 32,
     32, 32, 45, 97, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 115,
     101, 116, 32, 97, 100, 97, 112, 116, 97, 116, 105, 111, 110, 32, 108, 97,
     121, 101, 114, 32, 105, 110, 100, 105, 99, 97, 116, 105, 111, 110, 10,
     32, 32, 32, 32, 32, 32, 32, 32, 45, 69, 32, 32, 32, 32, 32, 32, 32, 32,
     32, 32, 32, 32, 32, 108, 111, 99, 97, 108, 32, 85, 68, 80, 32, 101, 110,
     99, 97, 112, 115, 117, 108, 97, 116, 105, 111, 110, 32, 112, 111, 114,
     116, 32, 40, 100, 101, 102, 97, 117, 108, 116, 32, 57, 56, 57, 57, 41,
     10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 102, 32, 32, 32, 32, 32, 32, 32,
     32, 32, 32, 32, 32, 32, 102, 114, 97, 103, 109, 101, 110, 116, 97, 116,
     105, 111, 110, 32, 112, 111, 105, 110, 116, 10, 32, 32, 32, 32, 32, 32,
     32, 32, 45, 72, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 104,
     117, 109, 97, 110, 32, 114, 101, 97, 100, 97, 98, 108, 101, 32, 115, 116,
     97, 116, 105, 115, 116, 105, 99, 115, 32, 32, 32, 32, 32, 32, 32, 32, 45,
     108, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 109, 101, 115,
     115, 97, 103, 101, 32, 108, 101, 110, 103, 116, 104, 10, 32, 32, 32, 32,
     32, 32, 32, 32, 45, 76, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
     32, 98, 105, 110, 100, 32, 116, 111, 32, 108, 111, 99, 97, 108, 32, 73,
     80, 32, 40, 100, 101, 102, 97, 117, 108, 116, 32, 73, 78, 65, 68, 68, 82,
     95, 65, 78, 89, 41, 10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 110, 32, 32,
     32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 110, 117, 109, 98, 101, 114,
     32, 111, 102, 32, 109, 101, 115, 115, 97, 103, 101, 115, 32, 115, 101,
     110, 116, 32, 40, 48, 32, 109, 101, 97, 110, 115, 32, 105, 110, 102, 105,
     110, 105, 116, 101, 41, 47, 114, 101, 99, 101, 105, 118, 101, 100, 10,
     32, 32, 32, 32, 32, 32, 32, 32, 45, 68, 32, 32, 32, 32, 32, 32, 32, 32,
     32, 32, 32, 32, 32, 116, 117, 114, 110, 115, 32, 78, 97, 103, 108, 101,
     32, 111, 102, 102, 10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 82, 32, 32,
     32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 115, 111, 99, 107, 101, 116,
     32, 114, 101, 99, 118, 32, 98, 117, 102, 102, 101, 114, 10, 32, 32, 32,
     32, 32, 32, 32, 32, 45, 83, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
     32, 32, 115, 111, 99, 107, 101, 116, 32, 115, 101, 110, 100, 32, 98, 117,
     102, 102, 101, 114, 10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 84, 32, 32,
     32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 116, 105, 109, 101, 32, 116,
     111, 32, 115, 101, 110, 100, 32, 109, 101, 115, 115, 97, 103, 101, 115,
     10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 117, 32, 32, 32, 32, 32, 32, 32,
     32, 32, 32, 32, 32, 32, 117, 115, 101, 32, 117, 110, 111, 114, 100, 101,
     114, 101, 100, 32, 117, 115, 101, 114, 32, 109, 101, 115, 115, 97, 103,
     101, 115, 10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 85, 32, 32, 32, 32, 32,
     32, 32, 32, 32, 32, 32, 32, 32, 114, 101, 109, 111, 116, 101, 32, 85, 68,
     80, 32, 101, 110, 99, 97, 112, 115, 117, 108, 97, 116, 105, 111, 110, 32,
     112, 111, 114, 116, 10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 118, 32, 32,
     32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 118, 101, 114, 98, 111, 115,
     101, 10, 32, 32, 32, 32, 32, 32, 32, 32, 45, 86, 32, 32, 32, 32, 32, 32,
     32, 32, 32, 32, 32, 32, 32, 118, 101, 114, 121, 32, 118, 101, 114, 98,
     111, 115, 101, 10, 0];
unsafe extern "C" fn bytes2human(mut bytes: uint64_t) -> *const libc::c_char {
    let mut suffix: [*mut libc::c_char; 5] =
        [b"\x00" as *const u8 as *const libc::c_char as *mut libc::c_char,
         b"K\x00" as *const u8 as *const libc::c_char as *mut libc::c_char,
         b"M\x00" as *const u8 as *const libc::c_char as *mut libc::c_char,
         b"G\x00" as *const u8 as *const libc::c_char as *mut libc::c_char,
         b"T\x00" as *const u8 as *const libc::c_char as *mut libc::c_char];
    let mut suffix_length: libc::c_char =
        (::std::mem::size_of::<[*mut libc::c_char; 5]>() as
             libc::c_ulong).wrapping_div(::std::mem::size_of::<*mut libc::c_char>()
                                             as libc::c_ulong) as
            libc::c_char;
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut human_size: libc::c_double = bytes as libc::c_double;
    static mut output: [libc::c_char; 200] = [0; 200];
    if bytes > 1024 as libc::c_int as libc::c_ulong {
        i = 0 as libc::c_int;
        while bytes.wrapping_div(1024 as libc::c_int as libc::c_ulong) >
                  0 as libc::c_int as libc::c_ulong &&
                  i < suffix_length as libc::c_int - 1 as libc::c_int {
            human_size = bytes as libc::c_double / 1024.0f64;
            bytes =
                (bytes as
                     libc::c_ulong).wrapping_div(1024 as libc::c_int as
                                                     libc::c_ulong) as
                    uint64_t as uint64_t;
            i += 1
        }
    }
    snprintf(output.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 200]>() as libc::c_ulong,
             b"%.02lf %s\x00" as *const u8 as *const libc::c_char, human_size,
             suffix[i as usize]);
    return output.as_mut_ptr();
}
unsafe extern "C" fn handle_accept(mut upcall_socket: *mut socket,
                                   mut upcall_data: *mut libc::c_void,
                                   mut upcall_flags: libc::c_int) {
    let mut conn_sock: *mut socket = 0 as *mut socket;
    let mut remote_addr: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut addr_len: socklen_t =
        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t;
    let mut meta_listening: *mut tsctp_meta = 0 as *mut tsctp_meta;
    let mut meta_accepted: *mut tsctp_meta = 0 as *mut tsctp_meta;
    let mut addrbuf: [libc::c_char; 16] = [0; 16];
    meta_listening = upcall_data as *mut tsctp_meta;
    memset(&mut remote_addr as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    conn_sock =
        usrsctp_accept(upcall_socket,
                       &mut remote_addr as *mut sockaddr_in as *mut sockaddr,
                       &mut addr_len);
    if conn_sock.is_null() && *__errno_location() != 115 as libc::c_int {
        perror(b"usrsctp_accept\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    if par_verbose != 0 {
        printf(b"Connection accepted from %s:%d\n\x00" as *const u8 as
                   *const libc::c_char,
               inet_ntop(2 as libc::c_int,
                         &mut remote_addr.sin_addr as *mut in_addr as
                             *const libc::c_void, addrbuf.as_mut_ptr(),
                         16 as libc::c_int as socklen_t),
               ntohs(remote_addr.sin_port) as libc::c_int);
    }
    meta_accepted =
        malloc(::std::mem::size_of::<tsctp_meta>() as libc::c_ulong) as
            *mut tsctp_meta;
    if meta_accepted.is_null() {
        printf(b"malloc() failed!\n\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    memset(meta_accepted as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<tsctp_meta>() as libc::c_ulong);
    (*meta_accepted).par_role = (*meta_listening).par_role;
    (*meta_accepted).par_stats_human = (*meta_listening).par_stats_human;
    (*meta_accepted).buffer =
        malloc(((1 as libc::c_int) << 16 as libc::c_int) as libc::c_ulong) as
            *mut libc::c_char;
    if (*meta_accepted).buffer.is_null() {
        printf(b"malloc() failed!\n\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    usrsctp_set_upcall(conn_sock,
                       Some(handle_upcall as
                                unsafe extern "C" fn(_: *mut socket,
                                                     _: *mut libc::c_void,
                                                     _: libc::c_int) -> ()),
                       meta_accepted as *mut libc::c_void);
}
unsafe extern "C" fn handle_upcall(mut upcall_socket: *mut socket,
                                   mut upcall_data: *mut libc::c_void,
                                   mut upcall_flags: libc::c_int) {
    let mut events: libc::c_int = usrsctp_get_events(upcall_socket);
    let mut tsctp_meta: *mut tsctp_meta = upcall_data as *mut tsctp_meta;
    let mut rn: sctp_recvv_rn =
        sctp_recvv_rn{recvv_rcvinfo:
                          sctp_rcvinfo{rcv_sid: 0,
                                       rcv_ssn: 0,
                                       rcv_flags: 0,
                                       rcv_ppid: 0,
                                       rcv_tsn: 0,
                                       rcv_cumtsn: 0,
                                       rcv_context: 0,
                                       rcv_assoc_id: 0,},
                      recvv_nxtinfo:
                          sctp_nxtinfo{nxt_sid: 0,
                                       nxt_flags: 0,
                                       nxt_ppid: 0,
                                       nxt_length: 0,
                                       nxt_assoc_id: 0,},};
    let mut n: ssize_t = 0;
    let mut addr: sockaddr_storage =
        sockaddr_storage{ss_family: 0,
                         __ss_padding: [0; 118],
                         __ss_align: 0,};
    let mut recv_flags: libc::c_int = 0 as libc::c_int;
    let mut len: socklen_t =
        ::std::mem::size_of::<sockaddr_storage>() as libc::c_ulong as
            socklen_t;
    let mut infotype: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut infolen: socklen_t =
        ::std::mem::size_of::<sctp_recvv_rn>() as libc::c_ulong as socklen_t;
    let mut rcvinfo: *mut sctp_rcvinfo =
        &mut rn as *mut sctp_recvv_rn as *mut sctp_rcvinfo;
    memset(&mut rn as *mut sctp_recvv_rn as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_recvv_rn>() as libc::c_ulong);
    let mut note_time: timeval = timeval{tv_sec: 0, tv_usec: 0,};
    let mut snp: *mut sctp_notification = 0 as *mut sctp_notification;
    let mut spc: *mut sctp_paddr_change = 0 as *mut sctp_paddr_change;
    let mut time_now: timeval = timeval{tv_sec: 0, tv_usec: 0,};
    let mut time_diff: timeval = timeval{tv_sec: 0, tv_usec: 0,};
    let mut seconds: libc::c_float = 0.;
    let mut snd_info: sctp_sndinfo =
        sctp_sndinfo{snd_sid: 0,
                     snd_flags: 0,
                     snd_ppid: 0,
                     snd_context: 0,
                     snd_assoc_id: 0,};
    if events & 0x1 as libc::c_int != 0 {
        loop  {
            n =
                usrsctp_recvv(upcall_socket,
                              (*tsctp_meta).buffer as *mut libc::c_void,
                              ((1 as libc::c_int) << 16 as libc::c_int) as
                                  size_t,
                              &mut addr as *mut sockaddr_storage as
                                  *mut sockaddr, &mut len,
                              &mut rn as *mut sctp_recvv_rn as
                                  *mut libc::c_void, &mut infolen,
                              &mut infotype, &mut recv_flags);
            if !(n > 0 as libc::c_int as libc::c_long) { break ; }
            if (*tsctp_meta).stat_recv_calls == 0 {
                gettimeofday(&mut (*tsctp_meta).stat_start,
                             0 as *mut timezone);
            }
            (*tsctp_meta).stat_recv_calls =
                (*tsctp_meta).stat_recv_calls.wrapping_add(1);
            if recv_flags & 0x2000 as libc::c_int != 0 {
                (*tsctp_meta).stat_notifications =
                    (*tsctp_meta).stat_notifications.wrapping_add(1);
                gettimeofday(&mut note_time, 0 as *mut timezone);
                if par_verbose != 0 {
                    printf(b"notification arrived at %f\n\x00" as *const u8 as
                               *const libc::c_char,
                           note_time.tv_sec as libc::c_double +
                               note_time.tv_usec as libc::c_double /
                                   1000000.0f64);
                    snp = (*tsctp_meta).buffer as *mut sctp_notification;
                    if (*snp).sn_header.sn_type as libc::c_int ==
                           0x2 as libc::c_int {
                        spc = &mut (*snp).sn_paddr_change;
                        printf(b"SCTP_PEER_ADDR_CHANGE: state=%d, error=%d\n\x00"
                                   as *const u8 as *const libc::c_char,
                               (*spc).spc_state, (*spc).spc_error);
                    }
                }
            } else {
                if par_very_verbose != 0 {
                    if infotype == 1 as libc::c_int as libc::c_uint {
                        printf(b"Message received - %zd bytes - %s - sid %u - tsn %u %s\n\x00"
                                   as *const u8 as *const libc::c_char, n,
                               if (*rcvinfo).rcv_flags as libc::c_int &
                                      0x400 as libc::c_int != 0 {
                                   b"unordered\x00" as *const u8 as
                                       *const libc::c_char
                               } else {
                                   b"ordered\x00" as *const u8 as
                                       *const libc::c_char
                               }, (*rcvinfo).rcv_sid as libc::c_int,
                               (*rcvinfo).rcv_tsn,
                               if recv_flags & MSG_EOR as libc::c_int != 0 {
                                   b"- EOR\x00" as *const u8 as
                                       *const libc::c_char
                               } else {
                                   b"\x00" as *const u8 as *const libc::c_char
                               });
                    } else {
                        printf(b"Message received - %zd bytes %s\n\x00" as
                                   *const u8 as *const libc::c_char, n,
                               if recv_flags & MSG_EOR as libc::c_int != 0 {
                                   b"- EOR\x00" as *const u8 as
                                       *const libc::c_char
                               } else {
                                   b"\x00" as *const u8 as *const libc::c_char
                               });
                    }
                }
                (*tsctp_meta).stat_fragment_sum =
                    ((*tsctp_meta).stat_fragment_sum as
                         libc::c_ulong).wrapping_add(n as libc::c_ulong) as
                        uint64_t as uint64_t;
                if recv_flags & MSG_EOR as libc::c_int != 0 {
                    (*tsctp_meta).stat_messages =
                        (*tsctp_meta).stat_messages.wrapping_add(1);
                    if (*tsctp_meta).stat_message_length ==
                           0 as libc::c_int as libc::c_ulong {
                        (*tsctp_meta).stat_message_length =
                            (*tsctp_meta).stat_fragment_sum
                    }
                }
            }
        }
        if n < 0 as libc::c_int as libc::c_long &&
               *__errno_location() != 11 as libc::c_int &&
               *__errno_location() != 11 as libc::c_int {
            perror(b"usrsctp_recvv\x00" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        if n == 0 as libc::c_int as libc::c_long {
            done = 1 as libc::c_int as libc::c_uint;
            gettimeofday(&mut time_now, 0 as *mut timezone);
            time_diff.tv_sec =
                time_now.tv_sec - (*tsctp_meta).stat_start.tv_sec;
            time_diff.tv_usec =
                time_now.tv_usec - (*tsctp_meta).stat_start.tv_usec;
            if time_diff.tv_usec < 0 as libc::c_int as libc::c_long {
                time_diff.tv_sec -= 1;
                time_diff.tv_usec += 1000000 as libc::c_int as libc::c_long
            }
            seconds =
                (time_diff.tv_sec as libc::c_double +
                     time_diff.tv_usec as libc::c_double / 1000000.0f64) as
                    libc::c_float;
            if (*tsctp_meta).par_stats_human != 0 {
                printf(b"Connection closed - statistics\n\x00" as *const u8 as
                           *const libc::c_char);
                printf(b"\tmessage size  : %lu\n\x00" as *const u8 as
                           *const libc::c_char,
                       (*tsctp_meta).stat_message_length);
                printf(b"\tmessages      : %lu\n\x00" as *const u8 as
                           *const libc::c_char, (*tsctp_meta).stat_messages);
                printf(b"\trecv() calls  : %lu\n\x00" as *const u8 as
                           *const libc::c_char,
                       (*tsctp_meta).stat_recv_calls);
                printf(b"\tnotifications : %lu\n\x00" as *const u8 as
                           *const libc::c_char,
                       (*tsctp_meta).stat_notifications);
                printf(b"\ttransferred   : %sByte\n\x00" as *const u8 as
                           *const libc::c_char,
                       bytes2human((*tsctp_meta).stat_message_length.wrapping_mul((*tsctp_meta).stat_messages)));
                printf(b"\truntime       : %.2f s\n\x00" as *const u8 as
                           *const libc::c_char, seconds as libc::c_double);
                printf(b"\tgoodput       : %sBit/s\n\x00" as *const u8 as
                           *const libc::c_char,
                       bytes2human(((*tsctp_meta).stat_message_length as
                                        libc::c_double *
                                        (*tsctp_meta).stat_messages as
                                            libc::c_double /
                                        seconds as libc::c_double *
                                        8 as libc::c_int as libc::c_double) as
                                       uint64_t));
            } else {
                printf(b"%lu, %lu, %lu, %lu, %f, %f, %lu\n\x00" as *const u8
                           as *const libc::c_char,
                       (*tsctp_meta).stat_message_length,
                       (*tsctp_meta).stat_messages,
                       (*tsctp_meta).stat_recv_calls,
                       (*tsctp_meta).stat_message_length.wrapping_mul((*tsctp_meta).stat_messages),
                       seconds as libc::c_double,
                       (*tsctp_meta).stat_message_length as libc::c_double *
                           (*tsctp_meta).stat_messages as libc::c_double /
                           seconds as libc::c_double,
                       (*tsctp_meta).stat_notifications);
            }
            fflush(stdout);
            usrsctp_close(upcall_socket);
            free((*tsctp_meta).buffer as *mut libc::c_void);
            free(tsctp_meta as *mut libc::c_void);
            return
        }
    }
    if events & 0x2 as libc::c_int != 0 &&
           (*tsctp_meta).par_role as libc::c_int == 1 as libc::c_int &&
           done == 0 {
        memset(&mut snd_info as *mut sctp_sndinfo as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong);
        if (*tsctp_meta).par_ordered as libc::c_int == 0 as libc::c_int {
            snd_info.snd_flags =
                (snd_info.snd_flags as libc::c_int | 0x400 as libc::c_int) as
                    uint16_t
        }
        loop  {
            n =
                usrsctp_sendv(upcall_socket,
                              (*tsctp_meta).buffer as *const libc::c_void,
                              (*tsctp_meta).par_message_length,
                              0 as *mut sockaddr, 0 as libc::c_int,
                              &mut snd_info as *mut sctp_sndinfo as
                                  *mut libc::c_void,
                              ::std::mem::size_of::<sctp_sndinfo>() as
                                  libc::c_ulong as socklen_t,
                              1 as libc::c_int as libc::c_uint,
                              0 as libc::c_int);
            if !(n > 0 as libc::c_int as libc::c_long) { break ; }
            if (*tsctp_meta).stat_messages ==
                   0 as libc::c_int as libc::c_ulong {
                gettimeofday(&mut (*tsctp_meta).stat_start,
                             0 as *mut timezone);
            }
            (*tsctp_meta).stat_messages =
                (*tsctp_meta).stat_messages.wrapping_add(1);
            if par_very_verbose != 0 {
                printf(b"Message #%lu sent\n\x00" as *const u8 as
                           *const libc::c_char, (*tsctp_meta).stat_messages);
            }
            if (*tsctp_meta).par_messages != 0 &&
                   (*tsctp_meta).par_messages == (*tsctp_meta).stat_messages {
                break ;
            }
        }
        if *__errno_location() != 11 as libc::c_int &&
               *__errno_location() != 11 as libc::c_int {
            done = 1 as libc::c_int as libc::c_uint;
            usrsctp_close(upcall_socket);
            printf(b"client socket %p closed\n\x00" as *const u8 as
                       *const libc::c_char,
                   upcall_socket as *mut libc::c_void);
            free((*tsctp_meta).buffer as *mut libc::c_void);
            free(tsctp_meta as *mut libc::c_void);
            return
        }
        gettimeofday(&mut time_now, 0 as *mut timezone);
        time_diff.tv_sec = time_now.tv_sec - (*tsctp_meta).stat_start.tv_sec;
        time_diff.tv_usec =
            time_now.tv_usec - (*tsctp_meta).stat_start.tv_usec;
        if time_diff.tv_usec < 0 as libc::c_int as libc::c_long {
            time_diff.tv_sec -= 1;
            time_diff.tv_usec += 1000000 as libc::c_int as libc::c_long
        }
        seconds =
            (time_diff.tv_sec as libc::c_double +
                 time_diff.tv_usec as libc::c_double / 1000000.0f64) as
                libc::c_float;
        if (*tsctp_meta).par_messages != 0 &&
               (*tsctp_meta).par_messages == (*tsctp_meta).stat_messages ||
               (*tsctp_meta).par_runtime != 0 &&
                   (*tsctp_meta).par_runtime as libc::c_float <= seconds {
            if par_verbose != 0 {
                printf(b"Runtime or max messages reached - finishing...\n\x00"
                           as *const u8 as *const libc::c_char);
            }
            done = 1 as libc::c_int as libc::c_uint;
            usrsctp_close(upcall_socket);
            free((*tsctp_meta).buffer as *mut libc::c_void);
            free(tsctp_meta as *mut libc::c_void);
            return
        }
    };
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut c: libc::c_int = 0;
    let mut psock: *mut socket = 0 as *mut socket;
    let mut local_addr: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut remote_addr: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut optval: libc::c_int = 0;
    let mut local_port: uint16_t = 0;
    let mut remote_port: uint16_t = 0;
    let mut local_udp_port: uint16_t = 0;
    let mut remote_udp_port: uint16_t = 0;
    let mut rcvbufsize: libc::c_int = 0 as libc::c_int;
    let mut sndbufsize: libc::c_int = 0 as libc::c_int;
    let mut intlen: socklen_t = 0;
    let mut nodelay: libc::c_int = 0 as libc::c_int;
    let mut av: sctp_assoc_value =
        sctp_assoc_value{assoc_id: 0, assoc_value: 0,};
    let mut encaps: sctp_udpencaps =
        sctp_udpencaps{sue_address:
                           sockaddr_storage{ss_family: 0,
                                            __ss_padding: [0; 118],
                                            __ss_align: 0,},
                       sue_assoc_id: 0,
                       sue_port: 0,};
    let mut meta: *mut tsctp_meta = 0 as *mut tsctp_meta;
    let mut par_port: uint16_t = 5001 as libc::c_int as uint16_t;
    let mut par_stats_human: uint8_t = 0 as libc::c_int as uint8_t;
    let mut par_ordered: libc::c_int = 1 as libc::c_int;
    let mut par_message_length: libc::c_int = 1024 as libc::c_int;
    let mut par_messages: libc::c_int = 1024 as libc::c_int;
    let mut par_runtime: libc::c_int = 0 as libc::c_int;
    let mut src_addr: in_addr_t = 0;
    let mut fragpoint: libc::c_int = 0 as libc::c_int;
    let mut ind: sctp_setadaptation =
        {
            let mut init =
                sctp_setadaptation{ssb_adaptation_ind:
                                       0 as libc::c_int as uint32_t,};
            init
        };
    remote_udp_port = 0 as libc::c_int as uint16_t;
    local_udp_port = 9899 as libc::c_int as uint16_t;
    src_addr = htonl(0 as libc::c_int as in_addr_t);
    memset(&mut remote_addr as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    memset(&mut local_addr as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    loop  {
        c =
            getopt(argc, argv,
                   b"a:DE:f:Hl:L:n:p:R:S:T:uU:vV\x00" as *const u8 as
                       *const libc::c_char);
        if !(c != -(1 as libc::c_int)) { break ; }
        match c {
            97 => { ind.ssb_adaptation_ind = atoi(optarg) as uint32_t }
            68 => { nodelay = 1 as libc::c_int }
            69 => { local_udp_port = atoi(optarg) as uint16_t }
            102 => { fragpoint = atoi(optarg) }
            72 => { par_stats_human = 1 as libc::c_int as uint8_t }
            108 => { par_message_length = atoi(optarg) }
            76 => {
                if inet_pton(2 as libc::c_int, optarg,
                             &mut src_addr as *mut in_addr_t as
                                 *mut libc::c_void) != 1 as libc::c_int {
                    printf(b"Can\'t parse %s\n\x00" as *const u8 as
                               *const libc::c_char, optarg);
                    exit(1 as libc::c_int);
                }
            }
            110 => { par_messages = atoi(optarg) }
            112 => { par_port = atoi(optarg) as uint16_t }
            82 => { rcvbufsize = atoi(optarg) }
            83 => { sndbufsize = atoi(optarg) }
            84 => {
                par_runtime = atoi(optarg);
                par_messages = 0 as libc::c_int
            }
            117 => { par_ordered = 0 as libc::c_int }
            85 => { remote_udp_port = atoi(optarg) as uint16_t }
            118 => { par_verbose = 1 as libc::c_int }
            86 => {
                par_verbose = 1 as libc::c_int;
                par_very_verbose = 1 as libc::c_int
            }
            _ => {
                fprintf(stderr, b"%s\x00" as *const u8 as *const libc::c_char,
                        Usage.as_mut_ptr());
                exit(1 as libc::c_int);
            }
        }
    }
    meta =
        malloc(::std::mem::size_of::<tsctp_meta>() as libc::c_ulong) as
            *mut tsctp_meta;
    if meta.is_null() {
        printf(b"malloc() failed!\n\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    memset(meta as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<tsctp_meta>() as libc::c_ulong);
    (*meta).buffer =
        malloc(((1 as libc::c_int) << 16 as libc::c_int) as libc::c_ulong) as
            *mut libc::c_char;
    if (*meta).buffer.is_null() {
        printf(b"malloc() failed!\n\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    (*meta).par_stats_human = par_stats_human;
    (*meta).par_message_length = par_message_length as uint64_t;
    (*meta).par_messages = par_messages as uint64_t;
    (*meta).par_ordered = par_ordered as uint8_t;
    (*meta).par_runtime = par_runtime as uint64_t;
    if optind == argc {
        (*meta).par_role = 2 as libc::c_int as uint8_t;
        local_port = par_port;
        remote_port = 0 as libc::c_int as uint16_t
    } else {
        (*meta).par_role = 1 as libc::c_int as uint8_t;
        local_port = 0 as libc::c_int as uint16_t;
        remote_port = par_port
    }
    local_addr.sin_family = 2 as libc::c_int as sa_family_t;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = src_addr;
    usrsctp_init(local_udp_port, None,
                 Some(debug_printf_stack as
                          unsafe extern "C" fn(_: *const libc::c_char, _: ...)
                              -> ()));
    usrsctp_sysctl_set_sctp_debug_on(0xffffffff as libc::c_uint);
    usrsctp_sysctl_set_sctp_blackhole(2 as libc::c_int as uint32_t);
    usrsctp_sysctl_set_sctp_no_csum_on_loopback(0 as libc::c_int as uint32_t);
    usrsctp_sysctl_set_sctp_enable_sack_immediately(1 as libc::c_int as
                                                        uint32_t);
    psock =
        usrsctp_socket(2 as libc::c_int, SOCK_STREAM as libc::c_int,
                       IPPROTO_SCTP as libc::c_int, None, None,
                       0 as libc::c_int as uint32_t, 0 as *mut libc::c_void);
    if psock.is_null() {
        perror(b"user_socket\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    optval = 1 as libc::c_int;
    if usrsctp_setsockopt(psock, IPPROTO_SCTP as libc::c_int,
                          0x1f as libc::c_int,
                          &mut optval as *mut libc::c_int as
                              *const libc::c_void,
                          ::std::mem::size_of::<libc::c_int>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_setsockopt SCTP_RECVRCVINFO\x00" as *const u8 as
                   *const libc::c_char);
    }
    usrsctp_set_non_blocking(psock, 1 as libc::c_int);
    if usrsctp_bind(psock,
                    &mut local_addr as *mut sockaddr_in as *mut sockaddr,
                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                        socklen_t) == -(1 as libc::c_int) {
        perror(b"usrsctp_bind\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    if usrsctp_setsockopt(psock, IPPROTO_SCTP as libc::c_int,
                          0x8 as libc::c_int,
                          &mut ind as *mut sctp_setadaptation as
                              *const libc::c_void,
                          ::std::mem::size_of::<sctp_setadaptation>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"setsockopt\x00" as *const u8 as *const libc::c_char);
    }
    if (*meta).par_role as libc::c_int == 2 as libc::c_int {
        if rcvbufsize != 0 {
            if usrsctp_setsockopt(psock, 1 as libc::c_int, 8 as libc::c_int,
                                  &mut rcvbufsize as *mut libc::c_int as
                                      *const libc::c_void,
                                  ::std::mem::size_of::<libc::c_int>() as
                                      libc::c_ulong as socklen_t) <
                   0 as libc::c_int {
                perror(b"setsockopt: rcvbuf\x00" as *const u8 as
                           *const libc::c_char);
            }
        }
        if par_verbose != 0 {
            intlen =
                ::std::mem::size_of::<libc::c_int>() as libc::c_ulong as
                    socklen_t;
            if usrsctp_getsockopt(psock, 1 as libc::c_int, 8 as libc::c_int,
                                  &mut rcvbufsize as *mut libc::c_int as
                                      *mut libc::c_void,
                                  &mut intlen as *mut socklen_t) <
                   0 as libc::c_int {
                perror(b"getsockopt: rcvbuf\x00" as *const u8 as
                           *const libc::c_char);
            } else {
                fprintf(stdout,
                        b"Receive buffer size: %d.\n\x00" as *const u8 as
                            *const libc::c_char, rcvbufsize);
            }
        }
        if usrsctp_listen(psock, 1 as libc::c_int) < 0 as libc::c_int {
            perror(b"usrsctp_listen\x00" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        usrsctp_set_upcall(psock,
                           Some(handle_accept as
                                    unsafe extern "C" fn(_: *mut socket,
                                                         _: *mut libc::c_void,
                                                         _: libc::c_int)
                                        -> ()), meta as *mut libc::c_void);
        loop  { sleep(1 as libc::c_int as libc::c_uint); }
    } else {
        memset(&mut encaps as *mut sctp_udpencaps as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong);
        encaps.sue_address.ss_family = 2 as libc::c_int as sa_family_t;
        encaps.sue_port = htons(remote_udp_port);
        if usrsctp_setsockopt(psock, IPPROTO_SCTP as libc::c_int,
                              0x24 as libc::c_int,
                              &mut encaps as *mut sctp_udpencaps as
                                  *const libc::c_void,
                              ::std::mem::size_of::<sctp_udpencaps>() as
                                  libc::c_ulong as socklen_t) <
               0 as libc::c_int {
            perror(b"setsockopt\x00" as *const u8 as *const libc::c_char);
        }
        remote_addr.sin_family = 2 as libc::c_int as sa_family_t;
        if inet_pton(2 as libc::c_int, *argv.offset(optind as isize),
                     &mut remote_addr.sin_addr.s_addr as *mut in_addr_t as
                         *mut libc::c_void) == 0 {
            printf(b"error: invalid destination address\n\x00" as *const u8 as
                       *const libc::c_char);
            exit(1 as libc::c_int);
        }
        remote_addr.sin_port = htons(remote_port);
        memset((*meta).buffer as *mut libc::c_void, 'X' as i32,
               ((1 as libc::c_int) << 16 as libc::c_int) as libc::c_ulong);
        usrsctp_set_upcall(psock,
                           Some(handle_upcall as
                                    unsafe extern "C" fn(_: *mut socket,
                                                         _: *mut libc::c_void,
                                                         _: libc::c_int)
                                        -> ()), meta as *mut libc::c_void);
        usrsctp_setsockopt(psock, IPPROTO_SCTP as libc::c_int,
                           0x4 as libc::c_int,
                           &mut nodelay as *mut libc::c_int as
                               *const libc::c_void,
                           ::std::mem::size_of::<libc::c_int>() as
                               libc::c_ulong as socklen_t);
        if fragpoint != 0 {
            av.assoc_id = 0 as libc::c_int as sctp_assoc_t;
            av.assoc_value = fragpoint as uint32_t;
            if usrsctp_setsockopt(psock, IPPROTO_SCTP as libc::c_int,
                                  0xe as libc::c_int,
                                  &mut av as *mut sctp_assoc_value as
                                      *const libc::c_void,
                                  ::std::mem::size_of::<sctp_assoc_value>() as
                                      libc::c_ulong as socklen_t) <
                   0 as libc::c_int {
                perror(b"setsockopt: SCTP_MAXSEG\x00" as *const u8 as
                           *const libc::c_char);
            }
        }
        if sndbufsize != 0 {
            if usrsctp_setsockopt(psock, 1 as libc::c_int, 7 as libc::c_int,
                                  &mut sndbufsize as *mut libc::c_int as
                                      *const libc::c_void,
                                  ::std::mem::size_of::<libc::c_int>() as
                                      libc::c_ulong as socklen_t) <
                   0 as libc::c_int {
                perror(b"setsockopt: sndbuf\x00" as *const u8 as
                           *const libc::c_char);
            }
        }
        if par_verbose != 0 {
            intlen =
                ::std::mem::size_of::<libc::c_int>() as libc::c_ulong as
                    socklen_t;
            if usrsctp_getsockopt(psock, 1 as libc::c_int, 7 as libc::c_int,
                                  &mut sndbufsize as *mut libc::c_int as
                                      *mut libc::c_void,
                                  &mut intlen as *mut socklen_t) <
                   0 as libc::c_int {
                perror(b"setsockopt: SO_SNDBUF\x00" as *const u8 as
                           *const libc::c_char);
            } else {
                fprintf(stdout,
                        b"Send buffer size: %d.\n\x00" as *const u8 as
                            *const libc::c_char, sndbufsize);
            }
        }
        if usrsctp_connect(psock,
                           &mut remote_addr as *mut sockaddr_in as
                               *mut sockaddr,
                           ::std::mem::size_of::<sockaddr_in>() as
                               libc::c_ulong as socklen_t) ==
               -(1 as libc::c_int) {
            if *__errno_location() != 115 as libc::c_int {
                perror(b"usrsctp_connect\x00" as *const u8 as
                           *const libc::c_char);
                exit(1 as libc::c_int);
            }
        }
        while done == 0 { sleep(1 as libc::c_int as libc::c_uint); }
        if par_verbose != 0 {
            printf(b"Finished... \n\x00" as *const u8 as *const libc::c_char);
        }
    }
    while usrsctp_finish() != 0 as libc::c_int {
        sleep(1 as libc::c_int as libc::c_uint);
    }
    return 0 as libc::c_int;
}
#[main]
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(::std::ffi::CString::new(arg).expect("Failed to convert argument into CString.").into_raw());
    };
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0((args.len() - 1) as libc::c_int,
                                    args.as_mut_ptr() as
                                        *mut *mut libc::c_char) as i32)
    }
}
