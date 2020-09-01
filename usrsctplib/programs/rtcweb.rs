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
    fn ntohl(__netlong: uint32_t) -> uint32_t;
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
    fn pthread_mutex_init(__mutex: *mut pthread_mutex_t,
                          __mutexattr: *const pthread_mutexattr_t)
     -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    static mut stdin: *mut FILE;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn fgets(__s: *mut libc::c_char, __n: libc::c_int, __stream: *mut FILE)
     -> *mut libc::c_char;
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
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char,
               _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn strstr(_: *const libc::c_char, _: *const libc::c_char)
     -> *mut libc::c_char;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
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
                      receive_cb_0:
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
    fn usrsctp_shutdown(so: *mut socket, how: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_no_csum_on_loopback(value: uint32_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_blackhole(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_debug_on(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn debug_printf_stack(format: *const libc::c_char, _: ...);
}
pub type __uint8_t = libc::c_uchar;
pub type __int16_t = libc::c_short;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
pub type __pthread_list_t = __pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: libc::c_int,
    pub __count: libc::c_uint,
    pub __owner: libc::c_int,
    pub __nusers: libc::c_uint,
    pub __kind: libc::c_int,
    pub __spins: libc::c_short,
    pub __elision: libc::c_short,
    pub __list: __pthread_list_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [libc::c_char; 4],
    pub __align: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [libc::c_char; 40],
    pub __align: libc::c_long,
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
pub const SHUT_RDWR: C2RustUnnamed = 2;
pub const SHUT_WR: C2RustUnnamed = 1;
pub const SHUT_RD: C2RustUnnamed = 0;
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
pub struct sctp_sndinfo {
    pub snd_sid: uint16_t,
    pub snd_flags: uint16_t,
    pub snd_ppid: uint32_t,
    pub snd_context: uint32_t,
    pub snd_assoc_id: sctp_assoc_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_prinfo {
    pub pr_policy: uint16_t,
    pub pr_value: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_authinfo {
    pub auth_keynumber: uint16_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_sendv_spa {
    pub sendv_flags: uint32_t,
    pub sendv_sndinfo: sctp_sndinfo,
    pub sendv_prinfo: sctp_prinfo,
    pub sendv_authinfo: sctp_authinfo,
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
/* on wire at failure */
/* SCTP event option */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_event {
    pub se_assoc_id: sctp_assoc_t,
    pub se_type: uint16_t,
    pub se_on: uint8_t,
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
/* struct sctp_add_streams */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_initmsg {
    pub sinit_num_ostreams: uint16_t,
    pub sinit_max_instreams: uint16_t,
    pub sinit_max_attempts: uint16_t,
    pub sinit_max_init_timeo: uint16_t,
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
pub struct sctp_reset_streams {
    pub srs_assoc_id: sctp_assoc_t,
    pub srs_flags: uint16_t,
    pub srs_number_streams: uint16_t,
    pub srs_stream_list: [uint16_t; 0],
}
/* list if strrst_num_streams is not 0 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_add_streams {
    pub sas_assoc_id: sctp_assoc_t,
    pub sas_instrms: uint16_t,
    pub sas_outstrms: uint16_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_paddrinfo {
    pub spinfo_address: sockaddr_storage,
    pub spinfo_assoc_id: sctp_assoc_t,
    pub spinfo_state: int32_t,
    pub spinfo_cwnd: uint32_t,
    pub spinfo_srtt: uint32_t,
    pub spinfo_rto: uint32_t,
    pub spinfo_mtu: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_status {
    pub sstat_assoc_id: sctp_assoc_t,
    pub sstat_state: int32_t,
    pub sstat_rwnd: uint32_t,
    pub sstat_unackdata: uint16_t,
    pub sstat_penddata: uint16_t,
    pub sstat_instrms: uint16_t,
    pub sstat_outstrms: uint16_t,
    pub sstat_fragmentation_point: uint32_t,
    pub sstat_primary: sctp_paddrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel {
    pub id: uint32_t,
    pub pr_value: uint32_t,
    pub pr_policy: uint16_t,
    pub i_stream: uint16_t,
    pub o_stream: uint16_t,
    pub unordered: uint8_t,
    pub state: uint8_t,
    pub flags: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct peer_connection {
    pub channels: [channel; 100],
    pub i_stream_channel: [*mut channel; 100],
    pub o_stream_channel: [*mut channel; 100],
    pub o_stream_buffer: [uint16_t; 100],
    pub o_stream_buffer_counter: uint32_t,
    pub mutex: pthread_mutex_t,
    pub sock: *mut socket,
}
/* defined(_WIN32) && !defined(__MINGW32__) */
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct rtcweb_datachannel_open_request {
    pub msg_type: uint8_t,
    pub channel_type: uint8_t,
    pub flags: uint16_t,
    pub reliability_params: uint16_t,
    pub priority: int16_t,
    pub label: [libc::c_char; 0],
}
/* defined(_WIN32) && !defined(__MINGW32__) */
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct rtcweb_datachannel_open_response {
    pub msg_type: uint8_t,
    pub error: uint8_t,
    pub flags: uint16_t,
    pub reverse_stream: uint16_t,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct rtcweb_datachannel_ack {
    pub msg_type: uint8_t,
}
#[no_mangle]
pub static mut peer_connection: peer_connection =
    peer_connection{channels:
                        [channel{id: 0,
                                 pr_value: 0,
                                 pr_policy: 0,
                                 i_stream: 0,
                                 o_stream: 0,
                                 unordered: 0,
                                 state: 0,
                                 flags: 0,}; 100],
                    i_stream_channel:
                        [0 as *const channel as *mut channel; 100],
                    o_stream_channel:
                        [0 as *const channel as *mut channel; 100],
                    o_stream_buffer: [0; 100],
                    o_stream_buffer_counter: 0,
                    mutex:
                        pthread_mutex_t{__data:
                                            __pthread_mutex_s{__lock: 0,
                                                              __count: 0,
                                                              __owner: 0,
                                                              __nusers: 0,
                                                              __kind: 0,
                                                              __spins: 0,
                                                              __elision: 0,
                                                              __list:
                                                                  __pthread_list_t{__prev:
                                                                                       0
                                                                                           as
                                                                                           *const __pthread_internal_list
                                                                                           as
                                                                                           *mut __pthread_internal_list,
                                                                                   __next:
                                                                                       0
                                                                                           as
                                                                                           *const __pthread_internal_list
                                                                                           as
                                                                                           *mut __pthread_internal_list,},},},
                    sock: 0 as *const socket as *mut socket,};
unsafe extern "C" fn init_peer_connection(mut pc: *mut peer_connection) {
    let mut i: uint32_t = 0;
    let mut channel: *mut channel = 0 as *mut channel;
    pthread_mutex_init(&mut (*pc).mutex, 0 as *const pthread_mutexattr_t);
    lock_peer_connection(pc);
    i = 0 as libc::c_int as uint32_t;
    while i < 100 as libc::c_int as libc::c_uint {
        channel =
            &mut *(*pc).channels.as_mut_ptr().offset(i as isize) as
                *mut channel;
        (*channel).id = i;
        (*channel).state = 0 as libc::c_int as uint8_t;
        (*channel).pr_policy = 0 as libc::c_int as uint16_t;
        (*channel).pr_value = 0 as libc::c_int as uint32_t;
        (*channel).i_stream = 0 as libc::c_int as uint16_t;
        (*channel).o_stream = 0 as libc::c_int as uint16_t;
        (*channel).unordered = 0 as libc::c_int as uint8_t;
        (*channel).flags = 0 as libc::c_int as uint32_t;
        i = i.wrapping_add(1)
    }
    i = 0 as libc::c_int as uint32_t;
    while i < 100 as libc::c_int as libc::c_uint {
        (*pc).i_stream_channel[i as usize] = 0 as *mut channel;
        (*pc).o_stream_channel[i as usize] = 0 as *mut channel;
        (*pc).o_stream_buffer[i as usize] = 0 as libc::c_int as uint16_t;
        i = i.wrapping_add(1)
    }
    (*pc).o_stream_buffer_counter = 0 as libc::c_int as uint32_t;
    (*pc).sock = 0 as *mut socket;
    unlock_peer_connection(pc);
}
/* DATA_CHANNEL_ACK */
unsafe extern "C" fn lock_peer_connection(mut pc: *mut peer_connection) {
    pthread_mutex_lock(&mut (*pc).mutex);
}
unsafe extern "C" fn unlock_peer_connection(mut pc: *mut peer_connection) {
    pthread_mutex_unlock(&mut (*pc).mutex);
}
unsafe extern "C" fn find_channel_by_i_stream(mut pc: *mut peer_connection,
                                              mut i_stream: uint16_t)
 -> *mut channel {
    if (i_stream as libc::c_int) < 100 as libc::c_int {
        return (*pc).i_stream_channel[i_stream as usize]
    } else { return 0 as *mut channel };
}
unsafe extern "C" fn find_channel_by_o_stream(mut pc: *mut peer_connection,
                                              mut o_stream: uint16_t)
 -> *mut channel {
    if (o_stream as libc::c_int) < 100 as libc::c_int {
        return (*pc).o_stream_channel[o_stream as usize]
    } else { return 0 as *mut channel };
}
unsafe extern "C" fn find_free_channel(mut pc: *mut peer_connection)
 -> *mut channel {
    let mut i: uint32_t = 0;
    i = 0 as libc::c_int as uint32_t;
    while i < 100 as libc::c_int as libc::c_uint {
        if (*pc).channels[i as usize].state as libc::c_int == 0 as libc::c_int
           {
            break ;
        }
        i = i.wrapping_add(1)
    }
    if i == 100 as libc::c_int as libc::c_uint {
        return 0 as *mut channel
    } else {
        return &mut *(*pc).channels.as_mut_ptr().offset(i as isize) as
                   *mut channel
    };
}
unsafe extern "C" fn find_free_o_stream(mut pc: *mut peer_connection)
 -> uint16_t {
    let mut status: sctp_status =
        sctp_status{sstat_assoc_id: 0,
                    sstat_state: 0,
                    sstat_rwnd: 0,
                    sstat_unackdata: 0,
                    sstat_penddata: 0,
                    sstat_instrms: 0,
                    sstat_outstrms: 0,
                    sstat_fragmentation_point: 0,
                    sstat_primary:
                        sctp_paddrinfo{spinfo_address:
                                           sockaddr_storage{ss_family: 0,
                                                            __ss_padding:
                                                                [0; 118],
                                                            __ss_align: 0,},
                                       spinfo_assoc_id: 0,
                                       spinfo_state: 0,
                                       spinfo_cwnd: 0,
                                       spinfo_srtt: 0,
                                       spinfo_rto: 0,
                                       spinfo_mtu: 0,},};
    let mut i: uint32_t = 0;
    let mut limit: uint32_t = 0;
    let mut len: socklen_t = 0;
    len = ::std::mem::size_of::<sctp_status>() as libc::c_ulong as socklen_t;
    if usrsctp_getsockopt((*pc).sock, IPPROTO_SCTP as libc::c_int,
                          0x100 as libc::c_int,
                          &mut status as *mut sctp_status as
                              *mut libc::c_void, &mut len) < 0 as libc::c_int
       {
        perror(b"getsockopt\x00" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int as uint16_t
    }
    if (status.sstat_outstrms as libc::c_int) < 100 as libc::c_int {
        limit = status.sstat_outstrms as uint32_t
    } else { limit = 100 as libc::c_int as uint32_t }
    /* stream id 0 is reserved */
    i = 1 as libc::c_int as uint32_t; /* XXX eror handling */
    while i < limit {
        if (*pc).o_stream_channel[i as usize].is_null() { break ; }
        i = i.wrapping_add(1)
    }
    if i == limit {
        return 0 as libc::c_int as uint16_t
    } else { return i as uint16_t };
}
unsafe extern "C" fn request_more_o_streams(mut pc: *mut peer_connection) {
    let mut status: sctp_status =
        sctp_status{sstat_assoc_id: 0,
                    sstat_state: 0,
                    sstat_rwnd: 0,
                    sstat_unackdata: 0,
                    sstat_penddata: 0,
                    sstat_instrms: 0,
                    sstat_outstrms: 0,
                    sstat_fragmentation_point: 0,
                    sstat_primary:
                        sctp_paddrinfo{spinfo_address:
                                           sockaddr_storage{ss_family: 0,
                                                            __ss_padding:
                                                                [0; 118],
                                                            __ss_align: 0,},
                                       spinfo_assoc_id: 0,
                                       spinfo_state: 0,
                                       spinfo_cwnd: 0,
                                       spinfo_srtt: 0,
                                       spinfo_rto: 0,
                                       spinfo_mtu: 0,},};
    let mut sas: sctp_add_streams =
        sctp_add_streams{sas_assoc_id: 0, sas_instrms: 0, sas_outstrms: 0,};
    let mut i: uint32_t = 0;
    let mut o_streams_needed: uint32_t = 0;
    let mut len: socklen_t = 0;
    o_streams_needed = 0 as libc::c_int as uint32_t;
    i = 0 as libc::c_int as uint32_t;
    while i < 100 as libc::c_int as libc::c_uint {
        if (*pc).channels[i as usize].state as libc::c_int == 1 as libc::c_int
               &&
               (*pc).channels[i as usize].o_stream as libc::c_int ==
                   0 as libc::c_int {
            o_streams_needed = o_streams_needed.wrapping_add(1)
        }
        i = i.wrapping_add(1)
    }
    len = ::std::mem::size_of::<sctp_status>() as libc::c_ulong as socklen_t;
    if usrsctp_getsockopt((*pc).sock, IPPROTO_SCTP as libc::c_int,
                          0x100 as libc::c_int,
                          &mut status as *mut sctp_status as
                              *mut libc::c_void, &mut len) < 0 as libc::c_int
       {
        perror(b"getsockopt\x00" as *const u8 as *const libc::c_char);
        return
    }
    if (status.sstat_outstrms as libc::c_uint).wrapping_add(o_streams_needed)
           > 100 as libc::c_int as libc::c_uint {
        o_streams_needed =
            (100 as libc::c_int - status.sstat_outstrms as libc::c_int) as
                uint32_t
    }
    if o_streams_needed == 0 as libc::c_int as libc::c_uint { return }
    memset(&mut sas as *mut sctp_add_streams as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_add_streams>() as libc::c_ulong);
    sas.sas_instrms = 0 as libc::c_int as uint16_t;
    sas.sas_outstrms = o_streams_needed as uint16_t;
    if usrsctp_setsockopt((*pc).sock, IPPROTO_SCTP as libc::c_int,
                          0x903 as libc::c_int,
                          &mut sas as *mut sctp_add_streams as
                              *const libc::c_void,
                          ::std::mem::size_of::<sctp_add_streams>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"setsockopt\x00" as *const u8 as *const libc::c_char);
    };
}
unsafe extern "C" fn send_open_request_message(mut sock: *mut socket,
                                               mut o_stream: uint16_t,
                                               mut unordered: uint8_t,
                                               mut pr_policy: uint16_t,
                                               mut pr_value: uint32_t)
 -> libc::c_int {
    /* XXX: This should be encoded in a better way */
    let mut req: rtcweb_datachannel_open_request =
        rtcweb_datachannel_open_request{msg_type: 0,
                                        channel_type: 0,
                                        flags: 0,
                                        reliability_params: 0,
                                        priority: 0,
                                        label: [],};
    let mut sndinfo: sctp_sndinfo =
        sctp_sndinfo{snd_sid: 0,
                     snd_flags: 0,
                     snd_ppid: 0,
                     snd_context: 0,
                     snd_assoc_id: 0,};
    memset(&mut req as *mut rtcweb_datachannel_open_request as
               *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<rtcweb_datachannel_open_request>() as
               libc::c_ulong);
    req.msg_type = 0 as libc::c_int as uint8_t;
    match pr_policy as libc::c_int {
        0 => {
            /* XXX: What about DATA_CHANNEL_RELIABLE_STREAM */
            req.channel_type = 0 as libc::c_int as uint8_t
        }
        1 => {
            /* XXX: What about DATA_CHANNEL_UNRELIABLE */
            req.channel_type = 4 as libc::c_int as uint8_t
        }
        3 => { req.channel_type = 3 as libc::c_int as uint8_t }
        _ => { return 0 as libc::c_int }
    } /* XXX Why 16-bit */
    req.flags = htons(0 as libc::c_int as uint16_t); /* XXX: add support */
    if unordered != 0 {
        req.flags =
            (req.flags as libc::c_int |
                 htons(0x1 as libc::c_int as uint16_t) as libc::c_int) as
                uint16_t
    }
    req.reliability_params = htons(pr_value as uint16_t);
    req.priority = htons(0 as libc::c_int as uint16_t) as int16_t;
    memset(&mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong);
    sndinfo.snd_sid = o_stream;
    sndinfo.snd_flags = 0x2000 as libc::c_int as uint16_t;
    sndinfo.snd_ppid = htonl(50 as libc::c_int as uint32_t);
    if usrsctp_sendv(sock,
                     &mut req as *mut rtcweb_datachannel_open_request as
                         *const libc::c_void,
                     ::std::mem::size_of::<rtcweb_datachannel_open_request>()
                         as libc::c_ulong, 0 as *mut sockaddr,
                     0 as libc::c_int,
                     &mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
                     ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong as
                         socklen_t, 1 as libc::c_int as libc::c_uint,
                     0 as libc::c_int) < 0 as libc::c_int as libc::c_long {
        perror(b"sctp_sendv\x00" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int
    } else { return 1 as libc::c_int };
}
unsafe extern "C" fn send_open_response_message(mut sock: *mut socket,
                                                mut o_stream: uint16_t,
                                                mut i_stream: uint16_t)
 -> libc::c_int {
    /* XXX: This should be encoded in a better way */
    let mut rsp: rtcweb_datachannel_open_response =
        rtcweb_datachannel_open_response{msg_type: 0,
                                         error: 0,
                                         flags: 0,
                                         reverse_stream: 0,};
    let mut sndinfo: sctp_sndinfo =
        sctp_sndinfo{snd_sid: 0,
                     snd_flags: 0,
                     snd_ppid: 0,
                     snd_context: 0,
                     snd_assoc_id: 0,};
    memset(&mut rsp as *mut rtcweb_datachannel_open_response as
               *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<rtcweb_datachannel_open_response>() as
               libc::c_ulong);
    rsp.msg_type = 1 as libc::c_int as uint8_t;
    rsp.error = 0 as libc::c_int as uint8_t;
    rsp.flags = htons(0 as libc::c_int as uint16_t);
    rsp.reverse_stream = htons(i_stream);
    memset(&mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong);
    sndinfo.snd_sid = o_stream;
    sndinfo.snd_flags = 0x2000 as libc::c_int as uint16_t;
    sndinfo.snd_ppid = htonl(50 as libc::c_int as uint32_t);
    if usrsctp_sendv(sock,
                     &mut rsp as *mut rtcweb_datachannel_open_response as
                         *const libc::c_void,
                     ::std::mem::size_of::<rtcweb_datachannel_open_response>()
                         as libc::c_ulong, 0 as *mut sockaddr,
                     0 as libc::c_int,
                     &mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
                     ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong as
                         socklen_t, 1 as libc::c_int as libc::c_uint,
                     0 as libc::c_int) < 0 as libc::c_int as libc::c_long {
        perror(b"sctp_sendv\x00" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int
    } else { return 1 as libc::c_int };
}
unsafe extern "C" fn send_open_ack_message(mut sock: *mut socket,
                                           mut o_stream: uint16_t)
 -> libc::c_int {
    /* XXX: This should be encoded in a better way */
    let mut ack: rtcweb_datachannel_ack =
        rtcweb_datachannel_ack{msg_type: 0,};
    let mut sndinfo: sctp_sndinfo =
        sctp_sndinfo{snd_sid: 0,
                     snd_flags: 0,
                     snd_ppid: 0,
                     snd_context: 0,
                     snd_assoc_id: 0,};
    memset(&mut ack as *mut rtcweb_datachannel_ack as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<rtcweb_datachannel_ack>() as libc::c_ulong);
    ack.msg_type = 2 as libc::c_int as uint8_t;
    memset(&mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong);
    sndinfo.snd_sid = o_stream;
    sndinfo.snd_flags = 0x2000 as libc::c_int as uint16_t;
    sndinfo.snd_ppid = htonl(50 as libc::c_int as uint32_t);
    if usrsctp_sendv(sock,
                     &mut ack as *mut rtcweb_datachannel_ack as
                         *const libc::c_void,
                     ::std::mem::size_of::<rtcweb_datachannel_ack>() as
                         libc::c_ulong, 0 as *mut sockaddr, 0 as libc::c_int,
                     &mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
                     ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong as
                         socklen_t, 1 as libc::c_int as libc::c_uint,
                     0 as libc::c_int) < 0 as libc::c_int as libc::c_long {
        perror(b"sctp_sendv\x00" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int
    } else { return 1 as libc::c_int };
}
unsafe extern "C" fn send_deferred_messages(mut pc: *mut peer_connection) {
    let mut i: uint32_t = 0;
    let mut channel: *mut channel = 0 as *mut channel;
    i = 0 as libc::c_int as uint32_t;
    while i < 100 as libc::c_int as libc::c_uint {
        channel =
            &mut *(*pc).channels.as_mut_ptr().offset(i as isize) as
                *mut channel;
        if (*channel).flags & 0x1 as libc::c_int as libc::c_uint != 0 {
            if send_open_request_message((*pc).sock, (*channel).o_stream,
                                         (*channel).unordered,
                                         (*channel).pr_policy,
                                         (*channel).pr_value) != 0 {
                (*channel).flags &= !(0x1 as libc::c_int) as libc::c_uint
            } else { (*__errno_location()) != 11 as libc::c_int; }
        }
        if (*channel).flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            if send_open_response_message((*pc).sock, (*channel).o_stream,
                                          (*channel).i_stream) != 0 {
                (*channel).flags &= !(0x2 as libc::c_int) as libc::c_uint
            } else { (*__errno_location()) != 11 as libc::c_int; }
        }
        if (*channel).flags & 0x4 as libc::c_int as libc::c_uint != 0 {
            if send_open_ack_message((*pc).sock, (*channel).o_stream) != 0 {
                (*channel).flags &= !(0x4 as libc::c_int) as libc::c_uint
            } else { (*__errno_location()) != 11 as libc::c_int; }
        }
        i = i.wrapping_add(1)
    };
}
unsafe extern "C" fn open_channel(mut pc: *mut peer_connection,
                                  mut unordered: uint8_t,
                                  mut pr_policy: uint16_t,
                                  mut pr_value: uint32_t) -> *mut channel {
    let mut channel: *mut channel = 0 as *mut channel;
    let mut o_stream: uint16_t = 0;
    if pr_policy as libc::c_int != 0 as libc::c_int &&
           pr_policy as libc::c_int != 0x1 as libc::c_int &&
           pr_policy as libc::c_int != 0x3 as libc::c_int {
        return 0 as *mut channel
    }
    if unordered as libc::c_int != 0 as libc::c_int &&
           unordered as libc::c_int != 1 as libc::c_int {
        return 0 as *mut channel
    }
    if pr_policy as libc::c_int == 0 as libc::c_int &&
           pr_value != 0 as libc::c_int as libc::c_uint {
        return 0 as *mut channel
    }
    channel = find_free_channel(pc);
    if channel.is_null() { return 0 as *mut channel }
    o_stream = find_free_o_stream(pc);
    (*channel).state = 1 as libc::c_int as uint8_t;
    (*channel).unordered = unordered;
    (*channel).pr_policy = pr_policy;
    (*channel).pr_value = pr_value;
    (*channel).o_stream = o_stream;
    (*channel).flags = 0 as libc::c_int as uint32_t;
    if o_stream as libc::c_int == 0 as libc::c_int {
        request_more_o_streams(pc);
    } else if send_open_request_message((*pc).sock, o_stream, unordered,
                                        pr_policy, pr_value) != 0 {
        (*pc).o_stream_channel[o_stream as usize] = channel
    } else if *__errno_location() == 11 as libc::c_int {
        (*pc).o_stream_channel[o_stream as usize] = channel;
        (*channel).flags |= 0x1 as libc::c_int as libc::c_uint
    } else {
        (*channel).state = 0 as libc::c_int as uint8_t;
        (*channel).unordered = 0 as libc::c_int as uint8_t;
        (*channel).pr_policy = 0 as libc::c_int as uint16_t;
        (*channel).pr_value = 0 as libc::c_int as uint32_t;
        (*channel).o_stream = 0 as libc::c_int as uint16_t;
        (*channel).flags = 0 as libc::c_int as uint32_t;
        channel = 0 as *mut channel
    }
    return channel;
}
unsafe extern "C" fn send_user_message(mut pc: *mut peer_connection,
                                       mut channel: *mut channel,
                                       mut message: *mut libc::c_char,
                                       mut length: size_t) -> libc::c_int {
    let mut spa: sctp_sendv_spa =
        sctp_sendv_spa{sendv_flags: 0,
                       sendv_sndinfo:
                           sctp_sndinfo{snd_sid: 0,
                                        snd_flags: 0,
                                        snd_ppid: 0,
                                        snd_context: 0,
                                        snd_assoc_id: 0,},
                       sendv_prinfo: sctp_prinfo{pr_policy: 0, pr_value: 0,},
                       sendv_authinfo: sctp_authinfo{auth_keynumber: 0,},};
    if channel.is_null() { return 0 as libc::c_int }
    if (*channel).state as libc::c_int != 2 as libc::c_int &&
           (*channel).state as libc::c_int != 1 as libc::c_int {
        /* XXX: What to do in other states */
        return 0 as libc::c_int
    }
    memset(&mut spa as *mut sctp_sendv_spa as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_sendv_spa>() as libc::c_ulong);
    spa.sendv_sndinfo.snd_sid = (*channel).o_stream;
    if (*channel).state as libc::c_int == 2 as libc::c_int &&
           (*channel).unordered as libc::c_int != 0 {
        spa.sendv_sndinfo.snd_flags =
            (0x2000 as libc::c_int | 0x400 as libc::c_int) as uint16_t
    } else { spa.sendv_sndinfo.snd_flags = 0x2000 as libc::c_int as uint16_t }
    spa.sendv_sndinfo.snd_ppid = htonl(51 as libc::c_int as uint32_t);
    spa.sendv_flags = 0x1 as libc::c_int as uint32_t;
    if (*channel).pr_policy as libc::c_int == 0x1 as libc::c_int ||
           (*channel).pr_policy as libc::c_int == 0x3 as libc::c_int {
        spa.sendv_prinfo.pr_policy = (*channel).pr_policy;
        spa.sendv_prinfo.pr_value = (*channel).pr_value;
        spa.sendv_flags |= 0x2 as libc::c_int as libc::c_uint
    }
    if usrsctp_sendv((*pc).sock, message as *const libc::c_void, length,
                     0 as *mut sockaddr, 0 as libc::c_int,
                     &mut spa as *mut sctp_sendv_spa as *mut libc::c_void,
                     ::std::mem::size_of::<sctp_sendv_spa>() as libc::c_ulong
                         as socklen_t, 4 as libc::c_int as libc::c_uint,
                     0 as libc::c_int) < 0 as libc::c_int as libc::c_long {
        perror(b"sctp_sendv\x00" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int
    } else { return 1 as libc::c_int };
}
unsafe extern "C" fn reset_outgoing_stream(mut pc: *mut peer_connection,
                                           mut o_stream: uint16_t) {
    let mut i: uint32_t = 0;
    i = 0 as libc::c_int as uint32_t;
    while i < (*pc).o_stream_buffer_counter {
        if (*pc).o_stream_buffer[i as usize] as libc::c_int ==
               o_stream as libc::c_int {
            return
        }
        i = i.wrapping_add(1)
    }
    let fresh0 = (*pc).o_stream_buffer_counter;
    (*pc).o_stream_buffer_counter =
        (*pc).o_stream_buffer_counter.wrapping_add(1);
    (*pc).o_stream_buffer[fresh0 as usize] = o_stream;
}
unsafe extern "C" fn send_outgoing_stream_reset(mut pc:
                                                    *mut peer_connection) {
    let mut srs: *mut sctp_reset_streams = 0 as *mut sctp_reset_streams;
    let mut i: uint32_t = 0;
    let mut len: size_t = 0;
    if (*pc).o_stream_buffer_counter == 0 as libc::c_int as libc::c_uint {
        return
    }
    len =
        (::std::mem::size_of::<sctp_assoc_t>() as
             libc::c_ulong).wrapping_add(((2 as libc::c_int as
                                               libc::c_uint).wrapping_add((*pc).o_stream_buffer_counter)
                                              as
                                              libc::c_ulong).wrapping_mul(::std::mem::size_of::<uint16_t>()
                                                                              as
                                                                              libc::c_ulong));
    srs = malloc(len) as *mut sctp_reset_streams;
    if srs.is_null() { return }
    memset(srs as *mut libc::c_void, 0 as libc::c_int, len);
    (*srs).srs_flags = 0x2 as libc::c_int as uint16_t;
    (*srs).srs_number_streams = (*pc).o_stream_buffer_counter as uint16_t;
    i = 0 as libc::c_int as uint32_t;
    while i < (*pc).o_stream_buffer_counter {
        *(*srs).srs_stream_list.as_mut_ptr().offset(i as isize) =
            (*pc).o_stream_buffer[i as usize];
        i = i.wrapping_add(1)
    }
    if usrsctp_setsockopt((*pc).sock, IPPROTO_SCTP as libc::c_int,
                          0x901 as libc::c_int, srs as *const libc::c_void,
                          len as socklen_t) < 0 as libc::c_int {
        perror(b"setsockopt\x00" as *const u8 as *const libc::c_char);
    } else {
        i = 0 as libc::c_int as uint32_t;
        while i < (*pc).o_stream_buffer_counter {
            *(*srs).srs_stream_list.as_mut_ptr().offset(i as isize) =
                0 as libc::c_int as uint16_t;
            i = i.wrapping_add(1)
        }
        (*pc).o_stream_buffer_counter = 0 as libc::c_int as uint32_t
    }
    free(srs as *mut libc::c_void);
}
unsafe extern "C" fn close_channel(mut pc: *mut peer_connection,
                                   mut channel: *mut channel) {
    if channel.is_null() { return }
    if (*channel).state as libc::c_int != 2 as libc::c_int { return }
    reset_outgoing_stream(pc, (*channel).o_stream);
    send_outgoing_stream_reset(pc);
    (*channel).state = 3 as libc::c_int as uint8_t;
}
unsafe extern "C" fn handle_open_request_message(mut pc: *mut peer_connection,
                                                 mut req:
                                                     *mut rtcweb_datachannel_open_request,
                                                 mut length: size_t,
                                                 mut i_stream: uint16_t) {
    let mut channel: *mut channel = 0 as *mut channel;
    let mut pr_value: uint32_t = 0;
    let mut pr_policy: uint16_t = 0;
    let mut o_stream: uint16_t = 0;
    let mut unordered: uint8_t = 0;
    channel = find_channel_by_i_stream(pc, i_stream);
    if !channel.is_null() {
        printf(b"handle_open_request_message: channel %d is in state %d instead of CLOSED.\n\x00"
                   as *const u8 as *const libc::c_char, (*channel).id,
               (*channel).state as libc::c_int);
        /* XXX: some error handling */
        return
    }
    channel = find_free_channel(pc);
    if channel.is_null() {
        /* XXX: some error handling */
        return
    }
    match (*req).channel_type as libc::c_int {
        0 => { pr_policy = 0 as libc::c_int as uint16_t }
        1 => {
            /* XXX Doesn't make sense */
            pr_policy = 0 as libc::c_int as uint16_t
        }
        2 => {
            /* XXX Doesn't make sense */
            pr_policy = 0x1 as libc::c_int as uint16_t
        }
        3 => { pr_policy = 0x3 as libc::c_int as uint16_t }
        4 => { pr_policy = 0x1 as libc::c_int as uint16_t }
        _ => { pr_policy = 0 as libc::c_int as uint16_t }
    }
    pr_value = ntohs((*req).reliability_params) as uint32_t;
    if ntohs((*req).flags) as libc::c_int & 0x1 as libc::c_int != 0 {
        unordered = 1 as libc::c_int as uint8_t
    } else { unordered = 0 as libc::c_int as uint8_t }
    o_stream = find_free_o_stream(pc);
    (*channel).state = 1 as libc::c_int as uint8_t;
    (*channel).unordered = unordered;
    (*channel).pr_policy = pr_policy;
    (*channel).pr_value = pr_value;
    (*channel).i_stream = i_stream;
    (*channel).o_stream = o_stream;
    (*channel).flags = 0 as libc::c_int as uint32_t;
    (*pc).i_stream_channel[i_stream as usize] = channel;
    if o_stream as libc::c_int == 0 as libc::c_int {
        request_more_o_streams(pc);
    } else if send_open_response_message((*pc).sock, o_stream, i_stream) != 0
     {
        (*pc).o_stream_channel[o_stream as usize] = channel
    } else if *__errno_location() == 11 as libc::c_int {
        (*channel).flags |= 0x2 as libc::c_int as libc::c_uint;
        (*pc).o_stream_channel[o_stream as usize] = channel
    } else {
        /* XXX: Signal error to the other end. */
        (*pc).i_stream_channel[i_stream as usize] = 0 as *mut channel;
        (*channel).state = 0 as libc::c_int as uint8_t;
        (*channel).unordered = 0 as libc::c_int as uint8_t;
        (*channel).pr_policy = 0 as libc::c_int as uint16_t;
        (*channel).pr_value = 0 as libc::c_int as uint32_t;
        (*channel).i_stream = 0 as libc::c_int as uint16_t;
        (*channel).o_stream = 0 as libc::c_int as uint16_t;
        (*channel).flags = 0 as libc::c_int as uint32_t
    };
}
unsafe extern "C" fn handle_open_response_message(mut pc:
                                                      *mut peer_connection,
                                                  mut rsp:
                                                      *mut rtcweb_datachannel_open_response,
                                                  mut length: size_t,
                                                  mut i_stream: uint16_t) {
    let mut o_stream: uint16_t = 0;
    let mut channel: *mut channel = 0 as *mut channel;
    o_stream = ntohs((*rsp).reverse_stream);
    channel = find_channel_by_o_stream(pc, o_stream);
    if channel.is_null() {
        /* XXX: improve error handling */
        printf(b"handle_open_response_message: Can\'t find channel for outgoing steam %d.\n\x00"
                   as *const u8 as *const libc::c_char,
               o_stream as libc::c_int);
        return
    }
    if (*channel).state as libc::c_int != 1 as libc::c_int {
        /* XXX: improve error handling */
        printf(b"handle_open_response_message: Channel with id %d for outgoing steam %d is in state %d.\n\x00"
                   as *const u8 as *const libc::c_char, (*channel).id,
               o_stream as libc::c_int, (*channel).state as libc::c_int);
        return
    }
    if !find_channel_by_i_stream(pc, i_stream).is_null() {
        /* XXX: improve error handling */
        printf(b"handle_open_response_message: Channel collision for channel with id %d and streams (in/out) = (%d/%d).\n\x00"
                   as *const u8 as *const libc::c_char, (*channel).id,
               i_stream as libc::c_int, o_stream as libc::c_int);
        return
    }
    (*channel).i_stream = i_stream;
    (*channel).state = 2 as libc::c_int as uint8_t;
    (*pc).i_stream_channel[i_stream as usize] = channel;
    if send_open_ack_message((*pc).sock, o_stream) != 0 {
        (*channel).flags = 0 as libc::c_int as uint32_t
    } else { (*channel).flags |= 0x4 as libc::c_int as libc::c_uint };
}
unsafe extern "C" fn handle_open_ack_message(mut pc: *mut peer_connection,
                                             mut ack:
                                                 *mut rtcweb_datachannel_ack,
                                             mut length: size_t,
                                             mut i_stream: uint16_t) {
    let mut channel: *mut channel = 0 as *mut channel;
    channel = find_channel_by_i_stream(pc, i_stream);
    if channel.is_null() {
        /* XXX: some error handling */
        return
    }
    if (*channel).state as libc::c_int == 2 as libc::c_int { return }
    if (*channel).state as libc::c_int != 1 as libc::c_int {
        /* XXX: error handling */
        return
    }
    (*channel).state = 2 as libc::c_int as uint8_t;
}
unsafe extern "C" fn handle_unknown_message(mut msg: *mut libc::c_char,
                                            mut length: size_t,
                                            mut i_stream: uint16_t) {
}
unsafe extern "C" fn handle_data_message(mut pc: *mut peer_connection,
                                         mut buffer: *mut libc::c_char,
                                         mut length: size_t,
                                         mut i_stream: uint16_t) {
    let mut channel: *mut channel = 0 as *mut channel;
    channel = find_channel_by_i_stream(pc, i_stream);
    if channel.is_null() {
        /* XXX: Some error handling */
        return
    }
    if (*channel).state as libc::c_int == 1 as libc::c_int {
        /* Implicit ACK */
        (*channel).state = 2 as libc::c_int as uint8_t
    }
    if (*channel).state as libc::c_int != 2 as libc::c_int {
        /* XXX: What about other states? */
		/* XXX: Some error handling */
        return
    } else {
        /* Assuming DATA_CHANNEL_PPID_DOMSTRING */
		/* XXX: Protect for non 0 terminated buffer */
        printf(b"Message received of length %zu on channel with id %d: %.*s\n\x00"
                   as *const u8 as *const libc::c_char, length, (*channel).id,
               length as libc::c_int, buffer);
    };
}
unsafe extern "C" fn handle_message(mut pc: *mut peer_connection,
                                    mut buffer: *mut libc::c_char,
                                    mut length: size_t, mut ppid: uint32_t,
                                    mut i_stream: uint16_t) {
    let mut req: *mut rtcweb_datachannel_open_request =
        0 as *mut rtcweb_datachannel_open_request;
    let mut rsp: *mut rtcweb_datachannel_open_response =
        0 as *mut rtcweb_datachannel_open_response;
    let mut ack: *mut rtcweb_datachannel_ack =
        0 as *mut rtcweb_datachannel_ack;
    let mut msg: *mut rtcweb_datachannel_ack =
        0 as *mut rtcweb_datachannel_ack;
    match ppid {
        50 => {
            if length <
                   ::std::mem::size_of::<rtcweb_datachannel_ack>() as
                       libc::c_ulong {
                return
            }
            msg = buffer as *mut rtcweb_datachannel_ack;
            match (*msg).msg_type as libc::c_int {
                0 => {
                    if length <
                           ::std::mem::size_of::<rtcweb_datachannel_open_request>()
                               as libc::c_ulong {
                        /* XXX: error handling? */
                        return
                    }
                    req = buffer as *mut rtcweb_datachannel_open_request;
                    handle_open_request_message(pc, req, length, i_stream);
                }
                1 => {
                    if length <
                           ::std::mem::size_of::<rtcweb_datachannel_open_response>()
                               as libc::c_ulong {
                        /* XXX: error handling? */
                        return
                    }
                    rsp = buffer as *mut rtcweb_datachannel_open_response;
                    handle_open_response_message(pc, rsp, length, i_stream);
                }
                2 => {
                    if length <
                           ::std::mem::size_of::<rtcweb_datachannel_ack>() as
                               libc::c_ulong {
                        /* XXX: error handling? */
                        return
                    }
                    ack = buffer as *mut rtcweb_datachannel_ack;
                    handle_open_ack_message(pc, ack, length, i_stream);
                }
                _ => { handle_unknown_message(buffer, length, i_stream); }
            }
        }
        51 | 52 => { handle_data_message(pc, buffer, length, i_stream); }
        _ => {
            printf(b"Message of length %zu, PPID %u on stream %u received.\n\x00"
                       as *const u8 as *const libc::c_char, length, ppid,
                   i_stream as libc::c_int);
        }
    };
}
unsafe extern "C" fn handle_association_change_event(mut sac:
                                                         *mut sctp_assoc_change) {
    let mut i: libc::c_uint = 0;
    let mut n: libc::c_uint = 0;
    printf(b"Association change \x00" as *const u8 as *const libc::c_char);
    match (*sac).sac_state as libc::c_int {
        1 => {
            printf(b"SCTP_COMM_UP\x00" as *const u8 as *const libc::c_char);
        }
        2 => {
            printf(b"SCTP_COMM_LOST\x00" as *const u8 as *const libc::c_char);
        }
        3 => {
            printf(b"SCTP_RESTART\x00" as *const u8 as *const libc::c_char);
        }
        4 => {
            printf(b"SCTP_SHUTDOWN_COMP\x00" as *const u8 as
                       *const libc::c_char);
        }
        5 => {
            printf(b"SCTP_CANT_STR_ASSOC\x00" as *const u8 as
                       *const libc::c_char);
        }
        _ => { printf(b"UNKNOWN\x00" as *const u8 as *const libc::c_char); }
    }
    printf(b", streams (in/out) = (%u/%u)\x00" as *const u8 as
               *const libc::c_char, (*sac).sac_inbound_streams as libc::c_int,
           (*sac).sac_outbound_streams as libc::c_int);
    n =
        ((*sac).sac_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_assoc_change>()
                                             as libc::c_ulong) as
            libc::c_uint;
    if ((*sac).sac_state as libc::c_int == 0x1 as libc::c_int ||
            (*sac).sac_state as libc::c_int == 0x3 as libc::c_int) &&
           n > 0 as libc::c_int as libc::c_uint {
        printf(b", supports\x00" as *const u8 as *const libc::c_char);
        i = 0 as libc::c_int as libc::c_uint;
        while i < n {
            match *(*sac).sac_info.as_mut_ptr().offset(i as isize) as
                      libc::c_int {
                1 => {
                    printf(b" PR\x00" as *const u8 as *const libc::c_char);
                }
                2 => {
                    printf(b" AUTH\x00" as *const u8 as *const libc::c_char);
                }
                3 => {
                    printf(b" ASCONF\x00" as *const u8 as
                               *const libc::c_char);
                }
                4 => {
                    printf(b" MULTIBUF\x00" as *const u8 as
                               *const libc::c_char);
                }
                5 => {
                    printf(b" RE-CONFIG\x00" as *const u8 as
                               *const libc::c_char);
                }
                _ => {
                    printf(b" UNKNOWN(0x%02x)\x00" as *const u8 as
                               *const libc::c_char,
                           *(*sac).sac_info.as_mut_ptr().offset(i as isize) as
                               libc::c_int);
                }
            }
            i = i.wrapping_add(1)
        }
    } else if ((*sac).sac_state as libc::c_int == 0x2 as libc::c_int ||
                   (*sac).sac_state as libc::c_int == 0x5 as libc::c_int) &&
                  n > 0 as libc::c_int as libc::c_uint {
        printf(b", ABORT =\x00" as *const u8 as *const libc::c_char);
        i = 0 as libc::c_int as libc::c_uint;
        while i < n {
            printf(b" 0x%02x\x00" as *const u8 as *const libc::c_char,
                   *(*sac).sac_info.as_mut_ptr().offset(i as isize) as
                       libc::c_int);
            i = i.wrapping_add(1)
        }
    }
    printf(b".\n\x00" as *const u8 as *const libc::c_char);
    if (*sac).sac_state as libc::c_int == 0x5 as libc::c_int ||
           (*sac).sac_state as libc::c_int == 0x4 as libc::c_int ||
           (*sac).sac_state as libc::c_int == 0x2 as libc::c_int {
        exit(0 as libc::c_int);
    };
}
unsafe extern "C" fn handle_peer_address_change_event(mut spc:
                                                          *mut sctp_paddr_change) {
    let mut addr_buf: [libc::c_char; 46] = [0; 46];
    let mut addr: *const libc::c_char = 0 as *const libc::c_char;
    let mut sin: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut sin6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    match (*spc).spc_aaddr.ss_family as libc::c_int {
        2 => {
            sin =
                &mut (*spc).spc_aaddr as *mut sockaddr_storage as
                    *mut sockaddr_in;
            addr =
                inet_ntop(2 as libc::c_int,
                          &mut (*sin).sin_addr as *mut in_addr as
                              *const libc::c_void, addr_buf.as_mut_ptr(),
                          16 as libc::c_int as socklen_t)
        }
        10 => {
            sin6 =
                &mut (*spc).spc_aaddr as *mut sockaddr_storage as
                    *mut sockaddr_in6;
            addr =
                inet_ntop(10 as libc::c_int,
                          &mut (*sin6).sin6_addr as *mut in6_addr as
                              *const libc::c_void, addr_buf.as_mut_ptr(),
                          46 as libc::c_int as socklen_t)
        }
        _ => {
            snprintf(addr_buf.as_mut_ptr(),
                     46 as libc::c_int as libc::c_ulong,
                     b"Unknown family %d\x00" as *const u8 as
                         *const libc::c_char,
                     (*spc).spc_aaddr.ss_family as libc::c_int);
            addr = addr_buf.as_mut_ptr()
        }
    }
    printf(b"Peer address %s is now \x00" as *const u8 as *const libc::c_char,
           addr);
    match (*spc).spc_state {
        1 => {
            printf(b"SCTP_ADDR_AVAILABLE\x00" as *const u8 as
                       *const libc::c_char);
        }
        2 => {
            printf(b"SCTP_ADDR_UNREACHABLE\x00" as *const u8 as
                       *const libc::c_char);
        }
        3 => {
            printf(b"SCTP_ADDR_REMOVED\x00" as *const u8 as
                       *const libc::c_char);
        }
        4 => {
            printf(b"SCTP_ADDR_ADDED\x00" as *const u8 as
                       *const libc::c_char);
        }
        5 => {
            printf(b"SCTP_ADDR_MADE_PRIM\x00" as *const u8 as
                       *const libc::c_char);
        }
        6 => {
            printf(b"SCTP_ADDR_CONFIRMED\x00" as *const u8 as
                       *const libc::c_char);
        }
        _ => { printf(b"UNKNOWN\x00" as *const u8 as *const libc::c_char); }
    }
    printf(b" (error = 0x%08x).\n\x00" as *const u8 as *const libc::c_char,
           (*spc).spc_error);
}
unsafe extern "C" fn handle_adaptation_indication(mut sai:
                                                      *mut sctp_adaptation_event) {
    printf(b"Adaptation indication: %x.\n\x00" as *const u8 as
               *const libc::c_char, (*sai).sai_adaptation_ind);
}
unsafe extern "C" fn handle_shutdown_event(mut sse:
                                               *mut sctp_shutdown_event) {
    printf(b"Shutdown event.\n\x00" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn handle_stream_reset_event(mut pc: *mut peer_connection,
                                               mut strrst:
                                                   *mut sctp_stream_reset_event) {
    let mut n: uint32_t = 0;
    let mut i: uint32_t = 0;
    let mut channel: *mut channel = 0 as *mut channel;
    n =
        ((*strrst).strreset_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_stream_reset_event>()
                                             as
                                             libc::c_ulong).wrapping_div(::std::mem::size_of::<uint16_t>()
                                                                             as
                                                                             libc::c_ulong)
            as uint32_t;
    printf(b"Stream reset event: flags = %x, \x00" as *const u8 as
               *const libc::c_char, (*strrst).strreset_flags as libc::c_int);
    if (*strrst).strreset_flags as libc::c_int & 0x1 as libc::c_int != 0 {
        if (*strrst).strreset_flags as libc::c_int & 0x2 as libc::c_int != 0 {
            printf(b"incoming/\x00" as *const u8 as *const libc::c_char);
        }
        printf(b"incoming \x00" as *const u8 as *const libc::c_char);
    }
    if (*strrst).strreset_flags as libc::c_int & 0x2 as libc::c_int != 0 {
        printf(b"outgoing \x00" as *const u8 as *const libc::c_char);
    }
    printf(b"stream ids = \x00" as *const u8 as *const libc::c_char);
    i = 0 as libc::c_int as uint32_t;
    while i < n {
        if i > 0 as libc::c_int as libc::c_uint {
            printf(b", \x00" as *const u8 as *const libc::c_char);
        }
        printf(b"%d\x00" as *const u8 as *const libc::c_char,
               *(*strrst).strreset_stream_list.as_mut_ptr().offset(i as isize)
                   as libc::c_int);
        i = i.wrapping_add(1)
    }
    printf(b".\n\x00" as *const u8 as *const libc::c_char);
    if (*strrst).strreset_flags as libc::c_int & 0x4 as libc::c_int == 0 &&
           (*strrst).strreset_flags as libc::c_int & 0x8 as libc::c_int == 0 {
        i = 0 as libc::c_int as uint32_t;
        while i < n {
            if (*strrst).strreset_flags as libc::c_int & 0x1 as libc::c_int !=
                   0 {
                channel =
                    find_channel_by_i_stream(pc,
                                             *(*strrst).strreset_stream_list.as_mut_ptr().offset(i
                                                                                                     as
                                                                                                     isize));
                if !channel.is_null() {
                    (*pc).i_stream_channel[(*channel).i_stream as usize] =
                        0 as *mut channel;
                    (*channel).i_stream = 0 as libc::c_int as uint16_t;
                    if (*channel).o_stream as libc::c_int == 0 as libc::c_int
                       {
                        (*channel).pr_policy = 0 as libc::c_int as uint16_t;
                        (*channel).pr_value = 0 as libc::c_int as uint32_t;
                        (*channel).unordered = 0 as libc::c_int as uint8_t;
                        (*channel).flags = 0 as libc::c_int as uint32_t;
                        (*channel).state = 0 as libc::c_int as uint8_t
                    } else if (*channel).state as libc::c_int ==
                                  2 as libc::c_int {
                        reset_outgoing_stream(pc, (*channel).o_stream);
                        (*channel).state = 3 as libc::c_int as uint8_t
                    }
                }
            }
            if (*strrst).strreset_flags as libc::c_int & 0x2 as libc::c_int !=
                   0 {
                channel =
                    find_channel_by_o_stream(pc,
                                             *(*strrst).strreset_stream_list.as_mut_ptr().offset(i
                                                                                                     as
                                                                                                     isize));
                if !channel.is_null() {
                    (*pc).o_stream_channel[(*channel).o_stream as usize] =
                        0 as *mut channel;
                    (*channel).o_stream = 0 as libc::c_int as uint16_t;
                    if (*channel).i_stream as libc::c_int == 0 as libc::c_int
                       {
                        (*channel).pr_policy = 0 as libc::c_int as uint16_t;
                        (*channel).pr_value = 0 as libc::c_int as uint32_t;
                        (*channel).unordered = 0 as libc::c_int as uint8_t;
                        (*channel).flags = 0 as libc::c_int as uint32_t;
                        (*channel).state = 0 as libc::c_int as uint8_t
                    }
                }
            }
            i = i.wrapping_add(1)
        }
    };
}
unsafe extern "C" fn handle_stream_change_event(mut pc: *mut peer_connection,
                                                mut strchg:
                                                    *mut sctp_stream_change_event) {
    let mut o_stream: uint16_t = 0;
    let mut i: uint32_t = 0;
    let mut channel: *mut channel = 0 as *mut channel;
    printf(b"Stream change event: streams (in/out) = (%u/%u), flags = %x.\n\x00"
               as *const u8 as *const libc::c_char,
           (*strchg).strchange_instrms as libc::c_int,
           (*strchg).strchange_outstrms as libc::c_int,
           (*strchg).strchange_flags as libc::c_int);
    i = 0 as libc::c_int as uint32_t;
    while i < 100 as libc::c_int as libc::c_uint {
        channel =
            &mut *(*pc).channels.as_mut_ptr().offset(i as isize) as
                *mut channel;
        if (*channel).state as libc::c_int == 1 as libc::c_int &&
               (*channel).o_stream as libc::c_int == 0 as libc::c_int {
            if (*strchg).strchange_flags as libc::c_int & 0x4 as libc::c_int
                   != 0 ||
                   (*strchg).strchange_flags as libc::c_int &
                       0x8 as libc::c_int != 0 {
                /* XXX: Signal to the other end. */
                if (*channel).i_stream as libc::c_int != 0 as libc::c_int {
                    (*pc).i_stream_channel[(*channel).i_stream as usize] =
                        0 as *mut channel
                }
                (*channel).unordered = 0 as libc::c_int as uint8_t;
                (*channel).pr_policy = 0 as libc::c_int as uint16_t;
                (*channel).pr_value = 0 as libc::c_int as uint32_t;
                (*channel).i_stream = 0 as libc::c_int as uint16_t;
                (*channel).o_stream = 0 as libc::c_int as uint16_t;
                (*channel).flags = 0 as libc::c_int as uint32_t;
                (*channel).state = 0 as libc::c_int as uint8_t
            } else {
                o_stream = find_free_o_stream(pc);
                if !(o_stream as libc::c_int != 0 as libc::c_int) { break ; }
                (*channel).o_stream = o_stream;
                (*pc).o_stream_channel[o_stream as usize] = channel;
                if (*channel).i_stream as libc::c_int == 0 as libc::c_int {
                    (*channel).flags |= 0x1 as libc::c_int as libc::c_uint
                } else {
                    (*channel).flags |= 0x2 as libc::c_int as libc::c_uint
                }
            }
        }
        i = i.wrapping_add(1)
    };
}
unsafe extern "C" fn handle_remote_error_event(mut sre:
                                                   *mut sctp_remote_error) {
    let mut i: size_t = 0;
    let mut n: size_t = 0;
    n =
        ((*sre).sre_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_remote_error>()
                                             as libc::c_ulong);
    printf(b"Remote Error (error = 0x%04x): \x00" as *const u8 as
               *const libc::c_char, (*sre).sre_error as libc::c_int);
    i = 0 as libc::c_int as size_t;
    while i < n {
        printf(b" 0x%02x\x00" as *const u8 as *const libc::c_char,
               *(*sre).sre_data.as_mut_ptr().offset(i as isize) as
                   libc::c_int);
        i = i.wrapping_add(1)
    }
    printf(b".\n\x00" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn handle_send_failed_event(mut ssfe:
                                                  *mut sctp_send_failed_event) {
    let mut i: size_t = 0;
    let mut n: size_t = 0;
    if (*ssfe).ssfe_flags as libc::c_int & 0x1 as libc::c_int != 0 {
        printf(b"Unsent \x00" as *const u8 as *const libc::c_char);
    }
    if (*ssfe).ssfe_flags as libc::c_int & 0x2 as libc::c_int != 0 {
        printf(b"Sent \x00" as *const u8 as *const libc::c_char);
    }
    if (*ssfe).ssfe_flags as libc::c_int &
           !(0x2 as libc::c_int | 0x1 as libc::c_int) != 0 {
        printf(b"(flags = %x) \x00" as *const u8 as *const libc::c_char,
               (*ssfe).ssfe_flags as libc::c_int);
    }
    printf(b"message with PPID = %u, SID = %u, flags: 0x%04x due to error = 0x%08x\x00"
               as *const u8 as *const libc::c_char,
           ntohl((*ssfe).ssfe_info.snd_ppid),
           (*ssfe).ssfe_info.snd_sid as libc::c_int,
           (*ssfe).ssfe_info.snd_flags as libc::c_int, (*ssfe).ssfe_error);
    n =
        ((*ssfe).ssfe_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_send_failed_event>()
                                             as libc::c_ulong);
    i = 0 as libc::c_int as size_t;
    while i < n {
        printf(b" 0x%02x\x00" as *const u8 as *const libc::c_char,
               *(*ssfe).ssfe_data.as_mut_ptr().offset(i as isize) as
                   libc::c_int);
        i = i.wrapping_add(1)
    }
    printf(b".\n\x00" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn handle_notification_rtcweb(mut pc: *mut peer_connection,
                                                mut notif:
                                                    *mut sctp_notification,
                                                mut n: size_t) {
    if (*notif).sn_header.sn_length != n as uint32_t { return }
    match (*notif).sn_header.sn_type as libc::c_int {
        1 => {
            handle_association_change_event(&mut (*notif).sn_assoc_change);
        }
        2 => {
            handle_peer_address_change_event(&mut (*notif).sn_paddr_change);
        }
        3 => { handle_remote_error_event(&mut (*notif).sn_remote_error); }
        5 => { handle_shutdown_event(&mut (*notif).sn_shutdown_event); }
        6 => {
            handle_adaptation_indication(&mut (*notif).sn_adaptation_event);
        }
        14 => {
            handle_send_failed_event(&mut (*notif).sn_send_failed_event);
        }
        9 => {
            handle_stream_reset_event(pc, &mut (*notif).sn_strreset_event);
            send_deferred_messages(pc);
            send_outgoing_stream_reset(pc);
            request_more_o_streams(pc);
        }
        13 => {
            handle_stream_change_event(pc, &mut (*notif).sn_strchange_event);
            send_deferred_messages(pc);
            send_outgoing_stream_reset(pc);
            request_more_o_streams(pc);
        }
        7 | 8 | 10 | 11 | 12 | _ => { }
    };
}
unsafe extern "C" fn print_status(mut pc: *mut peer_connection) {
    let mut status: sctp_status =
        sctp_status{sstat_assoc_id: 0,
                    sstat_state: 0,
                    sstat_rwnd: 0,
                    sstat_unackdata: 0,
                    sstat_penddata: 0,
                    sstat_instrms: 0,
                    sstat_outstrms: 0,
                    sstat_fragmentation_point: 0,
                    sstat_primary:
                        sctp_paddrinfo{spinfo_address:
                                           sockaddr_storage{ss_family: 0,
                                                            __ss_padding:
                                                                [0; 118],
                                                            __ss_align: 0,},
                                       spinfo_assoc_id: 0,
                                       spinfo_state: 0,
                                       spinfo_cwnd: 0,
                                       spinfo_srtt: 0,
                                       spinfo_rto: 0,
                                       spinfo_mtu: 0,},};
    let mut len: socklen_t = 0;
    let mut i: uint32_t = 0;
    let mut channel: *mut channel = 0 as *mut channel;
    len = ::std::mem::size_of::<sctp_status>() as libc::c_ulong as socklen_t;
    if usrsctp_getsockopt((*pc).sock, IPPROTO_SCTP as libc::c_int,
                          0x100 as libc::c_int,
                          &mut status as *mut sctp_status as
                              *mut libc::c_void, &mut len) < 0 as libc::c_int
       {
        perror(b"getsockopt\x00" as *const u8 as *const libc::c_char);
        return
    }
    printf(b"Association state: \x00" as *const u8 as *const libc::c_char);
    match status.sstat_state {
        0 => { printf(b"CLOSED\n\x00" as *const u8 as *const libc::c_char); }
        4096 => {
            printf(b"BOUND\n\x00" as *const u8 as *const libc::c_char);
        }
        8192 => {
            printf(b"LISTEN\n\x00" as *const u8 as *const libc::c_char);
        }
        2 => {
            printf(b"COOKIE_WAIT\n\x00" as *const u8 as *const libc::c_char);
        }
        4 => {
            printf(b"COOKIE_ECHOED\n\x00" as *const u8 as
                       *const libc::c_char);
        }
        8 => {
            printf(b"ESTABLISHED\n\x00" as *const u8 as *const libc::c_char);
        }
        128 => {
            printf(b"SHUTDOWN_PENDING\n\x00" as *const u8 as
                       *const libc::c_char);
        }
        16 => {
            printf(b"SHUTDOWN_SENT\n\x00" as *const u8 as
                       *const libc::c_char);
        }
        32 => {
            printf(b"SHUTDOWN_RECEIVED\n\x00" as *const u8 as
                       *const libc::c_char);
        }
        64 => {
            printf(b"SHUTDOWN_ACK_SENT\n\x00" as *const u8 as
                       *const libc::c_char);
        }
        _ => { printf(b"UNKNOWN\n\x00" as *const u8 as *const libc::c_char); }
    }
    printf(b"Number of streams (i/o) = (%u/%u)\n\x00" as *const u8 as
               *const libc::c_char, status.sstat_instrms as libc::c_int,
           status.sstat_outstrms as libc::c_int);
    i = 0 as libc::c_int as uint32_t;
    while i < 100 as libc::c_int as libc::c_uint {
        channel =
            &mut *(*pc).channels.as_mut_ptr().offset(i as isize) as
                *mut channel;
        if !((*channel).state as libc::c_int == 0 as libc::c_int) {
            printf(b"Channel with id = %u: state \x00" as *const u8 as
                       *const libc::c_char, (*channel).id);
            match (*channel).state as libc::c_int {
                0 => {
                    printf(b"CLOSED\x00" as *const u8 as *const libc::c_char);
                }
                1 => {
                    printf(b"CONNECTING\x00" as *const u8 as
                               *const libc::c_char);
                }
                2 => {
                    printf(b"OPEN\x00" as *const u8 as *const libc::c_char);
                }
                3 => {
                    printf(b"CLOSING\x00" as *const u8 as
                               *const libc::c_char);
                }
                _ => {
                    printf(b"UNKNOWN(%d)\x00" as *const u8 as
                               *const libc::c_char,
                           (*channel).state as libc::c_int);
                }
            }
            printf(b", flags = 0x%08x, stream id (in/out): (%u/%u), \x00" as
                       *const u8 as *const libc::c_char, (*channel).flags,
                   (*channel).i_stream as libc::c_int,
                   (*channel).o_stream as libc::c_int);
            if (*channel).unordered != 0 {
                printf(b"unordered, \x00" as *const u8 as
                           *const libc::c_char);
            } else {
                printf(b"ordered, \x00" as *const u8 as *const libc::c_char);
            }
            match (*channel).pr_policy as libc::c_int {
                0 => {
                    printf(b"reliable.\n\x00" as *const u8 as
                               *const libc::c_char);
                }
                1 => {
                    printf(b"unreliable (timeout %ums).\n\x00" as *const u8 as
                               *const libc::c_char, (*channel).pr_value);
                }
                3 => {
                    printf(b"unreliable (max. %u rtx).\n\x00" as *const u8 as
                               *const libc::c_char, (*channel).pr_value);
                }
                _ => {
                    printf(b"unknown policy %u.\n\x00" as *const u8 as
                               *const libc::c_char,
                           (*channel).pr_policy as libc::c_int);
                }
            }
        }
        i = i.wrapping_add(1)
    };
}
unsafe extern "C" fn receive_cb(mut sock: *mut socket,
                                mut addr: sctp_sockstore,
                                mut data: *mut libc::c_void,
                                mut datalen: size_t, mut rcv: sctp_rcvinfo,
                                mut flags: libc::c_int,
                                mut ulp_info: *mut libc::c_void)
 -> libc::c_int {
    let mut pc: *mut peer_connection = 0 as *mut peer_connection;
    pc = ulp_info as *mut peer_connection;
    if !data.is_null() {
        lock_peer_connection(pc);
        if flags & 0x2000 as libc::c_int != 0 {
            handle_notification_rtcweb(pc, data as *mut sctp_notification,
                                       datalen);
        } else {
            handle_message(pc, data as *mut libc::c_char, datalen,
                           ntohl(rcv.rcv_ppid), rcv.rcv_sid);
        }
        unlock_peer_connection(pc);
    }
    return 1 as libc::c_int;
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut sock: *mut socket = 0 as *mut socket;
    let mut addr: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut addr_len: socklen_t = 0;
    let mut line: [libc::c_char; 1025] = [0; 1025];
    let mut unordered: libc::c_uint = 0;
    let mut policy: libc::c_uint = 0;
    let mut value: libc::c_uint = 0;
    let mut id: libc::c_uint = 0;
    let mut seconds: libc::c_uint = 0;
    let mut i: libc::c_uint = 0;
    let mut channel: *mut channel = 0 as *mut channel;
    let on: libc::c_int = 1 as libc::c_int;
    let mut av: sctp_assoc_value =
        sctp_assoc_value{assoc_id: 0, assoc_value: 0,};
    let mut event: sctp_event =
        sctp_event{se_assoc_id: 0, se_type: 0, se_on: 0,};
    let mut encaps: sctp_udpencaps =
        sctp_udpencaps{sue_address:
                           sockaddr_storage{ss_family: 0,
                                            __ss_padding: [0; 118],
                                            __ss_align: 0,},
                       sue_assoc_id: 0,
                       sue_port: 0,};
    let mut initmsg: sctp_initmsg =
        sctp_initmsg{sinit_num_ostreams: 0,
                     sinit_max_instreams: 0,
                     sinit_max_attempts: 0,
                     sinit_max_init_timeo: 0,};
    let mut event_types: [uint16_t; 8] =
        [0x1 as libc::c_int as uint16_t, 0x2 as libc::c_int as uint16_t,
         0x3 as libc::c_int as uint16_t, 0x5 as libc::c_int as uint16_t,
         0x6 as libc::c_int as uint16_t, 0xe as libc::c_int as uint16_t,
         0x9 as libc::c_int as uint16_t, 0xd as libc::c_int as uint16_t];
    let mut addrbuf: [libc::c_char; 16] = [0; 16];
    if argc > 1 as libc::c_int {
        usrsctp_init(atoi(*argv.offset(1 as libc::c_int as isize)) as
                         uint16_t, None,
                     Some(debug_printf_stack as
                              unsafe extern "C" fn(_: *const libc::c_char,
                                                   _: ...) -> ()));
    } else {
        usrsctp_init(9899 as libc::c_int as uint16_t, None,
                     Some(debug_printf_stack as
                              unsafe extern "C" fn(_: *const libc::c_char,
                                                   _: ...) -> ()));
    }
    usrsctp_sysctl_set_sctp_debug_on(0 as libc::c_int as uint32_t);
    usrsctp_sysctl_set_sctp_blackhole(2 as libc::c_int as uint32_t);
    usrsctp_sysctl_set_sctp_no_csum_on_loopback(0 as libc::c_int as uint32_t);
    sock =
        usrsctp_socket(2 as libc::c_int, SOCK_STREAM as libc::c_int,
                       IPPROTO_SCTP as libc::c_int,
                       Some(receive_cb as
                                unsafe extern "C" fn(_: *mut socket,
                                                     _: sctp_sockstore,
                                                     _: *mut libc::c_void,
                                                     _: size_t,
                                                     _: sctp_rcvinfo,
                                                     _: libc::c_int,
                                                     _: *mut libc::c_void)
                                    -> libc::c_int), None,
                       0 as libc::c_int as uint32_t,
                       &mut peer_connection as *mut peer_connection as
                           *mut libc::c_void);
    if sock.is_null() {
        perror(b"socket\x00" as *const u8 as *const libc::c_char);
    }
    init_peer_connection(&mut peer_connection);
    if argc > 2 as libc::c_int {
        memset(&mut encaps as *mut sctp_udpencaps as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong);
        encaps.sue_address.ss_family = 10 as libc::c_int as sa_family_t;
        encaps.sue_port =
            htons(atoi(*argv.offset(2 as libc::c_int as isize)) as uint16_t);
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x24 as libc::c_int,
                              &mut encaps as *mut sctp_udpencaps as
                                  *const libc::c_void,
                              ::std::mem::size_of::<sctp_udpencaps>() as
                                  libc::c_ulong as socklen_t) <
               0 as libc::c_int {
            perror(b"setsockopt\x00" as *const u8 as *const libc::c_char);
        }
    }
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x1f as libc::c_int,
                          &on as *const libc::c_int as *const libc::c_void,
                          ::std::mem::size_of::<libc::c_int>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"setsockopt SCTP_RECVRCVINFO\x00" as *const u8 as
                   *const libc::c_char);
    }
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x1b as libc::c_int,
                          &on as *const libc::c_int as *const libc::c_void,
                          ::std::mem::size_of::<libc::c_int>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"setsockopt SCTP_EXPLICIT_EOR\x00" as *const u8 as
                   *const libc::c_char);
    }
    /* Allow resetting streams. */
    av.assoc_id = 2 as libc::c_int as sctp_assoc_t;
    av.assoc_value = (0x1 as libc::c_int | 0x4 as libc::c_int) as uint32_t;
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x900 as libc::c_int,
                          &mut av as *mut sctp_assoc_value as
                              *const libc::c_void,
                          ::std::mem::size_of::<sctp_assoc_value>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"setsockopt SCTP_ENABLE_STREAM_RESET\x00" as *const u8 as
                   *const libc::c_char);
    }
    /* Enable the events of interest. */
    memset(&mut event as *mut sctp_event as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_event>() as libc::c_ulong);
    event.se_assoc_id = 2 as libc::c_int as sctp_assoc_t;
    event.se_on = 1 as libc::c_int as uint8_t;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) <
              (::std::mem::size_of::<[uint16_t; 8]>() as
                   libc::c_ulong).wrapping_div(::std::mem::size_of::<uint16_t>()
                                                   as libc::c_ulong) {
        event.se_type = event_types[i as usize];
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x1e as libc::c_int,
                              &mut event as *mut sctp_event as
                                  *const libc::c_void,
                              ::std::mem::size_of::<sctp_event>() as
                                  libc::c_ulong as socklen_t) <
               0 as libc::c_int {
            perror(b"setsockopt SCTP_EVENT\x00" as *const u8 as
                       *const libc::c_char);
        }
        i = i.wrapping_add(1)
    }
    memset(&mut initmsg as *mut sctp_initmsg as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_initmsg>() as libc::c_ulong);
    initmsg.sinit_num_ostreams = 5 as libc::c_int as uint16_t;
    initmsg.sinit_max_instreams = 65535 as libc::c_int as uint16_t;
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x3 as libc::c_int,
                          &mut initmsg as *mut sctp_initmsg as
                              *const libc::c_void,
                          ::std::mem::size_of::<sctp_initmsg>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"setsockopt SCTP_INITMSG\x00" as *const u8 as
                   *const libc::c_char);
    }
    if argc == 5 as libc::c_int {
        /* operating as client */
        memset(&mut addr as *mut sockaddr_in as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
        addr.sin_family = 2 as libc::c_int as sa_family_t;
        if inet_pton(2 as libc::c_int,
                     *argv.offset(3 as libc::c_int as isize),
                     &mut addr.sin_addr.s_addr as *mut in_addr_t as
                         *mut libc::c_void) == 0 {
            printf(b"error: invalid address\n\x00" as *const u8 as
                       *const libc::c_char);
            exit(1 as libc::c_int);
        }
        addr.sin_port =
            htons(atoi(*argv.offset(4 as libc::c_int as isize)) as uint16_t);
        if usrsctp_connect(sock,
                           &mut addr as *mut sockaddr_in as *mut sockaddr,
                           ::std::mem::size_of::<sockaddr_in>() as
                               libc::c_ulong as socklen_t) < 0 as libc::c_int
           {
            perror(b"connect\x00" as *const u8 as *const libc::c_char);
        }
        printf(b"Connected to %s:%d.\n\x00" as *const u8 as
                   *const libc::c_char,
               inet_ntop(2 as libc::c_int,
                         &mut addr.sin_addr as *mut in_addr as
                             *const libc::c_void, addrbuf.as_mut_ptr(),
                         16 as libc::c_int as socklen_t),
               ntohs(addr.sin_port) as libc::c_int);
    } else if argc == 4 as libc::c_int {
        let mut conn_sock: *mut socket = 0 as *mut socket;
        /* operating as server */
        memset(&mut addr as *mut sockaddr_in as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
        addr.sin_family = 2 as libc::c_int as sa_family_t;
        addr.sin_addr.s_addr = 0 as libc::c_int as in_addr_t;
        addr.sin_port =
            htons(atoi(*argv.offset(3 as libc::c_int as isize)) as uint16_t);
        if usrsctp_bind(sock, &mut addr as *mut sockaddr_in as *mut sockaddr,
                        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong
                            as socklen_t) < 0 as libc::c_int {
            perror(b"bind\x00" as *const u8 as *const libc::c_char);
        }
        if usrsctp_listen(sock, 1 as libc::c_int) < 0 as libc::c_int {
            perror(b"listen\x00" as *const u8 as *const libc::c_char);
        }
        addr_len =
            ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                socklen_t;
        memset(&mut addr as *mut sockaddr_in as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
        conn_sock =
            usrsctp_accept(sock,
                           &mut addr as *mut sockaddr_in as *mut sockaddr,
                           &mut addr_len);
        if conn_sock.is_null() {
            perror(b"accept\x00" as *const u8 as *const libc::c_char);
        }
        usrsctp_close(sock);
        sock = conn_sock;
        printf(b"Connected to %s:%d.\n\x00" as *const u8 as
                   *const libc::c_char,
               inet_ntop(2 as libc::c_int,
                         &mut addr.sin_addr as *mut in_addr as
                             *const libc::c_void, addrbuf.as_mut_ptr(),
                         16 as libc::c_int as socklen_t),
               ntohs(addr.sin_port) as libc::c_int);
    } else {
        printf(b"Usage: %s local_udp_port remote_udp_port local_port when operating as server\n       %s local_udp_port remote_udp_port remote_addr remote_port when operating as client\n\x00"
                   as *const u8 as *const libc::c_char,
               *argv.offset(0 as libc::c_int as isize),
               *argv.offset(0 as libc::c_int as isize));
        return 0 as libc::c_int
    }
    lock_peer_connection(&mut peer_connection);
    peer_connection.sock = sock;
    unlock_peer_connection(&mut peer_connection);
    loop  {
        if fgets(line.as_mut_ptr(), 1024 as libc::c_int, stdin).is_null() {
            if usrsctp_shutdown(sock, SHUT_WR as libc::c_int) <
                   0 as libc::c_int {
                perror(b"usrsctp_shutdown\x00" as *const u8 as
                           *const libc::c_char);
            }
            while usrsctp_finish() != 0 as libc::c_int {
                sleep(1 as libc::c_int as libc::c_uint);
            }
            break ;
        } else if strncmp(line.as_mut_ptr(),
                          b"?\x00" as *const u8 as *const libc::c_char,
                          strlen(b"?\x00" as *const u8 as
                                     *const libc::c_char)) == 0 as libc::c_int
                      ||
                      strncmp(line.as_mut_ptr(),
                              b"help\x00" as *const u8 as *const libc::c_char,
                              strlen(b"help\x00" as *const u8 as
                                         *const libc::c_char)) ==
                          0 as libc::c_int {
            printf(b"Commands:\nopen unordered pr_policy pr_value - opens a channel\nclose channel - closes the channel\nsend channel:string - sends string using channel\nstatus - prints the status\nsleep n - sleep for n seconds\nhelp - this message\n\x00"
                       as *const u8 as *const libc::c_char);
        } else if strncmp(line.as_mut_ptr(),
                          b"status\x00" as *const u8 as *const libc::c_char,
                          strlen(b"status\x00" as *const u8 as
                                     *const libc::c_char)) == 0 as libc::c_int
         {
            lock_peer_connection(&mut peer_connection);
            print_status(&mut peer_connection);
            unlock_peer_connection(&mut peer_connection);
        } else if strncmp(line.as_mut_ptr(),
                          b"quit\x00" as *const u8 as *const libc::c_char,
                          strlen(b"quit\x00" as *const u8 as
                                     *const libc::c_char)) == 0 as libc::c_int
         {
            if usrsctp_shutdown(sock, SHUT_WR as libc::c_int) <
                   0 as libc::c_int {
                perror(b"usrsctp_shutdown\x00" as *const u8 as
                           *const libc::c_char);
            }
            while usrsctp_finish() != 0 as libc::c_int {
                sleep(1 as libc::c_int as libc::c_uint);
            }
            break ;
        } else if sscanf(line.as_mut_ptr(),
                         b"open %u %u %u\x00" as *const u8 as
                             *const libc::c_char,
                         &mut unordered as *mut libc::c_uint,
                         &mut policy as *mut libc::c_uint,
                         &mut value as *mut libc::c_uint) == 3 as libc::c_int
         {
            lock_peer_connection(&mut peer_connection);
            channel =
                open_channel(&mut peer_connection, unordered as uint8_t,
                             policy as uint16_t, value);
            unlock_peer_connection(&mut peer_connection);
            if channel.is_null() {
                printf(b"Creating channel failed.\n\x00" as *const u8 as
                           *const libc::c_char);
            } else {
                printf(b"Channel with id %u created.\n\x00" as *const u8 as
                           *const libc::c_char, (*channel).id);
            }
        } else if sscanf(line.as_mut_ptr(),
                         b"close %u\x00" as *const u8 as *const libc::c_char,
                         &mut id as *mut libc::c_uint) == 1 as libc::c_int {
            if id < 100 as libc::c_int as libc::c_uint {
                lock_peer_connection(&mut peer_connection);
                close_channel(&mut peer_connection,
                              &mut *peer_connection.channels.as_mut_ptr().offset(id
                                                                                     as
                                                                                     isize));
                unlock_peer_connection(&mut peer_connection);
            }
        } else if sscanf(line.as_mut_ptr(),
                         b"send %u\x00" as *const u8 as *const libc::c_char,
                         &mut id as *mut libc::c_uint) == 1 as libc::c_int {
            if id < 100 as libc::c_int as libc::c_uint {
                let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
                msg =
                    strstr(line.as_mut_ptr(),
                           b":\x00" as *const u8 as *const libc::c_char);
                if !msg.is_null() {
                    msg = msg.offset(1);
                    lock_peer_connection(&mut peer_connection);
                    if send_user_message(&mut peer_connection,
                                         &mut *peer_connection.channels.as_mut_ptr().offset(id
                                                                                                as
                                                                                                isize),
                                         msg,
                                         strlen(msg).wrapping_sub(1 as
                                                                      libc::c_int
                                                                      as
                                                                      libc::c_ulong))
                           != 0 {
                        printf(b"Message sent.\n\x00" as *const u8 as
                                   *const libc::c_char);
                    } else {
                        printf(b"Message sending failed.\n\x00" as *const u8
                                   as *const libc::c_char);
                    }
                    unlock_peer_connection(&mut peer_connection);
                }
            }
        } else if sscanf(line.as_mut_ptr(),
                         b"sleep %u\x00" as *const u8 as *const libc::c_char,
                         &mut seconds as *mut libc::c_uint) ==
                      1 as libc::c_int {
            sleep(seconds);
        } else {
            printf(b"Unknown command: %s\x00" as *const u8 as
                       *const libc::c_char, line.as_mut_ptr());
        }
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
