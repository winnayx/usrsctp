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
    static mut stdout: *mut FILE;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn fileno(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    static in6addr_any: in6_addr;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn inet_pton(__af: libc::c_int, __cp: *const libc::c_char,
                 __buf: *mut libc::c_void) -> libc::c_int;
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
    fn usrsctp_sendv(so: *mut socket, data: *const libc::c_void, len: size_t,
                     to: *mut sockaddr, addrcnt: libc::c_int,
                     info: *mut libc::c_void, infolen: socklen_t,
                     infotype: libc::c_uint, flags: libc::c_int) -> ssize_t;
    #[no_mangle]
    fn usrsctp_bind(so: *mut socket, name: *mut sockaddr, namelen: socklen_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_connect(so: *mut socket, name: *mut sockaddr,
                       namelen: socklen_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_close(so: *mut socket);
    #[no_mangle]
    fn usrsctp_finish() -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_no_csum_on_loopback(value: uint32_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_blackhole(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_debug_on(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    /* I-TSN */
    /* optional param's follow */
    #[no_mangle]
    fn handle_notification(notif: *mut sctp_notification, n: size_t);
    #[no_mangle]
    fn debug_printf_stack(format: *const libc::c_char, _: ...);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
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
pub type ssize_t = __ssize_t;
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
    pub __in6_u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
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
pub type C2RustUnnamed_0 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_0 = 256;
pub const IPPROTO_RAW: C2RustUnnamed_0 = 255;
pub const IPPROTO_MPLS: C2RustUnnamed_0 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_0 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_0 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_0 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_0 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_0 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_0 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_0 = 92;
pub const IPPROTO_AH: C2RustUnnamed_0 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_0 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_0 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_0 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_0 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_0 = 33;
pub const IPPROTO_TP: C2RustUnnamed_0 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_0 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_0 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_0 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_0 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_0 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_0 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_0 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_0 = 1;
pub const IPPROTO_IP: C2RustUnnamed_0 = 0;
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
/* flag that indicates state of data */
/* inqueue never on wire */
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
/* struct sctp_assoc_value */
/* Pluggable Stream Scheduling Socket option */
/*
 * read-only options
 */
/* authentication support */
/*
 * write-only options
 */
/* struct sctp_reset_streams */
/* sctp_assoc_t */
/* struct sctp_add_streams */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_initmsg {
    pub sinit_num_ostreams: uint16_t,
    pub sinit_max_instreams: uint16_t,
    pub sinit_max_attempts: uint16_t,
    pub sinit_max_init_timeo: uint16_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_rtoinfo {
    pub srto_assoc_id: sctp_assoc_t,
    pub srto_initial: uint32_t,
    pub srto_max: uint32_t,
    pub srto_min: uint32_t,
}
#[no_mangle]
pub static mut done: libc::c_int = 0 as libc::c_int;
static mut request_prefix: *const libc::c_char =
    b"GET\x00" as *const u8 as *const libc::c_char;
static mut request_postfix: *const libc::c_char =
    b"HTTP/1.0\r\nUser-agent: libusrsctp\r\nConnection: close\r\n\r\n\x00" as
        *const u8 as *const libc::c_char;
#[no_mangle]
pub static mut request: [libc::c_char; 512] = [0; 512];
unsafe extern "C" fn receive_cb(mut sock: *mut socket,
                                mut addr: sctp_sockstore,
                                mut data: *mut libc::c_void,
                                mut datalen: size_t, mut rcv: sctp_rcvinfo,
                                mut flags: libc::c_int,
                                mut ulp_info: *mut libc::c_void)
 -> libc::c_int {
    if data.is_null() {
        done = 1 as libc::c_int; /* PPID for HTTP/SCTP */
        usrsctp_close(sock);
    } else {
        if flags & 0x2000 as libc::c_int != 0 {
            handle_notification(data as *mut sctp_notification, datalen);
        } else if write(fileno(stdout), data, datalen) <
                      0 as libc::c_int as libc::c_long {
            perror(b"write\x00" as *const u8 as *const libc::c_char);
        }
        free(data);
    }
    return 1 as libc::c_int;
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut current_block: u64;
    let mut sock: *mut socket = 0 as *mut socket;
    let mut addr: *mut sockaddr = 0 as *mut sockaddr;
    let mut addr_len: socklen_t = 0;
    let mut addr4: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut addr6: sockaddr_in6 =
        sockaddr_in6{sin6_family: 0,
                     sin6_port: 0,
                     sin6_flowinfo: 0,
                     sin6_addr:
                         in6_addr{__in6_u:
                                      C2RustUnnamed{__u6_addr8: [0; 16],},},
                     sin6_scope_id: 0,};
    let mut bind4: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut bind6: sockaddr_in6 =
        sockaddr_in6{sin6_family: 0,
                     sin6_port: 0,
                     sin6_flowinfo: 0,
                     sin6_addr:
                         in6_addr{__in6_u:
                                      C2RustUnnamed{__u6_addr8: [0; 16],},},
                     sin6_scope_id: 0,};
    let mut encaps: sctp_udpencaps =
        sctp_udpencaps{sue_address:
                           sockaddr_storage{ss_family: 0,
                                            __ss_padding: [0; 118],
                                            __ss_align: 0,},
                       sue_assoc_id: 0,
                       sue_port: 0,};
    let mut sndinfo: sctp_sndinfo =
        sctp_sndinfo{snd_sid: 0,
                     snd_flags: 0,
                     snd_ppid: 0,
                     snd_context: 0,
                     snd_assoc_id: 0,};
    let mut rtoinfo: sctp_rtoinfo =
        sctp_rtoinfo{srto_assoc_id: 0,
                     srto_initial: 0,
                     srto_max: 0,
                     srto_min: 0,};
    let mut initmsg: sctp_initmsg =
        sctp_initmsg{sinit_num_ostreams: 0,
                     sinit_max_instreams: 0,
                     sinit_max_attempts: 0,
                     sinit_max_init_timeo: 0,};
    let mut event: sctp_event =
        sctp_event{se_assoc_id: 0, se_type: 0, se_on: 0,};
    let mut result: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_uint = 0;
    let mut address_family: uint8_t = 0 as libc::c_int as uint8_t;
    let mut event_types: [uint16_t; 7] =
        [0x1 as libc::c_int as uint16_t, 0x2 as libc::c_int as uint16_t,
         0xe as libc::c_int as uint16_t, 0x3 as libc::c_int as uint16_t,
         0x5 as libc::c_int as uint16_t, 0x6 as libc::c_int as uint16_t,
         0x7 as libc::c_int as uint16_t];
    if argc < 3 as libc::c_int {
        printf(b"Usage: http_client remote_addr remote_port [local_port] [local_encaps_port] [remote_encaps_port] [uri]\n\x00"
                   as *const u8 as *const libc::c_char);
        return 1 as libc::c_int
    }
    memset(&mut addr4 as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    memset(&mut addr6 as *mut sockaddr_in6 as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
    if inet_pton(2 as libc::c_int, *argv.offset(1 as libc::c_int as isize),
                 &mut addr4.sin_addr as *mut in_addr as *mut libc::c_void) ==
           1 as libc::c_int {
        address_family = 2 as libc::c_int as uint8_t;
        addr = &mut addr4 as *mut sockaddr_in as *mut sockaddr;
        addr_len =
            ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                socklen_t;
        addr4.sin_family = 2 as libc::c_int as sa_family_t;
        addr4.sin_port =
            htons(atoi(*argv.offset(2 as libc::c_int as isize)) as uint16_t);
        current_block = 3437258052017859086;
    } else if inet_pton(10 as libc::c_int,
                        *argv.offset(1 as libc::c_int as isize),
                        &mut addr6.sin6_addr as *mut in6_addr as
                            *mut libc::c_void) == 1 as libc::c_int {
        address_family = 10 as libc::c_int as uint8_t;
        addr = &mut addr6 as *mut sockaddr_in6 as *mut sockaddr;
        addr_len =
            ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong as
                socklen_t;
        addr6.sin6_family = 10 as libc::c_int as sa_family_t;
        addr6.sin6_port =
            htons(atoi(*argv.offset(2 as libc::c_int as isize)) as uint16_t);
        current_block = 3437258052017859086;
    } else {
        printf(b"Unsupported destination address - use IPv4 or IPv6 address\n\x00"
                   as *const u8 as *const libc::c_char);
        result = 50 as libc::c_int;
        current_block = 16829189941923093006;
    }
    match current_block {
        3437258052017859086 => {
            if argc > 4 as libc::c_int {
                usrsctp_init(atoi(*argv.offset(4 as libc::c_int as isize)) as
                                 uint16_t, None,
                             Some(debug_printf_stack as
                                      unsafe extern "C" fn(_:
                                                               *const libc::c_char,
                                                           _: ...) -> ()));
            } else {
                usrsctp_init(9899 as libc::c_int as uint16_t, None,
                             Some(debug_printf_stack as
                                      unsafe extern "C" fn(_:
                                                               *const libc::c_char,
                                                           _: ...) -> ()));
            }
            usrsctp_sysctl_set_sctp_debug_on(0xffffffff as libc::c_uint);
            usrsctp_sysctl_set_sctp_blackhole(2 as libc::c_int as uint32_t);
            usrsctp_sysctl_set_sctp_no_csum_on_loopback(0 as libc::c_int as
                                                            uint32_t);
            sock =
                usrsctp_socket(address_family as libc::c_int,
                               SOCK_STREAM as libc::c_int,
                               IPPROTO_SCTP as libc::c_int,
                               Some(receive_cb as
                                        unsafe extern "C" fn(_: *mut socket,
                                                             _:
                                                                 sctp_sockstore,
                                                             _:
                                                                 *mut libc::c_void,
                                                             _: size_t,
                                                             _: sctp_rcvinfo,
                                                             _: libc::c_int,
                                                             _:
                                                                 *mut libc::c_void)
                                            -> libc::c_int), None,
                               0 as libc::c_int as uint32_t,
                               0 as *mut libc::c_void);
            if sock.is_null() {
                perror(b"usrsctp_socket\x00" as *const u8 as
                           *const libc::c_char);
                result = 50 as libc::c_int
            } else {
                memset(&mut event as *mut sctp_event as *mut libc::c_void,
                       0 as libc::c_int,
                       ::std::mem::size_of::<sctp_event>() as libc::c_ulong);
                event.se_assoc_id = 2 as libc::c_int as sctp_assoc_t;
                event.se_on = 1 as libc::c_int as uint8_t;
                i = 0 as libc::c_int as libc::c_uint;
                while (i as libc::c_ulong) <
                          (::std::mem::size_of::<[uint16_t; 7]>() as
                               libc::c_ulong).wrapping_div(::std::mem::size_of::<uint16_t>()
                                                               as
                                                               libc::c_ulong)
                      {
                    event.se_type = event_types[i as usize];
                    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                                          0x1e as libc::c_int,
                                          &mut event as *mut sctp_event as
                                              *const libc::c_void,
                                          ::std::mem::size_of::<sctp_event>()
                                              as libc::c_ulong as socklen_t) <
                           0 as libc::c_int {
                        perror(b"setsockopt SCTP_EVENT\x00" as *const u8 as
                                   *const libc::c_char);
                    }
                    i = i.wrapping_add(1)
                }
                rtoinfo.srto_assoc_id = 0 as libc::c_int as sctp_assoc_t;
                rtoinfo.srto_initial = 1000 as libc::c_int as uint32_t;
                rtoinfo.srto_min = 1000 as libc::c_int as uint32_t;
                rtoinfo.srto_max = 8000 as libc::c_int as uint32_t;
                if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                                      0x1 as libc::c_int,
                                      &mut rtoinfo as *mut sctp_rtoinfo as
                                          *const libc::c_void,
                                      ::std::mem::size_of::<sctp_rtoinfo>() as
                                          libc::c_ulong as socklen_t) <
                       0 as libc::c_int {
                    perror(b"setsockopt\x00" as *const u8 as
                               *const libc::c_char);
                    usrsctp_close(sock);
                    result = 50 as libc::c_int
                } else {
                    initmsg.sinit_num_ostreams = 1 as libc::c_int as uint16_t;
                    initmsg.sinit_max_instreams =
                        1 as libc::c_int as uint16_t;
                    initmsg.sinit_max_attempts = 5 as libc::c_int as uint16_t;
                    initmsg.sinit_max_init_timeo =
                        4000 as libc::c_int as uint16_t;
                    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                                          0x3 as libc::c_int,
                                          &mut initmsg as *mut sctp_initmsg as
                                              *const libc::c_void,
                                          ::std::mem::size_of::<sctp_initmsg>()
                                              as libc::c_ulong as socklen_t) <
                           0 as libc::c_int {
                        perror(b"setsockopt\x00" as *const u8 as
                                   *const libc::c_char);
                        usrsctp_close(sock);
                        result = 50 as libc::c_int
                    } else {
                        if argc > 3 as libc::c_int {
                            if address_family as libc::c_int ==
                                   2 as libc::c_int {
                                memset(&mut bind4 as *mut sockaddr_in as
                                           *mut libc::c_void,
                                       0 as libc::c_int,
                                       ::std::mem::size_of::<sockaddr_in>() as
                                           libc::c_ulong);
                                bind4.sin_family =
                                    2 as libc::c_int as sa_family_t;
                                bind4.sin_port =
                                    htons(atoi(*argv.offset(3 as libc::c_int
                                                                as isize)) as
                                              uint16_t);
                                bind4.sin_addr.s_addr =
                                    htonl(0 as libc::c_int as in_addr_t);
                                if usrsctp_bind(sock,
                                                &mut bind4 as *mut sockaddr_in
                                                    as *mut sockaddr,
                                                ::std::mem::size_of::<sockaddr_in>()
                                                    as libc::c_ulong as
                                                    socklen_t) <
                                       0 as libc::c_int {
                                    perror(b"bind\x00" as *const u8 as
                                               *const libc::c_char);
                                    usrsctp_close(sock);
                                    result = 50 as libc::c_int;
                                    current_block = 16829189941923093006;
                                } else { current_block = 576355610076403033; }
                            } else {
                                memset(&mut bind6 as *mut sockaddr_in6 as
                                           *mut libc::c_void,
                                       0 as libc::c_int,
                                       ::std::mem::size_of::<sockaddr_in6>()
                                           as libc::c_ulong);
                                bind6.sin6_family =
                                    10 as libc::c_int as sa_family_t;
                                bind6.sin6_port =
                                    htons(atoi(*argv.offset(3 as libc::c_int
                                                                as isize)) as
                                              uint16_t);
                                bind6.sin6_addr = in6addr_any;
                                if usrsctp_bind(sock,
                                                &mut bind6 as
                                                    *mut sockaddr_in6 as
                                                    *mut sockaddr,
                                                ::std::mem::size_of::<sockaddr_in6>()
                                                    as libc::c_ulong as
                                                    socklen_t) <
                                       0 as libc::c_int {
                                    perror(b"bind\x00" as *const u8 as
                                               *const libc::c_char);
                                    usrsctp_close(sock);
                                    result = 50 as libc::c_int;
                                    current_block = 16829189941923093006;
                                } else { current_block = 576355610076403033; }
                            }
                        } else { current_block = 576355610076403033; }
                        match current_block {
                            16829189941923093006 => { }
                            _ => {
                                if argc > 5 as libc::c_int {
                                    memset(&mut encaps as *mut sctp_udpencaps
                                               as *mut libc::c_void,
                                           0 as libc::c_int,
                                           ::std::mem::size_of::<sctp_udpencaps>()
                                               as libc::c_ulong);
                                    encaps.sue_address.ss_family =
                                        address_family as sa_family_t;
                                    encaps.sue_port =
                                        htons(atoi(*argv.offset(5 as
                                                                    libc::c_int
                                                                    as isize))
                                                  as uint16_t);
                                    if usrsctp_setsockopt(sock,
                                                          IPPROTO_SCTP as
                                                              libc::c_int,
                                                          0x24 as libc::c_int,
                                                          &mut encaps as
                                                              *mut sctp_udpencaps
                                                              as
                                                              *const libc::c_void,
                                                          ::std::mem::size_of::<sctp_udpencaps>()
                                                              as libc::c_ulong
                                                              as socklen_t) <
                                           0 as libc::c_int {
                                        perror(b"setsockopt\x00" as *const u8
                                                   as *const libc::c_char);
                                        usrsctp_close(sock);
                                        result = 50 as libc::c_int;
                                        current_block = 16829189941923093006;
                                    } else {
                                        current_block = 11869735117417356968;
                                    }
                                } else {
                                    current_block = 11869735117417356968;
                                }
                                match current_block {
                                    16829189941923093006 => { }
                                    _ => {
                                        if argc > 6 as libc::c_int {
                                            snprintf(request.as_mut_ptr(),
                                                     ::std::mem::size_of::<[libc::c_char; 512]>()
                                                         as libc::c_ulong,
                                                     b"%s %s %s\x00" as
                                                         *const u8 as
                                                         *const libc::c_char,
                                                     request_prefix,
                                                     *argv.offset(6 as
                                                                      libc::c_int
                                                                      as
                                                                      isize),
                                                     request_postfix);
                                        } else {
                                            snprintf(request.as_mut_ptr(),
                                                     ::std::mem::size_of::<[libc::c_char; 512]>()
                                                         as libc::c_ulong,
                                                     b"%s %s %s\x00" as
                                                         *const u8 as
                                                         *const libc::c_char,
                                                     request_prefix,
                                                     b"/\x00" as *const u8 as
                                                         *const libc::c_char,
                                                     request_postfix);
                                        }
                                        printf(b"\nHTTP request:\n%s\n\x00" as
                                                   *const u8 as
                                                   *const libc::c_char,
                                               request.as_mut_ptr());
                                        printf(b"\nHTTP response:\n\x00" as
                                                   *const u8 as
                                                   *const libc::c_char);
                                        if usrsctp_connect(sock, addr,
                                                           addr_len) <
                                               0 as libc::c_int {
                                            if *__errno_location() ==
                                                   111 as libc::c_int {
                                                result = 61 as libc::c_int
                                            } else if *__errno_location() ==
                                                          110 as libc::c_int {
                                                result = 60 as libc::c_int
                                            } else {
                                                result = 50 as libc::c_int
                                            }
                                            perror(b"usrsctp_connect\x00" as
                                                       *const u8 as
                                                       *const libc::c_char);
                                            usrsctp_close(sock);
                                        } else {
                                            memset(&mut sndinfo as
                                                       *mut sctp_sndinfo as
                                                       *mut libc::c_void,
                                                   0 as libc::c_int,
                                                   ::std::mem::size_of::<sctp_sndinfo>()
                                                       as libc::c_ulong);
                                            sndinfo.snd_ppid =
                                                htonl(63 as libc::c_int as
                                                          uint32_t);
                                            /* send GET request */
                                            if usrsctp_sendv(sock,
                                                             request.as_mut_ptr()
                                                                 as
                                                                 *const libc::c_void,
                                                             strlen(request.as_mut_ptr()),
                                                             0 as
                                                                 *mut sockaddr,
                                                             0 as libc::c_int,
                                                             &mut sndinfo as
                                                                 *mut sctp_sndinfo
                                                                 as
                                                                 *mut libc::c_void,
                                                             ::std::mem::size_of::<sctp_sndinfo>()
                                                                 as
                                                                 libc::c_ulong
                                                                 as socklen_t,
                                                             1 as libc::c_int
                                                                 as
                                                                 libc::c_uint,
                                                             0 as libc::c_int)
                                                   <
                                                   0 as libc::c_int as
                                                       libc::c_long {
                                                perror(b"usrsctp_sendv\x00" as
                                                           *const u8 as
                                                           *const libc::c_char);
                                                usrsctp_close(sock);
                                                result = 50 as libc::c_int
                                            } else {
                                                while done == 0 {
                                                    sleep(1 as libc::c_int as
                                                              libc::c_uint);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => { }
    }
    while usrsctp_finish() != 0 as libc::c_int {
        sleep(1 as libc::c_int as libc::c_uint);
    }
    printf(b"Finished, returning with %d\n\x00" as *const u8 as
               *const libc::c_char, result);
    return result;
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
