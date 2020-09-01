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
    static mut stdin: *mut FILE;
    #[no_mangle]
    static mut stdout: *mut FILE;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn fgets(__s: *mut libc::c_char, __n: libc::c_int, __stream: *mut FILE)
     -> *mut libc::c_char;
    #[no_mangle]
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn fileno(__stream: *mut FILE) -> libc::c_int;
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
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    static in6addr_any: in6_addr;
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
    fn usrsctp_getpaddrs(so: *mut socket, id: sctp_assoc_t,
                         raddrs: *mut *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_freepaddrs(addrs: *mut sockaddr);
    #[no_mangle]
    fn usrsctp_getladdrs(so: *mut socket, id: sctp_assoc_t,
                         raddrs: *mut *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_freeladdrs(addrs: *mut sockaddr);
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
    fn usrsctp_shutdown(so: *mut socket, how: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_no_csum_on_loopback(value: uint32_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_blackhole(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_debug_on(value: uint32_t) -> libc::c_int;
    /* Future ABI compat - remove int's from here when adding new */
    #[no_mangle]
    fn usrsctp_get_stat(_: *mut sctpstat);
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
pub type __caddr_t = *mut libc::c_char;
pub type __socklen_t = libc::c_uint;

#[repr(C)]#[derive(Copy, Clone)]
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
pub type caddr_t = __caddr_t;
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

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
pub type C2RustUnnamed_0 = libc::c_uint;
pub const SHUT_RDWR: C2RustUnnamed_0 = 2;
pub const SHUT_WR: C2RustUnnamed_0 = 1;
pub const SHUT_RD: C2RustUnnamed_0 = 0;

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
pub type uint32_t = __uint32_t;

#[repr(C)]#[derive(Copy, Clone)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_1,
}

#[repr(C)]#[derive(Copy, Clone)]
pub union C2RustUnnamed_1 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
pub type in_port_t = uint16_t;

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_2 = 256;
pub const IPPROTO_RAW: C2RustUnnamed_2 = 255;
pub const IPPROTO_MPLS: C2RustUnnamed_2 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_2 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_2 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_2 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_2 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_2 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_2 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_2 = 92;
pub const IPPROTO_AH: C2RustUnnamed_2 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_2 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_2 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_2 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_2 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_2 = 33;
pub const IPPROTO_TP: C2RustUnnamed_2 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_2 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_2 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_2 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_2 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_2 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_2 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_2 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_2 = 1;
pub const IPPROTO_IP: C2RustUnnamed_2 = 0;
pub type sctp_assoc_t = uint32_t;
/* The definition of struct sockaddr_conn MUST be in
 * tune with other sockaddr_* structures.
 */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_conn {
    pub sconn_family: uint16_t,
    pub sconn_port: uint16_t,
    pub sconn_addr: *mut libc::c_void,
}

#[repr(C)]#[derive(Copy, Clone)]
pub union sctp_sockstore {
    pub sin: sockaddr_in,
    pub sin6: sockaddr_in6,
    pub sconn: sockaddr_conn,
    pub sa: sockaddr,
}
/* **  Structures and definitions to use the socket API  ***/

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_sndinfo {
    pub snd_sid: uint16_t,
    pub snd_flags: uint16_t,
    pub snd_ppid: uint32_t,
    pub snd_context: uint32_t,
    pub snd_assoc_id: sctp_assoc_t,
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_udpencaps {
    pub sue_address: sockaddr_storage,
    pub sue_assoc_id: uint32_t,
    pub sue_port: uint16_t,
}
/* notification event structures */
/* association change event */

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_remote_error {
    pub sre_type: uint16_t,
    pub sre_flags: uint16_t,
    pub sre_length: uint32_t,
    pub sre_error: uint16_t,
    pub sre_assoc_id: sctp_assoc_t,
    pub sre_data: [uint8_t; 0],
}
/* shutdown event */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_shutdown_event {
    pub sse_type: uint16_t,
    pub sse_flags: uint16_t,
    pub sse_length: uint32_t,
    pub sse_assoc_id: sctp_assoc_t,
}
/* Adaptation layer indication */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_adaptation_event {
    pub sai_type: uint16_t,
    pub sai_flags: uint16_t,
    pub sai_length: uint32_t,
    pub sai_adaptation_ind: uint32_t,
    pub sai_assoc_id: sctp_assoc_t,
}
/* Partial delivery event */

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_sender_dry_event {
    pub sender_dry_type: uint16_t,
    pub sender_dry_flags: uint16_t,
    pub sender_dry_length: uint32_t,
    pub sender_dry_assoc_id: sctp_assoc_t,
}
/* Stream reset event - subscribe to SCTP_STREAM_RESET_EVENT */

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_assoc_reset_event {
    pub assocreset_type: uint16_t,
    pub assocreset_flags: uint16_t,
    pub assocreset_length: uint32_t,
    pub assocreset_assoc_id: sctp_assoc_t,
    pub assocreset_local_tsn: uint32_t,
    pub assocreset_remote_tsn: uint32_t,
}
/* Stream change event - subscribe to SCTP_STREAM_CHANGE_EVENT */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_stream_change_event {
    pub strchange_type: uint16_t,
    pub strchange_flags: uint16_t,
    pub strchange_length: uint32_t,
    pub strchange_assoc_id: sctp_assoc_t,
    pub strchange_instrms: uint16_t,
    pub strchange_outstrms: uint16_t,
}
/* SCTP send failed event */

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_event {
    pub se_assoc_id: sctp_assoc_t,
    pub se_type: uint16_t,
    pub se_on: uint8_t,
}

#[repr(C)]#[derive(Copy, Clone)]
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

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_tlv {
    pub sn_type: uint16_t,
    pub sn_flags: uint16_t,
    pub sn_length: uint32_t,
}
/* More specific values can be found in sctp_constants, but
 * are not considered to be part of the API.
 */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_timeval {
    pub tv_sec: uint32_t,
    pub tv_usec: uint32_t,
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctpstat {
    pub sctps_discontinuitytime: sctp_timeval,
    pub sctps_currestab: uint32_t,
    pub sctps_activeestab: uint32_t,
    pub sctps_restartestab: uint32_t,
    pub sctps_collisionestab: uint32_t,
    pub sctps_passiveestab: uint32_t,
    pub sctps_aborted: uint32_t,
    pub sctps_shutdown: uint32_t,
    pub sctps_outoftheblue: uint32_t,
    pub sctps_checksumerrors: uint32_t,
    pub sctps_outcontrolchunks: uint32_t,
    pub sctps_outorderchunks: uint32_t,
    pub sctps_outunorderchunks: uint32_t,
    pub sctps_incontrolchunks: uint32_t,
    pub sctps_inorderchunks: uint32_t,
    pub sctps_inunorderchunks: uint32_t,
    pub sctps_fragusrmsgs: uint32_t,
    pub sctps_reasmusrmsgs: uint32_t,
    pub sctps_outpackets: uint32_t,
    pub sctps_inpackets: uint32_t,
    pub sctps_recvpackets: uint32_t,
    pub sctps_recvdatagrams: uint32_t,
    pub sctps_recvpktwithdata: uint32_t,
    pub sctps_recvsacks: uint32_t,
    pub sctps_recvdata: uint32_t,
    pub sctps_recvdupdata: uint32_t,
    pub sctps_recvheartbeat: uint32_t,
    pub sctps_recvheartbeatack: uint32_t,
    pub sctps_recvecne: uint32_t,
    pub sctps_recvauth: uint32_t,
    pub sctps_recvauthmissing: uint32_t,
    pub sctps_recvivalhmacid: uint32_t,
    pub sctps_recvivalkeyid: uint32_t,
    pub sctps_recvauthfailed: uint32_t,
    pub sctps_recvexpress: uint32_t,
    pub sctps_recvexpressm: uint32_t,
    pub sctps_recv_spare: uint32_t,
    pub sctps_recvswcrc: uint32_t,
    pub sctps_recvhwcrc: uint32_t,
    pub sctps_sendpackets: uint32_t,
    pub sctps_sendsacks: uint32_t,
    pub sctps_senddata: uint32_t,
    pub sctps_sendretransdata: uint32_t,
    pub sctps_sendfastretrans: uint32_t,
    pub sctps_sendmultfastretrans: uint32_t,
    pub sctps_sendheartbeat: uint32_t,
    pub sctps_sendecne: uint32_t,
    pub sctps_sendauth: uint32_t,
    pub sctps_senderrors: uint32_t,
    pub sctps_send_spare: uint32_t,
    pub sctps_sendswcrc: uint32_t,
    pub sctps_sendhwcrc: uint32_t,
    pub sctps_pdrpfmbox: uint32_t,
    pub sctps_pdrpfehos: uint32_t,
    pub sctps_pdrpmbda: uint32_t,
    pub sctps_pdrpmbct: uint32_t,
    pub sctps_pdrpbwrpt: uint32_t,
    pub sctps_pdrpcrupt: uint32_t,
    pub sctps_pdrpnedat: uint32_t,
    pub sctps_pdrppdbrk: uint32_t,
    pub sctps_pdrptsnnf: uint32_t,
    pub sctps_pdrpdnfnd: uint32_t,
    pub sctps_pdrpdiwnp: uint32_t,
    pub sctps_pdrpdizrw: uint32_t,
    pub sctps_pdrpbadd: uint32_t,
    pub sctps_pdrpmark: uint32_t,
    pub sctps_timoiterator: uint32_t,
    pub sctps_timodata: uint32_t,
    pub sctps_timowindowprobe: uint32_t,
    pub sctps_timoinit: uint32_t,
    pub sctps_timosack: uint32_t,
    pub sctps_timoshutdown: uint32_t,
    pub sctps_timoheartbeat: uint32_t,
    pub sctps_timocookie: uint32_t,
    pub sctps_timosecret: uint32_t,
    pub sctps_timopathmtu: uint32_t,
    pub sctps_timoshutdownack: uint32_t,
    pub sctps_timoshutdownguard: uint32_t,
    pub sctps_timostrmrst: uint32_t,
    pub sctps_timoearlyfr: uint32_t,
    pub sctps_timoasconf: uint32_t,
    pub sctps_timodelprim: uint32_t,
    pub sctps_timoautoclose: uint32_t,
    pub sctps_timoassockill: uint32_t,
    pub sctps_timoinpkill: uint32_t,
    pub sctps_spare: [uint32_t; 11],
    pub sctps_hdrops: uint32_t,
    pub sctps_badsum: uint32_t,
    pub sctps_noport: uint32_t,
    pub sctps_badvtag: uint32_t,
    pub sctps_badsid: uint32_t,
    pub sctps_nomem: uint32_t,
    pub sctps_fastretransinrtt: uint32_t,
    pub sctps_markedretrans: uint32_t,
    pub sctps_naglesent: uint32_t,
    pub sctps_naglequeued: uint32_t,
    pub sctps_maxburstqueued: uint32_t,
    pub sctps_ifnomemqueued: uint32_t,
    pub sctps_windowprobed: uint32_t,
    pub sctps_lowlevelerr: uint32_t,
    pub sctps_lowlevelerrusr: uint32_t,
    pub sctps_datadropchklmt: uint32_t,
    pub sctps_datadroprwnd: uint32_t,
    pub sctps_ecnereducedcwnd: uint32_t,
    pub sctps_vtagexpress: uint32_t,
    pub sctps_vtagbogus: uint32_t,
    pub sctps_primary_randry: uint32_t,
    pub sctps_cmt_randry: uint32_t,
    pub sctps_slowpath_sack: uint32_t,
    pub sctps_wu_sacks_sent: uint32_t,
    pub sctps_sends_with_flags: uint32_t,
    pub sctps_sends_with_unord: uint32_t,
    pub sctps_sends_with_eof: uint32_t,
    pub sctps_sends_with_abort: uint32_t,
    pub sctps_protocol_drain_calls: uint32_t,
    pub sctps_protocol_drains_done: uint32_t,
    pub sctps_read_peeks: uint32_t,
    pub sctps_cached_chk: uint32_t,
    pub sctps_cached_strmoq: uint32_t,
    pub sctps_left_abandon: uint32_t,
    pub sctps_send_burst_avoid: uint32_t,
    pub sctps_send_cwnd_avoid: uint32_t,
    pub sctps_fwdtsn_map_over: uint32_t,
    pub sctps_queue_upd_ecne: uint32_t,
    pub sctps_reserved: [uint32_t; 31],
}
/*
 * Copyright (C) 2011-2013 Michael Tuexen
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Usage: client remote_addr remote_port [local_port] [local_encaps_port] [remote_encaps_port]
 */
#[no_mangle]
pub static mut adone: libc::c_int = 0i32;
unsafe extern "C" fn receive_cb(mut sock: *mut socket,
                                mut addr: sctp_sockstore,
                                mut data: *mut libc::c_void,
                                mut datalen: size_t, mut rcv: sctp_rcvinfo,
                                mut flags: libc::c_int,
                                mut ulp_info: *mut libc::c_void)
 -> libc::c_int {
    if data.is_null() {
        adone = 1i32;
        usrsctp_close(sock);
    } else {
        if flags & 0x2000i32 != 0 {
            handle_notification(data as *mut sctp_notification, datalen);
        } else if write(fileno(stdout), data, datalen) <
                      0i64 {
            perror(b"write\x00" as *const u8 as *const libc::c_char);
        }
        free(data);
    }
    return 1i32;
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    
    
    
    
    
    
    
    
    
    
    
                       let mut addr =    0 as *mut sockaddr; let mut addrs =    0 as *mut sockaddr; let mut addr4 =
    
    
    
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],}; let mut addr6 =
    
    
    
        sockaddr_in6{sin6_family: 0,
                     sin6_port: 0,
                     sin6_flowinfo: 0,
                     sin6_addr:
                         in6_addr{__in6_u:
                                      C2RustUnnamed_1{__u6_addr8:  [0; 16],},},
                     sin6_scope_id: 0,}; let mut stat =
    
    
    
        sctpstat{sctps_discontinuitytime:
                     sctp_timeval{tv_sec: 0, tv_usec: 0,},
                 sctps_currestab: 0,
                 sctps_activeestab: 0,
                 sctps_restartestab: 0,
                 sctps_collisionestab: 0,
                 sctps_passiveestab: 0,
                 sctps_aborted: 0,
                 sctps_shutdown: 0,
                 sctps_outoftheblue: 0,
                 sctps_checksumerrors: 0,
                 sctps_outcontrolchunks: 0,
                 sctps_outorderchunks: 0,
                 sctps_outunorderchunks: 0,
                 sctps_incontrolchunks: 0,
                 sctps_inorderchunks: 0,
                 sctps_inunorderchunks: 0,
                 sctps_fragusrmsgs: 0,
                 sctps_reasmusrmsgs: 0,
                 sctps_outpackets: 0,
                 sctps_inpackets: 0,
                 sctps_recvpackets: 0,
                 sctps_recvdatagrams: 0,
                 sctps_recvpktwithdata: 0,
                 sctps_recvsacks: 0,
                 sctps_recvdata: 0,
                 sctps_recvdupdata: 0,
                 sctps_recvheartbeat: 0,
                 sctps_recvheartbeatack: 0,
                 sctps_recvecne: 0,
                 sctps_recvauth: 0,
                 sctps_recvauthmissing: 0,
                 sctps_recvivalhmacid: 0,
                 sctps_recvivalkeyid: 0,
                 sctps_recvauthfailed: 0,
                 sctps_recvexpress: 0,
                 sctps_recvexpressm: 0,
                 sctps_recv_spare: 0,
                 sctps_recvswcrc: 0,
                 sctps_recvhwcrc: 0,
                 sctps_sendpackets: 0,
                 sctps_sendsacks: 0,
                 sctps_senddata: 0,
                 sctps_sendretransdata: 0,
                 sctps_sendfastretrans: 0,
                 sctps_sendmultfastretrans: 0,
                 sctps_sendheartbeat: 0,
                 sctps_sendecne: 0,
                 sctps_sendauth: 0,
                 sctps_senderrors: 0,
                 sctps_send_spare: 0,
                 sctps_sendswcrc: 0,
                 sctps_sendhwcrc: 0,
                 sctps_pdrpfmbox: 0,
                 sctps_pdrpfehos: 0,
                 sctps_pdrpmbda: 0,
                 sctps_pdrpmbct: 0,
                 sctps_pdrpbwrpt: 0,
                 sctps_pdrpcrupt: 0,
                 sctps_pdrpnedat: 0,
                 sctps_pdrppdbrk: 0,
                 sctps_pdrptsnnf: 0,
                 sctps_pdrpdnfnd: 0,
                 sctps_pdrpdiwnp: 0,
                 sctps_pdrpdizrw: 0,
                 sctps_pdrpbadd: 0,
                 sctps_pdrpmark: 0,
                 sctps_timoiterator: 0,
                 sctps_timodata: 0,
                 sctps_timowindowprobe: 0,
                 sctps_timoinit: 0,
                 sctps_timosack: 0,
                 sctps_timoshutdown: 0,
                 sctps_timoheartbeat: 0,
                 sctps_timocookie: 0,
                 sctps_timosecret: 0,
                 sctps_timopathmtu: 0,
                 sctps_timoshutdownack: 0,
                 sctps_timoshutdownguard: 0,
                 sctps_timostrmrst: 0,
                 sctps_timoearlyfr: 0,
                 sctps_timoasconf: 0,
                 sctps_timodelprim: 0,
                 sctps_timoautoclose: 0,
                 sctps_timoassockill: 0,
                 sctps_timoinpkill: 0,
                 sctps_spare: [0; 11],
                 sctps_hdrops: 0,
                 sctps_badsum: 0,
                 sctps_noport: 0,
                 sctps_badvtag: 0,
                 sctps_badsid: 0,
                 sctps_nomem: 0,
                 sctps_fastretransinrtt: 0,
                 sctps_markedretrans: 0,
                 sctps_naglesent: 0,
                 sctps_naglequeued: 0,
                 sctps_maxburstqueued: 0,
                 sctps_ifnomemqueued: 0,
                 sctps_windowprobed: 0,
                 sctps_lowlevelerr: 0,
                 sctps_lowlevelerrusr: 0,
                 sctps_datadropchklmt: 0,
                 sctps_datadroprwnd: 0,
                 sctps_ecnereducedcwnd: 0,
                 sctps_vtagexpress: 0,
                 sctps_vtagbogus: 0,
                 sctps_primary_randry: 0,
                 sctps_cmt_randry: 0,
                 sctps_slowpath_sack: 0,
                 sctps_wu_sacks_sent: 0,
                 sctps_sends_with_flags: 0,
                 sctps_sends_with_unord: 0,
                 sctps_sends_with_eof: 0,
                 sctps_sends_with_abort: 0,
                 sctps_protocol_drain_calls: 0,
                 sctps_protocol_drains_done: 0,
                 sctps_read_peeks: 0,
                 sctps_cached_chk: 0,
                 sctps_cached_strmoq: 0,
                 sctps_left_abandon: 0,
                 sctps_send_burst_avoid: 0,
                 sctps_send_cwnd_avoid: 0,
                 sctps_fwdtsn_map_over: 0,
                 sctps_queue_upd_ecne: 0,
                 sctps_reserved: [0; 31],}; let mut event =   
        sctp_event{se_assoc_id: 0, se_type: 0, se_on: 0,}; let mut buffer =    [0; 80]; let mut i =    0u32;  
    if argc < 3i32 {
        printf(b"%s\x00" as *const u8 as *const libc::c_char,
               b"Usage: client remote_addr remote_port local_port local_encaps_port remote_encaps_port\n\x00"
                   as *const u8 as *const libc::c_char);
        return -(1i32)
    }
    if argc > 4i32 {
        usrsctp_init(atoi(*argv.offset(4isize)) as
                         uint16_t, None,
                     Some(debug_printf_stack as
                              unsafe extern "C" fn(_: *const libc::c_char,
                                                   _: ...) -> ()));
    } else {
        usrsctp_init(9899u16, None,
                     Some(debug_printf_stack as
                              unsafe extern "C" fn(_: *const libc::c_char,
                                                   _: ...) -> ()));
    }
    usrsctp_sysctl_set_sctp_debug_on(0u32);
    usrsctp_sysctl_set_sctp_blackhole(2u32);
    usrsctp_sysctl_set_sctp_no_csum_on_loopback(0u32);
     let mut sock =
    
        usrsctp_socket(10i32, SOCK_STREAM as libc::c_int,
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
                       0u32, 0 as *mut libc::c_void);
    if sock.is_null() {
        perror(b"usrsctp_socket\x00" as *const u8 as *const libc::c_char);
    }
    memset(&mut event as *mut sctp_event as *mut libc::c_void,
           0i32,
           ::std::mem::size_of::<sctp_event>() as libc::c_ulong);
    
    
    
     
    event = crate::client::sctp_event{se_assoc_id:   2u32, se_on:   1u8, ..
    event};
     
    while (i as libc::c_ulong) <
              (::std::mem::size_of::<[uint16_t; 3]>() as
                   libc::c_ulong).wrapping_div(::std::mem::size_of::<uint16_t>()
                                                   as libc::c_ulong) {
        
         
          let mut event_types =  
    
        [0x1u16, 0x2u16,
         0xeu16];event = crate::client::sctp_event{se_type:   event_types[i as usize], ..
        event};
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x1ei32,
                              &mut event as *mut sctp_event as
                                  *const libc::c_void,
                              
                              ::std::mem::size_of::<sctp_event>() as socklen_t) <
               0i32 {
            perror(b"setsockopt SCTP_EVENT\x00" as *const u8 as
                       *const libc::c_char);
        }
        i = i.wrapping_add(1)
    }
    if argc > 3i32 {
        memset(&mut addr6 as *mut sockaddr_in6 as *mut libc::c_void,
               0i32,
               ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
        
        
        
        
        
         
        addr6 =
    crate::client::sockaddr_in6{sin6_family:   10u16,
                                sin6_port:
                                    
                                
            htons(atoi(*argv.offset(3isize)) as uint16_t),
                                sin6_addr:   in6addr_any, ..
        addr6};
        if usrsctp_bind(sock,
                        &mut addr6 as *mut sockaddr_in6 as *mut sockaddr,
                        
                        ::std::mem::size_of::<sockaddr_in6>()
                            as socklen_t) < 0i32 {
            perror(b"bind\x00" as *const u8 as *const libc::c_char);
        }
    }
    if argc > 5i32 {
          let mut encaps =
    
    
    
        sctp_udpencaps{sue_address:
                           sockaddr_storage{ss_family: 0,
                                            __ss_padding: [0; 118],
                                            __ss_align: 0,},
                       sue_assoc_id: 0,
                       sue_port: 0,};memset(&mut encaps as *mut sctp_udpencaps as *mut libc::c_void,
               0i32,
               ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong);
        
        
        
         
        encaps.sue_address =
    crate::client::sockaddr_storage{ss_family:   10u16, ..
        encaps.sue_address}; 
        encaps =
    crate::client::sctp_udpencaps{sue_port:
                                      
                                  
            htons(atoi(*argv.offset(5isize)) as uint16_t), ..
        encaps};
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x24i32,
                              &mut encaps as *mut sctp_udpencaps as
                                  *const libc::c_void,
                              
                              ::std::mem::size_of::<sctp_udpencaps>() as socklen_t) <
               0i32 {
            perror(b"setsockopt\x00" as *const u8 as *const libc::c_char);
        }
    }
    memset(&mut addr4 as *mut sockaddr_in as *mut libc::c_void,
           0i32,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    memset(&mut addr6 as *mut sockaddr_in6 as *mut libc::c_void,
           0i32,
           ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
    
    
    
    
    
    
    
     
    addr4 = crate::client::sockaddr_in{sin_family:   2u16, ..
    addr4}; 
    addr6 = crate::client::sockaddr_in6{sin6_family:   10u16, ..
    addr6}; 
    addr4 =
    crate::client::sockaddr_in{sin_port:
                                   
                               
        htons(atoi(*argv.offset(2isize)) as uint16_t), ..
    addr4}; 
    addr6 =
    crate::client::sockaddr_in6{sin6_port:
                                    
                                
        htons(atoi(*argv.offset(2isize)) as uint16_t), ..
    addr6};
    if inet_pton(10i32, *argv.offset(1isize),
                 &mut addr6.sin6_addr as *mut in6_addr as *mut libc::c_void)
           == 1i32 {
        if usrsctp_connect(sock,
                           &mut addr6 as *mut sockaddr_in6 as *mut sockaddr,
                           
                           ::std::mem::size_of::<sockaddr_in6>() as socklen_t) < 0i32
           {
            perror(b"usrsctp_connect\x00" as *const u8 as
                       *const libc::c_char);
        }
    } else if inet_pton(2i32,
                        *argv.offset(1isize),
                        &mut addr4.sin_addr as *mut in_addr as
                            *mut libc::c_void) == 1i32 {
        if usrsctp_connect(sock,
                           &mut addr4 as *mut sockaddr_in as *mut sockaddr,
                           
                           ::std::mem::size_of::<sockaddr_in>() as socklen_t) < 0i32
           {
            perror(b"usrsctp_connect\x00" as *const u8 as
                       *const libc::c_char);
        }
    } else {
        printf(b"Illegal destination address.\n\x00" as *const u8 as
                   *const libc::c_char);
    }
     let mut n =  usrsctp_getladdrs(sock, 0u32, &mut addrs);
    if n < 0i32 {
        perror(b"usrsctp_getladdrs\x00" as *const u8 as *const libc::c_char);
    } else {
        addr = addrs;
        printf(b"Local addresses: \x00" as *const u8 as *const libc::c_char);
        i = 0u32;
        while i < n as libc::c_uint {
            if i > 0u32 {
                printf(b"%s\x00" as *const u8 as *const libc::c_char,
                       b", \x00" as *const u8 as *const libc::c_char);
            }
            match (*addr).sa_family as libc::c_int {
                2 => {
                    
                    
                        let mut buf =    [0; 16]; 
                    
                     let mut sin =  addr as *mut sockaddr_in; let mut name =
    
                        inet_ntop(2i32,
                                  &mut (*sin).sin_addr as *mut in_addr as
                                      *const libc::c_void, buf.as_mut_ptr(),
                                  16u32);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in>() as isize) as
                            *mut sockaddr
                }
                10 => {
                    
                    
                        let mut buf_0 =    [0; 46]; 
                    
                     let mut sin6 =  addr as *mut sockaddr_in6; let mut name_0 =
    
                        inet_ntop(10i32,
                                  &mut (*sin6).sin6_addr as *mut in6_addr as
                                      *const libc::c_void, buf_0.as_mut_ptr(),
                                  46u32);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name_0);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in6>() as isize) as
                            *mut sockaddr
                }
                _ => { }
            }
            i = i.wrapping_add(1)
        }
        printf(b".\n\x00" as *const u8 as *const libc::c_char);
        usrsctp_freeladdrs(addrs);
    }
    n = usrsctp_getpaddrs(sock, 0u32, &mut addrs);
    if n < 0i32 {
        perror(b"usrsctp_getpaddrs\x00" as *const u8 as *const libc::c_char);
    } else {
        addr = addrs;
        printf(b"Peer addresses: \x00" as *const u8 as *const libc::c_char);
        i = 0u32;
        while i < n as libc::c_uint {
            if i > 0u32 {
                printf(b"%s\x00" as *const u8 as *const libc::c_char,
                       b", \x00" as *const u8 as *const libc::c_char);
            }
            match (*addr).sa_family as libc::c_int {
                2 => {
                    
                    
                        let mut buf_1 =    [0; 16]; 
                    
                     let mut sin_0 =  addr as *mut sockaddr_in; let mut name_1 =
    
                        inet_ntop(2i32,
                                  &mut (*sin_0).sin_addr as *mut in_addr as
                                      *const libc::c_void, buf_1.as_mut_ptr(),
                                  16u32);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name_1);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in>() as isize) as
                            *mut sockaddr
                }
                10 => {
                    
                    
                        let mut buf_2 =    [0; 46]; 
                    
                     let mut sin6_0 =  addr as *mut sockaddr_in6; let mut name_2 =
    
                        inet_ntop(10i32,
                                  &mut (*sin6_0).sin6_addr as *mut in6_addr as
                                      *const libc::c_void, buf_2.as_mut_ptr(),
                                  46u32);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name_2);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in6>() as isize) as
                            *mut sockaddr
                }
                _ => { }
            }
            i = i.wrapping_add(1)
        }
        printf(b".\n\x00" as *const u8 as *const libc::c_char);
        usrsctp_freepaddrs(addrs);
    }
    while !fgets(buffer.as_mut_ptr(),
                 
                 ::std::mem::size_of::<[libc::c_char; 80]>()
                     as libc::c_int, stdin).is_null() && adone == 0 {
        usrsctp_sendv(sock, buffer.as_mut_ptr() as *const libc::c_void,
                      strlen(buffer.as_mut_ptr()), 0 as *mut sockaddr,
                      0i32, 0 as *mut libc::c_void,
                      0u32,
                      0u32, 0i32);
    }
    if adone == 0 {
        if usrsctp_shutdown(sock, SHUT_WR as libc::c_int) < 0i32 {
            perror(b"usrsctp_shutdown\x00" as *const u8 as
                       *const libc::c_char);
        }
    }
    while adone == 0 { sleep(1u32); }
    usrsctp_get_stat(&mut stat);
    printf(b"Number of packets (sent/received): (%u/%u).\n\x00" as *const u8
               as *const libc::c_char, stat.sctps_outpackets,
           stat.sctps_inpackets);
    while usrsctp_finish() != 0i32 {
        sleep(1u32);
    }
    return 0i32;
}
#[main]
pub fn main() {
       let mut args =    Vec::new();
    for arg in ::std::env::args() {
        args.push(::std::ffi::CString::new(arg).expect("Failed to convert argument into CString.").into_raw());
    };
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0((args.len() - 1) as libc::c_int,
                                    
                                    args.as_mut_ptr()))
    }
}
