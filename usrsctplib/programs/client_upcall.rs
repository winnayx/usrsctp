use ::libc;
use ::c2rust_asm_casts;
use c2rust_asm_casts::AsmCastTrait;
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
    fn fileno(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn fgets(__s: *mut libc::c_char, __n: libc::c_int, __stream: *mut FILE)
     -> *mut libc::c_char;
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn select(__nfds: libc::c_int, __readfds: *mut fd_set,
              __writefds: *mut fd_set, __exceptfds: *mut fd_set,
              __timeout: *mut timeval) -> libc::c_int;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
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
    fn usrsctp_recvv(so: *mut socket, dbuf: *mut libc::c_void, len: size_t,
                     from: *mut sockaddr, fromlen: *mut socklen_t,
                     info: *mut libc::c_void, infolen: *mut socklen_t,
                     infotype: *mut libc::c_uint, msg_flags: *mut libc::c_int)
     -> ssize_t;
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
    fn usrsctp_sysctl_set_sctp_blackhole(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_debug_on(value: uint32_t) -> libc::c_int;
    /* Future ABI compat - remove int's from here when adding new */
    #[no_mangle]
    fn usrsctp_get_stat(_: *mut sctpstat);
    #[no_mangle]
    fn debug_printf_stack(format: *const libc::c_char, _: ...);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __caddr_t = *mut libc::c_char;
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
pub type caddr_t = __caddr_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
pub type __fd_mask = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fd_set {
    pub fds_bits: [__fd_mask; 16],
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
/*-
 * Copyright (c) 2009-2010 Brad Penoff
 * Copyright (c) 2009-2010 Humaira Kamal
 * Copyright (c) 2011-2012 Irene Ruengeler
 * Copyright (c) 2011-2012 Michael Tuexen
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* This definition MUST be in sync with usrsctplib/user_socketvar.h */
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
pub struct sctp_udpencaps {
    pub sue_address: sockaddr_storage,
    pub sue_assoc_id: uint32_t,
    pub sue_port: uint16_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_timeval {
    pub tv_sec: uint32_t,
    pub tv_usec: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
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
#[no_mangle]
pub static mut dddone: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut input_done: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut connected: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn inputAvailable() -> libc::c_int {
    let mut tv: timeval = timeval{tv_sec: 0, tv_usec: 0,};
    let mut fds: fd_set = fd_set{fds_bits: [0; 16],};
    tv.tv_sec = 0 as libc::c_int as __time_t;
    tv.tv_usec = 0 as libc::c_int as __suseconds_t;
    let mut __d0: libc::c_int = 0;
    let mut __d1: libc::c_int = 0;
    let fresh0 = &mut __d0;
    let fresh1;
    let fresh2 = &mut __d1;
    let fresh3;
    let fresh4 =
        (::std::mem::size_of::<fd_set>() as
             libc::c_ulong).wrapping_div(::std::mem::size_of::<__fd_mask>() as
                                             libc::c_ulong);
    let fresh5 =
        &mut *fds.fds_bits.as_mut_ptr().offset(0 as libc::c_int as isize) as
            *mut __fd_mask;
    asm!("cld; rep; stosq" : "={cx}" (fresh1), "={di}" (fresh3) : "{ax}"
         (0 as libc::c_int), "0"
         (c2rust_asm_casts::AsmCast::cast_in(fresh0, fresh4)), "1"
         (c2rust_asm_casts::AsmCast::cast_in(fresh2, fresh5)) : "memory" :
         "volatile");
    c2rust_asm_casts::AsmCast::cast_out(fresh0, fresh4, fresh1);
    c2rust_asm_casts::AsmCast::cast_out(fresh2, fresh5, fresh3);
    fds.fds_bits[(0 as libc::c_int /
                      (8 as libc::c_int *
                           ::std::mem::size_of::<__fd_mask>() as libc::c_ulong
                               as libc::c_int)) as usize] |=
        ((1 as libc::c_ulong) <<
             0 as libc::c_int %
                 (8 as libc::c_int *
                      ::std::mem::size_of::<__fd_mask>() as libc::c_ulong as
                          libc::c_int)) as __fd_mask;
    select(0 as libc::c_int + 1 as libc::c_int, &mut fds, 0 as *mut fd_set,
           0 as *mut fd_set, &mut tv);
    return (fds.fds_bits[(0 as libc::c_int /
                              (8 as libc::c_int *
                                   ::std::mem::size_of::<__fd_mask>() as
                                       libc::c_ulong as libc::c_int)) as
                             usize] &
                ((1 as libc::c_ulong) <<
                     0 as libc::c_int %
                         (8 as libc::c_int *
                              ::std::mem::size_of::<__fd_mask>() as
                                  libc::c_ulong as libc::c_int)) as __fd_mask
                != 0 as libc::c_int as libc::c_long) as libc::c_int;
}
unsafe extern "C" fn handle_upcall(mut sock: *mut socket,
                                   mut arg: *mut libc::c_void,
                                   mut flgs: libc::c_int) {
    let mut events: libc::c_int = usrsctp_get_events(sock);
    if events & 0x2 as libc::c_int != 0 && dddone == 0 && connected == 0 {
        connected = 1 as libc::c_int;
        printf(b"socket connected\n\x00" as *const u8 as *const libc::c_char);
        return
    }
    while events & 0x1 as libc::c_int != 0 && dddone == 0 && connected != 0 {
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
        let mut addr: sockaddr_in =
            sockaddr_in{sin_family: 0,
                        sin_port: 0,
                        sin_addr: in_addr{s_addr: 0,},
                        sin_zero: [0; 8],};
        let mut buf: *mut libc::c_char =
            calloc(1 as libc::c_int as libc::c_ulong,
                   ((1 as libc::c_int) << 16 as libc::c_int) as libc::c_ulong)
                as *mut libc::c_char;
        let mut flags: libc::c_int = 0 as libc::c_int;
        let mut len: socklen_t =
            ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                socklen_t;
        let mut infotype: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        let mut infolen: socklen_t =
            ::std::mem::size_of::<sctp_recvv_rn>() as libc::c_ulong as
                socklen_t;
        memset(&mut rn as *mut sctp_recvv_rn as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sctp_recvv_rn>() as libc::c_ulong);
        n =
            usrsctp_recvv(sock, buf as *mut libc::c_void,
                          ((1 as libc::c_int) << 16 as libc::c_int) as size_t,
                          &mut addr as *mut sockaddr_in as *mut sockaddr,
                          &mut len,
                          &mut rn as *mut sctp_recvv_rn as *mut libc::c_void,
                          &mut infolen, &mut infotype, &mut flags);
        if n > 0 as libc::c_int as libc::c_long {
            if write(fileno(stdout), buf as *const libc::c_void, n as size_t)
                   < 0 as libc::c_int as libc::c_long {
                perror(b"write\x00" as *const u8 as *const libc::c_char);
            }
            free(buf as *mut libc::c_void);
            events = usrsctp_get_events(sock)
        } else if n == 0 as libc::c_int as libc::c_long {
            dddone = 1 as libc::c_int;
            input_done = 1 as libc::c_int;
            free(buf as *mut libc::c_void);
            break ;
        } else {
            perror(b"\nusrsctp_recvv\x00" as *const u8 as
                       *const libc::c_char);
            free(buf as *mut libc::c_void);
            break ;
        }
    };
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut sock: *mut socket = 0 as *mut socket;
    let mut addr: *mut sockaddr = 0 as *mut sockaddr;
    let mut addrs: *mut sockaddr = 0 as *mut sockaddr;
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
                                      C2RustUnnamed_0{__u6_addr8: [0; 16],},},
                     sin6_scope_id: 0,};
    let mut encaps: sctp_udpencaps =
        sctp_udpencaps{sue_address:
                           sockaddr_storage{ss_family: 0,
                                            __ss_padding: [0; 118],
                                            __ss_align: 0,},
                       sue_assoc_id: 0,
                       sue_port: 0,};
    let mut stat: sctpstat =
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
                 sctps_reserved: [0; 31],};
    let mut buffer: [libc::c_char; 200] = [0; 200];
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    if argc > 4 as libc::c_int {
        usrsctp_init(atoi(*argv.offset(4 as libc::c_int as isize)) as
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
        usrsctp_socket(10 as libc::c_int, SOCK_STREAM as libc::c_int,
                       IPPROTO_SCTP as libc::c_int, None, None,
                       0 as libc::c_int as uint32_t, 0 as *mut libc::c_void);
    if sock.is_null() {
        perror(b"usrsctp_socket\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    usrsctp_set_non_blocking(sock, 1 as libc::c_int);
    if argc > 3 as libc::c_int {
        memset(&mut addr6 as *mut sockaddr_in6 as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
        addr6.sin6_family = 10 as libc::c_int as sa_family_t;
        addr6.sin6_port =
            htons(atoi(*argv.offset(3 as libc::c_int as isize)) as uint16_t);
        addr6.sin6_addr = in6addr_any;
        if usrsctp_bind(sock,
                        &mut addr6 as *mut sockaddr_in6 as *mut sockaddr,
                        ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong
                            as socklen_t) < 0 as libc::c_int {
            perror(b"bind\x00" as *const u8 as *const libc::c_char);
            usrsctp_close(sock);
            exit(1 as libc::c_int);
        }
    }
    if argc > 5 as libc::c_int {
        memset(&mut encaps as *mut sctp_udpencaps as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong);
        encaps.sue_address.ss_family = 10 as libc::c_int as sa_family_t;
        encaps.sue_port =
            htons(atoi(*argv.offset(5 as libc::c_int as isize)) as uint16_t);
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x24 as libc::c_int,
                              &mut encaps as *mut sctp_udpencaps as
                                  *const libc::c_void,
                              ::std::mem::size_of::<sctp_udpencaps>() as
                                  libc::c_ulong as socklen_t) <
               0 as libc::c_int {
            perror(b"setsockopt\x00" as *const u8 as *const libc::c_char);
            usrsctp_close(sock);
            exit(1 as libc::c_int);
        }
    }
    memset(&mut addr4 as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    memset(&mut addr6 as *mut sockaddr_in6 as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
    addr4.sin_family = 2 as libc::c_int as sa_family_t;
    addr6.sin6_family = 10 as libc::c_int as sa_family_t;
    addr4.sin_port =
        htons(atoi(*argv.offset(2 as libc::c_int as isize)) as uint16_t);
    addr6.sin6_port =
        htons(atoi(*argv.offset(2 as libc::c_int as isize)) as uint16_t);
    if inet_pton(10 as libc::c_int, *argv.offset(1 as libc::c_int as isize),
                 &mut addr6.sin6_addr as *mut in6_addr as *mut libc::c_void)
           == 1 as libc::c_int {
        if usrsctp_connect(sock,
                           &mut addr6 as *mut sockaddr_in6 as *mut sockaddr,
                           ::std::mem::size_of::<sockaddr_in6>() as
                               libc::c_ulong as socklen_t) < 0 as libc::c_int
           {
            perror(b"usrsctp_connect\x00" as *const u8 as
                       *const libc::c_char);
        }
    } else if inet_pton(2 as libc::c_int,
                        *argv.offset(1 as libc::c_int as isize),
                        &mut addr4.sin_addr as *mut in_addr as
                            *mut libc::c_void) == 1 as libc::c_int {
        if usrsctp_connect(sock,
                           &mut addr4 as *mut sockaddr_in as *mut sockaddr,
                           ::std::mem::size_of::<sockaddr_in>() as
                               libc::c_ulong as socklen_t) < 0 as libc::c_int
           {
            perror(b"usrsctp_connect\x00" as *const u8 as
                       *const libc::c_char);
        }
    } else {
        printf(b"Illegal destination address.\n\x00" as *const u8 as
                   *const libc::c_char);
    }
    usrsctp_set_upcall(sock,
                       Some(handle_upcall as
                                unsafe extern "C" fn(_: *mut socket,
                                                     _: *mut libc::c_void,
                                                     _: libc::c_int) -> ()),
                       0 as *mut libc::c_void);
    n = usrsctp_getladdrs(sock, 0 as libc::c_int as sctp_assoc_t, &mut addrs);
    if n < 0 as libc::c_int {
        perror(b"usrsctp_getladdrs\x00" as *const u8 as *const libc::c_char);
    } else {
        addr = addrs;
        printf(b"Local addresses: \x00" as *const u8 as *const libc::c_char);
        i = 0 as libc::c_int;
        while i < n {
            if i > 0 as libc::c_int {
                printf(b"%s\x00" as *const u8 as *const libc::c_char,
                       b", \x00" as *const u8 as *const libc::c_char);
            }
            match (*addr).sa_family as libc::c_int {
                2 => {
                    let mut sin: *mut sockaddr_in = 0 as *mut sockaddr_in;
                    let mut buf: [libc::c_char; 16] = [0; 16];
                    let mut name: *const libc::c_char =
                        0 as *const libc::c_char;
                    sin = addr as *mut sockaddr_in;
                    name =
                        inet_ntop(2 as libc::c_int,
                                  &mut (*sin).sin_addr as *mut in_addr as
                                      *const libc::c_void, buf.as_mut_ptr(),
                                  16 as libc::c_int as socklen_t);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in>()
                                                 as libc::c_ulong as isize) as
                            *mut sockaddr
                }
                10 => {
                    let mut sin6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
                    let mut buf_0: [libc::c_char; 46] = [0; 46];
                    let mut name_0: *const libc::c_char =
                        0 as *const libc::c_char;
                    sin6 = addr as *mut sockaddr_in6;
                    name_0 =
                        inet_ntop(10 as libc::c_int,
                                  &mut (*sin6).sin6_addr as *mut in6_addr as
                                      *const libc::c_void, buf_0.as_mut_ptr(),
                                  46 as libc::c_int as socklen_t);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name_0);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in6>()
                                                 as libc::c_ulong as isize) as
                            *mut sockaddr
                }
                _ => { }
            }
            i += 1
        }
        printf(b".\n\x00" as *const u8 as *const libc::c_char);
        usrsctp_freeladdrs(addrs);
    }
    n = usrsctp_getpaddrs(sock, 0 as libc::c_int as sctp_assoc_t, &mut addrs);
    if n < 0 as libc::c_int {
        perror(b"usrsctp_getpaddrs\x00" as *const u8 as *const libc::c_char);
    } else {
        addr = addrs;
        printf(b"Peer addresses: \x00" as *const u8 as *const libc::c_char);
        i = 0 as libc::c_int;
        while i < n {
            if i > 0 as libc::c_int {
                printf(b"%s\x00" as *const u8 as *const libc::c_char,
                       b", \x00" as *const u8 as *const libc::c_char);
            }
            match (*addr).sa_family as libc::c_int {
                2 => {
                    let mut sin_0: *mut sockaddr_in = 0 as *mut sockaddr_in;
                    let mut buf_1: [libc::c_char; 16] = [0; 16];
                    let mut name_1: *const libc::c_char =
                        0 as *const libc::c_char;
                    sin_0 = addr as *mut sockaddr_in;
                    name_1 =
                        inet_ntop(2 as libc::c_int,
                                  &mut (*sin_0).sin_addr as *mut in_addr as
                                      *const libc::c_void, buf_1.as_mut_ptr(),
                                  16 as libc::c_int as socklen_t);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name_1);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in>()
                                                 as libc::c_ulong as isize) as
                            *mut sockaddr
                }
                10 => {
                    let mut sin6_0: *mut sockaddr_in6 =
                        0 as *mut sockaddr_in6;
                    let mut buf_2: [libc::c_char; 46] = [0; 46];
                    let mut name_2: *const libc::c_char =
                        0 as *const libc::c_char;
                    sin6_0 = addr as *mut sockaddr_in6;
                    name_2 =
                        inet_ntop(10 as libc::c_int,
                                  &mut (*sin6_0).sin6_addr as *mut in6_addr as
                                      *const libc::c_void, buf_2.as_mut_ptr(),
                                  46 as libc::c_int as socklen_t);
                    printf(b"%s\x00" as *const u8 as *const libc::c_char,
                           name_2);
                    addr =
                        (addr as
                             caddr_t).offset(::std::mem::size_of::<sockaddr_in6>()
                                                 as libc::c_ulong as isize) as
                            *mut sockaddr
                }
                _ => { }
            }
            i += 1
        }
        printf(b".\n\x00" as *const u8 as *const libc::c_char);
        usrsctp_freepaddrs(addrs);
    }
    while dddone == 0 && input_done == 0 {
        if !(inputAvailable() != 0) { continue ; }
        if !fgets(buffer.as_mut_ptr(),
                  ::std::mem::size_of::<[libc::c_char; 200]>() as
                      libc::c_ulong as libc::c_int, stdin).is_null() {
            buffer[strlen(buffer.as_mut_ptr()) as usize] =
                '\u{0}' as i32 as libc::c_char;
            usrsctp_sendv(sock, buffer.as_mut_ptr() as *const libc::c_void,
                          strlen(buffer.as_mut_ptr()), 0 as *mut sockaddr,
                          0 as libc::c_int, 0 as *mut libc::c_void,
                          0 as libc::c_int as socklen_t,
                          0 as libc::c_int as libc::c_uint, 0 as libc::c_int);
        } else {
            if usrsctp_shutdown(sock, SHUT_WR as libc::c_int) <
                   0 as libc::c_int {
                perror(b"usrsctp_shutdown\x00" as *const u8 as
                           *const libc::c_char);
            }
            break ;
        }
    }
    sleep(1 as libc::c_int as libc::c_uint);
    usrsctp_close(sock);
    usrsctp_get_stat(&mut stat);
    printf(b"Number of packets (sent/received): (%u/%u).\n\x00" as *const u8
               as *const libc::c_char, stat.sctps_outpackets,
           stat.sctps_inpackets);
    while usrsctp_finish() != 0 as libc::c_int {
        sleep(1 as libc::c_int as libc::c_uint);
    }
    printf(b"Client finished\n\x00" as *const u8 as *const libc::c_char);
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
