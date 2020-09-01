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
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn fileno(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    static in6addr_any: in6_addr;
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
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
    fn usrsctp_sysctl_set_sctp_blackhole(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_debug_on(value: uint32_t) -> libc::c_int;
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
/* Used for SCTP_MAXSEG, SCTP_MAX_BURST, SCTP_ENABLE_STREAM_RESET, and SCTP_CONTEXT */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sctp_assoc_value {
    pub assoc_id: sctp_assoc_t,
    pub assoc_value: uint32_t,
}
unsafe extern "C" fn handle_upcall(mut sock: *mut socket,
                                   mut data: *mut libc::c_void,
                                   mut flgs: libc::c_int) {
    let mut namebuf: [libc::c_char; 46] = [0; 46];
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    let mut port: uint16_t = 0;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut events: libc::c_int = 0;
    loop  {
        events = usrsctp_get_events(sock);
        if !(events != 0 && events & 0x1 as libc::c_int != 0) { break ; }
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
        buf =
            malloc(10240 as libc::c_int as libc::c_ulong) as
                *mut libc::c_char;
        let mut flags: libc::c_int = 0 as libc::c_int;
        let mut len: socklen_t =
            ::std::mem::size_of::<sockaddr_storage>() as libc::c_ulong as
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
                          10240 as libc::c_int as size_t,
                          &mut addr as *mut sockaddr_storage as *mut sockaddr,
                          &mut len,
                          &mut rn as *mut sctp_recvv_rn as *mut libc::c_void,
                          &mut infolen, &mut infotype, &mut flags);
        if n < 0 as libc::c_int as libc::c_long {
            perror(b"usrsctp_recvv\x00" as *const u8 as *const libc::c_char);
        }
        if n == 0 as libc::c_int as libc::c_long {
            usrsctp_close(sock);
            return
        }
        if n > 0 as libc::c_int as libc::c_long {
            if flags & 0x2000 as libc::c_int != 0 {
                printf(b"Notification of length %d received.\n\x00" as
                           *const u8 as *const libc::c_char,
                       n as libc::c_int);
            } else {
                if write(fileno(stdout), buf as *const libc::c_void,
                         n as size_t) < 0 as libc::c_int as libc::c_long {
                    perror(b"write\x00" as *const u8 as *const libc::c_char);
                }
                match addr.ss_family as libc::c_int {
                    2 => {
                        let mut addr4: sockaddr_in =
                            sockaddr_in{sin_family: 0,
                                        sin_port: 0,
                                        sin_addr: in_addr{s_addr: 0,},
                                        sin_zero: [0; 8],};
                        memcpy(&mut addr4 as *mut sockaddr_in as
                                   *mut libc::c_void,
                               &mut addr as *mut sockaddr_storage as
                                   *mut sockaddr_in as *const libc::c_void,
                               ::std::mem::size_of::<sockaddr_in>() as
                                   libc::c_ulong);
                        name =
                            inet_ntop(2 as libc::c_int,
                                      &mut addr4.sin_addr as *mut in_addr as
                                          *const libc::c_void,
                                      namebuf.as_mut_ptr(),
                                      16 as libc::c_int as socklen_t);
                        port = ntohs(addr4.sin_port)
                    }
                    10 => {
                        let mut addr6: sockaddr_in6 =
                            sockaddr_in6{sin6_family: 0,
                                         sin6_port: 0,
                                         sin6_flowinfo: 0,
                                         sin6_addr:
                                             in6_addr{__in6_u:
                                                          C2RustUnnamed_0{__u6_addr8:
                                                                              [0;
                                                                                  16],},},
                                         sin6_scope_id: 0,};
                        memcpy(&mut addr6 as *mut sockaddr_in6 as
                                   *mut libc::c_void,
                               &mut addr as *mut sockaddr_storage as
                                   *mut sockaddr_in6 as *const libc::c_void,
                               ::std::mem::size_of::<sockaddr_in6>() as
                                   libc::c_ulong);
                        name =
                            inet_ntop(10 as libc::c_int,
                                      &mut addr6.sin6_addr as *mut in6_addr as
                                          *const libc::c_void,
                                      namebuf.as_mut_ptr(),
                                      46 as libc::c_int as socklen_t);
                        port = ntohs(addr6.sin6_port)
                    }
                    _ => {
                        name = 0 as *const libc::c_char;
                        port = 0 as libc::c_int as uint16_t
                    }
                }
                if name.is_null() {
                    printf(b"inet_ntop failed\n\x00" as *const u8 as
                               *const libc::c_char);
                    free(buf as *mut libc::c_void);
                    return
                }
                printf(b"Msg of length %d received from %s:%u on stream %d with SSN %u and TSN %u, PPID %u, context %u.\n\x00"
                           as *const u8 as *const libc::c_char,
                       n as libc::c_int, namebuf.as_mut_ptr(),
                       port as libc::c_int,
                       rn.recvv_rcvinfo.rcv_sid as libc::c_int,
                       rn.recvv_rcvinfo.rcv_ssn as libc::c_int,
                       rn.recvv_rcvinfo.rcv_tsn,
                       ntohl(rn.recvv_rcvinfo.rcv_ppid),
                       rn.recvv_rcvinfo.rcv_context);
                if flags & MSG_EOR as libc::c_int != 0 {
                    let mut snd_info: sctp_sndinfo =
                        sctp_sndinfo{snd_sid: 0,
                                     snd_flags: 0,
                                     snd_ppid: 0,
                                     snd_context: 0,
                                     snd_assoc_id: 0,};
                    snd_info.snd_sid = rn.recvv_rcvinfo.rcv_sid;
                    snd_info.snd_flags = 0 as libc::c_int as uint16_t;
                    if rn.recvv_rcvinfo.rcv_flags as libc::c_int &
                           0x400 as libc::c_int != 0 {
                        snd_info.snd_flags =
                            (snd_info.snd_flags as libc::c_int |
                                 0x400 as libc::c_int) as uint16_t
                    }
                    snd_info.snd_ppid = rn.recvv_rcvinfo.rcv_ppid;
                    snd_info.snd_context = 0 as libc::c_int as uint32_t;
                    snd_info.snd_assoc_id = rn.recvv_rcvinfo.rcv_assoc_id;
                    if usrsctp_sendv(sock, buf as *const libc::c_void,
                                     n as size_t, 0 as *mut sockaddr,
                                     0 as libc::c_int,
                                     &mut snd_info as *mut sctp_sndinfo as
                                         *mut libc::c_void,
                                     ::std::mem::size_of::<sctp_sndinfo>() as
                                         libc::c_ulong as socklen_t,
                                     1 as libc::c_int as libc::c_uint,
                                     0 as libc::c_int) <
                           0 as libc::c_int as libc::c_long {
                        perror(b"sctp_sendv\x00" as *const u8 as
                                   *const libc::c_char);
                    }
                }
            }
        }
        free(buf as *mut libc::c_void);
    };
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut sock: *mut socket = 0 as *mut socket;
    let mut addr: sockaddr_in6 =
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
    let mut event: sctp_event =
        sctp_event{se_assoc_id: 0, se_type: 0, se_on: 0,};
    let mut event_types: [uint16_t; 6] =
        [0x1 as libc::c_int as uint16_t, 0x2 as libc::c_int as uint16_t,
         0x3 as libc::c_int as uint16_t, 0x5 as libc::c_int as uint16_t,
         0x6 as libc::c_int as uint16_t, 0x7 as libc::c_int as uint16_t];
    let mut i: libc::c_uint = 0;
    let mut av: sctp_assoc_value =
        sctp_assoc_value{assoc_id: 0, assoc_value: 0,};
    let on: libc::c_int = 1 as libc::c_int;
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
        usrsctp_socket(10 as libc::c_int, SOCK_SEQPACKET as libc::c_int,
                       IPPROTO_SCTP as libc::c_int, None, None,
                       0 as libc::c_int as uint32_t, 0 as *mut libc::c_void);
    if sock.is_null() {
        perror(b"usrsctp_socket\x00" as *const u8 as *const libc::c_char);
    }
    usrsctp_set_non_blocking(sock, 1 as libc::c_int);
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0xd as libc::c_int,
                          &on as *const libc::c_int as *const libc::c_void,
                          ::std::mem::size_of::<libc::c_int>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_setsockopt SCTP_I_WANT_MAPPED_V4_ADDR\x00" as
                   *const u8 as *const libc::c_char);
    }
    memset(&mut av as *mut sctp_assoc_value as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong);
    av.assoc_id = 2 as libc::c_int as sctp_assoc_t;
    av.assoc_value = 47 as libc::c_int as uint32_t;
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x1a as libc::c_int,
                          &mut av as *mut sctp_assoc_value as
                              *const libc::c_void,
                          ::std::mem::size_of::<sctp_assoc_value>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_setsockopt SCTP_CONTEXT\x00" as *const u8 as
                   *const libc::c_char);
    }
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x1f as libc::c_int,
                          &on as *const libc::c_int as *const libc::c_void,
                          ::std::mem::size_of::<libc::c_int>() as
                              libc::c_ulong as socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_setsockopt SCTP_RECVRCVINFO\x00" as *const u8 as
                   *const libc::c_char);
    }
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
            perror(b"usrsctp_setsockopt SCTP_REMOTE_UDP_ENCAPS_PORT\x00" as
                       *const u8 as *const libc::c_char);
        }
    }
    memset(&mut event as *mut sctp_event as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sctp_event>() as libc::c_ulong);
    event.se_assoc_id = 0 as libc::c_int as sctp_assoc_t;
    event.se_on = 1 as libc::c_int as uint8_t;
    i = 0 as libc::c_int as libc::c_uint;
    while i <
              (::std::mem::size_of::<[uint16_t; 6]>() as
                   libc::c_ulong).wrapping_div(::std::mem::size_of::<uint16_t>()
                                                   as libc::c_ulong) as
                  libc::c_uint {
        event.se_type = event_types[i as usize];
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x1e as libc::c_int,
                              &mut event as *mut sctp_event as
                                  *const libc::c_void,
                              ::std::mem::size_of::<sctp_event>() as
                                  libc::c_ulong as socklen_t) <
               0 as libc::c_int {
            perror(b"usrsctp_setsockopt SCTP_EVENT\x00" as *const u8 as
                       *const libc::c_char);
        }
        i = i.wrapping_add(1)
    }
    usrsctp_set_upcall(sock,
                       Some(handle_upcall as
                                unsafe extern "C" fn(_: *mut socket,
                                                     _: *mut libc::c_void,
                                                     _: libc::c_int) -> ()),
                       0 as *mut libc::c_void);
    memset(&mut addr as *mut sockaddr_in6 as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
    addr.sin6_family = 10 as libc::c_int as sa_family_t;
    addr.sin6_port = htons(7 as libc::c_int as uint16_t);
    addr.sin6_addr = in6addr_any;
    if usrsctp_bind(sock, &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                    ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong as
                        socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_bind\x00" as *const u8 as *const libc::c_char);
    }
    if usrsctp_listen(sock, 1 as libc::c_int) < 0 as libc::c_int {
        perror(b"usrsctp_listen\x00" as *const u8 as *const libc::c_char);
    }
    loop  { sleep(1 as libc::c_int as libc::c_uint); };
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
