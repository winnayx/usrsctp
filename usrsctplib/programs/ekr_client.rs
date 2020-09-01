use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sockaddr_x25;
    pub type sockaddr_un;
    pub type sockaddr_ns;
    pub type sockaddr_iso;
    pub type sockaddr_ipx;
    pub type sockaddr_inarp;
    pub type sockaddr_eon;
    pub type sockaddr_dl;
    pub type sockaddr_ax25;
    pub type sockaddr_at;
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
    static mut stderr: *mut FILE;
    #[no_mangle]
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn socket(__domain: libc::c_int, __type: libc::c_int,
              __protocol: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn bind(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t)
     -> libc::c_int;
    #[no_mangle]
    fn connect(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG,
               __len: socklen_t) -> libc::c_int;
    #[no_mangle]
    fn send(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t,
            __flags: libc::c_int) -> ssize_t;
    #[no_mangle]
    fn recv(__fd: libc::c_int, __buf: *mut libc::c_void, __n: size_t,
            __flags: libc::c_int) -> ssize_t;
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn inet_pton(__af: libc::c_int, __cp: *const libc::c_char,
                 __buf: *mut libc::c_void) -> libc::c_int;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn pthread_create(__newthread: *mut pthread_t,
                      __attr: *const pthread_attr_t,
                      __start_routine:
                          Option<unsafe extern "C" fn(_: *mut libc::c_void)
                                     -> *mut libc::c_void>,
                      __arg: *mut libc::c_void) -> libc::c_int;
    #[no_mangle]
    fn pthread_join(__th: pthread_t, __thread_return: *mut *mut libc::c_void)
     -> libc::c_int;
    #[no_mangle]
    fn pthread_cancel(__th: pthread_t) -> libc::c_int;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
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
    fn usrsctp_conninput(_: *mut libc::c_void, _: *const libc::c_void,
                         _: size_t, _: uint8_t);
    #[no_mangle]
    fn usrsctp_register_address(_: *mut libc::c_void);
    #[no_mangle]
    fn usrsctp_deregister_address(_: *mut libc::c_void);
    #[no_mangle]
    fn usrsctp_dumppacket(_: *const libc::c_void, _: size_t, _: libc::c_int)
     -> *mut libc::c_char;
    #[no_mangle]
    fn usrsctp_freedumpbuffer(_: *mut libc::c_char);
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_ecn_enable(value: uint32_t) -> libc::c_int;
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
pub type pthread_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [libc::c_char; 56],
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
#[derive(Copy, Clone)]
#[repr(C)]
pub union __CONST_SOCKADDR_ARG {
    pub __sockaddr__: *const sockaddr,
    pub __sockaddr_at__: *const sockaddr_at,
    pub __sockaddr_ax25__: *const sockaddr_ax25,
    pub __sockaddr_dl__: *const sockaddr_dl,
    pub __sockaddr_eon__: *const sockaddr_eon,
    pub __sockaddr_in__: *const sockaddr_in,
    pub __sockaddr_in6__: *const sockaddr_in6,
    pub __sockaddr_inarp__: *const sockaddr_inarp,
    pub __sockaddr_ipx__: *const sockaddr_ipx,
    pub __sockaddr_iso__: *const sockaddr_iso,
    pub __sockaddr_ns__: *const sockaddr_ns,
    pub __sockaddr_un__: *const sockaddr_un,
    pub __sockaddr_x25__: *const sockaddr_x25,
}
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
pub struct sctp_sndinfo {
    pub snd_sid: uint16_t,
    pub snd_flags: uint16_t,
    pub snd_ppid: uint32_t,
    pub snd_context: uint32_t,
    pub snd_assoc_id: sctp_assoc_t,
}
unsafe extern "C" fn handle_packets(mut arg: *mut libc::c_void)
 -> *mut libc::c_void {
    let mut fdp: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut dump_buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut length: ssize_t = 0;
    let mut buf: [libc::c_char; 65536] = [0; 65536];
    fdp = arg as *mut libc::c_int;
    loop  {
        length =
            recv(*fdp, buf.as_mut_ptr() as *mut libc::c_void,
                 ((1 as libc::c_int) << 16 as libc::c_int) as size_t,
                 0 as libc::c_int);
        if length > 0 as libc::c_int as libc::c_long {
            dump_buf =
                usrsctp_dumppacket(buf.as_mut_ptr() as *const libc::c_void,
                                   length as size_t, 0 as libc::c_int);
            if !dump_buf.is_null() {
                fprintf(stderr, b"%s\x00" as *const u8 as *const libc::c_char,
                        dump_buf);
                usrsctp_freedumpbuffer(dump_buf);
            }
            usrsctp_conninput(fdp as *mut libc::c_void,
                              buf.as_mut_ptr() as *const libc::c_void,
                              length as size_t, 0 as libc::c_int as uint8_t);
        }
    };
}
unsafe extern "C" fn conn_output(mut addr: *mut libc::c_void,
                                 mut buf: *mut libc::c_void,
                                 mut length: size_t, mut tos: uint8_t,
                                 mut set_df: uint8_t) -> libc::c_int {
    let mut dump_buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fdp: *mut libc::c_int = 0 as *mut libc::c_int;
    fdp = addr as *mut libc::c_int;
    dump_buf = usrsctp_dumppacket(buf, length, 1 as libc::c_int);
    if !dump_buf.is_null() {
        fprintf(stderr, b"%s\x00" as *const u8 as *const libc::c_char,
                dump_buf);
        usrsctp_freedumpbuffer(dump_buf);
    }
    if send(*fdp, buf, length, 0 as libc::c_int) <
           0 as libc::c_int as libc::c_long {
        return *__errno_location()
    } else { return 0 as libc::c_int };
}
unsafe extern "C" fn receive_cb(mut sock: *mut socket,
                                mut addr: sctp_sockstore,
                                mut data: *mut libc::c_void,
                                mut datalen: size_t, mut rcv: sctp_rcvinfo,
                                mut flags: libc::c_int,
                                mut ulp_info: *mut libc::c_void)
 -> libc::c_int {
    if !data.is_null() {
        if flags & 0x2000 as libc::c_int != 0 {
            printf(b"Notification of length %d received.\n\x00" as *const u8
                       as *const libc::c_char, datalen as libc::c_int);
        } else {
            printf(b"Msg of length %d received via %p:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u.\n\x00"
                       as *const u8 as *const libc::c_char,
                   datalen as libc::c_int, addr.sconn.sconn_addr,
                   ntohs(addr.sconn.sconn_port) as libc::c_int,
                   rcv.rcv_sid as libc::c_int, rcv.rcv_ssn as libc::c_int,
                   rcv.rcv_tsn, ntohl(rcv.rcv_ppid), rcv.rcv_context);
        }
        free(data);
    } else { usrsctp_deregister_address(ulp_info); usrsctp_close(sock); }
    return 1 as libc::c_int;
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut sin: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut sconn: sockaddr_conn =
        sockaddr_conn{sconn_family: 0,
                      sconn_port: 0,
                      sconn_addr: 0 as *mut libc::c_void,};
    let mut fd: libc::c_int = 0;
    let mut s: *mut socket = 0 as *mut socket;
    let mut tid: pthread_t = 0;
    let mut sndinfo: sctp_sndinfo =
        sctp_sndinfo{snd_sid: 0,
                     snd_flags: 0,
                     snd_ppid: 0,
                     snd_context: 0,
                     snd_assoc_id: 0,};
    let mut buffer: [libc::c_char; 80] = [0; 80];
    if argc < 4 as libc::c_int {
        printf(b"error: this program requires 4 arguments!\n\x00" as *const u8
                   as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    usrsctp_init(0 as libc::c_int as uint16_t,
                 Some(conn_output as
                          unsafe extern "C" fn(_: *mut libc::c_void,
                                               _: *mut libc::c_void,
                                               _: size_t, _: uint8_t,
                                               _: uint8_t) -> libc::c_int),
                 Some(debug_printf_stack as
                          unsafe extern "C" fn(_: *const libc::c_char, _: ...)
                              -> ()));
    /* set up a connected UDP socket */
    fd =
        socket(2 as libc::c_int, SOCK_DGRAM as libc::c_int,
               IPPROTO_UDP as libc::c_int);
    if fd < 0 as libc::c_int {
        perror(b"socket\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    memset(&mut sin as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    sin.sin_family = 2 as libc::c_int as sa_family_t;
    sin.sin_port =
        htons(atoi(*argv.offset(2 as libc::c_int as isize)) as uint16_t);
    if inet_pton(2 as libc::c_int, *argv.offset(1 as libc::c_int as isize),
                 &mut sin.sin_addr.s_addr as *mut in_addr_t as
                     *mut libc::c_void) == 0 {
        printf(b"error: invalid address\n\x00" as *const u8 as
                   *const libc::c_char);
        exit(1 as libc::c_int);
    }
    if bind(fd,
            __CONST_SOCKADDR_ARG{__sockaddr__:
                                     &mut sin as *mut sockaddr_in as
                                         *mut sockaddr,},
            ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                socklen_t) < 0 as libc::c_int {
        perror(b"bind\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    memset(&mut sin as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    sin.sin_family = 2 as libc::c_int as sa_family_t;
    sin.sin_port =
        htons(atoi(*argv.offset(4 as libc::c_int as isize)) as uint16_t);
    if inet_pton(2 as libc::c_int, *argv.offset(3 as libc::c_int as isize),
                 &mut sin.sin_addr.s_addr as *mut in_addr_t as
                     *mut libc::c_void) == 0 {
        printf(b"error: invalid address\n\x00" as *const u8 as
                   *const libc::c_char);
        exit(1 as libc::c_int);
    }
    if connect(fd,
               __CONST_SOCKADDR_ARG{__sockaddr__:
                                        &mut sin as *mut sockaddr_in as
                                            *mut sockaddr,},
               ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                   socklen_t) < 0 as libc::c_int {
        perror(b"connect\x00" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    usrsctp_sysctl_set_sctp_debug_on(0 as libc::c_int as uint32_t);
    usrsctp_sysctl_set_sctp_ecn_enable(0 as libc::c_int as uint32_t);
    usrsctp_register_address(&mut fd as *mut libc::c_int as
                                 *mut libc::c_void);
    pthread_create(&mut tid, 0 as *const pthread_attr_t,
                   Some(handle_packets as
                            unsafe extern "C" fn(_: *mut libc::c_void)
                                -> *mut libc::c_void),
                   &mut fd as *mut libc::c_int as *mut libc::c_void);
    s =
        usrsctp_socket(123 as libc::c_int, SOCK_STREAM as libc::c_int,
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
                       &mut fd as *mut libc::c_int as *mut libc::c_void);
    if s.is_null() {
        perror(b"usrsctp_socket\x00" as *const u8 as *const libc::c_char);
    }
    memset(&mut sconn as *mut sockaddr_conn as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong);
    sconn.sconn_family = 123 as libc::c_int as uint16_t;
    sconn.sconn_port = htons(0 as libc::c_int as uint16_t);
    sconn.sconn_addr = 0 as *mut libc::c_void;
    if usrsctp_bind(s, &mut sconn as *mut sockaddr_conn as *mut sockaddr,
                    ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong as
                        socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_bind\x00" as *const u8 as *const libc::c_char);
    }
    memset(&mut sconn as *mut sockaddr_conn as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong);
    sconn.sconn_family = 123 as libc::c_int as uint16_t;
    sconn.sconn_port = htons(5001 as libc::c_int as uint16_t);
    sconn.sconn_addr = &mut fd as *mut libc::c_int as *mut libc::c_void;
    if usrsctp_connect(s, &mut sconn as *mut sockaddr_conn as *mut sockaddr,
                       ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong
                           as socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_connect\x00" as *const u8 as *const libc::c_char);
    }
    memset(buffer.as_mut_ptr() as *mut libc::c_void, 'A' as i32,
           80 as libc::c_int as libc::c_ulong);
    sndinfo.snd_sid = 1 as libc::c_int as uint16_t;
    sndinfo.snd_flags = 0 as libc::c_int as uint16_t;
    sndinfo.snd_ppid = htonl(39 as libc::c_int as uint32_t);
    sndinfo.snd_context = 0 as libc::c_int as uint32_t;
    sndinfo.snd_assoc_id = 0 as libc::c_int as sctp_assoc_t;
    if usrsctp_sendv(s, buffer.as_mut_ptr() as *const libc::c_void,
                     80 as libc::c_int as size_t, 0 as *mut sockaddr,
                     0 as libc::c_int,
                     &mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
                     ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong as
                         socklen_t, 1 as libc::c_int as libc::c_uint,
                     0 as libc::c_int) < 0 as libc::c_int as libc::c_long {
        perror(b"usrsctp_sendv\x00" as *const u8 as *const libc::c_char);
    }
    usrsctp_shutdown(s, SHUT_WR as libc::c_int);
    while usrsctp_finish() != 0 as libc::c_int {
        sleep(1 as libc::c_int as libc::c_uint);
    }
    pthread_cancel(tid);
    pthread_join(tid, 0 as *mut *mut libc::c_void);
    if close(fd) < 0 as libc::c_int {
        perror(b"close\x00" as *const u8 as *const libc::c_char);
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
