use ::libc;
extern "C" {
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
    fn perror(__s: *const libc::c_char);
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn time(__timer: *mut time_t) -> time_t;
    #[no_mangle]
    fn ctime(__timer: *const time_t) -> *mut libc::c_char;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
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
    fn usrsctp_bind(so: *mut socket, name: *mut sockaddr, namelen: socklen_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_listen(so: *mut socket, backlog: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_accept(so: *mut socket, aname: *mut sockaddr,
                      anamelen: *mut socklen_t) -> *mut socket;
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
    fn usrsctp_sysctl_set_sctp_no_csum_on_loopback(value: uint32_t)
     -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_blackhole(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn usrsctp_sysctl_set_sctp_debug_on(value: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn debug_printf_stack(format: *const libc::c_char, _: ...);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
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
unsafe extern "C" fn handle_accept(mut sock: *mut socket,
                                   mut data: *mut libc::c_void,
                                   mut flags: libc::c_int) {
    let mut conn_sock: *mut socket = 0 as *mut socket;
    let mut buffer: [libc::c_char; 80] = [0; 80];
    let mut now: time_t = 0;
    let mut addr_len: socklen_t = 0 as libc::c_int as socklen_t;
    let mut sndinfo: sctp_sndinfo =
        sctp_sndinfo{snd_sid: 0,
                     snd_flags: 0,
                     snd_ppid: 0,
                     snd_context: 0,
                     snd_assoc_id: 0,};
    conn_sock = usrsctp_accept(sock, 0 as *mut sockaddr, &mut addr_len);
    if conn_sock.is_null() && *__errno_location() != 115 as libc::c_int {
        perror(b"usrsctp_accept\x00" as *const u8 as *const libc::c_char);
        return
    }
    time(&mut now);
    snprintf(buffer.as_mut_ptr(),
             ::std::mem::size_of::<[libc::c_char; 80]>() as libc::c_ulong,
             b"%s\x00" as *const u8 as *const libc::c_char, ctime(&mut now));
    sndinfo.snd_sid = 0 as libc::c_int as uint16_t;
    sndinfo.snd_flags = 0 as libc::c_int as uint16_t;
    sndinfo.snd_ppid = htonl(40 as libc::c_int as uint32_t);
    sndinfo.snd_context = 0 as libc::c_int as uint32_t;
    sndinfo.snd_assoc_id = 0 as libc::c_int as sctp_assoc_t;
    usrsctp_sendv(conn_sock, buffer.as_mut_ptr() as *const libc::c_void,
                  strlen(buffer.as_mut_ptr()), 0 as *mut sockaddr,
                  0 as libc::c_int,
                  &mut sndinfo as *mut sctp_sndinfo as *mut libc::c_void,
                  ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong as
                      socklen_t, 1 as libc::c_int as libc::c_uint,
                  0 as libc::c_int);
    usrsctp_close(conn_sock);
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut sock: *mut socket = 0 as *mut socket;
    let mut addr: sockaddr_in =
        sockaddr_in{sin_family: 0,
                    sin_port: 0,
                    sin_addr: in_addr{s_addr: 0,},
                    sin_zero: [0; 8],};
    let mut encaps: sctp_udpencaps =
        sctp_udpencaps{sue_address:
                           sockaddr_storage{ss_family: 0,
                                            __ss_padding: [0; 118],
                                            __ss_align: 0,},
                       sue_assoc_id: 0,
                       sue_port: 0,};
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
                       IPPROTO_SCTP as libc::c_int, None, None,
                       0 as libc::c_int as uint32_t, 0 as *mut libc::c_void);
    if sock.is_null() {
        perror(b"usrsctp_socket\x00" as *const u8 as *const libc::c_char);
    }
    usrsctp_set_non_blocking(sock, 1 as libc::c_int);
    if argc > 2 as libc::c_int {
        memset(&mut encaps as *mut sctp_udpencaps as *mut libc::c_void,
               0 as libc::c_int,
               ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong);
        encaps.sue_address.ss_family = 2 as libc::c_int as sa_family_t;
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
    memset(&mut addr as *mut sockaddr_in as *mut libc::c_void,
           0 as libc::c_int,
           ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
    addr.sin_family = 2 as libc::c_int as sa_family_t;
    addr.sin_port = htons(13 as libc::c_int as uint16_t);
    addr.sin_addr.s_addr = htonl(0 as libc::c_int as in_addr_t);
    if usrsctp_bind(sock, &mut addr as *mut sockaddr_in as *mut sockaddr,
                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                        socklen_t) < 0 as libc::c_int {
        perror(b"usrsctp_bind\x00" as *const u8 as *const libc::c_char);
    }
    if usrsctp_listen(sock, 1 as libc::c_int) < 0 as libc::c_int {
        perror(b"usrsctp_listen\x00" as *const u8 as *const libc::c_char);
    }
    usrsctp_set_upcall(sock,
                       Some(handle_accept as
                                unsafe extern "C" fn(_: *mut socket,
                                                     _: *mut libc::c_void,
                                                     _: libc::c_int) -> ()),
                       0 as *mut libc::c_void);
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
