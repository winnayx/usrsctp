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
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
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
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
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
pub const MSG_CMSG_CLOEXEC: C2RustUnnamed_0 = 1073741824;
pub const MSG_FASTOPEN: C2RustUnnamed_0 = 536870912;
pub const MSG_ZEROCOPY: C2RustUnnamed_0 = 67108864;
pub const MSG_BATCH: C2RustUnnamed_0 = 262144;
pub const MSG_WAITFORONE: C2RustUnnamed_0 = 65536;
pub const MSG_MORE: C2RustUnnamed_0 = 32768;
pub const MSG_NOSIGNAL: C2RustUnnamed_0 = 16384;
pub const MSG_ERRQUEUE: C2RustUnnamed_0 = 8192;
pub const MSG_RST: C2RustUnnamed_0 = 4096;
pub const MSG_CONFIRM: C2RustUnnamed_0 = 2048;
pub const MSG_SYN: C2RustUnnamed_0 = 1024;
pub const MSG_FIN: C2RustUnnamed_0 = 512;
pub const MSG_WAITALL: C2RustUnnamed_0 = 256;
pub const MSG_EOR: C2RustUnnamed_0 = 128;
pub const MSG_DONTWAIT: C2RustUnnamed_0 = 64;
pub const MSG_TRUNC: C2RustUnnamed_0 = 32;
pub const MSG_PROXY: C2RustUnnamed_0 = 16;
pub const MSG_CTRUNC: C2RustUnnamed_0 = 8;
pub const MSG_TRYHARD: C2RustUnnamed_0 = 4;
pub const MSG_DONTROUTE: C2RustUnnamed_0 = 4;
pub const MSG_PEEK: C2RustUnnamed_0 = 2;
pub const MSG_OOB: C2RustUnnamed_0 = 1;

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
pub struct sctp_udpencaps {
    pub sue_address: sockaddr_storage,
    pub sue_assoc_id: uint32_t,
    pub sue_port: uint16_t,
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
/* Used for SCTP_MAXSEG, SCTP_MAX_BURST, SCTP_ENABLE_STREAM_RESET, and SCTP_CONTEXT */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_assoc_value {
    pub assoc_id: sctp_assoc_t,
    pub assoc_value: uint32_t,
}
#[no_mangle]
pub static mut use_cb: libc::c_int = 0i32;
unsafe extern "C" fn receive_cb(mut sock: *mut socket,
                                mut addr: sctp_sockstore,
                                mut data: *mut libc::c_void,
                                mut datalen: size_t, mut rcv: sctp_rcvinfo,
                                mut flags: libc::c_int,
                                mut ulp_info: *mut libc::c_void)
 -> libc::c_int {
    
    
       
    if !data.is_null() {
        if flags & 0x2000i32 != 0 {
            printf(b"Notification of length %d received.\n\x00" as *const u8
                       as *const libc::c_char, datalen as libc::c_int);
        } else {
                let mut namebuf =    [0; 46]; let mut name =    0 as *const libc::c_char; let mut port =    0;match addr.sa.sa_family as libc::c_int {
                2 => {
                    name =
                        inet_ntop(2i32,
                                  &mut addr.sin.sin_addr as *mut in_addr as
                                      *const libc::c_void,
                                  namebuf.as_mut_ptr(),
                                  16u32);
                    port = ntohs(addr.sin.sin_port)
                }
                10 => {
                    name =
                        inet_ntop(10i32,
                                  &mut addr.sin6.sin6_addr as *mut in6_addr as
                                      *const libc::c_void,
                                  namebuf.as_mut_ptr(),
                                  46u32);
                    port = ntohs(addr.sin6.sin6_port)
                }
                123 => {
                    snprintf(namebuf.as_mut_ptr(),
                             46u64,
                             b"%p\x00" as *const u8 as *const libc::c_char,
                             addr.sconn.sconn_addr);
                    name = namebuf.as_mut_ptr();
                    port = ntohs(addr.sconn.sconn_port)
                }
                _ => {
                    name = 0 as *const libc::c_char;
                    port = 0u16
                }
            }
            printf(b"Msg of length %d received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u.\n\x00"
                       as *const u8 as *const libc::c_char,
                   datalen as libc::c_int, name, port as libc::c_int,
                   rcv.rcv_sid as libc::c_int, rcv.rcv_ssn as libc::c_int,
                   rcv.rcv_tsn, ntohl(rcv.rcv_ppid), rcv.rcv_context);
        }
        free(data);
    }
    return 1i32;
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
                          let mut addr =
    
    
    
        sockaddr_in6{sin6_family: 0,
                     sin6_port: 0,
                     sin6_flowinfo: 0,
                     sin6_addr:
                         in6_addr{__in6_u:
                                      C2RustUnnamed_1{__u6_addr8:  [0; 16],},},
                     sin6_scope_id: 0,}; let mut event =   
        sctp_event{se_assoc_id: 0, se_type: 0, se_on: 0,}; let mut av =   
        sctp_assoc_value{assoc_id: 0, assoc_value: 0,}; let on =    1i32; let mut i =    0u32;
    if argc > 1i32 {
        usrsctp_init(atoi(*argv.offset(1isize)) as
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
    usrsctp_sysctl_set_sctp_debug_on(0xffffffffu32);
    usrsctp_sysctl_set_sctp_blackhole(2u32);
    usrsctp_sysctl_set_sctp_no_csum_on_loopback(0u32);
     let mut sock =
    
        usrsctp_socket(10i32, SOCK_SEQPACKET as libc::c_int,
                       IPPROTO_SCTP as libc::c_int,
                       if use_cb != 0 {
                           Some(receive_cb as
                                    unsafe extern "C" fn(_: *mut socket,
                                                         _: sctp_sockstore,
                                                         _: *mut libc::c_void,
                                                         _: size_t,
                                                         _: sctp_rcvinfo,
                                                         _: libc::c_int,
                                                         _: *mut libc::c_void)
                                        -> libc::c_int)
                       } else { None }, None, 0u32,
                       0 as *mut libc::c_void);
    if sock.is_null() {
        perror(b"usrsctp_socket\x00" as *const u8 as *const libc::c_char);
    }
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0xdi32,
                          &on as *const libc::c_int as *const libc::c_void,
                          
                          ::std::mem::size_of::<libc::c_int>() as socklen_t) < 0i32 {
        perror(b"usrsctp_setsockopt SCTP_I_WANT_MAPPED_V4_ADDR\x00" as
                   *const u8 as *const libc::c_char);
    }
    memset(&mut av as *mut sctp_assoc_value as *mut libc::c_void,
           0i32,
           ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong);
    
    
    
     
    av =
    crate::discard_server::sctp_assoc_value{assoc_id:   2u32,
                                            assoc_value:   47u32, ..
    av};
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x1ai32,
                          &mut av as *mut sctp_assoc_value as
                              *const libc::c_void,
                          
                          ::std::mem::size_of::<sctp_assoc_value>() as socklen_t) < 0i32 {
        perror(b"usrsctp_setsockopt SCTP_CONTEXT\x00" as *const u8 as
                   *const libc::c_char);
    }
    if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                          0x1fi32,
                          &on as *const libc::c_int as *const libc::c_void,
                          
                          ::std::mem::size_of::<libc::c_int>() as socklen_t) < 0i32 {
        perror(b"usrsctp_setsockopt SCTP_RECVRCVINFO\x00" as *const u8 as
                   *const libc::c_char);
    }
    if argc > 2i32 {
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
    crate::discard_server::sockaddr_storage{ss_family:
                                                
                                             10u16, ..
        encaps.sue_address}; 
        encaps =
    crate::discard_server::sctp_udpencaps{sue_port:
                                              
                                          
            htons(atoi(*argv.offset(2isize)) as uint16_t), ..
        encaps};
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x24i32,
                              &mut encaps as *mut sctp_udpencaps as
                                  *const libc::c_void,
                              
                              ::std::mem::size_of::<sctp_udpencaps>() as socklen_t) <
               0i32 {
            perror(b"usrsctp_setsockopt SCTP_REMOTE_UDP_ENCAPS_PORT\x00" as
                       *const u8 as *const libc::c_char);
        }
    }
    memset(&mut event as *mut sctp_event as *mut libc::c_void,
           0i32,
           ::std::mem::size_of::<sctp_event>() as libc::c_ulong);
    
    
    
     
    event =
    crate::discard_server::sctp_event{se_assoc_id:   0u32, se_on:   1u8, ..
    event};
     
    while i <
              (::std::mem::size_of::<[uint16_t; 6]>() as
                   libc::c_ulong).wrapping_div(::std::mem::size_of::<uint16_t>()
                                                   as libc::c_ulong) as
                  libc::c_uint {
        
         
          let mut event_types =  
    
        [0x1u16, 0x2u16,
         0x3u16, 0x5u16,
         0x6u16, 0x7u16];event =
    crate::discard_server::sctp_event{se_type:
                                            event_types[i as usize], ..
        event};
        if usrsctp_setsockopt(sock, IPPROTO_SCTP as libc::c_int,
                              0x1ei32,
                              &mut event as *mut sctp_event as
                                  *const libc::c_void,
                              
                              ::std::mem::size_of::<sctp_event>() as socklen_t) <
               0i32 {
            perror(b"usrsctp_setsockopt SCTP_EVENT\x00" as *const u8 as
                       *const libc::c_char);
        }
        i = i.wrapping_add(1)
    }
    memset(&mut addr as *mut sockaddr_in6 as *mut libc::c_void,
           0i32,
           ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
    
    
    
    
    
     
    addr =
    crate::discard_server::sockaddr_in6{sin6_family:   10u16,
                                        sin6_port:   htons(9u16),
                                        sin6_addr:   in6addr_any, ..
    addr};
    if usrsctp_bind(sock, &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                    
                    ::std::mem::size_of::<sockaddr_in6>() as
                        socklen_t) < 0i32 {
        perror(b"usrsctp_bind\x00" as *const u8 as *const libc::c_char);
    }
    if usrsctp_listen(sock, 1i32) < 0i32 {
        perror(b"usrsctp_listen\x00" as *const u8 as *const libc::c_char);
    }
    loop  {
        if use_cb != 0 {
            sleep(1u32);
        } else {
                     let mut n =    0; let mut flags =    0; let mut from_len =    0; let mut buffer =    [0; 10240]; let mut name =    [0; 46]; let mut infolen =    0; let mut rcv_info =
    
    
    
        sctp_rcvinfo{rcv_sid: 0,
                     rcv_ssn: 0,
                     rcv_flags: 0,
                     rcv_ppid: 0,
                     rcv_tsn: 0,
                     rcv_cumtsn: 0,
                     rcv_context: 0,
                     rcv_assoc_id: 0,}; let mut infotype =    0;from_len =
                
                ::std::mem::size_of::<sockaddr_in6>() as
                    socklen_t;
            flags = 0i32;
            infolen =
                
                ::std::mem::size_of::<sctp_rcvinfo>() as
                    socklen_t;
            n =
                usrsctp_recvv(sock, buffer.as_mut_ptr() as *mut libc::c_void,
                              10240u64,
                              &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                              &mut from_len,
                              &mut rcv_info as *mut sctp_rcvinfo as
                                  *mut libc::c_void, &mut infolen,
                              &mut infotype, &mut flags);
            if !(n > 0i64) { break ; }
            if flags & 0x2000i32 != 0 {
                printf(b"Notification of length %llu received.\n\x00" as
                           *const u8 as *const libc::c_char,
                       n as libc::c_ulonglong);
            } else if infotype == 1u32 {
                printf(b"Msg of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u, complete %d.\n\x00"
                           as *const u8 as *const libc::c_char,
                       n as libc::c_ulonglong,
                       inet_ntop(10i32,
                                 &mut addr.sin6_addr as *mut in6_addr as
                                     *const libc::c_void, name.as_mut_ptr(),
                                 46u32),
                       ntohs(addr.sin6_port) as libc::c_int,
                       rcv_info.rcv_sid as libc::c_int,
                       rcv_info.rcv_ssn as libc::c_int, rcv_info.rcv_tsn,
                       ntohl(rcv_info.rcv_ppid), rcv_info.rcv_context,
                       if flags & MSG_EOR as libc::c_int != 0 {
                           1i32
                       } else { 0i32 });
            } else {
                printf(b"Msg of length %llu received from %s:%u, complete %d.\n\x00"
                           as *const u8 as *const libc::c_char,
                       n as libc::c_ulonglong,
                       inet_ntop(10i32,
                                 &mut addr.sin6_addr as *mut in6_addr as
                                     *const libc::c_void, name.as_mut_ptr(),
                                 46u32),
                       ntohs(addr.sin6_port) as libc::c_int,
                       if flags & MSG_EOR as libc::c_int != 0 {
                           1i32
                       } else { 0i32 });
            }
        }
    }
    usrsctp_close(sock);
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
