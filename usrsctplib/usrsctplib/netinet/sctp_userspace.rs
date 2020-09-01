use ::libc;
extern "C" {
    pub type ifnet;
    pub type iface;
    #[no_mangle]
    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn pthread_create(
        __newthread: *mut pthread_t,
        __attr: *const pthread_attr_t,
        __start_routine: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> *mut libc::c_void>,
        __arg: *mut libc::c_void,
    ) -> libc::c_int;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn if_indextoname(__ifindex: libc::c_uint, __ifname: *mut libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...) -> libc::c_int;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn prctl(__option: libc::c_int, _: ...) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint32_t = libc::c_uint;
pub type __caddr_t = *mut libc::c_char;
pub type pthread_t = libc::c_ulong;

#[repr(C)]
#[derive(Copy, Clone)]
pub union pthread_attr_t {
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint32_t = __uint32_t;
pub type userland_thread_t = pthread_t;
/* sys/mutex.h typically on FreeBSD */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mtx {
    pub dummy: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_714,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_714 {
    pub ifu_broadaddr: sockaddr,
    pub ifu_dstaddr: sockaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifmap {
    pub mem_start: libc::c_ulong,
    pub mem_end: libc::c_ulong,
    pub base_addr: libc::c_ushort,
    pub irq: libc::c_uchar,
    pub dma: libc::c_uchar,
    pub port: libc::c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifr_ifrn: C2RustUnnamed_716,
    pub ifr_ifru: C2RustUnnamed_715,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_715 {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: libc::c_short,
    pub ifru_ivalue: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_map: ifmap,
    pub ifru_slave: [libc::c_char; 16],
    pub ifru_newname: [libc::c_char; 16],
    pub ifru_data: __caddr_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_716 {
    pub ifrn_name: [libc::c_char; 16],
}
/* MTU for this path */
/*
 * We distinguish between routes to hosts and routes to networks,
 * preferring the former if available.  For each route we infer
 * the interface to use from the gateway address supplied when
 * the route was entered.  Routes that forward packets through
 * gateways are marked so that the output routines know to address the
 * gateway rather than the ultimate destination.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_rtentry {
    pub rt_ifp: *mut ifnet,
    pub rt_ifa: *mut ifaddr,
    pub rt_rmx: sctp_rt_metrics_lite,
    pub rt_refcnt: libc::c_long,
    pub rt_mtx: mtx,
}
/*
 * These numbers are used by reliable protocols for determining
 * retransmission behavior and are included in the routing structure.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_rt_metrics_lite {
    pub rmx_mtu: uint32_t,
}
pub type sctp_rtentry_t = sctp_rtentry;
pub type start_routine_t = Option<unsafe extern "C" fn(_: *mut libc::c_void) -> *mut libc::c_void>;
/*-
 * Copyright (c) 2011-2012 Irene Ruengeler
 * Copyright (c) 2011-2012 Michael Tuexen
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
 *
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_userspace_thread_create(
    mut thread: *mut userland_thread_t,
    mut start_routine: start_routine_t,
) -> libc::c_int {
    return pthread_create(
        thread,
        0 as *const pthread_attr_t,
        start_routine,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn sctp_userspace_set_threadname(mut name: *const libc::c_char) {
    prctl(15i32, name);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_userspace_get_mtu_from_ifn(
    mut if_index: uint32_t,
    mut af: libc::c_int,
) -> libc::c_int {
    let mut ifr = ifreq {
        ifr_ifrn: C2RustUnnamed_716 { ifrn_name: [0; 16] },
        ifr_ifru: C2RustUnnamed_715 {
            ifru_addr: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    memset(
        &mut ifr as *mut ifreq as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<ifreq>() as libc::c_ulong,
    );
    if !if_indextoname(if_index, ifr.ifr_ifrn.ifrn_name.as_mut_ptr()).is_null() {
        let mut fd = 0;
        fd = socket(af, SOCK_DGRAM as libc::c_int, 0i32);
        if fd < 0i32 {
            return 0i32;
        }
        if ioctl(fd, 0x8921u64, &mut ifr as *mut ifreq) < 0i32 {
            close(fd);
            return 0i32;
        }
        close(fd);
        return ifr.ifr_ifru.ifru_mtu;
    } else {
        return 0i32;
    };
}
/* #include <sys/param.h>  in FreeBSD defines MSIZE */
/* #include <sys/ktr.h> */
/* #include <sys/systm.h> */
/* #include <sys/kernel.h> */
/* #include <sys/sysctl.h> */
/* #include <sys/protosw.h> */
/* on FreeBSD, this results in a redefintion of SOCK(BUF)_(UN)LOCK and
 *  uknown type of struct mtx for sb_mtx in struct sockbuf */
/* #include <sys/jail.h> */
/* #include <sys/sysctl.h> */
/* #include <sys/uio.h> */
/* #include <sys/lock.h> */
/* #include <sys/kthread.h> */
/* #include <sys/random.h> */
/* #include <machine/cpu.h> */
/* OOTB only - dummy route used at the moment. should we port route to
 *  userspace as well? */
/* on FreeBSD, this results in a redefintion of struct route */
/* #include <net/route.h> */
/* #include <netinet/in_pcb.h> ported to userspace */
/* for getifaddrs */
/* for ioctl */
/* for close, etc. */
/* lots of errno's used and needed in userspace */
/* for offsetof */
/* for pthread_mutex_lock, pthread_mutex_unlock, etc. */
/* IPSEC */
/* INET6 */
/* Declare all the malloc names for all the various mallocs */
/* Empty ktr statement for _Userspace__ (similar to what is done for mac) */
/*
 *
 */
/* FIX ME: temp */
/*
 * Local address and interface list handling
 */
/* BSD definition */
/* #define SCTP_ROUTE_IS_REAL_LOOP(ro) ((ro)->ro_rt && (ro)->ro_rt->rt_ifa && (ro)->ro_rt->rt_ifa->ifa_ifp && (ro)->ro_rt->rt_ifa->ifa_ifp->if_type == IFT_LOOP) */
/* only used in IPv6 scenario, which isn't supported yet */
/*
 * Access to IFN's to help with src-addr-selection
 */
/* This could return VOID if the index works but for BSD we provide both. */
/* compiles...  TODO use routing socket to determine */
/*
 * general memory allocation
 */
/*
 * zone allocation functions
 */
/*typedef size_t sctp_zone_t;*/
/* __Userspace__ SCTP_ZONE_GET: allocate element from the zone */
/* __Userspace__ SCTP_ZONE_FREE: free element from the zone */
/*
 * __Userspace__ Defining sctp_hashinit_flags() and sctp_hashdestroy() for userland.
 */
/* M_PCB is MALLOC_DECLARE'd in sys/socketvar.h */
/*
 * timers
 */
/* __Userspace__
 * user_sctp_callout.h has typedef struct sctp_callout sctp_os_timer_t;
 * which is used in the timer related functions such as
 * SCTP_OS_TIMER_INIT etc.
*/
/* __Userspace__ Creating a receive thread */
/*__Userspace__ defining KTR_SUBSYS 1 as done in sctp_os_macosx.h */
/* The packed define for 64 bit platforms */
/*
 * Functions
 */
/* Mbuf manipulation and access macros  */
/* We make it so if you have up to 4 threads
 * writting based on the default size of
 * the packet log 65 k, that would be
 * 4 16k packets before we would hit
 * a problem.
 */
/*
 * routes, output, etc.
 */
/* initialize */
/* set MTU */
/* TODO set this based on the ro->ro_dst, looking up MTU with routing socket */
/* FIXME temporary solution */
/* TODO enable the ability to obtain interface index of route for
 *  SCTP_GET_IF_INDEX_FROM_ROUTE macro.
 */
/* dummy rtfree needed once user_route.h is included */
/* ************************/
/*      MTU              */
/* ************************/
/* (de-)register interface event notifications */
/* ************************/
/* These are for logging */
/* ************************/
/* return the base ext data pointer */
/* return the refcnt of the data pointer */
/* return any buffer related flags, this is
 * used beyond logging for apple only.
 */
/* For BSD this just accesses the M_PKTHDR length
 * so it operates on an mbuf with hdr flag. Other
 * O/S's may have seperate packet header and mbuf
 * chain pointers.. thus the macro.
 */
/* Attach the chain of data into the sendable packet. */
/* Other m_pkthdr type things */
/* FIXME need real definitions */
/* OOTB only #define SCTP_IS_IT_BROADCAST(dst, m) ((m->m_flags & M_PKTHDR) ? in_broadcast(dst, m->m_pkthdr.rcvif) : 0)  BSD def */
/* OOTB ONLY #define SCTP_IS_IT_LOOPBACK(m) ((m->m_flags & M_PKTHDR) && ((m->m_pkthdr.rcvif == NULL) || (m->m_pkthdr.rcvif->if_type == IFT_LOOP)))  BSD def */
/* This converts any input packet header
 * into the chain of data holders, for BSD
 * its a NOP.
 */
/* get the v6 hop limit */
/* As done for __Windows__ */
/* is the endpoint v6only? */
/* is the socket non-blocking? */
/* get the socket type */
/* reserve sb space for a socket */
/* wakeup a socket */
/* clear the socket buffer state */
/* start OOTB only stuff */
/* TODO IFT_LOOP is in net/if_types.h on Linux */
/* sctp_pcb.h */
/* netinet/ip_var.h defintions are behind an if defined for _KERNEL on FreeBSD */
/* end OOTB only stuff */
/*
 * SCTP protocol specific mbuf flags.
 */
/* SCTP notification */
/*
 * IP output routines
 */
/* Defining SCTP_IP_ID macro.
  In netinet/ip_output.c, we have u_short ip_id;
  In netinet/ip_var.h, we have extern u_short	ip_id; (enclosed within _KERNEL_)
  See static __inline uint16_t ip_newid(void) in netinet/ip_var.h
*/
/* need sctphdr to get port in SCTP_IP_OUTPUT. sctphdr defined in sctp.h  */
/* with the current included files, this is defined in Linux but
 *  in FreeBSD, it is behind a _KERNEL in sys/socket.h ...
 */
#[no_mangle]
pub unsafe extern "C" fn timingsafe_bcmp(
    mut b1: *const libc::c_void,
    mut b2: *const libc::c_void,
    mut n: size_t,
) -> libc::c_int {
    let mut ret = 0i32;
    let mut p1 = b1 as *const libc::c_uchar;
    let mut p2 = b2 as *const libc::c_uchar;

    while n > 0u64 {
        let fresh0 = p1;
        p1 = p1.offset(1);
        let fresh1 = p2;
        p2 = p2.offset(1);
        ret |= *fresh0 as libc::c_int ^ *fresh1 as libc::c_int;
        n = n.wrapping_sub(1)
    }
    return (ret != 0i32) as libc::c_int;
}
