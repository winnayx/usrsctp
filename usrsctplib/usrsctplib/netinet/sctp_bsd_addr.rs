use ::libc;
extern "C" {
    pub type witness;
    pub type accept_filter;
    pub type label;
    pub type ifnet;
    pub type aiocblist;
    pub type sigio;
    pub type iface;
    /*-
     * Copyright (c) 1982, 1986, 1990, 1993
     *	The Regents of the University of California.  All rights reserved.
     *
     * Redistribution and use in source and binary forms, with or without
     * modification, are permitted provided that the following conditions
     * are met:
     * 1. Redistributions of source code must retain the above copyright
     *    notice, this list of conditions and the following disclaimer.
     * 2. Redistributions in binary form must reproduce the above copyright
     *    notice, this list of conditions and the following disclaimer in the
     *    documentation and/or other materials provided with the distribution.
     * 4. Neither the name of the University nor the names of its contributors
     *    may be used to endorse or promote products derived from this software
     *    without specific prior written permission.
     *
     * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
     * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
     * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
     * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
     * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
     * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
     * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
     * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
     * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
     * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
     * SUCH DAMAGE.
     *
     *	@(#)in_pcb.h	8.1 (Berkeley) 6/10/93
     * $FreeBSD: src/sys/netinet/in_pcb.h,v 1.100.2.1 2007/12/07 05:46:08 kmacy Exp $
     */
    pub type inpcbpolicy;
    /*
     * PCB with AF_INET6 null bind'ed laddr can receive AF_INET input packet.
     * So, AF_INET6 null laddr is also used as AF_INET null laddr, by utilizing
     * the following structure.
     */
    /*
     * NOTE: ipv6 addrs should be 64-bit aligned, per RFC 2553.  in_conninfo has
     * some extra padding to accomplish this.
     */
    /* foreign port */
    /* local port */
    /* protocol dependent part, local and foreign addr */
    /* foreign host table entry */
    /* local host table entry */
    /*
     * XXX The defines for inc_* are hacks and should be changed to direct
     * references.
     */
    /* XXX alignment for in_endpoints */
    /* protocol dependent part */
    /* temp compatibility */
    pub type icmp6_filter;
    pub type ip6_pktopts;
    pub type ip_moptions;
    pub type uma_zone;
    #[no_mangle]
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_cond_broadcast(__cond: *mut pthread_cond_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_cond_wait(__cond: *mut pthread_cond_t, __mutex: *mut pthread_mutex_t)
        -> libc::c_int;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn m_getm2(
        m: *mut mbuf,
        len: libc::c_int,
        how: libc::c_int,
        type_0: libc::c_short,
        flags: libc::c_int,
        allonebuf: libc::c_int,
    ) -> *mut mbuf;
    #[no_mangle]
    fn if_nametoindex(__ifname: *const libc::c_char) -> libc::c_uint;
    #[no_mangle]
    fn getifaddrs(__ifap: *mut *mut ifaddrs) -> libc::c_int;
    #[no_mangle]
    fn freeifaddrs(__ifa: *mut ifaddrs);
    #[no_mangle]
    fn sctp_userspace_thread_create(
        thread: *mut userland_thread_t,
        start_routine: start_routine_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_userspace_set_threadname(name: *const libc::c_char);
    /* TODO where to put non-_KERNEL things for __Userspace__? */
    /* Attention Julian, this is the extern that
     * goes with the base info. sctp_pcb.c has
     * the real definition.
     */
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_allocate_vrf(vrfid: libc::c_int) -> *mut sctp_vrf;
    #[no_mangle]
    fn sctp_add_addr_to_vrf(
        vrfid: uint32_t,
        ifn: *mut libc::c_void,
        ifn_index: uint32_t,
        ifn_type: uint32_t,
        if_name: *const libc::c_char,
        ifa: *mut libc::c_void,
        addr: *mut sockaddr,
        ifa_flags: uint32_t,
        dynamic_add: libc::c_int,
    ) -> *mut sctp_ifa;
    #[no_mangle]
    fn sctp_iterator_worker();
}
pub type size_t = libc::c_ulong;
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int16_t = libc::c_short;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __caddr_t = *mut libc::c_char;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type caddr_t = __caddr_t;
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
pub type __pthread_list_t = __pthread_internal_list;

#[repr(C)]
#[derive(Copy, Clone)]
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct __pthread_cond_s {
    pub c2rust_unnamed: C2RustUnnamed_108,
    pub c2rust_unnamed_0: C2RustUnnamed_106,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_106 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_107,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_107 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_108 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_109,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_109 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}
pub type pthread_t = libc::c_ulong;

#[repr(C)]
#[derive(Copy, Clone)]
pub union pthread_mutexattr_t {
    pub __size: [libc::c_char; 4],
    pub __align: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [libc::c_char; 40],
    pub __align: libc::c_long,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union pthread_cond_t {
    pub __data: __pthread_cond_s,
    pub __size: [libc::c_char; 48],
    pub __align: libc::c_longlong,
}
pub type sa_family_t = libc::c_ushort;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ucred {
    pub pid: pid_t,
    pub uid: uid_t,
    pub gid: gid_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
pub type uint32_t = __uint32_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_110,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_110 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
pub type in_port_t = uint16_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2006-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2011, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2011, by Michael Tuexen. All rights reserved.
 * Copyright (c) 2008-2011, by Brad Penoff. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Userspace includes
 * All the opt_xxx.h files are placed in the kernel build directory.
 * We will place them in userspace stack build directory.
 */
/* !defined(Userspace_os_Windows) */
pub type userland_mutex_t = pthread_mutex_t;
pub type userland_cond_t = pthread_cond_t;
pub type userland_thread_t = pthread_t;
/* sys/mutex.h typically on FreeBSD */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mtx {
    pub dummy: libc::c_int,
}
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
/*
 * ABI-compatible version of the old 'struct malloc_type', only all stats are
 * now malloc-managed in malloc-owned memory rather than in caller memory, so
 * as to avoid ABI issues.  The ks_next pointer is reused as a pointer to the
 * internal data handle.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct malloc_type {
    pub ks_next: *mut malloc_type,
    pub _ks_memuse: u_long,
    pub _ks_size: u_long,
    pub _ks_inuse: u_long,
    pub _ks_calls: uint64_t,
    pub _ks_maxused: u_long,
    pub ks_magic: u_long,
    pub ks_shortdesc: *const libc::c_char,
    pub ks_handle: *mut libc::c_void,
    pub _lo_name: *const libc::c_char,
    pub _lo_type: *const libc::c_char,
    pub _lo_flags: u_int,
    pub _lo_list_next: *mut libc::c_void,
    pub _lo_witness: *mut witness,
    pub _mtx_lock: uintptr_t,
    pub _mtx_recurse: u_int,
}
/* operation */
/* __Userspace__ */
/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
/*-
 * Locking key to struct socket:
 * (a) constant after allocation, no locking required.
 * (b) locked by SOCK_LOCK(so).
 * (c) locked by SOCKBUF_LOCK(&so->so_rcv).
 * (d) locked by SOCKBUF_LOCK(&so->so_snd).
 * (e) locked by ACCEPT_LOCK().
 * (f) not locked since integer reads/writes are atomic.
 * (g) used only as a sleep/wakeup address, no value.
 * (h) locked by global mutex so_global_mtx.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct socket {
    pub so_count: libc::c_int,
    pub so_type: libc::c_short,
    pub so_options: libc::c_short,
    pub so_linger: libc::c_short,
    pub so_state: libc::c_short,
    pub so_qstate: libc::c_int,
    pub so_pcb: *mut libc::c_void,
    pub so_dom: libc::c_int,
    pub so_head: *mut socket,
    pub so_incomp: C2RustUnnamed_118,
    pub so_comp: C2RustUnnamed_117,
    pub so_list: C2RustUnnamed_116,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_115,
    pub so_rcv: sockbuf,
    pub so_snd: sockbuf,
    pub so_upcall:
        Option<unsafe extern "C" fn(_: *mut socket, _: *mut libc::c_void, _: libc::c_int) -> ()>,
    pub so_upcallarg: *mut libc::c_void,
    pub so_cred: *mut ucred,
    pub so_label: *mut label,
    pub so_peerlabel: *mut label,
    pub so_gencnt: uint32_t,
    pub so_emuldata: *mut libc::c_void,
    pub so_accf: *mut so_accf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct so_accf {
    pub so_accept_filter: *mut accept_filter,
    pub so_accept_filter_arg: *mut libc::c_void,
    pub so_accept_filter_str: *mut libc::c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockbuf {
    pub sb_cond: userland_cond_t,
    pub sb_mtx: userland_mutex_t,
    pub sb_state: libc::c_short,
    pub sb_mb: *mut mbuf,
    pub sb_mbtail: *mut mbuf,
    pub sb_lastrecord: *mut mbuf,
    pub sb_sndptr: *mut mbuf,
    pub sb_sndptroff: u_int,
    pub sb_cc: u_int,
    pub sb_hiwat: u_int,
    pub sb_mbcnt: u_int,
    pub sb_mbmax: u_int,
    pub sb_ctl: u_int,
    pub sb_lowat: libc::c_int,
    pub sb_timeo: libc::c_int,
    pub sb_flags: libc::c_short,
}
/* type of external storage */
/*
 * The core of the mbuf object along with some shortcut defined for practical
 * purposes.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mbuf {
    pub m_hdr: m_hdr,
    pub M_dat: C2RustUnnamed_111,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_111 {
    pub MH: C2RustUnnamed_112,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_112 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_113,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_113 {
    pub MH_ext: m_ext,
    pub MH_databuf: [libc::c_char; 176],
}
/* mbuf initialization function */
/* modified for __Userspace__ */
/* Length to m_copy to copy all. */
/* umem_cache_t is defined in user_include/umem.h as
 * typedef struct umem_cache umem_cache_t;
 * Note:umem_zone_t is a pointer.
 */
/*-
 * Macros for type conversion:
 * mtod(m, t)	-- Convert mbuf pointer to data pointer of correct type.
 * dtom(x)	-- Convert data pointer within mbuf to mbuf pointer (XXX).
 */
/* Flags for mbuf being allocated */
/* Type of mbuf being allocated */
/* Not a type but a flag to allocate
a non-initialized mbuf */
/*
 * General mbuf allocator statistics structure.
 * __Userspace__ mbstat may be useful for gathering statistics.
 * In the kernel many of these statistics are no longer used as
 * they track allocator statistics through kernel UMA's built in statistics mechanism.
 */
/* XXX */
/* XXX */
/* times drained protocols for space */
/* XXX: times m_copym failed */
/* XXX: times m_pullup failed */
/* length of an mbuf */
/* length of an mbuf cluster */
/* min length of data to allocate a cluster */
/* length of data in an mbuf */
/* length of data in a header mbuf */
/* Number of mbtypes (gives # elems in mbtypes[] array: */
/* XXX: Sendfile stats should eventually move to their own struct */
/* times sendfile had to do disk I/O */
/* times sfbuf allocation failed */
/* times sfbuf allocation had to wait */
/*
 * Mbufs are of a single size, MSIZE (sys/param.h), which includes overhead.
 * An mbuf may add a single "mbuf cluster" of size MCLBYTES (also in
 * sys/param.h), which has no additional overhead and is used instead of the
 * internal data area; this is done when at least MINCLSIZE of data must be
 * stored.  Additionally, it is possible to allocate a separate buffer
 * externally and attach it to the mbuf in a way similar to that of mbuf
 * clusters.
 */
/* normal data len */
/* data len w/pkthdr */
/* smallest amount to put in cluster */
/* max amount to copy for compression */
/*
 * Header present at the beginning of every mbuf.
 */
/* next buffer in chain */
/* next chain in queue/record */
/* location of data */
/* amount of data in this mbuf */
/* flags; see below */
/* type of data in this mbuf */
/* word align                  */
/*
 * Packet tag structure (see below for details).
 */
/* List of packet tags */
/* Tag ID */
/* Length of data */
/* ABI/Module ID */
/*
 * Record/packet header in first mbuf of chain; valid only if M_PKTHDR is set.
 */
/* rcv interface */
/* variables for ip and tcp reassembly */
/* pointer to packet header */
/* total packet length */
/* variables for hardware checksum */
/* flags regarding checksum */
/* data field used by csum routines */
/* TSO segment size */
/* Ethernet 802.1p+q vlan tag */
/* list of packet tags */
/*
 * Description of external storage mapped into mbuf; valid only if M_EXT is
 * set.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct m_ext {
    pub ext_buf: caddr_t,
    pub ext_free: Option<unsafe extern "C" fn(_: *mut libc::c_void, _: *mut libc::c_void) -> ()>,
    pub ext_args: *mut libc::c_void,
    pub ext_size: u_int,
    pub ref_cnt: *mut u_int,
    pub ext_type: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pkthdr {
    pub rcvif: *mut ifnet,
    pub header: *mut libc::c_void,
    pub len: libc::c_int,
    pub csum_flags: libc::c_int,
    pub csum_data: libc::c_int,
    pub tso_segsz: u_int16_t,
    pub ether_vtag: u_int16_t,
    pub tags: packet_tags,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct packet_tags {
    pub slh_first: *mut m_tag,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct m_tag {
    pub m_tag_link: C2RustUnnamed_114,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_114 {
    pub sle_next: *mut m_tag,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct m_hdr {
    pub mh_next: *mut mbuf,
    pub mh_nextpkt: *mut mbuf,
    pub mh_data: caddr_t,
    pub mh_len: libc::c_int,
    pub mh_flags: libc::c_int,
    pub mh_type: libc::c_short,
    pub pad: [uint8_t; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_115 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_116 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_117 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_118 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}
pub type sctp_zone_t = size_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_119,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_119 {
    pub ifu_broadaddr: sockaddr,
    pub ifu_dstaddr: sockaddr,
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
/*
 * Struct inpcb is the ommon structure pcb for the Internet Protocol
 * implementation.
 *
 * Pointers to local and foreign host table entries, local and foreign socket
 * numbers, and pointers up (to a socket structure) and down (to a
 * protocol-specific control block) are stored here.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbhead {
    pub lh_first: *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcb {
    pub inp_hash: C2RustUnnamed_127,
    pub inp_list: C2RustUnnamed_126,
    pub inp_ppcb: *mut libc::c_void,
    pub inp_pcbinfo: *mut inpcbinfo,
    pub inp_socket: *mut socket,
    pub inp_flow: u_int32_t,
    pub inp_flags: libc::c_int,
    pub inp_vflag: u_char,
    pub inp_ip_ttl: u_char,
    pub inp_ip_p: u_char,
    pub inp_ip_minttl: u_char,
    pub inp_ispare1: uint32_t,
    pub inp_pspare: [*mut libc::c_void; 2],
    pub inp_inc: in_conninfo,
    pub inp_label: *mut label,
    pub inp_sp: *mut inpcbpolicy,
    pub inp_depend4: C2RustUnnamed_123,
    pub inp_depend6: C2RustUnnamed_122,
    pub inp_portlist: C2RustUnnamed_121,
    pub inp_phd: *mut inpcbport,
    pub inp_mtx: mtx,
}
/* default hop limit */
/* for KAME src sync over BSD*'s */
/* for KAME src sync over BSD*'s */
/* for KAME src sync over BSD*'s */
/* for KAME src sync over BSD*'s */
/* for KAME src sync over BSD*'s */
/*
 * The range of the generation count, as used in this implementation, is 9e19.
 * We would have to create 300 billion connections per second for this number
 * to roll over in a year.  This seems sufficiently unlikely that we simply
 * don't concern ourselves with that possibility.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbport {
    pub phd_hash: C2RustUnnamed_120,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_120 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_121 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_122 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_123 {
    pub inp4_ip_tos: u_char,
    pub inp4_options: *mut mbuf,
    pub inp4_moptions: *mut ip_moptions,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_conninfo {
    pub inc_flags: u_int8_t,
    pub inc_len: u_int8_t,
    pub inc_pad: u_int16_t,
    pub inc_ie: in_endpoints,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_endpoints {
    pub ie_fport: u_int16_t,
    pub ie_lport: u_int16_t,
    pub ie_dependfaddr: C2RustUnnamed_125,
    pub ie_dependladdr: C2RustUnnamed_124,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_124 {
    pub ie46_local: in_addr_4in6,
    pub ie6_local: in6_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_addr_4in6 {
    pub ia46_pad32: [u_int32_t; 3],
    pub ia46_addr4: in_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_125 {
    pub ie46_foreign: in_addr_4in6,
    pub ie6_foreign: in6_addr,
}
/*
 * Global data structure for each high-level protocol (UDP, TCP, ...) in both
 * IPv4 and IPv6.  Holds inpcb lists and information for managing them.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbinfo {
    pub ipi_listhead: *mut inpcbhead,
    pub ipi_count: u_int,
    pub ipi_hashbase: *mut inpcbhead,
    pub ipi_hashmask: u_long,
    pub ipi_porthashbase: *mut inpcbporthead,
    pub ipi_porthashmask: u_long,
    pub ipi_lastport: u_short,
    pub ipi_lastlow: u_short,
    pub ipi_lasthi: u_short,
    pub ipi_zone: *mut uma_zone,
    pub ipi_mtx: mtx,
    pub ipi_pspare: [*mut libc::c_void; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbporthead {
    pub lh_first: *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_126 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_127 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut libc::c_char,
    pub ifa_flags: libc::c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: C2RustUnnamed_128,
    pub ifa_data: *mut libc::c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_128 {
    pub ifu_broadaddr: *mut sockaddr,
    pub ifu_dstaddr: *mut sockaddr,
}
pub type sctp_rtentry_t = sctp_rtentry;
pub type end_func = Option<unsafe extern "C" fn(_: *mut libc::c_void, _: uint32_t) -> ()>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_158,
    pub tmr: sctp_timer,
    pub inp: *mut sctp_inpcb,
    pub stcb: *mut sctp_tcb,
    pub next_inp: *mut sctp_inpcb,
    pub function_assoc: asoc_func,
    pub function_inp: inp_func,
    pub function_inp_end: inp_func,
    pub function_atend: end_func,
    pub pointer: *mut libc::c_void,
    pub val: uint32_t,
    pub pcb_flags: uint32_t,
    pub pcb_features: uint32_t,
    pub asoc_state: uint32_t,
    pub iterator_flags: uint32_t,
    pub no_chunk_output: uint8_t,
    pub done_current_ep: uint8_t,
}
pub type inp_func = Option<
    unsafe extern "C" fn(_: *mut sctp_inpcb, _: *mut libc::c_void, _: uint32_t) -> libc::c_int,
>;
/* we choose the number to make a pcb a page */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_157,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_156,
    pub sctp_hash: C2RustUnnamed_155,
    pub laddr_count: libc::c_int,
    pub sctp_addr_list: sctpladdr,
    pub next_addr_touse: *mut sctp_laddr,
    pub sctp_socket: *mut socket,
    pub sctp_features: uint64_t,
    pub sctp_flags: uint32_t,
    pub sctp_mobility_features: uint32_t,
    pub sctp_ep: sctp_pcb,
    pub sctp_tcbhash: *mut sctpasochead,
    pub sctp_hashmark: u_long,
    pub sctp_asoc_list: sctpasochead,
    pub inp_starting_point_for_iterator: *mut sctp_iterator,
    pub sctp_frag_point: uint32_t,
    pub partial_delivery_point: uint32_t,
    pub sctp_context: uint32_t,
    pub max_cwnd: uint32_t,
    pub local_strreset_support: uint8_t,
    pub sctp_cmt_on_off: uint32_t,
    pub ecn_supported: uint8_t,
    pub prsctp_supported: uint8_t,
    pub auth_supported: uint8_t,
    pub idata_supported: uint8_t,
    pub asconf_supported: uint8_t,
    pub reconfig_supported: uint8_t,
    pub nrsack_supported: uint8_t,
    pub pktdrop_supported: uint8_t,
    pub def_send: sctp_nonpad_sndrcvinfo,
    pub pkt: *mut mbuf,
    pub pkt_last: *mut mbuf,
    pub control: *mut mbuf,
    pub inp_mtx: userland_mutex_t,
    pub inp_create_mtx: userland_mutex_t,
    pub inp_rdata_mtx: userland_mutex_t,
    pub refcount: int32_t,
    pub def_vrf_id: uint32_t,
    pub fibnum: uint16_t,
    pub total_sends: uint32_t,
    pub total_recvs: uint32_t,
    pub last_abort_code: uint32_t,
    pub total_nospaces: uint32_t,
    pub sctp_asocidhash: *mut sctpasochead,
    pub hashasocidmark: u_long,
    pub sctp_associd_counter: uint32_t,
    pub ulp_info: *mut libc::c_void,
    pub recv_callback: Option<
        unsafe extern "C" fn(
            _: *mut socket,
            _: sctp_sockstore,
            _: *mut libc::c_void,
            _: size_t,
            _: sctp_rcvinfo,
            _: libc::c_int,
            _: *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub send_sb_threshold: uint32_t,
    pub send_callback: Option<unsafe extern "C" fn(_: *mut socket, _: uint32_t) -> libc::c_int>,
}

#[repr(C)]
#[derive(Copy, Clone)]
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
pub type sctp_assoc_t = uint32_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub union sctp_sockstore {
    pub sin: sockaddr_in,
    pub sin6: sockaddr_in6,
    pub sconn: sockaddr_conn,
    pub sa: sockaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_conn {
    pub sconn_family: uint16_t,
    pub sconn_port: uint16_t,
    pub sconn_addr: *mut libc::c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpasochead {
    pub lh_first: *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_154,
    pub sctp_tcblist: C2RustUnnamed_153,
    pub sctp_tcbasocidhash: C2RustUnnamed_152,
    pub sctp_asocs: C2RustUnnamed_151,
    pub block_entry: *mut sctp_block_entry,
    pub asoc: sctp_association,
    pub freed_by_sorcv_sincelast: uint32_t,
    pub total_sends: uint32_t,
    pub total_recvs: uint32_t,
    pub freed_from_where: libc::c_int,
    pub rport: uint16_t,
    pub resv: uint16_t,
    pub tcb_mtx: userland_mutex_t,
    pub tcb_send_mtx: userland_mutex_t,
}
/*
 * Here we have information about each individual association that we track.
 * We probably in production would be more dynamic. But for ease of
 * implementation we will have a fixed array that we hunt for in a linear
 * fashion.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_association {
    pub state: libc::c_int,
    pub asconf_queue: sctp_asconf_addrhead,
    pub time_entered: timeval,
    pub time_last_rcvd: timeval,
    pub time_last_sent: timeval,
    pub time_last_sat_advance: timeval,
    pub def_send: sctp_nonpad_sndrcvinfo,
    pub dack_timer: sctp_timer,
    pub asconf_timer: sctp_timer,
    pub strreset_timer: sctp_timer,
    pub shut_guard_timer: sctp_timer,
    pub autoclose_timer: sctp_timer,
    pub delayed_event_timer: sctp_timer,
    pub delete_prim_timer: sctp_timer,
    pub sctp_restricted_addrs: sctpladdr,
    pub asconf_addr_del_pending: *mut sctp_ifa,
    pub deleted_primary: *mut sctp_nets,
    pub nets: sctpnetlisthead,
    pub free_chunks: sctpchunk_listhead,
    pub control_send_queue: sctpchunk_listhead,
    pub asconf_send_queue: sctpchunk_listhead,
    pub sent_queue: sctpchunk_listhead,
    pub send_queue: sctpchunk_listhead,
    pub ss_data: scheduling_data,
    pub stcb_starting_point_for_iterator: *mut sctp_iterator,
    pub asconf_ack_sent: sctp_asconf_ackhead,
    pub str_reset: *mut sctp_tmit_chunk,
    pub last_used_address: *mut sctp_laddr,
    pub strmin: *mut sctp_stream_in,
    pub strmout: *mut sctp_stream_out,
    pub mapping_array: *mut uint8_t,
    pub primary_destination: *mut sctp_nets,
    pub alternate: *mut sctp_nets,
    pub last_net_cmt_send_started: *mut sctp_nets,
    pub last_data_chunk_from: *mut sctp_nets,
    pub last_control_chunk_from: *mut sctp_nets,
    pub resetHead: sctp_resethead,
    pub pending_reply_queue: sctp_readhead,
    pub cc_functions: sctp_cc_functions,
    pub congestion_control_module: uint32_t,
    pub ss_functions: sctp_ss_functions,
    pub stream_scheduling_module: uint32_t,
    pub vrf_id: uint32_t,
    pub cookie_preserve_req: uint32_t,
    pub asconf_seq_out: uint32_t,
    pub asconf_seq_out_acked: uint32_t,
    pub asconf_seq_in: uint32_t,
    pub str_reset_seq_out: uint32_t,
    pub str_reset_seq_in: uint32_t,
    pub my_vtag: uint32_t,
    pub peer_vtag: uint32_t,
    pub my_vtag_nonce: uint32_t,
    pub peer_vtag_nonce: uint32_t,
    pub assoc_id: uint32_t,
    pub smallest_mtu: uint32_t,
    pub this_sack_highest_gap: uint32_t,
    pub last_acked_seq: uint32_t,
    pub sending_seq: uint32_t,
    pub init_seq_number: uint32_t,
    pub advanced_peer_ack_point: uint32_t,
    pub cumulative_tsn: uint32_t,
    pub mapping_array_base_tsn: uint32_t,
    pub highest_tsn_inside_map: uint32_t,
    pub nr_mapping_array: *mut uint8_t,
    pub highest_tsn_inside_nr_map: uint32_t,
    pub fast_recovery_tsn: uint32_t,
    pub sat_t3_recovery_tsn: uint32_t,
    pub tsn_last_delivered: uint32_t,
    pub control_pdapi: *mut sctp_queued_to_read,
    pub tsn_of_pdapi_last_delivered: uint32_t,
    pub pdapi_ppid: uint32_t,
    pub context: uint32_t,
    pub last_reset_action: [uint32_t; 2],
    pub last_sending_seq: [uint32_t; 2],
    pub last_base_tsnsent: [uint32_t; 2],
    pub peers_rwnd: uint32_t,
    pub my_rwnd: uint32_t,
    pub my_last_reported_rwnd: uint32_t,
    pub sctp_frag_point: uint32_t,
    pub total_output_queue_size: uint32_t,
    pub sb_cc: uint32_t,
    pub sb_send_resv: uint32_t,
    pub my_rwnd_control_len: uint32_t,
    pub default_flowlabel: uint32_t,
    pub pr_sctp_cnt: uint32_t,
    pub ctrl_queue_cnt: libc::c_int,
    pub stream_queue_cnt: libc::c_uint,
    pub send_queue_cnt: libc::c_uint,
    pub sent_queue_cnt: libc::c_uint,
    pub sent_queue_cnt_removeable: libc::c_uint,
    pub sent_queue_retran_cnt: libc::c_uint,
    pub size_on_reasm_queue: libc::c_uint,
    pub cnt_on_reasm_queue: libc::c_uint,
    pub fwd_tsn_cnt: libc::c_uint,
    pub total_flight: libc::c_uint,
    pub total_flight_count: libc::c_uint,
    pub numnets: libc::c_uint,
    pub overall_error_count: libc::c_uint,
    pub cnt_msg_on_sb: libc::c_uint,
    pub size_on_all_streams: libc::c_uint,
    pub cnt_on_all_streams: libc::c_uint,
    pub heart_beat_delay: uint32_t,
    pub sctp_autoclose_ticks: libc::c_uint,
    pub pre_open_streams: libc::c_uint,
    pub max_inbound_streams: libc::c_uint,
    pub cookie_life: libc::c_uint,
    pub delayed_ack: libc::c_uint,
    pub old_delayed_ack: libc::c_uint,
    pub sack_freq: libc::c_uint,
    pub data_pkts_seen: libc::c_uint,
    pub numduptsns: libc::c_uint,
    pub dup_tsns: [libc::c_int; 20],
    pub initial_init_rto_max: libc::c_uint,
    pub initial_rto: libc::c_uint,
    pub minrto: libc::c_uint,
    pub maxrto: libc::c_uint,
    pub local_auth_chunks: *mut sctp_auth_chklist_t,
    pub peer_auth_chunks: *mut sctp_auth_chklist_t,
    pub local_hmacs: *mut sctp_hmaclist_t,
    pub peer_hmacs: *mut sctp_hmaclist_t,
    pub shared_keys: sctp_keyhead,
    pub authinfo: sctp_authinfo_t,
    pub refcnt: uint32_t,
    pub chunks_on_out_queue: uint32_t,
    pub peers_adaptation: uint32_t,
    pub default_mtu: uint32_t,
    pub peer_hmac_id: uint16_t,
    pub stale_cookie_count: uint16_t,
    pub str_of_pdapi: uint16_t,
    pub ssn_of_pdapi: uint16_t,
    pub streamincnt: uint16_t,
    pub streamoutcnt: uint16_t,
    pub strm_realoutsize: uint16_t,
    pub strm_pending_add_size: uint16_t,
    pub max_init_times: uint16_t,
    pub max_send_times: uint16_t,
    pub def_net_failure: uint16_t,
    pub def_net_pf_threshold: uint16_t,
    pub mapping_array_size: uint16_t,
    pub last_strm_seq_delivered: uint16_t,
    pub last_strm_no_delivered: uint16_t,
    pub last_revoke_count: uint16_t,
    pub num_send_timers_up: int16_t,
    pub stream_locked_on: uint16_t,
    pub ecn_echo_cnt_onq: uint16_t,
    pub free_chunk_cnt: uint16_t,
    pub stream_locked: uint8_t,
    pub authenticated: uint8_t,
    pub send_sack: uint8_t,
    pub max_burst: uint32_t,
    pub fr_max_burst: uint32_t,
    pub sat_network: uint8_t,
    pub sat_network_lockout: uint8_t,
    pub burst_limit_applied: uint8_t,
    pub hb_random_values: [uint8_t; 4],
    pub fragmented_delivery_inprogress: uint8_t,
    pub fragment_flags: uint8_t,
    pub last_flags_delivered: uint8_t,
    pub hb_ect_randombit: uint8_t,
    pub hb_random_idx: uint8_t,
    pub default_dscp: uint8_t,
    pub asconf_del_pending: uint8_t,
    pub trigger_reset: uint8_t,
    pub ecn_supported: uint8_t,
    pub prsctp_supported: uint8_t,
    pub auth_supported: uint8_t,
    pub asconf_supported: uint8_t,
    pub reconfig_supported: uint8_t,
    pub nrsack_supported: uint8_t,
    pub pktdrop_supported: uint8_t,
    pub idata_supported: uint8_t,
    pub peer_req_out: uint8_t,
    pub local_strreset_support: uint8_t,
    pub peer_supports_nat: uint8_t,
    pub scope: sctp_scoping,
    pub used_alt_asconfack: uint8_t,
    pub fast_retran_loss_recovery: uint8_t,
    pub sat_t3_loss_recovery: uint8_t,
    pub dropped_special_cnt: uint8_t,
    pub seen_a_sack_this_pkt: uint8_t,
    pub stream_reset_outstanding: uint8_t,
    pub stream_reset_out_is_outstanding: uint8_t,
    pub delayed_connection: uint8_t,
    pub ifp_had_enobuf: uint8_t,
    pub saw_sack_with_frags: uint8_t,
    pub saw_sack_with_nr_frags: uint8_t,
    pub in_asocid_hash: uint8_t,
    pub assoc_up_sent: uint8_t,
    pub adaptation_needed: uint8_t,
    pub adaptation_sent: uint8_t,
    pub cmt_dac_pkts_rcvd: uint8_t,
    pub sctp_cmt_on_off: uint8_t,
    pub iam_blocking: uint8_t,
    pub cookie_how: [uint8_t; 8],
    pub sctp_cmt_pf: uint8_t,
    pub use_precise_time: uint8_t,
    pub sctp_features: uint64_t,
    pub max_cwnd: uint32_t,
    pub port: uint16_t,
    pub marked_retrans: uint32_t,
    pub timoinit: uint32_t,
    pub timodata: uint32_t,
    pub timosack: uint32_t,
    pub timoshutdown: uint32_t,
    pub timoheartbeat: uint32_t,
    pub timocookie: uint32_t,
    pub timoshutdownack: uint32_t,
    pub start_time: timeval,
    pub discontinuity_time: timeval,
    pub abandoned_unsent: [uint64_t; 4],
    pub abandoned_sent: [uint64_t; 4],
}
/* bp to asoc this belongs to */
/* filled in if RTT being calculated */
/* pointer to mbuf chain of data */
/* pointer to last mbuf in chain */
/* next link */
/* the send status */
/* number of times I sent */
/* flags, such as FRAGMENT_OK */
/* flag if auth keyid refcount is held */
/* sinfo structure Pluse more */
/* off the wire */
/* SCTP_UNORDERED from wire use SCTP_EOF for
 * EOR */
/* off the wire */
/* pick this up from assoc def context? */
/* not used by kernel */
/* Use this in reassembly as first TSN */
/* Use this in reassembly as last TSN */
/* our assoc id */
/* Non sinfo stuff */
/* Fragment Index */
/* length of data */
/* length held in sb */
/* Highest FSN in queue */
/* Highest FSN in *data portion */
/* where it came from */
/* front of the mbuf chain of data with
 * PKT_HDR */
/* used for multi-part data */
/* used to hold/cache  control if o/s does not take it from us */
/* assoc, used for window update */
/* Flags to hold the notification field */
/* This data structure will be on the outbound
 * stream queues. Data will be pulled off from
 * the front of the mbuf data and chunk-ified
 * by the output routines. We will custom
 * fit every chunk we pull to the send/sent
 * queue to make up the next full packet
 * if we can. An entry cannot be removed
 * from the stream_out queue until
 * the msg_is_complete flag is set. This
 * means at times data/tail_mbuf MIGHT
 * be NULL.. If that occurs it happens
 * for one of two reasons. Either the user
 * is blocked on a send() call and has not
 * awoken to copy more data down... OR
 * the user is in the explict MSG_EOR mode
 * and wrote some data, but has not completed
 * sending.
 */
/*
 * this struct contains info that is used to track inbound stream data and
 * help with ordering.
 */
/* used for re-order */
/* Round-robin schedulers */
/* next link in wheel */
/* Priority scheduler */
/* next link in wheel */
/* priority id */
/* Fair Bandwidth scheduler */
/* next link in wheel */
/* stores message size */
/*
 * This union holds all data necessary for
 * different stream schedulers.
 */
/* circular looking for output selection */
/*
 * This union holds all parameters per stream
 * necessary for different stream schedulers.
 */
/* States for outgoing streams */
/* This struct is used to track the traffic on outbound streams */
/* send queue and sent queue */
/* Only the aggregation */
/* For associations using DATA chunks, the lower 16-bit of
 * next_mid_ordered are used as the next SSN.
 */
/* used to keep track of the addresses yet to try to add/delete */
/* save the ifa for add/del ip */
/* has this been sent yet? */
/* not to be used in lookup */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_scoping {
    pub ipv4_addr_legal: uint8_t,
    pub ipv6_addr_legal: uint8_t,
    pub conn_addr_legal: uint8_t,
    pub loopback_scope: uint8_t,
    pub ipv4_local_scope: uint8_t,
    pub local_scope: uint8_t,
    pub site_scope: uint8_t,
}
pub type sctp_authinfo_t = sctp_authinformation;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_authinformation {
    pub random: *mut sctp_key_t,
    pub random_len: uint32_t,
    pub peer_random: *mut sctp_key_t,
    pub assoc_key: *mut sctp_key_t,
    pub recv_key: *mut sctp_key_t,
    pub active_keyid: uint16_t,
    pub assoc_keyid: uint16_t,
    pub recv_keyid: uint16_t,
}
pub type sctp_key_t = sctp_key;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_key {
    pub keylen: uint32_t,
    pub key: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_keyhead {
    pub lh_first: *mut sctp_shared_key,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_shared_key {
    pub next: C2RustUnnamed_129,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_129 {
    pub le_next: *mut sctp_shared_key,
    pub le_prev: *mut *mut sctp_shared_key,
}
pub type sctp_hmaclist_t = sctp_hmaclist;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_hmaclist {
    pub max_algo: uint16_t,
    pub num_algo: uint16_t,
    pub hmac: [uint16_t; 0],
}
pub type sctp_auth_chklist_t = sctp_auth_chklist;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_auth_chklist {
    pub chunks: [uint8_t; 256],
    pub num_chunks: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_queued_to_read {
    pub sinfo_stream: uint16_t,
    pub sinfo_flags: uint16_t,
    pub sinfo_ppid: uint32_t,
    pub sinfo_context: uint32_t,
    pub sinfo_timetolive: uint32_t,
    pub sinfo_tsn: uint32_t,
    pub sinfo_cumtsn: uint32_t,
    pub sinfo_assoc_id: sctp_assoc_t,
    pub mid: uint32_t,
    pub length: uint32_t,
    pub held_length: uint32_t,
    pub top_fsn: uint32_t,
    pub fsn_included: uint32_t,
    pub whoFrom: *mut sctp_nets,
    pub data: *mut mbuf,
    pub tail_mbuf: *mut mbuf,
    pub aux_data: *mut mbuf,
    pub stcb: *mut sctp_tcb,
    pub next: C2RustUnnamed_140,
    pub next_instrm: C2RustUnnamed_139,
    pub reasm: sctpchunk_listhead,
    pub port_from: uint16_t,
    pub spec_flags: uint16_t,
    pub do_not_ref_stcb: uint8_t,
    pub end_added: uint8_t,
    pub pdapi_aborted: uint8_t,
    pub pdapi_started: uint8_t,
    pub some_taken: uint8_t,
    pub last_frag_seen: uint8_t,
    pub first_frag_seen: uint8_t,
    pub on_read_q: uint8_t,
    pub on_strm_q: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpchunk_listhead {
    pub tqh_first: *mut sctp_tmit_chunk,
    pub tqh_last: *mut *mut sctp_tmit_chunk,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tmit_chunk {
    pub rec: C2RustUnnamed_138,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_130,
    pub sent: int32_t,
    pub snd_count: uint16_t,
    pub flags: uint16_t,
    pub send_size: uint16_t,
    pub book_size: uint16_t,
    pub mbcnt: uint16_t,
    pub auth_keyid: uint16_t,
    pub holds_key_ref: uint8_t,
    pub pad_inplace: uint8_t,
    pub do_rtt: uint8_t,
    pub book_size_scale: uint8_t,
    pub no_fr_allowed: uint8_t,
    pub copy_by_ref: uint8_t,
    pub window_probe: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_130 {
    pub tqe_next: *mut sctp_tmit_chunk,
    pub tqe_prev: *mut *mut sctp_tmit_chunk,
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2008, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/* managing mobility_feature in inpcb (by micchie) */
/*
 * I tried to cache the readq entries at one point. But the reality
 * is that it did not add any performance since this meant we had to
 * lock the STCB on read. And at that point once you have to do an
 * extra lock, it really does not matter if the lock is in the ZONE
 * stuff or in our code. Note that this same problem would occur with
 * an mbuf cache as well so it is not really worth doing, at least
 * right now :-D
 */
/* FreeBSD Version <= 500000 or non-FreeBSD */
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2008, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Depending on the timer type these will be setup and cast with the
 * appropriate entity.
 */
/* for sanity checking */
/*
 * This is the information we track on each interface that we know about from
 * the distant end.
 */
/*
 * Users of the iterator need to malloc a iterator with a call to
 * sctp_initiate_iterator(inp_func, assoc_func, inp_func,  pcb_flags, pcb_features,
 *     asoc_state, void-ptr-arg, uint32-arg, end_func, inp);
 *
 * Use the following two defines if you don't care what pcb flags are on the EP
 * and/or you don't care what state the association is in.
 *
 * Note that if you specify an INP as the last argument then ONLY each
 * association of that single INP will be executed upon. Note that the pcb
 * flags STILL apply so if the inp you specify has different pcb_flags then
 * what you put in pcb_flags nothing will happen. use SCTP_PCB_ANY_FLAGS to
 * assure the inp you specify gets treated.
 */
/* current endpoint */
/* current* assoc */
/* special hook to skip to */
/* per assoc function */
/* per endpoint function */
/* end INP function */
/* iterator completion function */
/* pointer for apply func to use */
/* value for apply func to use */
/* endpoint flags being checked */
/* endpoint features being checked */
/* assoc state being checked */
/* iterator_flags values */
/* ep */
/* remote peer addr */
/* our selected src addr */
/* Fixed point arith, << 7 */
/* Fixed point arith, << 7 */
/* Delay modeswitch until we had at least one congestion event */
/* Time since last congestion event end */
/* Bandwidth estimation */
/* The time we started the sending  */
/* Our last estimated bw */
/* RTT at bw estimate */
/* The total bytes since this sending began */
/* The total time since sending began */
/* temp holding the new value */
/* What bw_bytes was at last rtt calc */
/* Cwnd at last bw saved - lbw */
/* cnt of voluntary reductions */
/* The number required to be in steady state*/
/* The current number */
/* When all things are equal what do I return 0/1 - 1 no cc advance */
/* Flag to enable DCCC ECN */
/* Flag to indicate we need to set tls 0 or 1 means set at send 2 not */
/* Last state if steady state stepdown is on */
/* Flag saying this sack had RTT calc on it */
/* Last saved inst indication */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_nets {
    pub sctp_next: C2RustUnnamed_137,
    pub pmtu_timer: sctp_timer,
    pub hb_timer: sctp_timer,
    pub ro: sctp_net_route,
    pub mtu: uint32_t,
    pub ssthresh: uint32_t,
    pub last_cwr_tsn: uint32_t,
    pub cwr_window_tsn: uint32_t,
    pub ecn_ce_pkt_cnt: uint32_t,
    pub lost_cnt: uint32_t,
    pub lastsa: libc::c_int,
    pub lastsv: libc::c_int,
    pub rtt: uint64_t,
    pub RTO: libc::c_uint,
    pub rxt_timer: sctp_timer,
    pub last_sent_time: timeval,
    pub cc_mod: cc_control_data,
    pub ref_count: libc::c_int,
    pub flight_size: uint32_t,
    pub cwnd: uint32_t,
    pub prev_cwnd: uint32_t,
    pub ecn_prev_cwnd: uint32_t,
    pub partial_bytes_acked: uint32_t,
    pub net_ack: libc::c_uint,
    pub net_ack2: libc::c_uint,
    pub last_active: uint32_t,
    pub this_sack_highest_newack: uint32_t,
    pub pseudo_cumack: uint32_t,
    pub rtx_pseudo_cumack: uint32_t,
    pub fast_recovery_tsn: uint32_t,
    pub heartbeat_random1: uint32_t,
    pub heartbeat_random2: uint32_t,
    pub flowlabel: uint32_t,
    pub dscp: uint8_t,
    pub start_time: timeval,
    pub marked_retrans: uint32_t,
    pub marked_fastretrans: uint32_t,
    pub heart_beat_delay: uint32_t,
    pub dest_state: uint16_t,
    pub failure_threshold: uint16_t,
    pub pf_threshold: uint16_t,
    pub error_count: uint16_t,
    pub port: uint16_t,
    pub fast_retran_loss_recovery: uint8_t,
    pub will_exit_fast_recovery: uint8_t,
    pub fast_retran_ip: uint8_t,
    pub hb_responded: uint8_t,
    pub saw_newack: uint8_t,
    pub src_addr_selected: uint8_t,
    pub indx_of_eligible_next_to_use: uint8_t,
    pub addr_is_local: uint8_t,
    pub find_pseudo_cumack: uint8_t,
    pub find_rtx_pseudo_cumack: uint8_t,
    pub new_pseudo_cumack: uint8_t,
    pub window_probe: uint8_t,
    pub RTO_measured: uint8_t,
    pub last_hs_used: uint8_t,
    pub lan_type: uint8_t,
    pub rto_needed: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union cc_control_data {
    pub htcp_ca: htcp,
    pub rtcc: rtcc_cc,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rtcc_cc {
    pub tls: timeval,
    pub lbw: uint64_t,
    pub lbw_rtt: uint64_t,
    pub bw_bytes: uint64_t,
    pub bw_tot_time: uint64_t,
    pub new_tot_time: uint64_t,
    pub bw_bytes_at_last_rttc: uint64_t,
    pub cwnd_at_bw_set: uint32_t,
    pub vol_reduce: uint32_t,
    pub steady_step: uint16_t,
    pub step_cnt: uint16_t,
    pub ret_from_eq: uint8_t,
    pub use_dccc_ecn: uint8_t,
    pub tls_needs_set: uint8_t,
    pub last_step_state: uint8_t,
    pub rtt_set_this_sack: uint8_t,
    pub last_inst_ind: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct htcp {
    pub alpha: uint16_t,
    pub beta: uint8_t,
    pub modeswitch: uint8_t,
    pub last_cong: uint32_t,
    pub undo_last_cong: uint32_t,
    pub bytes_acked: uint16_t,
    pub bytecount: uint32_t,
    pub minRTT: uint32_t,
    pub maxRTT: uint32_t,
    pub undo_maxRTT: uint32_t,
    pub undo_old_maxB: uint32_t,
    pub minB: uint32_t,
    pub maxB: uint32_t,
    pub old_maxB: uint32_t,
    pub Bi: uint32_t,
    pub lasttime: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_timer {
    pub timer: sctp_os_timer_t,
    pub type_0: libc::c_int,
    pub ep: *mut libc::c_void,
    pub tcb: *mut libc::c_void,
    pub net: *mut libc::c_void,
    pub self_0: *mut libc::c_void,
    pub ticks: uint32_t,
    pub stopped_from: uint32_t,
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * NOTE: the following MACROS are required for locking the callout
 * queue along with a lock/mutex in the OS specific headers and
 * implementation files::
 * - SCTP_TIMERQ_LOCK()
 * - SCTP_TIMERQ_UNLOCK()
 * - SCTP_TIMERQ_LOCK_INIT()
 * - SCTP_TIMERQ_LOCK_DESTROY()
 */
/* called about every 20ms */
/* ticks to the event */
/* function argument */
/* function to call */
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_callout {
    pub tqe: C2RustUnnamed_131,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_131 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_net_route {
    pub ro_rt: *mut sctp_rtentry_t,
    pub _l_addr: sctp_sockstore,
    pub _s_addr: *mut sctp_ifa,
}
/* Hold off using this one */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifa {
    pub next_ifa: C2RustUnnamed_136,
    pub next_bucket: C2RustUnnamed_135,
    pub ifn_p: *mut sctp_ifn,
    pub ifa: *mut libc::c_void,
    pub address: sctp_sockstore,
    pub refcount: uint32_t,
    pub flags: uint32_t,
    pub localifa_flags: uint32_t,
    pub vrf_id: uint32_t,
    pub src_is_loop: uint8_t,
    pub src_is_priv: uint8_t,
    pub src_is_glob: uint8_t,
    pub resv: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifn {
    pub ifalist: sctp_ifalist,
    pub vrf: *mut sctp_vrf,
    pub next_ifn: C2RustUnnamed_133,
    pub next_bucket: C2RustUnnamed_132,
    pub ifn_p: *mut libc::c_void,
    pub ifn_mtu: uint32_t,
    pub ifn_type: uint32_t,
    pub ifn_index: uint32_t,
    pub refcount: uint32_t,
    pub ifa_count: uint32_t,
    pub num_v6: uint32_t,
    pub num_v4: uint32_t,
    pub registered_af: uint32_t,
    pub ifn_name: [libc::c_char; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_132 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_133 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_134,
    pub vrf_addr_hash: *mut sctp_ifalist,
    pub ifnlist: sctp_ifnlist,
    pub vrf_id: uint32_t,
    pub tbl_id_v4: uint32_t,
    pub tbl_id_v6: uint32_t,
    pub total_ifa_count: uint32_t,
    pub vrf_addr_hashmark: u_long,
    pub refcount: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifnlist {
    pub lh_first: *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifalist {
    pub lh_first: *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_134 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_135 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_136 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_137 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_138 {
    pub data: sctp_data_chunkrec,
    pub chunk_id: chk_id,
}
/* the TSN of this transmit */
/* the message identifier of this transmit */
/* the stream number of this guy */
/* from send */
/*
 * part of the Highest sacked algorithm to be able to stroke counts
 * on ones that are FR'd.
 */
/* sending_seq at the time of FR */
/* time we drop it from queue */
/* Fragment Sequence Number */
/* flags pulled from data chunk on inbound for
 * outbound holds sending flags for PR-SCTP.
 */
/* The lower byte is used to enumerate PR_SCTP policies */
/* The upper byte is used as a bit mask */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct chk_id {
    pub id: uint8_t,
    pub can_take_data: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_data_chunkrec {
    pub tsn: uint32_t,
    pub mid: uint32_t,
    pub sid: uint16_t,
    pub ppid: uint32_t,
    pub context: uint32_t,
    pub cwnd_at_send: uint32_t,
    pub fast_retran_tsn: uint32_t,
    pub timetodrop: timeval,
    pub fsn: uint32_t,
    pub doing_fast_retransmit: uint8_t,
    pub rcv_flags: uint8_t,
    pub state_flags: uint8_t,
    pub chunk_was_revoked: uint8_t,
    pub fwd_tsn_cnt: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_139 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_140 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}
/* This struct is here to cut out the compatiabilty
 * pad that bulks up both the inp and stcb. The non
 * pad portion MUST stay in complete sync with
 * sctp_sndrcvinfo... i.e. if sinfo_xxxx is added
 * this must be done here too.
 */
/*
 * JRS - Structure to hold function pointers to the functions responsible
 * for congestion control.
 */
/*
 * RS - Structure to hold function pointers to the functions responsible
 * for stream scheduling.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ss_functions {
    pub sctp_ss_init: Option<
        unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association, _: libc::c_int) -> (),
    >,
    pub sctp_ss_clear: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_association,
            _: libc::c_int,
            _: libc::c_int,
        ) -> (),
    >,
    pub sctp_ss_init_stream: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_stream_out,
            _: *mut sctp_stream_out,
        ) -> (),
    >,
    pub sctp_ss_add_to_stream: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_association,
            _: *mut sctp_stream_out,
            _: *mut sctp_stream_queue_pending,
            _: libc::c_int,
        ) -> (),
    >,
    pub sctp_ss_is_empty:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association) -> libc::c_int>,
    pub sctp_ss_remove_from_stream: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_association,
            _: *mut sctp_stream_out,
            _: *mut sctp_stream_queue_pending,
            _: libc::c_int,
        ) -> (),
    >,
    pub sctp_ss_select_stream: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_nets,
            _: *mut sctp_association,
        ) -> *mut sctp_stream_out,
    >,
    pub sctp_ss_scheduled: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_nets,
            _: *mut sctp_association,
            _: *mut sctp_stream_out,
            _: libc::c_int,
        ) -> (),
    >,
    pub sctp_ss_packet_done: Option<
        unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets, _: *mut sctp_association) -> (),
    >,
    pub sctp_ss_get_value: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_association,
            _: *mut sctp_stream_out,
            _: *mut uint16_t,
        ) -> libc::c_int,
    >,
    pub sctp_ss_set_value: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_association,
            _: *mut sctp_stream_out,
            _: uint16_t,
        ) -> libc::c_int,
    >,
    pub sctp_ss_is_user_msgs_incomplete:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association) -> libc::c_int>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_out {
    pub outqueue: sctp_streamhead,
    pub ss_params: scheduling_parameters,
    pub chunks_on_queues: uint32_t,
    pub abandoned_unsent: [uint32_t; 1],
    pub abandoned_sent: [uint32_t; 1],
    pub next_mid_ordered: uint32_t,
    pub next_mid_unordered: uint32_t,
    pub sid: uint16_t,
    pub last_msg_incomplete: uint8_t,
    pub state: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union scheduling_parameters {
    pub rr: ss_rr,
    pub prio: ss_prio,
    pub fb: ss_fb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_fb {
    pub next_spoke: C2RustUnnamed_141,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_141 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_142,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_142 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_143,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_143 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_streamhead {
    pub tqh_first: *mut sctp_stream_queue_pending,
    pub tqh_last: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_queue_pending {
    pub data: *mut mbuf,
    pub tail_mbuf: *mut mbuf,
    pub ts: timeval,
    pub net: *mut sctp_nets,
    pub next: C2RustUnnamed_145,
    pub ss_next: C2RustUnnamed_144,
    pub fsn: uint32_t,
    pub length: uint32_t,
    pub timetolive: uint32_t,
    pub ppid: uint32_t,
    pub context: uint32_t,
    pub sinfo_flags: uint16_t,
    pub sid: uint16_t,
    pub act_flags: uint16_t,
    pub auth_keyid: uint16_t,
    pub holds_key_ref: uint8_t,
    pub msg_is_complete: uint8_t,
    pub some_taken: uint8_t,
    pub sender_all_done: uint8_t,
    pub put_last_out: uint8_t,
    pub discard_rest: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_144 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_145 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_cc_functions {
    pub sctp_set_initial_cc_param:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> ()>,
    pub sctp_cwnd_update_after_sack: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_association,
            _: libc::c_int,
            _: libc::c_int,
            _: libc::c_int,
        ) -> (),
    >,
    pub sctp_cwnd_update_exit_pf:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> ()>,
    pub sctp_cwnd_update_after_fr:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association) -> ()>,
    pub sctp_cwnd_update_after_timeout:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> ()>,
    pub sctp_cwnd_update_after_ecn_echo: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_nets,
            _: libc::c_int,
            _: libc::c_int,
        ) -> (),
    >,
    pub sctp_cwnd_update_after_packet_dropped: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: *mut sctp_nets,
            _: *mut sctp_pktdrop_chunk,
            _: *mut uint32_t,
            _: *mut uint32_t,
        ) -> (),
    >,
    pub sctp_cwnd_update_after_output:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets, _: libc::c_int) -> ()>,
    pub sctp_cwnd_update_packet_transmitted:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> ()>,
    pub sctp_cwnd_update_tsn_acknowledged:
        Option<unsafe extern "C" fn(_: *mut sctp_nets, _: *mut sctp_tmit_chunk) -> ()>,
    pub sctp_cwnd_new_transmission_begins:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> ()>,
    pub sctp_cwnd_prepare_net_for_sack:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> ()>,
    pub sctp_cwnd_socket_option: Option<
        unsafe extern "C" fn(
            _: *mut sctp_tcb,
            _: libc::c_int,
            _: *mut sctp_cc_option,
        ) -> libc::c_int,
    >,
    pub sctp_rtt_calculated:
        Option<unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets, _: *mut timeval) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_cc_option {
    pub option: libc::c_int,
    pub aid_value: sctp_assoc_value,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_assoc_value {
    pub assoc_id: sctp_assoc_t,
    pub assoc_value: uint32_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_pktdrop_chunk {
    pub ch: sctp_chunkhdr,
    pub bottle_bw: uint32_t,
    pub current_onq: uint32_t,
    pub trunc_len: uint16_t,
    pub reserved: uint16_t,
    pub data: [uint8_t; 0],
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2008, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * SCTP protocol - RFC4960.
 */
/* source port */
/* destination port */
/* verification tag of packet */
/* CRC32C checksum */
/* chunks follow... */
/*
 * SCTP Chunks
 */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_chunkhdr {
    pub chunk_type: uint8_t,
    pub chunk_flags: uint8_t,
    pub chunk_length: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_readhead {
    pub tqh_first: *mut sctp_queued_to_read,
    pub tqh_last: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_resethead {
    pub tqh_first: *mut sctp_stream_reset_list,
    pub tqh_last: *mut *mut sctp_stream_reset_list,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_reset_list {
    pub next_resp: C2RustUnnamed_146,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_146 {
    pub tqe_next: *mut sctp_stream_reset_list,
    pub tqe_prev: *mut *mut sctp_stream_reset_list,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_in {
    pub inqueue: sctp_readhead,
    pub uno_inqueue: sctp_readhead,
    pub last_mid_delivered: uint32_t,
    pub sid: uint16_t,
    pub delivery_started: uint8_t,
    pub pd_api_started: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_laddr {
    pub sctp_nxt_addr: C2RustUnnamed_147,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_147 {
    pub le_next: *mut sctp_laddr,
    pub le_prev: *mut *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ackhead {
    pub tqh_first: *mut sctp_asconf_ack,
    pub tqh_last: *mut *mut sctp_asconf_ack,
}
/* used to save ASCONF-ACK chunks for retransmission */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ack {
    pub next: C2RustUnnamed_148,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_148 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_149,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_149 {
    pub wheel: sctpwheel_listhead,
    pub list: sctplist_listhead,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctplist_listhead {
    pub tqh_first: *mut sctp_stream_queue_pending,
    pub tqh_last: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpwheel_listhead {
    pub tqh_first: *mut sctp_stream_out,
    pub tqh_last: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpnetlisthead {
    pub tqh_first: *mut sctp_nets,
    pub tqh_last: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpladdr {
    pub lh_first: *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_nonpad_sndrcvinfo {
    pub sinfo_stream: uint16_t,
    pub sinfo_ssn: uint16_t,
    pub sinfo_flags: uint16_t,
    pub sinfo_ppid: uint32_t,
    pub sinfo_context: uint32_t,
    pub sinfo_timetolive: uint32_t,
    pub sinfo_tsn: uint32_t,
    pub sinfo_cumtsn: uint32_t,
    pub sinfo_assoc_id: sctp_assoc_t,
    pub sinfo_keynumber: uint16_t,
    pub sinfo_keynumber_valid: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addrhead {
    pub tqh_first: *mut sctp_asconf_addr,
    pub tqh_last: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_150,
    pub ap: sctp_asconf_addr_param,
    pub ifa: *mut sctp_ifa,
    pub sent: uint8_t,
    pub special_del: uint8_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr_param {
    pub aph: sctp_asconf_paramhdr,
    pub addrp: sctp_ipv6addr_param,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_ipv6addr_param {
    pub ph: sctp_paramhdr,
    pub addr: [uint8_t; 16],
}
/* chunk length */
/* optional params follow */
/*
 * SCTP chunk parameters
 */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_paramhdr {
    pub param_type: uint16_t,
    pub param_length: uint16_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_paramhdr {
    pub ph: sctp_paramhdr,
    pub correlation_id: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_150 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}
/* time when this address was created */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_block_entry {
    pub error: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_151 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_152 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_153 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_154 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}
/*-
 * Here we have all the relevant information for each SCTP entity created. We
 * will need to modify this as approprate. We also need to figure out how to
 * access /dev/random.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_pcb {
    pub time_of_secret_change: libc::c_uint,
    pub secret_key: [[uint32_t; 8]; 2],
    pub size_of_a_cookie: libc::c_uint,
    pub sctp_timeoutticks: [libc::c_uint; 7],
    pub sctp_minrto: libc::c_uint,
    pub sctp_maxrto: libc::c_uint,
    pub initial_rto: libc::c_uint,
    pub initial_init_rto_max: libc::c_int,
    pub sctp_sack_freq: libc::c_uint,
    pub sctp_sws_sender: uint32_t,
    pub sctp_sws_receiver: uint32_t,
    pub sctp_default_cc_module: uint32_t,
    pub sctp_default_ss_module: uint32_t,
    pub shared_keys: sctp_keyhead,
    pub local_auth_chunks: *mut sctp_auth_chklist_t,
    pub local_hmacs: *mut sctp_hmaclist_t,
    pub default_keyid: uint16_t,
    pub default_mtu: uint32_t,
    pub max_init_times: uint16_t,
    pub max_send_times: uint16_t,
    pub def_net_failure: uint16_t,
    pub def_net_pf_threshold: uint16_t,
    pub pre_open_stream_count: uint16_t,
    pub max_open_streams_intome: uint16_t,
    pub random_counter: uint32_t,
    pub random_numbers: [uint8_t; 20],
    pub random_store: [uint8_t; 20],
    pub signature_change: sctp_timer,
    pub def_cookie_life: uint32_t,
    pub auto_close_time: libc::c_int,
    pub initial_sequence_debug: uint32_t,
    pub adaptation_layer_indicator: uint32_t,
    pub adaptation_layer_indicator_provided: uint8_t,
    pub store_at: uint32_t,
    pub max_burst: uint32_t,
    pub fr_max_burst: uint32_t,
    pub default_flowlabel: uint32_t,
    pub default_dscp: uint8_t,
    pub current_secret_number: libc::c_char,
    pub last_secret_number: libc::c_char,
    pub port: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_155 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_156 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_157 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}
pub type asoc_func = Option<
    unsafe extern "C" fn(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: *mut libc::c_void,
        _: uint32_t,
    ) -> (),
>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_158 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct calloutlist {
    pub tqh_first: *mut sctp_callout,
    pub tqh_last: *mut *mut sctp_callout,
}
pub type start_routine_t = Option<unsafe extern "C" fn(_: *mut libc::c_void) -> *mut libc::c_void>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_timeval {
    pub tv_sec: uint32_t,
    pub tv_usec: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
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
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_sysctl {
    pub sctp_sendspace: uint32_t,
    pub sctp_recvspace: uint32_t,
    pub sctp_auto_asconf: uint32_t,
    pub sctp_multiple_asconfs: uint32_t,
    pub sctp_ecn_enable: uint32_t,
    pub sctp_pr_enable: uint32_t,
    pub sctp_auth_enable: uint32_t,
    pub sctp_asconf_enable: uint32_t,
    pub sctp_reconfig_enable: uint32_t,
    pub sctp_nrsack_enable: uint32_t,
    pub sctp_pktdrop_enable: uint32_t,
    pub sctp_fr_max_burst_default: uint32_t,
    pub sctp_no_csum_on_loopback: uint32_t,
    pub sctp_peer_chunk_oh: uint32_t,
    pub sctp_max_burst_default: uint32_t,
    pub sctp_max_chunks_on_queue: uint32_t,
    pub sctp_hashtblsize: uint32_t,
    pub sctp_pcbtblsize: uint32_t,
    pub sctp_min_split_point: uint32_t,
    pub sctp_chunkscale: uint32_t,
    pub sctp_delayed_sack_time_default: uint32_t,
    pub sctp_sack_freq_default: uint32_t,
    pub sctp_system_free_resc_limit: uint32_t,
    pub sctp_asoc_free_resc_limit: uint32_t,
    pub sctp_heartbeat_interval_default: uint32_t,
    pub sctp_pmtu_raise_time_default: uint32_t,
    pub sctp_shutdown_guard_time_default: uint32_t,
    pub sctp_secret_lifetime_default: uint32_t,
    pub sctp_rto_max_default: uint32_t,
    pub sctp_rto_min_default: uint32_t,
    pub sctp_rto_initial_default: uint32_t,
    pub sctp_init_rto_max_default: uint32_t,
    pub sctp_valid_cookie_life_default: uint32_t,
    pub sctp_init_rtx_max_default: uint32_t,
    pub sctp_assoc_rtx_max_default: uint32_t,
    pub sctp_path_rtx_max_default: uint32_t,
    pub sctp_path_pf_threshold: uint32_t,
    pub sctp_add_more_threshold: uint32_t,
    pub sctp_nr_incoming_streams_default: uint32_t,
    pub sctp_nr_outgoing_streams_default: uint32_t,
    pub sctp_cmt_on_off: uint32_t,
    pub sctp_cmt_use_dac: uint32_t,
    pub sctp_use_cwnd_based_maxburst: uint32_t,
    pub sctp_nat_friendly: uint32_t,
    pub sctp_L2_abc_variable: uint32_t,
    pub sctp_mbuf_threshold_count: uint32_t,
    pub sctp_do_drain: uint32_t,
    pub sctp_hb_maxburst: uint32_t,
    pub sctp_abort_if_one_2_one_hits_limit: uint32_t,
    pub sctp_min_residual: uint32_t,
    pub sctp_max_retran_chunk: uint32_t,
    pub sctp_logging_level: uint32_t,
    pub sctp_default_cc_module: uint32_t,
    pub sctp_default_ss_module: uint32_t,
    pub sctp_default_frag_interleave: uint32_t,
    pub sctp_mobility_base: uint32_t,
    pub sctp_mobility_fasthandoff: uint32_t,
    pub sctp_inits_include_nat_friendly: uint32_t,
    pub sctp_rttvar_bw: uint32_t,
    pub sctp_rttvar_rtt: uint32_t,
    pub sctp_rttvar_eqret: uint32_t,
    pub sctp_steady_step: uint32_t,
    pub sctp_use_dccc_ecn: uint32_t,
    pub sctp_diag_info_code: uint32_t,
    pub sctp_udp_tunneling_port: uint32_t,
    pub sctp_enable_sack_immediately: uint32_t,
    pub sctp_vtag_time_wait: uint32_t,
    pub sctp_buffer_splitting: uint32_t,
    pub sctp_initial_cwnd: uint32_t,
    pub sctp_blackhole: uint32_t,
    pub sctp_sendall_limit: uint32_t,
    pub sctp_debug_on: uint32_t,
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctppcbhead {
    pub lh_first: *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpvtaghead {
    pub lh_first: *mut sctp_tagblock,
}
/* the remote port used in vtag */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tagblock {
    pub sctp_nxt_tagblock: C2RustUnnamed_159,
    pub vtag_block: [sctp_timewait; 15],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_timewait {
    pub tv_sec_at_expire: uint32_t,
    pub v_tag: uint32_t,
    pub lport: uint16_t,
    pub rport: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_159 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrflist {
    pub lh_first: *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpiterators {
    pub tqh_first: *mut sctp_iterator,
    pub tqh_last: *mut *mut sctp_iterator,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iterator_control {
    pub ipi_iterator_wq_mtx: userland_mutex_t,
    pub it_mtx: userland_mutex_t,
    pub iterator_wakeup: userland_cond_t,
    pub thread_proc: userland_thread_t,
    pub iteratorhead: sctpiterators,
    pub cur_it: *mut sctp_iterator,
    pub iterator_running: uint32_t,
    pub iterator_flags: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_epinfo {
    pub sctp_asochash: *mut sctpasochead,
    pub hashasocmark: u_long,
    pub sctp_ephash: *mut sctppcbhead,
    pub hashmark: u_long,
    pub sctp_tcpephash: *mut sctppcbhead,
    pub hashtcpmark: u_long,
    pub hashtblsize: uint32_t,
    pub sctp_vrfhash: *mut sctp_vrflist,
    pub hashvrfmark: u_long,
    pub vrf_ifn_hash: *mut sctp_ifnlist,
    pub vrf_ifn_hashmark: u_long,
    pub listhead: sctppcbhead,
    pub addr_wq: sctpladdr,
    pub ipi_zone_ep: sctp_zone_t,
    pub ipi_zone_asoc: sctp_zone_t,
    pub ipi_zone_laddr: sctp_zone_t,
    pub ipi_zone_net: sctp_zone_t,
    pub ipi_zone_chunk: sctp_zone_t,
    pub ipi_zone_readq: sctp_zone_t,
    pub ipi_zone_strmoq: sctp_zone_t,
    pub ipi_zone_asconf: sctp_zone_t,
    pub ipi_zone_asconf_ack: sctp_zone_t,
    pub ipi_ep_mtx: userland_mutex_t,
    pub ipi_addr_mtx: userland_mutex_t,
    pub ipi_count_mtx: userland_mutex_t,
    pub ipi_pktlog_mtx: userland_mutex_t,
    pub wq_addr_mtx: userland_mutex_t,
    pub ipi_count_ep: uint32_t,
    pub ipi_count_asoc: uint32_t,
    pub ipi_count_laddr: uint32_t,
    pub ipi_count_raddr: uint32_t,
    pub ipi_count_chunk: uint32_t,
    pub ipi_count_readq: uint32_t,
    pub ipi_count_strmoq: uint32_t,
    pub ipi_count_vrfs: uint32_t,
    pub ipi_count_ifns: uint32_t,
    pub ipi_count_ifas: uint32_t,
    pub ipi_free_chunks: uint32_t,
    pub ipi_free_strmoq: uint32_t,
    pub vtag_timewait: [sctpvtaghead; 32],
    pub addr_wq_timer: sctp_timer,
    pub callqueue: calloutlist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_base_info {
    pub sctppcbinfo: sctp_epinfo,
    pub sctpstat: sctpstat,
    pub sctpsysctl: sctp_sysctl,
    pub first_time: uint8_t,
    pub sctp_pcb_initialized: libc::c_char,
    pub timer_mtx: userland_mutex_t,
    pub timer_thread: userland_thread_t,
    pub timer_thread_should_exit: libc::c_int,
    pub mtx_attr: pthread_mutexattr_t,
    pub userspace_route: libc::c_int,
    pub recvthreadroute: userland_thread_t,
    pub userspace_rawsctp: libc::c_int,
    pub userspace_udpsctp: libc::c_int,
    pub recvthreadraw: userland_thread_t,
    pub recvthreadudp: userland_thread_t,
    pub userspace_rawsctp6: libc::c_int,
    pub userspace_udpsctp6: libc::c_int,
    pub recvthreadraw6: userland_thread_t,
    pub recvthreadudp6: userland_thread_t,
    pub conn_output: Option<
        unsafe extern "C" fn(
            _: *mut libc::c_void,
            _: *mut libc::c_void,
            _: size_t,
            _: uint8_t,
            _: uint8_t,
        ) -> libc::c_int,
    >,
    pub debug_printf: Option<unsafe extern "C" fn(_: *const libc::c_char, _: ...) -> ()>,
    pub crc32c_offloaded: libc::c_int,
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/* Declare all of our malloc named types */
#[no_mangle]
pub static mut SCTP_M_MAP: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_map\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_STRMI: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_stri\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_STRMO: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_stro\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_ASC_ADDR: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_aadr\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_ASC_IT: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_a_it\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_AUTH_CL: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_atcl\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_AUTH_KY: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_atky\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_AUTH_HL: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_athm\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_AUTH_IF: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_athi\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_STRESET: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_stre\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_CMSG: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_cmsg\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_COPYAL: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_cpal\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_VRF: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_vrf\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_IFA: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_ifa\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_IFN: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_ifn\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_TIMW: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_timw\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_MVRF: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_mvrf\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_ITER: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_iter\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_SOCKOPT: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_socko\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut SCTP_M_MCORE: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_mcore\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
/* Global NON-VNET structure that controls the iterator */
#[no_mangle]
pub static mut sctp_it_ctl: iterator_control = iterator_control {
    ipi_iterator_wq_mtx: pthread_mutex_t {
        __data: __pthread_mutex_s {
            __lock: 0,
            __count: 0,
            __owner: 0,
            __nusers: 0,
            __kind: 0,
            __spins: 0,
            __elision: 0,
            __list: __pthread_list_t {
                __prev: 0 as *mut __pthread_internal_list,
                __next: 0 as *mut __pthread_internal_list,
            },
        },
    },
    it_mtx: pthread_mutex_t {
        __data: __pthread_mutex_s {
            __lock: 0,
            __count: 0,
            __owner: 0,
            __nusers: 0,
            __kind: 0,
            __spins: 0,
            __elision: 0,
            __list: __pthread_list_t {
                __prev: 0 as *mut __pthread_internal_list,
                __next: 0 as *mut __pthread_internal_list,
            },
        },
    },
    iterator_wakeup: pthread_cond_t {
        __data: __pthread_cond_s {
            c2rust_unnamed: C2RustUnnamed_108 { __wseq: 0 },
            c2rust_unnamed_0: C2RustUnnamed_106 { __g1_start: 0 },
            __g_refs: [0; 2],
            __g_size: [0; 2],
            __g1_orig_size: 0,
            __wrefs: 0,
            __g_signals: [0; 2],
        },
    },
    thread_proc: 0,
    iteratorhead: sctpiterators {
        tqh_first: 0 as *mut sctp_iterator,
        tqh_last: 0 as *mut *mut sctp_iterator,
    },
    cur_it: 0 as *mut sctp_iterator,
    iterator_running: 0,
    iterator_flags: 0,
};
unsafe extern "C" fn sctp_cleanup_itqueue() {
    let mut it = 0 as *mut sctp_iterator;
    let mut nit = 0 as *mut sctp_iterator;
    it = sctp_it_ctl.iteratorhead.tqh_first;
    while !it.is_null() && {
        nit = (*it).sctp_nxt_itr.tqe_next;
        (1i32) != 0
    } {
        if (*it).function_atend.is_some() {
            Some((*it).function_atend.expect("non-null function pointer"))
                .expect("non-null function pointer")((*it).pointer, (*it).val);
        }
        if !(*it).sctp_nxt_itr.tqe_next.is_null() {
            (*(*it).sctp_nxt_itr.tqe_next).sctp_nxt_itr.tqe_prev = (*it).sctp_nxt_itr.tqe_prev
        } else {
            sctp_it_ctl.iteratorhead.tqh_last = (*it).sctp_nxt_itr.tqe_prev
        }
        *(*it).sctp_nxt_itr.tqe_prev = (*it).sctp_nxt_itr.tqe_next;
        free(it as *mut libc::c_void);
        it = nit
    }
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2001-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*__Userspace__ TODO if we use thread based iterator
 * then the implementation of wakeup will need to change.
 * Currently we are using timeo_cond for ident so_timeo
 * but that is not sufficient if we need to use another ident
 * like wakeup(&sctppcbinfo.iterator_running);
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_wakeup_iterator() {
    pthread_cond_broadcast(&mut sctp_it_ctl.iterator_wakeup);
}
unsafe extern "C" fn sctp_iterator_thread(mut v: *mut libc::c_void) -> *mut libc::c_void {
    sctp_userspace_set_threadname(b"SCTP iterator\x00" as *const u8 as *const libc::c_char);
    pthread_mutex_lock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    /* In FreeBSD this thread never terminates. */
    while sctp_it_ctl.iterator_flags & 0x1u32 == 0u32 {
        pthread_cond_wait(
            &mut sctp_it_ctl.iterator_wakeup,
            &mut sctp_it_ctl.ipi_iterator_wq_mtx,
        );
        if sctp_it_ctl.iterator_flags & 0x1u32 != 0 {
            break;
        }
        sctp_iterator_worker();
    }
    /* Now this thread needs to be terminated */
    sctp_cleanup_itqueue();
    sctp_it_ctl.iterator_flags |= 0x2u32;
    pthread_mutex_unlock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    sctp_wakeup_iterator();
    return 0 as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_startup_iterator() {
    if sctp_it_ctl.thread_proc != 0 {
        /* You only get one */
        return;
    }
    /* Initialize global locks here, thus only once. */
    pthread_mutex_init(&mut sctp_it_ctl.it_mtx, &mut system_base_info.mtx_attr);
    pthread_mutex_init(
        &mut sctp_it_ctl.ipi_iterator_wq_mtx,
        &mut system_base_info.mtx_attr,
    );
    sctp_it_ctl.iteratorhead.tqh_first = 0 as *mut sctp_iterator;
    sctp_it_ctl.iteratorhead.tqh_last = &mut sctp_it_ctl.iteratorhead.tqh_first;
    if sctp_userspace_thread_create(
        &mut sctp_it_ctl.thread_proc,
        Some(
            sctp_iterator_thread as unsafe extern "C" fn(_: *mut libc::c_void) -> *mut libc::c_void,
        ),
    ) != 0
    {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"ERROR: Creating sctp_iterator_thread failed.\n\x00" as *const u8
                    as *const libc::c_char,
            );
        }
    };
}
/* __Userspace__ TODO. struct in6_ifaddr is defined in sys/netinet6/in6_var.h
  ip6_use_deprecated is defined as  int ip6_use_deprecated = 1; in /src/sys/netinet6/in6_proto.c
*/
#[no_mangle]
pub unsafe extern "C" fn sctp_gather_internal_ifa_flags(mut ifa: *mut sctp_ifa) {
    /* stub */
}
/* __Userspace__ */
/* INET6 */
unsafe extern "C" fn sctp_init_ifns_for_vrf(mut vrfid: libc::c_int) {
    let mut rc = 0;
    let mut ifa = 0 as *mut ifaddrs;
    let mut ifas = 0 as *mut ifaddrs;
    rc = getifaddrs(&mut ifas);
    if rc != 0i32 {
        return;
    }
    ifa = ifas;
    while !ifa.is_null() {
        if !(*ifa).ifa_addr.is_null() {
            if !((*(*ifa).ifa_addr).sa_family as libc::c_int != 2i32
                && (*(*ifa).ifa_addr).sa_family as libc::c_int != 10i32)
            {
                if !((*(*ifa).ifa_addr).sa_family as libc::c_int == 10i32
                    && ({
                        let mut __a = &mut (*((*ifa).ifa_addr as *mut sockaddr_in6)).sin6_addr
                            as *mut in6_addr
                            as *const in6_addr;
                        ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                            && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                            && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                            && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                            as libc::c_int
                    }) != 0)
                {
                    if !((*(*ifa).ifa_addr).sa_family as libc::c_int == 2i32
                        && (*((*ifa).ifa_addr as *mut sockaddr_in)).sin_addr.s_addr == 0u32)
                    {
                        let mut sctp_ifa = 0 as *mut sctp_ifa;
                        let mut ifa_flags = 0;
                        ifa_flags = 0u32;
                        sctp_ifa = sctp_add_addr_to_vrf(
                            vrfid as uint32_t,
                            0 as *mut libc::c_void,
                            if_nametoindex((*ifa).ifa_name),
                            0u32,
                            (*ifa).ifa_name,
                            0 as *mut libc::c_void,
                            (*ifa).ifa_addr,
                            ifa_flags,
                            0i32,
                        );
                        if !sctp_ifa.is_null() {
                            (*sctp_ifa).localifa_flags &= !(0x4i32) as libc::c_uint
                        }
                    }
                }
            }
        }
        /* skip unspecifed addresses */
        ifa = (*ifa).ifa_next
    }
    freeifaddrs(ifas);
}
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2006-2007, by Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2008-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2008-2012, by Michael Tuexen. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * General kernel memory allocation:
 *  SCTP_MALLOC(element, type, size, name)
 *  SCTP_FREE(element)
 * Kernel memory allocation for "soname"- memory must be zeroed.
 *  SCTP_MALLOC_SONAME(name, type, size)
 *  SCTP_FREE_SONAME(name)
 */
/*
 * Zone(pool) allocation routines: MUST be defined for each OS.
 *  zone = zone/pool pointer.
 *  name = string name of the zone/pool.
 *  size = size of each zone/pool element.
 *  number = number of elements in zone/pool.
 *  type = structure type to allocate
 *
 * sctp_zone_t
 * SCTP_ZONE_INIT(zone, name, size, number)
 * SCTP_ZONE_GET(zone, type)
 * SCTP_ZONE_FREE(zone, element)
 * SCTP_ZONE_DESTROY(zone)
 */
/* All os's must implement this address gatherer. If
 * no VRF's exist, then vrf 0 is the only one and all
 * addresses and ifn's live here.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_init_vrf_list(mut vrfid: libc::c_int) {
    if vrfid > 0i32 {
        /* can't do that */
        return;
    }
    /* Don't care about return here */
    sctp_allocate_vrf(vrfid);
    /* Now we need to build all the ifn's
     * for this vrf and there addresses
     */
    sctp_init_ifns_for_vrf(vrfid);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_addr_change(mut ifa: *mut ifaddr, mut cmd: libc::c_int) {}
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
#[no_mangle]
pub unsafe extern "C" fn sctp_get_mbuf_for_msg(
    mut space_needed: libc::c_uint,
    mut want_header: libc::c_int,
    mut how: libc::c_int,
    mut allonebuf: libc::c_int,
    mut type_0: libc::c_int,
) -> *mut mbuf {
    let mut m = 0 as *mut mbuf;
    m = m_getm2(
        0 as *mut mbuf,
        space_needed as libc::c_int,
        how,
        type_0 as libc::c_short,
        if want_header != 0 { 0x2i32 } else { 0i32 },
        allonebuf,
    );
    if m.is_null() {
        /* bad, no memory */
        return m;
    }
    return m;
}
