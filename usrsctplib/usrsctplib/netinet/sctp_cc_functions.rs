use ::libc;
extern "C" {
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
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    /* int hz; is declared in sys/kern/subr_param.c and refers to kernel timer frequency.
     * See http://ivoras.sharanet.org/freebsd/vmware.html for additional info about kern.hz
     * hz is initialized in void init_param1(void) in that file.
     */
    #[no_mangle]
    static mut hz: libc::c_int;
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
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
    #[no_mangle]
    fn sctp_get_tick_count() -> uint32_t;
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t) -> libc::c_int;
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_timer_start(_: libc::c_int, _: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_timer_stop(
        _: libc::c_int,
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: *mut sctp_nets,
        _: uint32_t,
    );
    #[no_mangle]
    fn sctp_log_cwnd(stcb: *mut sctp_tcb, _: *mut sctp_nets, _: libc::c_int, _: uint8_t);
}
pub type size_t = libc::c_ulong;
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __int8_t = libc::c_schar;
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
pub type int8_t = __int8_t;
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
    pub c2rust_unnamed: C2RustUnnamed_215,
    pub c2rust_unnamed_0: C2RustUnnamed_213,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_213 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_214,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_214 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_215 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_216,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_216 {
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
    pub __in6_u: C2RustUnnamed_217,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_217 {
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
    pub so_incomp: C2RustUnnamed_225,
    pub so_comp: C2RustUnnamed_224,
    pub so_list: C2RustUnnamed_223,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_222,
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
    pub M_dat: C2RustUnnamed_218,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_218 {
    pub MH: C2RustUnnamed_219,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_219 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_220,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_220 {
    pub MH_ext: m_ext,
    pub MH_databuf: [libc::c_char; 176],
}
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct m_tag {
    pub m_tag_link: C2RustUnnamed_221,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_221 {
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
pub struct C2RustUnnamed_222 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_223 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_224 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_225 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}
/* modified for __Userspace__ */
/* Length to m_copy to copy all. */
/* umem_cache_t is defined in user_include/umem.h as
 * typedef struct umem_cache umem_cache_t;
 * Note:umem_zone_t is a pointer.
 */
pub type sctp_zone_t = size_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_226,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_226 {
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
    pub inp_hash: C2RustUnnamed_234,
    pub inp_list: C2RustUnnamed_233,
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
    pub inp_depend4: C2RustUnnamed_230,
    pub inp_depend6: C2RustUnnamed_229,
    pub inp_portlist: C2RustUnnamed_228,
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
    pub phd_hash: C2RustUnnamed_227,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_227 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_228 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_229 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_230 {
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
    pub ie_dependfaddr: C2RustUnnamed_232,
    pub ie_dependladdr: C2RustUnnamed_231,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_231 {
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
pub union C2RustUnnamed_232 {
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
pub struct C2RustUnnamed_233 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_234 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct calloutlist {
    pub tqh_first: *mut sctp_callout,
    pub tqh_last: *mut *mut sctp_callout,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_callout {
    pub tqe: C2RustUnnamed_235,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_235 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;
pub type sctp_rtentry_t = sctp_rtentry;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tmit_chunk {
    pub rec: C2RustUnnamed_264,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_236,
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
pub struct C2RustUnnamed_236 {
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
    pub sctp_next: C2RustUnnamed_242,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_net_route {
    pub ro_rt: *mut sctp_rtentry_t,
    pub _l_addr: sctp_sockstore,
    pub _s_addr: *mut sctp_ifa,
}
/* SCTP local IFA flags */
/* its up and active */
/* being deleted,
 * when refcount = 0. Note
 * that it is pulled from the ifn list
 * and ifa_p is nulled right away but
 * it cannot be freed until the last *net
 * pointing to it is deleted.
 */
/* Hold off using this one */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifa {
    pub next_ifa: C2RustUnnamed_241,
    pub next_bucket: C2RustUnnamed_240,
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
pub struct sctp_ifn {
    pub ifalist: sctp_ifalist,
    pub vrf: *mut sctp_vrf,
    pub next_ifn: C2RustUnnamed_238,
    pub next_bucket: C2RustUnnamed_237,
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
pub struct C2RustUnnamed_237 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_238 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_239,
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
pub struct C2RustUnnamed_239 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_240 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_241 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_242 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
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
    pub next: C2RustUnnamed_243,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_243 {
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
    pub next: C2RustUnnamed_245,
    pub next_instrm: C2RustUnnamed_244,
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
pub struct C2RustUnnamed_244 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_245 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_249,
    pub sctp_tcblist: C2RustUnnamed_248,
    pub sctp_tcbasocidhash: C2RustUnnamed_247,
    pub sctp_asocs: C2RustUnnamed_246,
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
/* time when this address was created */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_block_entry {
    pub error: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_246 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_247 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_248 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_249 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}
/* we choose the number to make a pcb a page */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_254,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_253,
    pub sctp_hash: C2RustUnnamed_252,
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
pub struct sctpasochead {
    pub lh_first: *mut sctp_tcb,
}
/* This struct is here to cut out the compatiabilty
 * pad that bulks up both the inp and stcb. The non
 * pad portion MUST stay in complete sync with
 * sctp_sndrcvinfo... i.e. if sinfo_xxxx is added
 * this must be done here too.
 */

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
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_250,
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
pub type end_func = Option<unsafe extern "C" fn(_: *mut libc::c_void, _: uint32_t) -> ()>;
pub type inp_func = Option<
    unsafe extern "C" fn(_: *mut sctp_inpcb, _: *mut libc::c_void, _: uint32_t) -> libc::c_int,
>;
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
pub struct C2RustUnnamed_250 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
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
pub struct sctp_laddr {
    pub sctp_nxt_addr: C2RustUnnamed_251,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_251 {
    pub le_next: *mut sctp_laddr,
    pub le_prev: *mut *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpladdr {
    pub lh_first: *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_252 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_253 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_readhead {
    pub tqh_first: *mut sctp_queued_to_read,
    pub tqh_last: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_254 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}
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
    pub next_spoke: C2RustUnnamed_255,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_255 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_256,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_256 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_257,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_257 {
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
    pub next: C2RustUnnamed_259,
    pub ss_next: C2RustUnnamed_258,
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
pub struct C2RustUnnamed_258 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_259 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}
/*
 * JRS - Structure to hold function pointers to the functions responsible
 * for congestion control.
 */

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

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_chunkhdr {
    pub chunk_type: uint8_t,
    pub chunk_flags: uint8_t,
    pub chunk_length: uint16_t,
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
    pub next_resp: C2RustUnnamed_260,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_260 {
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
/* used to save ASCONF-ACK chunks for retransmission */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ackhead {
    pub tqh_first: *mut sctp_asconf_ack,
    pub tqh_last: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ack {
    pub next: C2RustUnnamed_261,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_261 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_262,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_262 {
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
pub struct sctp_asconf_addrhead {
    pub tqh_first: *mut sctp_asconf_addr,
    pub tqh_last: *mut *mut sctp_asconf_addr,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_263,
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
pub struct C2RustUnnamed_263 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_264 {
    pub data: sctp_data_chunkrec,
    pub chunk_id: chk_id,
}

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
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctphdr {
    pub src_port: uint16_t,
    pub dest_port: uint16_t,
    pub v_tag: uint32_t,
    pub checksum: uint32_t,
}

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
    pub sctp_nxt_tagblock: C2RustUnnamed_265,
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
pub struct C2RustUnnamed_265 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrflist {
    pub lh_first: *mut sctp_vrf,
}
pub type __timezone_ptr_t = *mut timezone;

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
/* Here starts Sally Floyds HS-TCP */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_hs_raise_drop {
    pub cwnd: int32_t,
    pub increase: int8_t,
    pub drop_percent: int8_t,
}
unsafe extern "C" fn sctp_enforce_cwnd_limit(
    mut assoc: *mut sctp_association,
    mut net: *mut sctp_nets,
) {
    if (*assoc).max_cwnd > 0u32
        && (*net).cwnd > (*assoc).max_cwnd
        && (*net).cwnd as libc::c_ulong
            > ((*net).mtu as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
    {
        (*net).cwnd = (*assoc).max_cwnd;
        if ((*net).cwnd as libc::c_ulong)
            < ((*net).mtu as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
        {
            (*net).cwnd = ((*net).mtu as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                as uint32_t
        }
    };
}
unsafe extern "C" fn sctp_set_initial_cc_param(mut stcb: *mut sctp_tcb, mut net: *mut sctp_nets) {
    let mut assoc = 0 as *mut sctp_association;
    let mut cwnd_in_mtu = 0;
    assoc = &mut (*stcb).asoc;
    cwnd_in_mtu = system_base_info.sctpsysctl.sctp_initial_cwnd;
    if cwnd_in_mtu == 0u32 {
        /* Using 0 means that the value of RFC 4960 is used. */
        (*net).cwnd = if (*net).mtu.wrapping_mul(4u32)
            > (if (2u32).wrapping_mul((*net).mtu) > 4380u32 {
                (2u32).wrapping_mul((*net).mtu)
            } else {
                4380u32
            }) {
            if (2u32).wrapping_mul((*net).mtu) > 4380u32 {
                (2u32).wrapping_mul((*net).mtu)
            } else {
                4380u32
            }
        } else {
            (*net).mtu.wrapping_mul(4u32)
        }
    } else {
        /*
         * We take the minimum of the burst limit and the
         * initial congestion window.
         */
        if (*assoc).max_burst > 0u32 && cwnd_in_mtu > (*assoc).max_burst {
            cwnd_in_mtu = (*assoc).max_burst
        }
        (*net).cwnd = ((*net).mtu as libc::c_ulong)
            .wrapping_sub(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
            .wrapping_mul(cwnd_in_mtu as libc::c_ulong) as uint32_t
    }
    if (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 2i32
        || (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 3i32
    {
        /* In case of resource pooling initialize appropriately */
        (*net).cwnd = ((*net).cwnd).wrapping_div((*assoc).numnets);
        if ((*net).cwnd as libc::c_ulong)
            < ((*net).mtu as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
        {
            (*net).cwnd = ((*net).mtu as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                as uint32_t
        }
    }
    sctp_enforce_cwnd_limit(assoc, net);
    (*net).ssthresh = (*assoc).peers_rwnd;
    if system_base_info.sctpsysctl.sctp_logging_level & (0x2i32 | 0x4i32) as libc::c_uint != 0 {
        sctp_log_cwnd(stcb, net, 0i32, 62u8);
    };
}
unsafe extern "C" fn sctp_cwnd_update_after_fr(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) {
    let mut net = 0 as *mut sctp_nets;
    let mut t_ssthresh = 0;
    let mut t_cwnd = 0;
    let mut t_ucwnd_sbw = 0;
    /* MT FIXME: Don't compute this over and over again */
    t_ssthresh = 0u32;
    t_cwnd = 0u32;
    t_ucwnd_sbw = 0u64;
    if (*asoc).sctp_cmt_on_off as libc::c_int == 2i32
        || (*asoc).sctp_cmt_on_off as libc::c_int == 3i32
    {
        net = (*asoc).nets.tqh_first;
        while !net.is_null() {
            t_ssthresh = (t_ssthresh).wrapping_add((*net).ssthresh);
            t_cwnd = (t_cwnd).wrapping_add((*net).cwnd);
            if (*net).lastsa > 0i32 {
                t_ucwnd_sbw = (t_ucwnd_sbw)
                    .wrapping_add(((*net).cwnd as uint64_t).wrapping_div((*net).lastsa as uint64_t))
            }
            net = (*net).sctp_next.tqe_next
        }
        if t_ucwnd_sbw == 0u64 {
            t_ucwnd_sbw = 1u64
        }
    }
    /*-
     * CMT fast recovery code. Need to debug. ((sctp_cmt_on_off > 0) &&
     * (net->fast_retran_loss_recovery == 0)))
     */
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        if (*asoc).fast_retran_loss_recovery as libc::c_int == 0i32
            || (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
        {
            /* out of a RFC2582 Fast recovery window? */
            if (*net).net_ack > 0u32 {
                let mut lchk = 0 as *mut sctp_tmit_chunk;
                let mut old_cwnd = (*net).cwnd as libc::c_int;
                if (*asoc).sctp_cmt_on_off as libc::c_int == 2i32
                    || (*asoc).sctp_cmt_on_off as libc::c_int == 3i32
                {
                    if (*asoc).sctp_cmt_on_off as libc::c_int == 2i32 {
                        (*net).ssthresh = (4u64)
                            .wrapping_mul((*net).mtu as uint64_t)
                            .wrapping_mul((*net).ssthresh as uint64_t)
                            .wrapping_div(t_ssthresh as uint64_t)
                            as uint32_t
                    }
                    if (*asoc).sctp_cmt_on_off as libc::c_int == 3i32 {
                        let mut srtt = 0;
                        srtt = (*net).lastsa as uint32_t;
                        /* lastsa>>3;  we don't need to devide ...*/
                        if srtt == 0u32 {
                            srtt = 1u32
                        }
                        /* Short Version => Equal to Contel Version MBe */
                        (*net).ssthresh = (4u64)
                            .wrapping_mul((*net).mtu as uint64_t)
                            .wrapping_mul((*net).cwnd as uint64_t)
                            .wrapping_div((srtt as uint64_t).wrapping_mul(t_ucwnd_sbw))
                            as uint32_t
                    }
                    if (*net).cwnd > t_cwnd.wrapping_div(2u32)
                        && (*net).ssthresh < (*net).cwnd.wrapping_sub(t_cwnd.wrapping_div(2u32))
                    {
                        (*net).ssthresh = (*net).cwnd.wrapping_sub(t_cwnd.wrapping_div(2u32))
                    }
                    if (*net).ssthresh < (*net).mtu {
                        (*net).ssthresh = (*net).mtu
                    }
                } else {
                    (*net).ssthresh = (*net).cwnd.wrapping_div(2u32);
                    if (*net).ssthresh < (*net).mtu.wrapping_mul(2u32) {
                        (*net).ssthresh = (2u32).wrapping_mul((*net).mtu)
                    }
                }
                (*net).cwnd = (*net).ssthresh;
                sctp_enforce_cwnd_limit(asoc, net);
                if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                    sctp_log_cwnd(
                        stcb,
                        net,
                        (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                        1u8,
                    );
                }
                lchk = (*asoc).send_queue.tqh_first;
                (*net).partial_bytes_acked = 0u32;
                /* Turn on fast recovery window */
                (*asoc).fast_retran_loss_recovery = 1u8;
                if lchk.is_null() {
                    /* Mark end of the window */
                    (*asoc).fast_recovery_tsn = (*asoc).sending_seq.wrapping_sub(1u32)
                } else {
                    (*asoc).fast_recovery_tsn = (*lchk).rec.data.tsn.wrapping_sub(1u32)
                }
                /*
                 * CMT fast recovery -- per destination
                 * recovery variable.
                 */
                (*net).fast_retran_loss_recovery = 1u8;
                if lchk.is_null() {
                    /* Mark end of the window */
                    (*net).fast_recovery_tsn = (*asoc).sending_seq.wrapping_sub(1u32)
                } else {
                    (*net).fast_recovery_tsn = (*lchk).rec.data.tsn.wrapping_sub(1u32)
                }
                sctp_timer_stop(
                    1i32,
                    (*stcb).sctp_ep,
                    stcb,
                    net,
                    (0xd0000000u32).wrapping_add(0x1u32),
                );
                sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, net);
            }
        } else if (*net).net_ack > 0u32 {
            /*
             * Mark a peg that we WOULD have done a cwnd
             * reduction but RFC2582 prevented this action.
             */
            ::std::intrinsics::atomic_xadd(
                &mut system_base_info.sctpstat.sctps_fastretransinrtt,
                1u32,
            );
        }
        net = (*net).sctp_next.tqe_next
    }
}
/* Gaining, step down possible */
unsafe extern "C" fn cc_bw_same(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut nbw: uint64_t,
    mut rtt_offset: uint64_t,
    mut inst_ind: uint8_t,
) -> libc::c_int {
    if (*net).rtt > (*net).cc_mod.rtcc.lbw_rtt.wrapping_add(rtt_offset) {
        /*
         * rtt increased
         * we don't update bw.. so we don't
         * update the rtt either.
         */
        if (*net).cc_mod.rtcc.steady_step as libc::c_int != 0 && inst_ind as libc::c_int != 1i32 {
            if (*net).cc_mod.rtcc.last_step_state as libc::c_int == 5i32 {
                (*net).cc_mod.rtcc.step_cnt = (*net).cc_mod.rtcc.step_cnt.wrapping_add(1)
            } else {
                (*net).cc_mod.rtcc.step_cnt = 1u16
            }
            (*net).cc_mod.rtcc.last_step_state = 5u8;
            if (*net).cc_mod.rtcc.step_cnt as libc::c_int
                == (*net).cc_mod.rtcc.steady_step as libc::c_int
                || (*net).cc_mod.rtcc.step_cnt as libc::c_int
                    > (*net).cc_mod.rtcc.steady_step as libc::c_int
                    && (*net).cc_mod.rtcc.step_cnt as libc::c_int
                        % (*net).cc_mod.rtcc.steady_step as libc::c_int
                        == 0i32
            {
                /* Try a step down */
                if (*net).cwnd > (4u32).wrapping_mul((*net).mtu) {
                    (*net).cwnd = ((*net).cwnd).wrapping_sub((*net).mtu);
                    (*net).cc_mod.rtcc.vol_reduce = (*net).cc_mod.rtcc.vol_reduce.wrapping_add(1)
                } else {
                    (*net).cc_mod.rtcc.step_cnt = 0u16
                }
            }
        }
        return 1i32;
    }
    if (*net).rtt < (*net).cc_mod.rtcc.lbw_rtt.wrapping_sub(rtt_offset) {
        /*
         * rtt decreased, there could be more room.
         * we update both the bw and the rtt here to
         * lock this in as a good step down.
         */
        if (*net).cc_mod.rtcc.steady_step != 0 {
            if (*net).cc_mod.rtcc.last_step_state as libc::c_int == 5i32
                && (*net).cc_mod.rtcc.step_cnt as libc::c_int
                    > (*net).cc_mod.rtcc.steady_step as libc::c_int
            {
                /* Step down worked */
                (*net).cc_mod.rtcc.step_cnt = 0u16;
                return 1i32;
            } else {
                (*net).cc_mod.rtcc.last_step_state = 6u8;
                (*net).cc_mod.rtcc.step_cnt = 0u16
            }
        }
        (*net).cc_mod.rtcc.lbw = nbw;
        (*net).cc_mod.rtcc.lbw_rtt = (*net).rtt;
        (*net).cc_mod.rtcc.cwnd_at_bw_set = (*net).cwnd;
        if inst_ind as libc::c_int == 3i32 {
            return 1i32;
        } else if inst_ind as libc::c_int == 2i32 {
            return 1i32;
        } else {
            return 0i32;
        }
    }
    /* Ok bw and rtt remained the same .. no update to any
     */
    if (*net).cc_mod.rtcc.steady_step as libc::c_int != 0 && inst_ind as libc::c_int != 1i32 {
        if (*net).cc_mod.rtcc.last_step_state as libc::c_int == 5i32 {
            (*net).cc_mod.rtcc.step_cnt = (*net).cc_mod.rtcc.step_cnt.wrapping_add(1)
        } else {
            (*net).cc_mod.rtcc.step_cnt = 1u16
        }
        (*net).cc_mod.rtcc.last_step_state = 5u8;
        if (*net).cc_mod.rtcc.step_cnt as libc::c_int
            == (*net).cc_mod.rtcc.steady_step as libc::c_int
            || (*net).cc_mod.rtcc.step_cnt as libc::c_int
                > (*net).cc_mod.rtcc.steady_step as libc::c_int
                && (*net).cc_mod.rtcc.step_cnt as libc::c_int
                    % (*net).cc_mod.rtcc.steady_step as libc::c_int
                    == 0i32
        {
            /* Try a step down */
            if (*net).cwnd > (4u32).wrapping_mul((*net).mtu) {
                (*net).cwnd = ((*net).cwnd).wrapping_sub((*net).mtu);
                (*net).cc_mod.rtcc.vol_reduce = (*net).cc_mod.rtcc.vol_reduce.wrapping_add(1);
                return 1i32;
            } else {
                (*net).cc_mod.rtcc.step_cnt = 0u16
            }
        }
    }
    if inst_ind as libc::c_int == 3i32 {
        return 1i32;
    } else if inst_ind as libc::c_int == 2i32 {
        return 1i32;
    } else {
        return (*net).cc_mod.rtcc.ret_from_eq as libc::c_int;
    };
}
unsafe extern "C" fn cc_bw_decrease(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut nbw: uint64_t,
    mut rtt_offset: uint64_t,
    mut inst_ind: uint8_t,
) -> libc::c_int {
    /* Bandwidth decreased.*/
    if (*net).rtt > (*net).cc_mod.rtcc.lbw_rtt.wrapping_add(rtt_offset) {
        /* rtt increased */
        /* Did we add more */
        if (*net).cwnd > (*net).cc_mod.rtcc.cwnd_at_bw_set && inst_ind as libc::c_int != 1i32 {
            /* We caused it maybe.. back off? */
            if (*net).cc_mod.rtcc.ret_from_eq != 0 {
                /* Switch over to CA if we are less aggressive */
                (*net).ssthresh = (*net).cwnd.wrapping_sub(1u32);
                (*net).partial_bytes_acked = 0u32
            }
            return 1i32;
        }
        /* Someone else - fight for more? */
        if (*net).cc_mod.rtcc.steady_step != 0 {
            /* Did we voluntarily give up some? if so take
             * one back please
             */
            if (*net).cc_mod.rtcc.vol_reduce != 0 && inst_ind as libc::c_int != 3i32 {
                (*net).cwnd = ((*net).cwnd).wrapping_add((*net).mtu);
                sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
                (*net).cc_mod.rtcc.vol_reduce = (*net).cc_mod.rtcc.vol_reduce.wrapping_sub(1)
            }
            (*net).cc_mod.rtcc.last_step_state = 2u8;
            (*net).cc_mod.rtcc.step_cnt = 0u16
        }
    } else if (*net).rtt < (*net).cc_mod.rtcc.lbw_rtt.wrapping_sub(rtt_offset) {
        /* bw & rtt decreased */
        if (*net).cc_mod.rtcc.steady_step != 0 {
            if (*net).cc_mod.rtcc.vol_reduce != 0 && inst_ind as libc::c_int != 3i32 {
                (*net).cwnd = ((*net).cwnd).wrapping_add((*net).mtu);
                sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
                (*net).cc_mod.rtcc.vol_reduce = (*net).cc_mod.rtcc.vol_reduce.wrapping_sub(1)
            }
            (*net).cc_mod.rtcc.last_step_state = 3u8;
            (*net).cc_mod.rtcc.step_cnt = 0u16
        }
    } else if (*net).cc_mod.rtcc.steady_step != 0 {
        if (*net).cc_mod.rtcc.vol_reduce != 0 && inst_ind as libc::c_int != 3i32 {
            (*net).cwnd = ((*net).cwnd).wrapping_add((*net).mtu);
            sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
            (*net).cc_mod.rtcc.vol_reduce = (*net).cc_mod.rtcc.vol_reduce.wrapping_sub(1)
        }
        (*net).cc_mod.rtcc.last_step_state = 4u8;
        (*net).cc_mod.rtcc.step_cnt = 0u16
    }
    (*net).cc_mod.rtcc.lbw = nbw;
    (*net).cc_mod.rtcc.lbw_rtt = (*net).rtt;
    (*net).cc_mod.rtcc.cwnd_at_bw_set = (*net).cwnd;
    if inst_ind as libc::c_int == 3i32 {
        return 1i32;
    } else {
        return 0i32;
    };
}
unsafe extern "C" fn cc_bw_increase(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut nbw: uint64_t,
) -> libc::c_int {
    /* The bw decreased but rtt stayed the same */
    /* BW increased, so update and
     * return 0, since all actions in
     * our table say to do the normal CC
     * update. Note that we pay no attention to
     * the inst_ind since our overall sum is increasing.
     */
    if (*net).cc_mod.rtcc.steady_step != 0 {
        (*net).cc_mod.rtcc.last_step_state = 0u8;
        (*net).cc_mod.rtcc.step_cnt = 0u16;
        (*net).cc_mod.rtcc.vol_reduce = 0u32
    }
    (*net).cc_mod.rtcc.lbw = nbw;
    (*net).cc_mod.rtcc.lbw_rtt = (*net).rtt;
    (*net).cc_mod.rtcc.cwnd_at_bw_set = (*net).cwnd;
    return 0i32;
}
/* RTCC Algorithm to limit growth of cwnd, return
 * true if you want to NOT allow cwnd growth
 */
unsafe extern "C" fn cc_bw_limit(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut nbw: uint64_t,
) -> libc::c_int {
    let mut bw_offset = 0;
    let mut bw_shift = 0;
    let mut inst_ind = 0;
    let mut ret = 0;
    /*-
     * Here we need to see if we want
     * to limit cwnd growth due to increase
     * in overall rtt but no increase in bw.
     * We use the following table to figure
     * out what we should do. When we return
     * 0, cc update goes on as planned. If we
     * return 1, then no cc update happens and cwnd
     * stays where it is at.
     * ----------------------------------
     *   BW    |    RTT   | Action
     * *********************************
     *   INC   |    INC   | return 0
     * ----------------------------------
     *   INC   |    SAME  | return 0
     * ----------------------------------
     *   INC   |    DECR  | return 0
     * ----------------------------------
     *   SAME  |    INC   | return 1
     * ----------------------------------
     *   SAME  |    SAME  | return 1
     * ----------------------------------
     *   SAME  |    DECR  | return 0
     * ----------------------------------
     *   DECR  |    INC   | return 0 or 1 based on if we caused.
     * ----------------------------------
     *   DECR  |    SAME  | return 0
     * ----------------------------------
     *   DECR  |    DECR  | return 0
     * ----------------------------------
     *
     * We are a bit fuzz on what an increase or
     * decrease is. For BW it is the same if
     * it did not change within 1/64th. For
     * RTT it stayed the same if it did not
     * change within 1/32nd
     */
    bw_shift = system_base_info.sctpsysctl.sctp_rttvar_bw as libc::c_int;
    if (*net).cc_mod.rtcc.rtt_set_this_sack != 0 {
        let mut bytes_for_this_rtt = 0;
        (*net).cc_mod.rtcc.rtt_set_this_sack = 0u8;
        bytes_for_this_rtt = (*net)
            .cc_mod
            .rtcc
            .bw_bytes
            .wrapping_sub((*net).cc_mod.rtcc.bw_bytes_at_last_rttc);
        (*net).cc_mod.rtcc.bw_bytes_at_last_rttc = (*net).cc_mod.rtcc.bw_bytes;
        if (*net).rtt != 0 {
            let mut div = 0;
            div = (*net).rtt.wrapping_div(1000u64);
            if div != 0 {
                let mut inst_bw = 0;
                let mut inst_off = 0;
                inst_bw = bytes_for_this_rtt.wrapping_div(div);
                inst_off = inst_bw >> bw_shift;
                if inst_bw > nbw {
                    inst_ind = 3u8
                } else if inst_bw.wrapping_add(inst_off) < nbw {
                    inst_ind = 1u8
                } else {
                    inst_ind = 2u8
                }
            } else {
                inst_ind = (*net).cc_mod.rtcc.last_inst_ind
            }
        } else {
            inst_ind = (*net).cc_mod.rtcc.last_inst_ind
        }
    } else {
        /* No rtt measurement, use last one */
        inst_ind = (*net).cc_mod.rtcc.last_inst_ind
    }
    bw_offset = (*net).cc_mod.rtcc.lbw >> bw_shift;
    if nbw > (*net).cc_mod.rtcc.lbw.wrapping_add(bw_offset) {
        ret = cc_bw_increase(stcb, net, nbw)
    } else {
        let mut rtt_offset = 0;
        rtt_offset = (*net).cc_mod.rtcc.lbw_rtt >> system_base_info.sctpsysctl.sctp_rttvar_rtt;
        if nbw < (*net).cc_mod.rtcc.lbw.wrapping_sub(bw_offset) {
            ret = cc_bw_decrease(stcb, net, nbw, rtt_offset, inst_ind)
        } else {
            /* If we reach here then
             * we are in a situation where
             * the bw stayed the same.
             */
            ret = cc_bw_same(stcb, net, nbw, rtt_offset, inst_ind)
        }
    }
    (*net).cc_mod.rtcc.last_inst_ind = inst_ind;
    return ret;
}
unsafe extern "C" fn sctp_cwnd_update_after_sack_common(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut accum_moved: libc::c_int,
    mut reneged_all: libc::c_int,
    mut will_exit: libc::c_int,
    mut use_rtcc: libc::c_int,
) {
    let mut net = 0 as *mut sctp_nets;
    let mut t_ssthresh = 0;
    let mut t_cwnd = 0;
    let mut t_ucwnd_sbw = 0;
    let mut t_path_mptcp = 0;
    let mut mptcp_like_alpha = 0;
    let mut srtt = 0;
    /* MT FIXME: Don't compute this over and over again */
    t_ssthresh = 0u32;
    t_cwnd = 0u32;
    t_ucwnd_sbw = 0u64;
    t_path_mptcp = 0u64;
    mptcp_like_alpha = 1u64;
    if (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 2i32
        || (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 3i32
        || (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 4i32
    {
        let mut max_path = 0;
        max_path = 0u64;
        net = (*stcb).asoc.nets.tqh_first;
        while !net.is_null() {
            t_ssthresh = (t_ssthresh).wrapping_add((*net).ssthresh);
            t_cwnd = (t_cwnd).wrapping_add((*net).cwnd);
            /* lastsa>>3;  we don't need to devide ...*/
            srtt = (*net).lastsa as uint32_t;
            if srtt > 0u32 {
                let mut tmp = 0;
                t_ucwnd_sbw = (t_ucwnd_sbw)
                    .wrapping_add(((*net).cwnd as uint64_t).wrapping_div(srtt as uint64_t));
                t_path_mptcp = (t_path_mptcp).wrapping_add(
                    (((*net).cwnd as uint64_t) << 16i32)
                        .wrapping_div(((*net).mtu as uint64_t).wrapping_mul(srtt as uint64_t)),
                );
                tmp = (((*net).cwnd as uint64_t) << 40i32).wrapping_div(
                    ((*net).mtu as uint64_t).wrapping_mul(srtt.wrapping_mul(srtt) as uint64_t),
                );
                if tmp > max_path {
                    max_path = tmp
                }
            }
            net = (*net).sctp_next.tqe_next
        }
        if t_path_mptcp > 0u64 {
            mptcp_like_alpha = max_path.wrapping_div(t_path_mptcp.wrapping_mul(t_path_mptcp))
        } else {
            mptcp_like_alpha = 1u64
        }
    }
    if t_ssthresh == 0u32 {
        t_ssthresh = 1u32
    }
    if t_ucwnd_sbw == 0u64 {
        t_ucwnd_sbw = 1u64
    }

    /* *****************************/
    /* update cwnd and Early FR   */
    /* *****************************/
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        /* if nothing was acked on this destination skip it */
        if (*net).net_ack == 0u32 {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                sctp_log_cwnd(stcb, net, 0i32, 64u8);
            }
        } else {
            let mut current_block_138: u64;
            if (*asoc).fast_retran_loss_recovery as libc::c_int != 0
                && will_exit == 0i32
                && (*asoc).sctp_cmt_on_off as libc::c_int == 0i32
            {
                /*
                 * If we are in loss recovery we skip any cwnd
                 * update
                 */
                return;
            }
            /*
             * Did any measurements go on for this network?
             */
            if use_rtcc != 0 && (*net).cc_mod.rtcc.tls_needs_set as libc::c_int > 0i32 {
                let mut nbw = 0;
                /*
                 * At this point our bw_bytes has been updated
                 * by incoming sack information.
                 *
                 * But our bw may not yet be set.
                 *
                 */
                if (*net).cc_mod.rtcc.new_tot_time.wrapping_div(1000u64) > 0u64 {
                    nbw = (*net)
                        .cc_mod
                        .rtcc
                        .bw_bytes
                        .wrapping_div((*net).cc_mod.rtcc.new_tot_time.wrapping_div(1000u64))
                } else {
                    nbw = (*net).cc_mod.rtcc.bw_bytes
                }
                if (*net).cc_mod.rtcc.lbw != 0 {
                    if cc_bw_limit(stcb, net, nbw) != 0 {
                        current_block_138 = 7245201122033322888;
                    } else {
                        current_block_138 = 11441799814184323368;
                    }
                } else {
                    (*net).cc_mod.rtcc.lbw = nbw;
                    (*net).cc_mod.rtcc.lbw_rtt = (*net).rtt;
                    if (*net).cc_mod.rtcc.rtt_set_this_sack != 0 {
                        (*net).cc_mod.rtcc.rtt_set_this_sack = 0u8;
                        (*net).cc_mod.rtcc.bw_bytes_at_last_rttc = (*net).cc_mod.rtcc.bw_bytes
                    }
                    current_block_138 = 11441799814184323368;
                }
            } else {
                current_block_138 = 11441799814184323368;
            }
            match current_block_138 {
                7245201122033322888 => {}
                _ => {
                    /*
                     * CMT: CUC algorithm. Update cwnd if pseudo-cumack has
                     * moved.
                     */
                    if accum_moved != 0
                        || (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
                            && (*net).new_pseudo_cumack as libc::c_int != 0
                    {
                        let mut incr = 0;
                        if (*net).cwnd <= (*net).ssthresh {
                            /* We are in slow start */
                            if (*net).flight_size.wrapping_add((*net).net_ack) >= (*net).cwnd {
                                let mut limit = 0;
                                match (*asoc).sctp_cmt_on_off as libc::c_int {
                                    2 => {
                                        limit = ((*net).mtu as uint64_t)
                                            .wrapping_mul(
                                                system_base_info.sctpsysctl.sctp_L2_abc_variable
                                                    as uint64_t,
                                            )
                                            .wrapping_mul((*net).ssthresh as uint64_t)
                                            .wrapping_div(t_ssthresh as uint64_t)
                                            as uint32_t;
                                        incr = ((*net).net_ack as uint64_t)
                                            .wrapping_mul((*net).ssthresh as uint64_t)
                                            .wrapping_div(t_ssthresh as uint64_t)
                                            as uint32_t;
                                        if incr > limit {
                                            incr = limit
                                        }
                                        if incr == 0u32 {
                                            incr = 1u32
                                        }
                                    }
                                    3 => {
                                        /* lastsa>>3;  we don't need to divide ...*/
                                        srtt = (*net).lastsa as uint32_t;
                                        if srtt == 0u32 {
                                            srtt = 1u32
                                        }
                                        limit = ((*net).mtu as uint64_t)
                                            .wrapping_mul(
                                                system_base_info.sctpsysctl.sctp_L2_abc_variable
                                                    as uint64_t,
                                            )
                                            .wrapping_mul((*net).cwnd as uint64_t)
                                            .wrapping_div(
                                                (srtt as uint64_t).wrapping_mul(t_ucwnd_sbw),
                                            )
                                            as uint32_t;
                                        /* INCREASE FACTOR */
                                        incr = ((*net).net_ack as uint64_t)
                                            .wrapping_mul((*net).cwnd as uint64_t)
                                            .wrapping_div(
                                                (srtt as uint64_t).wrapping_mul(t_ucwnd_sbw),
                                            )
                                            as uint32_t;
                                        /* INCREASE FACTOR */
                                        if incr > limit {
                                            incr = limit
                                        }
                                        if incr == 0u32 {
                                            incr = 1u32
                                        }
                                    }
                                    4 => {
                                        limit = (((*net).mtu as uint64_t)
                                            .wrapping_mul(mptcp_like_alpha)
                                            .wrapping_mul(
                                                system_base_info.sctpsysctl.sctp_L2_abc_variable
                                                    as uint64_t,
                                            )
                                            >> 8i32)
                                            as uint32_t;
                                        incr = (((*net).net_ack as uint64_t)
                                            .wrapping_mul(mptcp_like_alpha)
                                            >> 8i32)
                                            as uint32_t;
                                        if incr > limit {
                                            incr = limit
                                        }
                                        if incr > (*net).net_ack {
                                            incr = (*net).net_ack
                                        }
                                        if incr > (*net).mtu {
                                            incr = (*net).mtu
                                        }
                                    }
                                    _ => {
                                        incr = (*net).net_ack;
                                        if incr
                                            > (*net).mtu.wrapping_mul(
                                                system_base_info.sctpsysctl.sctp_L2_abc_variable,
                                            )
                                        {
                                            incr = (*net).mtu.wrapping_mul(
                                                system_base_info.sctpsysctl.sctp_L2_abc_variable,
                                            )
                                        }
                                    }
                                }
                                (*net).cwnd = ((*net).cwnd).wrapping_add(incr);
                                sctp_enforce_cwnd_limit(asoc, net);
                                if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                                    sctp_log_cwnd(stcb, net, incr as libc::c_int, 4u8);
                                }
                            } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                                sctp_log_cwnd(stcb, net, (*net).net_ack as libc::c_int, 31u8);
                            }
                        } else {
                            /* We are in congestion avoidance */
                            /*
                             * Add to pba
                             */
                            (*net).partial_bytes_acked =
                                ((*net).partial_bytes_acked).wrapping_add((*net).net_ack);
                            if (*net).flight_size.wrapping_add((*net).net_ack) >= (*net).cwnd
                                && (*net).partial_bytes_acked >= (*net).cwnd
                            {
                                (*net).partial_bytes_acked =
                                    ((*net).partial_bytes_acked).wrapping_sub((*net).cwnd);
                                match (*asoc).sctp_cmt_on_off as libc::c_int {
                                    2 => {
                                        incr = ((*net).mtu as uint64_t)
                                            .wrapping_mul((*net).ssthresh as uint64_t)
                                            .wrapping_div(t_ssthresh as uint64_t)
                                            as uint32_t;
                                        if incr == 0u32 {
                                            incr = 1u32
                                        }
                                    }
                                    3 => {
                                        /* lastsa>>3;  we don't need to divide ... */
                                        srtt = (*net).lastsa as uint32_t;
                                        if srtt == 0u32 {
                                            srtt = 1u32
                                        }
                                        incr = ((*net).mtu as uint64_t)
                                            .wrapping_mul((*net).cwnd as uint64_t)
                                            .wrapping_div(
                                                (srtt as uint64_t).wrapping_mul(t_ucwnd_sbw),
                                            )
                                            as uint32_t;
                                        /* INCREASE FACTOR */
                                        if incr == 0u32 {
                                            incr = 1u32
                                        }
                                    }
                                    4 => {
                                        incr = (mptcp_like_alpha
                                            .wrapping_mul((*net).cwnd as uint64_t)
                                            >> 8i32)
                                            as uint32_t;
                                        if incr > (*net).mtu {
                                            incr = (*net).mtu
                                        }
                                    }
                                    _ => incr = (*net).mtu,
                                }
                                (*net).cwnd = ((*net).cwnd).wrapping_add(incr);
                                sctp_enforce_cwnd_limit(asoc, net);
                                if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                                    sctp_log_cwnd(stcb, net, (*net).mtu as libc::c_int, 5u8);
                                }
                            } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                                sctp_log_cwnd(stcb, net, (*net).net_ack as libc::c_int, 32u8);
                            }
                        }
                    } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                        sctp_log_cwnd(stcb, net, (*net).mtu as libc::c_int, 65u8);
                    }
                }
            }
        }
        /* Hold here, no update */
        net = (*net).sctp_next.tqe_next
    }
}
unsafe extern "C" fn sctp_cwnd_update_exit_pf_common(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    (*net).cwnd = (*net).mtu;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x1000000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Destination %p moved from PF to reachable with cwnd %d.\n\x00" as *const u8
                    as *const libc::c_char,
                net as *mut libc::c_void,
                (*net).cwnd,
            );
        }
    };
}
unsafe extern "C" fn sctp_cwnd_update_after_timeout(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    let mut t_ssthresh = 0;
    let mut t_cwnd = 0;
    let mut old_cwnd = (*net).cwnd as libc::c_int;

    /* MT FIXME: Don't compute this over and over again */
    t_ssthresh = 0u32;
    t_cwnd = 0u32;
    if (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 2i32
        || (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 3i32
    {
        let mut t_ucwnd_sbw = 0;
        let mut lnet = 0 as *mut sctp_nets;
        let mut srtt = 0;
        t_ucwnd_sbw = 0u64;
        lnet = (*stcb).asoc.nets.tqh_first;
        while !lnet.is_null() {
            t_ssthresh = (t_ssthresh).wrapping_add((*lnet).ssthresh);
            t_cwnd = (t_cwnd).wrapping_add((*lnet).cwnd);
            srtt = (*lnet).lastsa as uint32_t;
            /* lastsa>>3;  we don't need to divide ... */
            if srtt > 0u32 {
                t_ucwnd_sbw = (t_ucwnd_sbw)
                    .wrapping_add(((*lnet).cwnd as uint64_t).wrapping_div(srtt as uint64_t))
            }
            lnet = (*lnet).sctp_next.tqe_next
        }
        if t_ssthresh < 1u32 {
            t_ssthresh = 1u32
        }
        if t_ucwnd_sbw < 1u64 {
            t_ucwnd_sbw = 1u64
        }
        if (*stcb).asoc.sctp_cmt_on_off as libc::c_int == 2i32 {
            (*net).ssthresh = (4u64)
                .wrapping_mul((*net).mtu as uint64_t)
                .wrapping_mul((*net).ssthresh as uint64_t)
                .wrapping_div(t_ssthresh as uint64_t) as uint32_t
        } else {
            let mut cc_delta = 0;
            srtt = (*net).lastsa as uint32_t;
            /* lastsa>>3;  we don't need to divide ... */
            if srtt == 0u32 {
                srtt = 1u32
            }
            cc_delta = t_ucwnd_sbw
                .wrapping_mul(srtt as uint64_t)
                .wrapping_div(2u64);
            if cc_delta < t_cwnd as libc::c_ulong {
                (*net).ssthresh = (t_cwnd as uint64_t).wrapping_sub(cc_delta) as uint32_t
            } else {
                (*net).ssthresh = (*net).mtu
            }
        }
        if (*net).cwnd > t_cwnd.wrapping_div(2u32)
            && (*net).ssthresh < (*net).cwnd.wrapping_sub(t_cwnd.wrapping_div(2u32))
        {
            (*net).ssthresh = (*net).cwnd.wrapping_sub(t_cwnd.wrapping_div(2u32))
        }
        if (*net).ssthresh < (*net).mtu {
            (*net).ssthresh = (*net).mtu
        }
    } else {
        (*net).ssthresh = if (*net).cwnd.wrapping_div(2u32) > (4u32).wrapping_mul((*net).mtu) {
            (*net).cwnd.wrapping_div(2u32)
        } else {
            (4u32).wrapping_mul((*net).mtu)
        }
    }
    (*net).cwnd = (*net).mtu;
    (*net).partial_bytes_acked = 0u32;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
        sctp_log_cwnd(
            stcb,
            net,
            (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
            2u8,
        );
    };
}
unsafe extern "C" fn sctp_cwnd_update_after_ecn_echo_common(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut in_window: libc::c_int,
    mut num_pkt_lost: libc::c_int,
    mut use_rtcc: libc::c_int,
) {
    let mut old_cwnd = (*net).cwnd as libc::c_int;
    if use_rtcc != 0
        && (*net).lan_type as libc::c_int == 1i32
        && (*net).cc_mod.rtcc.use_dccc_ecn as libc::c_int != 0
    {
        /* Data center Congestion Control */
        if in_window == 0i32 {
            /* Go to CA with the cwnd at the point we sent
             * the TSN that was marked with a CE.
             */
            if (*net).ecn_prev_cwnd < (*net).cwnd {
                /* Restore to prev cwnd */
                (*net).cwnd = (*net)
                    .ecn_prev_cwnd
                    .wrapping_sub((*net).mtu.wrapping_mul(num_pkt_lost as libc::c_uint))
            } else {
                /* Just cut in 1/2 */
                (*net).cwnd = ((*net).cwnd).wrapping_div(2u32)
            }
            /* Drop to CA */
            (*net).ssthresh = (*net)
                .cwnd
                .wrapping_sub((num_pkt_lost as libc::c_uint).wrapping_mul((*net).mtu));
            if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                sctp_log_cwnd(
                    stcb,
                    net,
                    (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                    6u8,
                );
            }
        } else {
            /* Further tuning down required over the drastic original cut */
            (*net).ssthresh = ((*net).ssthresh)
                .wrapping_sub((*net).mtu.wrapping_mul(num_pkt_lost as libc::c_uint));
            (*net).cwnd =
                ((*net).cwnd).wrapping_sub((*net).mtu.wrapping_mul(num_pkt_lost as libc::c_uint));
            if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                sctp_log_cwnd(
                    stcb,
                    net,
                    (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                    6u8,
                );
            }
        }
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_ecnereducedcwnd, 1u32);
    } else if in_window == 0i32 {
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_ecnereducedcwnd, 1u32);
        (*net).ssthresh = (*net).cwnd.wrapping_div(2u32);
        if (*net).ssthresh < (*net).mtu {
            (*net).ssthresh = (*net).mtu;
            /* here back off the timer as well, to slow us down */
            (*net).RTO <<= 1i32
        }
        (*net).cwnd = (*net).ssthresh;
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
            sctp_log_cwnd(
                stcb,
                net,
                (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                6u8,
            );
        }
    };
}
unsafe extern "C" fn sctp_cwnd_update_after_packet_dropped(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut cp: *mut sctp_pktdrop_chunk,
    mut bottle_bw: *mut uint32_t,
    mut on_queue: *mut uint32_t,
) {
    let mut bw_avail = 0;
    let mut incr = 0;
    let mut old_cwnd = (*net).cwnd as libc::c_int;
    /* get bottle neck bw */
    *bottle_bw = ntohl((*cp).bottle_bw);
    /* and whats on queue */
    *on_queue = ntohl((*cp).current_onq);
    /*
     * adjust the on-queue if our flight is more it could be
     * that the router has not yet gotten data "in-flight" to it
     */
    if *on_queue < (*net).flight_size {
        *on_queue = (*net).flight_size
    }
    /* rtt is measured in micro seconds, bottle_bw in bytes per second */
    bw_avail = (*bottle_bw as uint64_t)
        .wrapping_mul((*net).rtt)
        .wrapping_div(1000000u64) as uint32_t;
    if bw_avail > *bottle_bw {
        /*
         * Cap the growth to no more than the bottle neck.
         * This can happen as RTT slides up due to queues.
         * It also means if you have more than a 1 second
         * RTT with a empty queue you will be limited to the
         * bottle_bw per second no matter if other points
         * have 1/2 the RTT and you could get more out...
         */
        bw_avail = *bottle_bw
    }
    if *on_queue > bw_avail {
        let mut seg_inflight = 0;
        let mut seg_onqueue = 0;
        let mut my_portion = 0;
        (*net).partial_bytes_acked = 0u32;
        /* how much are we over queue size? */
        incr = (*on_queue).wrapping_sub(bw_avail);
        if (*stcb).asoc.seen_a_sack_this_pkt != 0 {
            /*
             * undo any cwnd adjustment that the sack
             * might have made
             */
            (*net).cwnd = (*net).prev_cwnd
        }
        /* Now how much of that is mine? */
        seg_inflight = (*net).flight_size.wrapping_div((*net).mtu) as libc::c_int;
        seg_onqueue = (*on_queue).wrapping_div((*net).mtu) as libc::c_int;
        my_portion = incr
            .wrapping_mul(seg_inflight as libc::c_uint)
            .wrapping_div(seg_onqueue as libc::c_uint) as libc::c_int;
        /* Have I made an adjustment already */
        if (*net).cwnd > (*net).flight_size {
            let mut diff_adj = 0;
            diff_adj = (*net).cwnd.wrapping_sub((*net).flight_size) as libc::c_int;
            if diff_adj > my_portion {
                my_portion = 0i32
            } else {
                my_portion -= diff_adj
            }
        }
        /*
         * back down to the previous cwnd (assume we have
         * had a sack before this packet). minus what ever
         * portion of the overage is my fault.
         */
        (*net).cwnd = ((*net).cwnd).wrapping_sub(my_portion as libc::c_uint);
        /* we will NOT back down more than 1 MTU */
        if (*net).cwnd <= (*net).mtu {
            (*net).cwnd = (*net).mtu
        }
        /* force into CA */
        (*net).ssthresh = (*net).cwnd.wrapping_sub(1u32)
    } else {
        /*
         * Take 1/4 of the space left or max burst up ..
         * whichever is less.
         */
        incr = bw_avail.wrapping_sub(*on_queue) >> 2i32;
        if (*stcb).asoc.max_burst > 0u32 && (*stcb).asoc.max_burst.wrapping_mul((*net).mtu) < incr {
            incr = (*stcb).asoc.max_burst.wrapping_mul((*net).mtu)
        }
        (*net).cwnd = ((*net).cwnd).wrapping_add(incr)
    }
    if (*net).cwnd > bw_avail {
        /* We can't exceed the pipe size */
        (*net).cwnd = bw_avail
    }
    if (*net).cwnd < (*net).mtu {
        /* We always have 1 MTU */
        (*net).cwnd = (*net).mtu
    }
    sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
    if (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) != 0u32 {
        /* log only changes */
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
            sctp_log_cwnd(
                stcb,
                net,
                (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                6u8,
            );
        }
    };
}
unsafe extern "C" fn sctp_cwnd_update_after_output(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut burst_limit: libc::c_int,
) {
    let mut old_cwnd = (*net).cwnd as libc::c_int;
    if (*net).ssthresh < (*net).cwnd {
        (*net).ssthresh = (*net).cwnd
    }
    if burst_limit != 0 {
        (*net).cwnd = (*net)
            .flight_size
            .wrapping_add((burst_limit as libc::c_uint).wrapping_mul((*net).mtu));
        sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
            sctp_log_cwnd(
                stcb,
                net,
                (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                3u8,
            );
        }
    };
}
unsafe extern "C" fn sctp_cwnd_update_after_sack(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut accum_moved: libc::c_int,
    mut reneged_all: libc::c_int,
    mut will_exit: libc::c_int,
) {
    /* Passing a zero argument in last disables the rtcc algorithm */
    sctp_cwnd_update_after_sack_common(stcb, asoc, accum_moved, reneged_all, will_exit, 0i32);
}
unsafe extern "C" fn sctp_cwnd_update_after_ecn_echo(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut in_window: libc::c_int,
    mut num_pkt_lost: libc::c_int,
) {
    /* Passing a zero argument in last disables the rtcc algorithm */
    sctp_cwnd_update_after_ecn_echo_common(stcb, net, in_window, num_pkt_lost, 0i32);
}
/* Here starts the RTCCVAR type CC invented by RRS which
 * is a slight mod to RFC2581. We reuse a common routine or
 * two since these algorithms are so close and need to
 * remain the same.
 */
unsafe extern "C" fn sctp_cwnd_update_rtcc_after_ecn_echo(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut in_window: libc::c_int,
    mut num_pkt_lost: libc::c_int,
) {
    sctp_cwnd_update_after_ecn_echo_common(stcb, net, in_window, num_pkt_lost, 1i32);
}
unsafe extern "C" fn sctp_cwnd_update_rtcc_tsn_acknowledged(
    mut net: *mut sctp_nets,
    mut tp1: *mut sctp_tmit_chunk,
) {
    (*net).cc_mod.rtcc.bw_bytes =
        ((*net).cc_mod.rtcc.bw_bytes).wrapping_add((*tp1).send_size as libc::c_ulong);
}
unsafe extern "C" fn sctp_cwnd_prepare_rtcc_net_for_sack(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    if (*net).cc_mod.rtcc.tls_needs_set as libc::c_int > 0i32 {
        let mut ltls = timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        gettimeofday(&mut ltls, 0 as *mut timezone);
        ltls.tv_sec -= (*net).cc_mod.rtcc.tls.tv_sec;
        ltls.tv_usec -= (*net).cc_mod.rtcc.tls.tv_usec;
        if ltls.tv_usec < 0i64 {
            ltls.tv_sec -= 1;
            ltls.tv_usec += 1000000i64
        }
        (*net).cc_mod.rtcc.new_tot_time = (ltls.tv_sec * 1000000i64 + ltls.tv_usec) as uint64_t
    };
}
unsafe extern "C" fn sctp_cwnd_new_rtcc_transmission_begins(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    if (*net).cc_mod.rtcc.lbw != 0 {
        (*net).cc_mod.rtcc.lbw_rtt = 0u64;
        (*net).cc_mod.rtcc.cwnd_at_bw_set = 0u32;
        (*net).cc_mod.rtcc.lbw = 0u64;
        (*net).cc_mod.rtcc.bw_bytes_at_last_rttc = 0u64;
        (*net).cc_mod.rtcc.vol_reduce = 0u32;
        (*net).cc_mod.rtcc.bw_tot_time = 0u64;
        (*net).cc_mod.rtcc.bw_bytes = 0u64;
        (*net).cc_mod.rtcc.tls_needs_set = 0u8;
        if (*net).cc_mod.rtcc.steady_step != 0 {
            (*net).cc_mod.rtcc.vol_reduce = 0u32;
            (*net).cc_mod.rtcc.step_cnt = 0u16;
            (*net).cc_mod.rtcc.last_step_state = 0u8
        }
        if (*net).cc_mod.rtcc.ret_from_eq != 0 {
            let mut cwnd_in_mtu = 0;
            let mut cwnd = 0;
            cwnd_in_mtu = system_base_info.sctpsysctl.sctp_initial_cwnd;
            if cwnd_in_mtu == 0u32 {
                /* Using 0 means that the value of RFC 4960 is used. */
                cwnd = if (*net).mtu.wrapping_mul(4u32)
                    > (if (2u32).wrapping_mul((*net).mtu) > 4380u32 {
                        (2u32).wrapping_mul((*net).mtu)
                    } else {
                        4380u32
                    }) {
                    if (2u32).wrapping_mul((*net).mtu) > 4380u32 {
                        (2u32).wrapping_mul((*net).mtu)
                    } else {
                        4380u32
                    }
                } else {
                    (*net).mtu.wrapping_mul(4u32)
                }
            } else {
                /*
                 * We take the minimum of the burst limit and the
                 * initial congestion window.
                 */
                if (*stcb).asoc.max_burst > 0u32 && cwnd_in_mtu > (*stcb).asoc.max_burst {
                    cwnd_in_mtu = (*stcb).asoc.max_burst
                }
                cwnd = ((*net).mtu as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                    .wrapping_mul(cwnd_in_mtu as libc::c_ulong) as uint32_t
            }
            if (*net).cwnd > cwnd {
                /* Only set if we are not a timeout (i.e. down to 1 mtu) */
                (*net).cwnd = cwnd
            }
        }
    };
}
unsafe extern "C" fn sctp_set_rtcc_initial_cc_param(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    sctp_set_initial_cc_param(stcb, net);
    (*stcb).asoc.use_precise_time = 1u8;
    (*net).cc_mod.rtcc.lbw_rtt = 0u64;
    (*net).cc_mod.rtcc.cwnd_at_bw_set = 0u32;
    (*net).cc_mod.rtcc.vol_reduce = 0u32;
    (*net).cc_mod.rtcc.lbw = 0u64;
    (*net).cc_mod.rtcc.vol_reduce = 0u32;
    (*net).cc_mod.rtcc.bw_bytes_at_last_rttc = 0u64;
    (*net).cc_mod.rtcc.bw_tot_time = 0u64;
    (*net).cc_mod.rtcc.bw_bytes = 0u64;
    (*net).cc_mod.rtcc.tls_needs_set = 0u8;
    (*net).cc_mod.rtcc.ret_from_eq = system_base_info.sctpsysctl.sctp_rttvar_eqret as uint8_t;
    (*net).cc_mod.rtcc.steady_step = system_base_info.sctpsysctl.sctp_steady_step as uint16_t;
    (*net).cc_mod.rtcc.use_dccc_ecn = system_base_info.sctpsysctl.sctp_use_dccc_ecn as uint8_t;
    (*net).cc_mod.rtcc.step_cnt = 0u16;
    (*net).cc_mod.rtcc.last_step_state = 0u8;
}
unsafe extern "C" fn sctp_cwnd_rtcc_socket_option(
    mut stcb: *mut sctp_tcb,
    mut setorget: libc::c_int,
    mut cc_opt: *mut sctp_cc_option,
) -> libc::c_int {
    let mut net = 0 as *mut sctp_nets;
    if setorget == 1i32 {
        /* a set */
        if (*cc_opt).option == 0x2000i32 {
            if (*cc_opt).aid_value.assoc_value != 0u32 && (*cc_opt).aid_value.assoc_value != 1u32 {
                return 22i32;
            }
            net = (*stcb).asoc.nets.tqh_first;
            while !net.is_null() {
                (*net).cc_mod.rtcc.ret_from_eq = (*cc_opt).aid_value.assoc_value as uint8_t;
                net = (*net).sctp_next.tqe_next
            }
        } else if (*cc_opt).option == 0x2001i32 {
            if (*cc_opt).aid_value.assoc_value != 0u32 && (*cc_opt).aid_value.assoc_value != 1u32 {
                return 22i32;
            }
            net = (*stcb).asoc.nets.tqh_first;
            while !net.is_null() {
                (*net).cc_mod.rtcc.use_dccc_ecn = (*cc_opt).aid_value.assoc_value as uint8_t;
                net = (*net).sctp_next.tqe_next
            }
        } else if (*cc_opt).option == 0x2002i32 {
            net = (*stcb).asoc.nets.tqh_first;
            while !net.is_null() {
                (*net).cc_mod.rtcc.steady_step = (*cc_opt).aid_value.assoc_value as uint16_t;
                net = (*net).sctp_next.tqe_next
            }
        } else {
            return 22i32;
        }
    } else if (*cc_opt).option == 0x2000i32 {
        net = (*stcb).asoc.nets.tqh_first;
        if net.is_null() {
            return 14i32;
        }
        (*cc_opt).aid_value.assoc_value = (*net).cc_mod.rtcc.ret_from_eq as uint32_t
    } else if (*cc_opt).option == 0x2001i32 {
        net = (*stcb).asoc.nets.tqh_first;
        if net.is_null() {
            return 14i32;
        }
        (*cc_opt).aid_value.assoc_value = (*net).cc_mod.rtcc.use_dccc_ecn as uint32_t
    } else if (*cc_opt).option == 0x2002i32 {
        net = (*stcb).asoc.nets.tqh_first;
        if net.is_null() {
            return 14i32;
        }
        (*cc_opt).aid_value.assoc_value = (*net).cc_mod.rtcc.steady_step as uint32_t
    } else {
        return 22i32;
    }
    return 0i32;
}
unsafe extern "C" fn sctp_cwnd_update_rtcc_packet_transmitted(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    if (*net).cc_mod.rtcc.tls_needs_set as libc::c_int == 0i32 {
        gettimeofday(&mut (*net).cc_mod.rtcc.tls, 0 as *mut timezone);
        (*net).cc_mod.rtcc.tls_needs_set = 2u8
    };
}
unsafe extern "C" fn sctp_cwnd_update_rtcc_after_sack(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut accum_moved: libc::c_int,
    mut reneged_all: libc::c_int,
    mut will_exit: libc::c_int,
) {
    /* a get */
    /* Passing a one argument at the last enables the rtcc algorithm */
    sctp_cwnd_update_after_sack_common(stcb, asoc, accum_moved, reneged_all, will_exit, 1i32);
}
unsafe extern "C" fn sctp_rtt_rtcc_calculated(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut now: *mut timeval,
) {
    (*net).cc_mod.rtcc.rtt_set_this_sack = 1u8;
}
static mut sctp_cwnd_adjust: [sctp_hs_raise_drop; 73] = [
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 38i32,
            increase: 1i8,
            drop_percent: 50i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 118i32,
            increase: 2i8,
            drop_percent: 44i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 221i32,
            increase: 3i8,
            drop_percent: 41i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 347i32,
            increase: 4i8,
            drop_percent: 38i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 495i32,
            increase: 5i8,
            drop_percent: 37i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 663i32,
            increase: 6i8,
            drop_percent: 35i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 851i32,
            increase: 7i8,
            drop_percent: 34i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 1058i32,
            increase: 8i8,
            drop_percent: 33i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 1284i32,
            increase: 9i8,
            drop_percent: 32i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 1529i32,
            increase: 10i8,
            drop_percent: 31i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 1793i32,
            increase: 11i8,
            drop_percent: 30i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 2076i32,
            increase: 12i8,
            drop_percent: 29i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 2378i32,
            increase: 13i8,
            drop_percent: 28i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 2699i32,
            increase: 14i8,
            drop_percent: 28i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 3039i32,
            increase: 15i8,
            drop_percent: 27i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 3399i32,
            increase: 16i8,
            drop_percent: 27i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 3778i32,
            increase: 17i8,
            drop_percent: 26i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 4177i32,
            increase: 18i8,
            drop_percent: 26i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 4596i32,
            increase: 19i8,
            drop_percent: 25i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 5036i32,
            increase: 20i8,
            drop_percent: 25i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 5497i32,
            increase: 21i8,
            drop_percent: 24i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 5979i32,
            increase: 22i8,
            drop_percent: 24i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 6483i32,
            increase: 23i8,
            drop_percent: 23i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 7009i32,
            increase: 24i8,
            drop_percent: 23i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 7558i32,
            increase: 25i8,
            drop_percent: 22i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 8130i32,
            increase: 26i8,
            drop_percent: 22i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 8726i32,
            increase: 27i8,
            drop_percent: 22i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 9346i32,
            increase: 28i8,
            drop_percent: 21i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 9991i32,
            increase: 29i8,
            drop_percent: 21i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 10661i32,
            increase: 30i8,
            drop_percent: 21i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 11358i32,
            increase: 31i8,
            drop_percent: 20i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 12082i32,
            increase: 32i8,
            drop_percent: 20i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 12834i32,
            increase: 33i8,
            drop_percent: 20i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 13614i32,
            increase: 34i8,
            drop_percent: 19i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 14424i32,
            increase: 35i8,
            drop_percent: 19i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 15265i32,
            increase: 36i8,
            drop_percent: 19i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 16137i32,
            increase: 37i8,
            drop_percent: 19i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 17042i32,
            increase: 38i8,
            drop_percent: 18i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 17981i32,
            increase: 39i8,
            drop_percent: 18i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 18955i32,
            increase: 40i8,
            drop_percent: 18i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 19965i32,
            increase: 41i8,
            drop_percent: 17i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 21013i32,
            increase: 42i8,
            drop_percent: 17i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 22101i32,
            increase: 43i8,
            drop_percent: 17i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 23230i32,
            increase: 44i8,
            drop_percent: 17i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 24402i32,
            increase: 45i8,
            drop_percent: 16i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 25618i32,
            increase: 46i8,
            drop_percent: 16i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 26881i32,
            increase: 47i8,
            drop_percent: 16i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 28193i32,
            increase: 48i8,
            drop_percent: 16i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 29557i32,
            increase: 49i8,
            drop_percent: 15i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 30975i32,
            increase: 50i8,
            drop_percent: 15i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 32450i32,
            increase: 51i8,
            drop_percent: 15i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 33986i32,
            increase: 52i8,
            drop_percent: 15i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 35586i32,
            increase: 53i8,
            drop_percent: 14i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 37253i32,
            increase: 54i8,
            drop_percent: 14i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 38992i32,
            increase: 55i8,
            drop_percent: 14i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 40808i32,
            increase: 56i8,
            drop_percent: 14i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 42707i32,
            increase: 57i8,
            drop_percent: 13i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 44694i32,
            increase: 58i8,
            drop_percent: 13i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 46776i32,
            increase: 59i8,
            drop_percent: 13i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 48961i32,
            increase: 60i8,
            drop_percent: 13i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 51258i32,
            increase: 61i8,
            drop_percent: 13i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 53677i32,
            increase: 62i8,
            drop_percent: 12i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 56230i32,
            increase: 63i8,
            drop_percent: 12i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 58932i32,
            increase: 64i8,
            drop_percent: 12i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 61799i32,
            increase: 65i8,
            drop_percent: 12i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 64851i32,
            increase: 66i8,
            drop_percent: 11i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 68113i32,
            increase: 67i8,
            drop_percent: 11i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 71617i32,
            increase: 68i8,
            drop_percent: 11i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 75401i32,
            increase: 69i8,
            drop_percent: 10i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 79517i32,
            increase: 70i8,
            drop_percent: 10i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 84035i32,
            increase: 71i8,
            drop_percent: 10i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 89053i32,
            increase: 72i8,
            drop_percent: 10i8,
        };
        init
    },
    {
        let mut init = sctp_hs_raise_drop {
            cwnd: 94717i32,
            increase: 73i8,
            drop_percent: 9i8,
        };
        init
    },
];
unsafe extern "C" fn sctp_hs_cwnd_increase(mut stcb: *mut sctp_tcb, mut net: *mut sctp_nets) {
    let mut cur_val = 0;
    let mut indx = 0;
    let mut old_cwnd = (*net).cwnd as libc::c_int;
    cur_val = ((*net).cwnd >> 10i32) as libc::c_int;
    indx = 73i32 - 1i32;
    if cur_val < sctp_cwnd_adjust[0usize].cwnd {
        /* normal mode */
        if (*net).net_ack > (*net).mtu {
            (*net).cwnd = ((*net).cwnd).wrapping_add((*net).mtu)
        } else {
            (*net).cwnd = ((*net).cwnd).wrapping_add((*net).net_ack)
        }
    } else {
        let mut i = 0;
        let mut incr = 0;
        i = (*net).last_hs_used as libc::c_int;
        while i < 73i32 {
            if cur_val < sctp_cwnd_adjust[i as usize].cwnd {
                indx = i;
                break;
            } else {
                i += 1
            }
        }
        (*net).last_hs_used = indx as uint8_t;
        incr = (sctp_cwnd_adjust[indx as usize].increase as int32_t) << 10i32;
        (*net).cwnd = ((*net).cwnd).wrapping_add(incr as libc::c_uint)
    }
    sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
    if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
        sctp_log_cwnd(
            stcb,
            net,
            (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
            4u8,
        );
    };
}
unsafe extern "C" fn sctp_hs_cwnd_decrease(mut stcb: *mut sctp_tcb, mut net: *mut sctp_nets) {
    let mut cur_val = 0;
    let mut old_cwnd = (*net).cwnd as libc::c_int;
    cur_val = ((*net).cwnd >> 10i32) as libc::c_int;
    if cur_val < sctp_cwnd_adjust[0usize].cwnd {
        /* normal mode */
        (*net).ssthresh = (*net).cwnd.wrapping_div(2u32);
        if (*net).ssthresh < (*net).mtu.wrapping_mul(2u32) {
            (*net).ssthresh = (2u32).wrapping_mul((*net).mtu)
        }
        (*net).cwnd = (*net).ssthresh
    } else {
        let mut indx = 0;
        (*net).ssthresh = (*net)
            .cwnd
            .wrapping_sub((*net).cwnd.wrapping_div(100u32).wrapping_mul(
                sctp_cwnd_adjust[(*net).last_hs_used as usize].drop_percent as libc::c_uint,
            ));
        (*net).cwnd = (*net).ssthresh;
        /* now where are we */
        indx = (*net).last_hs_used as libc::c_int;
        cur_val = ((*net).cwnd >> 10i32) as libc::c_int;
        /* reset where we are in the table */
        if cur_val < sctp_cwnd_adjust[0usize].cwnd {
            /* feel out of hs */
            (*net).last_hs_used = 0u8
        } else {
            let mut i = 0;
            i = indx;
            while i >= 1i32 {
                if cur_val > sctp_cwnd_adjust[(i - 1i32) as usize].cwnd {
                    break;
                }
                i -= 1
            }
            (*net).last_hs_used = indx as uint8_t
        }
    }
    sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
    if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
        sctp_log_cwnd(
            stcb,
            net,
            (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
            1u8,
        );
    };
}
unsafe extern "C" fn sctp_hs_cwnd_update_after_fr(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) {
    let mut net = 0 as *mut sctp_nets;
    /*
     * CMT fast recovery code. Need to debug. ((sctp_cmt_on_off > 0) &&
     * (net->fast_retran_loss_recovery == 0)))
     */
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        if (*asoc).fast_retran_loss_recovery as libc::c_int == 0i32
            || (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
        {
            /* out of a RFC2582 Fast recovery window? */
            if (*net).net_ack > 0u32 {
                let mut lchk = 0 as *mut sctp_tmit_chunk;
                sctp_hs_cwnd_decrease(stcb, net);
                lchk = (*asoc).send_queue.tqh_first;
                (*net).partial_bytes_acked = 0u32;
                /* Turn on fast recovery window */
                (*asoc).fast_retran_loss_recovery = 1u8;
                if lchk.is_null() {
                    /* Mark end of the window */
                    (*asoc).fast_recovery_tsn = (*asoc).sending_seq.wrapping_sub(1u32)
                } else {
                    (*asoc).fast_recovery_tsn = (*lchk).rec.data.tsn.wrapping_sub(1u32)
                }
                /*
                 * CMT fast recovery -- per destination
                 * recovery variable.
                 */
                (*net).fast_retran_loss_recovery = 1u8;
                if lchk.is_null() {
                    /* Mark end of the window */
                    (*net).fast_recovery_tsn = (*asoc).sending_seq.wrapping_sub(1u32)
                } else {
                    (*net).fast_recovery_tsn = (*lchk).rec.data.tsn.wrapping_sub(1u32)
                }
                sctp_timer_stop(
                    1i32,
                    (*stcb).sctp_ep,
                    stcb,
                    net,
                    (0xd0000000u32).wrapping_add(0x2u32),
                );
                sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, net);
            }
        } else if (*net).net_ack > 0u32 {
            /*
             * Mark a peg that we WOULD have done a cwnd
             * reduction but RFC2582 prevented this action.
             */
            ::std::intrinsics::atomic_xadd(
                &mut system_base_info.sctpstat.sctps_fastretransinrtt,
                1u32,
            );
        }
        net = (*net).sctp_next.tqe_next
    }
}
unsafe extern "C" fn sctp_hs_cwnd_update_after_sack(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut accum_moved: libc::c_int,
    mut reneged_all: libc::c_int,
    mut will_exit: libc::c_int,
) {
    let mut net = 0 as *mut sctp_nets;
    /* *****************************/
    /* update cwnd and Early FR   */
    /* *****************************/
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        /* if nothing was acked on this destination skip it */
        if (*net).net_ack == 0u32 {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                sctp_log_cwnd(stcb, net, 0i32, 64u8);
            }
        } else {
            if (*asoc).fast_retran_loss_recovery as libc::c_int != 0
                && will_exit == 0i32
                && (*asoc).sctp_cmt_on_off as libc::c_int == 0i32
            {
                /*
                 * If we are in loss recovery we skip any cwnd
                 * update
                 */
                return;
            }
            /*
             * CMT: CUC algorithm. Update cwnd if pseudo-cumack has
             * moved.
             */
            if accum_moved != 0
                || (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
                    && (*net).new_pseudo_cumack as libc::c_int != 0
            {
                /* If the cumulative ack moved we can proceed */
                if (*net).cwnd <= (*net).ssthresh {
                    /* We are in slow start */
                    if (*net).flight_size.wrapping_add((*net).net_ack) >= (*net).cwnd {
                        sctp_hs_cwnd_increase(stcb, net);
                    } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                        sctp_log_cwnd(stcb, net, (*net).net_ack as libc::c_int, 31u8);
                    }
                } else {
                    /* We are in congestion avoidance */
                    (*net).partial_bytes_acked =
                        ((*net).partial_bytes_acked).wrapping_add((*net).net_ack);
                    if (*net).flight_size.wrapping_add((*net).net_ack) >= (*net).cwnd
                        && (*net).partial_bytes_acked >= (*net).cwnd
                    {
                        (*net).partial_bytes_acked =
                            ((*net).partial_bytes_acked).wrapping_sub((*net).cwnd);
                        (*net).cwnd = ((*net).cwnd).wrapping_add((*net).mtu);
                        sctp_enforce_cwnd_limit(asoc, net);
                        if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                            sctp_log_cwnd(stcb, net, (*net).mtu as libc::c_int, 5u8);
                        }
                    } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                        sctp_log_cwnd(stcb, net, (*net).net_ack as libc::c_int, 32u8);
                    }
                }
            } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                sctp_log_cwnd(stcb, net, (*net).mtu as libc::c_int, 65u8);
            }
        }
        net = (*net).sctp_next.tqe_next
    }
}
/*
 * H-TCP congestion control. The algorithm is detailed in:
 * R.N.Shorten, D.J.Leith:
 *   "H-TCP: TCP for high-speed and long-distance networks"
 *   Proc. PFLDnet, Argonne, 2004.
 * http://www.hamilton.ie/net/htcp3.pdf
 */
static mut use_rtt_scaling: libc::c_int = 1i32;
static mut use_bandwidth_switch: libc::c_int = 1i32;
#[inline]
unsafe extern "C" fn between(
    mut seq1: uint32_t,
    mut seq2: uint32_t,
    mut seq3: uint32_t,
) -> libc::c_int {
    return (seq3.wrapping_sub(seq2) >= seq1.wrapping_sub(seq2)) as libc::c_int;
}
#[inline]
unsafe extern "C" fn htcp_cong_time(mut ca: *mut htcp) -> uint32_t {
    return sctp_get_tick_count().wrapping_sub((*ca).last_cong);
}
#[inline]
unsafe extern "C" fn htcp_ccount(mut ca: *mut htcp) -> uint32_t {
    return if (*ca).minRTT == 0u32 {
        htcp_cong_time(ca)
    } else {
        htcp_cong_time(ca).wrapping_div((*ca).minRTT)
    };
}
#[inline]
unsafe extern "C" fn htcp_reset(mut ca: *mut htcp) {
    (*ca).undo_last_cong = (*ca).last_cong;
    (*ca).undo_maxRTT = (*ca).maxRTT;
    (*ca).undo_old_maxB = (*ca).old_maxB;
    (*ca).last_cong = sctp_get_tick_count();
}
#[inline]
unsafe extern "C" fn measure_rtt(mut net: *mut sctp_nets) {
    let mut srtt = ((*net).lastsa >> 3i32) as uint32_t;
    /* keep track of minimum RTT seen so far, minRTT is zero at first */
    if (*net).cc_mod.htcp_ca.minRTT > srtt || (*net).cc_mod.htcp_ca.minRTT == 0 {
        (*net).cc_mod.htcp_ca.minRTT = srtt
    }
    /* max RTT */
    if (*net).fast_retran_ip as libc::c_int == 0i32
        && (*net).ssthresh < 0xffffu32
        && htcp_ccount(&mut (*net).cc_mod.htcp_ca) > 3u32
    {
        if (*net).cc_mod.htcp_ca.maxRTT < (*net).cc_mod.htcp_ca.minRTT {
            (*net).cc_mod.htcp_ca.maxRTT = (*net).cc_mod.htcp_ca.minRTT
        }
        if (*net).cc_mod.htcp_ca.maxRTT < srtt
            && srtt
                <= (*net).cc_mod.htcp_ca.maxRTT.wrapping_add(
                    (if hz == 1000i32 {
                        20i32
                    } else {
                        (20i32 * hz + 999i32) / 1000i32
                    }) as libc::c_uint,
                )
        {
            (*net).cc_mod.htcp_ca.maxRTT = srtt
        }
    };
}
unsafe extern "C" fn measure_achieved_throughput(mut net: *mut sctp_nets) {
    let mut now = sctp_get_tick_count();
    if (*net).fast_retran_ip as libc::c_int == 0i32 {
        (*net).cc_mod.htcp_ca.bytes_acked = (*net).net_ack as uint16_t
    }
    if use_bandwidth_switch == 0 {
        return;
    }
    /* achieved throughput calculations */
    /* JRS - not 100% sure of this statement */
    if (*net).fast_retran_ip as libc::c_int == 1i32 {
        (*net).cc_mod.htcp_ca.bytecount = 0u32;
        (*net).cc_mod.htcp_ca.lasttime = now;
        return;
    }
    (*net).cc_mod.htcp_ca.bytecount =
        ((*net).cc_mod.htcp_ca.bytecount).wrapping_add((*net).net_ack);
    if (*net).cc_mod.htcp_ca.bytecount
        >= (*net).cwnd.wrapping_sub(
            ((if (*net).cc_mod.htcp_ca.alpha as libc::c_int >> 7i32 != 0 {
                ((*net).cc_mod.htcp_ca.alpha as libc::c_int) >> 7i32
            } else {
                1i32
            }) as libc::c_uint)
                .wrapping_mul((*net).mtu),
        )
        && now.wrapping_sub((*net).cc_mod.htcp_ca.lasttime) >= (*net).cc_mod.htcp_ca.minRTT
        && (*net).cc_mod.htcp_ca.minRTT > 0u32
    {
        let mut cur_Bi = (*net)
            .cc_mod
            .htcp_ca
            .bytecount
            .wrapping_div((*net).mtu)
            .wrapping_mul(hz as libc::c_uint)
            .wrapping_div(now.wrapping_sub((*net).cc_mod.htcp_ca.lasttime));
        if htcp_ccount(&mut (*net).cc_mod.htcp_ca) <= 3u32 {
            /* just after backoff */
            (*net).cc_mod.htcp_ca.Bi = cur_Bi; /* clamping ratio to interval [0.5,10]<<3 */
            (*net).cc_mod.htcp_ca.maxB = (*net).cc_mod.htcp_ca.Bi;
            (*net).cc_mod.htcp_ca.minB = (*net).cc_mod.htcp_ca.maxB
        } else {
            (*net).cc_mod.htcp_ca.Bi = (3u32)
                .wrapping_mul((*net).cc_mod.htcp_ca.Bi)
                .wrapping_add(cur_Bi)
                .wrapping_div(4u32);
            if (*net).cc_mod.htcp_ca.Bi > (*net).cc_mod.htcp_ca.maxB {
                (*net).cc_mod.htcp_ca.maxB = (*net).cc_mod.htcp_ca.Bi
            }
            if (*net).cc_mod.htcp_ca.minB > (*net).cc_mod.htcp_ca.maxB {
                (*net).cc_mod.htcp_ca.minB = (*net).cc_mod.htcp_ca.maxB
            }
        }
        (*net).cc_mod.htcp_ca.bytecount = 0u32;
        (*net).cc_mod.htcp_ca.lasttime = now
    };
}
#[inline]
unsafe extern "C" fn htcp_beta_update(
    mut ca: *mut htcp,
    mut minRTT: uint32_t,
    mut maxRTT: uint32_t,
) {
    if use_bandwidth_switch != 0 {
        let mut maxB = (*ca).maxB;
        let mut old_maxB = (*ca).old_maxB;
        (*ca).old_maxB = (*ca).maxB;
        if between(
            (5u32).wrapping_mul(maxB),
            (4u32).wrapping_mul(old_maxB),
            (6u32).wrapping_mul(old_maxB),
        ) == 0
        {
            (*ca).beta = ((1i32) << 6i32) as uint8_t;
            (*ca).modeswitch = 0u8;
            return;
        }
    }
    if (*ca).modeswitch as libc::c_int != 0
        && minRTT
            > (if hz == 1000i32 {
                10i32
            } else {
                (10i32 * hz + 999i32) / 1000i32
            }) as uint32_t
        && maxRTT != 0
    {
        (*ca).beta = (minRTT << 7i32).wrapping_div(maxRTT) as uint8_t;
        if ((*ca).beta as libc::c_int) < (1i32) << 6i32 {
            (*ca).beta = ((1i32) << 6i32) as uint8_t
        } else if (*ca).beta as libc::c_int > 102i32 {
            (*ca).beta = 102u8
        }
    } else {
        (*ca).beta = ((1i32) << 6i32) as uint8_t;
        (*ca).modeswitch = 1u8
    };
}
#[inline]
unsafe extern "C" fn htcp_alpha_update(mut ca: *mut htcp) {
    let mut factor = 1u32;
    let mut minRTT = (*ca).minRTT;
    let mut diff = htcp_cong_time(ca);
    if diff > hz as uint32_t {
        diff = (diff).wrapping_sub(hz as libc::c_uint);
        factor = (1u32).wrapping_add(
            (10u32)
                .wrapping_mul(diff)
                .wrapping_add(
                    diff.wrapping_div(2u32)
                        .wrapping_mul(diff.wrapping_div(2u32))
                        .wrapping_div(hz as libc::c_uint),
                )
                .wrapping_div(hz as libc::c_uint),
        )
    }
    if use_rtt_scaling != 0 && minRTT != 0 {
        let mut scale = ((hz << 3i32) as libc::c_uint).wrapping_div((10u32).wrapping_mul(minRTT));
        scale = if (if scale > (1u32) << 2i32 {
            scale
        } else {
            (1u32) << 2i32
        }) > (10u32) << 3i32
        {
            (10u32) << 3i32
        } else if scale > (1u32) << 2i32 {
            scale
        } else {
            (1u32) << 2i32
        };
        factor = (factor << 3i32).wrapping_div(scale);
        if factor == 0 {
            factor = 1u32
        }
    }
    (*ca).alpha = (2u32)
        .wrapping_mul(factor)
        .wrapping_mul((((1i32) << 7i32) - (*ca).beta as libc::c_int) as libc::c_uint)
        as uint16_t;
    if (*ca).alpha == 0 {
        (*ca).alpha = ((1i32) << 7i32) as uint16_t
    };
}
/* After we have the rtt data to calculate beta, we'd still prefer to wait one
 * rtt before we adjust our beta to ensure we are working from a consistent
 * data.
 *
 * This function should be called when we hit a congestion event since only at
 * that point do we really have a real sense of maxRTT (the queues en route
 * were getting just too full now).
 */
unsafe extern "C" fn htcp_param_update(mut net: *mut sctp_nets) {
    let mut minRTT = (*net).cc_mod.htcp_ca.minRTT;
    let mut maxRTT = (*net).cc_mod.htcp_ca.maxRTT;
    htcp_beta_update(&mut (*net).cc_mod.htcp_ca, minRTT, maxRTT);
    htcp_alpha_update(&mut (*net).cc_mod.htcp_ca);
    /* add slowly fading memory for maxRTT to accommodate routing changes etc */
    if minRTT > 0u32 && maxRTT > minRTT {
        (*net).cc_mod.htcp_ca.maxRTT = minRTT.wrapping_add(
            maxRTT
                .wrapping_sub(minRTT)
                .wrapping_mul(95u32)
                .wrapping_div(100u32),
        )
    };
}
unsafe extern "C" fn htcp_recalc_ssthresh(mut net: *mut sctp_nets) -> uint32_t {
    htcp_param_update(net);
    return if ((*net)
        .cwnd
        .wrapping_div((*net).mtu)
        .wrapping_mul((*net).cc_mod.htcp_ca.beta as libc::c_uint)
        >> 7i32)
        .wrapping_mul((*net).mtu)
        > (2u32).wrapping_mul((*net).mtu)
    {
        ((*net)
            .cwnd
            .wrapping_div((*net).mtu)
            .wrapping_mul((*net).cc_mod.htcp_ca.beta as libc::c_uint)
            >> 7i32)
            .wrapping_mul((*net).mtu)
    } else {
        (2u32).wrapping_mul((*net).mtu)
    };
}
unsafe extern "C" fn htcp_cong_avoid(mut stcb: *mut sctp_tcb, mut net: *mut sctp_nets) {
    /*-
     * How to handle these functions?
     *	if (!tcp_is_cwnd_limited(sk, in_flight)) RRS - good question.
     *		return;
     */
    if (*net).cwnd <= (*net).ssthresh {
        /* We are in slow start */
        if (*net).flight_size.wrapping_add((*net).net_ack) >= (*net).cwnd {
            if (*net).net_ack
                > (*net)
                    .mtu
                    .wrapping_mul(system_base_info.sctpsysctl.sctp_L2_abc_variable)
            {
                (*net).cwnd = ((*net).cwnd).wrapping_add(
                    (*net)
                        .mtu
                        .wrapping_mul(system_base_info.sctpsysctl.sctp_L2_abc_variable),
                );
                if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                    sctp_log_cwnd(stcb, net, (*net).mtu as libc::c_int, 4u8);
                }
            } else {
                (*net).cwnd = ((*net).cwnd).wrapping_add((*net).net_ack);
                if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                    sctp_log_cwnd(stcb, net, (*net).net_ack as libc::c_int, 4u8);
                }
            }
            sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
        } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
            sctp_log_cwnd(stcb, net, (*net).net_ack as libc::c_int, 31u8);
        }
    } else {
        measure_rtt(net);
        /* In dangerous area, increase slowly.
         * In theory this is net->cwnd += alpha / net->cwnd
         */
        /* What is snd_cwnd_cnt?? */
        if ((*net)
            .partial_bytes_acked
            .wrapping_div((*net).mtu)
            .wrapping_mul((*net).cc_mod.htcp_ca.alpha as libc::c_uint)
            >> 7i32)
            .wrapping_mul((*net).mtu)
            >= (*net).cwnd
        {
            /*-
             * Does SCTP have a cwnd clamp?
             * if (net->snd_cwnd < net->snd_cwnd_clamp) - Nope (RRS).
             */
            (*net).cwnd = ((*net).cwnd).wrapping_add((*net).mtu);
            (*net).partial_bytes_acked = 0u32;
            sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
            htcp_alpha_update(&mut (*net).cc_mod.htcp_ca);
            if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                sctp_log_cwnd(stcb, net, (*net).mtu as libc::c_int, 5u8);
            }
        } else {
            (*net).partial_bytes_acked = ((*net).partial_bytes_acked).wrapping_add((*net).net_ack);
            if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                sctp_log_cwnd(stcb, net, (*net).net_ack as libc::c_int, 32u8);
            }
        }
        (*net).cc_mod.htcp_ca.bytes_acked = (*net).mtu as uint16_t
    };
}
unsafe extern "C" fn htcp_init(mut net: *mut sctp_nets) {
    memset(
        &mut (*net).cc_mod.htcp_ca as *mut htcp as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<htcp>() as libc::c_ulong,
    );
    (*net).cc_mod.htcp_ca.alpha = ((1i32) << 7i32) as uint16_t;
    (*net).cc_mod.htcp_ca.beta = ((1i32) << 6i32) as uint8_t;
    (*net).cc_mod.htcp_ca.bytes_acked = (*net).mtu as uint16_t;
    (*net).cc_mod.htcp_ca.last_cong = sctp_get_tick_count();
}
unsafe extern "C" fn sctp_htcp_set_initial_cc_param(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    /*
     * We take the max of the burst limit times a MTU or the
     * INITIAL_CWND. We then limit this to 4 MTU's of sending.
     */
    (*net).cwnd = if (*net).mtu.wrapping_mul(4u32)
        > (if (2u32).wrapping_mul((*net).mtu) > 4380u32 {
            (2u32).wrapping_mul((*net).mtu)
        } else {
            4380u32
        }) {
        if (2u32).wrapping_mul((*net).mtu) > 4380u32 {
            (2u32).wrapping_mul((*net).mtu)
        } else {
            4380u32
        }
    } else {
        (*net).mtu.wrapping_mul(4u32)
    };
    (*net).ssthresh = (*stcb).asoc.peers_rwnd;
    sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
    htcp_init(net);
    if system_base_info.sctpsysctl.sctp_logging_level & (0x2i32 | 0x4i32) as libc::c_uint != 0 {
        sctp_log_cwnd(stcb, net, 0i32, 62u8);
    };
}
unsafe extern "C" fn sctp_htcp_cwnd_update_after_sack(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut accum_moved: libc::c_int,
    mut reneged_all: libc::c_int,
    mut will_exit: libc::c_int,
) {
    let mut net = 0 as *mut sctp_nets;
    /* *****************************/
    /* update cwnd and Early FR   */
    /* *****************************/
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        /* if nothing was acked on this destination skip it */
        if (*net).net_ack == 0u32 {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                sctp_log_cwnd(stcb, net, 0i32, 64u8);
            }
        } else {
            if (*asoc).fast_retran_loss_recovery as libc::c_int != 0
                && will_exit == 0i32
                && (*asoc).sctp_cmt_on_off as libc::c_int == 0i32
            {
                /*
                 * If we are in loss recovery we skip any cwnd
                 * update
                 */
                return;
            }
            /*
             * CMT: CUC algorithm. Update cwnd if pseudo-cumack has
             * moved.
             */
            if accum_moved != 0
                || (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
                    && (*net).new_pseudo_cumack as libc::c_int != 0
            {
                htcp_cong_avoid(stcb, net);
                measure_achieved_throughput(net);
            } else if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                sctp_log_cwnd(stcb, net, (*net).mtu as libc::c_int, 65u8);
            }
        }
        net = (*net).sctp_next.tqe_next
    }
}
unsafe extern "C" fn sctp_htcp_cwnd_update_after_fr(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) {
    let mut net = 0 as *mut sctp_nets;
    /*
     * CMT fast recovery code. Need to debug. ((sctp_cmt_on_off > 0) &&
     * (net->fast_retran_loss_recovery == 0)))
     */
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        if (*asoc).fast_retran_loss_recovery as libc::c_int == 0i32
            || (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
        {
            /* out of a RFC2582 Fast recovery window? */
            if (*net).net_ack > 0u32 {
                let mut lchk = 0 as *mut sctp_tmit_chunk;
                let mut old_cwnd = (*net).cwnd as libc::c_int;
                /* JRS - reset as if state were changed */
                htcp_reset(&mut (*net).cc_mod.htcp_ca);
                (*net).ssthresh = htcp_recalc_ssthresh(net);
                (*net).cwnd = (*net).ssthresh;
                sctp_enforce_cwnd_limit(asoc, net);
                if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
                    sctp_log_cwnd(
                        stcb,
                        net,
                        (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                        1u8,
                    );
                }
                lchk = (*asoc).send_queue.tqh_first;
                (*net).partial_bytes_acked = 0u32;
                /* Turn on fast recovery window */
                (*asoc).fast_retran_loss_recovery = 1u8;
                if lchk.is_null() {
                    /* Mark end of the window */
                    (*asoc).fast_recovery_tsn = (*asoc).sending_seq.wrapping_sub(1u32)
                } else {
                    (*asoc).fast_recovery_tsn = (*lchk).rec.data.tsn.wrapping_sub(1u32)
                }
                /*
                 * CMT fast recovery -- per destination
                 * recovery variable.
                 */
                (*net).fast_retran_loss_recovery = 1u8;
                if lchk.is_null() {
                    /* Mark end of the window */
                    (*net).fast_recovery_tsn = (*asoc).sending_seq.wrapping_sub(1u32)
                } else {
                    (*net).fast_recovery_tsn = (*lchk).rec.data.tsn.wrapping_sub(1u32)
                }
                sctp_timer_stop(
                    1i32,
                    (*stcb).sctp_ep,
                    stcb,
                    net,
                    (0xd0000000u32).wrapping_add(0x3u32),
                );
                sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, net);
            }
        } else if (*net).net_ack > 0u32 {
            /*
             * Mark a peg that we WOULD have done a cwnd
             * reduction but RFC2582 prevented this action.
             */
            ::std::intrinsics::atomic_xadd(
                &mut system_base_info.sctpstat.sctps_fastretransinrtt,
                1u32,
            );
        }
        net = (*net).sctp_next.tqe_next
    }
}
unsafe extern "C" fn sctp_htcp_cwnd_update_after_timeout(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    let mut old_cwnd = (*net).cwnd as libc::c_int;
    /* JRS - reset as if the state were being changed to timeout */
    htcp_reset(&mut (*net).cc_mod.htcp_ca);
    (*net).ssthresh = htcp_recalc_ssthresh(net);
    (*net).cwnd = (*net).mtu;
    (*net).partial_bytes_acked = 0u32;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
        sctp_log_cwnd(
            stcb,
            net,
            (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
            2u8,
        );
    };
}
unsafe extern "C" fn sctp_htcp_cwnd_update_after_ecn_echo(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut in_window: libc::c_int,
    mut num_pkt_lost: libc::c_int,
) {
    let mut old_cwnd = 0;
    old_cwnd = (*net).cwnd as libc::c_int;
    /* JRS - reset hctp as if state changed */
    if in_window == 0i32 {
        htcp_reset(&mut (*net).cc_mod.htcp_ca);
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_ecnereducedcwnd, 1u32);
        (*net).ssthresh = htcp_recalc_ssthresh(net);
        if (*net).ssthresh < (*net).mtu {
            (*net).ssthresh = (*net).mtu;
            /* here back off the timer as well, to slow us down */
            (*net).RTO <<= 1i32
        }
        (*net).cwnd = (*net).ssthresh;
        sctp_enforce_cwnd_limit(&mut (*stcb).asoc, net);
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
            sctp_log_cwnd(
                stcb,
                net,
                (*net).cwnd.wrapping_sub(old_cwnd as libc::c_uint) as libc::c_int,
                6u8,
            );
        }
    };
}
#[no_mangle]
pub static mut sctp_cc_functions: [sctp_cc_functions; 4] = {
    [
        {
            let mut init = sctp_cc_functions {
                sctp_set_initial_cc_param: Some(
                    sctp_set_initial_cc_param
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_sack: Some(
                    sctp_cwnd_update_after_sack
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_exit_pf: Some(
                    sctp_cwnd_update_exit_pf_common
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_fr: Some(
                    sctp_cwnd_update_after_fr
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association) -> (),
                ),
                sctp_cwnd_update_after_timeout: Some(
                    sctp_cwnd_update_after_timeout
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_ecn_echo: Some(
                    sctp_cwnd_update_after_ecn_echo
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_after_packet_dropped: Some(
                    sctp_cwnd_update_after_packet_dropped
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_pktdrop_chunk,
                            _: *mut uint32_t,
                            _: *mut uint32_t,
                        ) -> (),
                ),
                sctp_cwnd_update_after_output: Some(
                    sctp_cwnd_update_after_output
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_packet_transmitted: None,
                sctp_cwnd_update_tsn_acknowledged: None,
                sctp_cwnd_new_transmission_begins: None,
                sctp_cwnd_prepare_net_for_sack: None,
                sctp_cwnd_socket_option: None,
                sctp_rtt_calculated: None,
            };
            init
        },
        {
            let mut init = sctp_cc_functions {
                sctp_set_initial_cc_param: Some(
                    sctp_set_initial_cc_param
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_sack: Some(
                    sctp_hs_cwnd_update_after_sack
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_exit_pf: Some(
                    sctp_cwnd_update_exit_pf_common
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_fr: Some(
                    sctp_hs_cwnd_update_after_fr
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association) -> (),
                ),
                sctp_cwnd_update_after_timeout: Some(
                    sctp_cwnd_update_after_timeout
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_ecn_echo: Some(
                    sctp_cwnd_update_after_ecn_echo
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_after_packet_dropped: Some(
                    sctp_cwnd_update_after_packet_dropped
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_pktdrop_chunk,
                            _: *mut uint32_t,
                            _: *mut uint32_t,
                        ) -> (),
                ),
                sctp_cwnd_update_after_output: Some(
                    sctp_cwnd_update_after_output
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_packet_transmitted: None,
                sctp_cwnd_update_tsn_acknowledged: None,
                sctp_cwnd_new_transmission_begins: None,
                sctp_cwnd_prepare_net_for_sack: None,
                sctp_cwnd_socket_option: None,
                sctp_rtt_calculated: None,
            };
            init
        },
        {
            let mut init = sctp_cc_functions {
                sctp_set_initial_cc_param: Some(
                    sctp_htcp_set_initial_cc_param
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_sack: Some(
                    sctp_htcp_cwnd_update_after_sack
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_exit_pf: Some(
                    sctp_cwnd_update_exit_pf_common
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_fr: Some(
                    sctp_htcp_cwnd_update_after_fr
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association) -> (),
                ),
                sctp_cwnd_update_after_timeout: Some(
                    sctp_htcp_cwnd_update_after_timeout
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_ecn_echo: Some(
                    sctp_htcp_cwnd_update_after_ecn_echo
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_after_packet_dropped: Some(
                    sctp_cwnd_update_after_packet_dropped
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_pktdrop_chunk,
                            _: *mut uint32_t,
                            _: *mut uint32_t,
                        ) -> (),
                ),
                sctp_cwnd_update_after_output: Some(
                    sctp_cwnd_update_after_output
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_packet_transmitted: None,
                sctp_cwnd_update_tsn_acknowledged: None,
                sctp_cwnd_new_transmission_begins: None,
                sctp_cwnd_prepare_net_for_sack: None,
                sctp_cwnd_socket_option: None,
                sctp_rtt_calculated: None,
            };
            init
        },
        {
            let mut init = sctp_cc_functions {
                sctp_set_initial_cc_param: Some(
                    sctp_set_rtcc_initial_cc_param
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_sack: Some(
                    sctp_cwnd_update_rtcc_after_sack
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_exit_pf: Some(
                    sctp_cwnd_update_exit_pf_common
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_fr: Some(
                    sctp_cwnd_update_after_fr
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_association) -> (),
                ),
                sctp_cwnd_update_after_timeout: Some(
                    sctp_cwnd_update_after_timeout
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_after_ecn_echo: Some(
                    sctp_cwnd_update_rtcc_after_ecn_echo
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_after_packet_dropped: Some(
                    sctp_cwnd_update_after_packet_dropped
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_pktdrop_chunk,
                            _: *mut uint32_t,
                            _: *mut uint32_t,
                        ) -> (),
                ),
                sctp_cwnd_update_after_output: Some(
                    sctp_cwnd_update_after_output
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_cwnd_update_packet_transmitted: Some(
                    sctp_cwnd_update_rtcc_packet_transmitted
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_update_tsn_acknowledged: Some(
                    sctp_cwnd_update_rtcc_tsn_acknowledged
                        as unsafe extern "C" fn(_: *mut sctp_nets, _: *mut sctp_tmit_chunk) -> (),
                ),
                sctp_cwnd_new_transmission_begins: Some(
                    sctp_cwnd_new_rtcc_transmission_begins
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_prepare_net_for_sack: Some(
                    sctp_cwnd_prepare_rtcc_net_for_sack
                        as unsafe extern "C" fn(_: *mut sctp_tcb, _: *mut sctp_nets) -> (),
                ),
                sctp_cwnd_socket_option: Some(
                    sctp_cwnd_rtcc_socket_option
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: libc::c_int,
                            _: *mut sctp_cc_option,
                        ) -> libc::c_int,
                ),
                sctp_rtt_calculated: Some(
                    sctp_rtt_rtcc_calculated
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut timeval,
                        ) -> (),
                ),
            };
            init
        },
    ]
};
