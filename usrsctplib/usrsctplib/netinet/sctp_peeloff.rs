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
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_free_chunklist(chklist: *mut sctp_auth_chklist_t);
    #[no_mangle]
    fn sctp_copy_chunklist(chklist: *mut sctp_auth_chklist_t) -> *mut sctp_auth_chklist_t;
    #[no_mangle]
    fn sctp_copy_skeylist(src: *const sctp_keyhead, dest: *mut sctp_keyhead) -> libc::c_int;
    #[no_mangle]
    fn sctp_free_hmaclist(list: *mut sctp_hmaclist_t);
    #[no_mangle]
    fn sctp_copy_hmaclist(list: *mut sctp_hmaclist_t) -> *mut sctp_hmaclist_t;
    #[no_mangle]
    fn sctp_move_pcb_and_assoc(_: *mut sctp_inpcb, _: *mut sctp_inpcb, _: *mut sctp_tcb);
    #[no_mangle]
    fn sctp_findassociation_ep_asocid(
        _: *mut sctp_inpcb,
        _: sctp_assoc_t,
        _: libc::c_int,
    ) -> *mut sctp_tcb;
    #[no_mangle]
    fn sctp_pull_off_control_to_new_inp(
        old_inp: *mut sctp_inpcb,
        new_inp: *mut sctp_inpcb,
        stcb: *mut sctp_tcb,
        waitflags: libc::c_int,
    );
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
    pub c2rust_unnamed: C2RustUnnamed_502,
    pub c2rust_unnamed_0: C2RustUnnamed_500,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_500 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_501,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_501 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_502 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_503,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_503 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
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
    pub __in6_u: C2RustUnnamed_504,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_504 {
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
    pub so_incomp: C2RustUnnamed_512,
    pub so_comp: C2RustUnnamed_511,
    pub so_list: C2RustUnnamed_510,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_509,
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
    pub M_dat: C2RustUnnamed_505,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_505 {
    pub MH: C2RustUnnamed_506,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_506 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_507,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_507 {
    pub MH_ext: m_ext,
    pub MH_databuf: [libc::c_char; 176],
}
/*-
 * Copyright (c) 1982, 1986, 1988, 1993
 *      The Regents of the University of California.
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
 * 3. Neither the name of the University nor the names of its contributors
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
 */
/* __Userspace__ header file for mbufs */
/* For Linux */
/* #define MSIZE 1024 */
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
    pub m_tag_link: C2RustUnnamed_508,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_508 {
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
pub struct C2RustUnnamed_509 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_510 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_511 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_512 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_513,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_513 {
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
    pub inp_hash: C2RustUnnamed_521,
    pub inp_list: C2RustUnnamed_520,
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
    pub inp_depend4: C2RustUnnamed_517,
    pub inp_depend6: C2RustUnnamed_516,
    pub inp_portlist: C2RustUnnamed_515,
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
    pub phd_hash: C2RustUnnamed_514,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_514 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_515 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_516 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_517 {
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
    pub ie_dependfaddr: C2RustUnnamed_519,
    pub ie_dependladdr: C2RustUnnamed_518,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_518 {
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
pub union C2RustUnnamed_519 {
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
pub struct C2RustUnnamed_520 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_521 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_callout {
    pub tqe: C2RustUnnamed_522,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_522 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;
pub type sctp_rtentry_t = sctp_rtentry;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_551,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_550,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_549,
    pub sctp_hash: C2RustUnnamed_548,
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
    pub sctp_tcbhash: C2RustUnnamed_547,
    pub sctp_tcblist: C2RustUnnamed_546,
    pub sctp_tcbasocidhash: C2RustUnnamed_545,
    pub sctp_asocs: C2RustUnnamed_544,
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
/* next link */
/*
 * Things on the top half may be able to be split into a common
 * structure shared by all.
 */
/*
 * The following two in combination equate to a route entry for v6
 * or v4.
 */
/* mtu discovered so far */
/* not sure about this one for split */
/* smoothed average things for RTT and RTO itself */
/* last measured rtt value in us */
/* This is used for SHUTDOWN/SHUTDOWN-ACK/SEND or INIT timers */
/* last time in seconds I sent to it */
/* JRS - struct used in HTCP algorithm */
/* rtcc module cc stuff  */
/* Congestion stats per destination */
/*
 * flight size variables and such, sorry Vern, I could not avoid
 * this if I wanted performance :>
 */
/* actual cwnd */
/* cwnd before any processing */
/* ECN prev cwnd at first ecn_echo seen in new window */
/* in CA tracks when to incr a MTU */
/* tracking variables to avoid the aloc/free in sack processing */
/*
 * JRS - 5/8/07 - Variable to track last time
 *  a destination was active for CMT PF
 */
/*
 * CMT variables (iyengar@cis.udel.edu)
 */
/* tracks highest TSN newly
 * acked for a given dest in
 * the current SACK. Used in
 * SFR and HTNA algos */
/* CMT CUC algorithm. Maintains next expected
 * pseudo-cumack for this destination */
/* CMT CUC algorithm. Maintains next
 * expected pseudo-cumack for this
 * destination */
/* CMT fast recovery variables */
/* time when this net was created */
/* number or DATA chunks marked for
timer based retransmissions */
/* Heart Beat delay in ms */
/* if this guy is ok or not ... status */
/* number of timeouts to consider the destination unreachable */
/* number of timeouts to consider the destination potentially failed */
/* error stats on the destination */
/* UDP port number in case of UDP tunneling */
/* Flags that probably can be combined into dest_state */
/* fast retransmit in progress */
/* CMT's SFR algorithm flag */
/* if we split we move */
/* its a local address (if known) could move
 * in split */
/*
 * CMT variables (iyengar@cis.udel.edu)
 */
/* CMT CUC algorithm. Flag used to
 * find a new pseudocumack. This flag
 * is set after a new pseudo-cumack
 * has been received and indicates
 * that the sender should find the
 * next pseudo-cumack expected for
 * this destination */
/* CMT CUCv2 algorithm. Flag used to
 * find a new rtx-pseudocumack. This
 * flag is set after a new
 * rtx-pseudo-cumack has been received
 * and indicates that the sender
 * should find the next
 * rtx-pseudo-cumack expected for this
 * destination */
/* CMT CUC algorithm. Flag used to
 * indicate if a new pseudo-cumack or
 * rtx-pseudo-cumack has been received */
/* Doing a window probe? */
/* Have we done the first measure */
/* index into the last HS table entry we used */
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
/* digest lengths */
/* random sizes */
/* union of all supported HMAC algorithm contexts */
/* key text */
/* reference count */
/* shared key ID */
/* key is deactivated */
/* authentication chunks list */
/* hmac algos supported list */
/* max algorithms allocated */
/* num algorithms used */
/* authentication info */
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
    pub next: C2RustUnnamed_523,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_523 {
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
    pub next: C2RustUnnamed_533,
    pub next_instrm: C2RustUnnamed_532,
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
    pub rec: C2RustUnnamed_531,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_524,
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
pub struct C2RustUnnamed_524 {
    pub tqe_next: *mut sctp_tmit_chunk,
    pub tqe_prev: *mut *mut sctp_tmit_chunk,
}
/* local random key (concatenated) */
/* local random number length for param */
/* peer's random key (concatenated) */
/* cached concatenated send key */
/* cached concatenated recv key */
/* active send keyid */
/* current send keyid (cached) */
/* last recv keyid (cached) */
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_nets {
    pub sctp_next: C2RustUnnamed_530,
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
/* default v4 table id */
/* default v6 table id */
/* never access without appropriate lock */
/* shorthand way to look at ifn for reference */
/* number of reference held should be >= ifa_count */
/* IFA's we hold (in our list - ifalist)*/
/* number of v6 addresses */
/* number of v4 addresses */
/* registered address family for i/f events */
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
    pub next_ifa: C2RustUnnamed_529,
    pub next_bucket: C2RustUnnamed_528,
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
    pub next_ifn: C2RustUnnamed_526,
    pub next_bucket: C2RustUnnamed_525,
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
pub struct C2RustUnnamed_525 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_526 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_527,
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
pub struct C2RustUnnamed_527 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_528 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_529 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_530 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_531 {
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
pub struct C2RustUnnamed_532 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_533 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

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
    pub next_spoke: C2RustUnnamed_534,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_534 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_535,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_535 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_536,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_536 {
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
    pub next: C2RustUnnamed_538,
    pub ss_next: C2RustUnnamed_537,
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
pub struct C2RustUnnamed_537 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_538 {
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
/* max storage size */
/* an ASCONF NAT-Vtag parameter */
/* asconf "parameter" */
/* an ASCONF address (v4) parameter */
/* asconf "parameter" */
/* max storage size */
/* type = 0x8008  len = x */
/*
 * Structures for DATA chunks
 */
/* user data follows */
/* Where does the SSN go? */
/* Fragment Sequence Number */
/* user data follows */
/*
 * Structures for the control chunks
 */
/* Initiate (INIT)/Initiate Ack (INIT ACK) */
/* initiate tag */
/* a_rwnd */
/* OS */
/* MIS */
/* I-TSN */
/* optional param's follow */
/* state cookie header */
/* this is our definition... */
/* id of who we are */
/* the time I built cookie */
/* life I will award this cookie */
/* my tag in old association */
/* peers tag in old association */
/* peers tag in INIT (for quick ref) */
/* my tag in INIT-ACK (for quick ref) */
/* 4 ints/128 bits */
/* address type */
/* my local from address */
/* my local from address type */
/* v6 scope id for link-locals */
/* port address of the peer in the INIT */
/* my port address used in the INIT */
/* Are V4 addr legal? */
/* Are V6 addr legal? */
/* IPv6 local scope flag */
/* IPv6 site scope flag */
/* IPv4 private addr scope */
/* loopback scope information */
/* Align to 64 bits */
/*
 * at the end is tacked on the INIT chunk and the INIT-ACK chunk
 * (minus the cookie).
 */
/* state cookie parameter */
/* ... used for both INIT and INIT ACK */
/* Selective Ack (SACK) */
/* Gap Ack block start */
/* Gap Ack block end */
/* cumulative TSN Ack */
/* updated a_rwnd of sender */
/* number of Gap Ack blocks */
/* number of duplicate TSNs */
/* struct sctp_gap_ack_block's follow */
/* uint32_t duplicate_tsn's follow */
/* cumulative TSN Ack */
/* updated a_rwnd of sender */
/* number of Gap Ack blocks */
/* number of NR Gap Ack blocks */
/* number of duplicate TSNs */
/* not currently used*/
/* struct sctp_gap_ack_block's follow */
/* uint32_t duplicate_tsn's follow */
/* Heartbeat Request (HEARTBEAT) */
/* ... used for Heartbeat Ack (HEARTBEAT ACK) */
/* Abort Asssociation (ABORT) */
/* optional error cause may follow */
/* Shutdown Association (SHUTDOWN) */
/* Shutdown Acknowledgment (SHUTDOWN ACK) */
/* Operation Error (ERROR) */
/* optional error causes follow */
/* Cookie Echo (COOKIE ECHO) */
/* Cookie Acknowledgment (COOKIE ACK) */
/* Explicit Congestion Notification Echo (ECNE) */
/* Congestion Window Reduced (CWR) */
/* Shutdown Complete (SHUTDOWN COMPLETE) */
/*
 * draft-ietf-tsvwg-addip-sctp
 */
/* Address/Stream Configuration Change (ASCONF) */
/* lookup address parameter (mandatory) */
/* asconf parameters follow */
/* Address/Stream Configuration Acknowledge (ASCONF ACK) */
/* asconf parameters follow */
/* draft-ietf-tsvwg-prsctp */
/* Forward Cumulative TSN (FORWARD TSN) */
/* stream/sequence pairs (sctp_strseq) follow */
/* should be a multiple of 4 - 1 aka 3/7/11 etc. */

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
    pub next_resp: C2RustUnnamed_539,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_539 {
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
    pub sctp_nxt_addr: C2RustUnnamed_540,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_540 {
    pub le_next: *mut sctp_laddr,
    pub le_prev: *mut *mut sctp_laddr,
}
/*
 * JRS - Structure to hold function pointers to the functions responsible
 * for congestion control.
 */
/*
 * RS - Structure to hold function pointers to the functions responsible
 * for stream scheduling.
 */
/* used to save ASCONF chunks for retransmission */
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
    pub next: C2RustUnnamed_541,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_541 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_542,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_542 {
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
/*
 * This is the information we track on each interface that we know about from
 * the distant end.
 */

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
pub struct sctp_asconf_addrhead {
    pub tqh_first: *mut sctp_asconf_addr,
    pub tqh_last: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_543,
    pub ap: sctp_asconf_addr_param,
    pub ifa: *mut sctp_ifa,
    pub sent: uint8_t,
    pub special_del: uint8_t,
}
/* correlation id for this param */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr_param {
    pub aph: sctp_asconf_paramhdr,
    pub addrp: sctp_ipv6addr_param,
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
/*
 * Parameter structures
 */
/* type=SCTP_IPV4_PARAM_TYPE, len=8 */
/* IPV4 address */

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
/* IPV6 address */
/* Cookie Preservative */
/* type=SCTP_COOKIE_PRESERVE, len=8 */
/* time in ms to extend cookie */
/* Host Name Address */
/* type=SCTP_HOSTNAME_ADDRESS */
/* host name */
/*
 * This is the maximum padded size of a s-a-p
 * so paramheadr + 3 address types (6 bytes) + 2 byte pad = 12
 */
/* supported address type */
/* type=SCTP_SUPPORTED_ADDRTYPE */
/* array of supported address types */
/* heartbeat info parameter */
/* make sure that this structure is 4 byte aligned */
/* draft-ietf-tsvwg-prsctp */
/* PR-SCTP supported parameter */
/* draft-ietf-tsvwg-addip-sctp */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_paramhdr {
    pub ph: sctp_paramhdr,
    pub correlation_id: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_543 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_block_entry {
    pub error: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_544 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_545 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_546 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_547 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

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
pub struct C2RustUnnamed_548 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_549 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_550 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}
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
pub struct C2RustUnnamed_551 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
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
/* HAVE_SCTP_PEELOFF_SOCKOPT */
/* _KERNEL */
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
#[no_mangle]
pub unsafe extern "C" fn sctp_can_peel_off(
    mut head: *mut socket,
    mut assoc_id: sctp_assoc_t,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut state = 0;
    if head.is_null() {
        return 9i32;
    }
    inp = (*head).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 14i32;
    }
    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
        return 95i32;
    }
    stcb = sctp_findassociation_ep_asocid(inp, assoc_id, 1i32);
    if stcb.is_null() {
        return 2i32;
    }
    state = ((*stcb).asoc.state & 0x7fi32) as uint32_t;
    if state == 0u32 || state == 0x1u32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        return 107i32;
    }
    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
    /* We are clear to peel this one off */
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_do_peeloff(
    mut head: *mut socket,
    mut so: *mut socket,
    mut assoc_id: sctp_assoc_t,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut n_inp = 0 as *mut sctp_inpcb;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut state = 0;
    inp = (*head).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 14i32;
    }
    stcb = sctp_findassociation_ep_asocid(inp, assoc_id, 1i32);
    if stcb.is_null() {
        return 107i32;
    }
    state = ((*stcb).asoc.state & 0x7fi32) as uint32_t;
    if state == 0u32 || state == 0x1u32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        return 107i32;
    }
    n_inp = (*so).so_pcb as *mut sctp_inpcb;
    (*n_inp).sctp_flags = (0x1i32 | 0x200000i32 | 0x400000i32) as libc::c_uint
        | ((0x4i32 | 0x2000000i32 | 0x4000000i32) as libc::c_uint | 0x80000000u32)
            & (*inp).sctp_flags;
    (*n_inp).sctp_socket = so;
    (*n_inp).sctp_features = (*inp).sctp_features;
    (*n_inp).sctp_mobility_features = (*inp).sctp_mobility_features;
    (*n_inp).sctp_frag_point = (*inp).sctp_frag_point;
    (*n_inp).sctp_cmt_on_off = (*inp).sctp_cmt_on_off;
    (*n_inp).ecn_supported = (*inp).ecn_supported;
    (*n_inp).prsctp_supported = (*inp).prsctp_supported;
    (*n_inp).auth_supported = (*inp).auth_supported;
    (*n_inp).asconf_supported = (*inp).asconf_supported;
    (*n_inp).reconfig_supported = (*inp).reconfig_supported;
    (*n_inp).nrsack_supported = (*inp).nrsack_supported;
    (*n_inp).pktdrop_supported = (*inp).pktdrop_supported;
    (*n_inp).partial_delivery_point = (*inp).partial_delivery_point;
    (*n_inp).sctp_context = (*inp).sctp_context;
    (*n_inp).max_cwnd = (*inp).max_cwnd;
    (*n_inp).local_strreset_support = (*inp).local_strreset_support;
    (*n_inp).inp_starting_point_for_iterator = 0 as *mut sctp_iterator;
    /* copy in the authentication parameters from the original endpoint */
    if !(*n_inp).sctp_ep.local_hmacs.is_null() {
        sctp_free_hmaclist((*n_inp).sctp_ep.local_hmacs);
    }
    (*n_inp).sctp_ep.local_hmacs = sctp_copy_hmaclist((*inp).sctp_ep.local_hmacs);
    if !(*n_inp).sctp_ep.local_auth_chunks.is_null() {
        sctp_free_chunklist((*n_inp).sctp_ep.local_auth_chunks);
    }
    (*n_inp).sctp_ep.local_auth_chunks = sctp_copy_chunklist((*inp).sctp_ep.local_auth_chunks);
    sctp_copy_skeylist(
        &mut (*inp).sctp_ep.shared_keys,
        &mut (*n_inp).sctp_ep.shared_keys,
    );
    (*n_inp).ulp_info = (*inp).ulp_info;
    (*n_inp).recv_callback = (*inp).recv_callback;
    (*n_inp).send_callback = (*inp).send_callback;
    (*n_inp).send_sb_threshold = (*inp).send_sb_threshold;
    /*
     * Now we must move it from one hash table to another and get the
     * stcb in the right place.
     */
    sctp_move_pcb_and_assoc(inp, n_inp, stcb);
    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
    sctp_pull_off_control_to_new_inp(inp, n_inp, stcb, 0x2i32);
    ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.refcnt, 1u32);
    return 0i32;
}
