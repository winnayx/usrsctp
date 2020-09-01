use ::libc;
extern "C" {
    pub type accept_filter;
    pub type label;
    pub type ifnet;
    pub type aiocblist;
    pub type sigio;
    pub type iface;
    pub type inpcbpolicy;
    pub type icmp6_filter;
    pub type ip6_pktopts;
    pub type ip_moptions;
    pub type uma_zone;
    #[no_mangle]
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
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
    pub c2rust_unnamed: C2RustUnnamed_554,
    pub c2rust_unnamed_0: C2RustUnnamed_552,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_552 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_553,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_553 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_554 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_555,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_555 {
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
    pub __in6_u: C2RustUnnamed_556,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_556 {
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
    pub so_incomp: C2RustUnnamed_564,
    pub so_comp: C2RustUnnamed_563,
    pub so_list: C2RustUnnamed_562,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_561,
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
    pub M_dat: C2RustUnnamed_557,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_557 {
    pub MH: C2RustUnnamed_558,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_558 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_559,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_559 {
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
    pub m_tag_link: C2RustUnnamed_560,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_560 {
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
pub struct C2RustUnnamed_561 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_562 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_563 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_564 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}
pub type sctp_zone_t = size_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_565,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_565 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbhead {
    pub lh_first: *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcb {
    pub inp_hash: C2RustUnnamed_573,
    pub inp_list: C2RustUnnamed_572,
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
    pub inp_depend4: C2RustUnnamed_569,
    pub inp_depend6: C2RustUnnamed_568,
    pub inp_portlist: C2RustUnnamed_567,
    pub inp_phd: *mut inpcbport,
    pub inp_mtx: mtx,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbport {
    pub phd_hash: C2RustUnnamed_566,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_566 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_567 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_568 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_569 {
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
    pub ie_dependfaddr: C2RustUnnamed_571,
    pub ie_dependladdr: C2RustUnnamed_570,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_570 {
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
pub union C2RustUnnamed_571 {
    pub ie46_foreign: in_addr_4in6,
    pub ie6_foreign: in6_addr,
}

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
pub struct C2RustUnnamed_572 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_573 {
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
    pub tqe: C2RustUnnamed_574,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_574 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;
pub type sctp_rtentry_t = sctp_rtentry;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_queue_pending {
    pub data: *mut mbuf,
    pub tail_mbuf: *mut mbuf,
    pub ts: timeval,
    pub net: *mut sctp_nets,
    pub next: C2RustUnnamed_576,
    pub ss_next: C2RustUnnamed_575,
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
pub struct C2RustUnnamed_575 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_576 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_nets {
    pub sctp_next: C2RustUnnamed_582,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifa {
    pub next_ifa: C2RustUnnamed_581,
    pub next_bucket: C2RustUnnamed_580,
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
/* Compatibility to previous define's */
/* On/Off setup for subscription to events */
/* ancillary data types */
/*
 * ancillary data structures
 */
/* We add 96 bytes to the size of sctp_sndrcvinfo.
 * This makes the current structure 128 bytes long
 * which is nicely 64 bit aligned but also has room
 * for us to add more and keep ABI compatibility.
 * For example, already we have the sctp_extrcvinfo
 * when enabled which is 48 bytes.
 */
/*
 * The assoc up needs a verfid
 * all sendrcvinfo's need a verfid for SENDING only.
 */
/* should have been sinfo_pr_value */
/* Flags that go into the sinfo->sinfo_flags field */
/* next message is a notification */
/* next message is complete */
/* Start shutdown procedures */
/* Send an ABORT to peer */
/* Message is un-ordered */
/* Override the primary-address */
/* Send this on all associations */
/* end of message signal */
/* Set I-Bit */
/* for the endpoint */
/* The lower four bits is an enumeration of PR-SCTP policies */
/* Reliable transfer */
/* Time based PR-SCTP */
/* Buffer based PR-SCTP */
/* For backwards compatibility */
/* Number of retransmissions based PR-SCTP */
/* Used for aggregated stats */
/* Stat's */
/*
 * notification event structures
 */
/*
 * association change event
 */
/* sac_state values */
/* sac_info values */
/*
 * Address event
 */
/* paddr state values */
/* SCTP_ADDR_REACHABLE */
/* neither SCTP_ADDR_REACHABLE
nor SCTP_ADDR_UNCONFIRMED */
/* SCTP_ADDR_UNCONFIRMED */
/* remote error events */
/* data send failure event (deprecated) */
/* data send failure event (not deprecated) */
/* flag that indicates state of data */
/* inqueue never on wire */
/* on wire at failure */
/* shutdown event */
/* Adaptation layer indication stuff */
/* compatible old spelling */
/*
 * Partial Delivery API event
 */
/* indication values */
/*
 * authentication key event
 */
/* indication values */
/*
 * Stream reset event - subscribe to SCTP_STREAM_RESET_EVENT
 */
/* flags in stream_reset_event (strreset_flags) */
/*
 * Assoc reset event - subscribe to SCTP_ASSOC_RESET_EVENT
 */
/*
 * Stream change event - subscribe to SCTP_STREAM_CHANGE_EVENT
 */
/* SCTP notification event */
/* compatibility same as above */
/* notification types */
/* same as above */
/* we don't send this*/
/*
 * socket option structs
 */
/* addr is filled in for N * sockaddr_storage */
/*
 * AUTHENTICATION support
 */
/* SCTP_AUTH_CHUNK */
/* SCTP_AUTH_KEY */
/* SCTP_HMAC_IDENT */
/* AUTH hmac_id */
/* default, mandatory */
/* SCTP_AUTH_ACTIVE_KEY / SCTP_AUTH_DELETE_KEY */
/* SCTP_PEER_AUTH_CHUNKS / SCTP_LOCAL_AUTH_CHUNKS */
/* network to */
/* FIXME: LP64 issue */
/* cwnd in k */
/* flightsize in k */
/* increment to it */
/* in 1k bytes */
/* len of send being attempted */
/* rwnd of peer */
/* chnk cnt */
/* chnk cnt */
/* chunks out */
/* flight size in k */
/*
 * Max we can reset in one setting, note this is dictated not by the define
 * but the size of a mbuf cluster so don't change this define and think you
 * can specify more. You must do multiple resets if you want to reset more
 * than SCTP_MAX_EXPLICIT_STR_RESET.
 */
/* 0 == ALL */
/* list if strrst_num_streams is not 0 */
/* Debugging logs */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* chnk cnt */
/* chunks out */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* FIXME: LP64 issue */
/* Number in log */
/* Number returned */
/* start at this one */
/* end at this one */
/* sctpStats 18 (TimeStamp) */
/* MIB according to RFC 3873 */
/* sctpStats  1   (Gauge32) */
/* sctpStats  2 (Counter32) */
/* sctpStats  3 (Counter32) */
/* sctpStats  4 (Counter32) */
/* sctpStats  5 (Counter32) */
/* sctpStats  6 (Counter32) */
/* sctpStats  7 (Counter32) */
/* sctpStats  8 (Counter64) */
/* sctpStats  9 (Counter64) */
/* sctpStats 10 (Counter64) */
/* sctpStats 11 (Counter64) */
/* sctpStats 12 (Counter64) */
/* sctpStats 13 (Counter64) */
/* sctpStats 14 (Counter64) */
/* sctpStats 15 (Counter64) */
/* sctpStats 16 (Counter64) */
/* sctpStats 17 (Counter64) */
/* input statistics: */
/* total input packets        */
/* total input datagrams      */
/* total packets that had data */
/* total input SACK chunks    */
/* total input DATA chunks    */
/* total input duplicate DATA chunks */
/* total input HB chunks      */
/* total input HB-ACK chunks  */
/* total input ECNE chunks    */
/* total input AUTH chunks    */
/* total input chunks missing AUTH */
/* total number of invalid HMAC ids received */
/* total number of invalid secret ids received */
/* total number of auth failed */
/* total fast path receives all one chunk */
/* total fast path multi-part data */
/* formerly sctps_recvnocrc */
/* output statistics: */
/* total output packets       */
/* total output SACKs         */
/* total output DATA chunks   */
/* total output retransmitted DATA chunks */
/* total output fast retransmitted DATA chunks */
/* total FR's that happened more than once
 * to same chunk (u-del multi-fr algo).
 */
/* total output HB chunks     */
/* total output ECNE chunks    */
/* total output AUTH chunks FIXME   */
/* ip_output error counter */
/* formerly sctps_sendnocrc */
/* PCKDROPREP statistics: */
/* Packet drop from middle box */
/* P-drop from end host */
/* P-drops with data */
/* P-drops, non-data, non-endhost */
/* P-drop, non-endhost, bandwidth rep only */
/* P-drop, not enough for chunk header */
/* P-drop, not enough data to confirm */
/* P-drop, where process_chunk_drop said break */
/* P-drop, could not find TSN */
/* P-drop, attempt reverse TSN lookup */
/* P-drop, e-host confirms zero-rwnd */
/* P-drop, midbox confirms no space */
/* P-drop, data did not match TSN */
/* P-drop, TSN's marked for Fast Retran */
/* timeouts */
/* Number of iterator timers that fired */
/* Number of T3 data time outs */
/* Number of window probe (T3) timers that fired */
/* Number of INIT timers that fired */
/* Number of sack timers that fired */
/* Number of shutdown timers that fired */
/* Number of heartbeat timers that fired */
/* Number of times a cookie timeout fired */
/* Number of times an endpoint changed its cookie secret*/
/* Number of PMTU timers that fired */
/* Number of shutdown ack timers that fired */
/* Number of shutdown guard timers that fired */
/* Number of stream reset timers that fired */
/* Number of early FR timers that fired */
/* Number of times an asconf timer fired */
/* Number of times a prim_deleted timer fired */
/* Number of times auto close timer fired */
/* Number of asoc free timers expired */
/* Number of inp free timers expired */
/* former early FR counters */
/* others */
/* packet shorter than header */
/* checksum error             */
/* no endpoint for port       */
/* bad v-tag                  */
/* bad SID                    */
/* no memory                  */
/* number of multiple FR in a RTT window */
/* nagle allowed sending      */
/* nagle doesn't allow sending */
/* max burst doesn't allow sending */
/* look ahead tells us no memory in
 * interface ring buffer OR we had a
 * send error and are queuing one send.
 */
/* total number of window probes sent */
/* total times an output error causes us
 * to clamp down on next user send.
 */
/* total times sctp_senderrors were caused from
 * a user send from a user invoked send not
 * a sack response
 */
/* Number of in data drops due to chunk limit reached */
/* Number of in data drops due to rwnd limit reached */
/* Number of times a ECN reduced the cwnd */
/* Used express lookup via vtag */
/* Collision in express lookup. */
/* Number of times the sender ran dry of user data on primary */
/* Same for above */
/* Sacks the slow way */
/* Window Update only sacks sent */
/* number of sends with sinfo_flags !=0 */
/* number of unordered sends */
/* number of sends with EOF flag set */
/* number of sends with ABORT flag set */
/* number of times protocol drain called */
/* number of times we did a protocol drain */
/* Number of times recv was called with peek */
/* Number of cached chunks used */
/* Number of cached stream oq's used */
/* Number of unread messages abandoned by close */
/* Unused */
/* Send cwnd full  avoidance, already max burst inflight to net */
/* number of map array over-runs via fwd-tsn's */
/* Number of times we queued or updated an ECN chunk on send queue */
/* Future ABI compat - remove int's from here when adding new */
/* The following macros are for handling MIB values, */

#[repr(C)]
#[derive(Copy, Clone)]
pub union sctp_sockstore {
    pub sin: sockaddr_in,
    pub sin6: sockaddr_in6,
    pub sconn: sockaddr_conn,
    pub sa: sockaddr,
}
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
    pub next_ifn: C2RustUnnamed_578,
    pub next_bucket: C2RustUnnamed_577,
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
pub struct C2RustUnnamed_577 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_578 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_579,
    pub vrf_addr_hash: *mut sctp_ifalist,
    pub ifnlist: sctp_ifnlist,
    pub vrf_id: uint32_t,
    pub tbl_id_v4: uint32_t,
    pub tbl_id_v6: uint32_t,
    pub total_ifa_count: uint32_t,
    pub vrf_addr_hashmark: u_long,
    pub refcount: uint32_t,
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
pub struct C2RustUnnamed_579 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_580 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_581 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_582 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
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
    pub next_spoke: C2RustUnnamed_583,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_583 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_584,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_584 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_585,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_585 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_streamhead {
    pub tqh_first: *mut sctp_stream_queue_pending,
    pub tqh_last: *mut *mut sctp_stream_queue_pending,
}
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
pub type sctp_assoc_t = uint32_t;

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_assoc_value {
    pub assoc_id: sctp_assoc_t,
    pub assoc_value: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_cc_option {
    pub option: libc::c_int,
    pub aid_value: sctp_assoc_value,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctppcbhead {
    pub lh_first: *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_603,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_602,
    pub sctp_hash: C2RustUnnamed_601,
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
pub struct sctpasochead {
    pub lh_first: *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_600,
    pub sctp_tcblist: C2RustUnnamed_599,
    pub sctp_tcbasocidhash: C2RustUnnamed_598,
    pub sctp_asocs: C2RustUnnamed_597,
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
    pub next: C2RustUnnamed_586,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_586 {
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
    pub next: C2RustUnnamed_590,
    pub next_instrm: C2RustUnnamed_589,
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
    pub rec: C2RustUnnamed_588,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_587,
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
pub struct C2RustUnnamed_587 {
    pub tqe_next: *mut sctp_tmit_chunk,
    pub tqe_prev: *mut *mut sctp_tmit_chunk,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_588 {
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
pub struct C2RustUnnamed_589 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_590 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}
/* local random key (concatenated) */
/* local random number length for param */
/* peer's random key (concatenated) */
/* cached concatenated send key */
/* cached concatenated recv key */
/* active send keyid */
/* current send keyid (cached) */
/* last recv keyid (cached) */
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
    pub next_resp: C2RustUnnamed_591,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_591 {
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
    pub sctp_nxt_addr: C2RustUnnamed_592,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_592 {
    pub le_next: *mut sctp_laddr,
    pub le_prev: *mut *mut sctp_laddr,
}
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
    pub next: C2RustUnnamed_593,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_593 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_594,
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
pub struct C2RustUnnamed_594 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_595,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_595 {
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
    pub next: C2RustUnnamed_596,
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
pub struct sctp_asconf_paramhdr {
    pub ph: sctp_paramhdr,
    pub correlation_id: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_596 {
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
pub struct C2RustUnnamed_597 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_598 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_599 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_600 {
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
pub struct C2RustUnnamed_601 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_602 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_603 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpvtaghead {
    pub lh_first: *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tagblock {
    pub sctp_nxt_tagblock: C2RustUnnamed_604,
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
pub struct C2RustUnnamed_604 {
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
unsafe extern "C" fn sctp_ss_default_init(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut holds_lock: libc::c_int,
) {
    let mut i = 0;
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    (*asoc).ss_data.locked_on_sending = 0 as *mut sctp_stream_out;
    (*asoc).ss_data.last_out_stream = 0 as *mut sctp_stream_out;
    (*asoc).ss_data.out.wheel.tqh_first = 0 as *mut sctp_stream_out;
    (*asoc).ss_data.out.wheel.tqh_last = &mut (*asoc).ss_data.out.wheel.tqh_first;
    /*
     * If there is data in the stream queues already,
     * the scheduler of an existing association has
     * been changed. We need to add all stream queues
     * to the wheel.
     */
    i = 0u16;
    while (i as libc::c_int) < (*stcb).asoc.streamoutcnt as libc::c_int {
        (*stcb)
            .asoc
            .ss_functions
            .sctp_ss_add_to_stream
            .expect("non-null function pointer")(
            stcb,
            &mut (*stcb).asoc,
            &mut *(*stcb).asoc.strmout.offset(i as isize),
            0 as *mut sctp_stream_queue_pending,
            1i32,
        );
        i = i.wrapping_add(1)
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_default_clear(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut clear_values: libc::c_int,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    while !(*asoc).ss_data.out.wheel.tqh_first.is_null() {
        let mut strq = 0 as *mut sctp_stream_out;
        strq = (*asoc).ss_data.out.wheel.tqh_first;
        if !(*strq).ss_params.rr.next_spoke.tqe_next.is_null() {
            (*(*strq).ss_params.rr.next_spoke.tqe_next)
                .ss_params
                .rr
                .next_spoke
                .tqe_prev = (*strq).ss_params.rr.next_spoke.tqe_prev
        } else {
            (*asoc).ss_data.out.wheel.tqh_last = (*strq).ss_params.rr.next_spoke.tqe_prev
        }
        *(*strq).ss_params.rr.next_spoke.tqe_prev = (*strq).ss_params.rr.next_spoke.tqe_next;
        (*strq).ss_params.rr.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.rr.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out
    }
    (*asoc).ss_data.last_out_stream = 0 as *mut sctp_stream_out;
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_default_init_stream(
    mut stcb: *mut sctp_tcb,
    mut strq: *mut sctp_stream_out,
    mut with_strq: *mut sctp_stream_out,
) {
    if !with_strq.is_null() {
        if (*stcb).asoc.ss_data.locked_on_sending == with_strq {
            (*stcb).asoc.ss_data.locked_on_sending = strq
        }
        if (*stcb).asoc.ss_data.last_out_stream == with_strq {
            (*stcb).asoc.ss_data.last_out_stream = strq
        }
    }
    (*strq).ss_params.rr.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
    (*strq).ss_params.rr.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out;
}
/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2010-2012, by Michael Tuexen. All rights reserved.
 * Copyright (c) 2010-2012, by Randall Stewart. All rights reserved.
 * Copyright (c) 2010-2012, by Robin Seggelmann. All rights reserved.
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
 * Default simple round-robin algorithm.
 * Just interates the streams in the order they appear.
 */
unsafe extern "C" fn sctp_ss_default_add(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    /* Add to wheel if not already on it and stream queue not empty */
    if !(*strq).outqueue.tqh_first.is_null()
        && (*strq).ss_params.rr.next_spoke.tqe_next.is_null()
        && (*strq).ss_params.rr.next_spoke.tqe_prev.is_null()
    {
        (*strq).ss_params.rr.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.rr.next_spoke.tqe_prev = (*asoc).ss_data.out.wheel.tqh_last;
        *(*asoc).ss_data.out.wheel.tqh_last = strq;
        (*asoc).ss_data.out.wheel.tqh_last = &mut (*strq).ss_params.rr.next_spoke.tqe_next
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_default_is_empty(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) -> libc::c_int {
    if (*asoc).ss_data.out.wheel.tqh_first.is_null() {
        return 1i32;
    } else {
        return 0i32;
    };
}
unsafe extern "C" fn sctp_ss_default_remove(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    /* Remove from wheel if stream queue is empty and actually is on the wheel */
    if (*strq).outqueue.tqh_first.is_null()
        && (!(*strq).ss_params.rr.next_spoke.tqe_next.is_null()
            || !(*strq).ss_params.rr.next_spoke.tqe_prev.is_null())
    {
        if (*asoc).ss_data.last_out_stream == strq {
            (*asoc).ss_data.last_out_stream = *(*((*(*asoc).ss_data.last_out_stream)
                .ss_params
                .rr
                .next_spoke
                .tqe_prev
                as *mut sctpwheel_listhead))
                .tqh_last;
            if (*asoc).ss_data.last_out_stream.is_null() {
                (*asoc).ss_data.last_out_stream =
                    *(*((*asoc).ss_data.out.wheel.tqh_last as *mut sctpwheel_listhead)).tqh_last
            }
            if (*asoc).ss_data.last_out_stream == strq {
                (*asoc).ss_data.last_out_stream = 0 as *mut sctp_stream_out
            }
        }
        if !(*strq).ss_params.rr.next_spoke.tqe_next.is_null() {
            (*(*strq).ss_params.rr.next_spoke.tqe_next)
                .ss_params
                .rr
                .next_spoke
                .tqe_prev = (*strq).ss_params.rr.next_spoke.tqe_prev
        } else {
            (*asoc).ss_data.out.wheel.tqh_last = (*strq).ss_params.rr.next_spoke.tqe_prev
        }
        *(*strq).ss_params.rr.next_spoke.tqe_prev = (*strq).ss_params.rr.next_spoke.tqe_next;
        (*strq).ss_params.rr.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.rr.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_default_select(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
) -> *mut sctp_stream_out {
    let mut strq = 0 as *mut sctp_stream_out;
    let mut strqt = 0 as *mut sctp_stream_out;
    if !(*asoc).ss_data.locked_on_sending.is_null() {
        return (*asoc).ss_data.locked_on_sending;
    }
    strqt = (*asoc).ss_data.last_out_stream;
    loop {
        /* Find the next stream to use */
        if strqt.is_null() {
            strq = (*asoc).ss_data.out.wheel.tqh_first
        } else {
            strq = (*strqt).ss_params.rr.next_spoke.tqe_next;
            if strq.is_null() {
                strq = (*asoc).ss_data.out.wheel.tqh_first
            }
        }
        /* If CMT is off, we must validate that
         * the stream in question has the first
         * item pointed towards are network destination
         * requested by the caller. Note that if we
         * turn out to be locked to a stream (assigning
         * TSN's then we must stop, since we cannot
         * look for another stream with data to send
         * to that destination). In CMT's case, by
         * skipping this check, we will send one
         * data packet towards the requested net.
         */
        if !(!net.is_null()
            && !strq.is_null()
            && system_base_info.sctpsysctl.sctp_cmt_on_off == 0u32)
        {
            break;
        }
        if !(!(*strq).outqueue.tqh_first.is_null()
            && !(*(*strq).outqueue.tqh_first).net.is_null()
            && (*(*strq).outqueue.tqh_first).net != net)
        {
            break;
        }
        if strq == (*asoc).ss_data.last_out_stream {
            return 0 as *mut sctp_stream_out;
        } else {
            strqt = strq
        }
    }
    return strq;
}
unsafe extern "C" fn sctp_ss_default_scheduled(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut moved_how_much: libc::c_int,
) {
    (*asoc).ss_data.last_out_stream = strq;
    if (*stcb).asoc.idata_supported as libc::c_int == 0i32 {
        let mut sp = 0 as *mut sctp_stream_queue_pending;
        sp = (*strq).outqueue.tqh_first;
        if !sp.is_null() && (*sp).some_taken as libc::c_int == 1i32 {
            (*stcb).asoc.ss_data.locked_on_sending = strq
        } else {
            (*stcb).asoc.ss_data.locked_on_sending = 0 as *mut sctp_stream_out
        }
    } else {
        (*stcb).asoc.ss_data.locked_on_sending = 0 as *mut sctp_stream_out
    };
}
unsafe extern "C" fn sctp_ss_default_packet_done(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
) {
}
unsafe extern "C" fn sctp_ss_default_get_value(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut value: *mut uint16_t,
) -> libc::c_int {
    /* Nothing to be done here */
    return -(1i32);
}
unsafe extern "C" fn sctp_ss_default_set_value(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut value: uint16_t,
) -> libc::c_int {
    /* Nothing to be done here */
    return -(1i32);
}
unsafe extern "C" fn sctp_ss_default_is_user_msgs_incomplete(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) -> libc::c_int {
    let mut strq = 0 as *mut sctp_stream_out;
    let mut sp = 0 as *mut sctp_stream_queue_pending;
    if (*asoc).stream_queue_cnt != 1u32 {
        return 0i32;
    }
    strq = (*asoc).ss_data.locked_on_sending;
    if strq.is_null() {
        return 0i32;
    }
    sp = (*strq).outqueue.tqh_first;
    if sp.is_null() {
        return 0i32;
    }
    return ((*sp).msg_is_complete == 0) as libc::c_int;
}
/*
 * Real round-robin algorithm.
 * Always interates the streams in ascending order.
 */
unsafe extern "C" fn sctp_ss_rr_add(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    if !(*strq).outqueue.tqh_first.is_null()
        && (*strq).ss_params.rr.next_spoke.tqe_next.is_null()
        && (*strq).ss_params.rr.next_spoke.tqe_prev.is_null()
    {
        if (*asoc).ss_data.out.wheel.tqh_first.is_null() {
            (*strq).ss_params.rr.next_spoke.tqe_next = (*asoc).ss_data.out.wheel.tqh_first;
            if !(*strq).ss_params.rr.next_spoke.tqe_next.is_null() {
                (*(*asoc).ss_data.out.wheel.tqh_first)
                    .ss_params
                    .rr
                    .next_spoke
                    .tqe_prev = &mut (*strq).ss_params.rr.next_spoke.tqe_next
            } else {
                (*asoc).ss_data.out.wheel.tqh_last = &mut (*strq).ss_params.rr.next_spoke.tqe_next
            }
            (*asoc).ss_data.out.wheel.tqh_first = strq;
            (*strq).ss_params.rr.next_spoke.tqe_prev = &mut (*asoc).ss_data.out.wheel.tqh_first
        } else {
            let mut strqt = 0 as *mut sctp_stream_out;
            strqt = (*asoc).ss_data.out.wheel.tqh_first;
            while !strqt.is_null() && ((*strqt).sid as libc::c_int) < (*strq).sid as libc::c_int {
                strqt = (*strqt).ss_params.rr.next_spoke.tqe_next
            }
            if !strqt.is_null() {
                (*strq).ss_params.rr.next_spoke.tqe_prev =
                    (*strqt).ss_params.rr.next_spoke.tqe_prev;
                (*strq).ss_params.rr.next_spoke.tqe_next = strqt;
                *(*strqt).ss_params.rr.next_spoke.tqe_prev = strq;
                (*strqt).ss_params.rr.next_spoke.tqe_prev =
                    &mut (*strq).ss_params.rr.next_spoke.tqe_next
            } else {
                (*strq).ss_params.rr.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
                (*strq).ss_params.rr.next_spoke.tqe_prev = (*asoc).ss_data.out.wheel.tqh_last;
                *(*asoc).ss_data.out.wheel.tqh_last = strq;
                (*asoc).ss_data.out.wheel.tqh_last = &mut (*strq).ss_params.rr.next_spoke.tqe_next
            }
        }
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
/*
 * Real round-robin per packet algorithm.
 * Always interates the streams in ascending order and
 * only fills messages of the same stream in a packet.
 */
unsafe extern "C" fn sctp_ss_rrp_select(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
) -> *mut sctp_stream_out {
    return (*asoc).ss_data.last_out_stream;
}
unsafe extern "C" fn sctp_ss_rrp_packet_done(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
) {
    let mut strq = 0 as *mut sctp_stream_out;
    let mut strqt = 0 as *mut sctp_stream_out;
    strqt = (*asoc).ss_data.last_out_stream;
    loop {
        /* Find the next stream to use */
        if strqt.is_null() {
            strq = (*asoc).ss_data.out.wheel.tqh_first
        } else {
            strq = (*strqt).ss_params.rr.next_spoke.tqe_next;
            if strq.is_null() {
                strq = (*asoc).ss_data.out.wheel.tqh_first
            }
        }
        /* If CMT is off, we must validate that
         * the stream in question has the first
         * item pointed towards are network destination
         * requested by the caller. Note that if we
         * turn out to be locked to a stream (assigning
         * TSN's then we must stop, since we cannot
         * look for another stream with data to send
         * to that destination). In CMT's case, by
         * skipping this check, we will send one
         * data packet towards the requested net.
         */
        if !(!net.is_null()
            && !strq.is_null()
            && system_base_info.sctpsysctl.sctp_cmt_on_off == 0u32)
        {
            break;
        }
        if !(!(*strq).outqueue.tqh_first.is_null()
            && !(*(*strq).outqueue.tqh_first).net.is_null()
            && (*(*strq).outqueue.tqh_first).net != net)
        {
            break;
        }
        if strq == (*asoc).ss_data.last_out_stream {
            strq = 0 as *mut sctp_stream_out;
            break;
        } else {
            strqt = strq
        }
    }
    (*asoc).ss_data.last_out_stream = strq;
}
/*
 * Priority algorithm.
 * Always prefers streams based on their priority id.
 */
unsafe extern "C" fn sctp_ss_prio_clear(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut clear_values: libc::c_int,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    while !(*asoc).ss_data.out.wheel.tqh_first.is_null() {
        let mut strq = 0 as *mut sctp_stream_out;
        strq = (*asoc).ss_data.out.wheel.tqh_first;
        if clear_values != 0 {
            (*strq).ss_params.prio.priority = 0u16
        }
        if !(*strq).ss_params.prio.next_spoke.tqe_next.is_null() {
            (*(*strq).ss_params.prio.next_spoke.tqe_next)
                .ss_params
                .prio
                .next_spoke
                .tqe_prev = (*strq).ss_params.prio.next_spoke.tqe_prev
        } else {
            (*asoc).ss_data.out.wheel.tqh_last = (*strq).ss_params.prio.next_spoke.tqe_prev
        }
        *(*strq).ss_params.prio.next_spoke.tqe_prev = (*strq).ss_params.prio.next_spoke.tqe_next;
        (*strq).ss_params.prio.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.prio.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out
    }
    (*asoc).ss_data.last_out_stream = 0 as *mut sctp_stream_out;
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_prio_init_stream(
    mut stcb: *mut sctp_tcb,
    mut strq: *mut sctp_stream_out,
    mut with_strq: *mut sctp_stream_out,
) {
    if !with_strq.is_null() {
        if (*stcb).asoc.ss_data.locked_on_sending == with_strq {
            (*stcb).asoc.ss_data.locked_on_sending = strq
        }
        if (*stcb).asoc.ss_data.last_out_stream == with_strq {
            (*stcb).asoc.ss_data.last_out_stream = strq
        }
    }
    (*strq).ss_params.prio.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
    (*strq).ss_params.prio.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out;
    if !with_strq.is_null() {
        (*strq).ss_params.prio.priority = (*with_strq).ss_params.prio.priority
    } else {
        (*strq).ss_params.prio.priority = 0u16
    };
}
unsafe extern "C" fn sctp_ss_prio_add(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    /* Add to wheel if not already on it and stream queue not empty */
    if !(*strq).outqueue.tqh_first.is_null()
        && (*strq).ss_params.prio.next_spoke.tqe_next.is_null()
        && (*strq).ss_params.prio.next_spoke.tqe_prev.is_null()
    {
        if (*asoc).ss_data.out.wheel.tqh_first.is_null() {
            (*strq).ss_params.prio.next_spoke.tqe_next = (*asoc).ss_data.out.wheel.tqh_first;
            if !(*strq).ss_params.prio.next_spoke.tqe_next.is_null() {
                (*(*asoc).ss_data.out.wheel.tqh_first)
                    .ss_params
                    .prio
                    .next_spoke
                    .tqe_prev = &mut (*strq).ss_params.prio.next_spoke.tqe_next
            } else {
                (*asoc).ss_data.out.wheel.tqh_last = &mut (*strq).ss_params.prio.next_spoke.tqe_next
            }
            (*asoc).ss_data.out.wheel.tqh_first = strq;
            (*strq).ss_params.prio.next_spoke.tqe_prev = &mut (*asoc).ss_data.out.wheel.tqh_first
        } else {
            let mut strqt = 0 as *mut sctp_stream_out;
            strqt = (*asoc).ss_data.out.wheel.tqh_first;
            while !strqt.is_null()
                && ((*strqt).ss_params.prio.priority as libc::c_int)
                    < (*strq).ss_params.prio.priority as libc::c_int
            {
                strqt = (*strqt).ss_params.prio.next_spoke.tqe_next
            }
            if !strqt.is_null() {
                (*strq).ss_params.prio.next_spoke.tqe_prev =
                    (*strqt).ss_params.prio.next_spoke.tqe_prev;
                (*strq).ss_params.prio.next_spoke.tqe_next = strqt;
                *(*strqt).ss_params.prio.next_spoke.tqe_prev = strq;
                (*strqt).ss_params.prio.next_spoke.tqe_prev =
                    &mut (*strq).ss_params.prio.next_spoke.tqe_next
            } else {
                (*strq).ss_params.prio.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
                (*strq).ss_params.prio.next_spoke.tqe_prev = (*asoc).ss_data.out.wheel.tqh_last;
                *(*asoc).ss_data.out.wheel.tqh_last = strq;
                (*asoc).ss_data.out.wheel.tqh_last = &mut (*strq).ss_params.prio.next_spoke.tqe_next
            }
        }
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_prio_remove(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    /* Remove from wheel if stream queue is empty and actually is on the wheel */
    if (*strq).outqueue.tqh_first.is_null()
        && (!(*strq).ss_params.prio.next_spoke.tqe_next.is_null()
            || !(*strq).ss_params.prio.next_spoke.tqe_prev.is_null())
    {
        if (*asoc).ss_data.last_out_stream == strq {
            (*asoc).ss_data.last_out_stream = *(*((*(*asoc).ss_data.last_out_stream)
                .ss_params
                .prio
                .next_spoke
                .tqe_prev
                as *mut sctpwheel_listhead))
                .tqh_last;
            if (*asoc).ss_data.last_out_stream.is_null() {
                (*asoc).ss_data.last_out_stream =
                    *(*((*asoc).ss_data.out.wheel.tqh_last as *mut sctpwheel_listhead)).tqh_last
            }
            if (*asoc).ss_data.last_out_stream == strq {
                (*asoc).ss_data.last_out_stream = 0 as *mut sctp_stream_out
            }
        }
        if !(*strq).ss_params.prio.next_spoke.tqe_next.is_null() {
            (*(*strq).ss_params.prio.next_spoke.tqe_next)
                .ss_params
                .prio
                .next_spoke
                .tqe_prev = (*strq).ss_params.prio.next_spoke.tqe_prev
        } else {
            (*asoc).ss_data.out.wheel.tqh_last = (*strq).ss_params.prio.next_spoke.tqe_prev
        }
        *(*strq).ss_params.prio.next_spoke.tqe_prev = (*strq).ss_params.prio.next_spoke.tqe_next;
        (*strq).ss_params.prio.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.prio.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_prio_select(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
) -> *mut sctp_stream_out {
    let mut strq = 0 as *mut sctp_stream_out;
    let mut strqt = 0 as *mut sctp_stream_out;
    strqt = (*asoc).ss_data.last_out_stream;
    loop {
        /* Find the next stream to use */
        if strqt.is_null() {
            strq = (*asoc).ss_data.out.wheel.tqh_first
        } else {
            let mut strqn = 0 as *mut sctp_stream_out;
            strqn = (*strqt).ss_params.prio.next_spoke.tqe_next;
            if !strqn.is_null()
                && (*strqn).ss_params.prio.priority as libc::c_int
                    == (*strqt).ss_params.prio.priority as libc::c_int
            {
                strq = strqn
            } else {
                strq = (*asoc).ss_data.out.wheel.tqh_first
            }
        }
        /* If CMT is off, we must validate that
         * the stream in question has the first
         * item pointed towards are network destination
         * requested by the caller. Note that if we
         * turn out to be locked to a stream (assigning
         * TSN's then we must stop, since we cannot
         * look for another stream with data to send
         * to that destination). In CMT's case, by
         * skipping this check, we will send one
         * data packet towards the requested net.
         */
        if !(!net.is_null()
            && !strq.is_null()
            && system_base_info.sctpsysctl.sctp_cmt_on_off == 0u32)
        {
            break;
        }
        if !(!(*strq).outqueue.tqh_first.is_null()
            && !(*(*strq).outqueue.tqh_first).net.is_null()
            && (*(*strq).outqueue.tqh_first).net != net)
        {
            break;
        }
        if strq == (*asoc).ss_data.last_out_stream {
            return 0 as *mut sctp_stream_out;
        } else {
            strqt = strq
        }
    }
    return strq;
}
unsafe extern "C" fn sctp_ss_prio_get_value(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut value: *mut uint16_t,
) -> libc::c_int {
    if strq.is_null() {
        return -(1i32);
    }
    *value = (*strq).ss_params.prio.priority;
    return 1i32;
}
unsafe extern "C" fn sctp_ss_prio_set_value(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut value: uint16_t,
) -> libc::c_int {
    if strq.is_null() {
        return -(1i32);
    }
    (*strq).ss_params.prio.priority = value;
    sctp_ss_prio_remove(stcb, asoc, strq, 0 as *mut sctp_stream_queue_pending, 1i32);
    sctp_ss_prio_add(stcb, asoc, strq, 0 as *mut sctp_stream_queue_pending, 1i32);
    return 1i32;
}
/*
 * Fair bandwidth algorithm.
 * Maintains an equal troughput per stream.
 */
unsafe extern "C" fn sctp_ss_fb_clear(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut clear_values: libc::c_int,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    while !(*asoc).ss_data.out.wheel.tqh_first.is_null() {
        let mut strq = 0 as *mut sctp_stream_out;
        strq = (*asoc).ss_data.out.wheel.tqh_first;
        if clear_values != 0 {
            (*strq).ss_params.fb.rounds = -(1i32)
        }
        if !(*strq).ss_params.fb.next_spoke.tqe_next.is_null() {
            (*(*strq).ss_params.fb.next_spoke.tqe_next)
                .ss_params
                .fb
                .next_spoke
                .tqe_prev = (*strq).ss_params.fb.next_spoke.tqe_prev
        } else {
            (*asoc).ss_data.out.wheel.tqh_last = (*strq).ss_params.fb.next_spoke.tqe_prev
        }
        *(*strq).ss_params.fb.next_spoke.tqe_prev = (*strq).ss_params.fb.next_spoke.tqe_next;
        (*strq).ss_params.fb.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.fb.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out
    }
    (*asoc).ss_data.last_out_stream = 0 as *mut sctp_stream_out;
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_fb_init_stream(
    mut stcb: *mut sctp_tcb,
    mut strq: *mut sctp_stream_out,
    mut with_strq: *mut sctp_stream_out,
) {
    if !with_strq.is_null() {
        if (*stcb).asoc.ss_data.locked_on_sending == with_strq {
            (*stcb).asoc.ss_data.locked_on_sending = strq
        }
        if (*stcb).asoc.ss_data.last_out_stream == with_strq {
            (*stcb).asoc.ss_data.last_out_stream = strq
        }
    }
    (*strq).ss_params.fb.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
    (*strq).ss_params.fb.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out;
    if !with_strq.is_null() {
        (*strq).ss_params.fb.rounds = (*with_strq).ss_params.fb.rounds
    } else {
        (*strq).ss_params.fb.rounds = -(1i32)
    };
}
unsafe extern "C" fn sctp_ss_fb_add(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    if !(*strq).outqueue.tqh_first.is_null()
        && (*strq).ss_params.fb.next_spoke.tqe_next.is_null()
        && (*strq).ss_params.fb.next_spoke.tqe_prev.is_null()
    {
        if (*strq).ss_params.fb.rounds < 0i32 {
            (*strq).ss_params.fb.rounds = (*(*strq).outqueue.tqh_first).length as int32_t
        }
        (*strq).ss_params.fb.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.fb.next_spoke.tqe_prev = (*asoc).ss_data.out.wheel.tqh_last;
        *(*asoc).ss_data.out.wheel.tqh_last = strq;
        (*asoc).ss_data.out.wheel.tqh_last = &mut (*strq).ss_params.fb.next_spoke.tqe_next
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_fb_remove(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    /* Remove from wheel if stream queue is empty and actually is on the wheel */
    if (*strq).outqueue.tqh_first.is_null()
        && (!(*strq).ss_params.fb.next_spoke.tqe_next.is_null()
            || !(*strq).ss_params.fb.next_spoke.tqe_prev.is_null())
    {
        if (*asoc).ss_data.last_out_stream == strq {
            (*asoc).ss_data.last_out_stream = *(*((*(*asoc).ss_data.last_out_stream)
                .ss_params
                .fb
                .next_spoke
                .tqe_prev
                as *mut sctpwheel_listhead))
                .tqh_last;
            if (*asoc).ss_data.last_out_stream.is_null() {
                (*asoc).ss_data.last_out_stream =
                    *(*((*asoc).ss_data.out.wheel.tqh_last as *mut sctpwheel_listhead)).tqh_last
            }
            if (*asoc).ss_data.last_out_stream == strq {
                (*asoc).ss_data.last_out_stream = 0 as *mut sctp_stream_out
            }
        }
        if !(*strq).ss_params.fb.next_spoke.tqe_next.is_null() {
            (*(*strq).ss_params.fb.next_spoke.tqe_next)
                .ss_params
                .fb
                .next_spoke
                .tqe_prev = (*strq).ss_params.fb.next_spoke.tqe_prev
        } else {
            (*asoc).ss_data.out.wheel.tqh_last = (*strq).ss_params.fb.next_spoke.tqe_prev
        }
        *(*strq).ss_params.fb.next_spoke.tqe_prev = (*strq).ss_params.fb.next_spoke.tqe_next;
        (*strq).ss_params.fb.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
        (*strq).ss_params.fb.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_fb_select(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
) -> *mut sctp_stream_out {
    let mut strq = 0 as *mut sctp_stream_out;
    let mut strqt = 0 as *mut sctp_stream_out;
    if (*asoc).ss_data.last_out_stream.is_null()
        || (*asoc).ss_data.out.wheel.tqh_first
            == *(*((*asoc).ss_data.out.wheel.tqh_last as *mut sctpwheel_listhead)).tqh_last
    {
        strqt = (*asoc).ss_data.out.wheel.tqh_first
    } else {
        strqt = (*(*asoc).ss_data.last_out_stream)
            .ss_params
            .fb
            .next_spoke
            .tqe_next
    }
    loop {
        if !strqt.is_null()
            && (system_base_info.sctpsysctl.sctp_cmt_on_off > 0u32
                || system_base_info.sctpsysctl.sctp_cmt_on_off == 0u32
                    && (net.is_null()
                        || !(*strqt).outqueue.tqh_first.is_null()
                            && (*(*strqt).outqueue.tqh_first).net.is_null()
                        || !net.is_null()
                            && !(*strqt).outqueue.tqh_first.is_null()
                            && !(*(*strqt).outqueue.tqh_first).net.is_null()
                            && (*(*strqt).outqueue.tqh_first).net == net))
        {
            if (*strqt).ss_params.fb.rounds >= 0i32
                && (strq.is_null() || (*strqt).ss_params.fb.rounds < (*strq).ss_params.fb.rounds)
            {
                strq = strqt
            }
        }
        if !strqt.is_null() {
            strqt = (*strqt).ss_params.fb.next_spoke.tqe_next
        } else {
            strqt = (*asoc).ss_data.out.wheel.tqh_first
        }
        if !(strqt != strq) {
            break;
        }
    }
    return strq;
}
unsafe extern "C" fn sctp_ss_fb_scheduled(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut moved_how_much: libc::c_int,
) {
    let mut strqt = 0 as *mut sctp_stream_out;
    let mut subtract = 0;
    if (*stcb).asoc.idata_supported as libc::c_int == 0i32 {
        let mut sp = 0 as *mut sctp_stream_queue_pending;
        sp = (*strq).outqueue.tqh_first;
        if !sp.is_null() && (*sp).some_taken as libc::c_int == 1i32 {
            (*stcb).asoc.ss_data.locked_on_sending = strq
        } else {
            (*stcb).asoc.ss_data.locked_on_sending = 0 as *mut sctp_stream_out
        }
    } else {
        (*stcb).asoc.ss_data.locked_on_sending = 0 as *mut sctp_stream_out
    }
    subtract = (*strq).ss_params.fb.rounds;
    strqt = (*asoc).ss_data.out.wheel.tqh_first;
    while !strqt.is_null() {
        (*strqt).ss_params.fb.rounds -= subtract;
        if (*strqt).ss_params.fb.rounds < 0i32 {
            (*strqt).ss_params.fb.rounds = 0i32
        }
        strqt = (*strqt).ss_params.fb.next_spoke.tqe_next
    }
    if !(*strq).outqueue.tqh_first.is_null() {
        (*strq).ss_params.fb.rounds = (*(*strq).outqueue.tqh_first).length as int32_t
    } else {
        (*strq).ss_params.fb.rounds = -(1i32)
    }
    (*asoc).ss_data.last_out_stream = strq;
}
unsafe extern "C" fn sctp_ss_fcfs_init(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut holds_lock: libc::c_int,
) {
    let mut add_more = 1u32;
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    (*asoc).ss_data.out.list.tqh_first = 0 as *mut sctp_stream_queue_pending;
    (*asoc).ss_data.out.list.tqh_last = &mut (*asoc).ss_data.out.list.tqh_first;
    /*
     * If there is data in the stream queues already,
     * the scheduler of an existing association has
     * been changed. We can only cycle through the
     * stream queues and add everything to the FCFS
     * queue.
     */
    while add_more != 0 {
        let mut n = 0u32;
        let mut i = 0;
        add_more = 0u32;
        i = 0u16;
        while (i as libc::c_int) < (*stcb).asoc.streamoutcnt as libc::c_int {
            let mut x = 0;
            let mut sp = 0 as *mut sctp_stream_queue_pending;
            sp = (*(*stcb).asoc.strmout.offset(i as isize))
                .outqueue
                .tqh_first;
            x = 0u32;
            /* Find n. message in current stream queue */
            while !sp.is_null() && x < n {
                sp = (*sp).next.tqe_next;
                x = x.wrapping_add(1)
            }
            if !sp.is_null() {
                sctp_ss_fcfs_add(
                    stcb,
                    &mut (*stcb).asoc,
                    &mut *(*stcb).asoc.strmout.offset(i as isize),
                    sp,
                    1i32,
                );
                add_more = 1u32
            }
            i = i.wrapping_add(1)
        }
        n = n.wrapping_add(1)
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_fcfs_clear(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut clear_values: libc::c_int,
    mut holds_lock: libc::c_int,
) {
    if clear_values != 0 {
        if holds_lock == 0i32 {
            pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
        }
        while !(*asoc).ss_data.out.list.tqh_first.is_null() {
            let mut sp = 0 as *mut sctp_stream_queue_pending;
            sp = (*asoc).ss_data.out.list.tqh_first;
            if !(*sp).ss_next.tqe_next.is_null() {
                (*(*sp).ss_next.tqe_next).ss_next.tqe_prev = (*sp).ss_next.tqe_prev
            } else {
                (*asoc).ss_data.out.list.tqh_last = (*sp).ss_next.tqe_prev
            }
            *(*sp).ss_next.tqe_prev = (*sp).ss_next.tqe_next;
            (*sp).ss_next.tqe_next = 0 as *mut sctp_stream_queue_pending;
            (*sp).ss_next.tqe_prev = 0 as *mut *mut sctp_stream_queue_pending
        }
        if holds_lock == 0i32 {
            pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
        }
    };
}
unsafe extern "C" fn sctp_ss_fcfs_init_stream(
    mut stcb: *mut sctp_tcb,
    mut strq: *mut sctp_stream_out,
    mut with_strq: *mut sctp_stream_out,
) {
    if !with_strq.is_null() {
        if (*stcb).asoc.ss_data.locked_on_sending == with_strq {
            (*stcb).asoc.ss_data.locked_on_sending = strq
        }
        if (*stcb).asoc.ss_data.last_out_stream == with_strq {
            (*stcb).asoc.ss_data.last_out_stream = strq
        }
    }
    (*strq).ss_params.fb.next_spoke.tqe_next = 0 as *mut sctp_stream_out;
    (*strq).ss_params.fb.next_spoke.tqe_prev = 0 as *mut *mut sctp_stream_out;
}
/*
 * First-come, first-serve algorithm.
 * Maintains the order provided by the application.
 */
unsafe extern "C" fn sctp_ss_fcfs_add(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    if !sp.is_null() && (*sp).ss_next.tqe_next.is_null() && (*sp).ss_next.tqe_prev.is_null() {
        (*sp).ss_next.tqe_next = 0 as *mut sctp_stream_queue_pending;
        (*sp).ss_next.tqe_prev = (*asoc).ss_data.out.list.tqh_last;
        *(*asoc).ss_data.out.list.tqh_last = sp;
        (*asoc).ss_data.out.list.tqh_last = &mut (*sp).ss_next.tqe_next
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_fcfs_is_empty(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) -> libc::c_int {
    if (*asoc).ss_data.out.list.tqh_first.is_null() {
        return 1i32;
    } else {
        return 0i32;
    };
}
unsafe extern "C" fn sctp_ss_fcfs_remove(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strq: *mut sctp_stream_out,
    mut sp: *mut sctp_stream_queue_pending,
    mut holds_lock: libc::c_int,
) {
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    if !sp.is_null() && (!(*sp).ss_next.tqe_next.is_null() || !(*sp).ss_next.tqe_prev.is_null()) {
        if !(*sp).ss_next.tqe_next.is_null() {
            (*(*sp).ss_next.tqe_next).ss_next.tqe_prev = (*sp).ss_next.tqe_prev
        } else {
            (*asoc).ss_data.out.list.tqh_last = (*sp).ss_next.tqe_prev
        }
        *(*sp).ss_next.tqe_prev = (*sp).ss_next.tqe_next;
        (*sp).ss_next.tqe_next = 0 as *mut sctp_stream_queue_pending;
        (*sp).ss_next.tqe_prev = 0 as *mut *mut sctp_stream_queue_pending
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
unsafe extern "C" fn sctp_ss_fcfs_select(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut asoc: *mut sctp_association,
) -> *mut sctp_stream_out {
    let mut strq = 0 as *mut sctp_stream_out;
    let mut sp = 0 as *mut sctp_stream_queue_pending;
    sp = (*asoc).ss_data.out.list.tqh_first;
    loop {
        if !sp.is_null() {
            strq = &mut *(*asoc).strmout.offset((*sp).sid as isize) as *mut sctp_stream_out
        } else {
            strq = 0 as *mut sctp_stream_out
        }
        /*
         * If CMT is off, we must validate that
         * the stream in question has the first
         * item pointed towards are network destination
         * requested by the caller. Note that if we
         * turn out to be locked to a stream (assigning
         * TSN's then we must stop, since we cannot
         * look for another stream with data to send
         * to that destination). In CMT's case, by
         * skipping this check, we will send one
         * data packet towards the requested net.
         */
        if !(!net.is_null()
            && !strq.is_null()
            && system_base_info.sctpsysctl.sctp_cmt_on_off == 0u32)
        {
            break;
        }
        if !(!(*strq).outqueue.tqh_first.is_null()
            && !(*(*strq).outqueue.tqh_first).net.is_null()
            && (*(*strq).outqueue.tqh_first).net != net)
        {
            break;
        }
        sp = (*sp).ss_next.tqe_next
    }
    return strq;
}
#[no_mangle]
pub static mut sctp_ss_functions: [sctp_ss_functions; 6] = {
    [
        {
            let mut init = sctp_ss_functions {
                sctp_ss_init: Some(
                    sctp_ss_default_init
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_clear: Some(
                    sctp_ss_default_clear
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_init_stream: Some(
                    sctp_ss_default_init_stream
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_out,
                        ) -> (),
                ),
                sctp_ss_add_to_stream: Some(
                    sctp_ss_default_add
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_is_empty: Some(
                    sctp_ss_default_is_empty
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
                sctp_ss_remove_from_stream: Some(
                    sctp_ss_default_remove
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_select_stream: Some(
                    sctp_ss_default_select
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> *mut sctp_stream_out,
                ),
                sctp_ss_scheduled: Some(
                    sctp_ss_default_scheduled
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_packet_done: Some(
                    sctp_ss_default_packet_done
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> (),
                ),
                sctp_ss_get_value: Some(
                    sctp_ss_default_get_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_set_value: Some(
                    sctp_ss_default_set_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_is_user_msgs_incomplete: Some(
                    sctp_ss_default_is_user_msgs_incomplete
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = sctp_ss_functions {
                sctp_ss_init: Some(
                    sctp_ss_default_init
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_clear: Some(
                    sctp_ss_default_clear
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_init_stream: Some(
                    sctp_ss_default_init_stream
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_out,
                        ) -> (),
                ),
                sctp_ss_add_to_stream: Some(
                    sctp_ss_rr_add
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_is_empty: Some(
                    sctp_ss_default_is_empty
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
                sctp_ss_remove_from_stream: Some(
                    sctp_ss_default_remove
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_select_stream: Some(
                    sctp_ss_default_select
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> *mut sctp_stream_out,
                ),
                sctp_ss_scheduled: Some(
                    sctp_ss_default_scheduled
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_packet_done: Some(
                    sctp_ss_default_packet_done
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> (),
                ),
                sctp_ss_get_value: Some(
                    sctp_ss_default_get_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_set_value: Some(
                    sctp_ss_default_set_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_is_user_msgs_incomplete: Some(
                    sctp_ss_default_is_user_msgs_incomplete
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = sctp_ss_functions {
                sctp_ss_init: Some(
                    sctp_ss_default_init
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_clear: Some(
                    sctp_ss_default_clear
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_init_stream: Some(
                    sctp_ss_default_init_stream
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_out,
                        ) -> (),
                ),
                sctp_ss_add_to_stream: Some(
                    sctp_ss_rr_add
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_is_empty: Some(
                    sctp_ss_default_is_empty
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
                sctp_ss_remove_from_stream: Some(
                    sctp_ss_default_remove
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_select_stream: Some(
                    sctp_ss_rrp_select
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> *mut sctp_stream_out,
                ),
                sctp_ss_scheduled: Some(
                    sctp_ss_default_scheduled
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_packet_done: Some(
                    sctp_ss_rrp_packet_done
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> (),
                ),
                sctp_ss_get_value: Some(
                    sctp_ss_default_get_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_set_value: Some(
                    sctp_ss_default_set_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_is_user_msgs_incomplete: Some(
                    sctp_ss_default_is_user_msgs_incomplete
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = sctp_ss_functions {
                sctp_ss_init: Some(
                    sctp_ss_default_init
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_clear: Some(
                    sctp_ss_prio_clear
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_init_stream: Some(
                    sctp_ss_prio_init_stream
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_out,
                        ) -> (),
                ),
                sctp_ss_add_to_stream: Some(
                    sctp_ss_prio_add
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_is_empty: Some(
                    sctp_ss_default_is_empty
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
                sctp_ss_remove_from_stream: Some(
                    sctp_ss_prio_remove
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_select_stream: Some(
                    sctp_ss_prio_select
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> *mut sctp_stream_out,
                ),
                sctp_ss_scheduled: Some(
                    sctp_ss_default_scheduled
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_packet_done: Some(
                    sctp_ss_default_packet_done
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> (),
                ),
                sctp_ss_get_value: Some(
                    sctp_ss_prio_get_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_set_value: Some(
                    sctp_ss_prio_set_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_is_user_msgs_incomplete: Some(
                    sctp_ss_default_is_user_msgs_incomplete
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = sctp_ss_functions {
                sctp_ss_init: Some(
                    sctp_ss_default_init
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_clear: Some(
                    sctp_ss_fb_clear
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_init_stream: Some(
                    sctp_ss_fb_init_stream
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_out,
                        ) -> (),
                ),
                sctp_ss_add_to_stream: Some(
                    sctp_ss_fb_add
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_is_empty: Some(
                    sctp_ss_default_is_empty
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
                sctp_ss_remove_from_stream: Some(
                    sctp_ss_fb_remove
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_select_stream: Some(
                    sctp_ss_fb_select
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> *mut sctp_stream_out,
                ),
                sctp_ss_scheduled: Some(
                    sctp_ss_fb_scheduled
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_packet_done: Some(
                    sctp_ss_default_packet_done
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> (),
                ),
                sctp_ss_get_value: Some(
                    sctp_ss_default_get_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_set_value: Some(
                    sctp_ss_default_set_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_is_user_msgs_incomplete: Some(
                    sctp_ss_default_is_user_msgs_incomplete
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
            };
            init
        },
        {
            let mut init = sctp_ss_functions {
                sctp_ss_init: Some(
                    sctp_ss_fcfs_init
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_clear: Some(
                    sctp_ss_fcfs_clear
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: libc::c_int,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_init_stream: Some(
                    sctp_ss_fcfs_init_stream
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_out,
                        ) -> (),
                ),
                sctp_ss_add_to_stream: Some(
                    sctp_ss_fcfs_add
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_is_empty: Some(
                    sctp_ss_fcfs_is_empty
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
                sctp_ss_remove_from_stream: Some(
                    sctp_ss_fcfs_remove
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut sctp_stream_queue_pending,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_select_stream: Some(
                    sctp_ss_fcfs_select
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> *mut sctp_stream_out,
                ),
                sctp_ss_scheduled: Some(
                    sctp_ss_default_scheduled
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: libc::c_int,
                        ) -> (),
                ),
                sctp_ss_packet_done: Some(
                    sctp_ss_default_packet_done
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_nets,
                            _: *mut sctp_association,
                        ) -> (),
                ),
                sctp_ss_get_value: Some(
                    sctp_ss_default_get_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: *mut uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_set_value: Some(
                    sctp_ss_default_set_value
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                            _: *mut sctp_stream_out,
                            _: uint16_t,
                        ) -> libc::c_int,
                ),
                sctp_ss_is_user_msgs_incomplete: Some(
                    sctp_ss_default_is_user_msgs_incomplete
                        as unsafe extern "C" fn(
                            _: *mut sctp_tcb,
                            _: *mut sctp_association,
                        ) -> libc::c_int,
                ),
            };
            init
        },
    ]
};
