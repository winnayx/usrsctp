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
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    /*__Userspace__ */
    #[no_mangle]
    fn uiomove(cp: *mut libc::c_void, n: libc::c_int, uio: *mut uio) -> libc::c_int;
    /* remote UDP encapsulation port */
    /* we choose the number to make a pcb a page */
    /*-
     * put an inpcb in front of it all, kind of a waste but we need to
     * for compatibility with all the other stuff.
     */
    /* Socket buffer lock protects read_queue and of course sb_cc */
    /* lists all endpoints */
    /* hash of all endpoints for model */
    /* count of local addresses bound, 0 if bound all */
    /* list of addrs in use by the EP, NULL if bound-all */
    /* used for source address selection rotation when we are subset bound */
    /* back pointer to our socket */
    /* Feature flags */
    /* INP state flag set */
    /* Mobility  Feature flags */
    /* SCTP ep data */
    /* head of the hash of all associations */
    /* head of the list of all associations */
    /*-
     * These three are here for the sosend_dgram
     * (pkt, pkt_last and control).
     * routine. However, I don't think anyone in
     * the current FreeBSD kernel calls this. So
     * they are candidates with sctp_sendm for
     * de-supporting.
     */
    /* back pointer to socket */
    /* back pointer to ep */
    /* next link in hash
     * table */
    /* list of all of the
     * TCB's */
    /* next link in asocid
     * hash table
     */
    /* vtag hash list */
    /* pointer locked by  socket
     * send buffer */
    /*-
     * freed_by_sorcv_sincelast is protected by the sockbuf_lock NOT the
     * tcb_lock. Its special in this way to help avoid extra mutex calls
     * in the reading of data.
     */
    /* remote port in network format */
    /* TODO where to put non-_KERNEL things for __Userspace__? */
    /* Attention Julian, this is the extern that
     * goes with the base info. sctp_pcb.c has
     * the real definition.
     */
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
pub type __off_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __caddr_t = *mut libc::c_char;
pub type off_t = __off_t;
pub type ssize_t = __ssize_t;
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
    pub c2rust_unnamed: C2RustUnnamed_883,
    pub c2rust_unnamed_0: C2RustUnnamed_881,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_881 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_882,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_882 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_883 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_884,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_884 {
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
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut libc::c_void,
    pub iov_len: size_t,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_885,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_885 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
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
 */
/* __Userspace__ version of <sys/socketvar.h> goes here.*/
/* #include <sys/selinfo.h> */
/*__Userspace__ alternative?*/
/* for struct selinfo */
/* #include <sys/_lock.h>  was 0 byte file */
/* #include <sys/_mutex.h> was 0 byte file */
/* #include <sys/_sx.h> */
/*__Userspace__ alternative?*/
/* SCTP notification */
pub type uio_rw = libc::c_uint;
pub const UIO_WRITE: uio_rw = 1;
pub const UIO_READ: uio_rw = 0;
/* Segment flag values. */
pub type uio_seg = libc::c_uint;
/* from system space */
/* from user data space */
pub const UIO_SYSSPACE: uio_seg = 1;
pub const UIO_USERSPACE: uio_seg = 0;
/* __Userspace__ Are these all the fields we need?
 * Removing struct thread *uio_td;    owner field
*/

#[repr(C)]
#[derive(Copy, Clone)]
pub struct uio {
    pub uio_iov: *mut iovec,
    pub uio_iovcnt: libc::c_int,
    pub uio_offset: off_t,
    pub uio_resid: ssize_t,
    pub uio_segflg: uio_seg,
    pub uio_rw: uio_rw,
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
    pub so_incomp: C2RustUnnamed_893,
    pub so_comp: C2RustUnnamed_892,
    pub so_list: C2RustUnnamed_891,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_890,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mbuf {
    pub m_hdr: m_hdr,
    pub M_dat: C2RustUnnamed_886,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_886 {
    pub MH: C2RustUnnamed_887,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_887 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_888,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_888 {
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
    pub m_tag_link: C2RustUnnamed_889,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_889 {
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
pub struct C2RustUnnamed_890 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_891 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_892 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_893 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_894,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_894 {
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
    pub inp_hash: C2RustUnnamed_902,
    pub inp_list: C2RustUnnamed_901,
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
    pub inp_depend4: C2RustUnnamed_898,
    pub inp_depend6: C2RustUnnamed_897,
    pub inp_portlist: C2RustUnnamed_896,
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
    pub phd_hash: C2RustUnnamed_895,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_895 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_896 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_897 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_898 {
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
    pub ie_dependfaddr: C2RustUnnamed_900,
    pub ie_dependladdr: C2RustUnnamed_899,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_899 {
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
pub union C2RustUnnamed_900 {
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
pub struct C2RustUnnamed_901 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_902 {
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
    pub tqe: C2RustUnnamed_903,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_903 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;
pub type sctp_rtentry_t = sctp_rtentry;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_conn {
    pub sconn_family: uint16_t,
    pub sconn_port: uint16_t,
    pub sconn_addr: *mut libc::c_void,
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
pub struct sctp_nets {
    pub sctp_next: C2RustUnnamed_909,
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
/* our selected src addr */

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
    pub next_ifa: C2RustUnnamed_908,
    pub next_bucket: C2RustUnnamed_907,
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
pub struct sctp_ifn {
    pub ifalist: sctp_ifalist,
    pub vrf: *mut sctp_vrf,
    pub next_ifn: C2RustUnnamed_905,
    pub next_bucket: C2RustUnnamed_904,
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
pub struct C2RustUnnamed_904 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_905 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_906,
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
pub struct C2RustUnnamed_906 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_907 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_908 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_909 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mb_args {
    pub flags: libc::c_int,
    pub type_0: libc::c_short,
}
pub type sctp_zone_t = size_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct clust_args {
    pub parent_mbuf: *mut mbuf,
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
pub struct sctpvtaghead {
    pub lh_first: *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tagblock {
    pub sctp_nxt_tagblock: C2RustUnnamed_910,
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
pub struct C2RustUnnamed_910 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpladdr {
    pub lh_first: *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_laddr {
    pub sctp_nxt_addr: C2RustUnnamed_911,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_911 {
    pub le_next: *mut sctp_laddr,
    pub le_prev: *mut *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctppcbhead {
    pub lh_first: *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_933,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_932,
    pub sctp_hash: C2RustUnnamed_931,
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
    pub sctp_tcbhash: C2RustUnnamed_930,
    pub sctp_tcblist: C2RustUnnamed_929,
    pub sctp_tcbasocidhash: C2RustUnnamed_928,
    pub sctp_asocs: C2RustUnnamed_927,
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
    pub next: C2RustUnnamed_912,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_912 {
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
    pub next: C2RustUnnamed_916,
    pub next_instrm: C2RustUnnamed_915,
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
    pub rec: C2RustUnnamed_914,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_913,
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
pub struct C2RustUnnamed_913 {
    pub tqe_next: *mut sctp_tmit_chunk,
    pub tqe_prev: *mut *mut sctp_tmit_chunk,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_914 {
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
pub struct C2RustUnnamed_915 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_916 {
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
    pub next_spoke: C2RustUnnamed_917,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_917 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_918,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_918 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_919,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_919 {
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
    pub next: C2RustUnnamed_921,
    pub ss_next: C2RustUnnamed_920,
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
pub struct C2RustUnnamed_920 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_921 {
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
    pub next_resp: C2RustUnnamed_922,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_922 {
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
    pub next: C2RustUnnamed_923,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_923 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_924,
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
pub struct C2RustUnnamed_924 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_925,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_925 {
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
/* save the ifa for add/del ip */
/* has this been sent yet? */
/* not to be used in lookup */
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addrhead {
    pub tqh_first: *mut sctp_asconf_addr,
    pub tqh_last: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_926,
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
/* IPV4 address */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_ipv6addr_param {
    pub ph: sctp_paramhdr,
    pub addr: [uint8_t; 16],
}
/* draft-ietf-tsvwg-addip-sctp */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_paramhdr {
    pub ph: sctp_paramhdr,
    pub correlation_id: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_926 {
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
pub struct C2RustUnnamed_927 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_928 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_929 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_930 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
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
/* back pointer to parent ifn */
/* pointer to ifa, needed for flag
 * update for that we MUST lock
 * appropriate locks. This is for V6.
 */
/* number of folks referring to this */
/* vrf_id of this addr (for deleting) */
/* next in list */
/* Used during asconf and adding
 * if no-zero src-addr selection will
 * not consider this address.
 */
/* time when this address was created */
/* the seconds from boot to expire */
/* the vtag that can not be reused */
/* the local port used in vtag */
/* the remote port used in vtag */
/*-
 * The TCP model represents a substantial overhead in that we get an
 * additional hash table to keep explicit connections in. The
 * listening TCP endpoint will exist in the usual ephash above and
 * accept only INIT's. It will be incapable of sending off an INIT.
 * When a dg arrives we must look in the normal ephash. If we find a
 * TCP endpoint that will tell us to go to the specific endpoint
 * hash and re-hash to find the right assoc/socket. If we find a UDP
 * model socket we then must complete the lookup. If this fails,
 * i.e. no association can be found then we must continue to see if
 * a sctp_peeloff()'d socket is in the tcpephash (a spun off socket
 * acts like a TCP model connected socket).
 */
/* ep zone info */
/* assoc/tcb zone info */
/* local addrlist zone info */
/* remote addrlist zone info */
/* chunk structure list for output */
/* socket queue zone info */
/* socket queue zone info */
/* Number of vrfs */
/* Number of ifns */
/* Number of ifas */
/* system wide number of free chunks hanging around */
/* address work queue handling */
/* All static structures that
 * anchor the system must be here.
 */
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
pub struct C2RustUnnamed_931 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_932 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_933 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrflist {
    pub lh_first: *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mbstat {
    pub m_mbufs: u_long,
    pub m_mclusts: u_long,
    pub m_drain: u_long,
    pub m_mcfail: u_long,
    pub m_mpfail: u_long,
    pub m_msize: u_long,
    pub m_mclbytes: u_long,
    pub m_minclsize: u_long,
    pub m_mlen: u_long,
    pub m_mhlen: u_long,
    pub m_numtypes: libc::c_short,
    pub sf_iocnt: u_long,
    pub sf_allocfail: u_long,
    pub sf_allocwait: u_long,
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
/*
 *  __Userspace__ version of /usr/src/sys/kern/kern_mbuf.c
 *  We are initializing two zones for Mbufs and Clusters.
 *
 */
/* #include <sys/param.h> This defines MSIZE 256 */
#[no_mangle]
pub static mut mbstat: mbstat = mbstat {
    m_mbufs: 0,
    m_mclusts: 0,
    m_drain: 0,
    m_mcfail: 0,
    m_mpfail: 0,
    m_msize: 0,
    m_mclbytes: 0,
    m_minclsize: 0,
    m_mlen: 0,
    m_mhlen: 0,
    m_numtypes: 0,
    sf_iocnt: 0,
    sf_allocfail: 0,
    sf_allocwait: 0,
};
/* int: max length of network header (see sys/sysclt.h)*/
#[no_mangle]
pub static mut max_linkhdr: libc::c_int = 4i32;
#[no_mangle]
pub static mut max_protohdr: libc::c_int = 5i32;
/* Size of largest protocol layer header. */
/*
 * Zones from which we allocate.
 */
#[no_mangle]
pub static mut zone_mbuf: sctp_zone_t = 0;
#[no_mangle]
pub static mut zone_clust: sctp_zone_t = 0;
#[no_mangle]
pub static mut zone_ext_refcnt: sctp_zone_t = 0;
/* __Userspace__ clust_mb_args will be passed as callback data to mb_ctor_clust
 * and mb_dtor_clust.
 * Note: I had to use struct clust_args as an encapsulation for an mbuf pointer.
 * struct mbuf * clust_mb_args; does not work.
 */
#[no_mangle]
pub static mut clust_mb_args: clust_args = clust_args {
    parent_mbuf: 0 as *mut mbuf,
};
/* **************** Functions taken from user_mbuf.h *************/
unsafe extern "C" fn mbuf_constructor_dup(
    mut m: *mut mbuf,
    mut pkthdr: libc::c_int,
    mut type_0: libc::c_short,
) -> libc::c_int {
    let mut flags = pkthdr;
    if type_0 as libc::c_int == 255i32 {
        return 0i32;
    }
    (*m).m_hdr.mh_next = 0 as *mut mbuf;
    (*m).m_hdr.mh_nextpkt = 0 as *mut mbuf;
    (*m).m_hdr.mh_len = 0i32;
    (*m).m_hdr.mh_flags = flags;
    (*m).m_hdr.mh_type = type_0;
    if flags & 0x2i32 != 0 {
        (*m).m_hdr.mh_data = (*m).M_dat.MH.MH_dat.MH_databuf.as_mut_ptr();
        (*m).M_dat.MH.MH_pkthdr.rcvif = 0 as *mut ifnet;
        (*m).M_dat.MH.MH_pkthdr.len = 0i32;
        (*m).M_dat.MH.MH_pkthdr.header = 0 as *mut libc::c_void;
        (*m).M_dat.MH.MH_pkthdr.csum_flags = 0i32;
        (*m).M_dat.MH.MH_pkthdr.csum_data = 0i32;
        (*m).M_dat.MH.MH_pkthdr.tso_segsz = 0u16;
        (*m).M_dat.MH.MH_pkthdr.ether_vtag = 0u16;
        (*m).M_dat.MH.MH_pkthdr.tags.slh_first = 0 as *mut m_tag
    } else {
        (*m).m_hdr.mh_data = (*m).M_dat.M_databuf.as_mut_ptr()
    }
    return 0i32;
}
/* __Userspace__ */
#[no_mangle]
pub unsafe extern "C" fn m_get(mut how: libc::c_int, mut type_0: libc::c_short) -> *mut mbuf {
    let mut mret = 0 as *mut mbuf;
    let mut mbuf_mb_args = mb_args {
        flags: 0,
        type_0: 0,
    };
    /* The following setter function is not yet being enclosed within
     * #if USING_MBUF_CONSTRUCTOR - #endif, until I have thoroughly tested
     * mb_dtor_mbuf. See comment there
     */
    mbuf_mb_args.flags = 0i32;
    mbuf_mb_args.type_0 = type_0;
    /* Mbuf master zone, zone_mbuf, has already been
     * created in mbuf_initialize() */
    mret = malloc(zone_mbuf) as *mut mbuf;
    mb_ctor_mbuf(
        mret as *mut libc::c_void,
        &mut mbuf_mb_args as *mut mb_args as *mut libc::c_void,
        0i32,
    );
    /*mret =  ((struct mbuf *)umem_cache_alloc(zone_mbuf, UMEM_DEFAULT));*/
    /* There are cases when an object available in the current CPU's
     * loaded magazine and in those cases the object's constructor is not applied.
     * If that is the case, then we are duplicating constructor initialization here,
     * so that the mbuf is properly constructed before returning it.
     */
    if !mret.is_null() {
        mbuf_constructor_dup(mret, 0i32, type_0);
    }
    return mret;
}
/* __Userspace__ */
#[no_mangle]
pub unsafe extern "C" fn m_gethdr(mut how: libc::c_int, mut type_0: libc::c_short) -> *mut mbuf {
    let mut mret = 0 as *mut mbuf;
    let mut mbuf_mb_args = mb_args {
        flags: 0,
        type_0: 0,
    };
    /* The following setter function is not yet being enclosed within
     * #if USING_MBUF_CONSTRUCTOR - #endif, until I have thoroughly tested
     * mb_dtor_mbuf. See comment there
     */
    mbuf_mb_args.flags = 0x2i32;
    mbuf_mb_args.type_0 = type_0;
    mret = malloc(zone_mbuf) as *mut mbuf;
    mb_ctor_mbuf(
        mret as *mut libc::c_void,
        &mut mbuf_mb_args as *mut mb_args as *mut libc::c_void,
        0i32,
    );
    /*mret = ((struct mbuf *)umem_cache_alloc(zone_mbuf, UMEM_DEFAULT));*/
    /* There are cases when an object available in the current CPU's
     * loaded magazine and in those cases the object's constructor is not applied.
     * If that is the case, then we are duplicating constructor initialization here,
     * so that the mbuf is properly constructed before returning it.
     */
    if !mret.is_null() {
        mbuf_constructor_dup(mret, 0x2i32, type_0);
    }
    return mret;
}
/* __Userspace__ */
#[no_mangle]
pub unsafe extern "C" fn m_free(mut m: *mut mbuf) -> *mut mbuf {
    let mut n = (*m).m_hdr.mh_next;
    if (*m).m_hdr.mh_flags & 0x1i32 != 0 {
        mb_free_ext(m);
    } else if (*m).m_hdr.mh_flags & 0x40000i32 == 0i32 {
        mb_dtor_mbuf(m as *mut libc::c_void, 0 as *mut libc::c_void);
        free(m as *mut libc::c_void);
    }
    /*umem_cache_free(zone_mbuf, m);*/
    return n;
}
unsafe extern "C" fn clust_constructor_dup(mut m_clust: caddr_t, mut m: *mut mbuf) {
    let mut refcnt = 0 as *mut u_int;
    let mut type_0 = 0;
    let mut size = 0;
    if m.is_null() {
        return;
    }
    /* Assigning cluster of MCLBYTES. TODO: Add jumbo frame functionality */
    type_0 = 1i32;
    size = 2048i32;
    refcnt = malloc(zone_ext_refcnt) as *mut u_int;
    /*refcnt = (u_int *)umem_cache_alloc(zone_ext_refcnt, UMEM_DEFAULT);*/
    *refcnt = 1u32;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_buf = m_clust;
    (*m).m_hdr.mh_data = (*m).M_dat.MH.MH_dat.MH_ext.ext_buf;
    (*m).m_hdr.mh_flags |= 0x1i32;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_free = None;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_args = 0 as *mut libc::c_void;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_size = size as u_int;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_type = type_0;
    (*m).M_dat.MH.MH_dat.MH_ext.ref_cnt = refcnt;
}
/* __Userspace__ */
#[no_mangle]
pub unsafe extern "C" fn m_clget(mut m: *mut mbuf, mut how: libc::c_int) {
    let mut mclust_ret = 0 as *mut libc::c_char;
    let mut clust_mb_args_l = clust_args {
        parent_mbuf: 0 as *mut mbuf,
    };
    if (*m).m_hdr.mh_flags & 0x1i32 != 0 {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%s: %p mbuf already has cluster\n\x00" as *const u8 as *const libc::c_char,
                    (*::std::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"m_clget\x00"))
                        .as_ptr(),
                    m as *mut libc::c_void,
                );
            }
        }
    }
    (*m).M_dat.MH.MH_dat.MH_ext.ext_buf = 0 as *mut libc::c_char;
    clust_mb_args_l.parent_mbuf = m;
    mclust_ret = malloc(zone_clust) as *mut libc::c_char;
    mb_ctor_clust(
        mclust_ret as *mut libc::c_void,
        &mut clust_mb_args_l as *mut clust_args as *mut libc::c_void,
        0i32,
    );
    /*mclust_ret = umem_cache_alloc(zone_clust, UMEM_DEFAULT);*/
    /*
    On a cluster allocation failure, call umem_reap() and retry.
    */
    if mclust_ret.is_null() {
        /*mclust_ret = umem_cache_alloc(zone_clust, UMEM_DEFAULT);*/
        if mclust_ret.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x80000000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Memory allocation failure in %s\n\x00" as *const u8
                            as *const libc::c_char,
                        (*::std::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"m_clget\x00"))
                            .as_ptr(),
                    );
                }
            }
        }
    }
    clust_constructor_dup(mclust_ret, m);
}
#[no_mangle]
pub unsafe extern "C" fn m_getm2(
    mut m: *mut mbuf,
    mut len: libc::c_int,
    mut how: libc::c_int,
    mut type_0: libc::c_short,
    mut flags: libc::c_int,
    mut allonebuf: libc::c_int,
) -> *mut mbuf {
    let mut nm = 0 as *mut mbuf;
    let mut mtail = 0 as *mut mbuf;
    let mut mbuf_threshold = 0;
    let mut space_needed = len;
    /* Validate flags. */
    flags &= 0x2i32 | 0x4i32;
    /* Packet header mbuf must be first in chain. */
    if flags & 0x2i32 != 0 && !m.is_null() {
        flags &= !(0x2i32)
    }
    if allonebuf == 0i32 {
        mbuf_threshold = system_base_info.sctpsysctl.sctp_mbuf_threshold_count as libc::c_int
    } else {
        mbuf_threshold = 1i32
    }
    /* Loop and append maximum sized mbufs to the chain tail. */
    while len > 0i32 {
        let mut mb = 0 as *mut mbuf;
        let mut size = 0i32;
        if allonebuf == 0 && len >= 2048i32
            || len
                > (mbuf_threshold - 1i32)
                    * (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                        as libc::c_int
                    + ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                        as libc::c_int as libc::c_ulong)
                        .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                        as libc::c_int
        {
            mb = m_gethdr(how, type_0);
            m_clget(mb, how);
            size = 2048i32
        /* SCTP_BUF_LEN(mb) = MCLBYTES; */
        } else if flags & 0x2i32 != 0 {
            mb = m_gethdr(how, type_0);
            if len
                < ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                    as libc::c_int
            {
                size = len
            } else {
                size = ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                    as libc::c_int
            }
        } else {
            mb = m_get(how, type_0);
            if len
                < (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int
            {
                size = len
            } else {
                size = (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int
            }
        }
        /* Only valid on the first mbuf. */
        if mb.is_null() {
            if !nm.is_null() {
                m_freem(nm);
            }
            return 0 as *mut mbuf;
        }
        if allonebuf != 0i32 && size < space_needed {
            m_freem(mb);
            return 0 as *mut mbuf;
        }
        len -= size;
        if !mtail.is_null() {
            (*mtail).m_hdr.mh_next = mb
        } else {
            nm = mb
        }
        mtail = mb;
        flags &= !(0x2i32)
    }
    if flags & 0x4i32 != 0 {
        (*mtail).m_hdr.mh_flags |= 0x4i32
        /* Fail the whole operation if one mbuf can't be allocated. */
        /* Book keeping. */
        /* Only valid on the last mbuf. */
    }
    /* If mbuf was supplied, append new chain to the end of it. */
    if !m.is_null() {
        mtail = m;
        while !(*mtail).m_hdr.mh_next.is_null() {
            mtail = (*mtail).m_hdr.mh_next
        }
        (*mtail).m_hdr.mh_next = nm;
        (*mtail).m_hdr.mh_flags &= !(0x4i32)
    } else {
        m = nm
    }
    return m;
}
/*
 * Copy the contents of uio into a properly sized mbuf chain.
 */
#[no_mangle]
pub unsafe extern "C" fn m_uiotombuf(
    mut uio: *mut uio,
    mut how: libc::c_int,
    mut len: libc::c_int,
    mut align: libc::c_int,
    mut flags: libc::c_int,
) -> *mut mbuf {
    let mut m = 0 as *mut mbuf;
    let mut mb = 0 as *mut mbuf;
    let mut total = 0;
    /*
     * len can be zero or an arbitrary large value bound by
     * the total data supplied by the uio.
     */
    if len > 0i32 {
        total = if (*uio).uio_resid > len as libc::c_long {
            len as libc::c_long
        } else {
            (*uio).uio_resid
        }
    } else {
        total = (*uio).uio_resid
    }
    /*
     * The smallest unit returned by m_getm2() is a single mbuf
     * with pkthdr.  We can't align past it.
     */
    if align
        >= ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_int
            as libc::c_ulong)
            .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
            as libc::c_int
    {
        return 0 as *mut mbuf;
    }
    /*
     * Give us the full allocation or nothing.
     * If len is zero return the smallest empty mbuf.
     */
    m = m_getm2(
        0 as *mut mbuf,
        if total + align as libc::c_long > 1i64 {
            (total) + align as libc::c_long
        } else {
            1i64
        } as libc::c_int,
        how,
        1i16,
        flags,
        0i32,
    );
    if m.is_null() {
        return 0 as *mut mbuf;
    }
    (*m).m_hdr.mh_data = (*m).m_hdr.mh_data.offset(align as isize);
    /* Fill all mbufs with uio data and update header information. */
    mb = m;
    while !mb.is_null() {
        let mut error = 0;
        let mut length = 0;
        let mut progress = 0i32;
        length = if (if (*mb).m_hdr.mh_flags & 0x1i32 != 0 {
            (if (*mb).m_hdr.mh_flags & 0x8i32 == 0
                && ((*mb).m_hdr.mh_flags & 0x1i32 == 0
                    || *(*mb).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32)
            {
                (*mb)
                    .M_dat
                    .MH
                    .MH_dat
                    .MH_ext
                    .ext_buf
                    .offset((*mb).M_dat.MH.MH_dat.MH_ext.ext_size as isize)
                    .wrapping_offset_from((*mb).m_hdr.mh_data.offset((*mb).m_hdr.mh_len as isize))
                    as libc::c_long
            } else {
                0i64
            })
        } else {
            (&mut *(*mb).M_dat.M_databuf.as_mut_ptr().offset(
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_char)
                .wrapping_offset_from((*mb).m_hdr.mh_data.offset((*mb).m_hdr.mh_len as isize))
                as libc::c_long
        }) > total - progress as libc::c_long
        {
            (total) - progress as libc::c_long
        } else if (*mb).m_hdr.mh_flags & 0x1i32 != 0 {
            if (*mb).m_hdr.mh_flags & 0x8i32 == 0
                && ((*mb).m_hdr.mh_flags & 0x1i32 == 0
                    || *(*mb).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32)
            {
                (*mb)
                    .M_dat
                    .MH
                    .MH_dat
                    .MH_ext
                    .ext_buf
                    .offset((*mb).M_dat.MH.MH_dat.MH_ext.ext_size as isize)
                    .wrapping_offset_from((*mb).m_hdr.mh_data.offset((*mb).m_hdr.mh_len as isize))
                    as libc::c_long
            } else {
                0i64
            }
        } else {
            (&mut *(*mb).M_dat.M_databuf.as_mut_ptr().offset(
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_char)
                .wrapping_offset_from((*mb).m_hdr.mh_data.offset((*mb).m_hdr.mh_len as isize))
                as libc::c_long
        } as libc::c_int;
        error = uiomove((*mb).m_hdr.mh_data as *mut libc::c_void, length, uio);
        if error != 0 {
            m_freem(m);
            return 0 as *mut mbuf;
        }
        (*mb).m_hdr.mh_len = length;
        progress += length;
        if flags & 0x2i32 != 0 {
            (*m).M_dat.MH.MH_pkthdr.len += length
        }
        mb = (*mb).m_hdr.mh_next
    }
    return m;
}
#[no_mangle]
pub unsafe extern "C" fn m_length(mut m0: *mut mbuf, mut last: *mut *mut mbuf) -> u_int {
    let mut m = 0 as *mut mbuf;
    let mut len = 0;
    len = 0u32;
    m = m0;
    while !m.is_null() {
        len = (len).wrapping_add((*m).m_hdr.mh_len as libc::c_uint);
        if (*m).m_hdr.mh_next.is_null() {
            break;
        }
        m = (*m).m_hdr.mh_next
    }
    if !last.is_null() {
        *last = m
    }
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn m_last(mut m: *mut mbuf) -> *mut mbuf {
    while !(*m).m_hdr.mh_next.is_null() {
        m = (*m).m_hdr.mh_next
    }
    return m;
}
/*
 * Unlink a tag from the list of tags associated with an mbuf.
 */
#[inline]
unsafe extern "C" fn m_tag_unlink(mut m: *mut mbuf, mut t: *mut m_tag) {
    if (*m).M_dat.MH.MH_pkthdr.tags.slh_first == t {
        (*m).M_dat.MH.MH_pkthdr.tags.slh_first = (*(*m).M_dat.MH.MH_pkthdr.tags.slh_first)
            .m_tag_link
            .sle_next
    } else {
        let mut curelm = (*m).M_dat.MH.MH_pkthdr.tags.slh_first;
        while (*curelm).m_tag_link.sle_next != t {
            curelm = (*curelm).m_tag_link.sle_next
        }
        (*curelm).m_tag_link.sle_next = (*(*curelm).m_tag_link.sle_next).m_tag_link.sle_next
    };
}
/*
 * Reclaim resources associated with a tag.
 */
#[inline]
unsafe extern "C" fn m_tag_free(mut t: *mut m_tag) {
    Some((*t).m_tag_free.expect("non-null function pointer")).expect("non-null function pointer")(
        t,
    );
}
/*
 * Set up the contents of a tag.  Note that this does not fill in the free
 * method; the caller is expected to do that.
 *
 * XXX probably should be called m_tag_init, but that was already taken.
 */
#[inline]
unsafe extern "C" fn m_tag_setup(
    mut t: *mut m_tag,
    mut cookie: u_int32_t,
    mut type_0: libc::c_int,
    mut len: libc::c_int,
) {
    (*t).m_tag_id = type_0 as u_int16_t;
    (*t).m_tag_len = len as u_int16_t;
    (*t).m_tag_cookie = cookie;
}
/* *********** End functions from user_mbuf.h  ******************/
/* *********** End functions to substitute umem_cache_alloc and umem_cache_free **************/
#[no_mangle]
pub unsafe extern "C" fn mbuf_initialize(mut dummy: *mut libc::c_void) {
    /*
     * __Userspace__Configure UMA zones for Mbufs and Clusters.
     * (TODO: m_getcl() - using packet secondary zone).
     * There is no provision for trash_init and trash_fini in umem.
     *
     */
    /* zone_mbuf = umem_cache_create(MBUF_MEM_NAME, MSIZE, 0,
                mb_ctor_mbuf, mb_dtor_mbuf, NULL,
                &mbuf_mb_args,
                NULL, 0);
    zone_mbuf = umem_cache_create(MBUF_MEM_NAME, MSIZE, 0, NULL, NULL, NULL, NULL, NULL, 0);*/
    zone_mbuf = 256u64;
    /*zone_ext_refcnt = umem_cache_create(MBUF_EXTREFCNT_MEM_NAME, sizeof(u_int), 0,
    NULL, NULL, NULL,
    NULL,
    NULL, 0);*/
    zone_ext_refcnt = ::std::mem::size_of::<u_int>() as libc::c_ulong;
    /*zone_clust = umem_cache_create(MBUF_CLUSTER_MEM_NAME, MCLBYTES, 0,
                 mb_ctor_clust, mb_dtor_clust, NULL,
                 &clust_mb_args,
                 NULL, 0);
    zone_clust = umem_cache_create(MBUF_CLUSTER_MEM_NAME, MCLBYTES, 0, NULL, NULL, NULL, NULL, NULL,0);*/
    zone_clust = 2048u64;
    /* uma_prealloc() goes here... */
    /* __Userspace__ Add umem_reap here for low memory situation?
     *
     */
    /*
     * [Re]set counters and local statistics knobs.
     *
     */
    mbstat.m_mbufs = 0u64;
    mbstat.m_mclusts = 0u64;
    mbstat.m_drain = 0u64;
    mbstat.m_msize = 256u64;
    mbstat.m_mclbytes = 2048u64;
    mbstat.m_minclsize = (((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
        as libc::c_int as libc::c_ulong)
        .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
        as libc::c_int
        + 1i32) as u_long;
    mbstat.m_mlen = (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
        as libc::c_int as u_long;
    mbstat.m_mhlen = ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
        as libc::c_int as libc::c_ulong)
        .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
        as libc::c_int as u_long;
    mbstat.m_numtypes = 16i16;
    mbstat.m_mpfail = 0u64;
    mbstat.m_mcfail = mbstat.m_mpfail;
    mbstat.sf_iocnt = 0u64;
    mbstat.sf_allocfail = 0u64;
    mbstat.sf_allocwait = mbstat.sf_allocfail;
}
/* __Userspace__
 * Local prototypes.
 */
/*
 * __Userspace__
 *
 * Constructor for Mbuf master zone. We have a different constructor
 * for allocating the cluster.
 *
 * The 'arg' pointer points to a mb_args structure which
 * contains call-specific information required to support the
 * mbuf allocation API.  See user_mbuf.h.
 *
 * The flgs parameter below can be UMEM_DEFAULT or UMEM_NOFAIL depending on what
 * was passed when umem_cache_alloc was called.
 * TODO: Use UMEM_NOFAIL in umem_cache_alloc and also define a failure handler
 * and call umem_nofail_callback(my_failure_handler) in the stack initialization routines
 * The advantage of using UMEM_NOFAIL is that we don't have to check if umem_cache_alloc
 * was successful or not. The failure handler would take care of it, if we use the UMEM_NOFAIL
 * flag.
 *
 * NOTE Ref: http://docs.sun.com/app/docs/doc/819-2243/6n4i099p2?l=en&a=view&q=umem_zalloc)
 * The umem_nofail_callback() function sets the **process-wide** UMEM_NOFAIL callback.
 * It also mentions that umem_nofail_callback is Evolving.
 *
 */
unsafe extern "C" fn mb_ctor_mbuf(
    mut mem: *mut libc::c_void,
    mut arg: *mut libc::c_void,
    mut flgs: libc::c_int,
) -> libc::c_int {
    return 0i32;
}
/*
 * __Userspace__
 * The Mbuf master zone destructor.
 * This would be called in response to umem_cache_destroy
 * TODO: Recheck if this is what we want to do in this destructor.
 * (Note: the number of times mb_dtor_mbuf is called is equal to the
 * number of individual mbufs allocated from zone_mbuf.
 */
unsafe extern "C" fn mb_dtor_mbuf(mut mem: *mut libc::c_void, mut arg: *mut libc::c_void) {
    let mut m = 0 as *mut mbuf;
    m = mem as *mut mbuf;
    if (*m).m_hdr.mh_flags & 0x2i32 != 0i32 {
        m_tag_delete_chain(m, 0 as *mut m_tag);
    };
}
/* __Userspace__
 * The Cluster zone constructor.
 *
 * Here the 'arg' pointer points to the Mbuf which we
 * are configuring cluster storage for.  If 'arg' is
 * empty we allocate just the cluster without setting
 * the mbuf to it.  See mbuf.h.
 */
unsafe extern "C" fn mb_ctor_clust(
    mut mem: *mut libc::c_void,
    mut arg: *mut libc::c_void,
    mut flgs: libc::c_int,
) -> libc::c_int {
    return 0i32;
}
/* __Userspace__ */
unsafe extern "C" fn mb_dtor_clust(mut mem: *mut libc::c_void, mut arg: *mut libc::c_void) {
    /* mem is of type caddr_t.  In sys/types.h we have typedef char * caddr_t;  */
    /* mb_dtor_clust is called at time of umem_cache_destroy() (the number of times
     * mb_dtor_clust is called is equal to the number of individual mbufs allocated
     * from zone_clust. Similarly for mb_dtor_mbuf).
     * At this point the following:
     *  struct mbuf *m;
     *   m = (struct mbuf *)arg;
     *  assert (*(m->m_ext.ref_cnt) == 0); is not meaningful since  m->m_ext.ref_cnt = NULL;
     *  has been done in mb_free_ext().
     */
}
/* Unlink and free a packet tag. */
#[no_mangle]
pub unsafe extern "C" fn m_tag_delete(mut m: *mut mbuf, mut t: *mut m_tag) {
    m_tag_unlink(m, t);
    m_tag_free(t);
}
/* Unlink and free a packet tag chain, starting from given tag. */
#[no_mangle]
pub unsafe extern "C" fn m_tag_delete_chain(mut m: *mut mbuf, mut t: *mut m_tag) {
    let mut p = 0 as *mut m_tag;
    if !t.is_null() {
        p = t
    } else {
        p = (*m).M_dat.MH.MH_pkthdr.tags.slh_first
    }
    if p.is_null() {
        return;
    }
    loop {
        let mut q = 0 as *mut m_tag;
        q = (*p).m_tag_link.sle_next;
        if q.is_null() {
            break;
        }
        m_tag_delete(m, q);
    }
    m_tag_delete(m, p);
}
/*
 * Free an entire chain of mbufs and associated external buffers, if
 * applicable.
 */
#[no_mangle]
pub unsafe extern "C" fn m_freem(mut mb: *mut mbuf) {
    while !mb.is_null() {
        mb = m_free(mb)
    }
}
/*
 * __Userspace__
 * clean mbufs with M_EXT storage attached to them
 * if the reference count hits 1.
 */
#[no_mangle]
pub unsafe extern "C" fn mb_free_ext(mut m: *mut mbuf) {
    let mut skipmbuf = 0;
    /*
     * check if the header is embedded in the cluster
     */
    skipmbuf = (*m).m_hdr.mh_flags & 0x40000i32;
    /* Free the external attached storage if this
     * mbuf is the only reference to it.
     *__Userspace__ TODO: jumbo frames
     *
    	*/
    /* NOTE: We had the same code that SCTP_DECREMENT_AND_CHECK_REFCOUNT
             reduces to here before but the IPHONE malloc commit had changed
             this to compare to 0 instead of 1 (see next line).  Why?
            . .. this caused a huge memory leak in Linux.
    */
    if ::std::intrinsics::atomic_xadd((*m).M_dat.MH.MH_dat.MH_ext.ref_cnt, -(1i32) as u_int) == 1u32
    {
        if (*m).M_dat.MH.MH_dat.MH_ext.ext_type == 1i32 {
            mb_dtor_clust(
                (*m).M_dat.MH.MH_dat.MH_ext.ext_buf as *mut libc::c_void,
                &mut clust_mb_args as *mut clust_args as *mut libc::c_void,
            );
            free((*m).M_dat.MH.MH_dat.MH_ext.ext_buf as *mut libc::c_void);
            free((*m).M_dat.MH.MH_dat.MH_ext.ref_cnt as *mut libc::c_void);
            (*m).M_dat.MH.MH_dat.MH_ext.ref_cnt = 0 as *mut u_int
        }
    }
    if skipmbuf != 0 {
        return;
    }
    /* __Userspace__ Also freeing the storage for ref_cnt
     * Free this mbuf back to the mbuf zone with all m_ext
     * information purged.
     */
    (*m).M_dat.MH.MH_dat.MH_ext.ext_buf = 0 as caddr_t;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_free = None;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_args = 0 as *mut libc::c_void;
    (*m).M_dat.MH.MH_dat.MH_ext.ref_cnt = 0 as *mut u_int;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_size = 0u32;
    (*m).M_dat.MH.MH_dat.MH_ext.ext_type = 0i32;
    (*m).m_hdr.mh_flags &= !(0x1i32);
    mb_dtor_mbuf(m as *mut libc::c_void, 0 as *mut libc::c_void);
    free(m as *mut libc::c_void);
    /*umem_cache_free(zone_mbuf, m);*/
}
/*
 * "Move" mbuf pkthdr from "from" to "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 */
#[no_mangle]
pub unsafe extern "C" fn m_move_pkthdr(mut to: *mut mbuf, mut from: *mut mbuf) {
    (*to).m_hdr.mh_flags = (*from).m_hdr.mh_flags
        & (0x2i32
            | 0x4i32
            | 0x8i32
            | 0x10i32
            | 0x10i32
            | 0x20i32
            | 0x40i32
            | 0x80i32
            | 0x100i32
            | 0x200i32
            | 0x400i32
            | 0x800i32
            | 0x1000i32
            | 0x2000i32
            | 0x10000i32
            | 0x20000i32)
        | (*to).m_hdr.mh_flags & 0x1i32; /* especially tags */
    if (*to).m_hdr.mh_flags & 0x1i32 == 0i32 {
        (*to).m_hdr.mh_data = (*to).M_dat.MH.MH_dat.MH_databuf.as_mut_ptr()
    } /* purge tags from src */
    (*to).M_dat.MH.MH_pkthdr = (*from).M_dat.MH.MH_pkthdr;
    (*from).M_dat.MH.MH_pkthdr.tags.slh_first = 0 as *mut m_tag;
    (*from).m_hdr.mh_flags &= !(0x2i32);
}
/*
 * Rearange an mbuf chain so that len bytes are contiguous
 * and in the data area of an mbuf (so that mtod and dtom
 * will work for a structure of size len).  Returns the resulting
 * mbuf chain on success, frees it and returns null on failure.
 * If there is room, it will add up to max_protohdr-len extra bytes to the
 * contiguous region in an attempt to avoid being called next time.
 */
#[no_mangle]
pub unsafe extern "C" fn m_pullup(mut n: *mut mbuf, mut len: libc::c_int) -> *mut mbuf {
    let mut current_block: u64;
    let mut m = 0 as *mut mbuf;
    /*
     * If first mbuf has no cluster, and has room for len bytes
     * without shifting current data, pullup into it,
     * otherwise allocate a new mbuf to prepend to the chain.
     */
    if (*n).m_hdr.mh_flags & 0x1i32 == 0i32
        && (*n).m_hdr.mh_data.offset(len as isize)
            < &mut *(*n).M_dat.M_databuf.as_mut_ptr().offset(
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_char
        && !(*n).m_hdr.mh_next.is_null()
    {
        if (*n).m_hdr.mh_len >= len {
            return n;
        } /* XXX: No consistency. */
        m = n; /* TODO: include code for copying the header */
        n = (*n).m_hdr.mh_next; /* ENOBUFS */
        len -= (*m).m_hdr.mh_len;
        current_block = 3512920355445576850;
    } else if len
        > ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_int
            as libc::c_ulong)
            .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong) as libc::c_int
    {
        current_block = 17341963557469842190;
    } else {
        m = m_get(0x1i32, (*n).m_hdr.mh_type);
        if m.is_null() {
            current_block = 17341963557469842190;
        } else {
            (*m).m_hdr.mh_len = 0i32;
            if (*n).m_hdr.mh_flags & 0x2i32 != 0 {
                m_move_pkthdr(m, n);
            }
            current_block = 3512920355445576850;
        }
    }
    match current_block {
        3512920355445576850 => {
            let mut space = 0;
            space = (&mut *(*m).M_dat.M_databuf.as_mut_ptr().offset(
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_char)
                .wrapping_offset_from((*m).m_hdr.mh_data.offset((*m).m_hdr.mh_len as isize))
                as libc::c_int;
            loop {
                let mut count = 0;
                count = if (if (if len > max_protohdr {
                    len
                } else {
                    max_protohdr
                }) > space
                {
                    space
                } else {
                    (if len > max_protohdr {
                        len
                    } else {
                        max_protohdr
                    })
                }) > (*n).m_hdr.mh_len
                {
                    (*n).m_hdr.mh_len
                } else if (if len > max_protohdr {
                    len
                } else {
                    max_protohdr
                }) > space
                {
                    space
                } else if len > max_protohdr {
                    len
                } else {
                    max_protohdr
                };
                memcpy(
                    (*m).m_hdr.mh_data.offset((*m).m_hdr.mh_len as isize) as *mut libc::c_void,
                    (*n).m_hdr.mh_data as *const libc::c_void,
                    count as u_int as libc::c_ulong,
                );
                len -= count;
                (*m).m_hdr.mh_len += count;
                (*n).m_hdr.mh_len -= count;
                space -= count;
                if (*n).m_hdr.mh_len != 0 {
                    (*n).m_hdr.mh_data = (*n).m_hdr.mh_data.offset(count as isize)
                } else {
                    n = m_free(n)
                }
                if !(len > 0i32 && !n.is_null()) {
                    break;
                }
            }
            if len > 0i32 {
                m_free(m);
            } else {
                (*m).m_hdr.mh_next = n;
                return m;
            }
        }
        _ => {}
    }
    m_freem(n);
    mbstat.m_mpfail = mbstat.m_mpfail.wrapping_add(1);
    return 0 as *mut mbuf;
}
unsafe extern "C" fn m_dup1(
    mut m: *mut mbuf,
    mut off: libc::c_int,
    mut len: libc::c_int,
    mut wait: libc::c_int,
) -> *mut mbuf {
    let mut n = 0 as *mut mbuf;
    let mut copyhdr = 0;
    if len > 2048i32 {
        return 0 as *mut mbuf;
    }
    if off == 0i32 && (*m).m_hdr.mh_flags & 0x2i32 != 0i32 {
        copyhdr = 1i32
    } else {
        copyhdr = 0i32
    }
    if len
        >= ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_int
            as libc::c_ulong)
            .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
            as libc::c_int
            + 1i32
    {
        if copyhdr == 1i32 {
            m_clget(n, wait);
            m_dup_pkthdr(n, m, wait);
        } else {
            m_clget(n, wait);
        }
    } else if copyhdr == 1i32 {
        n = m_gethdr(wait, (*m).m_hdr.mh_type)
    } else {
        n = m_get(wait, (*m).m_hdr.mh_type)
    }
    if n.is_null() {
        return 0 as *mut mbuf;
    }
    if copyhdr != 0 && m_dup_pkthdr(n, m, wait) == 0 {
        m_free(n);
        return 0 as *mut mbuf;
    }
    m_copydata(m, off, len, (*n).m_hdr.mh_data);
    (*n).m_hdr.mh_len = len;
    return n;
}
/* Taken from sys/kern/uipc_mbuf2.c */
#[no_mangle]
pub unsafe extern "C" fn m_pulldown(
    mut m: *mut mbuf,
    mut off: libc::c_int,
    mut len: libc::c_int,
    mut offp: *mut libc::c_int,
) -> *mut mbuf {
    let mut n = 0 as *mut mbuf;
    let mut writable = 0;
    /* check invalid arguments. */
    if len > 2048i32 {
        m_freem(m);
        return 0 as *mut mbuf;
        /* impossible */
    }
    n = m;
    while !n.is_null() && off > 0i32 {
        if (*n).m_hdr.mh_len > off {
            break;
        }
        off -= (*n).m_hdr.mh_len;
        n = (*n).m_hdr.mh_next
    }
    /* be sure to point non-empty mbuf */
    while !n.is_null() && (*n).m_hdr.mh_len == 0i32 {
        n = (*n).m_hdr.mh_next
    }
    if n.is_null() {
        m_freem(m);
        return 0 as *mut mbuf;
        /* mbuf chain too short */
    }
    writable = 0i32;
    if (*n).m_hdr.mh_flags & 0x1i32 == 0i32
        || (*n).M_dat.MH.MH_dat.MH_ext.ext_type == 1i32
            && ((*n).m_hdr.mh_flags & 0x8i32 == 0
                && ((*n).m_hdr.mh_flags & 0x1i32 == 0
                    || *(*n).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32))
    {
        writable = 1i32
    }
    /*
     * the target data is on <n, off>.
     * if we got enough data on the mbuf "n", we're done.
     */
    if !((off == 0i32 || !offp.is_null()) && len <= (*n).m_hdr.mh_len - off && writable != 0) {
        let mut o = 0 as *mut mbuf;
        if len <= (*n).m_hdr.mh_len - off {
            o = m_dup1(n, off, (*n).m_hdr.mh_len - off, 0x1i32);
            if o.is_null() {
                m_freem(m);
                return 0 as *mut mbuf;
                /* ENOBUFS */
            }
            (*n).m_hdr.mh_len = off;
            (*o).m_hdr.mh_next = (*n).m_hdr.mh_next;
            (*n).m_hdr.mh_next = o;
            n = (*n).m_hdr.mh_next;
            off = 0i32
        } else {
            let mut hlen = 0;
            let mut tlen = 0;
            let mut olen = 0;
            hlen = (*n).m_hdr.mh_len - off;
            tlen = len - hlen;
            /*
             * ensure that we have enough trailing data on mbuf chain.
             * if not, we can do nothing about the chain.
             */
            olen = 0i32;
            o = (*n).m_hdr.mh_next;
            while !o.is_null() {
                olen += (*o).m_hdr.mh_len;
                o = (*o).m_hdr.mh_next
            }
            if hlen + olen < len {
                m_freem(m);
                return 0 as *mut mbuf;
                /* mbuf chain too short */
            }
            /*
             * easy cases first.
             * we need to use m_copydata() to get data from <n->m_next, 0>.
             */
            if (off == 0i32 || !offp.is_null())
                && (if (*n).m_hdr.mh_flags & 0x1i32 != 0 {
                    (if (*n).m_hdr.mh_flags & 0x8i32 == 0
                        && ((*n).m_hdr.mh_flags & 0x1i32 == 0
                            || *(*n).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32)
                    {
                        (*n).M_dat
                            .MH
                            .MH_dat
                            .MH_ext
                            .ext_buf
                            .offset((*n).M_dat.MH.MH_dat.MH_ext.ext_size as isize)
                            .wrapping_offset_from(
                                (*n).m_hdr.mh_data.offset((*n).m_hdr.mh_len as isize),
                            ) as libc::c_long
                    } else {
                        0i64
                    })
                } else {
                    (&mut *(*n).M_dat.M_databuf.as_mut_ptr().offset(
                        (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                            as libc::c_int as isize,
                    ) as *mut libc::c_char)
                        .wrapping_offset_from((*n).m_hdr.mh_data.offset((*n).m_hdr.mh_len as isize))
                        as libc::c_long
                }) >= tlen as libc::c_long
                && writable != 0
            {
                m_copydata(
                    (*n).m_hdr.mh_next,
                    0i32,
                    tlen,
                    (*n).m_hdr.mh_data.offset((*n).m_hdr.mh_len as isize),
                );
                (*n).m_hdr.mh_len += tlen;
                m_adj((*n).m_hdr.mh_next, tlen);
            } else if (off == 0i32 || !offp.is_null())
                && (if (*(*n).m_hdr.mh_next).m_hdr.mh_flags & 0x1i32 != 0 {
                    (if (*(*n).m_hdr.mh_next).m_hdr.mh_flags & 0x8i32 == 0
                        && ((*(*n).m_hdr.mh_next).m_hdr.mh_flags & 0x1i32 == 0
                            || *(*(*n).m_hdr.mh_next).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32)
                    {
                        (*(*n).m_hdr.mh_next).m_hdr.mh_data.wrapping_offset_from(
                            (*(*n).m_hdr.mh_next).M_dat.MH.MH_dat.MH_ext.ext_buf,
                        ) as libc::c_long
                    } else {
                        0i64
                    })
                } else {
                    (if (*(*n).m_hdr.mh_next).m_hdr.mh_flags & 0x2i32 != 0 {
                        (*(*n).m_hdr.mh_next).m_hdr.mh_data.wrapping_offset_from(
                            (*(*n).m_hdr.mh_next)
                                .M_dat
                                .MH
                                .MH_dat
                                .MH_databuf
                                .as_mut_ptr(),
                        ) as libc::c_long
                    } else {
                        (*(*n).m_hdr.mh_next).m_hdr.mh_data.wrapping_offset_from(
                            (*(*n).m_hdr.mh_next).M_dat.M_databuf.as_mut_ptr(),
                        ) as libc::c_long
                    })
                }) >= hlen as libc::c_long
                && writable != 0
            {
                (*(*n).m_hdr.mh_next).m_hdr.mh_data =
                    (*(*n).m_hdr.mh_next).m_hdr.mh_data.offset(-(hlen as isize));
                (*(*n).m_hdr.mh_next).m_hdr.mh_len += hlen;
                memcpy(
                    (*(*n).m_hdr.mh_next).m_hdr.mh_data as *mut libc::c_void,
                    (*n).m_hdr.mh_data.offset(off as isize) as *const libc::c_void,
                    hlen as libc::c_ulong,
                );
                (*n).m_hdr.mh_len -= hlen;
                n = (*n).m_hdr.mh_next;
                off = 0i32
            } else {
                /*
                 * now, we need to do the hard way.  don't m_copy as there's no room
                 * on both end.
                 */
                if len
                    > (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                        as libc::c_int
                {
                    m_clget(o, 0x1i32);
                } else {
                    /* o = m_getcl(M_NOWAIT, m->m_type, 0);*/
                    o = m_get(0x1i32, (*m).m_hdr.mh_type)
                }
                if o.is_null() {
                    m_freem(m);
                    return 0 as *mut mbuf;
                    /* ENOBUFS */
                }
                /* get hlen from <n, off> into <o, 0> */
                (*o).m_hdr.mh_len = hlen;
                memcpy(
                    (*o).m_hdr.mh_data as *mut libc::c_void,
                    (*n).m_hdr.mh_data.offset(off as isize) as *const libc::c_void,
                    hlen as libc::c_ulong,
                );
                (*n).m_hdr.mh_len -= hlen;
                /* get tlen from <n->m_next, 0> into <o, hlen> */
                m_copydata(
                    (*n).m_hdr.mh_next,
                    0i32,
                    tlen,
                    (*o).m_hdr.mh_data.offset((*o).m_hdr.mh_len as isize),
                );
                (*o).m_hdr.mh_len += tlen;
                m_adj((*n).m_hdr.mh_next, tlen);
                (*o).m_hdr.mh_next = (*n).m_hdr.mh_next;
                (*n).m_hdr.mh_next = o;
                n = o;
                off = 0i32
            }
        }
    }
    if !offp.is_null() {
        *offp = off
    }
    return n;
}
/*
 * Attach the the cluster from *m to *n, set up m_ext in *n
 * and bump the refcount of the cluster.
 */
unsafe extern "C" fn mb_dupcl(mut n: *mut mbuf, mut m: *mut mbuf) {
    if *(*m).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32 {
        ::std::ptr::write_volatile(
            (*m).M_dat.MH.MH_dat.MH_ext.ref_cnt,
            (::std::ptr::read_volatile::<u_int>(
                (*m).M_dat.MH.MH_dat.MH_ext.ref_cnt as *const u_int,
            ))
            .wrapping_add(1u32),
        )
    } else {
        ::std::intrinsics::atomic_xadd((*m).M_dat.MH.MH_dat.MH_ext.ref_cnt, 1u32);
    }
    (*n).M_dat.MH.MH_dat.MH_ext.ext_buf = (*m).M_dat.MH.MH_dat.MH_ext.ext_buf;
    (*n).M_dat.MH.MH_dat.MH_ext.ext_free = (*m).M_dat.MH.MH_dat.MH_ext.ext_free;
    (*n).M_dat.MH.MH_dat.MH_ext.ext_args = (*m).M_dat.MH.MH_dat.MH_ext.ext_args;
    (*n).M_dat.MH.MH_dat.MH_ext.ext_size = (*m).M_dat.MH.MH_dat.MH_ext.ext_size;
    (*n).M_dat.MH.MH_dat.MH_ext.ref_cnt = (*m).M_dat.MH.MH_dat.MH_ext.ref_cnt;
    (*n).M_dat.MH.MH_dat.MH_ext.ext_type = (*m).M_dat.MH.MH_dat.MH_ext.ext_type;
    (*n).m_hdr.mh_flags |= 0x1i32;
}
/*
 * Make a copy of an mbuf chain starting "off0" bytes from the beginning,
 * continuing for "len" bytes.  If len is M_COPYALL, copy to end of mbuf.
 * The wait parameter is a choice of M_TRYWAIT/M_NOWAIT from caller.
 * Note that the copy is read-only, because clusters are not copied,
 * only their reference counts are incremented.
 */
#[no_mangle]
pub unsafe extern "C" fn m_copym(
    mut m: *mut mbuf,
    mut off0: libc::c_int,
    mut len: libc::c_int,
    mut wait: libc::c_int,
) -> *mut mbuf {
    let mut current_block: u64;
    let mut np = 0 as *mut *mut mbuf;
    let mut top = 0 as *mut mbuf;
    let mut copyhdr = 0i32;
    let mut off = off0;

    if m.is_null() {
        return 0 as *mut mbuf;
    }
    if off == 0i32 && (*m).m_hdr.mh_flags & 0x2i32 != 0 {
        copyhdr = 1i32
    }
    while off > 0i32 {
        if off < (*m).m_hdr.mh_len {
            break;
        }
        off -= (*m).m_hdr.mh_len;
        m = (*m).m_hdr.mh_next
    }
    np = &mut top;
    top = 0 as *mut mbuf;
    loop {
        let mut n = 0 as *mut mbuf;
        if !(len > 0i32) {
            current_block = 3934796541983872331;
            break;
        }
        if m.is_null() {
            current_block = 3934796541983872331;
            break;
        }
        if copyhdr != 0 {
            n = m_gethdr(wait, (*m).m_hdr.mh_type)
        } else {
            n = m_get(wait, (*m).m_hdr.mh_type)
        }
        *np = n;
        if n.is_null() {
            current_block = 16168460772713070805;
            break;
        }
        if copyhdr != 0 {
            if m_dup_pkthdr(n, m, wait) == 0 {
                current_block = 16168460772713070805;
                break;
            }
            if len == 1000000000i32 {
                (*n).M_dat.MH.MH_pkthdr.len -= off0
            } else {
                (*n).M_dat.MH.MH_pkthdr.len = len
            }
            copyhdr = 0i32
        }
        (*n).m_hdr.mh_len = if len > (*m).m_hdr.mh_len - off {
            ((*m).m_hdr.mh_len) - off
        } else {
            len
        };
        if (*m).m_hdr.mh_flags & 0x1i32 != 0 {
            (*n).m_hdr.mh_data = (*m).m_hdr.mh_data.offset(off as isize);
            mb_dupcl(n, m);
        } else {
            memcpy(
                (*n).m_hdr.mh_data as *mut libc::c_void,
                (*m).m_hdr.mh_data.offset(off as isize) as *const libc::c_void,
                (*n).m_hdr.mh_len as u_int as libc::c_ulong,
            );
        }
        if len != 1000000000i32 {
            len -= (*n).m_hdr.mh_len
        }
        off = 0i32;
        m = (*m).m_hdr.mh_next;
        np = &mut (*n).m_hdr.mh_next
    }
    match current_block {
        16168460772713070805 => {
            m_freem(top);
            mbstat.m_mcfail = mbstat.m_mcfail.wrapping_add(1);
            return 0 as *mut mbuf;
        }
        _ => {
            if top.is_null() {
                mbstat.m_mcfail = mbstat.m_mcfail.wrapping_add(1)
            }
            return top;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn m_tag_copy_chain(
    mut to: *mut mbuf,
    mut from: *mut mbuf,
    mut how: libc::c_int,
) -> libc::c_int {
    let mut p = 0 as *mut m_tag;
    m_tag_delete_chain(to, 0 as *mut m_tag);
    p = (*from).M_dat.MH.MH_pkthdr.tags.slh_first;
    while !p.is_null() {
        let mut t = 0 as *mut m_tag;
        let mut tprev = 0 as *mut m_tag;
        t = m_tag_copy(p, how);
        if t.is_null() {
            m_tag_delete_chain(to, 0 as *mut m_tag);
            return 0i32;
        }
        if tprev.is_null() {
            (*t).m_tag_link.sle_next = (*to).M_dat.MH.MH_pkthdr.tags.slh_first;
            (*to).M_dat.MH.MH_pkthdr.tags.slh_first = t
        } else {
            (*t).m_tag_link.sle_next = (*tprev).m_tag_link.sle_next;
            (*tprev).m_tag_link.sle_next = t
        }
        tprev = t;
        p = (*p).m_tag_link.sle_next
    }
    return 1i32;
}
/*
 * Duplicate "from"'s mbuf pkthdr in "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 * In particular, this does a deep copy of the packet tags.
 */
#[no_mangle]
pub unsafe extern "C" fn m_dup_pkthdr(
    mut to: *mut mbuf,
    mut from: *mut mbuf,
    mut how: libc::c_int,
) -> libc::c_int {
    (*to).m_hdr.mh_flags = (*from).m_hdr.mh_flags
        & (0x2i32
            | 0x4i32
            | 0x8i32
            | 0x10i32
            | 0x10i32
            | 0x20i32
            | 0x40i32
            | 0x80i32
            | 0x100i32
            | 0x200i32
            | 0x400i32
            | 0x800i32
            | 0x1000i32
            | 0x2000i32
            | 0x10000i32
            | 0x20000i32)
        | (*to).m_hdr.mh_flags & 0x1i32;
    if (*to).m_hdr.mh_flags & 0x1i32 == 0i32 {
        (*to).m_hdr.mh_data = (*to).M_dat.MH.MH_dat.MH_databuf.as_mut_ptr()
    }
    (*to).M_dat.MH.MH_pkthdr = (*from).M_dat.MH.MH_pkthdr;
    (*to).M_dat.MH.MH_pkthdr.tags.slh_first = 0 as *mut m_tag;
    return m_tag_copy_chain(to, from, how);
}
/* Copy a single tag. */
#[no_mangle]
pub unsafe extern "C" fn m_tag_copy(mut t: *mut m_tag, mut how: libc::c_int) -> *mut m_tag {
    let mut p = 0 as *mut m_tag; /* Copy the data */
    p = m_tag_alloc(
        (*t).m_tag_cookie,
        (*t).m_tag_id as libc::c_int,
        (*t).m_tag_len as libc::c_int,
        how,
    );
    if p.is_null() {
        return 0 as *mut m_tag;
    }
    memcpy(
        p.offset(1isize) as *mut libc::c_void,
        t.offset(1isize) as *const libc::c_void,
        (*t).m_tag_len as libc::c_ulong,
    );
    return p;
}
/* Get a packet tag structure along with specified data following. */
#[no_mangle]
pub unsafe extern "C" fn m_tag_alloc(
    mut cookie: u_int32_t,
    mut type_0: libc::c_int,
    mut len: libc::c_int,
    mut wait: libc::c_int,
) -> *mut m_tag {
    let mut t = 0 as *mut m_tag;
    if len < 0i32 {
        return 0 as *mut m_tag;
    }
    t = malloc((len as libc::c_ulong).wrapping_add(::std::mem::size_of::<m_tag>() as libc::c_ulong))
        as *mut m_tag;
    if t.is_null() {
        return 0 as *mut m_tag;
    }
    m_tag_setup(t, cookie, type_0, len);
    (*t).m_tag_free = Some(m_tag_free_default as unsafe extern "C" fn(_: *mut m_tag) -> ());
    return t;
}
/* type of external storage */
/*
 * The core of the mbuf object along with some shortcut defined for practical
 * purposes.
 */
/* M_PKTHDR set */
/* M_EXT set */
/* !M_PKTHDR, !M_EXT */
/*
 * mbuf flags.
 */
/* has associated external storage */
/* start of record */
/* end of record */
/* associated data is marked read-only */
/* protocol-specific */
/* protocol-specific */
/* protocol-specific */
/* protocol-specific */
/* protocol-specific */
/* mbuf is on the free list */
/*
 * Flags copied when copying m_pkthdr.
 */
/*
 * mbuf pkthdr flags (also stored in m_flags).
 */
/* send/received as link-level broadcast */
/* send/received as link-level multicast */
/* packet is a fragment of a larger packet */
/* packet is first fragment */
/* packet is last fragment */
/* ether_vtag is valid */
/* packet was not for us */
/* do not free mbuf - it is embedded in the cluster */
/*
 * External buffer types: identify ext_buf type.
 */
/* mbuf cluster */
/* sendfile(2)'s sf_bufs */
/* jumbo cluster 4096 bytes */
/* jumbo cluster 9216 bytes */
/* jumbo cluster 16184 bytes */
/* mbuf+cluster from packet zone */
/* external mbuf reference (M_IOVEC) */
/* custom ext_buf provided by net driver(s) */
/* custom module's ext_buf type */
/* can throw this buffer away w/page flipping */
/* has externally maintained ref_cnt ptr */
/*
 * mbuf types.
 */
/* USED INTERNALLY ONLY! Object is not mbuf */
/* dynamic (data) allocation */
/* packet header, use M_PKTHDR instead */
/* socket name */
/* extra-data protocol message */
/* expedited data  */
/* number of mbuf types for mbtypes[] */
/* Not a type but a flag to allocate
a non-initialized mbuf */
/*
 * __Userspace__ flags like M_NOWAIT are defined in malloc.h
 * Flags like these are used in functions like uma_zalloc()
 * but don't have an equivalent in userland umem
 * Flags specifying how an allocation should be made.
 *
 * The flag to use is as follows:
 * - M_DONTWAIT or M_NOWAIT from an interrupt handler to not block allocation.
 * - M_WAIT or M_WAITOK or M_TRYWAIT from wherever it is safe to block.
 *
 * M_DONTWAIT/M_NOWAIT means that we will not block the thread explicitly and
 * if we cannot allocate immediately we may return NULL, whereas
 * M_WAIT/M_WAITOK/M_TRYWAIT means that if we cannot allocate resources we
 * will block until they are available, and thus never return NULL.
 *
 * XXX Eventually just phase this out to use M_WAITOK/M_NOWAIT.
 */
/* Free a packet tag. */
#[no_mangle]
pub unsafe extern "C" fn m_tag_free_default(mut t: *mut m_tag) {
    free(t as *mut libc::c_void);
}
/*
 * Copy data from a buffer back into the indicated mbuf chain,
 * starting "off" bytes from the beginning, extending the mbuf
 * chain if necessary.
 */
#[no_mangle]
pub unsafe extern "C" fn m_copyback(
    mut m0: *mut mbuf,
    mut off: libc::c_int,
    mut len: libc::c_int,
    mut cp: caddr_t,
) {
    let mut current_block: u64;
    let mut mlen = 0;
    let mut n = 0 as *mut mbuf;
    let mut totlen = 0i32;
    let mut m = m0;

    if m0.is_null() {
        return;
    }
    loop {
        mlen = (*m).m_hdr.mh_len;
        if !(off > mlen) {
            current_block = 12800627514080957624;
            break;
        }
        off -= mlen;
        totlen += mlen;
        if (*m).m_hdr.mh_next.is_null() {
            n = m_get(0x1i32, (*m).m_hdr.mh_type);
            if n.is_null() {
                current_block = 1612968708654363741;
                break;
            }
            memset(
                (*n).m_hdr.mh_data as *mut libc::c_void,
                0i32,
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as libc::c_ulong,
            );
            (*n).m_hdr.mh_len = if (256u64)
                .wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                as libc::c_int
                > len + off
            {
                (len) + off
            } else {
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int
            };
            (*m).m_hdr.mh_next = n
        }
        m = (*m).m_hdr.mh_next
    }
    match current_block {
        12800627514080957624 => {
            while len > 0i32 {
                mlen = if (*m).m_hdr.mh_len - off > len {
                    len
                } else {
                    ((*m).m_hdr.mh_len) - off
                };
                memcpy(
                    (*m).m_hdr.mh_data.offset(off as isize) as *mut libc::c_void,
                    cp as *const libc::c_void,
                    mlen as u_int as libc::c_ulong,
                );
                cp = cp.offset(mlen as isize);
                len -= mlen;
                mlen += off;
                off = 0i32;
                totlen += mlen;
                if len == 0i32 {
                    break;
                }
                if (*m).m_hdr.mh_next.is_null() {
                    n = m_get(0x1i32, (*m).m_hdr.mh_type);
                    if n.is_null() {
                        break;
                    }
                    (*n).m_hdr.mh_len = if (256u64)
                        .wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                        as libc::c_int
                        > len
                    {
                        len
                    } else {
                        (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                            as libc::c_int
                    };
                    (*m).m_hdr.mh_next = n
                }
                m = (*m).m_hdr.mh_next
            }
        }
        _ => {}
    }
    m = m0;
    if (*m).m_hdr.mh_flags & 0x2i32 != 0 && (*m).M_dat.MH.MH_pkthdr.len < totlen {
        (*m).M_dat.MH.MH_pkthdr.len = totlen
    };
}
/*
 * Lesser-used path for M_PREPEND:
 * allocate new mbuf to prepend to chain,
 * copy junk along.
 */
#[no_mangle]
pub unsafe extern "C" fn m_prepend(
    mut m: *mut mbuf,
    mut len: libc::c_int,
    mut how: libc::c_int,
) -> *mut mbuf {
    let mut mn = 0 as *mut mbuf;
    if (*m).m_hdr.mh_flags & 0x2i32 != 0 {
        mn = m_gethdr(how, (*m).m_hdr.mh_type)
    } else {
        mn = m_get(how, (*m).m_hdr.mh_type)
    }
    if mn.is_null() {
        m_freem(m);
        return 0 as *mut mbuf;
    }
    if (*m).m_hdr.mh_flags & 0x2i32 != 0 {
        m_move_pkthdr(mn, m);
    }
    (*mn).m_hdr.mh_next = m;
    m = mn;
    if (*m).m_hdr.mh_flags & 0x2i32 != 0 {
        if len
            < ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_int
                as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                as libc::c_int
        {
            (*m).m_hdr.mh_data = (*m).m_hdr.mh_data.offset(
                ((((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                    as libc::c_int
                    - len) as libc::c_ulong
                    & !(::std::mem::size_of::<libc::c_long>() as libc::c_ulong).wrapping_sub(1u64))
                    as isize,
            )
        }
    } else if len
        < (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_int
    {
        (*m).m_hdr.mh_data = (*m).m_hdr.mh_data.offset(
            (((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_int
                - len) as libc::c_ulong
                & !(::std::mem::size_of::<libc::c_long>() as libc::c_ulong).wrapping_sub(1u64))
                as isize,
        )
    }
    (*m).m_hdr.mh_len = len;
    return m;
}
/*
 * Copy data from an mbuf chain starting "off" bytes from the beginning,
 * continuing for "len" bytes, into the indicated buffer.
 */
#[no_mangle]
pub unsafe extern "C" fn m_copydata(
    mut m: *const mbuf,
    mut off: libc::c_int,
    mut len: libc::c_int,
    mut cp: caddr_t,
) {
    while off > 0i32 {
        if off < (*m).m_hdr.mh_len {
            break;
        }
        off -= (*m).m_hdr.mh_len;
        m = (*m).m_hdr.mh_next
    }
    while len > 0i32 {
        let mut count = 0;
        count = if (*m).m_hdr.mh_len - off > len {
            len
        } else {
            ((*m).m_hdr.mh_len) - off
        } as u_int;
        memcpy(
            cp as *mut libc::c_void,
            (*m).m_hdr.mh_data.offset(off as isize) as *const libc::c_void,
            count as libc::c_ulong,
        );
        len = (len as libc::c_uint).wrapping_sub(count) as libc::c_int;
        cp = cp.offset(count as isize);
        off = 0i32;
        m = (*m).m_hdr.mh_next
    }
}
/*
 * Concatenate mbuf chain n to m.
 * Both chains must be of the same type (e.g. MT_DATA).
 * Any m_pkthdr is not updated.
 */
#[no_mangle]
pub unsafe extern "C" fn m_cat(mut m: *mut mbuf, mut n: *mut mbuf) {
    while !(*m).m_hdr.mh_next.is_null() {
        m = (*m).m_hdr.mh_next
    }
    while !n.is_null() {
        if (*m).m_hdr.mh_flags & 0x1i32 != 0
            || (*m)
                .m_hdr
                .mh_data
                .offset((*m).m_hdr.mh_len as isize)
                .offset((*n).m_hdr.mh_len as isize)
                >= &mut *(*m).M_dat.M_databuf.as_mut_ptr().offset(
                    (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                        as libc::c_int as isize,
                ) as *mut libc::c_char
        {
            /* just join the two chains */
            (*m).m_hdr.mh_next = n;
            return;
        }
        /* splat the data from one into the other */
        memcpy(
            (*m).m_hdr.mh_data.offset((*m).m_hdr.mh_len as isize) as *mut libc::c_void,
            (*n).m_hdr.mh_data as *const libc::c_void,
            (*n).m_hdr.mh_len as u_int as libc::c_ulong,
        );
        (*m).m_hdr.mh_len += (*n).m_hdr.mh_len;
        n = m_free(n)
    }
}
#[no_mangle]
pub unsafe extern "C" fn m_adj(mut mp: *mut mbuf, mut req_len: libc::c_int) {
    let mut m = 0 as *mut mbuf;
    let mut len = req_len;

    m = mp;
    if m.is_null() {
        return;
    }
    if len >= 0i32 {
        /*
         * Trim from head.
         */
        while !m.is_null() && len > 0i32 {
            if (*m).m_hdr.mh_len <= len {
                len -= (*m).m_hdr.mh_len;
                (*m).m_hdr.mh_len = 0i32;
                m = (*m).m_hdr.mh_next
            } else {
                (*m).m_hdr.mh_len -= len;
                (*m).m_hdr.mh_data = (*m).m_hdr.mh_data.offset(len as isize);
                len = 0i32
            }
        }
        m = mp;
        if (*mp).m_hdr.mh_flags & 0x2i32 != 0 {
            (*m).M_dat.MH.MH_pkthdr.len -= req_len - len
        }
    } else {
        let mut count = 0;
        len = -len;
        count = 0i32;
        loop {
            count += (*m).m_hdr.mh_len;
            if (*m).m_hdr.mh_next.is_null() {
                break;
            }
            m = (*m).m_hdr.mh_next
        }
        if (*m).m_hdr.mh_len >= len {
            (*m).m_hdr.mh_len -= len;
            if (*mp).m_hdr.mh_flags & 0x2i32 != 0 {
                (*mp).M_dat.MH.MH_pkthdr.len -= len
            }
            return;
        }
        count -= len;
        if count < 0i32 {
            count = 0i32
        }
        /*
         * Correct length for chain is "count".
         * Find the mbuf with last data, adjust its length,
         * and toss data from remaining mbufs on chain.
         */
        m = mp;
        if (*m).m_hdr.mh_flags & 0x2i32 != 0 {
            (*m).M_dat.MH.MH_pkthdr.len = count
        }
        while !m.is_null() {
            if (*m).m_hdr.mh_len >= count {
                (*m).m_hdr.mh_len = count;
                if !(*m).m_hdr.mh_next.is_null() {
                    m_freem((*m).m_hdr.mh_next);
                    (*m).m_hdr.mh_next = 0 as *mut mbuf
                }
                break;
            } else {
                count -= (*m).m_hdr.mh_len;
                m = (*m).m_hdr.mh_next
            }
        }
    };
}
/* m_split is used within sctp_handle_cookie_echo. */
/*
 * Partition an mbuf chain in two pieces, returning the tail --
 * all but the first len0 bytes.  In case of failure, it returns NULL and
 * attempts to restore the chain to its original state.
 *
 * Note that the resulting mbufs might be read-only, because the new
 * mbuf can end up sharing an mbuf cluster with the original mbuf if
 * the "breaking point" happens to lie within a cluster mbuf. Use the
 * M_WRITABLE() macro to check for this case.
 */
#[no_mangle]
pub unsafe extern "C" fn m_split(
    mut m0: *mut mbuf,
    mut len0: libc::c_int,
    mut wait: libc::c_int,
) -> *mut mbuf {
    let mut m = 0 as *mut mbuf;
    let mut n = 0 as *mut mbuf;
    let mut remain = 0;
    let mut len = len0 as u_int;

    /* MBUF_CHECKSLEEP(wait); */
    m = m0;
    while !m.is_null() && len as libc::c_int > (*m).m_hdr.mh_len {
        len = (len).wrapping_sub((*m).m_hdr.mh_len as libc::c_uint);
        m = (*m).m_hdr.mh_next
    }
    if m.is_null() {
        return 0 as *mut mbuf;
    }
    remain = ((*m).m_hdr.mh_len as libc::c_uint).wrapping_sub(len);
    if (*m0).m_hdr.mh_flags & 0x2i32 != 0 {
        n = m_gethdr(wait, (*m0).m_hdr.mh_type);
        if n.is_null() {
            return 0 as *mut mbuf;
        }
        (*n).M_dat.MH.MH_pkthdr.rcvif = (*m0).M_dat.MH.MH_pkthdr.rcvif;
        (*n).M_dat.MH.MH_pkthdr.len = (*m0).M_dat.MH.MH_pkthdr.len - len0;
        (*m0).M_dat.MH.MH_pkthdr.len = len0;
        if !((*m).m_hdr.mh_flags & 0x1i32 != 0) {
            if remain
                > ((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                    as libc::c_uint
            {
                /* m can't be the lead packet */
                (*n).m_hdr.mh_data = (*n).m_hdr.mh_data.offset(
                    ((((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                        as libc::c_int as libc::c_ulong)
                        .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                        as libc::c_int
                        - 0i32) as libc::c_ulong
                        & !(::std::mem::size_of::<libc::c_long>() as libc::c_ulong)
                            .wrapping_sub(1u64)) as isize,
                );
                (*n).m_hdr.mh_next = m_split(m, len as libc::c_int, wait);
                if (*n).m_hdr.mh_next.is_null() {
                    m_free(n);
                    return 0 as *mut mbuf;
                } else {
                    (*n).m_hdr.mh_len = 0i32;
                    return n;
                }
            } else {
                (*n).m_hdr.mh_data = (*n).m_hdr.mh_data.offset(
                    ((((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                        as libc::c_int as libc::c_ulong)
                        .wrapping_sub(::std::mem::size_of::<pkthdr>() as libc::c_ulong)
                        as libc::c_uint)
                        .wrapping_sub(remain) as libc::c_ulong
                        & !(::std::mem::size_of::<libc::c_long>() as libc::c_ulong)
                            .wrapping_sub(1u64)) as isize,
                )
            }
        }
    } else if remain == 0u32 {
        n = (*m).m_hdr.mh_next;
        (*m).m_hdr.mh_next = 0 as *mut mbuf;
        return n;
    } else {
        n = m_get(wait, (*m).m_hdr.mh_type);
        if n.is_null() {
            return 0 as *mut mbuf;
        }
        (*n).m_hdr.mh_data = (*n).m_hdr.mh_data.offset(
            (((256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                as libc::c_uint)
                .wrapping_sub(remain) as libc::c_ulong
                & !(::std::mem::size_of::<libc::c_long>() as libc::c_ulong).wrapping_sub(1u64))
                as isize,
        )
    }
    if (*m).m_hdr.mh_flags & 0x1i32 != 0 {
        (*n).m_hdr.mh_data = (*m).m_hdr.mh_data.offset(len as isize);
        mb_dupcl(n, m);
    } else {
        memcpy(
            (*n).m_hdr.mh_data as *mut libc::c_void,
            (*m).m_hdr.mh_data.offset(len as isize) as *const libc::c_void,
            remain as libc::c_ulong,
        );
    }
    (*n).m_hdr.mh_len = remain as libc::c_int;
    (*m).m_hdr.mh_len = len as libc::c_int;
    (*n).m_hdr.mh_next = (*m).m_hdr.mh_next;
    (*m).m_hdr.mh_next = 0 as *mut mbuf;
    return n;
}
#[no_mangle]
pub unsafe extern "C" fn pack_send_buffer(mut buffer: caddr_t, mut mb: *mut mbuf) -> libc::c_int {
    let mut total_count_copied = 0i32;
    loop {
        let mut count_to_copy = 0;
        let mut offset = 0i32;
        count_to_copy = (*mb).m_hdr.mh_len;
        memcpy(
            buffer.offset(offset as isize) as *mut libc::c_void,
            (*mb).m_hdr.mh_data as *const libc::c_void,
            count_to_copy as libc::c_ulong,
        );
        offset += count_to_copy;
        total_count_copied += count_to_copy;
        mb = (*mb).m_hdr.mh_next;
        if mb.is_null() {
            break;
        }
    }
    return total_count_copied;
}
