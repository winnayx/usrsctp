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
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn read_random(buf: *mut libc::c_void, count: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn sctp_sha1_init(_: *mut sctp_sha1_context);
    #[no_mangle]
    fn sctp_sha1_update(_: *mut sctp_sha1_context, _: *const libc::c_uchar, _: libc::c_uint);
    #[no_mangle]
    fn sctp_sha1_final(_: *mut libc::c_uchar, _: *mut sctp_sha1_context);
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
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_get_mbuf_for_msg(
        space_needed: libc::c_uint,
        want_header: libc::c_int,
        how: libc::c_int,
        allonebuf: libc::c_int,
        type_0: libc::c_int,
    ) -> *mut mbuf;
    /* TODO where to put non-_KERNEL things for __Userspace__? */
    /* Attention Julian, this is the extern that
     * goes with the base info. sctp_pcb.c has
     * the real definition.
     */
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_add_to_readq(
        inp: *mut sctp_inpcb,
        stcb: *mut sctp_tcb,
        control: *mut sctp_queued_to_read,
        sb: *mut sockbuf,
        end: libc::c_int,
        inpread_locked: libc::c_int,
        so_locked: libc::c_int,
    );
    #[no_mangle]
    fn sctp_m_getptr(_: *mut mbuf, _: libc::c_int, _: libc::c_int, _: *mut uint8_t) -> caddr_t;
    #[no_mangle]
    fn sctp_get_next_param(
        _: *mut mbuf,
        _: libc::c_int,
        _: *mut sctp_paramhdr,
        _: libc::c_int,
    ) -> *mut sctp_paramhdr;
    #[no_mangle]
    fn sctp_ulp_notify(
        _: uint32_t,
        _: *mut sctp_tcb,
        _: uint32_t,
        _: *mut libc::c_void,
        _: libc::c_int,
    );
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
    fn sctp_build_readq_entry(
        stcb: *mut sctp_tcb,
        net: *mut sctp_nets,
        tsn: uint32_t,
        ppid: uint32_t,
        context: uint32_t,
        sid: uint16_t,
        mid: uint32_t,
        flags: uint8_t,
        dm: *mut mbuf,
    ) -> *mut sctp_queued_to_read;
    #[no_mangle]
    fn sctp_queue_op_err(_: *mut sctp_tcb, _: *mut mbuf);
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
    pub c2rust_unnamed: C2RustUnnamed_55,
    pub c2rust_unnamed_0: C2RustUnnamed_53,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_53 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_54,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_54 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_55 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_56,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_56 {
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
    pub __in6_u: C2RustUnnamed_57,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_57 {
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
    pub so_incomp: C2RustUnnamed_65,
    pub so_comp: C2RustUnnamed_64,
    pub so_list: C2RustUnnamed_63,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_62,
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
    pub M_dat: C2RustUnnamed_58,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_58 {
    pub MH: C2RustUnnamed_59,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_59 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_60,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_60 {
    pub MH_ext: m_ext,
    pub MH_databuf: [libc::c_char; 176],
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
    pub m_tag_link: C2RustUnnamed_61,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_61 {
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
pub struct C2RustUnnamed_62 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_63 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_64 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_65 {
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
    pub ifa_ifu: C2RustUnnamed_66,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_66 {
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
    pub inp_hash: C2RustUnnamed_74,
    pub inp_list: C2RustUnnamed_73,
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
    pub inp_depend4: C2RustUnnamed_70,
    pub inp_depend6: C2RustUnnamed_69,
    pub inp_portlist: C2RustUnnamed_68,
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
    pub phd_hash: C2RustUnnamed_67,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_67 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_68 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_69 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_70 {
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
    pub ie_dependfaddr: C2RustUnnamed_72,
    pub ie_dependladdr: C2RustUnnamed_71,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_71 {
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
pub union C2RustUnnamed_72 {
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
pub struct C2RustUnnamed_73 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_74 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_sha1_context {
    pub A: libc::c_uint,
    pub B: libc::c_uint,
    pub C: libc::c_uint,
    pub D: libc::c_uint,
    pub E: libc::c_uint,
    pub H0: libc::c_uint,
    pub H1: libc::c_uint,
    pub H2: libc::c_uint,
    pub H3: libc::c_uint,
    pub H4: libc::c_uint,
    pub words: [libc::c_uint; 80],
    pub TEMP: libc::c_uint,
    pub sha_block: [libc::c_char; 64],
    pub how_many_in_block: libc::c_int,
    pub running_total: libc::c_uint,
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
    pub tqe: C2RustUnnamed_75,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_75 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;
pub type sctp_rtentry_t = sctp_rtentry;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_paramhdr {
    pub param_type: uint16_t,
    pub param_length: uint16_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_auth_chunk_list {
    pub ph: sctp_paramhdr,
    pub chunk_types: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_shared_key {
    pub next: C2RustUnnamed_76,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
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
pub struct C2RustUnnamed_76 {
    pub le_next: *mut sctp_shared_key,
    pub le_prev: *mut *mut sctp_shared_key,
}
/* we choose the number to make a pcb a page */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_104,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_103,
    pub sctp_hash: C2RustUnnamed_102,
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
pub struct sctpasochead {
    pub lh_first: *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_101,
    pub sctp_tcblist: C2RustUnnamed_100,
    pub sctp_tcbasocidhash: C2RustUnnamed_99,
    pub sctp_asocs: C2RustUnnamed_98,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_keyhead {
    pub lh_first: *mut sctp_shared_key,
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
    pub next: C2RustUnnamed_86,
    pub next_instrm: C2RustUnnamed_85,
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
    pub rec: C2RustUnnamed_84,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_77,
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
pub struct C2RustUnnamed_77 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_nets {
    pub sctp_next: C2RustUnnamed_83,
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
    pub next_ifa: C2RustUnnamed_82,
    pub next_bucket: C2RustUnnamed_81,
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
    pub next_ifn: C2RustUnnamed_79,
    pub next_bucket: C2RustUnnamed_78,
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
pub struct C2RustUnnamed_78 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_79 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_80,
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
pub struct C2RustUnnamed_80 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_81 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_82 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_83 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_84 {
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
pub struct C2RustUnnamed_85 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_86 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
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
/* States for outgoing streams */
/* This struct is used to track the traffic on outbound streams */

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
    pub next_spoke: C2RustUnnamed_87,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_87 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_88,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_88 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_89,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_89 {
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
    pub next: C2RustUnnamed_91,
    pub ss_next: C2RustUnnamed_90,
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
pub struct C2RustUnnamed_90 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_91 {
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
    pub next_resp: C2RustUnnamed_92,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_92 {
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
    pub sctp_nxt_addr: C2RustUnnamed_93,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_93 {
    pub le_next: *mut sctp_laddr,
    pub le_prev: *mut *mut sctp_laddr,
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
    pub next: C2RustUnnamed_94,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_94 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_95,
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
pub struct C2RustUnnamed_95 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
}
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_96,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_96 {
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
    pub next: C2RustUnnamed_97,
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
pub struct C2RustUnnamed_97 {
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
pub struct C2RustUnnamed_98 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_99 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_100 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_101 {
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
pub struct C2RustUnnamed_102 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_103 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_104 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}
pub type sctp_sharedkey_t = sctp_shared_key;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_auth_hmac_algo {
    pub ph: sctp_paramhdr,
    pub hmac_ids: [uint16_t; 0],
}
/* ***************************************************/
/*
 * Authenticated chunks support draft-ietf-tsvwg-sctp-auth
 */
/* Should we make the max be 32? */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_auth_random {
    pub ph: sctp_paramhdr,
    pub random_data: [uint8_t; 0],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_auth_chunk {
    pub ch: sctp_chunkhdr,
    pub shared_key_id: uint16_t,
    pub hmac_id: uint16_t,
    pub hmac: [uint8_t; 0],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_error_cause {
    pub code: uint16_t,
    pub length: uint16_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_error_auth_invalid_hmac {
    pub cause: sctp_error_cause,
    pub hmac_id: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_authkey_event {
    pub auth_type: uint16_t,
    pub auth_flags: uint16_t,
    pub auth_length: uint32_t,
    pub auth_keynumber: uint16_t,
    pub auth_altkeynumber: uint16_t,
    pub auth_indication: uint32_t,
    pub auth_assoc_id: sctp_assoc_t,
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
/* max storage size */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_supported_chunk_types_param {
    pub ph: sctp_paramhdr,
    pub chunk_types: [uint8_t; 0],
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
    pub sctp_nxt_tagblock: C2RustUnnamed_105,
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
pub struct C2RustUnnamed_105 {
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
pub union sctp_hash_context {
    pub sha1: sctp_sha1_context,
}
pub type sctp_hash_context_t = sctp_hash_context;

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
/* SCTP_DEBUG */
#[no_mangle]
pub unsafe extern "C" fn sctp_clear_chunklist(mut chklist: *mut sctp_auth_chklist_t) {
    memset(
        chklist as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_auth_chklist_t>() as libc::c_ulong,
    );
    /* chklist->num_chunks = 0; */
}
#[no_mangle]
pub unsafe extern "C" fn sctp_alloc_chunklist() -> *mut sctp_auth_chklist_t {
    let mut chklist = 0 as *mut sctp_auth_chklist_t;
    chklist = malloc(::std::mem::size_of::<sctp_auth_chklist_t>() as libc::c_ulong)
        as *mut sctp_auth_chklist_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            chklist as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_auth_chklist_t>() as libc::c_ulong,
        );
    }
    if chklist.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"sctp_alloc_chunklist: failed to get memory!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
    } else {
        sctp_clear_chunklist(chklist);
    }
    return chklist;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_chunklist(mut list: *mut sctp_auth_chklist_t) {
    if !list.is_null() {
        free(list as *mut libc::c_void);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_copy_chunklist(
    mut list: *mut sctp_auth_chklist_t,
) -> *mut sctp_auth_chklist_t {
    let mut new_list = 0 as *mut sctp_auth_chklist_t;
    if list.is_null() {
        return 0 as *mut sctp_auth_chklist_t;
    }
    /* get a new list */
    new_list = sctp_alloc_chunklist();
    if new_list.is_null() {
        return 0 as *mut sctp_auth_chklist_t;
    }
    /* copy it */
    memcpy(
        new_list as *mut libc::c_void,
        list as *const libc::c_void,
        ::std::mem::size_of::<sctp_auth_chklist_t>() as libc::c_ulong,
    );
    return new_list;
}
/*
 * add a chunk to the required chunks list
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_add_chunk(
    mut chunk: uint8_t,
    mut list: *mut sctp_auth_chklist_t,
) -> libc::c_int {
    if list.is_null() {
        return -(1i32);
    }
    /* is chunk restricted? */
    if chunk as libc::c_int == 0x1i32
        || chunk as libc::c_int == 0x2i32
        || chunk as libc::c_int == 0xei32
        || chunk as libc::c_int == 0xfi32
    {
        return -(1i32);
    }
    if (*list).chunks[chunk as usize] as libc::c_int == 0i32 {
        (*list).chunks[chunk as usize] = 1u8;
        (*list).num_chunks = (*list).num_chunks.wrapping_add(1);
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP: added chunk %u (0x%02x) to Auth list\n\x00" as *const u8
                        as *const libc::c_char,
                    chunk as libc::c_int,
                    chunk as libc::c_int,
                );
            }
        }
    }
    return 0i32;
}
/*
 * delete a chunk from the required chunks list
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_delete_chunk(
    mut chunk: uint8_t,
    mut list: *mut sctp_auth_chklist_t,
) -> libc::c_int {
    if list.is_null() {
        return -(1i32);
    }
    if (*list).chunks[chunk as usize] as libc::c_int == 1i32 {
        (*list).chunks[chunk as usize] = 0u8;
        (*list).num_chunks = (*list).num_chunks.wrapping_sub(1);
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP: deleted chunk %u (0x%02x) from Auth list\n\x00" as *const u8
                        as *const libc::c_char,
                    chunk as libc::c_int,
                    chunk as libc::c_int,
                );
            }
        }
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_get_chklist_size(
    mut list: *const sctp_auth_chklist_t,
) -> size_t {
    if list.is_null() {
        return 0u64;
    } else {
        return (*list).num_chunks as size_t;
    };
}
/*
 * return the current number and list of required chunks caller must
 * guarantee ptr has space for up to 256 bytes
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_serialize_auth_chunks(
    mut list: *const sctp_auth_chklist_t,
    mut ptr: *mut uint8_t,
) -> libc::c_int {
    let mut count = 0i32;
    if list.is_null() {
        return 0i32;
    }

    for i in 0i32..256i32 {
        if (*list).chunks[i as usize] as libc::c_int != 0i32 {
            let fresh0 = ptr;
            ptr = ptr.offset(1);
            *fresh0 = i as uint8_t;
            count += 1
        }
    }
    return count;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_pack_auth_chunks(
    mut list: *const sctp_auth_chklist_t,
    mut ptr: *mut uint8_t,
) -> libc::c_int {
    let mut size = 0i32;
    if list.is_null() {
        return 0i32;
    }
    if (*list).num_chunks as libc::c_int <= 32i32 {
        for i in 0i32..256i32 {
            if (*list).chunks[i as usize] as libc::c_int != 0i32 {
                let fresh1 = ptr;
                ptr = ptr.offset(1);
                *fresh1 = i as uint8_t;
                size += 1
            }
        }
    } else {
        for i in 0i32..256i32 {
            if (*list).chunks[i as usize] as libc::c_int != 0i32 {
                let mut index = 0;
                let mut offset = 0;
                index = i / 8i32;
                offset = i % 8i32;
                let ref mut fresh2 = *ptr.offset(index as isize);
                *fresh2 = (*fresh2 as libc::c_int | (1i32) << offset) as uint8_t
            }
        }
        size = 32i32
    }
    return size;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_unpack_auth_chunks(
    mut ptr: *const uint8_t,
    mut num_chunks: uint8_t,
    mut list: *mut sctp_auth_chklist_t,
) -> libc::c_int {
    let mut size = 0;
    if list.is_null() {
        return 0i32;
    }
    if num_chunks as libc::c_int <= 32i32 {
        for i in 0i32..num_chunks as libc::c_int {
            let fresh3 = ptr;

            ptr = ptr.offset(1);

            sctp_auth_add_chunk(*fresh3, list);
        }
        size = num_chunks as libc::c_int
    } else {
        for index in 0i32..32i32 {
            for offset in 0i32..8i32 {
                if *ptr.offset(index as isize) as libc::c_int & (1i32) << offset != 0 {
                    sctp_auth_add_chunk((index * 8i32 + offset) as uint8_t, list);
                }
            }
        }
        size = 32i32
    }
    return size;
}
/*
 * allocate structure space for a key of length keylen
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_alloc_key(mut keylen: uint32_t) -> *mut sctp_key_t {
    let mut new_key = 0 as *mut sctp_key_t;
    new_key = malloc(
        (::std::mem::size_of::<sctp_key_t>() as libc::c_ulong)
            .wrapping_add(keylen as libc::c_ulong),
    ) as *mut sctp_key_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            new_key as *mut libc::c_void,
            0i32,
            (::std::mem::size_of::<sctp_key_t>() as libc::c_ulong)
                .wrapping_add(keylen as libc::c_ulong),
        );
    }
    if new_key.is_null() {
        /* out of memory */
        return 0 as *mut sctp_key_t;
    }
    (*new_key).keylen = keylen;
    return new_key;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_key(mut key: *mut sctp_key_t) {
    if !key.is_null() {
        free(key as *mut libc::c_void);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_print_key(mut key: *mut sctp_key_t, mut str: *const libc::c_char) {
    if key.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%s: [Null key]\n\x00" as *const u8 as *const libc::c_char,
                str,
            );
        }
        return;
    }
    if system_base_info.debug_printf.is_some() {
        system_base_info
            .debug_printf
            .expect("non-null function pointer")(
            b"%s: len %u, \x00" as *const u8 as *const libc::c_char,
            str,
            (*key).keylen,
        );
    }
    if (*key).keylen != 0 {
        let mut i = 0;
        i = 0u32;
        while i < (*key).keylen {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%02x\x00" as *const u8 as *const libc::c_char,
                    *(*key).key.as_mut_ptr().offset(i as isize) as libc::c_int,
                );
            }
            i = i.wrapping_add(1)
        }
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"\n\x00" as *const u8 as *const libc::c_char
            );
        }
    } else if system_base_info.debug_printf.is_some() {
        system_base_info
            .debug_printf
            .expect("non-null function pointer")(
            b"[Null key]\n\x00" as *const u8 as *const libc::c_char,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_show_key(mut key: *mut sctp_key_t, mut str: *const libc::c_char) {
    if key.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%s: [Null key]\n\x00" as *const u8 as *const libc::c_char,
                str,
            );
        }
        return;
    }
    if system_base_info.debug_printf.is_some() {
        system_base_info
            .debug_printf
            .expect("non-null function pointer")(
            b"%s: len %u, \x00" as *const u8 as *const libc::c_char,
            str,
            (*key).keylen,
        );
    }
    if (*key).keylen != 0 {
        let mut i = 0;
        i = 0u32;
        while i < (*key).keylen {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%02x\x00" as *const u8 as *const libc::c_char,
                    *(*key).key.as_mut_ptr().offset(i as isize) as libc::c_int,
                );
            }
            i = i.wrapping_add(1)
        }
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"\n\x00" as *const u8 as *const libc::c_char
            );
        }
    } else if system_base_info.debug_printf.is_some() {
        system_base_info
            .debug_printf
            .expect("non-null function pointer")(
            b"[Null key]\n\x00" as *const u8 as *const libc::c_char,
        );
    };
}
unsafe extern "C" fn sctp_get_keylen(mut key: *mut sctp_key_t) -> uint32_t {
    if !key.is_null() {
        return (*key).keylen;
    } else {
        return 0u32;
    };
}
/*
 * generate a new random key of length 'keylen'
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_generate_random_key(mut keylen: uint32_t) -> *mut sctp_key_t {
    let mut new_key = 0 as *mut sctp_key_t;
    new_key = sctp_alloc_key(keylen);
    if new_key.is_null() {
        /* out of memory */
        return 0 as *mut sctp_key_t;
    }
    read_random(
        (*new_key).key.as_mut_ptr() as *mut libc::c_void,
        keylen as libc::c_int,
    );
    (*new_key).keylen = keylen;
    return new_key;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_set_key(
    mut key: *mut uint8_t,
    mut keylen: uint32_t,
) -> *mut sctp_key_t {
    let mut new_key = 0 as *mut sctp_key_t;
    new_key = sctp_alloc_key(keylen);
    if new_key.is_null() {
        /* out of memory */
        return 0 as *mut sctp_key_t;
    }
    memcpy(
        (*new_key).key.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        keylen as libc::c_ulong,
    );
    return new_key;
}
/*-
 * given two keys of variable size, compute which key is "larger/smaller"
 * returns:  1 if key1 > key2
 *          -1 if key1 < key2
 *           0 if key1 = key2
 */
unsafe extern "C" fn sctp_compare_key(
    mut key1: *mut sctp_key_t,
    mut key2: *mut sctp_key_t,
) -> libc::c_int {
    let mut maxlen = 0;
    let mut i = 0;
    let mut key1len = 0;
    let mut key2len = 0;
    let mut key_1 = 0 as *mut uint8_t;
    let mut key_2 = 0 as *mut uint8_t;
    /* sanity/length check */
    key1len = sctp_get_keylen(key1);
    key2len = sctp_get_keylen(key2);
    if key1len == 0u32 && key2len == 0u32 {
        return 0i32;
    } else {
        if key1len == 0u32 {
            return -(1i32);
        } else {
            if key2len == 0u32 {
                return 1i32;
            }
        }
    }
    if key1len < key2len {
        maxlen = key2len
    } else {
        maxlen = key1len
    }
    key_1 = (*key1).key.as_mut_ptr();
    key_2 = (*key2).key.as_mut_ptr();
    /* check for numeric equality */
    i = 0u32;
    while i < maxlen {
        let mut val1 = 0;
        let mut val2 = 0;
        val1 = if i < maxlen.wrapping_sub(key1len) {
            0i32
        } else {
            let fresh4 = key_1;
            key_1 = key_1.offset(1);
            *fresh4 as libc::c_int
        } as uint8_t;
        val2 = if i < maxlen.wrapping_sub(key2len) {
            0i32
        } else {
            let fresh5 = key_2;
            key_2 = key_2.offset(1);
            *fresh5 as libc::c_int
        } as uint8_t;
        if val1 as libc::c_int > val2 as libc::c_int {
            return 1i32;
        } else {
            if (val1 as libc::c_int) < val2 as libc::c_int {
                return -(1i32);
            }
        }
        i = i.wrapping_add(1)
    }
    /* keys are equal value, so check lengths */
    if key1len == key2len {
        return 0i32;
    } else if key1len < key2len {
        return -(1i32);
    } else {
        return 1i32;
    };
}
/*
 * generate the concatenated keying material based on the two keys and the
 * shared key (if available). draft-ietf-tsvwg-auth specifies the specific
 * order for concatenation
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_compute_hashkey(
    mut key1: *mut sctp_key_t,
    mut key2: *mut sctp_key_t,
    mut shared: *mut sctp_key_t,
) -> *mut sctp_key_t {
    let mut keylen = 0;
    let mut new_key = 0 as *mut sctp_key_t;
    let mut key_ptr = 0 as *mut uint8_t;
    keylen = sctp_get_keylen(key1)
        .wrapping_add(sctp_get_keylen(key2))
        .wrapping_add(sctp_get_keylen(shared));
    if keylen > 0u32 {
        /* get space for the new key */
        new_key = sctp_alloc_key(keylen);
        if new_key.is_null() {
            /* out of memory */
            return 0 as *mut sctp_key_t;
        }
        (*new_key).keylen = keylen;
        key_ptr = (*new_key).key.as_mut_ptr()
    } else {
        /* all keys empty/null?! */
        return 0 as *mut sctp_key_t;
    }
    /* concatenate the keys */
    if sctp_compare_key(key1, key2) <= 0i32 {
        /* key is shared + key1 + key2 */
        if sctp_get_keylen(shared) != 0 {
            memcpy(
                key_ptr as *mut libc::c_void,
                (*shared).key.as_mut_ptr() as *const libc::c_void,
                (*shared).keylen as libc::c_ulong,
            );
            key_ptr = key_ptr.offset((*shared).keylen as isize)
        }
        if sctp_get_keylen(key1) != 0 {
            memcpy(
                key_ptr as *mut libc::c_void,
                (*key1).key.as_mut_ptr() as *const libc::c_void,
                (*key1).keylen as libc::c_ulong,
            );
            key_ptr = key_ptr.offset((*key1).keylen as isize)
        }
        if sctp_get_keylen(key2) != 0 {
            memcpy(
                key_ptr as *mut libc::c_void,
                (*key2).key.as_mut_ptr() as *const libc::c_void,
                (*key2).keylen as libc::c_ulong,
            );
        }
    } else {
        /* key is shared + key2 + key1 */
        if sctp_get_keylen(shared) != 0 {
            memcpy(
                key_ptr as *mut libc::c_void,
                (*shared).key.as_mut_ptr() as *const libc::c_void,
                (*shared).keylen as libc::c_ulong,
            );
            key_ptr = key_ptr.offset((*shared).keylen as isize)
        }
        if sctp_get_keylen(key2) != 0 {
            memcpy(
                key_ptr as *mut libc::c_void,
                (*key2).key.as_mut_ptr() as *const libc::c_void,
                (*key2).keylen as libc::c_ulong,
            );
            key_ptr = key_ptr.offset((*key2).keylen as isize)
        }
        if sctp_get_keylen(key1) != 0 {
            memcpy(
                key_ptr as *mut libc::c_void,
                (*key1).key.as_mut_ptr() as *const libc::c_void,
                (*key1).keylen as libc::c_ulong,
            );
        }
    }
    return new_key;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_alloc_sharedkey() -> *mut sctp_sharedkey_t {
    let mut new_key = 0 as *mut sctp_sharedkey_t;
    new_key =
        malloc(::std::mem::size_of::<sctp_sharedkey_t>() as libc::c_ulong) as *mut sctp_sharedkey_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            new_key as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_sharedkey_t>() as libc::c_ulong,
        );
    }
    if new_key.is_null() {
        /* out of memory */
        return 0 as *mut sctp_sharedkey_t;
    }
    (*new_key).keyid = 0u16;
    (*new_key).key = 0 as *mut sctp_key_t;
    (*new_key).refcount = 1u32;
    (*new_key).deactivated = 0u8;
    return new_key;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_sharedkey(mut skey: *mut sctp_sharedkey_t) {
    if skey.is_null() {
        return;
    }
    if ::std::intrinsics::atomic_xadd(&mut (*skey).refcount as *mut uint32_t, -(1i32) as uint32_t)
        == 1u32
    {
        if !(*skey).key.is_null() {
            sctp_free_key((*skey).key);
        }
        free(skey as *mut libc::c_void);
    };
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
/* local random key (concatenated) */
/* local random number length for param */
/* peer's random key (concatenated) */
/* cached concatenated send key */
/* cached concatenated recv key */
/* active send keyid */
/* current send keyid (cached) */
/* last recv keyid (cached) */
/*
 * Macros
 */
/*
 * function prototypes
 */
/* socket option api functions */
/* key handling */
/* shared key handling */
#[no_mangle]
pub unsafe extern "C" fn sctp_find_sharedkey(
    mut shared_keys: *mut sctp_keyhead,
    mut key_id: uint16_t,
) -> *mut sctp_sharedkey_t {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    skey = (*shared_keys).lh_first;
    while !skey.is_null() {
        if (*skey).keyid as libc::c_int == key_id as libc::c_int {
            return skey;
        }
        skey = (*skey).next.le_next
    }
    return 0 as *mut sctp_sharedkey_t;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_insert_sharedkey(
    mut shared_keys: *mut sctp_keyhead,
    mut new_skey: *mut sctp_sharedkey_t,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    if shared_keys.is_null() || new_skey.is_null() {
        return 22i32;
    }
    /* insert into an empty list? */
    if (*shared_keys).lh_first.is_null() {
        (*new_skey).next.le_next = (*shared_keys).lh_first;
        if !(*new_skey).next.le_next.is_null() {
            (*(*shared_keys).lh_first).next.le_prev = &mut (*new_skey).next.le_next
        }
        (*shared_keys).lh_first = new_skey;
        (*new_skey).next.le_prev = &mut (*shared_keys).lh_first;
        return 0i32;
    }
    /* insert into the existing list, ordered by key id */
    skey = (*shared_keys).lh_first;
    while !skey.is_null() {
        if ((*new_skey).keyid as libc::c_int) < (*skey).keyid as libc::c_int {
            /* insert it before here */
            (*new_skey).next.le_prev = (*skey).next.le_prev;
            (*new_skey).next.le_next = skey;
            *(*skey).next.le_prev = new_skey;
            (*skey).next.le_prev = &mut (*new_skey).next.le_next;
            return 0i32;
        } else {
            if (*new_skey).keyid as libc::c_int == (*skey).keyid as libc::c_int {
                /* replace the existing key */
                /* verify this key *can* be replaced */
                if (*skey).deactivated as libc::c_int != 0 || (*skey).refcount > 1u32 {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"can\'t replace shared key id %u\n\x00" as *const u8
                                    as *const libc::c_char,
                                (*new_skey).keyid as libc::c_int,
                            );
                        }
                    }
                    return 16i32;
                }
                if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"replacing shared key id %u\n\x00" as *const u8 as *const libc::c_char,
                            (*new_skey).keyid as libc::c_int,
                        );
                    }
                }
                (*new_skey).next.le_prev = (*skey).next.le_prev;
                (*new_skey).next.le_next = skey;
                *(*skey).next.le_prev = new_skey;
                (*skey).next.le_prev = &mut (*new_skey).next.le_next;
                if !(*skey).next.le_next.is_null() {
                    (*(*skey).next.le_next).next.le_prev = (*skey).next.le_prev
                }
                *(*skey).next.le_prev = (*skey).next.le_next;
                sctp_free_sharedkey(skey);
                return 0i32;
            }
        }
        if (*skey).next.le_next.is_null() {
            /* belongs at the end of the list */
            (*new_skey).next.le_next = (*skey).next.le_next;
            if !(*new_skey).next.le_next.is_null() {
                (*(*skey).next.le_next).next.le_prev = &mut (*new_skey).next.le_next
            }
            (*skey).next.le_next = new_skey;
            (*new_skey).next.le_prev = &mut (*skey).next.le_next;
            return 0i32;
        }
        skey = (*skey).next.le_next
    }
    /* shouldn't reach here */
    return 22i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_key_acquire(mut stcb: *mut sctp_tcb, mut key_id: uint16_t) {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    /* find the shared key */
    skey = sctp_find_sharedkey(&mut (*stcb).asoc.shared_keys, key_id);
    /* bump the ref count */
    if !skey.is_null() {
        ::std::intrinsics::atomic_xadd(&mut (*skey).refcount, 1u32);
        if system_base_info.sctpsysctl.sctp_debug_on & 0x800u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%s: stcb %p key %u refcount acquire to %d\n\x00" as *const u8
                        as *const libc::c_char,
                    (*::std::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"sctp_auth_key_acquire\x00",
                    ))
                    .as_ptr(),
                    stcb as *mut libc::c_void,
                    key_id as libc::c_int,
                    (*skey).refcount,
                );
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_key_release(
    mut stcb: *mut sctp_tcb,
    mut key_id: uint16_t,
    mut so_locked: libc::c_int,
) {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    /* find the shared key */
    skey = sctp_find_sharedkey(&mut (*stcb).asoc.shared_keys, key_id);
    /* decrement the ref count */
    if !skey.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x800u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%s: stcb %p key %u refcount release to %d\n\x00" as *const u8
                        as *const libc::c_char,
                    (*::std::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"sctp_auth_key_release\x00",
                    ))
                    .as_ptr(),
                    stcb as *mut libc::c_void,
                    key_id as libc::c_int,
                    (*skey).refcount,
                );
            }
        }
        /* see if a notification should be generated */
        if (*skey).refcount <= 2u32 && (*skey).deactivated as libc::c_int != 0 {
            /* notify ULP that key is no longer used */
            sctp_ulp_notify(
                24u32,
                stcb,
                key_id as uint32_t,
                0 as *mut libc::c_void,
                so_locked,
            );
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"%s: stcb %p key %u no longer used, %d\n\x00" as *const u8
                            as *const libc::c_char,
                        (*::std::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"sctp_auth_key_release\x00",
                        ))
                        .as_ptr(),
                        stcb as *mut libc::c_void,
                        key_id as libc::c_int,
                        (*skey).refcount,
                    );
                }
            }
        }
        sctp_free_sharedkey(skey);
    };
}
unsafe extern "C" fn sctp_copy_sharedkey(
    mut skey: *const sctp_sharedkey_t,
) -> *mut sctp_sharedkey_t {
    let mut new_skey = 0 as *mut sctp_sharedkey_t;
    if skey.is_null() {
        return 0 as *mut sctp_sharedkey_t;
    }
    new_skey = sctp_alloc_sharedkey();
    if new_skey.is_null() {
        return 0 as *mut sctp_sharedkey_t;
    }
    if !(*skey).key.is_null() {
        (*new_skey).key = sctp_set_key((*(*skey).key).key.as_mut_ptr(), (*(*skey).key).keylen)
    } else {
        (*new_skey).key = 0 as *mut sctp_key_t
    }
    (*new_skey).keyid = (*skey).keyid;
    return new_skey;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_copy_skeylist(
    mut src: *const sctp_keyhead,
    mut dest: *mut sctp_keyhead,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    let mut count = 0i32;
    if src.is_null() || dest.is_null() {
        return 0i32;
    }
    skey = (*src).lh_first;
    while !skey.is_null() {
        let mut new_skey = 0 as *mut sctp_sharedkey_t;
        new_skey = sctp_copy_sharedkey(skey);
        if !new_skey.is_null() {
            if sctp_insert_sharedkey(dest, new_skey) != 0 {
                sctp_free_sharedkey(new_skey);
            } else {
                count += 1
            }
        }
        skey = (*skey).next.le_next
    }
    return count;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_alloc_hmaclist(mut num_hmacs: uint16_t) -> *mut sctp_hmaclist_t {
    let mut new_list = 0 as *mut sctp_hmaclist_t;
    let mut alloc_size = 0;
    alloc_size = (::std::mem::size_of::<sctp_hmaclist_t>() as libc::c_ulong).wrapping_add(
        (num_hmacs as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong),
    ) as libc::c_int;
    new_list = malloc(alloc_size as u_long) as *mut sctp_hmaclist_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            new_list as *mut libc::c_void,
            0i32,
            alloc_size as libc::c_ulong,
        );
    }
    if new_list.is_null() {
        /* out of memory */
        return 0 as *mut sctp_hmaclist_t;
    }
    (*new_list).max_algo = num_hmacs;
    (*new_list).num_algo = 0u16;
    return new_list;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_hmaclist(mut list: *mut sctp_hmaclist_t) {
    if !list.is_null() {
        free(list as *mut libc::c_void);
        list = 0 as *mut sctp_hmaclist_t
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_add_hmacid(
    mut list: *mut sctp_hmaclist_t,
    mut hmac_id: uint16_t,
) -> libc::c_int {
    if list.is_null() {
        return -(1i32);
    }
    if (*list).num_algo as libc::c_int == (*list).max_algo as libc::c_int {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP: HMAC id list full, ignoring add %u\n\x00" as *const u8
                        as *const libc::c_char,
                    hmac_id as libc::c_int,
                );
            }
        }
        return -(1i32);
    }
    if hmac_id as libc::c_int != 0x1i32 {
        return -(1i32);
    }

    for i in 0i32..(*list).num_algo as libc::c_int {
        if *(*list).hmac.as_mut_ptr().offset(i as isize) as libc::c_int == hmac_id as libc::c_int {
            /* already in list */
            return -(1i32);
        }
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"SCTP: add HMAC id %u to list\n\x00" as *const u8 as *const libc::c_char,
                hmac_id as libc::c_int,
            );
        }
    }
    let fresh6 = (*list).num_algo;
    (*list).num_algo = (*list).num_algo.wrapping_add(1);
    *(*list).hmac.as_mut_ptr().offset(fresh6 as isize) = hmac_id;
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_copy_hmaclist(
    mut list: *mut sctp_hmaclist_t,
) -> *mut sctp_hmaclist_t {
    let mut new_list = 0 as *mut sctp_hmaclist_t;
    if list.is_null() {
        return 0 as *mut sctp_hmaclist_t;
    }
    /* get a new list */
    new_list = sctp_alloc_hmaclist((*list).max_algo);
    if new_list.is_null() {
        return 0 as *mut sctp_hmaclist_t;
    }
    /* copy it */
    (*new_list).max_algo = (*list).max_algo;
    (*new_list).num_algo = (*list).num_algo;

    for i in 0i32..(*list).num_algo as libc::c_int {
        *(*new_list).hmac.as_mut_ptr().offset(i as isize) =
            *(*list).hmac.as_mut_ptr().offset(i as isize);
    }
    return new_list;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_default_supported_hmaclist() -> *mut sctp_hmaclist_t {
    let mut new_list = 0 as *mut sctp_hmaclist_t;
    new_list = sctp_alloc_hmaclist(1u16);
    if new_list.is_null() {
        return 0 as *mut sctp_hmaclist_t;
    }
    sctp_auth_add_hmacid(new_list, 0x1u16);
    return new_list;
}
/*-
 * HMAC algos are listed in priority/preference order
 * find the best HMAC id to use for the peer based on local support
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_negotiate_hmacid(
    mut peer: *mut sctp_hmaclist_t,
    mut local: *mut sctp_hmaclist_t,
) -> uint16_t {
    if local.is_null() || peer.is_null() {
        return 0u16;
    }

    for i in 0i32..(*peer).num_algo as libc::c_int {
        for j in 0i32..(*local).num_algo as libc::c_int {
            if *(*peer).hmac.as_mut_ptr().offset(i as isize) as libc::c_int
                == *(*local).hmac.as_mut_ptr().offset(j as isize) as libc::c_int
            {
                /* found the "best" one */
                if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"SCTP: negotiated peer HMAC id %u\n\x00" as *const u8
                                as *const libc::c_char,
                            *(*peer).hmac.as_mut_ptr().offset(i as isize) as libc::c_int,
                        );
                    }
                }
                return *(*peer).hmac.as_mut_ptr().offset(i as isize);
            }
        }
    }
    /* didn't find one! */
    return 0u16;
}
/* ref counts on shared keys, by key id */
/* hmac list handling */
/*-
 * serialize the HMAC algo list and return space used
 * caller must guarantee ptr has appropriate space
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_serialize_hmaclist(
    mut list: *mut sctp_hmaclist_t,
    mut ptr: *mut uint8_t,
) -> libc::c_int {
    if list.is_null() {
        return 0i32;
    }

    for i in 0i32..(*list).num_algo as libc::c_int {
        let mut hmac_id = 0;
        hmac_id = htons(*(*list).hmac.as_mut_ptr().offset(i as isize));

        memcpy(
            ptr as *mut libc::c_void,
            &mut hmac_id as *mut uint16_t as *const libc::c_void,
            ::std::mem::size_of::<uint16_t>() as libc::c_ulong,
        );

        ptr = ptr.offset(::std::mem::size_of::<uint16_t>() as isize);
    }
    return ((*list).num_algo as libc::c_ulong)
        .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong)
        as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_verify_hmac_param(
    mut hmacs: *mut sctp_auth_hmac_algo,
    mut num_hmacs: uint32_t,
) -> libc::c_int {
    let mut i = 0;
    i = 0u32;
    while i < num_hmacs {
        if ntohs(*(*hmacs).hmac_ids.as_mut_ptr().offset(i as isize)) as libc::c_int == 0x1i32 {
            return 0i32;
        }
        i = i.wrapping_add(1)
    }
    return -(1i32);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_alloc_authinfo() -> *mut sctp_authinfo_t {
    let mut new_authinfo = 0 as *mut sctp_authinfo_t;
    new_authinfo =
        malloc(::std::mem::size_of::<sctp_authinfo_t>() as libc::c_ulong) as *mut sctp_authinfo_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            new_authinfo as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_authinfo_t>() as libc::c_ulong,
        );
    }
    if new_authinfo.is_null() {
        /* out of memory */
        return 0 as *mut sctp_authinfo_t;
    }
    memset(
        new_authinfo as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_authinfo_t>() as libc::c_ulong,
    );
    return new_authinfo;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_authinfo(mut authinfo: *mut sctp_authinfo_t) {
    if authinfo.is_null() {
        return;
    }
    if !(*authinfo).random.is_null() {
        sctp_free_key((*authinfo).random);
    }
    if !(*authinfo).peer_random.is_null() {
        sctp_free_key((*authinfo).peer_random);
    }
    if !(*authinfo).assoc_key.is_null() {
        sctp_free_key((*authinfo).assoc_key);
    }
    if !(*authinfo).recv_key.is_null() {
        sctp_free_key((*authinfo).recv_key);
    };
    /* We are NOT dynamically allocating authinfo's right now... */
    /* SCTP_FREE(authinfo, SCTP_M_AUTH_??); */
}
/* keyed-HMAC functions */
#[no_mangle]
pub unsafe extern "C" fn sctp_get_auth_chunk_len(mut hmac_algo: uint16_t) -> uint32_t {
    let mut size = 0;
    size = (::std::mem::size_of::<sctp_auth_chunk>() as libc::c_ulong)
        .wrapping_add(sctp_get_hmac_digest_len(hmac_algo) as libc::c_ulong)
        as libc::c_int;
    return ((size + 3i32 >> 2i32) << 2i32) as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_get_hmac_digest_len(mut hmac_algo: uint16_t) -> uint32_t {
    match hmac_algo as libc::c_int {
        1 => return 20u32,
        _ => {
            /* unknown HMAC algorithm: can't do anything */
            return 0u32;
        }
    };
    /* end switch */
}
#[inline]
unsafe extern "C" fn sctp_get_hmac_block_len(mut hmac_algo: uint16_t) -> libc::c_int {
    match hmac_algo as libc::c_int {
        1 => return 64i32,
        0 | _ => {
            /* unknown HMAC algorithm: can't do anything */
            return 0i32;
        }
    };
    /* end switch */
}
/* __Userspace__ SHA1_Init is defined in libcrypto.a (libssl-dev on Ubuntu) */
unsafe extern "C" fn sctp_hmac_init(mut hmac_algo: uint16_t, mut ctx: *mut sctp_hash_context_t) {
    match hmac_algo as libc::c_int {
        1 => {
            sctp_sha1_init(&mut (*ctx).sha1);
        }
        0 | _ => {
            /* unknown HMAC algorithm: can't do anything */
            return;
        }
    };
    /* end switch */
}
unsafe extern "C" fn sctp_hmac_update(
    mut hmac_algo: uint16_t,
    mut ctx: *mut sctp_hash_context_t,
    mut text: *mut uint8_t,
    mut textlen: uint32_t,
) {
    match hmac_algo as libc::c_int {
        1 => {
            sctp_sha1_update(&mut (*ctx).sha1, text, textlen);
        }
        0 | _ => {
            /* unknown HMAC algorithm: can't do anything */
            return;
        }
    };
    /* end switch */
}
unsafe extern "C" fn sctp_hmac_final(
    mut hmac_algo: uint16_t,
    mut ctx: *mut sctp_hash_context_t,
    mut digest: *mut uint8_t,
) {
    match hmac_algo as libc::c_int {
        1 => {
            sctp_sha1_final(digest, &mut (*ctx).sha1);
        }
        0 | _ => {
            /* unknown HMAC algorithm: can't do anything */
            return;
        }
    };
    /* end switch */
}
/*-
 * Keyed-Hashing for Message Authentication: FIPS 198 (RFC 2104)
 *
 * Compute the HMAC digest using the desired hash key, text, and HMAC
 * algorithm.  Resulting digest is placed in 'digest' and digest length
 * is returned, if the HMAC was performed.
 *
 * WARNING: it is up to the caller to supply sufficient space to hold the
 * resultant digest.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_hmac(
    mut hmac_algo: uint16_t,
    mut key: *mut uint8_t,
    mut keylen: uint32_t,
    mut text: *mut uint8_t,
    mut textlen: uint32_t,
    mut digest: *mut uint8_t,
) -> uint32_t {
    let mut digestlen = 0;
    let mut blocklen = 0;
    let mut ctx = sctp_hash_context {
        sha1: sctp_sha1_context {
            A: 0,
            B: 0,
            C: 0,
            D: 0,
            E: 0,
            H0: 0,
            H1: 0,
            H2: 0,
            H3: 0,
            H4: 0,
            words: [0; 80],
            TEMP: 0,
            sha_block: [0; 64],
            how_many_in_block: 0,
            running_total: 0,
        },
    };
    let mut ipad = [0; 128];
    let mut opad = [0; 128];
    let mut temp = [0; 32];
    let mut i = 0;
    /* sanity check the material and length */
    if key.is_null() || keylen == 0u32 || text.is_null() || textlen == 0u32 || digest.is_null() {
        /* can't do HMAC with empty key or text or digest store */
        return 0u32;
    }
    /* validate the hmac algo and get the digest length */
    digestlen = sctp_get_hmac_digest_len(hmac_algo);
    if digestlen == 0u32 {
        return 0u32;
    }
    /* hash the key if it is longer than the hash block size */
    blocklen = sctp_get_hmac_block_len(hmac_algo) as uint32_t;
    if keylen > blocklen {
        sctp_hmac_init(hmac_algo, &mut ctx);
        sctp_hmac_update(hmac_algo, &mut ctx, key, keylen);
        sctp_hmac_final(hmac_algo, &mut ctx, temp.as_mut_ptr());
        /* set the hashed key as the key */
        keylen = digestlen;
        key = temp.as_mut_ptr()
    }
    /* initialize the inner/outer pads with the key and "append" zeroes */
    memset(
        ipad.as_mut_ptr() as *mut libc::c_void,
        0i32,
        blocklen as libc::c_ulong,
    );
    memset(
        opad.as_mut_ptr() as *mut libc::c_void,
        0i32,
        blocklen as libc::c_ulong,
    );
    memcpy(
        ipad.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        keylen as libc::c_ulong,
    );
    memcpy(
        opad.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        keylen as libc::c_ulong,
    );
    /* XOR the key with ipad and opad values */
    i = 0u32;
    while i < blocklen {
        ipad[i as usize] = (ipad[i as usize] as libc::c_int ^ 0x36i32) as uint8_t;
        opad[i as usize] = (opad[i as usize] as libc::c_int ^ 0x5ci32) as uint8_t;
        i = i.wrapping_add(1)
    }
    /* perform inner hash */
    sctp_hmac_init(hmac_algo, &mut ctx);
    sctp_hmac_update(hmac_algo, &mut ctx, ipad.as_mut_ptr(), blocklen);
    sctp_hmac_update(hmac_algo, &mut ctx, text, textlen);
    sctp_hmac_final(hmac_algo, &mut ctx, temp.as_mut_ptr());
    /* perform outer hash */
    sctp_hmac_init(hmac_algo, &mut ctx);
    sctp_hmac_update(hmac_algo, &mut ctx, opad.as_mut_ptr(), blocklen);
    sctp_hmac_update(hmac_algo, &mut ctx, temp.as_mut_ptr(), digestlen);
    sctp_hmac_final(hmac_algo, &mut ctx, digest);
    return digestlen;
}
/* mbuf version */
#[no_mangle]
pub unsafe extern "C" fn sctp_hmac_m(
    mut hmac_algo: uint16_t,
    mut key: *mut uint8_t,
    mut keylen: uint32_t,
    mut m: *mut mbuf,
    mut m_offset: uint32_t,
    mut digest: *mut uint8_t,
    mut trailer: uint32_t,
) -> uint32_t {
    let mut digestlen = 0;
    let mut blocklen = 0;
    let mut ctx = sctp_hash_context {
        sha1: sctp_sha1_context {
            A: 0,
            B: 0,
            C: 0,
            D: 0,
            E: 0,
            H0: 0,
            H1: 0,
            H2: 0,
            H3: 0,
            H4: 0,
            words: [0; 80],
            TEMP: 0,
            sha_block: [0; 64],
            how_many_in_block: 0,
            running_total: 0,
        },
    };
    let mut ipad = [0; 128];
    let mut opad = [0; 128];
    let mut temp = [0; 32];
    let mut i = 0;
    let mut m_tmp = 0 as *mut mbuf;
    /* sanity check the material and length */
    if key.is_null() || keylen == 0u32 || m.is_null() || digest.is_null() {
        /* can't do HMAC with empty key or text or digest store */
        return 0u32;
    }
    /* validate the hmac algo and get the digest length */
    digestlen = sctp_get_hmac_digest_len(hmac_algo);
    if digestlen == 0u32 {
        return 0u32;
    }
    /* hash the key if it is longer than the hash block size */
    blocklen = sctp_get_hmac_block_len(hmac_algo) as uint32_t;
    if keylen > blocklen {
        sctp_hmac_init(hmac_algo, &mut ctx);
        sctp_hmac_update(hmac_algo, &mut ctx, key, keylen);
        sctp_hmac_final(hmac_algo, &mut ctx, temp.as_mut_ptr());
        /* set the hashed key as the key */
        keylen = digestlen;
        key = temp.as_mut_ptr()
    }
    /* initialize the inner/outer pads with the key and "append" zeroes */
    memset(
        ipad.as_mut_ptr() as *mut libc::c_void,
        0i32,
        blocklen as libc::c_ulong,
    );
    memset(
        opad.as_mut_ptr() as *mut libc::c_void,
        0i32,
        blocklen as libc::c_ulong,
    );
    memcpy(
        ipad.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        keylen as libc::c_ulong,
    );
    memcpy(
        opad.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        keylen as libc::c_ulong,
    );
    /* XOR the key with ipad and opad values */
    i = 0u32;
    while i < blocklen {
        ipad[i as usize] = (ipad[i as usize] as libc::c_int ^ 0x36i32) as uint8_t;
        opad[i as usize] = (opad[i as usize] as libc::c_int ^ 0x5ci32) as uint8_t;
        i = i.wrapping_add(1)
    }
    /* perform inner hash */
    sctp_hmac_init(hmac_algo, &mut ctx);
    sctp_hmac_update(hmac_algo, &mut ctx, ipad.as_mut_ptr(), blocklen);
    /* find the correct starting mbuf and offset (get start of text) */
    m_tmp = m;
    while !m_tmp.is_null() && m_offset >= (*m_tmp).m_hdr.mh_len as uint32_t {
        m_offset = (m_offset).wrapping_sub((*m_tmp).m_hdr.mh_len as libc::c_uint);
        m_tmp = (*m_tmp).m_hdr.mh_next
    }
    /* now use the rest of the mbuf chain for the text */
    while !m_tmp.is_null() {
        if (*m_tmp).m_hdr.mh_next.is_null() && trailer != 0 {
            sctp_hmac_update(
                hmac_algo,
                &mut ctx,
                ((*m_tmp).m_hdr.mh_data as *mut uint8_t).offset(m_offset as isize),
                ((*m_tmp).m_hdr.mh_len as libc::c_uint)
                    .wrapping_sub(trailer.wrapping_add(m_offset)),
            );
        } else {
            sctp_hmac_update(
                hmac_algo,
                &mut ctx,
                ((*m_tmp).m_hdr.mh_data as *mut uint8_t).offset(m_offset as isize),
                ((*m_tmp).m_hdr.mh_len as libc::c_uint).wrapping_sub(m_offset),
            );
        }
        /* clear the offset since it's only for the first mbuf */
        m_offset = 0u32;
        m_tmp = (*m_tmp).m_hdr.mh_next
    }
    sctp_hmac_final(hmac_algo, &mut ctx, temp.as_mut_ptr());
    /* perform outer hash */
    sctp_hmac_init(hmac_algo, &mut ctx);
    sctp_hmac_update(hmac_algo, &mut ctx, opad.as_mut_ptr(), blocklen);
    sctp_hmac_update(hmac_algo, &mut ctx, temp.as_mut_ptr(), digestlen);
    sctp_hmac_final(hmac_algo, &mut ctx, digest);
    return digestlen;
}
/*
 * computes the requested HMAC using a key struct (which may be modified if
 * the keylen exceeds the HMAC block len).
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_compute_hmac(
    mut hmac_algo: uint16_t,
    mut key: *mut sctp_key_t,
    mut text: *mut uint8_t,
    mut textlen: uint32_t,
    mut digest: *mut uint8_t,
) -> uint32_t {
    let mut digestlen = 0;
    let mut blocklen = 0;
    /* sanity check */
    if key.is_null() || text.is_null() || textlen == 0u32 || digest.is_null() {
        /* can't do HMAC with empty key or text or digest store */
        return 0u32;
    }
    /* validate the hmac algo and get the digest length */
    digestlen = sctp_get_hmac_digest_len(hmac_algo);
    if digestlen == 0u32 {
        return 0u32;
    }
    /* hash the key if it is longer than the hash block size */
    blocklen = sctp_get_hmac_block_len(hmac_algo) as uint32_t;
    if (*key).keylen > blocklen {
        let mut ctx = sctp_hash_context {
            sha1: sctp_sha1_context {
                A: 0,
                B: 0,
                C: 0,
                D: 0,
                E: 0,
                H0: 0,
                H1: 0,
                H2: 0,
                H3: 0,
                H4: 0,
                words: [0; 80],
                TEMP: 0,
                sha_block: [0; 64],
                how_many_in_block: 0,
                running_total: 0,
            },
        };
        let mut temp = [0; 32];
        sctp_hmac_init(hmac_algo, &mut ctx);
        sctp_hmac_update(hmac_algo, &mut ctx, (*key).key.as_mut_ptr(), (*key).keylen);
        sctp_hmac_final(hmac_algo, &mut ctx, temp.as_mut_ptr());
        /* save the hashed key as the new key */
        (*key).keylen = digestlen;
        memcpy(
            (*key).key.as_mut_ptr() as *mut libc::c_void,
            temp.as_mut_ptr() as *const libc::c_void,
            (*key).keylen as libc::c_ulong,
        );
    }
    return sctp_hmac(
        hmac_algo,
        (*key).key.as_mut_ptr(),
        (*key).keylen,
        text,
        textlen,
        digest,
    );
}
/* mbuf version */
#[no_mangle]
pub unsafe extern "C" fn sctp_compute_hmac_m(
    mut hmac_algo: uint16_t,
    mut key: *mut sctp_key_t,
    mut m: *mut mbuf,
    mut m_offset: uint32_t,
    mut digest: *mut uint8_t,
) -> uint32_t {
    let mut digestlen = 0;
    let mut blocklen = 0;
    /* sanity check */
    if key.is_null() || m.is_null() || digest.is_null() {
        /* can't do HMAC with empty key or text or digest store */
        return 0u32;
    }
    /* validate the hmac algo and get the digest length */
    digestlen = sctp_get_hmac_digest_len(hmac_algo);
    if digestlen == 0u32 {
        return 0u32;
    }
    /* hash the key if it is longer than the hash block size */
    blocklen = sctp_get_hmac_block_len(hmac_algo) as uint32_t;
    if (*key).keylen > blocklen {
        let mut ctx = sctp_hash_context {
            sha1: sctp_sha1_context {
                A: 0,
                B: 0,
                C: 0,
                D: 0,
                E: 0,
                H0: 0,
                H1: 0,
                H2: 0,
                H3: 0,
                H4: 0,
                words: [0; 80],
                TEMP: 0,
                sha_block: [0; 64],
                how_many_in_block: 0,
                running_total: 0,
            },
        };
        let mut temp = [0; 32];
        sctp_hmac_init(hmac_algo, &mut ctx);
        sctp_hmac_update(hmac_algo, &mut ctx, (*key).key.as_mut_ptr(), (*key).keylen);
        sctp_hmac_final(hmac_algo, &mut ctx, temp.as_mut_ptr());
        /* save the hashed key as the new key */
        (*key).keylen = digestlen;
        memcpy(
            (*key).key.as_mut_ptr() as *mut libc::c_void,
            temp.as_mut_ptr() as *const libc::c_void,
            (*key).keylen as libc::c_ulong,
        );
    }
    return sctp_hmac_m(
        hmac_algo,
        (*key).key.as_mut_ptr(),
        (*key).keylen,
        m,
        m_offset,
        digest,
        0u32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_is_supported_hmac(
    mut list: *mut sctp_hmaclist_t,
    mut id: uint16_t,
) -> libc::c_int {
    if list.is_null() || id as libc::c_int == 0i32 {
        return 0i32;
    }

    for i in 0i32..(*list).num_algo as libc::c_int {
        if *(*list).hmac.as_mut_ptr().offset(i as isize) as libc::c_int == id as libc::c_int {
            return 1i32;
        }
    }
    /* not in the list */
    return 0i32;
}
/*-
 * clear any cached key(s) if they match the given key id on an association.
 * the cached key(s) will be recomputed and re-cached at next use.
 * ASSUMES TCB_LOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_clear_cachedkeys(mut stcb: *mut sctp_tcb, mut keyid: uint16_t) {
    if stcb.is_null() {
        return;
    }
    if keyid as libc::c_int == (*stcb).asoc.authinfo.assoc_keyid as libc::c_int {
        sctp_free_key((*stcb).asoc.authinfo.assoc_key);
        (*stcb).asoc.authinfo.assoc_key = 0 as *mut sctp_key_t
    }
    if keyid as libc::c_int == (*stcb).asoc.authinfo.recv_keyid as libc::c_int {
        sctp_free_key((*stcb).asoc.authinfo.recv_key);
        (*stcb).asoc.authinfo.recv_key = 0 as *mut sctp_key_t
    };
}
/*-
 * clear any cached key(s) if they match the given key id for all assocs on
 * an endpoint.
 * ASSUMES INP_WLOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_clear_cachedkeys_ep(mut inp: *mut sctp_inpcb, mut keyid: uint16_t) {
    let mut stcb = 0 as *mut sctp_tcb;
    if inp.is_null() {
        return;
    }
    /* clear the cached keys on all assocs on this instance */
    stcb = (*inp).sctp_asoc_list.lh_first;
    while !stcb.is_null() {
        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
        sctp_clear_cachedkeys(stcb, keyid);
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        stcb = (*stcb).sctp_tcblist.le_next
    }
}
/*-
 * delete a shared key from an association
 * ASSUMES TCB_LOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_delete_sharedkey(
    mut stcb: *mut sctp_tcb,
    mut keyid: uint16_t,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    if stcb.is_null() {
        return -(1i32);
    }
    /* is the keyid the assoc active sending key */
    if keyid as libc::c_int == (*stcb).asoc.authinfo.active_keyid as libc::c_int {
        return -(1i32);
    }
    /* does the key exist? */
    skey = sctp_find_sharedkey(&mut (*stcb).asoc.shared_keys, keyid);
    if skey.is_null() {
        return -(1i32);
    }
    /* are there other refcount holders on the key? */
    if (*skey).refcount > 1u32 {
        return -(1i32);
    }
    /* remove it */
    if !(*skey).next.le_next.is_null() {
        (*(*skey).next.le_next).next.le_prev = (*skey).next.le_prev
    } /* frees skey->key as well */
    *(*skey).next.le_prev = (*skey).next.le_next;
    sctp_free_sharedkey(skey);
    /* clear any cached keys */
    sctp_clear_cachedkeys(stcb, keyid);
    return 0i32;
}
/*-
 * deletes a shared key from the endpoint
 * ASSUMES INP_WLOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_delete_sharedkey_ep(
    mut inp: *mut sctp_inpcb,
    mut keyid: uint16_t,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    if inp.is_null() {
        return -(1i32);
    }
    /* is the keyid the active sending key on the endpoint */
    if keyid as libc::c_int == (*inp).sctp_ep.default_keyid as libc::c_int {
        return -(1i32);
    }
    /* does the key exist? */
    skey = sctp_find_sharedkey(&mut (*inp).sctp_ep.shared_keys, keyid);
    if skey.is_null() {
        return -(1i32);
    }
    /* endpoint keys are not refcounted */
    /* remove it */
    if !(*skey).next.le_next.is_null() {
        (*(*skey).next.le_next).next.le_prev = (*skey).next.le_prev
    } /* frees skey->key as well */
    *(*skey).next.le_prev = (*skey).next.le_next;
    sctp_free_sharedkey(skey);
    /* clear any cached keys */
    sctp_clear_cachedkeys_ep(inp, keyid);
    return 0i32;
}
/*-
 * set the active key on an association
 * ASSUMES TCB_LOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_setactivekey(
    mut stcb: *mut sctp_tcb,
    mut keyid: uint16_t,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    /* find the key on the assoc */
    skey = sctp_find_sharedkey(&mut (*stcb).asoc.shared_keys, keyid);
    if skey.is_null() {
        /* that key doesn't exist */
        return -(1i32);
    }
    if (*skey).deactivated as libc::c_int != 0 && (*skey).refcount > 1u32 {
        /* can't reactivate a deactivated key with other refcounts */
        return -(1i32);
    }
    /* set the (new) active key */
    (*stcb).asoc.authinfo.active_keyid = keyid;
    /* reset the deactivated flag */
    (*skey).deactivated = 0u8;
    return 0i32;
}
/*-
 * set the active key on an endpoint
 * ASSUMES INP_WLOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_setactivekey_ep(
    mut inp: *mut sctp_inpcb,
    mut keyid: uint16_t,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    /* find the key */
    skey = sctp_find_sharedkey(&mut (*inp).sctp_ep.shared_keys, keyid);
    if skey.is_null() {
        /* that key doesn't exist */
        return -(1i32);
    }
    (*inp).sctp_ep.default_keyid = keyid;
    return 0i32;
}
/*-
 * deactivates a shared key from the association
 * ASSUMES INP_WLOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_deact_sharedkey(
    mut stcb: *mut sctp_tcb,
    mut keyid: uint16_t,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    if stcb.is_null() {
        return -(1i32);
    }
    /* is the keyid the assoc active sending key */
    if keyid as libc::c_int == (*stcb).asoc.authinfo.active_keyid as libc::c_int {
        return -(1i32);
    }
    /* does the key exist? */
    skey = sctp_find_sharedkey(&mut (*stcb).asoc.shared_keys, keyid);
    if skey.is_null() {
        return -(1i32);
    }
    /* are there other refcount holders on the key? */
    if (*skey).refcount == 1u32 {
        /* no other users, send a notification for this key */
        sctp_ulp_notify(24u32, stcb, keyid as uint32_t, 0 as *mut libc::c_void, 1i32);
    }
    /* mark the key as deactivated */
    (*skey).deactivated = 1u8;
    return 0i32;
}
/*-
 * deactivates a shared key from the endpoint
 * ASSUMES INP_WLOCK is already held
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_deact_sharedkey_ep(
    mut inp: *mut sctp_inpcb,
    mut keyid: uint16_t,
) -> libc::c_int {
    let mut skey = 0 as *mut sctp_sharedkey_t;
    if inp.is_null() {
        return -(1i32);
    }
    /* is the keyid the active sending key on the endpoint */
    if keyid as libc::c_int == (*inp).sctp_ep.default_keyid as libc::c_int {
        return -(1i32);
    }
    /* does the key exist? */
    skey = sctp_find_sharedkey(&mut (*inp).sctp_ep.shared_keys, keyid);
    if skey.is_null() {
        return -(1i32);
    }
    /* endpoint keys are not refcounted */
    /* remove it */
    if !(*skey).next.le_next.is_null() {
        (*(*skey).next.le_next).next.le_prev = (*skey).next.le_prev
    } /* frees skey->key as well */
    *(*skey).next.le_prev = (*skey).next.le_next;
    sctp_free_sharedkey(skey);
    return 0i32;
}
/*
 * get local authentication parameters from cookie (from INIT-ACK)
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_auth_get_cookie_params(
    mut stcb: *mut sctp_tcb,
    mut m: *mut mbuf,
    mut offset: uint32_t,
    mut length: uint32_t,
) {
    let mut phdr = 0 as *mut sctp_paramhdr;
    let mut tmp_param = sctp_paramhdr {
        param_type: 0,
        param_length: 0,
    };
    let mut p_random = 0 as *mut sctp_auth_random;
    let mut random_len = 0u16;
    let mut hmacs = 0 as *mut sctp_auth_hmac_algo;
    let mut hmacs_len = 0u16;
    let mut chunks = 0 as *mut sctp_auth_chunk_list;
    let mut num_chunks = 0u16;
    let mut new_key = 0 as *mut sctp_key_t;
    let mut keylen = 0;
    /* convert to upper bound */
    length = (length).wrapping_add(offset);
    phdr = sctp_m_getptr(
        m,
        offset as libc::c_int,
        ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
        &mut tmp_param as *mut sctp_paramhdr as *mut uint8_t,
    ) as *mut sctp_paramhdr;
    while !phdr.is_null() {
        let mut plen = 0;
        let mut ptype = 0;
        ptype = ntohs((*phdr).param_type);
        plen = ntohs((*phdr).param_length);
        if (plen as libc::c_ulong) < ::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong
            || offset.wrapping_add(plen as libc::c_uint) > length
        {
            break;
        }
        if ptype as libc::c_int == 0x8002i32 {
            let mut random_store = [0; 512];
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                break;
            }
            phdr = sctp_get_next_param(
                m,
                offset as libc::c_int,
                random_store.as_mut_ptr() as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return;
            }
            /* save the random and length for the key */
            p_random = phdr as *mut sctp_auth_random;
            random_len = (plen as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctp_auth_random>() as libc::c_ulong)
                as uint16_t
        } else if ptype as libc::c_int == 0x8004i32 {
            let mut hmacs_store = [0; 512];
            let mut num_hmacs = 0;
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                break;
            }
            phdr = sctp_get_next_param(
                m,
                offset as libc::c_int,
                hmacs_store.as_mut_ptr() as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return;
            }
            /* save the hmacs list and num for the key */
            hmacs = phdr as *mut sctp_auth_hmac_algo;
            hmacs_len = (plen as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctp_auth_hmac_algo>() as libc::c_ulong)
                as uint16_t;
            num_hmacs = (hmacs_len as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<uint16_t>() as libc::c_ulong)
                as uint16_t;
            if !(*stcb).asoc.local_hmacs.is_null() {
                sctp_free_hmaclist((*stcb).asoc.local_hmacs);
            }
            (*stcb).asoc.local_hmacs = sctp_alloc_hmaclist(num_hmacs);
            if !(*stcb).asoc.local_hmacs.is_null() {
                let mut i = 0;
                i = 0u16;
                while (i as libc::c_int) < num_hmacs as libc::c_int {
                    sctp_auth_add_hmacid(
                        (*stcb).asoc.local_hmacs,
                        ntohs(*(*hmacs).hmac_ids.as_mut_ptr().offset(i as isize)),
                    );
                    i = i.wrapping_add(1)
                }
            }
        } else if ptype as libc::c_int == 0x8003i32 {
            let mut chunks_store = [0; 512];
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                break;
            }
            phdr = sctp_get_next_param(
                m,
                offset as libc::c_int,
                chunks_store.as_mut_ptr() as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return;
            }
            chunks = phdr as *mut sctp_auth_chunk_list;
            num_chunks = (plen as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctp_auth_chunk_list>() as libc::c_ulong)
                as uint16_t;
            /* save chunks list and num for the key */
            if !(*stcb).asoc.local_auth_chunks.is_null() {
                sctp_clear_chunklist((*stcb).asoc.local_auth_chunks);
            } else {
                (*stcb).asoc.local_auth_chunks = sctp_alloc_chunklist()
            }

            for i_0 in 0i32..num_chunks as libc::c_int {
                sctp_auth_add_chunk(
                    *(*chunks).chunk_types.as_mut_ptr().offset(i_0 as isize),
                    (*stcb).asoc.local_auth_chunks,
                );
            }
        }
        /* get next parameter */
        offset =
            (offset).wrapping_add(((plen as libc::c_int + 3i32 >> 2i32) << 2i32) as libc::c_uint);
        if (offset as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            > length as libc::c_ulong
        {
            break;
        }
        phdr = sctp_m_getptr(
            m,
            offset as libc::c_int,
            ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
            &mut tmp_param as *mut sctp_paramhdr as *mut uint8_t,
        ) as *mut sctp_paramhdr
    }
    /* concatenate the full random key */
    keylen = (::std::mem::size_of::<sctp_auth_random>() as libc::c_ulong)
        .wrapping_add(random_len as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_auth_hmac_algo>() as libc::c_ulong)
        .wrapping_add(hmacs_len as libc::c_ulong) as uint32_t;
    if !chunks.is_null() {
        keylen = (keylen as libc::c_ulong).wrapping_add(
            (::std::mem::size_of::<sctp_auth_chunk_list>() as libc::c_ulong)
                .wrapping_add(num_chunks as libc::c_ulong),
        ) as uint32_t
    }
    new_key = sctp_alloc_key(keylen);
    if !new_key.is_null() {
        /* copy in the RANDOM */
        if !p_random.is_null() {
            keylen = (::std::mem::size_of::<sctp_auth_random>() as libc::c_ulong)
                .wrapping_add(random_len as libc::c_ulong) as uint32_t;
            memcpy(
                (*new_key).key.as_mut_ptr() as *mut libc::c_void,
                p_random as *const libc::c_void,
                keylen as libc::c_ulong,
            );
        } else {
            keylen = 0u32
        }
        /* append in the AUTH chunks */
        if !chunks.is_null() {
            memcpy(
                (*new_key).key.as_mut_ptr().offset(keylen as isize) as *mut libc::c_void,
                chunks as *const libc::c_void,
                (::std::mem::size_of::<sctp_auth_chunk_list>() as libc::c_ulong)
                    .wrapping_add(num_chunks as libc::c_ulong),
            );
            keylen = (keylen as libc::c_ulong).wrapping_add(
                (::std::mem::size_of::<sctp_auth_chunk_list>() as libc::c_ulong)
                    .wrapping_add(num_chunks as libc::c_ulong),
            ) as uint32_t
        }
        /* append in the HMACs */
        if !hmacs.is_null() {
            memcpy(
                (*new_key).key.as_mut_ptr().offset(keylen as isize) as *mut libc::c_void,
                hmacs as *const libc::c_void,
                (::std::mem::size_of::<sctp_auth_hmac_algo>() as libc::c_ulong)
                    .wrapping_add(hmacs_len as libc::c_ulong),
            );
        }
    }
    if !(*stcb).asoc.authinfo.random.is_null() {
        sctp_free_key((*stcb).asoc.authinfo.random);
    }
    (*stcb).asoc.authinfo.random = new_key;
    (*stcb).asoc.authinfo.random_len = random_len as uint32_t;
    sctp_clear_cachedkeys(stcb, (*stcb).asoc.authinfo.assoc_keyid);
    sctp_clear_cachedkeys(stcb, (*stcb).asoc.authinfo.recv_keyid);
    /* negotiate what HMAC to use for the peer */
    (*stcb).asoc.peer_hmac_id =
        sctp_negotiate_hmacid((*stcb).asoc.peer_hmacs, (*stcb).asoc.local_hmacs);
    /* copy defaults from the endpoint */
    /* FIX ME: put in cookie? */
    (*stcb).asoc.authinfo.active_keyid = (*(*stcb).sctp_ep).sctp_ep.default_keyid;
    /* copy out the shared key list (by reference) from the endpoint */
    sctp_copy_skeylist(
        &mut (*(*stcb).sctp_ep).sctp_ep.shared_keys,
        &mut (*stcb).asoc.shared_keys,
    );
}
/*
 * compute and fill in the HMAC digest for a packet
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_fill_hmac_digest_m(
    mut m: *mut mbuf,
    mut auth_offset: uint32_t,
    mut auth: *mut sctp_auth_chunk,
    mut stcb: *mut sctp_tcb,
    mut keyid: uint16_t,
) {
    let mut digestlen = 0;
    if stcb.is_null() || auth.is_null() {
        return;
    }
    /* zero the digest + chunk padding */
    digestlen = sctp_get_hmac_digest_len((*stcb).asoc.peer_hmac_id);
    memset(
        (*auth).hmac.as_mut_ptr() as *mut libc::c_void,
        0i32,
        ((digestlen.wrapping_add(3u32) >> 2i32) << 2i32) as libc::c_ulong,
    );
    /* is the desired key cached? */
    if keyid as libc::c_int != (*stcb).asoc.authinfo.assoc_keyid as libc::c_int
        || (*stcb).asoc.authinfo.assoc_key.is_null()
    {
        let mut skey = 0 as *mut sctp_sharedkey_t;
        let mut key = 0 as *mut sctp_key_t;
        if !(*stcb).asoc.authinfo.assoc_key.is_null() {
            /* free the old cached key */
            sctp_free_key((*stcb).asoc.authinfo.assoc_key);
        }
        skey = sctp_find_sharedkey(&mut (*stcb).asoc.shared_keys, keyid);
        /* the only way skey is NULL is if null key id 0 is used */
        if !skey.is_null() {
            key = (*skey).key
        } else {
            key = 0 as *mut sctp_key_t
        }
        /* compute a new assoc key and cache it */
        (*stcb).asoc.authinfo.assoc_key = sctp_compute_hashkey(
            (*stcb).asoc.authinfo.random,
            (*stcb).asoc.authinfo.peer_random,
            key,
        );
        (*stcb).asoc.authinfo.assoc_keyid = keyid;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"caching key id %u\n\x00" as *const u8 as *const libc::c_char,
                    (*stcb).asoc.authinfo.assoc_keyid as libc::c_int,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            sctp_print_key(
                (*stcb).asoc.authinfo.assoc_key,
                b"Assoc Key\x00" as *const u8 as *const libc::c_char,
            );
        }
    }
    /* set in the active key id */
    (*auth).shared_key_id = htons(keyid);
    /* compute and fill in the digest */
    sctp_compute_hmac_m(
        (*stcb).asoc.peer_hmac_id,
        (*stcb).asoc.authinfo.assoc_key,
        m,
        auth_offset,
        (*auth).hmac.as_mut_ptr(),
    );
}
unsafe extern "C" fn sctp_zero_m(mut m: *mut mbuf, mut m_offset: uint32_t, mut size: uint32_t) {
    let mut m_tmp = 0 as *mut mbuf;
    /* sanity check */
    if m.is_null() {
        return;
    }
    /* find the correct starting mbuf and offset (get start position) */
    m_tmp = m;
    while !m_tmp.is_null() && m_offset >= (*m_tmp).m_hdr.mh_len as uint32_t {
        m_offset = (m_offset).wrapping_sub((*m_tmp).m_hdr.mh_len as libc::c_uint);
        m_tmp = (*m_tmp).m_hdr.mh_next
    }
    /* now use the rest of the mbuf chain */
    while !m_tmp.is_null() && size > 0u32 {
        let mut data = 0 as *mut uint8_t;
        data = ((*m_tmp).m_hdr.mh_data as *mut uint8_t).offset(m_offset as isize);
        if size > ((*m_tmp).m_hdr.mh_len as libc::c_uint).wrapping_sub(m_offset) {
            memset(
                data as *mut libc::c_void,
                0i32,
                ((*m_tmp).m_hdr.mh_len as libc::c_uint).wrapping_sub(m_offset) as libc::c_ulong,
            );
            size =
                (size).wrapping_sub(((*m_tmp).m_hdr.mh_len as libc::c_uint).wrapping_sub(m_offset))
        } else {
            memset(data as *mut libc::c_void, 0i32, size as libc::c_ulong);
            size = 0u32
        }
        /* clear the offset since it's only for the first mbuf */
        m_offset = 0u32;
        m_tmp = (*m_tmp).m_hdr.mh_next
    }
}
/*-
 * process the incoming Authentication chunk
 * return codes:
 *   -1 on any authentication error
 *    0 on authentication verification
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_handle_auth(
    mut stcb: *mut sctp_tcb,
    mut auth: *mut sctp_auth_chunk,
    mut m: *mut mbuf,
    mut offset: uint32_t,
) -> libc::c_int {
    let mut chunklen = 0;
    let mut shared_key_id = 0;
    let mut hmac_id = 0;
    let mut digestlen = 0;
    let mut digest = [0; 32];
    let mut computed_digest = [0; 32];
    /* auth is checked for NULL by caller */
    chunklen = ntohs((*auth).ch.chunk_length);
    if (chunklen as libc::c_ulong) < ::std::mem::size_of::<sctp_auth_chunk>() as libc::c_ulong {
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvauthfailed, 1u32);
        return -(1i32);
    }
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvauth, 1u32);
    /* get the auth params */
    shared_key_id = ntohs((*auth).shared_key_id);
    hmac_id = ntohs((*auth).hmac_id);
    if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"SCTP AUTH Chunk: shared key %u, HMAC id %u\n\x00" as *const u8
                    as *const libc::c_char,
                shared_key_id as libc::c_int,
                hmac_id as libc::c_int,
            );
        }
    }
    /* is the indicated HMAC supported? */
    if sctp_auth_is_supported_hmac((*stcb).asoc.local_hmacs, hmac_id) == 0 {
        let mut op_err = 0 as *mut mbuf;
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvivalhmacid, 1u32);
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP Auth: unsupported HMAC id %u\n\x00" as *const u8 as *const libc::c_char,
                    hmac_id as libc::c_int,
                );
            }
        }
        /*
         * report this in an Error Chunk: Unsupported HMAC
         * Identifier
         */
        op_err = sctp_get_mbuf_for_msg(
            ::std::mem::size_of::<sctp_error_auth_invalid_hmac>() as libc::c_uint,
            0i32,
            0x1i32,
            1i32,
            1i32,
        );
        if !op_err.is_null() {
            let mut cause = 0 as *mut sctp_error_auth_invalid_hmac;
            (*op_err).m_hdr.mh_data = (*op_err)
                .m_hdr
                .mh_data
                .offset(::std::mem::size_of::<sctp_chunkhdr>() as isize);
            /* fill in the error */
            cause = (*op_err).m_hdr.mh_data as *mut sctp_error_auth_invalid_hmac;
            (*cause).cause.code = htons(0x105u16);
            (*cause).cause.length =
                htons(::std::mem::size_of::<sctp_error_auth_invalid_hmac>() as uint16_t);
            (*cause).hmac_id = ntohs(hmac_id);
            (*op_err).m_hdr.mh_len =
                ::std::mem::size_of::<sctp_error_auth_invalid_hmac>() as libc::c_int;
            /* queue it */
            sctp_queue_op_err(stcb, op_err);
        }
        return -(1i32);
    }
    /* get the indicated shared key, if available */
    if (*stcb).asoc.authinfo.recv_key.is_null()
        || (*stcb).asoc.authinfo.recv_keyid as libc::c_int != shared_key_id as libc::c_int
    {
        let mut skey = 0 as *mut sctp_sharedkey_t;
        skey = sctp_find_sharedkey(&mut (*stcb).asoc.shared_keys, shared_key_id);
        /* if the shared key isn't found, discard the chunk */
        if skey.is_null() {
            ::std::intrinsics::atomic_xadd(
                &mut system_base_info.sctpstat.sctps_recvivalkeyid,
                1u32,
            );
            if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"SCTP Auth: unknown key id %u\n\x00" as *const u8 as *const libc::c_char,
                        shared_key_id as libc::c_int,
                    );
                }
            }
            return -(1i32);
        }
        /* generate a notification if this is a new key id */
        if (*stcb).asoc.authinfo.recv_keyid as libc::c_int != shared_key_id as libc::c_int {
            /*
             * sctp_ulp_notify(SCTP_NOTIFY_AUTH_NEW_KEY, stcb,
             * shared_key_id, (void
             * *)stcb->asoc.authinfo.recv_keyid);
             */
            sctp_notify_authentication(
                stcb,
                0x1u32,
                shared_key_id,
                (*stcb).asoc.authinfo.recv_keyid,
                0i32,
            );
        }
        /* compute a new recv assoc key and cache it */
        if !(*stcb).asoc.authinfo.recv_key.is_null() {
            sctp_free_key((*stcb).asoc.authinfo.recv_key);
        }
        (*stcb).asoc.authinfo.recv_key = sctp_compute_hashkey(
            (*stcb).asoc.authinfo.random,
            (*stcb).asoc.authinfo.peer_random,
            (*skey).key,
        );
        (*stcb).asoc.authinfo.recv_keyid = shared_key_id;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            sctp_print_key(
                (*stcb).asoc.authinfo.recv_key,
                b"Recv Key\x00" as *const u8 as *const libc::c_char,
            );
        }
    }
    /* validate the digest length */
    digestlen = sctp_get_hmac_digest_len(hmac_id);
    if (chunklen as libc::c_ulong)
        < (::std::mem::size_of::<sctp_auth_chunk>() as libc::c_ulong)
            .wrapping_add(digestlen as libc::c_ulong)
    {
        /* invalid digest length */
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvauthfailed, 1u32);
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP Auth: chunk too short for HMAC\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return -(1i32);
    }
    /* save a copy of the digest, zero the pseudo header, and validate */
    memcpy(
        digest.as_mut_ptr() as *mut libc::c_void,
        (*auth).hmac.as_mut_ptr() as *const libc::c_void,
        digestlen as libc::c_ulong,
    );
    sctp_zero_m(
        m,
        (offset as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_auth_chunk>() as libc::c_ulong)
            as uint32_t,
        (digestlen.wrapping_add(3u32) >> 2i32) << 2i32,
    );
    sctp_compute_hmac_m(
        hmac_id,
        (*stcb).asoc.authinfo.recv_key,
        m,
        offset,
        computed_digest.as_mut_ptr(),
    );
    /* compare the computed digest with the one in the AUTH chunk */
    if timingsafe_bcmp(
        digest.as_mut_ptr() as *const libc::c_void,
        computed_digest.as_mut_ptr() as *const libc::c_void,
        digestlen as size_t,
    ) != 0i32
    {
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvauthfailed, 1u32);
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP Auth: HMAC digest check failed\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return -(1i32);
    }
    return 0i32;
}
/*
 * Generate NOTIFICATION
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_notify_authentication(
    mut stcb: *mut sctp_tcb,
    mut indication: uint32_t,
    mut keyid: uint16_t,
    mut alt_keyid: uint16_t,
    mut so_locked: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut auth = 0 as *mut sctp_authkey_event;
    let mut control = 0 as *mut sctp_queued_to_read;
    if stcb.is_null()
        || (*(*stcb).sctp_ep).sctp_flags & 0x10000000u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0
        || (*stcb).asoc.state & 0x100i32 != 0
    {
        /* If the socket is gone we are out of here */
        return;
    }
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x40000u64 == 0u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x40000u64 == 0u64
        || stcb.is_null() && (*stcb).sctp_ep.is_null()
    {
        /* event not enabled */
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_authkey_event>() as libc::c_uint,
        0i32,
        0x1i32,
        1i32,
        1i32,
    );
    if m_notify.is_null() {
        /* no space left */
        return;
    }
    (*m_notify).m_hdr.mh_len = 0i32;
    auth = (*m_notify).m_hdr.mh_data as *mut sctp_authkey_event;
    memset(
        auth as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_authkey_event>() as libc::c_ulong,
    );
    (*auth).auth_type = 0x8u16;
    (*auth).auth_flags = 0u16;
    (*auth).auth_length = ::std::mem::size_of::<sctp_authkey_event>() as uint32_t;
    (*auth).auth_keynumber = keyid;
    (*auth).auth_altkeynumber = alt_keyid;
    (*auth).auth_indication = indication;
    (*auth).auth_assoc_id = (*stcb).asoc.assoc_id;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_authkey_event>() as libc::c_int;
    (*m_notify).m_hdr.mh_next = 0 as *mut mbuf;
    /* append to socket */
    control = sctp_build_readq_entry(
        stcb,
        (*stcb).asoc.primary_destination,
        0u32,
        0u32,
        (*stcb).asoc.context,
        0u16,
        0u32,
        0u8,
        m_notify,
    );
    if control.is_null() {
        /* no memory */
        m_freem(m_notify);
        return;
    }
    (*control).length = (*m_notify).m_hdr.mh_len as uint32_t;
    (*control).spec_flags = 0x100u16;
    /* not that we need this */
    (*control).tail_mbuf = m_notify;
    sctp_add_to_readq(
        (*stcb).sctp_ep,
        stcb,
        control,
        &mut (*(*stcb).sctp_socket).so_rcv,
        1i32,
        0i32,
        so_locked,
    );
}
/*-
 * validates the AUTHentication related parameters in an INIT/INIT-ACK
 * Note: currently only used for INIT as INIT-ACK is handled inline
 * with sctp_load_addresses_from_init()
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_validate_init_auth_params(
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut limit: libc::c_int,
) -> libc::c_int {
    let mut phdr = 0 as *mut sctp_paramhdr;
    let mut param_buf = sctp_paramhdr {
        param_type: 0,
        param_length: 0,
    };
    let mut peer_supports_asconf = 0i32;
    let mut peer_supports_auth = 0i32;
    let mut got_random = 0i32;
    let mut got_hmacs = 0i32;
    let mut got_chklist = 0i32;
    let mut saw_asconf = 0u8;
    let mut saw_asconf_ack = 0u8;
    /* go through each of the params. */
    phdr = sctp_get_next_param(
        m,
        offset,
        &mut param_buf,
        ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
    );
    while !phdr.is_null() {
        let mut ptype = 0;
        let mut plen = 0;
        ptype = ntohs((*phdr).param_type);
        plen = ntohs((*phdr).param_length);
        if offset + plen as libc::c_int > limit {
            break;
        }
        if (plen as libc::c_ulong) < ::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong {
            break;
        }
        if ptype as libc::c_int == 0x8008i32 {
            let mut pr_supported = 0 as *mut sctp_supported_chunk_types_param;
            let mut local_store = [0u8; 260];
            let mut num_ent = 0;
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 260]>() as libc::c_ulong {
                break;
            }
            phdr = sctp_get_next_param(
                m,
                offset,
                &mut local_store as *mut [uint8_t; 260] as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return -(1i32);
            }
            pr_supported = phdr as *mut sctp_supported_chunk_types_param;
            num_ent = (plen as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
                as libc::c_int;

            for i in 0i32..num_ent {
                match *(*pr_supported).chunk_types.as_mut_ptr().offset(i as isize) as libc::c_int {
                    193 | 128 => peer_supports_asconf = 1i32,
                    _ => {}
                }
            }
        } else if ptype as libc::c_int == 0x8002i32 {
            /* enforce the random length */
            if plen as libc::c_ulong
                != (::std::mem::size_of::<sctp_auth_random>() as libc::c_ulong).wrapping_add(32u64)
            {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"SCTP: invalid RANDOM len\n\x00" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                return -(1i32);
            }
            got_random = 1i32
        } else if ptype as libc::c_int == 0x8004i32 {
            let mut hmacs = 0 as *mut sctp_auth_hmac_algo;
            let mut store = [0; 512];
            let mut num_hmacs = 0;
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                break;
            }
            phdr = sctp_get_next_param(
                m,
                offset,
                store.as_mut_ptr() as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return -(1i32);
            }
            hmacs = phdr as *mut sctp_auth_hmac_algo;
            num_hmacs = (plen as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctp_auth_hmac_algo>() as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<uint16_t>() as libc::c_ulong)
                as libc::c_int;
            /* validate the hmac list */
            if sctp_verify_hmac_param(hmacs, num_hmacs as uint32_t) != 0 {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"SCTP: invalid HMAC param\n\x00" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                return -(1i32);
            }
            got_hmacs = 1i32
        } else if ptype as libc::c_int == 0x8003i32 {
            let mut chunks = 0 as *mut sctp_auth_chunk_list;
            let mut chunks_store = [0; 260];
            let mut num_chunks = 0;
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 260]>() as libc::c_ulong {
                break;
            }
            phdr = sctp_get_next_param(
                m,
                offset,
                chunks_store.as_mut_ptr() as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return -(1i32);
            }
            /*-
             * Flip through the list and mark that the
             * peer supports asconf/asconf_ack.
             */
            chunks = phdr as *mut sctp_auth_chunk_list;
            num_chunks = (plen as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctp_auth_chunk_list>() as libc::c_ulong)
                as libc::c_int;

            for i_0 in 0i32..num_chunks {
                /* record asconf/asconf-ack if listed */
                if *(*chunks).chunk_types.as_mut_ptr().offset(i_0 as isize) as libc::c_int
                    == 0xc1i32
                {
                    saw_asconf = 1u8
                }

                if *(*chunks).chunk_types.as_mut_ptr().offset(i_0 as isize) as libc::c_int
                    == 0x80i32
                {
                    saw_asconf_ack = 1u8
                }
            }
            if num_chunks != 0 {
                got_chklist = 1i32
            }
        }
        offset += (plen as libc::c_int + 3i32 >> 2i32) << 2i32;
        if offset >= limit {
            break;
        }
        phdr = sctp_get_next_param(
            m,
            offset,
            &mut param_buf,
            ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
        )
    }
    /* validate authentication required parameters */
    if got_random != 0 && got_hmacs != 0 {
        peer_supports_auth = 1i32
    } else {
        peer_supports_auth = 0i32
    }
    if peer_supports_auth == 0 && got_chklist != 0 {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP: peer sent chunk list w/o AUTH\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return -(1i32);
    }
    if peer_supports_asconf != 0 && peer_supports_auth == 0 {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"SCTP: peer supports ASCONF but not AUTH\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return -(1i32);
    } else {
        if peer_supports_asconf != 0
            && peer_supports_auth != 0
            && (saw_asconf as libc::c_int == 0i32 || saw_asconf_ack as libc::c_int == 0i32)
        {
            return -(2i32);
        }
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_initialize_auth_params(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
) {
    let mut chunks_len = 0u16;
    let mut hmacs_len = 0u16;
    let mut random_len = 32u16;
    let mut new_key = 0 as *mut sctp_key_t;
    let mut keylen = 0;
    /* initialize hmac list from endpoint */
    (*stcb).asoc.local_hmacs = sctp_copy_hmaclist((*inp).sctp_ep.local_hmacs);
    if !(*stcb).asoc.local_hmacs.is_null() {
        hmacs_len = ((*(*stcb).asoc.local_hmacs).num_algo as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong)
            as uint16_t
    }
    /* initialize auth chunks list from endpoint */
    (*stcb).asoc.local_auth_chunks = sctp_copy_chunklist((*inp).sctp_ep.local_auth_chunks);
    if !(*stcb).asoc.local_auth_chunks.is_null() {
        for i in 0i32..256i32 {
            if (*(*stcb).asoc.local_auth_chunks).chunks[i as usize] != 0 {
                chunks_len = chunks_len.wrapping_add(1)
            }
        }
    }
    /* copy defaults from the endpoint */
    (*stcb).asoc.authinfo.active_keyid = (*inp).sctp_ep.default_keyid;
    /* copy out the shared key list (by reference) from the endpoint */
    sctp_copy_skeylist(
        &mut (*inp).sctp_ep.shared_keys,
        &mut (*stcb).asoc.shared_keys,
    );
    /* now set the concatenated key (random + chunks + hmacs) */
    /* key includes parameter headers */
    keylen = (3u64)
        .wrapping_mul(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
        .wrapping_add(random_len as libc::c_ulong)
        .wrapping_add(chunks_len as libc::c_ulong)
        .wrapping_add(hmacs_len as libc::c_ulong) as uint16_t;
    new_key = sctp_alloc_key(keylen as uint32_t);
    if !new_key.is_null() {
        let mut ph = 0 as *mut sctp_paramhdr;
        let mut plen = 0;
        /* generate and copy in the RANDOM */
        ph = (*new_key).key.as_mut_ptr() as *mut sctp_paramhdr;
        (*ph).param_type = htons(0x8002u16);
        plen = (::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            .wrapping_add(random_len as libc::c_ulong) as libc::c_int;
        (*ph).param_length = htons(plen as uint16_t);
        read_random(
            (*new_key)
                .key
                .as_mut_ptr()
                .offset(::std::mem::size_of::<sctp_paramhdr>() as isize)
                as *mut libc::c_void,
            random_len as libc::c_int,
        );
        keylen = plen as uint16_t;
        /* append in the AUTH chunks */
        /* NOTE: currently we always have chunks to list */
        ph = (*new_key)
            .key
            .as_mut_ptr()
            .offset(keylen as libc::c_int as isize) as *mut sctp_paramhdr;
        (*ph).param_type = htons(0x8003u16);
        plen = (::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            .wrapping_add(chunks_len as libc::c_ulong) as libc::c_int;
        (*ph).param_length = htons(plen as uint16_t);
        keylen = (keylen as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            as uint16_t;
        if !(*stcb).asoc.local_auth_chunks.is_null() {
            for i_0 in 0i32..256i32 {
                if (*(*stcb).asoc.local_auth_chunks).chunks[i_0 as usize] != 0 {
                    let fresh7 = keylen;
                    keylen = keylen.wrapping_add(1);
                    *(*new_key).key.as_mut_ptr().offset(fresh7 as isize) = i_0 as uint8_t
                }
            }
        }
        /* append in the HMACs */
        ph = (*new_key)
            .key
            .as_mut_ptr()
            .offset(keylen as libc::c_int as isize) as *mut sctp_paramhdr;
        (*ph).param_type = htons(0x8004u16);
        plen = (::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            .wrapping_add(hmacs_len as libc::c_ulong) as libc::c_int;
        (*ph).param_length = htons(plen as uint16_t);
        keylen = (keylen as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            as uint16_t;
        sctp_serialize_hmaclist(
            (*stcb).asoc.local_hmacs,
            (*new_key)
                .key
                .as_mut_ptr()
                .offset(keylen as libc::c_int as isize),
        );
    }
    if !(*stcb).asoc.authinfo.random.is_null() {
        sctp_free_key((*stcb).asoc.authinfo.random);
    }
    (*stcb).asoc.authinfo.random = new_key;
    (*stcb).asoc.authinfo.random_len = random_len as uint32_t;
}
/* SCTP_HMAC_TEST */
