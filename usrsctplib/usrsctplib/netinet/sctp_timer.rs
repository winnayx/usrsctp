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
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    /* int hz; is declared in sys/kern/subr_param.c and refers to kernel timer frequency.
     * See http://ivoras.sharanet.org/freebsd/vmware.html for additional info about kern.hz
     * hz is initialized in void init_param1(void) in that file.
     */
    #[no_mangle]
    static mut hz: libc::c_int;
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
    fn sctp_os_timer_stop(_: *mut sctp_os_timer_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_auth_key_release(stcb: *mut sctp_tcb, keyid: uint16_t, so_locked: libc::c_int);
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_free_ifa(sctp_ifap: *mut sctp_ifa);
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_select_initial_TSN(_: *mut sctp_pcb) -> uint32_t;
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
    fn sctp_get_next_mtu(_: uint32_t) -> uint32_t;
    #[no_mangle]
    fn sctp_ulp_notify(
        _: uint32_t,
        _: *mut sctp_tcb,
        _: uint32_t,
        _: *mut libc::c_void,
        _: libc::c_int,
    );
    #[no_mangle]
    fn sctp_stop_timers_for_shutdown(_: *mut sctp_tcb);
    /* We choose to abort via user input */
    #[no_mangle]
    fn sctp_abort_an_association(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: *mut mbuf,
        _: libc::c_int,
    );
    #[no_mangle]
    fn sctp_print_address(_: *mut sockaddr);
    #[no_mangle]
    fn sctp_release_pr_sctp_chunk(
        _: *mut sctp_tcb,
        _: *mut sctp_tmit_chunk,
        _: uint8_t,
        _: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_generate_cause(_: uint16_t, _: *mut libc::c_char) -> *mut mbuf;
    #[no_mangle]
    fn sctp_misc_ints(from: uint8_t, a: uint32_t, b: uint32_t, c: uint32_t, d: uint32_t);
    #[no_mangle]
    fn sctp_log_cwnd(stcb: *mut sctp_tcb, _: *mut sctp_nets, _: libc::c_int, _: uint8_t);
    #[no_mangle]
    fn sctp_log_fr(_: uint32_t, _: uint32_t, _: uint32_t, _: libc::c_int);
    #[no_mangle]
    fn sctp_set_state(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_source_address_selection(
        inp: *mut sctp_inpcb,
        stcb: *mut sctp_tcb,
        ro: *mut sctp_route_t,
        net: *mut sctp_nets,
        non_asoc_addr_ok: libc::c_int,
        vrf_id: uint32_t,
    ) -> *mut sctp_ifa;
    #[no_mangle]
    fn sctp_send_initiate(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_shutdown(_: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_send_shutdown_ack(_: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_send_asconf(_: *mut sctp_tcb, _: *mut sctp_nets, addr_locked: libc::c_int);
    #[no_mangle]
    fn sctp_move_chunks_from_net(stcb: *mut sctp_tcb, net: *mut sctp_nets);
    #[no_mangle]
    fn sctp_chunk_output(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: libc::c_int, _: libc::c_int);
    #[no_mangle]
    fn send_forward_tsn(_: *mut sctp_tcb, _: *mut sctp_association);
    #[no_mangle]
    fn sctp_send_hb(_: *mut sctp_tcb, _: *mut sctp_nets, _: libc::c_int);
    #[no_mangle]
    fn sctp_try_advance_peer_ack_point(
        _: *mut sctp_tcb,
        _: *mut sctp_association,
    ) -> *mut sctp_tmit_chunk;
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
     * function prototypes
     */
    #[no_mangle]
    fn sctp_asconf_cleanup(_: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_find_stream_reset(
        stcb: *mut sctp_tcb,
        seq: uint32_t,
        bchk: *mut *mut sctp_tmit_chunk,
    ) -> *mut sctp_stream_reset_request;
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
    pub c2rust_unnamed: C2RustUnnamed_660,
    pub c2rust_unnamed_0: C2RustUnnamed_658,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_658 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_659,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_659 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_660 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_661,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_661 {
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
    pub __in6_u: C2RustUnnamed_662,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_662 {
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
    pub so_incomp: C2RustUnnamed_670,
    pub so_comp: C2RustUnnamed_669,
    pub so_list: C2RustUnnamed_668,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_667,
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
    pub M_dat: C2RustUnnamed_663,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_663 {
    pub MH: C2RustUnnamed_664,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_664 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_665,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_665 {
    pub MH_ext: m_ext,
    pub MH_databuf: [libc::c_char; 176],
}
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
/*
 * Record/packet header in first mbuf of chain; valid only if M_PKTHDR is set.
 */

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
/* word align                  */
/*
 * Packet tag structure (see below for details).
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct m_tag {
    pub m_tag_link: C2RustUnnamed_666,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_666 {
    pub sle_next: *mut m_tag,
}
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
pub struct C2RustUnnamed_667 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_668 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_669 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_670 {
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
    pub ifa_ifu: C2RustUnnamed_671,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_671 {
    pub ifu_broadaddr: sockaddr,
    pub ifu_dstaddr: sockaddr,
}
/*-
 * Copyright (c) 1980, 1986, 1993
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
/*
 * Kernel resident routing tables.
 *
 * The routing tables are initialized when interface addresses
 * are set by making entries for all directly connected interfaces.
 */
/*
 * A route consists of a destination address and a reference
 * to a routing entry.  These are often held by protocols
 * in their control blocks, e.g. inpcb.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_route {
    pub ro_rt: *mut sctp_rtentry,
    pub ro_dst: sockaddr,
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
    pub inp_hash: C2RustUnnamed_679,
    pub inp_list: C2RustUnnamed_678,
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
    pub inp_depend4: C2RustUnnamed_675,
    pub inp_depend6: C2RustUnnamed_674,
    pub inp_portlist: C2RustUnnamed_673,
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
    pub phd_hash: C2RustUnnamed_672,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_672 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_673 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_674 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_675 {
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
    pub ie_dependfaddr: C2RustUnnamed_677,
    pub ie_dependladdr: C2RustUnnamed_676,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_676 {
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
pub union C2RustUnnamed_677 {
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
pub struct C2RustUnnamed_678 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_679 {
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
    pub tqe: C2RustUnnamed_680,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_680 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;
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
pub type sctp_route_t = sctp_route;
pub type sctp_rtentry_t = sctp_rtentry;
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
    pub sctp_next: C2RustUnnamed_686,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifa {
    pub next_ifa: C2RustUnnamed_685,
    pub next_bucket: C2RustUnnamed_684,
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
    pub next_ifn: C2RustUnnamed_682,
    pub next_bucket: C2RustUnnamed_681,
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
pub struct C2RustUnnamed_681 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_682 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_683,
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
pub struct C2RustUnnamed_683 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_684 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_685 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_686 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tmit_chunk {
    pub rec: C2RustUnnamed_709,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_687,
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
pub struct C2RustUnnamed_687 {
    pub tqe_next: *mut sctp_tmit_chunk,
    pub tqe_prev: *mut *mut sctp_tmit_chunk,
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
    pub next: C2RustUnnamed_688,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_688 {
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
    pub next: C2RustUnnamed_690,
    pub next_instrm: C2RustUnnamed_689,
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
pub struct C2RustUnnamed_689 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_690 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_694,
    pub sctp_tcblist: C2RustUnnamed_693,
    pub sctp_tcbasocidhash: C2RustUnnamed_692,
    pub sctp_asocs: C2RustUnnamed_691,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_block_entry {
    pub error: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_691 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_692 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_693 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_694 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_699,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_698,
    pub sctp_hash: C2RustUnnamed_697,
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
    pub sctp_nxt_itr: C2RustUnnamed_695,
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
pub struct C2RustUnnamed_695 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
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
pub struct sctp_laddr {
    pub sctp_nxt_addr: C2RustUnnamed_696,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_696 {
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
pub struct C2RustUnnamed_697 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_698 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
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
pub struct sctp_readhead {
    pub tqh_first: *mut sctp_queued_to_read,
    pub tqh_last: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_699 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
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
    pub next_spoke: C2RustUnnamed_700,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_700 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_701,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_701 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_702,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_702 {
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
    pub next: C2RustUnnamed_704,
    pub ss_next: C2RustUnnamed_703,
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
pub struct C2RustUnnamed_703 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_704 {
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
    pub next_resp: C2RustUnnamed_705,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_705 {
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
pub struct sctp_asconf_ackhead {
    pub tqh_first: *mut sctp_asconf_ack,
    pub tqh_last: *mut *mut sctp_asconf_ack,
}
/* used to save ASCONF-ACK chunks for retransmission */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ack {
    pub next: C2RustUnnamed_706,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_706 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_707,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_707 {
    pub wheel: sctpwheel_listhead,
    pub list: sctplist_listhead,
}
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
/* used to keep track of the addresses yet to try to add/delete */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_708,
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

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_paramhdr {
    pub param_type: uint16_t,
    pub param_length: uint16_t,
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
pub struct C2RustUnnamed_708 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_709 {
    pub data: sctp_data_chunkrec,
    pub chunk_id: chk_id,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct chk_id {
    pub id: uint8_t,
    pub can_take_data: uint8_t,
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
pub struct sctpvtaghead {
    pub lh_first: *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tagblock {
    pub sctp_nxt_tagblock: C2RustUnnamed_710,
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
pub struct C2RustUnnamed_710 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrflist {
    pub lh_first: *mut sctp_vrf,
}
pub type __timezone_ptr_t = *mut timezone;
/* *********STREAM RESET STUFF ******************/

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_stream_reset_request {
    pub ph: sctp_paramhdr,
    pub request_seq: uint32_t,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct udphdr {
    pub c2rust_unnamed: C2RustUnnamed_711,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_711 {
    pub c2rust_unnamed: C2RustUnnamed_713,
    pub c2rust_unnamed_0: C2RustUnnamed_712,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_712 {
    pub source: uint16_t,
    pub dest: uint16_t,
    pub len: uint16_t,
    pub check: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_713 {
    pub uh_sport: uint16_t,
    pub uh_dport: uint16_t,
    pub uh_ulen: uint16_t,
    pub uh_sum: uint16_t,
}
#[inline]
unsafe extern "C" fn sctp_userspace_rtfree(mut rt: *mut sctp_rtentry_t) {
    if rt.is_null() {
        return;
    }
    (*rt).rt_refcnt -= 1;
    if (*rt).rt_refcnt > 0i64 {
        return;
    }
    free(rt as *mut libc::c_void);
    rt = 0 as *mut sctp_rtentry_t;
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
#[no_mangle]
pub unsafe extern "C" fn sctp_audit_retranmission_queue(mut asoc: *mut sctp_association) {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x8u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Audit invoked on send queue cnt:%d onqueue:%d\n\x00" as *const u8
                    as *const libc::c_char,
                (*asoc).sent_queue_retran_cnt,
                (*asoc).sent_queue_cnt,
            );
        }
    }
    (*asoc).sent_queue_retran_cnt = 0u32;
    (*asoc).sent_queue_cnt = 0u32;
    chk = (*asoc).sent_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).sent == 4i32 {
            (*asoc).sent_queue_retran_cnt = (*asoc).sent_queue_retran_cnt.wrapping_add(1)
        }
        (*asoc).sent_queue_cnt = (*asoc).sent_queue_cnt.wrapping_add(1);
        chk = (*chk).sctp_next.tqe_next
    }
    chk = (*asoc).control_send_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).sent == 4i32 {
            (*asoc).sent_queue_retran_cnt = (*asoc).sent_queue_retran_cnt.wrapping_add(1)
        }
        chk = (*chk).sctp_next.tqe_next
    }
    chk = (*asoc).asconf_send_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).sent == 4i32 {
            (*asoc).sent_queue_retran_cnt = (*asoc).sent_queue_retran_cnt.wrapping_add(1)
        }
        chk = (*chk).sctp_next.tqe_next
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x8u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Audit completes retran:%d onqueue:%d\n\x00" as *const u8 as *const libc::c_char,
                (*asoc).sent_queue_retran_cnt,
                (*asoc).sent_queue_cnt,
            );
        }
    };
}
unsafe extern "C" fn sctp_threshold_management(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut threshold: uint16_t,
) -> libc::c_int {
    if !net.is_null() {
        (*net).error_count = (*net).error_count.wrapping_add(1);
        if system_base_info.sctpsysctl.sctp_debug_on & 0x8u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Error count for %p now %d thresh:%d\n\x00" as *const u8
                        as *const libc::c_char,
                    net as *mut libc::c_void,
                    (*net).error_count as libc::c_int,
                    (*net).failure_threshold as libc::c_int,
                );
            }
        }
        if (*net).error_count as libc::c_int > (*net).failure_threshold as libc::c_int {
            /* We had a threshold failure */
            if (*net).dest_state as libc::c_int & 0x1i32 != 0 {
                (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x400i32)) as uint16_t;
                (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x800i32)) as uint16_t;
                sctp_ulp_notify(3u32, stcb, 0u32, net as *mut libc::c_void, 0i32);
            }
        } else if ((*net).pf_threshold as libc::c_int) < (*net).failure_threshold as libc::c_int
            && (*net).error_count as libc::c_int > (*net).pf_threshold as libc::c_int
        {
            if (*net).dest_state as libc::c_int & 0x800i32 == 0 {
                (*net).dest_state = ((*net).dest_state as libc::c_int | 0x800i32) as uint16_t;
                (*net).last_active = sctp_get_tick_count();
                sctp_send_hb(stcb, net, 0i32);
                sctp_timer_stop(5i32, inp, stcb, net, (0x40000000i32 + 0x1i32) as uint32_t);
                sctp_timer_start(5i32, inp, stcb, net);
            }
        }
    }
    if stcb.is_null() {
        return 0i32;
    }
    if !net.is_null() {
        if (*net).dest_state as libc::c_int & 0x200i32 == 0i32 {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x2000000u32 != 0 {
                sctp_misc_ints(
                    121u8,
                    (*stcb).asoc.overall_error_count,
                    (*stcb).asoc.overall_error_count.wrapping_add(1u32),
                    0x40000000u32,
                    142u32,
                );
            }
            (*stcb).asoc.overall_error_count = (*stcb).asoc.overall_error_count.wrapping_add(1)
        }
    } else {
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2000000u32 != 0 {
            sctp_misc_ints(
                121u8,
                (*stcb).asoc.overall_error_count,
                (*stcb).asoc.overall_error_count.wrapping_add(1u32),
                0x40000000u32,
                152u32,
            );
        }
        (*stcb).asoc.overall_error_count = (*stcb).asoc.overall_error_count.wrapping_add(1)
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x8u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Overall error count for %p now %d thresh:%u state:%x\n\x00" as *const u8
                    as *const libc::c_char,
                &mut (*stcb).asoc as *mut sctp_association as *mut libc::c_void,
                (*stcb).asoc.overall_error_count,
                threshold as uint32_t,
                if net.is_null() {
                    0u32
                } else {
                    (*net).dest_state as uint32_t
                },
            );
        }
    }
    /*
     * We specifically do not do >= to give the assoc one more change
     * before we fail it.
     */
    if (*stcb).asoc.overall_error_count > threshold as libc::c_uint {
        let mut op_err = 0 as *mut mbuf;
        op_err = sctp_generate_cause(
            system_base_info.sctpsysctl.sctp_diag_info_code as uint16_t,
            b"Association error counter exceeded\x00" as *const u8 as *mut libc::c_char,
        );
        (*inp).last_abort_code = (0x40000000i32 + 0x2i32) as uint32_t;
        sctp_abort_an_association(inp, stcb, op_err, 0i32);
        return 1i32;
    }
    return 0i32;
}
/*
 * sctp_find_alternate_net() returns a non-NULL pointer as long
 * the argument net is non-NULL.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_find_alternate_net(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut mode: libc::c_int,
) -> *mut sctp_nets {
    let mut alt = 0 as *mut sctp_nets;
    let mut mnet = 0 as *mut sctp_nets;
    let mut max_cwnd_net = 0 as *mut sctp_nets;
    let mut once = 0;
    let mut max_cwnd = 0u32;
    let mut min_errors = -(1i32);

    if (*stcb).asoc.numnets == 1u32 {
        /* No others but net */
        return (*stcb).asoc.nets.tqh_first;
    }
    /*
     * JRS 5/14/07 - If mode is set to 2, use the CMT PF find alternate net algorithm.
     * This algorithm chooses the active destination (not in PF state) with the largest
     * cwnd value. If all destinations are in PF state, unreachable, or unconfirmed, choose
     * the desination that is in PF state with the lowest error count. In case of a tie,
     * choose the destination that was most recently active.
     */
    if mode == 2i32 {
        let mut min_errors_net = 0 as *mut sctp_nets;
        mnet = (*stcb).asoc.nets.tqh_first; /* JRS 5/14/07 - If mode is set to 1, use the CMT policy for choosing an alternate net. */
        while !mnet.is_null() {
            /* JRS 5/14/07 - If the destination is unreachable or unconfirmed, skip it. */
            if !((*mnet).dest_state as libc::c_int & 0x1i32 != 0x1i32
                || (*mnet).dest_state as libc::c_int & 0x200i32 != 0)
            {
                /*
                 * JRS 5/14/07 -  If the destination is reachable but in PF state, compare
                 *  the error count of the destination to the minimum error count seen thus far.
                 *  Store the destination with the lower error count.  If the error counts are
                 *  equal, store the destination that was most recently active.
                 */
                if (*mnet).dest_state as libc::c_int & 0x800i32 != 0 {
                    /*
                     * JRS 5/14/07 - If the destination under consideration is the current
                     *  destination, work as if the error count is one higher.  The
                     *  actual error count will not be incremented until later in the
                     *  t3 handler.
                     */
                    if mnet == net {
                        if min_errors == -(1i32) {
                            min_errors = (*mnet).error_count as libc::c_int + 1i32;
                            min_errors_net = mnet
                        } else if ((*mnet).error_count as libc::c_int + 1i32) < min_errors {
                            min_errors = (*mnet).error_count as libc::c_int + 1i32;
                            min_errors_net = mnet
                        } else if (*mnet).error_count as libc::c_int + 1i32 == min_errors
                            && (*mnet).last_active > (*min_errors_net).last_active
                        {
                            min_errors_net = mnet;
                            min_errors = (*mnet).error_count as libc::c_int + 1i32
                        }
                    } else if min_errors == -(1i32) {
                        min_errors = (*mnet).error_count as libc::c_int;
                        min_errors_net = mnet
                    } else if ((*mnet).error_count as libc::c_int) < min_errors {
                        min_errors = (*mnet).error_count as libc::c_int;
                        min_errors_net = mnet
                    } else if (*mnet).error_count as libc::c_int == min_errors
                        && (*mnet).last_active > (*min_errors_net).last_active
                    {
                        min_errors_net = mnet;
                        min_errors = (*mnet).error_count as libc::c_int
                    }
                } else if max_cwnd < (*mnet).cwnd {
                    max_cwnd_net = mnet;
                    max_cwnd = (*mnet).cwnd
                } else if max_cwnd == (*mnet).cwnd {
                    let mut this_random = 0;
                    if (*stcb).asoc.hb_random_idx as libc::c_int > 3i32 {
                        let mut rndval = 0;
                        rndval = sctp_select_initial_TSN(&mut (*(*stcb).sctp_ep).sctp_ep);
                        memcpy(
                            (*stcb).asoc.hb_random_values.as_mut_ptr() as *mut libc::c_void,
                            &mut rndval as *mut uint32_t as *const libc::c_void,
                            ::std::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong,
                        );
                        this_random = (*stcb).asoc.hb_random_values[0usize];
                        (*stcb).asoc.hb_random_idx = (*stcb).asoc.hb_random_idx.wrapping_add(1);
                        (*stcb).asoc.hb_ect_randombit = 0u8
                    } else {
                        this_random =
                            (*stcb).asoc.hb_random_values[(*stcb).asoc.hb_random_idx as usize];
                        (*stcb).asoc.hb_random_idx = (*stcb).asoc.hb_random_idx.wrapping_add(1);
                        (*stcb).asoc.hb_ect_randombit = 0u8
                    }
                    if this_random as libc::c_int % 2i32 == 1i32 {
                        max_cwnd_net = mnet;
                        max_cwnd = (*mnet).cwnd
                        /*
                         * JRS 5/14/07 - If the destination is reachable and not in PF state, compare the
                         *  cwnd of the destination to the highest cwnd seen thus far.  Store the
                         *  destination with the higher cwnd value.  If the cwnd values are equal,
                         *  randomly choose one of the two destinations.
                         */
                        /* Useless? */
                    }
                }
            }
            mnet = (*mnet).sctp_next.tqe_next
        }
        if max_cwnd_net.is_null() {
            if min_errors_net.is_null() {
                return net;
            }
            return min_errors_net;
        } else {
            return max_cwnd_net;
        }
    } else {
        if mode == 1i32 {
            mnet = (*stcb).asoc.nets.tqh_first;
            while !mnet.is_null() {
                if !((*mnet).dest_state as libc::c_int & 0x1i32 != 0x1i32
                    || (*mnet).dest_state as libc::c_int & 0x200i32 != 0)
                {
                    if max_cwnd < (*mnet).cwnd {
                        max_cwnd_net = mnet;
                        max_cwnd = (*mnet).cwnd
                    } else if max_cwnd == (*mnet).cwnd {
                        let mut this_random_0 = 0;
                        if (*stcb).asoc.hb_random_idx as libc::c_int > 3i32 {
                            let mut rndval_0 = 0;
                            rndval_0 = sctp_select_initial_TSN(&mut (*(*stcb).sctp_ep).sctp_ep);
                            memcpy(
                                (*stcb).asoc.hb_random_values.as_mut_ptr() as *mut libc::c_void,
                                &mut rndval_0 as *mut uint32_t as *const libc::c_void,
                                ::std::mem::size_of::<[uint8_t; 4]>() as libc::c_ulong,
                            );
                            this_random_0 = (*stcb).asoc.hb_random_values[0usize];
                            (*stcb).asoc.hb_random_idx = 0u8;
                            (*stcb).asoc.hb_ect_randombit = 0u8
                        } else {
                            this_random_0 =
                                (*stcb).asoc.hb_random_values[(*stcb).asoc.hb_random_idx as usize];
                            (*stcb).asoc.hb_random_idx = (*stcb).asoc.hb_random_idx.wrapping_add(1);
                            (*stcb).asoc.hb_ect_randombit = 0u8
                        }
                        if this_random_0 as libc::c_int % 2i32 != 0 {
                            max_cwnd_net = mnet;
                            max_cwnd = (*mnet).cwnd
                        }
                    }
                }
                /*
                 * will skip ones that are not-reachable or
                 * unconfirmed
                 */
                mnet = (*mnet).sctp_next.tqe_next
            }
            if !max_cwnd_net.is_null() {
                return max_cwnd_net;
            }
        }
    }
    mnet = net;
    once = 0i32;
    if mnet.is_null() {
        mnet = (*stcb).asoc.nets.tqh_first;
        if mnet.is_null() {
            return 0 as *mut sctp_nets;
        }
    }
    loop {
        alt = (*mnet).sctp_next.tqe_next;
        if alt.is_null() {
            once += 1;
            if once > 1i32 {
                break;
            }
            alt = (*stcb).asoc.nets.tqh_first;
            if alt.is_null() {
                return 0 as *mut sctp_nets;
            }
        }
        if (*alt).ro.ro_rt.is_null() {
            if !(*alt).ro._s_addr.is_null() {
                sctp_free_ifa((*alt).ro._s_addr);
                (*alt).ro._s_addr = 0 as *mut sctp_ifa
            }
            (*alt).src_addr_selected = 0u8
        }
        if (*alt).dest_state as libc::c_int & 0x1i32 == 0x1i32
            && !(*alt).ro.ro_rt.is_null()
            && (*alt).dest_state as libc::c_int & 0x200i32 == 0
        {
            break;
        }
        mnet = alt
    }
    if alt.is_null() {
        /* Case where NO insv network exists (dormant state) */
        /* we rotate destinations */
        once = 0i32;
        mnet = net;
        loop {
            if mnet.is_null() {
                return (*stcb).asoc.nets.tqh_first;
            }
            alt = (*mnet).sctp_next.tqe_next;
            if alt.is_null() {
                once += 1;
                if once > 1i32 {
                    break;
                }
                alt = (*stcb).asoc.nets.tqh_first;
                if alt.is_null() {
                    break;
                }
            }
            if (*alt).dest_state as libc::c_int & 0x200i32 == 0 && alt != net {
                break;
            }
            mnet = alt
        }
    }
    if alt.is_null() {
        return net;
    }
    return alt;
}
unsafe extern "C" fn sctp_backoff_on_timeout(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut win_probe: libc::c_int,
    mut num_marked: libc::c_int,
    mut num_abandoned: libc::c_int,
) {
    if (*net).RTO == 0u32 {
        if (*net).RTO_measured != 0 {
            (*net).RTO = (*stcb).asoc.minrto
        } else {
            (*net).RTO = (*stcb).asoc.initial_rto
        }
    }
    (*net).RTO <<= 1i32;
    if (*net).RTO > (*stcb).asoc.maxrto {
        (*net).RTO = (*stcb).asoc.maxrto
    }
    if win_probe == 0i32 && (num_marked != 0 || num_abandoned != 0) {
        /* We don't apply penalty to window probe scenarios */
        /* JRS - Use the congestion control given in the CC module */
        (*stcb)
            .asoc
            .cc_functions
            .sctp_cwnd_update_after_timeout
            .expect("non-null function pointer")(stcb, net);
    };
}
unsafe extern "C" fn sctp_recover_sent_list(mut stcb: *mut sctp_tcb) {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut nchk = 0 as *mut sctp_tmit_chunk;
    let mut asoc = 0 as *mut sctp_association;
    asoc = &mut (*stcb).asoc;
    chk = (*asoc).sent_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if (*asoc).last_acked_seq < (*chk).rec.data.tsn
            && (*chk).rec.data.tsn.wrapping_sub((*asoc).last_acked_seq) > (1u32) << 31i32
            || (*asoc).last_acked_seq > (*chk).rec.data.tsn
                && (*asoc).last_acked_seq.wrapping_sub((*chk).rec.data.tsn) < (1u32) << 31i32
            || (*asoc).last_acked_seq == (*chk).rec.data.tsn
        {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Found chk:%p tsn:%x <= last_acked_seq:%x\n\x00" as *const u8
                        as *const libc::c_char,
                    chk as *mut libc::c_void,
                    (*chk).rec.data.tsn,
                    (*asoc).last_acked_seq,
                );
            }
            if (*chk).sent != 40010i32 {
                if (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues > 0u32 {
                    let ref mut fresh0 =
                        (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues;
                    *fresh0 = (*fresh0).wrapping_sub(1)
                }
            }
            if (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues == 0u32
                && (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).state as libc::c_int
                    == 0x3i32
                && (*(*asoc).strmout.offset((*chk).rec.data.sid as isize))
                    .outqueue
                    .tqh_first
                    .is_null()
            {
                (*asoc).trigger_reset = 1u8
            }
            if !(*chk).sctp_next.tqe_next.is_null() {
                (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
            } else {
                (*asoc).sent_queue.tqh_last = (*chk).sctp_next.tqe_prev
            }
            *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
            if (*chk).flags as libc::c_int & 0xfi32 != 0i32
                && (*chk).flags as libc::c_int & 0xfi32 != 0xfi32
            {
                if (*asoc).pr_sctp_cnt != 0u32 {
                    (*asoc).pr_sctp_cnt = (*asoc).pr_sctp_cnt.wrapping_sub(1)
                }
            }
            if !(*chk).data.is_null() {
                /*sa_ignore NO_NULL_CHK*/
                if !(*chk).data.is_null() {
                    ::std::intrinsics::atomic_xsub(&mut (*asoc).chunks_on_out_queue, 1u32);
                    if (*asoc).total_output_queue_size >= (*chk).book_size as libc::c_uint {
                        ::std::intrinsics::atomic_xsub(
                            &mut (*asoc).total_output_queue_size,
                            (*chk).book_size as uint32_t,
                        );
                    } else {
                        (*asoc).total_output_queue_size = 0u32
                    }
                    if !(*stcb).sctp_socket.is_null()
                        && ((*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
                            || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0)
                    {
                        if (*(*stcb).sctp_socket).so_snd.sb_cc >= (*chk).book_size as libc::c_uint {
                            ::std::intrinsics::atomic_xsub(
                                &mut (*(*stcb).sctp_socket).so_snd.sb_cc,
                                (*chk).book_size as u_int,
                            );
                        } else {
                            (*(*stcb).sctp_socket).so_snd.sb_cc = 0u32
                        }
                    }
                }
                m_freem((*chk).data);
                (*chk).data = 0 as *mut mbuf;
                if (*asoc).prsctp_supported as libc::c_int != 0
                    && (*chk).flags as libc::c_int & 0xfi32 == 0x2i32
                {
                    (*asoc).sent_queue_cnt_removeable =
                        (*asoc).sent_queue_cnt_removeable.wrapping_sub(1)
                }
            }
            (*asoc).sent_queue_cnt = (*asoc).sent_queue_cnt.wrapping_sub(1);
            if (*chk).holds_key_ref != 0 {
                sctp_auth_key_release(stcb, (*chk).auth_keyid, 0i32);
                (*chk).holds_key_ref = 0u8
            }
            if !stcb.is_null() {
                if !(*chk).whoTo.is_null() {
                    if !(*chk).whoTo.is_null() {
                        if ::std::intrinsics::atomic_xadd(
                            &mut (*(*chk).whoTo).ref_count as *mut libc::c_int,
                            -(1i32),
                        ) == 1i32
                        {
                            sctp_os_timer_stop(&mut (*(*chk).whoTo).rxt_timer.timer);
                            sctp_os_timer_stop(&mut (*(*chk).whoTo).pmtu_timer.timer);
                            sctp_os_timer_stop(&mut (*(*chk).whoTo).hb_timer.timer);
                            if !(*(*chk).whoTo).ro.ro_rt.is_null() {
                                if (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                                    sctp_userspace_rtfree((*(*chk).whoTo).ro.ro_rt);
                                } else {
                                    (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt -= 1
                                }
                                (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                                (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                            }
                            if (*(*chk).whoTo).src_addr_selected != 0 {
                                sctp_free_ifa((*(*chk).whoTo).ro._s_addr);
                                (*(*chk).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                            }
                            (*(*chk).whoTo).src_addr_selected = 0u8;
                            (*(*chk).whoTo).dest_state =
                                ((*(*chk).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                            free((*chk).whoTo as *mut libc::c_void);
                            ::std::intrinsics::atomic_xsub(
                                &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                1u32,
                            );
                        }
                    }
                    (*chk).whoTo = 0 as *mut sctp_nets
                }
                if (*stcb).asoc.free_chunk_cnt as libc::c_uint
                    > system_base_info.sctpsysctl.sctp_asoc_free_resc_limit
                    || system_base_info.sctppcbinfo.ipi_free_chunks
                        > system_base_info.sctpsysctl.sctp_system_free_resc_limit
                {
                    free(chk as *mut libc::c_void);
                    ::std::intrinsics::atomic_xsub(
                        &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                        1u32,
                    );
                } else {
                    (*chk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
                    (*chk).sctp_next.tqe_prev = (*stcb).asoc.free_chunks.tqh_last;
                    *(*stcb).asoc.free_chunks.tqh_last = chk;
                    (*stcb).asoc.free_chunks.tqh_last = &mut (*chk).sctp_next.tqe_next;
                    (*stcb).asoc.free_chunk_cnt = (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctppcbinfo.ipi_free_chunks,
                        1u32,
                    );
                }
            } else {
                free(chk as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                    1u32,
                );
            }
        }
        chk = nchk
    }
    if system_base_info.debug_printf.is_some() {
        system_base_info
            .debug_printf
            .expect("non-null function pointer")(
            b"after recover order is as follows\n\x00" as *const u8 as *const libc::c_char,
        );
    }
    chk = (*asoc).sent_queue.tqh_first;
    while !chk.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"chk:%p TSN:%x\n\x00" as *const u8 as *const libc::c_char,
                chk as *mut libc::c_void,
                (*chk).rec.data.tsn,
            );
        }
        chk = (*chk).sctp_next.tqe_next
    }
}
unsafe extern "C" fn sctp_mark_all_for_resend(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut alt: *mut sctp_nets,
    mut window_probe: libc::c_int,
    mut num_marked: *mut libc::c_int,
    mut num_abandoned: *mut libc::c_int,
) -> libc::c_int {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut now = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut min_wait = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut tv = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut cur_rto = 0;
    let mut cnt_abandoned = 0;
    let mut audit_tf = 0;
    let mut num_mk = 0;
    let mut fir = 0;
    let mut cnt_mk = 0;
    let mut orig_flight = 0;
    let mut orig_tf = 0;
    let mut tsnlast = 0;
    let mut tsnfirst = 0;
    /* none in flight now */
    audit_tf = 0i32;
    fir = 0i32;
    /*
     * figure out how long a data chunk must be pending before we can
     * mark it ..
     */
    gettimeofday(&mut now, 0 as *mut timezone);
    /* get cur rto in micro-seconds */
    cur_rto = ((*net).lastsa >> 3i32) + (*net).lastsv;
    cur_rto *= 1000i32;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
        sctp_log_fr(
            cur_rto as uint32_t,
            (*stcb).asoc.peers_rwnd,
            window_probe as uint32_t,
            26i32,
        );
        sctp_log_fr((*net).flight_size, 0u32, 0u32, 58i32);
        sctp_log_fr(
            (*net).flight_size,
            (*net).cwnd,
            (*stcb).asoc.total_flight,
            58i32,
        );
    }
    tv.tv_sec = (cur_rto / 1000000i32) as __time_t;
    tv.tv_usec = (cur_rto % 1000000i32) as __suseconds_t;
    min_wait.tv_sec = now.tv_sec - tv.tv_sec;
    min_wait.tv_usec = now.tv_usec - tv.tv_usec;
    if min_wait.tv_usec < 0i64 {
        min_wait.tv_sec -= 1;
        min_wait.tv_usec += 1000000i64
    }
    if min_wait.tv_sec < 0i64 || min_wait.tv_usec < 0i64 {
        /*
         * if we hit here, we don't have enough seconds on the clock
         * to account for the RTO. We just let the lower seconds be
         * the bounds and don't worry about it. This may mean we
         * will mark a lot more than we should.
         */
        min_wait.tv_usec = 0i64;
        min_wait.tv_sec = min_wait.tv_usec
    }
    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
        sctp_log_fr(
            cur_rto as uint32_t,
            now.tv_sec as uint32_t,
            now.tv_usec as uint32_t,
            26i32,
        );
        sctp_log_fr(
            0u32,
            min_wait.tv_sec as uint32_t,
            min_wait.tv_usec as uint32_t,
            26i32,
        );
    }
    /*
     * Our rwnd will be incorrect here since we are not adding back the
     * cnt * mbuf but we will fix that down below.
     */
    orig_flight = (*net).flight_size;
    orig_tf = (*stcb).asoc.total_flight;
    (*net).fast_retran_ip = 0u8;
    /* Now on to each chunk */
    cnt_abandoned = 0i32;
    cnt_mk = 0u32;
    num_mk = cnt_mk as libc::c_int;
    tsnlast = 0u32;
    tsnfirst = tsnlast;

    's_175: loop {
        chk = (*stcb).asoc.sent_queue.tqh_first;
        loop {
            let mut nchk = 0 as *mut sctp_tmit_chunk;
            let mut current_block_169: u64;
            if !(!chk.is_null() && {
                nchk = (*chk).sctp_next.tqe_next;
                (1i32) != 0
            }) {
                break 's_175;
            }
            if (*stcb).asoc.last_acked_seq < (*chk).rec.data.tsn
                && (*chk)
                    .rec
                    .data
                    .tsn
                    .wrapping_sub((*stcb).asoc.last_acked_seq)
                    > (1u32) << 31i32
                || (*stcb).asoc.last_acked_seq > (*chk).rec.data.tsn
                    && (*stcb)
                        .asoc
                        .last_acked_seq
                        .wrapping_sub((*chk).rec.data.tsn)
                        < (1u32) << 31i32
                || (*stcb).asoc.last_acked_seq == (*chk).rec.data.tsn
            {
                let mut recovery_cnt = 0i32;
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Our list is out of order? last_acked:%x chk:%x\n\x00" as *const u8
                            as *const libc::c_char,
                        (*stcb).asoc.last_acked_seq,
                        (*chk).rec.data.tsn,
                    );
                }
                recovery_cnt += 1;
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Recover attempts a restart cnt:%d\n\x00" as *const u8
                            as *const libc::c_char,
                        recovery_cnt,
                    );
                }
                sctp_recover_sent_list(stcb);
                if recovery_cnt < 10i32 {
                    break;
                }
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Recovery fails %d times??\n\x00" as *const u8 as *const libc::c_char,
                        recovery_cnt,
                    );
                }
            }
            if (*chk).whoTo == net && (*chk).sent < 10010i32 {
                /*
                 * found one to mark: If it is less than
                 * DATAGRAM_ACKED it MUST not be a skipped or marked
                 * TSN but instead one that is either already set
                 * for retransmission OR one that needs
                 * retransmission.
                 */
                /* validate its been outstanding long enough */
                if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
                    sctp_log_fr(
                        (*chk).rec.data.tsn,
                        (*chk).sent_rcv_time.tv_sec as uint32_t,
                        (*chk).sent_rcv_time.tv_usec as uint32_t,
                        26i32,
                    );
                }
                if (*chk).sent_rcv_time.tv_sec > min_wait.tv_sec && window_probe == 0i32 {
                    /*
                     * we have reached a chunk that was sent
                     * some seconds past our min.. forget it we
                     * will find no more to send.
                     */
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
                        sctp_log_fr(
                            0u32,
                            (*chk).sent_rcv_time.tv_sec as uint32_t,
                            (*chk).sent_rcv_time.tv_usec as uint32_t,
                            28i32,
                        );
                    }
                    current_block_169 = 7245201122033322888;
                } else {
                    if (*chk).sent_rcv_time.tv_sec == min_wait.tv_sec && window_probe == 0i32 {
                        /*
                         * we must look at the micro seconds to
                         * know.
                         */
                        if (*chk).sent_rcv_time.tv_usec >= min_wait.tv_usec {
                            current_block_169 = 7245201122033322888;
                        } else {
                            current_block_169 = 1134115459065347084;
                        }
                    } else {
                        current_block_169 = 1134115459065347084;
                    }
                    match current_block_169 {
                        7245201122033322888 => {}
                        _ => {
                            if (*stcb).asoc.prsctp_supported as libc::c_int != 0
                                && (*chk).flags as libc::c_int & 0xfi32 == 0x1i32
                            {
                                /* Is it expired? */
                                if if now.tv_sec == (*chk).rec.data.timetodrop.tv_sec {
                                    (now.tv_usec > (*chk).rec.data.timetodrop.tv_usec)
                                        as libc::c_int
                                } else {
                                    (now.tv_sec > (*chk).rec.data.timetodrop.tv_sec) as libc::c_int
                                } != 0
                                {
                                    /* Yes so drop it */
                                    if !(*chk).data.is_null() {
                                        sctp_release_pr_sctp_chunk(stcb, chk, 1u8, 0i32);
                                        cnt_abandoned += 1
                                    }
                                    current_block_169 = 7245201122033322888;
                                } else {
                                    current_block_169 = 7419121793134201633;
                                }
                            } else {
                                current_block_169 = 7419121793134201633;
                            }
                            match current_block_169 {
                                7245201122033322888 => {}
                                _ => {
                                    if (*stcb).asoc.prsctp_supported as libc::c_int != 0
                                        && (*chk).flags as libc::c_int & 0xfi32 == 0x3i32
                                    {
                                        /* Has it been retransmitted tv_sec times? */
                                        if (*chk).snd_count as libc::c_long
                                            > (*chk).rec.data.timetodrop.tv_sec
                                        {
                                            if !(*chk).data.is_null() {
                                                sctp_release_pr_sctp_chunk(stcb, chk, 1u8, 0i32);
                                                cnt_abandoned += 1
                                            }
                                            current_block_169 = 7245201122033322888;
                                        } else {
                                            current_block_169 = 10778260831612459202;
                                        }
                                    } else {
                                        current_block_169 = 10778260831612459202;
                                    }
                                    match current_block_169 {
                                        7245201122033322888 => {}
                                        _ => {
                                            if (*chk).sent < 4i32 {
                                                (*stcb).asoc.sent_queue_retran_cnt = (*stcb)
                                                    .asoc
                                                    .sent_queue_retran_cnt
                                                    .wrapping_add(1);
                                                num_mk += 1;
                                                if fir == 0i32 {
                                                    fir = 1i32;
                                                    tsnfirst = (*chk).rec.data.tsn
                                                }
                                                tsnlast = (*chk).rec.data.tsn;
                                                if system_base_info.sctpsysctl.sctp_logging_level
                                                    & 0x40u32
                                                    != 0
                                                {
                                                    sctp_log_fr(
                                                        (*chk).rec.data.tsn,
                                                        (*chk).snd_count as uint32_t,
                                                        0u32,
                                                        27i32,
                                                    );
                                                }
                                                if (*chk).rec.data.chunk_was_revoked != 0 {
                                                    /* deflate the cwnd */
                                                    (*(*chk).whoTo).cwnd = ((*(*chk).whoTo).cwnd)
                                                        .wrapping_sub(
                                                            (*chk).book_size as libc::c_uint,
                                                        );
                                                    (*chk).rec.data.chunk_was_revoked = 0u8
                                                }
                                                (*net).marked_retrans =
                                                    (*net).marked_retrans.wrapping_add(1);
                                                (*stcb).asoc.marked_retrans =
                                                    (*stcb).asoc.marked_retrans.wrapping_add(1);
                                                if system_base_info.sctpsysctl.sctp_logging_level
                                                    & 0x20u32
                                                    != 0
                                                {
                                                    sctp_misc_ints(
                                                        112u8,
                                                        (*(*chk).whoTo).flight_size,
                                                        (*chk).book_size as uint32_t,
                                                        (*chk).whoTo as uint32_t,
                                                        (*chk).rec.data.tsn,
                                                    );
                                                }
                                                if (*(*chk).whoTo).flight_size
                                                    >= (*chk).book_size as libc::c_uint
                                                {
                                                    (*(*chk).whoTo).flight_size =
                                                        ((*(*chk).whoTo).flight_size).wrapping_sub(
                                                            (*chk).book_size as libc::c_uint,
                                                        )
                                                } else {
                                                    (*(*chk).whoTo).flight_size = 0u32
                                                }
                                                (*chk).window_probe = 0u8;
                                                if (*stcb).asoc.total_flight
                                                    >= (*chk).book_size as libc::c_uint
                                                {
                                                    (*stcb).asoc.total_flight =
                                                        (*stcb).asoc.total_flight.wrapping_sub(
                                                            (*chk).book_size as libc::c_uint,
                                                        );
                                                    if (*stcb).asoc.total_flight_count > 0u32 {
                                                        (*stcb).asoc.total_flight_count = (*stcb)
                                                            .asoc
                                                            .total_flight_count
                                                            .wrapping_sub(1)
                                                    }
                                                } else {
                                                    (*stcb).asoc.total_flight = 0u32;
                                                    (*stcb).asoc.total_flight_count = 0u32
                                                }
                                                (*stcb).asoc.peers_rwnd = ((*stcb).asoc.peers_rwnd)
                                                    .wrapping_add((*chk).send_size as libc::c_uint);
                                                (*stcb).asoc.peers_rwnd = ((*stcb).asoc.peers_rwnd)
                                                    .wrapping_add(
                                                        system_base_info
                                                            .sctpsysctl
                                                            .sctp_peer_chunk_oh,
                                                    )
                                            }
                                            (*chk).sent = 4i32;
                                            (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32)
                                                as uint16_t;
                                            ::std::intrinsics::atomic_xadd(
                                                &mut system_base_info.sctpstat.sctps_markedretrans,
                                                1u32,
                                            );
                                            /* reset the TSN for striking and other FR stuff */
                                            (*chk).rec.data.doing_fast_retransmit = 0u8;
                                            /* Clear any time so NO RTT is being done */
                                            if (*chk).do_rtt != 0 {
                                                if (*(*chk).whoTo).rto_needed as libc::c_int == 0i32
                                                {
                                                    (*(*chk).whoTo).rto_needed = 1u8
                                                }
                                            }
                                            (*chk).do_rtt = 0u8;
                                            if alt != net {
                                                if !(*chk).whoTo.is_null() {
                                                    if ::std::intrinsics::atomic_xadd(
                                                        &mut (*(*chk).whoTo).ref_count
                                                            as *mut libc::c_int,
                                                        -(1i32),
                                                    ) == 1i32
                                                    {
                                                        sctp_os_timer_stop(
                                                            &mut (*(*chk).whoTo).rxt_timer.timer,
                                                        );
                                                        sctp_os_timer_stop(
                                                            &mut (*(*chk).whoTo).pmtu_timer.timer,
                                                        );
                                                        sctp_os_timer_stop(
                                                            &mut (*(*chk).whoTo).hb_timer.timer,
                                                        );
                                                        if !(*(*chk).whoTo).ro.ro_rt.is_null() {
                                                            if (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt
                                                                <= 1i64
                                                            {
                                                                sctp_userspace_rtfree(
                                                                    (*(*chk).whoTo).ro.ro_rt,
                                                                );
                                                            } else {
                                                                (*(*(*chk).whoTo).ro.ro_rt)
                                                                    .rt_refcnt -= 1
                                                            }
                                                            (*(*chk).whoTo).ro.ro_rt =
                                                                0 as *mut sctp_rtentry_t;
                                                            (*(*chk).whoTo).ro.ro_rt =
                                                                0 as *mut sctp_rtentry_t
                                                        }
                                                        if (*(*chk).whoTo).src_addr_selected != 0 {
                                                            sctp_free_ifa(
                                                                (*(*chk).whoTo).ro._s_addr,
                                                            );
                                                            (*(*chk).whoTo).ro._s_addr =
                                                                0 as *mut sctp_ifa
                                                        }
                                                        (*(*chk).whoTo).src_addr_selected = 0u8;
                                                        (*(*chk).whoTo).dest_state =
                                                            ((*(*chk).whoTo).dest_state
                                                                as libc::c_int
                                                                & !(0x1i32))
                                                                as uint16_t;
                                                        free((*chk).whoTo as *mut libc::c_void);
                                                        ::std::intrinsics::atomic_xsub(
                                                            &mut system_base_info
                                                                .sctppcbinfo
                                                                .ipi_count_raddr,
                                                            1u32,
                                                        );
                                                    }
                                                }
                                                (*chk).no_fr_allowed = 1u8;
                                                (*chk).whoTo = alt;
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*alt).ref_count,
                                                    1i32,
                                                );
                                            } else {
                                                (*chk).no_fr_allowed = 0u8;
                                                if (*stcb).asoc.send_queue.tqh_first.is_null() {
                                                    (*chk).rec.data.fast_retran_tsn =
                                                        (*stcb).asoc.sending_seq
                                                } else {
                                                    (*chk).rec.data.fast_retran_tsn =
                                                        (*(*stcb).asoc.send_queue.tqh_first)
                                                            .rec
                                                            .data
                                                            .tsn
                                                }
                                            }
                                            /* CMT: Do not allow FRs on retransmitted TSNs.
                                             */
                                            if (*stcb).asoc.sctp_cmt_on_off as libc::c_int > 0i32 {
                                                (*chk).no_fr_allowed = 1u8
                                            }
                                            current_block_169 = 4894395567674443800;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                current_block_169 = 4894395567674443800;
            }
            match current_block_169 {
                4894395567674443800 => {
                    if (*chk).sent == 4i32 {
                        cnt_mk = cnt_mk.wrapping_add(1)
                    }
                }
                _ => {}
            }
            /*
             * ok it was sent after our boundary
             * time.
             */
            chk = nchk
        }
    }
    if orig_flight.wrapping_sub((*net).flight_size)
        != orig_tf.wrapping_sub((*stcb).asoc.total_flight)
    {
        /* we did not subtract the same things? */
        audit_tf = 1i32
    }
    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
        sctp_log_fr(tsnfirst, tsnlast, num_mk as uint32_t, 20i32);
    }
    if num_mk != 0 {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"LAST TSN marked was %x\n\x00" as *const u8 as *const libc::c_char,
                    tsnlast,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Num marked for retransmission was %d peer-rwd:%u\n\x00" as *const u8
                        as *const libc::c_char,
                    num_mk,
                    (*stcb).asoc.peers_rwnd,
                );
            }
        }
    }
    *num_marked = num_mk;
    *num_abandoned = cnt_abandoned;
    /* Now check for a ECN Echo that may be stranded And
     * include the cnt_mk'd to have all resends in the
     * control queue.
     */
    chk = (*stcb).asoc.control_send_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).sent == 4i32 {
            cnt_mk = cnt_mk.wrapping_add(1)
        }
        if (*chk).whoTo == net && (*chk).rec.chunk_id.id as libc::c_int == 0xci32 {
            if !(*chk).whoTo.is_null() {
                if ::std::intrinsics::atomic_xadd(
                    &mut (*(*chk).whoTo).ref_count as *mut libc::c_int,
                    -(1i32),
                ) == 1i32
                {
                    sctp_os_timer_stop(&mut (*(*chk).whoTo).rxt_timer.timer);
                    sctp_os_timer_stop(&mut (*(*chk).whoTo).pmtu_timer.timer);
                    sctp_os_timer_stop(&mut (*(*chk).whoTo).hb_timer.timer);
                    if !(*(*chk).whoTo).ro.ro_rt.is_null() {
                        if (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                            sctp_userspace_rtfree((*(*chk).whoTo).ro.ro_rt);
                        } else {
                            (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt -= 1
                        }
                        (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                        (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                    }
                    if (*(*chk).whoTo).src_addr_selected != 0 {
                        sctp_free_ifa((*(*chk).whoTo).ro._s_addr);
                        (*(*chk).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                    }
                    (*(*chk).whoTo).src_addr_selected = 0u8;
                    (*(*chk).whoTo).dest_state =
                        ((*(*chk).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                    free((*chk).whoTo as *mut libc::c_void);
                    ::std::intrinsics::atomic_xsub(
                        &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                        1u32,
                    );
                }
            }
            (*chk).whoTo = alt;
            if (*chk).sent != 4i32 {
                (*chk).sent = 4i32;
                (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t;
                (*stcb).asoc.sent_queue_retran_cnt =
                    (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1);
                cnt_mk = cnt_mk.wrapping_add(1)
            }
            ::std::intrinsics::atomic_xadd(&mut (*alt).ref_count, 1i32);
        }
        chk = (*chk).sctp_next.tqe_next
    }
    if (*stcb).asoc.sent_queue_retran_cnt != cnt_mk {
        (*stcb).asoc.sent_queue_retran_cnt = cnt_mk
    }
    if audit_tf != 0 {
        let mut lnets = 0 as *mut sctp_nets;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x8u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Audit total flight due to negative value net:%p\n\x00" as *const u8
                        as *const libc::c_char,
                    net as *mut libc::c_void,
                );
            }
        }
        (*stcb).asoc.total_flight = 0u32;
        (*stcb).asoc.total_flight_count = 0u32;
        /* Clear all networks flight size */
        lnets = (*stcb).asoc.nets.tqh_first;
        while !lnets.is_null() {
            (*lnets).flight_size = 0u32;
            if system_base_info.sctpsysctl.sctp_debug_on & 0x8u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Net:%p c-f cwnd:%d ssthresh:%d\n\x00" as *const u8 as *const libc::c_char,
                        lnets as *mut libc::c_void,
                        (*lnets).cwnd,
                        (*lnets).ssthresh,
                    );
                }
            }
            lnets = (*lnets).sctp_next.tqe_next
        }
        chk = (*stcb).asoc.sent_queue.tqh_first;
        while !chk.is_null() {
            if (*chk).sent < 4i32 {
                if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
                    sctp_misc_ints(
                        108u8,
                        (*(*chk).whoTo).flight_size,
                        (*chk).book_size as uint32_t,
                        (*chk).whoTo as uint32_t,
                        (*chk).rec.data.tsn,
                    );
                }
                (*(*chk).whoTo).flight_size =
                    ((*(*chk).whoTo).flight_size).wrapping_add((*chk).book_size as libc::c_uint);
                (*stcb).asoc.total_flight_count = (*stcb).asoc.total_flight_count.wrapping_add(1);
                (*stcb).asoc.total_flight = (*stcb)
                    .asoc
                    .total_flight
                    .wrapping_add((*chk).book_size as libc::c_uint)
            }
            chk = (*chk).sctp_next.tqe_next
        }
    }
    /* We return 1 if we only have a window probe outstanding */
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_t3rxt_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    let mut alt = 0 as *mut sctp_nets;
    let mut win_probe = 0;
    let mut num_mk = 0;
    let mut num_abandoned = 0;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
        sctp_log_fr(0u32, 0u32, 0u32, 20i32);
    }
    if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
        let mut lnet = 0 as *mut sctp_nets;
        lnet = (*stcb).asoc.nets.tqh_first;
        while !lnet.is_null() {
            if net == lnet {
                sctp_log_cwnd(stcb, lnet, 1i32, 63u8);
            } else {
                sctp_log_cwnd(stcb, lnet, 0i32, 63u8);
            }
            lnet = (*lnet).sctp_next.tqe_next
        }
    }
    /* Find an alternate and mark those for retransmission */
    if (*stcb).asoc.peers_rwnd == 0u32 && (*stcb).asoc.total_flight < (*net).mtu {
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_timowindowprobe, 1u32);
        win_probe = 1i32
    } else {
        win_probe = 0i32
    }
    if win_probe == 0i32 {
        /* We don't do normal threshold management on window probes */
        if sctp_threshold_management(inp, stcb, net, (*stcb).asoc.max_send_times) != 0 {
            /* Association was destroyed */
            return 1i32;
        } else {
            if net != (*stcb).asoc.primary_destination {
                let mut now = timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                };
                let mut ms_goneby = 0;
                gettimeofday(&mut now, 0 as *mut timezone);
                if (*net).last_sent_time.tv_sec != 0 {
                    ms_goneby =
                        ((now.tv_sec - (*net).last_sent_time.tv_sec) * 1000i64) as libc::c_uint
                } else {
                    ms_goneby = 0u32
                }
                if (*net).dest_state as libc::c_int & 0x800i32 == 0i32 {
                    if ms_goneby > (*net).RTO || (*net).RTO == 0u32 {
                        /*
                         * no recent feed back in an RTO or
                         * more, request a RTT update
                         */
                        sctp_send_hb(stcb, net, 0i32);
                    }
                }
            }
        }
    } else if sctp_threshold_management(inp, stcb, 0 as *mut sctp_nets, (*stcb).asoc.max_send_times)
        != 0
    {
        /*
         * For a window probe we don't penalize the net's but only
         * the association. This may fail it if SACKs are not coming
         * back. If sack's are coming with rwnd locked at 0, we will
         * continue to hold things waiting for rwnd to raise
         */
        /* Association was destroyed */
        return 1i32;
    }
    if (*stcb).asoc.sctp_cmt_on_off as libc::c_int > 0i32 {
        if ((*net).pf_threshold as libc::c_int) < (*net).failure_threshold as libc::c_int {
            alt = sctp_find_alternate_net(stcb, net, 2i32)
        } else {
            /*
             * CMT: Using RTX_SSTHRESH policy for CMT.
             * If CMT is being used, then pick dest with
             * largest ssthresh for any retransmission.
             */
            alt = sctp_find_alternate_net(stcb, net, 1i32);
            /*
             * CUCv2: If a different dest is picked for
             * the retransmission, then new
             * (rtx-)pseudo_cumack needs to be tracked
             * for orig dest. Let CUCv2 track new (rtx-)
             * pseudo-cumack always.
             */
            (*net).find_pseudo_cumack = 1u8;
            (*net).find_rtx_pseudo_cumack = 1u8
        }
    } else {
        alt = sctp_find_alternate_net(stcb, net, 0i32)
    }
    num_mk = 0i32;
    num_abandoned = 0i32;
    sctp_mark_all_for_resend(stcb, net, alt, win_probe, &mut num_mk, &mut num_abandoned);
    /* FR Loss recovery just ended with the T3. */
    (*stcb).asoc.fast_retran_loss_recovery = 0u8;
    /* CMT FR loss recovery ended with the T3 */
    (*net).fast_retran_loss_recovery = 0u8;
    if (*stcb)
        .asoc
        .cc_functions
        .sctp_cwnd_new_transmission_begins
        .is_some()
        && (*net).flight_size == 0u32
    {
        Some(
            (*stcb)
                .asoc
                .cc_functions
                .sctp_cwnd_new_transmission_begins
                .expect("non-null function pointer"),
        )
        .expect("non-null function pointer")(stcb, net);
    }
    /*
     * setup the sat loss recovery that prevents satellite cwnd advance.
     */
    (*stcb).asoc.sat_t3_loss_recovery = 1u8;
    (*stcb).asoc.sat_t3_recovery_tsn = (*stcb).asoc.sending_seq;
    /* Backoff the timer and cwnd */
    sctp_backoff_on_timeout(stcb, net, win_probe, num_mk, num_abandoned);
    if (*net).dest_state as libc::c_int & 0x1i32 == 0
        || (*net).dest_state as libc::c_int & 0x800i32 != 0
    {
        /* Move all pending over too */
        sctp_move_chunks_from_net(stcb, net);
        /* Get the address that failed, to
         * force a new src address selecton and
         * a route allocation.
         */
        if !(*net).ro._s_addr.is_null() {
            sctp_free_ifa((*net).ro._s_addr);
            (*net).ro._s_addr = 0 as *mut sctp_ifa
        }
        (*net).src_addr_selected = 0u8;
        /* Force a route allocation too */
        if !(*net).ro.ro_rt.is_null() {
            if (*(*net).ro.ro_rt).rt_refcnt <= 1i64 {
                sctp_userspace_rtfree((*net).ro.ro_rt);
            } else {
                (*(*net).ro.ro_rt).rt_refcnt -= 1
            }
            (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t;
            (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t
        }
        /* Was it our primary? */
        if (*stcb).asoc.primary_destination == net && alt != net {
            /*
             * Yes, note it as such and find an alternate note:
             * this means HB code must use this to resent the
             * primary if it goes active AND if someone does a
             * change-primary then this flag must be cleared
             * from any net structures.
             */
            if !(*stcb).asoc.alternate.is_null() {
                if !(*stcb).asoc.alternate.is_null() {
                    if ::std::intrinsics::atomic_xadd(
                        &mut (*(*stcb).asoc.alternate).ref_count as *mut libc::c_int,
                        -(1i32),
                    ) == 1i32
                    {
                        sctp_os_timer_stop(&mut (*(*stcb).asoc.alternate).rxt_timer.timer);
                        sctp_os_timer_stop(&mut (*(*stcb).asoc.alternate).pmtu_timer.timer);
                        sctp_os_timer_stop(&mut (*(*stcb).asoc.alternate).hb_timer.timer);
                        if !(*(*stcb).asoc.alternate).ro.ro_rt.is_null() {
                            if (*(*(*stcb).asoc.alternate).ro.ro_rt).rt_refcnt <= 1i64 {
                                sctp_userspace_rtfree((*(*stcb).asoc.alternate).ro.ro_rt);
                            } else {
                                (*(*(*stcb).asoc.alternate).ro.ro_rt).rt_refcnt -= 1
                            }
                            (*(*stcb).asoc.alternate).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                            (*(*stcb).asoc.alternate).ro.ro_rt = 0 as *mut sctp_rtentry_t
                        }
                        if (*(*stcb).asoc.alternate).src_addr_selected != 0 {
                            sctp_free_ifa((*(*stcb).asoc.alternate).ro._s_addr);
                            (*(*stcb).asoc.alternate).ro._s_addr = 0 as *mut sctp_ifa
                        }
                        (*(*stcb).asoc.alternate).src_addr_selected = 0u8;
                        (*(*stcb).asoc.alternate).dest_state =
                            ((*(*stcb).asoc.alternate).dest_state as libc::c_int & !(0x1i32))
                                as uint16_t;
                        free((*stcb).asoc.alternate as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                            1u32,
                        );
                    }
                }
            }
            (*stcb).asoc.alternate = alt;
            ::std::intrinsics::atomic_xadd(&mut (*(*stcb).asoc.alternate).ref_count, 1i32);
        }
    }
    /*
     * Special case for cookie-echo'ed case, we don't do output but must
     * await the COOKIE-ACK before retransmission
     */
    if (*stcb).asoc.state & 0x7fi32 == 0x4i32 {
        /*
         * Here we just reset the timer and start again since we
         * have not established the asoc
         */
        sctp_timer_start(1i32, inp, stcb, net);
        return 0i32;
    }
    if (*stcb).asoc.prsctp_supported != 0 {
        let mut lchk = 0 as *mut sctp_tmit_chunk;
        lchk = sctp_try_advance_peer_ack_point(stcb, &mut (*stcb).asoc);
        /* C3. See if we need to send a Fwd-TSN */
        if (*stcb).asoc.advanced_peer_ack_point < (*stcb).asoc.last_acked_seq
            && (*stcb)
                .asoc
                .last_acked_seq
                .wrapping_sub((*stcb).asoc.advanced_peer_ack_point)
                > (1u32) << 31i32
            || (*stcb).asoc.advanced_peer_ack_point > (*stcb).asoc.last_acked_seq
                && (*stcb)
                    .asoc
                    .advanced_peer_ack_point
                    .wrapping_sub((*stcb).asoc.last_acked_seq)
                    < (1u32) << 31i32
        {
            send_forward_tsn(stcb, &mut (*stcb).asoc);
            if !lchk.is_null() {
                /* Assure a timer is up */
                sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, (*lchk).whoTo);
            }
        }
    }
    if system_base_info.sctpsysctl.sctp_logging_level & 0x2u32 != 0 {
        sctp_log_cwnd(stcb, net, (*net).cwnd as libc::c_int, 2u8);
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_t1init_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    /* bump the thresholds */
    if (*stcb).asoc.delayed_connection != 0 {
        /*
         * special hook for delayed connection. The library did NOT
         * complete the rest of its sends.
         */
        (*stcb).asoc.delayed_connection = 0u8;
        sctp_send_initiate(inp, stcb, 0i32);
        return 0i32;
    }
    if (*stcb).asoc.state & 0x7fi32 != 0x2i32 {
        return 0i32;
    }
    if sctp_threshold_management(inp, stcb, net, (*stcb).asoc.max_init_times) != 0 {
        /* Association was destroyed */
        return 1i32;
    }
    (*stcb).asoc.dropped_special_cnt = 0u8;
    sctp_backoff_on_timeout(stcb, (*stcb).asoc.primary_destination, 1i32, 0i32, 0i32);
    if (*stcb).asoc.initial_init_rto_max < (*net).RTO {
        (*net).RTO = (*stcb).asoc.initial_init_rto_max
    }
    if (*stcb).asoc.numnets > 1u32 {
        let mut alt = 0 as *mut sctp_nets;
        alt = sctp_find_alternate_net(stcb, (*stcb).asoc.primary_destination, 0i32);
        if alt != (*stcb).asoc.primary_destination {
            sctp_move_chunks_from_net(stcb, (*stcb).asoc.primary_destination);
            (*stcb).asoc.primary_destination = alt
        }
    }
    /* Send out a new init */
    sctp_send_initiate(inp, stcb, 0i32);
    return 0i32;
}
/*
 * For cookie and asconf we actually need to find and mark for resend, then
 * increment the resend counter (after all the threshold management stuff of
 * course).
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_cookie_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    let mut alt = 0 as *mut sctp_nets;
    let mut cookie = 0 as *mut sctp_tmit_chunk;
    /* first before all else we must find the cookie */
    cookie = (*stcb).asoc.control_send_queue.tqh_first;
    while !cookie.is_null() {
        if (*cookie).rec.chunk_id.id as libc::c_int == 0xai32 {
            break;
        }
        cookie = (*cookie).sctp_next.tqe_next
    }
    if cookie.is_null() {
        if (*stcb).asoc.state & 0x7fi32 == 0x4i32 {
            let mut op_err = 0 as *mut mbuf;
            op_err = sctp_generate_cause(
                system_base_info.sctpsysctl.sctp_diag_info_code as uint16_t,
                b"Cookie timer expired, but no cookie\x00" as *const u8 as *mut libc::c_char,
            );
            (*inp).last_abort_code = (0x40000000i32 + 0x3i32) as uint32_t;
            sctp_abort_an_association(inp, stcb, op_err, 0i32);
        } else {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Strange in state %d not cookie-echoed yet c-e timer expires?\n\x00"
                        as *const u8 as *const libc::c_char,
                    (*stcb).asoc.state & 0x7fi32,
                );
            }
            return 0i32;
        }
        return 0i32;
    }
    /* Ok we found the cookie, threshold management next */
    if sctp_threshold_management(inp, stcb, (*cookie).whoTo, (*stcb).asoc.max_init_times) != 0 {
        /* Assoc is over */
        return 1i32;
    }
    /*
     * Cleared threshold management, now lets backoff the address
     * and select an alternate
     */
    (*stcb).asoc.dropped_special_cnt = 0u8;
    sctp_backoff_on_timeout(stcb, (*cookie).whoTo, 1i32, 0i32, 0i32);
    alt = sctp_find_alternate_net(stcb, (*cookie).whoTo, 0i32);
    if alt != (*cookie).whoTo {
        if !(*cookie).whoTo.is_null() {
            if ::std::intrinsics::atomic_xadd(
                &mut (*(*cookie).whoTo).ref_count as *mut libc::c_int,
                -(1i32),
            ) == 1i32
            {
                sctp_os_timer_stop(&mut (*(*cookie).whoTo).rxt_timer.timer);
                sctp_os_timer_stop(&mut (*(*cookie).whoTo).pmtu_timer.timer);
                sctp_os_timer_stop(&mut (*(*cookie).whoTo).hb_timer.timer);
                if !(*(*cookie).whoTo).ro.ro_rt.is_null() {
                    if (*(*(*cookie).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                        sctp_userspace_rtfree((*(*cookie).whoTo).ro.ro_rt);
                    } else {
                        (*(*(*cookie).whoTo).ro.ro_rt).rt_refcnt -= 1
                    }
                    (*(*cookie).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                    (*(*cookie).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                }
                if (*(*cookie).whoTo).src_addr_selected != 0 {
                    sctp_free_ifa((*(*cookie).whoTo).ro._s_addr);
                    (*(*cookie).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                }
                (*(*cookie).whoTo).src_addr_selected = 0u8;
                (*(*cookie).whoTo).dest_state =
                    ((*(*cookie).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                free((*cookie).whoTo as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                    1u32,
                );
            }
        }
        (*cookie).whoTo = alt;
        ::std::intrinsics::atomic_xadd(&mut (*alt).ref_count, 1i32);
    }
    /* Now mark the retran info */
    if (*cookie).sent != 4i32 {
        (*stcb).asoc.sent_queue_retran_cnt = (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1)
    }
    (*cookie).sent = 4i32;
    (*cookie).flags = ((*cookie).flags as libc::c_int | 0x100i32) as uint16_t;
    /*
     * Now call the output routine to kick out the cookie again, Note we
     * don't mark any chunks for retran so that FR will need to kick in
     * to move these (or a send timer).
     */
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_strreset_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    let mut alt = 0 as *mut sctp_nets;
    let mut strrst = 0 as *mut sctp_tmit_chunk;
    let mut chk = 0 as *mut sctp_tmit_chunk;
    if (*stcb).asoc.stream_reset_outstanding as libc::c_int == 0i32 {
        return 0i32;
    }
    /* find the existing STRRESET, we use the seq number we sent out on */
    sctp_find_stream_reset(stcb, (*stcb).asoc.str_reset_seq_out, &mut strrst);
    if strrst.is_null() {
        return 0i32;
    }
    /* do threshold management */
    if sctp_threshold_management(inp, stcb, (*strrst).whoTo, (*stcb).asoc.max_send_times) != 0 {
        /* Assoc is over */
        return 1i32;
    }
    /*
     * Cleared threshold management, now lets backoff the address
     * and select an alternate
     */
    sctp_backoff_on_timeout(stcb, (*strrst).whoTo, 1i32, 0i32, 0i32);
    alt = sctp_find_alternate_net(stcb, (*strrst).whoTo, 0i32);
    if !(*strrst).whoTo.is_null() {
        if ::std::intrinsics::atomic_xadd(
            &mut (*(*strrst).whoTo).ref_count as *mut libc::c_int,
            -(1i32),
        ) == 1i32
        {
            sctp_os_timer_stop(&mut (*(*strrst).whoTo).rxt_timer.timer);
            sctp_os_timer_stop(&mut (*(*strrst).whoTo).pmtu_timer.timer);
            sctp_os_timer_stop(&mut (*(*strrst).whoTo).hb_timer.timer);
            if !(*(*strrst).whoTo).ro.ro_rt.is_null() {
                if (*(*(*strrst).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                    sctp_userspace_rtfree((*(*strrst).whoTo).ro.ro_rt);
                } else {
                    (*(*(*strrst).whoTo).ro.ro_rt).rt_refcnt -= 1
                }
                (*(*strrst).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                (*(*strrst).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
            }
            if (*(*strrst).whoTo).src_addr_selected != 0 {
                sctp_free_ifa((*(*strrst).whoTo).ro._s_addr);
                (*(*strrst).whoTo).ro._s_addr = 0 as *mut sctp_ifa
            }
            (*(*strrst).whoTo).src_addr_selected = 0u8;
            (*(*strrst).whoTo).dest_state =
                ((*(*strrst).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
            free((*strrst).whoTo as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_raddr, 1u32);
        }
    }
    (*strrst).whoTo = alt;
    ::std::intrinsics::atomic_xadd(&mut (*alt).ref_count, 1i32);
    /* See if a ECN Echo is also stranded */
    chk = (*stcb).asoc.control_send_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).whoTo == net && (*chk).rec.chunk_id.id as libc::c_int == 0xci32 {
            if !(*chk).whoTo.is_null() {
                if ::std::intrinsics::atomic_xadd(
                    &mut (*(*chk).whoTo).ref_count as *mut libc::c_int,
                    -(1i32),
                ) == 1i32
                {
                    sctp_os_timer_stop(&mut (*(*chk).whoTo).rxt_timer.timer);
                    sctp_os_timer_stop(&mut (*(*chk).whoTo).pmtu_timer.timer);
                    sctp_os_timer_stop(&mut (*(*chk).whoTo).hb_timer.timer);
                    if !(*(*chk).whoTo).ro.ro_rt.is_null() {
                        if (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                            sctp_userspace_rtfree((*(*chk).whoTo).ro.ro_rt);
                        } else {
                            (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt -= 1
                        }
                        (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                        (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                    }
                    if (*(*chk).whoTo).src_addr_selected != 0 {
                        sctp_free_ifa((*(*chk).whoTo).ro._s_addr);
                        (*(*chk).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                    }
                    (*(*chk).whoTo).src_addr_selected = 0u8;
                    (*(*chk).whoTo).dest_state =
                        ((*(*chk).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                    free((*chk).whoTo as *mut libc::c_void);
                    ::std::intrinsics::atomic_xsub(
                        &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                        1u32,
                    );
                }
            }
            if (*chk).sent != 4i32 {
                (*chk).sent = 4i32;
                (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t;
                (*stcb).asoc.sent_queue_retran_cnt =
                    (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1)
            }
            (*chk).whoTo = alt;
            ::std::intrinsics::atomic_xadd(&mut (*alt).ref_count, 1i32);
        }
        chk = (*chk).sctp_next.tqe_next
    }
    if (*net).dest_state as libc::c_int & 0x1i32 == 0 {
        /*
         * If the address went un-reachable, we need to move to
         * alternates for ALL chk's in queue
         */
        sctp_move_chunks_from_net(stcb, net);
    }
    /* mark the retran info */
    if (*strrst).sent != 4i32 {
        (*stcb).asoc.sent_queue_retran_cnt = (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1)
    }
    (*strrst).sent = 4i32;
    (*strrst).flags = ((*strrst).flags as libc::c_int | 0x100i32) as uint16_t;
    /* restart the timer */
    sctp_timer_start(14i32, inp, stcb, (*strrst).whoTo);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_asconf_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    /* is this a first send, or a retransmission? */
    if (*stcb).asoc.asconf_send_queue.tqh_first.is_null() {
        /* compose a new ASCONF chunk and send it */
        sctp_send_asconf(stcb, net, 0i32);
    } else {
        let mut alt = 0 as *mut sctp_nets;
        let mut asconf = 0 as *mut sctp_tmit_chunk;
        let mut chk = 0 as *mut sctp_tmit_chunk;
        asconf = (*stcb).asoc.asconf_send_queue.tqh_first;
        if asconf.is_null() {
            return 0i32;
        }
        /* do threshold management */
        if sctp_threshold_management(inp, stcb, (*asconf).whoTo, (*stcb).asoc.max_send_times) != 0 {
            /* Assoc is over */
            return 1i32;
        }
        if (*asconf).snd_count as libc::c_int > (*stcb).asoc.max_send_times as libc::c_int {
            /*
             * Something is rotten: our peer is not responding to
             * ASCONFs but apparently is to other chunks.  i.e. it
             * is not properly handling the chunk type upper bits.
             * Mark this peer as ASCONF incapable and cleanup.
             */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"asconf_timer: Peer has not responded to our repeated ASCONFs\n\x00"
                            as *const u8 as *const libc::c_char,
                    );
                }
            }
            sctp_asconf_cleanup(stcb, net);
            return 0i32;
        }
        /*
         * cleared threshold management, so now backoff the net and
         * select an alternate
         */
        sctp_backoff_on_timeout(stcb, (*asconf).whoTo, 1i32, 0i32, 0i32);
        alt = sctp_find_alternate_net(stcb, (*asconf).whoTo, 0i32);
        if (*asconf).whoTo != alt {
            if !(*asconf).whoTo.is_null() {
                if ::std::intrinsics::atomic_xadd(
                    &mut (*(*asconf).whoTo).ref_count as *mut libc::c_int,
                    -(1i32),
                ) == 1i32
                {
                    sctp_os_timer_stop(&mut (*(*asconf).whoTo).rxt_timer.timer);
                    sctp_os_timer_stop(&mut (*(*asconf).whoTo).pmtu_timer.timer);
                    sctp_os_timer_stop(&mut (*(*asconf).whoTo).hb_timer.timer);
                    if !(*(*asconf).whoTo).ro.ro_rt.is_null() {
                        if (*(*(*asconf).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                            sctp_userspace_rtfree((*(*asconf).whoTo).ro.ro_rt);
                        } else {
                            (*(*(*asconf).whoTo).ro.ro_rt).rt_refcnt -= 1
                        }
                        (*(*asconf).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                        (*(*asconf).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                    }
                    if (*(*asconf).whoTo).src_addr_selected != 0 {
                        sctp_free_ifa((*(*asconf).whoTo).ro._s_addr);
                        (*(*asconf).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                    }
                    (*(*asconf).whoTo).src_addr_selected = 0u8;
                    (*(*asconf).whoTo).dest_state =
                        ((*(*asconf).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                    free((*asconf).whoTo as *mut libc::c_void);
                    ::std::intrinsics::atomic_xsub(
                        &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                        1u32,
                    );
                }
            }
            (*asconf).whoTo = alt;
            ::std::intrinsics::atomic_xadd(&mut (*alt).ref_count, 1i32);
        }
        /* See if an ECN Echo is also stranded */
        chk = (*stcb).asoc.control_send_queue.tqh_first;
        while !chk.is_null() {
            if (*chk).whoTo == net && (*chk).rec.chunk_id.id as libc::c_int == 0xci32 {
                if !(*chk).whoTo.is_null() {
                    if ::std::intrinsics::atomic_xadd(
                        &mut (*(*chk).whoTo).ref_count as *mut libc::c_int,
                        -(1i32),
                    ) == 1i32
                    {
                        sctp_os_timer_stop(&mut (*(*chk).whoTo).rxt_timer.timer);
                        sctp_os_timer_stop(&mut (*(*chk).whoTo).pmtu_timer.timer);
                        sctp_os_timer_stop(&mut (*(*chk).whoTo).hb_timer.timer);
                        if !(*(*chk).whoTo).ro.ro_rt.is_null() {
                            if (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                                sctp_userspace_rtfree((*(*chk).whoTo).ro.ro_rt);
                            } else {
                                (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt -= 1
                            }
                            (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                            (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                        }
                        if (*(*chk).whoTo).src_addr_selected != 0 {
                            sctp_free_ifa((*(*chk).whoTo).ro._s_addr);
                            (*(*chk).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                        }
                        (*(*chk).whoTo).src_addr_selected = 0u8;
                        (*(*chk).whoTo).dest_state =
                            ((*(*chk).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                        free((*chk).whoTo as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                            1u32,
                        );
                    }
                }
                (*chk).whoTo = alt;
                if (*chk).sent != 4i32 {
                    (*chk).sent = 4i32;
                    (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t;
                    (*stcb).asoc.sent_queue_retran_cnt =
                        (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1)
                }
                ::std::intrinsics::atomic_xadd(&mut (*alt).ref_count, 1i32);
            }
            chk = (*chk).sctp_next.tqe_next
        }
        chk = (*stcb).asoc.asconf_send_queue.tqh_first;
        while !chk.is_null() {
            if (*chk).whoTo != alt {
                if !(*chk).whoTo.is_null() {
                    if ::std::intrinsics::atomic_xadd(
                        &mut (*(*chk).whoTo).ref_count as *mut libc::c_int,
                        -(1i32),
                    ) == 1i32
                    {
                        sctp_os_timer_stop(&mut (*(*chk).whoTo).rxt_timer.timer);
                        sctp_os_timer_stop(&mut (*(*chk).whoTo).pmtu_timer.timer);
                        sctp_os_timer_stop(&mut (*(*chk).whoTo).hb_timer.timer);
                        if !(*(*chk).whoTo).ro.ro_rt.is_null() {
                            if (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                                sctp_userspace_rtfree((*(*chk).whoTo).ro.ro_rt);
                            } else {
                                (*(*(*chk).whoTo).ro.ro_rt).rt_refcnt -= 1
                            }
                            (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                            (*(*chk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                        }
                        if (*(*chk).whoTo).src_addr_selected != 0 {
                            sctp_free_ifa((*(*chk).whoTo).ro._s_addr);
                            (*(*chk).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                        }
                        (*(*chk).whoTo).src_addr_selected = 0u8;
                        (*(*chk).whoTo).dest_state =
                            ((*(*chk).whoTo).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                        free((*chk).whoTo as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                            1u32,
                        );
                    }
                }
                (*chk).whoTo = alt;
                ::std::intrinsics::atomic_xadd(&mut (*alt).ref_count, 1i32);
            }
            if (*asconf).sent != 4i32 && (*chk).sent != 0i32 {
                (*stcb).asoc.sent_queue_retran_cnt =
                    (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1)
            }
            (*chk).sent = 4i32;
            (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t;
            chk = (*chk).sctp_next.tqe_next
        }
        if (*net).dest_state as libc::c_int & 0x1i32 == 0 {
            /*
             * If the address went un-reachable, we need to move
             * to the alternate for ALL chunks in queue
             */
            sctp_move_chunks_from_net(stcb, net);
        }
        /* mark the retran info */
        if (*asconf).sent != 4i32 {
            (*stcb).asoc.sent_queue_retran_cnt = (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1)
        }
        (*asconf).sent = 4i32;
        (*asconf).flags = ((*asconf).flags as libc::c_int | 0x100i32) as uint16_t;
        /* send another ASCONF if any and we can do */
        sctp_send_asconf(stcb, alt, 0i32);
    }
    return 0i32;
}
/* Mobility adaptation */
#[no_mangle]
pub unsafe extern "C" fn sctp_delete_prim_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    if (*stcb).asoc.deleted_primary.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"delete_prim_timer: deleted_primary is not stored...\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        (*inp).sctp_mobility_features &= !(0x4i32) as libc::c_uint;
        return;
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"delete_prim_timer: finished to keep deleted primary \x00" as *const u8
                    as *const libc::c_char,
            );
        }
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
        sctp_print_address(&mut (*(*stcb).asoc.deleted_primary).ro._l_addr.sa);
    }
    if !(*stcb).asoc.deleted_primary.is_null() {
        if ::std::intrinsics::atomic_xadd(
            &mut (*(*stcb).asoc.deleted_primary).ref_count as *mut libc::c_int,
            -(1i32),
        ) == 1i32
        {
            sctp_os_timer_stop(&mut (*(*stcb).asoc.deleted_primary).rxt_timer.timer);
            sctp_os_timer_stop(&mut (*(*stcb).asoc.deleted_primary).pmtu_timer.timer);
            sctp_os_timer_stop(&mut (*(*stcb).asoc.deleted_primary).hb_timer.timer);
            if !(*(*stcb).asoc.deleted_primary).ro.ro_rt.is_null() {
                if (*(*(*stcb).asoc.deleted_primary).ro.ro_rt).rt_refcnt <= 1i64 {
                    sctp_userspace_rtfree((*(*stcb).asoc.deleted_primary).ro.ro_rt);
                } else {
                    (*(*(*stcb).asoc.deleted_primary).ro.ro_rt).rt_refcnt -= 1
                }
                (*(*stcb).asoc.deleted_primary).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                (*(*stcb).asoc.deleted_primary).ro.ro_rt = 0 as *mut sctp_rtentry_t
            }
            if (*(*stcb).asoc.deleted_primary).src_addr_selected != 0 {
                sctp_free_ifa((*(*stcb).asoc.deleted_primary).ro._s_addr);
                (*(*stcb).asoc.deleted_primary).ro._s_addr = 0 as *mut sctp_ifa
            }
            (*(*stcb).asoc.deleted_primary).src_addr_selected = 0u8;
            (*(*stcb).asoc.deleted_primary).dest_state =
                ((*(*stcb).asoc.deleted_primary).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
            free((*stcb).asoc.deleted_primary as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_raddr, 1u32);
        }
    }
    (*stcb).asoc.deleted_primary = 0 as *mut sctp_nets;
    (*inp).sctp_mobility_features &= !(0x4i32) as libc::c_uint;
}
/*
 * For the shutdown and shutdown-ack, we do not keep one around on the
 * control queue. This means we must generate a new one and call the general
 * chunk output routine, AFTER having done threshold management.
 * It is assumed that net is non-NULL.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_shutdown_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    let mut alt = 0 as *mut sctp_nets;
    /* first threshold management */
    if sctp_threshold_management(inp, stcb, net, (*stcb).asoc.max_send_times) != 0 {
        /* Assoc is over */
        return 1i32;
    }
    sctp_backoff_on_timeout(stcb, net, 1i32, 0i32, 0i32);
    /* second select an alternative */
    alt = sctp_find_alternate_net(stcb, net, 0i32);
    /* third generate a shutdown into the queue for out net */
    sctp_send_shutdown(stcb, alt);
    /* fourth restart timer */
    sctp_timer_start(4i32, inp, stcb, alt);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_shutdownack_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    let mut alt = 0 as *mut sctp_nets;
    /* first threshold management */
    if sctp_threshold_management(inp, stcb, net, (*stcb).asoc.max_send_times) != 0 {
        /* Assoc is over */
        return 1i32;
    }
    sctp_backoff_on_timeout(stcb, net, 1i32, 0i32, 0i32);
    /* second select an alternative */
    alt = sctp_find_alternate_net(stcb, net, 0i32);
    /* third generate a shutdown into the queue for out net */
    sctp_send_shutdown_ack(stcb, alt);
    /* fourth restart timer */
    sctp_timer_start(9i32, inp, stcb, alt);
    return 0i32;
}
unsafe extern "C" fn sctp_audit_stream_queues_for_size(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
) {
    let mut i = 0;
    let mut chks_in_queue = 0u32;
    let mut being_filled = 0i32;
    /*
     * This function is ONLY called when the send/sent queues are empty.
     */
    if stcb.is_null() || inp.is_null() {
        return;
    }
    if (*stcb).asoc.sent_queue_retran_cnt != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Hmm, sent_queue_retran_cnt is non-zero %d\n\x00" as *const u8
                    as *const libc::c_char,
                (*stcb).asoc.sent_queue_retran_cnt,
            );
        }
        (*stcb).asoc.sent_queue_retran_cnt = 0u32
    }
    if (*stcb)
        .asoc
        .ss_functions
        .sctp_ss_is_empty
        .expect("non-null function pointer")(stcb, &mut (*stcb).asoc)
        != 0
    {
        /* No stream scheduler information, initialize scheduler */
        (*stcb)
            .asoc
            .ss_functions
            .sctp_ss_init
            .expect("non-null function pointer")(stcb, &mut (*stcb).asoc, 0i32);
        if (*stcb)
            .asoc
            .ss_functions
            .sctp_ss_is_empty
            .expect("non-null function pointer")(stcb, &mut (*stcb).asoc)
            == 0
        {
            /* yep, we lost a stream or two */
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Found additional streams NOT managed by scheduler, corrected\n\x00"
                        as *const u8 as *const libc::c_char,
                );
            }
        } else {
            /* no streams lost */
            (*stcb).asoc.total_output_queue_size = 0u32
        }
    }
    /* Check to see if some data queued, if so report it */
    i = 0u32;
    while i < (*stcb).asoc.streamoutcnt as libc::c_uint {
        if !(*(*stcb).asoc.strmout.offset(i as isize))
            .outqueue
            .tqh_first
            .is_null()
        {
            let mut sp = 0 as *mut sctp_stream_queue_pending;
            sp = (*(*stcb).asoc.strmout.offset(i as isize))
                .outqueue
                .tqh_first;
            while !sp.is_null() {
                if (*sp).msg_is_complete != 0 {
                    being_filled += 1
                }
                chks_in_queue = chks_in_queue.wrapping_add(1);
                sp = (*sp).next.tqe_next
            }
        }
        i = i.wrapping_add(1)
    }
    if chks_in_queue != (*stcb).asoc.stream_queue_cnt {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Hmm, stream queue cnt at %d I counted %d in stream out wheel\n\x00" as *const u8
                    as *const libc::c_char,
                (*stcb).asoc.stream_queue_cnt,
                chks_in_queue,
            );
        }
    }
    if chks_in_queue != 0 {
        /* call the output queue function */
        sctp_chunk_output(inp, stcb, 1i32, 0i32);
        if (*stcb).asoc.send_queue.tqh_first.is_null()
            && (*stcb).asoc.sent_queue.tqh_first.is_null()
        {
            /*
             * Probably should go in and make it go back through
             * and add fragments allowed
             */
            if being_filled == 0i32 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Still nothing moved %d chunks are stuck\n\x00" as *const u8
                            as *const libc::c_char,
                        chks_in_queue,
                    );
                }
            }
        }
    } else {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Found no chunks on any queue tot:%lu\n\x00" as *const u8 as *const libc::c_char,
                (*stcb).asoc.total_output_queue_size as u_long,
            );
        }
        (*stcb).asoc.total_output_queue_size = 0u32
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_heartbeat_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    let mut net_was_pf = 0;
    if (*net).dest_state as libc::c_int & 0x800i32 != 0 {
        net_was_pf = 1u8
    } else {
        net_was_pf = 0u8
    }
    if (*net).hb_responded as libc::c_int == 0i32 {
        if !(*net).ro._s_addr.is_null() {
            /* Invalidate the src address if we did not get
             * a response last time.
             */
            sctp_free_ifa((*net).ro._s_addr);
            (*net).ro._s_addr = 0 as *mut sctp_ifa;
            (*net).src_addr_selected = 0u8
        }
        sctp_backoff_on_timeout(stcb, net, 1i32, 0i32, 0i32);
        if sctp_threshold_management(inp, stcb, net, (*stcb).asoc.max_send_times) != 0 {
            /* Assoc is over */
            return 1i32;
        }
    }
    /* Zero PBA, if it needs it */
    if (*net).partial_bytes_acked != 0 {
        (*net).partial_bytes_acked = 0u32
    }
    if (*stcb).asoc.total_output_queue_size > 0u32
        && (*stcb).asoc.send_queue.tqh_first.is_null()
        && (*stcb).asoc.sent_queue.tqh_first.is_null()
    {
        sctp_audit_stream_queues_for_size(inp, stcb);
    }
    if (*net).dest_state as libc::c_int & 0x4i32 == 0
        && !(net_was_pf as libc::c_int == 0i32 && (*net).dest_state as libc::c_int & 0x800i32 != 0)
    {
        let mut ms_gone_by = 0;
        if (*net).last_sent_time.tv_sec > 0i64 || (*net).last_sent_time.tv_usec > 0i64 {
            let mut diff = timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let mut now = timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            gettimeofday(&mut now, 0 as *mut timezone);
            diff.tv_sec = now.tv_sec - (*net).last_sent_time.tv_sec;
            diff.tv_usec = now.tv_usec - (*net).last_sent_time.tv_usec;
            if diff.tv_usec < 0i64 {
                diff.tv_sec -= 1;
                diff.tv_usec += 1000000i64
            }
            ms_gone_by = ((diff.tv_sec * 1000i64) as uint32_t)
                .wrapping_add((diff.tv_usec / 1000i64) as uint32_t)
        } else {
            ms_gone_by = 0xffffffffu32
        }
        if ms_gone_by >= (*net).heart_beat_delay || (*net).dest_state as libc::c_int & 0x800i32 != 0
        {
            sctp_send_hb(stcb, net, 0i32);
        }
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_pathmtu_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    let mut next_mtu = 0;
    next_mtu = sctp_get_next_mtu((*net).mtu);
    if next_mtu > (*net).mtu && (*net).port as libc::c_int == 0i32 {
        if (*net).src_addr_selected as libc::c_int == 0i32
            || (*net).ro._s_addr.is_null()
            || (*(*net).ro._s_addr).localifa_flags & 0x2u32 != 0
        {
            if !(*net).ro._s_addr.is_null() && (*(*net).ro._s_addr).localifa_flags & 0x2u32 != 0 {
                sctp_free_ifa((*net).ro._s_addr);
                (*net).ro._s_addr = 0 as *mut sctp_ifa;
                (*net).src_addr_selected = 0u8
            } else if (*net).ro._s_addr.is_null() {
                (*net).ro._s_addr = sctp_source_address_selection(
                    inp,
                    stcb,
                    &mut (*net).ro as *mut sctp_net_route as *mut sctp_route_t,
                    net,
                    0i32,
                    (*stcb).asoc.vrf_id,
                )
                /* INET6 */
            }
            if !(*net).ro._s_addr.is_null() {
                (*net).src_addr_selected = 1u8
            }
        }
        if !(*net).ro._s_addr.is_null() {
            let mut mtu = 0;
            mtu = if !(*net).ro.ro_rt.is_null() {
                (*(*net).ro.ro_rt).rt_rmx.rmx_mtu
            } else {
                0u32
            };
            if (*net).port != 0 {
                mtu = (mtu as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<udphdr>() as libc::c_ulong)
                    as uint32_t
            }
            if mtu > next_mtu {
                (*net).mtu = next_mtu
            } else {
                (*net).mtu = mtu
            }
        }
    }
    /* restart the timer */
    sctp_timer_start(8i32, inp, stcb, net);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_autoclose_timer(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    let mut tn = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    gettimeofday(&mut tn, 0 as *mut timezone);
    if (*stcb).asoc.sctp_autoclose_ticks != 0 && (*inp).sctp_features & 0x200u64 == 0x200u64 {
        let mut tim_touse = 0 as *mut timeval;
        let mut asoc = 0 as *mut sctp_association;
        let mut ticks_gone_by = 0;
        asoc = &mut (*stcb).asoc;
        /* pick the time to use */
        if (*asoc).time_last_rcvd.tv_sec > (*asoc).time_last_sent.tv_sec {
            tim_touse = &mut (*asoc).time_last_rcvd
        } else {
            tim_touse = &mut (*asoc).time_last_sent
        }
        /* Now has long enough transpired to autoclose? */
        ticks_gone_by = ((tn.tv_sec - (*tim_touse).tv_sec) * hz as libc::c_long) as libc::c_int;
        if ticks_gone_by > 0i32 && ticks_gone_by >= (*asoc).sctp_autoclose_ticks as libc::c_int {
            /*
             * autoclose time has hit, call the output routine,
             * which should do nothing just to be SURE we don't
             * have hanging data. We can then safely check the
             * queues and know that we are clear to send
             * shutdown
             */
            sctp_chunk_output(inp, stcb, 10i32, 0i32);
            /* Are we clean? */
            if (*asoc).send_queue.tqh_first.is_null() && (*asoc).sent_queue.tqh_first.is_null() {
                /*
                 * there is nothing queued to send, so I'm
                 * done...
                 */
                if (*stcb).asoc.state & 0x7fi32 != 0x10i32 {
                    let mut netp = 0 as *mut sctp_nets;
                    if (*stcb).asoc.state & 0x7fi32 == 0x8i32
                        || (*stcb).asoc.state & 0x7fi32 == 0x20i32
                    {
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctpstat.sctps_currestab,
                            1u32,
                        );
                    }
                    sctp_set_state(stcb, 0x10i32);
                    sctp_stop_timers_for_shutdown(stcb);
                    if !(*stcb).asoc.alternate.is_null() {
                        netp = (*stcb).asoc.alternate
                    } else {
                        netp = (*stcb).asoc.primary_destination
                    }
                    sctp_send_shutdown(stcb, netp);
                    sctp_timer_start(4i32, (*stcb).sctp_ep, stcb, netp);
                    sctp_timer_start(11i32, (*stcb).sctp_ep, stcb, netp);
                }
            }
        } else {
            let mut tmp = 0;
            /* fool the timer startup to use the time left */
            tmp = (*asoc).sctp_autoclose_ticks as libc::c_int;
            (*asoc).sctp_autoclose_ticks = (*asoc)
                .sctp_autoclose_ticks
                .wrapping_sub(ticks_gone_by as libc::c_uint);
            sctp_timer_start(12i32, inp, stcb, net);
            /* restore the real tick value */
            (*asoc).sctp_autoclose_ticks = tmp as libc::c_uint
        }
    };
}
