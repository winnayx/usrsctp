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
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn sowakeup(so: *mut socket, sb: *mut sockbuf);
    #[no_mangle]
    fn m_free(m: *mut mbuf) -> *mut mbuf;
    #[no_mangle]
    fn m_adj(_: *mut mbuf, _: libc::c_int);
    #[no_mangle]
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn m_copym(_: *mut mbuf, _: libc::c_int, _: libc::c_int, _: libc::c_int) -> *mut mbuf;
    #[no_mangle]
    fn sctp_os_timer_stop(_: *mut sctp_os_timer_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_get_mbuf_for_msg(
        space_needed: libc::c_uint,
        want_header: libc::c_int,
        how: libc::c_int,
        allonebuf: libc::c_int,
        type_0: libc::c_int,
    ) -> *mut mbuf;
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t) -> libc::c_int;
    /* TODO where to put non-_KERNEL things for __Userspace__? */
    /* Attention Julian, this is the extern that
     * goes with the base info. sctp_pcb.c has
     * the real definition.
     */
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_free_ifa(sctp_ifap: *mut sctp_ifa);
    #[no_mangle]
    fn sctp_auth_key_release(stcb: *mut sctp_tcb, keyid: uint16_t, so_locked: libc::c_int);
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
    fn sctp_wakeup_the_read_socket(
        inp: *mut sctp_inpcb,
        stcb: *mut sctp_tcb,
        so_locked: libc::c_int,
    );
    #[no_mangle]
    fn sctp_invoke_recv_callback(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: *mut sctp_queued_to_read,
        _: libc::c_int,
    );
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
    fn sctp_calculate_rto(
        _: *mut sctp_tcb,
        _: *mut sctp_association,
        _: *mut sctp_nets,
        _: *mut timeval,
        _: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_m_getptr(_: *mut mbuf, _: libc::c_int, _: libc::c_int, _: *mut uint8_t) -> caddr_t;
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
    #[no_mangle]
    fn sctp_expand_mapping_array(_: *mut sctp_association, _: uint32_t) -> libc::c_int;
    /* We choose to abort via user input */
    #[no_mangle]
    fn sctp_abort_an_association(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: *mut mbuf,
        _: libc::c_int,
    );
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
    fn sctp_generate_no_user_data_cause(_: uint32_t) -> *mut mbuf;
    #[no_mangle]
    fn sctp_misc_ints(from: uint8_t, a: uint32_t, b: uint32_t, c: uint32_t, d: uint32_t);
    #[no_mangle]
    fn sctp_wakeup_log(stcb: *mut sctp_tcb, wake_cnt: uint32_t, from: libc::c_int);
    #[no_mangle]
    fn sctp_log_strm_del_alt(
        stcb: *mut sctp_tcb,
        _: uint32_t,
        _: uint16_t,
        _: uint16_t,
        _: libc::c_int,
    );
    #[no_mangle]
    fn sctp_log_strm_del(
        control: *mut sctp_queued_to_read,
        poschk: *mut sctp_queued_to_read,
        from: libc::c_int,
    );
    #[no_mangle]
    fn sctp_log_cwnd(stcb: *mut sctp_tcb, _: *mut sctp_nets, _: libc::c_int, _: uint8_t);
    #[no_mangle]
    fn sctp_log_rwnd(_: uint8_t, _: uint32_t, _: uint32_t, _: uint32_t);
    #[no_mangle]
    fn sctp_log_rwnd_set(_: uint8_t, _: uint32_t, _: uint32_t, _: uint32_t, _: uint32_t);
    #[no_mangle]
    fn sctp_log_fr(_: uint32_t, _: uint32_t, _: uint32_t, _: libc::c_int);
    #[no_mangle]
    fn sctp_log_sack(
        _: uint32_t,
        _: uint32_t,
        _: uint32_t,
        _: uint16_t,
        _: uint16_t,
        _: libc::c_int,
    );
    #[no_mangle]
    fn sctp_log_map(_: uint32_t, _: uint32_t, _: uint32_t, _: libc::c_int);
    #[no_mangle]
    fn sctp_print_mapping_array(asoc: *mut sctp_association);
    #[no_mangle]
    fn sctp_set_state(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_add_substate(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_queue_op_err(_: *mut sctp_tcb, _: *mut mbuf);
    #[no_mangle]
    fn sctp_send_shutdown(_: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_send_shutdown_ack(_: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn send_forward_tsn(_: *mut sctp_tcb, _: *mut sctp_association);
    #[no_mangle]
    fn sctp_send_sack(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_packet_dropped(
        _: *mut sctp_tcb,
        _: *mut sctp_nets,
        _: *mut mbuf,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
    );
    #[no_mangle]
    fn sctp_send_deferred_reset_response(
        _: *mut sctp_tcb,
        _: *mut sctp_stream_reset_list,
        _: libc::c_int,
    );
    #[no_mangle]
    fn sctp_find_alternate_net(
        _: *mut sctp_tcb,
        _: *mut sctp_nets,
        mode: libc::c_int,
    ) -> *mut sctp_nets;
    #[no_mangle]
    fn sctp_reset_in_stream(stcb: *mut sctp_tcb, number_entries: uint32_t, list: *mut uint16_t);
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
    pub c2rust_unnamed: C2RustUnnamed_273,
    pub c2rust_unnamed_0: C2RustUnnamed_271,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_271 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_272,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_272 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_273 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_274,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_274 {
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
pub struct cmsghdr {
    pub cmsg_len: size_t,
    pub cmsg_level: libc::c_int,
    pub cmsg_type: libc::c_int,
    pub __cmsg_data: [libc::c_uchar; 0],
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
    pub __in6_u: C2RustUnnamed_275,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_275 {
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
    pub so_incomp: C2RustUnnamed_283,
    pub so_comp: C2RustUnnamed_282,
    pub so_list: C2RustUnnamed_281,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_280,
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
    pub M_dat: C2RustUnnamed_276,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_276 {
    pub MH: C2RustUnnamed_277,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_277 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_278,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_278 {
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
    pub m_tag_link: C2RustUnnamed_279,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_279 {
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
pub struct C2RustUnnamed_280 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_281 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_282 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_283 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}
pub type sctp_zone_t = size_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_284,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_284 {
    pub ifu_broadaddr: sockaddr,
    pub ifu_dstaddr: sockaddr,
}
pub type C2RustUnnamed_285 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_285 = 256;
pub const IPPROTO_RAW: C2RustUnnamed_285 = 255;
pub const IPPROTO_MPLS: C2RustUnnamed_285 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_285 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_285 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_285 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_285 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_285 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_285 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_285 = 92;
pub const IPPROTO_AH: C2RustUnnamed_285 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_285 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_285 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_285 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_285 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_285 = 33;
pub const IPPROTO_TP: C2RustUnnamed_285 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_285 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_285 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_285 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_285 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_285 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_285 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_285 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_285 = 1;
pub const IPPROTO_IP: C2RustUnnamed_285 = 0;
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
    pub inp_hash: C2RustUnnamed_293,
    pub inp_list: C2RustUnnamed_292,
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
    pub inp_depend4: C2RustUnnamed_289,
    pub inp_depend6: C2RustUnnamed_288,
    pub inp_portlist: C2RustUnnamed_287,
    pub inp_phd: *mut inpcbport,
    pub inp_mtx: mtx,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbport {
    pub phd_hash: C2RustUnnamed_286,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_286 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_287 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_288 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_289 {
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
    pub ie_dependfaddr: C2RustUnnamed_291,
    pub ie_dependladdr: C2RustUnnamed_290,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_290 {
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
pub union C2RustUnnamed_291 {
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
pub struct C2RustUnnamed_292 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_293 {
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
    pub tqe: C2RustUnnamed_294,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_294 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
/* state of this entry */
pub type sctp_os_timer_t = sctp_callout;
pub type sctp_rtentry_t = sctp_rtentry;

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
    pub next: C2RustUnnamed_323,
    pub next_instrm: C2RustUnnamed_322,
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
    pub rec: C2RustUnnamed_321,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_295,
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
pub struct C2RustUnnamed_295 {
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
    pub sctp_next: C2RustUnnamed_301,
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
    pub next_ifa: C2RustUnnamed_300,
    pub next_bucket: C2RustUnnamed_299,
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
    pub next_ifn: C2RustUnnamed_297,
    pub next_bucket: C2RustUnnamed_296,
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
pub struct C2RustUnnamed_296 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_297 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_298,
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
pub struct C2RustUnnamed_298 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_299 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_300 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_301 {
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
    pub next: C2RustUnnamed_302,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_302 {
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
pub type sctp_auth_chklist_t = sctp_auth_chklist;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_auth_chklist {
    pub chunks: [uint8_t; 256],
    pub num_chunks: uint8_t,
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
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_306,
    pub sctp_tcblist: C2RustUnnamed_305,
    pub sctp_tcbasocidhash: C2RustUnnamed_304,
    pub sctp_asocs: C2RustUnnamed_303,
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
pub struct C2RustUnnamed_303 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_304 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_305 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_306 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}
/* we choose the number to make a pcb a page */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_311,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_310,
    pub sctp_hash: C2RustUnnamed_309,
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
    pub sctp_nxt_itr: C2RustUnnamed_307,
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
pub struct C2RustUnnamed_307 {
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
    pub sctp_nxt_addr: C2RustUnnamed_308,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_308 {
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
pub struct C2RustUnnamed_309 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_310 {
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
pub union C2RustUnnamed_311 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
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
    pub next_spoke: C2RustUnnamed_312,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_312 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_313,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_313 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_314,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_314 {
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
    pub next: C2RustUnnamed_316,
    pub ss_next: C2RustUnnamed_315,
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
pub struct C2RustUnnamed_315 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_316 {
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
    pub next_resp: C2RustUnnamed_317,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_317 {
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
    pub next: C2RustUnnamed_318,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_318 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_319,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_319 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_320,
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
pub struct C2RustUnnamed_320 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_321 {
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
pub struct C2RustUnnamed_322 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_323 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}
/* stream/sequence pairs (sctp_strseq) follow */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_strseq {
    pub sid: uint16_t,
    pub ssn: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_strseq_mid {
    pub sid: uint16_t,
    pub flags: uint16_t,
    pub mid: uint32_t,
}
/* ... used for both INIT and INIT ACK */
/* Selective Ack (SACK) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_gap_ack_block {
    pub start: uint16_t,
    pub end: uint16_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_gen_error_cause {
    pub code: uint16_t,
    pub length: uint16_t,
    pub info: [uint8_t; 0],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_error_cause {
    pub code: uint16_t,
    pub length: uint16_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_error_invalid_stream {
    pub cause: sctp_error_cause,
    pub stream_id: uint16_t,
    pub reserved: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_sndrcvinfo {
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
    pub __reserve_pad: [uint8_t; 92],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_extrcvinfo {
    pub sinfo_stream: uint16_t,
    pub sinfo_ssn: uint16_t,
    pub sinfo_flags: uint16_t,
    pub sinfo_ppid: uint32_t,
    pub sinfo_context: uint32_t,
    pub sinfo_timetolive: uint32_t,
    pub sinfo_tsn: uint32_t,
    pub sinfo_cumtsn: uint32_t,
    pub sinfo_assoc_id: sctp_assoc_t,
    pub serinfo_next_flags: uint16_t,
    pub serinfo_next_stream: uint16_t,
    pub serinfo_next_aid: uint32_t,
    pub serinfo_next_length: uint32_t,
    pub serinfo_next_ppid: uint32_t,
    pub sinfo_keynumber: uint16_t,
    pub sinfo_keynumber_valid: uint16_t,
    pub __reserve_pad: [uint8_t; 76],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_nxtinfo {
    pub nxt_sid: uint16_t,
    pub nxt_flags: uint16_t,
    pub nxt_ppid: uint32_t,
    pub nxt_length: uint32_t,
    pub nxt_assoc_id: sctp_assoc_t,
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
pub type __timezone_ptr_t = *mut timezone;
/*
 * Structures for DATA chunks
 */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_data {
    pub tsn: uint32_t,
    pub sid: uint16_t,
    pub ssn: uint16_t,
    pub ppid: uint32_t,
}
/* user data follows */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_data_chunk {
    pub ch: sctp_chunkhdr,
    pub dp: sctp_data,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_idata {
    pub tsn: uint32_t,
    pub sid: uint16_t,
    pub reserved: uint16_t,
    pub mid: uint32_t,
    pub ppid_fsn: C2RustUnnamed_324,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_324 {
    pub ppid: uint32_t,
    pub fsn: uint32_t,
}
/* user data follows */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_idata_chunk {
    pub ch: sctp_chunkhdr,
    pub dp: sctp_idata,
}
/* Shutdown Association (SHUTDOWN) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_shutdown_chunk {
    pub ch: sctp_chunkhdr,
    pub cumulative_tsn_ack: uint32_t,
}
/* asconf parameters follow */
/* draft-ietf-tsvwg-prsctp */
/* Forward Cumulative TSN (FORWARD TSN) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_forward_tsn_chunk {
    pub ch: sctp_chunkhdr,
    pub new_cumulative_tsn: uint32_t,
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
    pub sctp_nxt_tagblock: C2RustUnnamed_325,
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
pub struct C2RustUnnamed_325 {
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
#[no_mangle]
pub unsafe extern "C" fn sctp_set_rwnd(mut stcb: *mut sctp_tcb, mut asoc: *mut sctp_association) {
    (*asoc).my_rwnd = sctp_calc_rwnd(stcb, asoc);
}
/* Calculate what the rwnd would be */
#[no_mangle]
pub unsafe extern "C" fn sctp_calc_rwnd(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) -> uint32_t {
    let mut calc = 0u32;
    /*
     * This is really set wrong with respect to a 1-2-m socket. Since
     * the sb_cc is the count that everyone as put up. When we re-write
     * sctp_soreceive then we will fix this so that ONLY this
     * associations data is taken into account.
     */
    if (*stcb).sctp_socket.is_null() {
        return calc;
    }
    if (*stcb).asoc.sb_cc == 0u32
        && (*asoc).cnt_on_reasm_queue == 0u32
        && (*asoc).cnt_on_all_streams == 0u32
    {
        /* Full rwnd granted */
        calc = if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
            (*(*stcb).sctp_socket).so_rcv.sb_hiwat
        } else {
            4096u32
        };
        return calc;
    }
    /* get actual space */
    calc = if (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
        (*(*stcb).sctp_socket).so_rcv.sb_hiwat
    } else {
        4096u32
    }) > (*stcb).asoc.sb_cc
    {
        (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
            (*(*stcb).sctp_socket).so_rcv.sb_hiwat
        } else {
            4096u32
        })
        .wrapping_sub((*stcb).asoc.sb_cc)
    } else {
        0u32
    };
    /*
     * take out what has NOT been put on socket queue and we yet hold
     * for putting up.
     */
    calc = if calc
        > (*asoc)
            .size_on_reasm_queue
            .wrapping_add((*asoc).cnt_on_reasm_queue.wrapping_mul(256u32))
    {
        calc.wrapping_sub(
            (*asoc)
                .size_on_reasm_queue
                .wrapping_add((*asoc).cnt_on_reasm_queue.wrapping_mul(256u32)),
        )
    } else {
        0u32
    };
    calc = if calc
        > (*asoc)
            .size_on_all_streams
            .wrapping_add((*asoc).cnt_on_all_streams.wrapping_mul(256u32))
    {
        calc.wrapping_sub(
            (*asoc)
                .size_on_all_streams
                .wrapping_add((*asoc).cnt_on_all_streams.wrapping_mul(256u32)),
        )
    } else {
        0u32
    };
    if calc == 0u32 {
        /* out of space */
        return calc;
    }
    /* what is the overhead of all these rwnd's */
    calc = if calc > (*stcb).asoc.my_rwnd_control_len {
        calc.wrapping_sub((*stcb).asoc.my_rwnd_control_len)
    } else {
        0u32
    };
    /* If the window gets too small due to ctrl-stuff, reduce it
     * to 1, even it is 0. SWS engaged
     */
    if calc < (*stcb).asoc.my_rwnd_control_len {
        calc = 1u32
    }
    return calc;
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
 * Build out our readq entry based on the incoming packet.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_build_readq_entry(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut tsn: uint32_t,
    mut ppid: uint32_t,
    mut context: uint32_t,
    mut sid: uint16_t,
    mut mid: uint32_t,
    mut flags: uint8_t,
    mut dm: *mut mbuf,
) -> *mut sctp_queued_to_read {
    let mut read_queue_e = 0 as *mut sctp_queued_to_read;
    read_queue_e = malloc(system_base_info.sctppcbinfo.ipi_zone_readq) as *mut sctp_queued_to_read;
    if !read_queue_e.is_null() {
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
    }
    if !read_queue_e.is_null() {
        memset(
            read_queue_e as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_queued_to_read>() as libc::c_ulong,
        );
        (*read_queue_e).sinfo_stream = sid;
        (*read_queue_e).sinfo_flags = ((flags as libc::c_int) << 8i32) as uint16_t;
        (*read_queue_e).sinfo_ppid = ppid;
        (*read_queue_e).sinfo_context = context;
        (*read_queue_e).sinfo_tsn = tsn;
        (*read_queue_e).sinfo_cumtsn = tsn;
        (*read_queue_e).sinfo_assoc_id = (*stcb).asoc.assoc_id;
        (*read_queue_e).mid = mid;
        (*read_queue_e).fsn_included = 0xffffffffu32;
        (*read_queue_e).top_fsn = (*read_queue_e).fsn_included;
        (*read_queue_e).reasm.tqh_first = 0 as *mut sctp_tmit_chunk;
        (*read_queue_e).reasm.tqh_last = &mut (*read_queue_e).reasm.tqh_first;
        (*read_queue_e).whoFrom = net;
        ::std::intrinsics::atomic_xadd(&mut (*net).ref_count, 1i32);
        (*read_queue_e).data = dm;
        (*read_queue_e).stcb = stcb;
        (*read_queue_e).port_from = (*stcb).rport
    }
    return read_queue_e;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_build_ctl_nchunk(
    mut inp: *mut sctp_inpcb,
    mut sinfo: *mut sctp_sndrcvinfo,
) -> *mut mbuf {
    let mut seinfo = 0 as *mut sctp_extrcvinfo;
    let mut cmh = 0 as *mut cmsghdr;
    let mut ret = 0 as *mut mbuf;
    let mut len = 0;
    let mut use_extended = 0;
    let mut provide_nxt = 0;
    if (*inp).sctp_features & 0x400u64 == 0u64
        && (*inp).sctp_features & 0x8000000u64 == 0u64
        && (*inp).sctp_features & 0x10000000u64 == 0u64
    {
        /* user does not want any ancillary data */
        return 0 as *mut mbuf;
    }
    len = 0i32;
    if (*inp).sctp_features & 0x8000000u64 == 0x8000000u64 {
        len = (len as libc::c_ulong).wrapping_add(
            ((::std::mem::size_of::<sctp_rcvinfo>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(
                (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
            ),
        ) as libc::c_int
    }
    seinfo = sinfo as *mut sctp_extrcvinfo;
    if (*inp).sctp_features & 0x10000000u64 == 0x10000000u64
        && (*seinfo).serinfo_next_flags as libc::c_int & 0x1i32 != 0
    {
        provide_nxt = 1i32;
        len = (len as libc::c_ulong).wrapping_add(
            ((::std::mem::size_of::<sctp_nxtinfo>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(
                (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
            ),
        ) as libc::c_int
    } else {
        provide_nxt = 0i32
    }
    if (*inp).sctp_features & 0x400u64 == 0x400u64 {
        if (*inp).sctp_features & 0x2u64 == 0x2u64 {
            use_extended = 1i32;
            len = (len as libc::c_ulong).wrapping_add(
                ((::std::mem::size_of::<sctp_extrcvinfo>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
                .wrapping_add(
                    (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                        .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                        .wrapping_sub(1u64)
                        & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
                ),
            ) as libc::c_int
        } else {
            use_extended = 0i32;
            len = (len as libc::c_ulong).wrapping_add(
                ((::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
                .wrapping_add(
                    (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                        .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                        .wrapping_sub(1u64)
                        & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
                ),
            ) as libc::c_int
        }
    } else {
        use_extended = 0i32
    }
    ret = sctp_get_mbuf_for_msg(len as libc::c_uint, 0i32, 0x1i32, 1i32, 1i32);
    if ret.is_null() {
        /* No space */
        return ret;
    }
    (*ret).m_hdr.mh_len = 0i32;
    /* We need a CMSG header followed by the struct */
    cmh = (*ret).m_hdr.mh_data as *mut cmsghdr;
    /*
     * Make sure that there is no un-initialized padding between
     * the cmsg header and cmsg data and after the cmsg data.
     */
    memset(cmh as *mut libc::c_void, 0i32, len as libc::c_ulong);
    if (*inp).sctp_features & 0x8000000u64 == 0x8000000u64 {
        let mut rcvinfo = 0 as *mut sctp_rcvinfo;
        (*cmh).cmsg_level = IPPROTO_SCTP as libc::c_int;
        (*cmh).cmsg_len = ((::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1u64)
            & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
        .wrapping_add(::std::mem::size_of::<sctp_rcvinfo>() as libc::c_ulong);
        (*cmh).cmsg_type = 0x5i32;
        rcvinfo = (*cmh).__cmsg_data.as_mut_ptr() as *mut sctp_rcvinfo;
        (*rcvinfo).rcv_sid = (*sinfo).sinfo_stream;
        (*rcvinfo).rcv_ssn = (*sinfo).sinfo_ssn;
        (*rcvinfo).rcv_flags = (*sinfo).sinfo_flags;
        (*rcvinfo).rcv_ppid = (*sinfo).sinfo_ppid;
        (*rcvinfo).rcv_tsn = (*sinfo).sinfo_tsn;
        (*rcvinfo).rcv_cumtsn = (*sinfo).sinfo_cumtsn;
        (*rcvinfo).rcv_context = (*sinfo).sinfo_context;
        (*rcvinfo).rcv_assoc_id = (*sinfo).sinfo_assoc_id;
        cmh = (cmh as caddr_t).offset(
            ((::std::mem::size_of::<sctp_rcvinfo>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(
                (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
            ) as isize,
        ) as *mut cmsghdr;
        (*ret).m_hdr.mh_len = ((*ret).m_hdr.mh_len as libc::c_ulong).wrapping_add(
            ((::std::mem::size_of::<sctp_rcvinfo>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(
                (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
            ),
        ) as libc::c_int
    }
    if provide_nxt != 0 {
        let mut nxtinfo = 0 as *mut sctp_nxtinfo;
        (*cmh).cmsg_level = IPPROTO_SCTP as libc::c_int;
        (*cmh).cmsg_len = ((::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1u64)
            & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
        .wrapping_add(::std::mem::size_of::<sctp_nxtinfo>() as libc::c_ulong);
        (*cmh).cmsg_type = 0x6i32;
        nxtinfo = (*cmh).__cmsg_data.as_mut_ptr() as *mut sctp_nxtinfo;
        (*nxtinfo).nxt_sid = (*seinfo).serinfo_next_stream;
        (*nxtinfo).nxt_flags = 0u16;
        if (*seinfo).serinfo_next_flags as libc::c_int & 0x4i32 != 0 {
            (*nxtinfo).nxt_flags = ((*nxtinfo).nxt_flags as libc::c_int | 0x400i32) as uint16_t
        }
        if (*seinfo).serinfo_next_flags as libc::c_int & 0x8i32 != 0 {
            (*nxtinfo).nxt_flags = ((*nxtinfo).nxt_flags as libc::c_int | 0x10i32) as uint16_t
        }
        if (*seinfo).serinfo_next_flags as libc::c_int & 0x2i32 != 0 {
            (*nxtinfo).nxt_flags = ((*nxtinfo).nxt_flags as libc::c_int | 0x20i32) as uint16_t
        }
        (*nxtinfo).nxt_ppid = (*seinfo).serinfo_next_ppid;
        (*nxtinfo).nxt_length = (*seinfo).serinfo_next_length;
        (*nxtinfo).nxt_assoc_id = (*seinfo).serinfo_next_aid;
        cmh = (cmh as caddr_t).offset(
            ((::std::mem::size_of::<sctp_nxtinfo>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(
                (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
            ) as isize,
        ) as *mut cmsghdr;
        (*ret).m_hdr.mh_len = ((*ret).m_hdr.mh_len as libc::c_ulong).wrapping_add(
            ((::std::mem::size_of::<sctp_nxtinfo>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(
                (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
            ),
        ) as libc::c_int
    }
    if (*inp).sctp_features & 0x400u64 == 0x400u64 {
        let mut outinfo = 0 as *mut sctp_sndrcvinfo;
        (*cmh).cmsg_level = IPPROTO_SCTP as libc::c_int;
        outinfo = (*cmh).__cmsg_data.as_mut_ptr() as *mut sctp_sndrcvinfo;
        if use_extended != 0 {
            (*cmh).cmsg_len = ((::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(::std::mem::size_of::<sctp_extrcvinfo>() as libc::c_ulong);
            (*cmh).cmsg_type = 0x3i32;
            memcpy(
                outinfo as *mut libc::c_void,
                sinfo as *const libc::c_void,
                ::std::mem::size_of::<sctp_extrcvinfo>() as libc::c_ulong,
            );
            (*ret).m_hdr.mh_len = ((*ret).m_hdr.mh_len as libc::c_ulong).wrapping_add(
                ((::std::mem::size_of::<sctp_extrcvinfo>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
                .wrapping_add(
                    (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                        .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                        .wrapping_sub(1u64)
                        & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
                ),
            ) as libc::c_int
        } else {
            (*cmh).cmsg_len = ((::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1u64)
                & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
            .wrapping_add(::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong);
            (*cmh).cmsg_type = 0x2i32;
            *outinfo = *sinfo;
            (*ret).m_hdr.mh_len = ((*ret).m_hdr.mh_len as libc::c_ulong).wrapping_add(
                ((::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                    .wrapping_sub(1u64)
                    & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64))
                .wrapping_add(
                    (::std::mem::size_of::<cmsghdr>() as libc::c_ulong)
                        .wrapping_add(::std::mem::size_of::<size_t>() as libc::c_ulong)
                        .wrapping_sub(1u64)
                        & !(::std::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1u64),
                ),
            ) as libc::c_int
        }
    }
    return ret;
}
unsafe extern "C" fn sctp_mark_non_revokable(mut asoc: *mut sctp_association, mut tsn: uint32_t) {
    let mut gap = 0;
    let mut cumackp1 = 0;
    let mut in_r = 0i32;
    let mut in_nr = 0i32;
    if system_base_info.sctpsysctl.sctp_do_drain == 0u32 {
        return;
    }
    cumackp1 = (*asoc).cumulative_tsn.wrapping_add(1u32);
    if cumackp1 < tsn && tsn.wrapping_sub(cumackp1) > (1u32) << 31i32
        || cumackp1 > tsn && cumackp1.wrapping_sub(tsn) < (1u32) << 31i32
    {
        /* this tsn is behind the cum ack and thus we don't
         * need to worry about it being moved from one to the other.
         */
        return;
    }
    if tsn >= (*asoc).mapping_array_base_tsn {
        gap = tsn.wrapping_sub((*asoc).mapping_array_base_tsn)
    } else {
        gap = (0xffffffffu32)
            .wrapping_sub((*asoc).mapping_array_base_tsn)
            .wrapping_add(tsn)
            .wrapping_add(1u32)
    }
    in_r = *(*asoc).mapping_array.offset((gap >> 3i32) as isize) as libc::c_int >> (gap & 0x7u32)
        & 0x1i32;
    in_nr = *(*asoc).nr_mapping_array.offset((gap >> 3i32) as isize) as libc::c_int
        >> (gap & 0x7u32)
        & 0x1i32;
    if in_r == 0i32 && in_nr == 0i32 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"gap:%x tsn:%x\n\x00" as *const u8 as *const libc::c_char,
                gap,
                tsn,
            );
        }
        sctp_print_mapping_array(asoc);
    }
    if in_nr == 0i32 {
        let ref mut fresh0 = *(*asoc).nr_mapping_array.offset((gap >> 3i32) as isize);
        *fresh0 = (*fresh0 as libc::c_int | (0x1i32) << (gap & 0x7u32)) as uint8_t
    }
    if in_r != 0 {
        let ref mut fresh1 = *(*asoc).mapping_array.offset((gap >> 3i32) as isize);
        *fresh1 = (*fresh1 as libc::c_int & (!((0x1i32) << (gap & 0x7u32)) & 0xffi32)) as uint8_t
    }
    if tsn < (*asoc).highest_tsn_inside_nr_map
        && (*asoc).highest_tsn_inside_nr_map.wrapping_sub(tsn) > (1u32) << 31i32
        || tsn > (*asoc).highest_tsn_inside_nr_map
            && tsn.wrapping_sub((*asoc).highest_tsn_inside_nr_map) < (1u32) << 31i32
    {
        (*asoc).highest_tsn_inside_nr_map = tsn
    }
    if tsn == (*asoc).highest_tsn_inside_map {
        let mut i = 0;
        let mut fnd = 0i32;
        i = tsn.wrapping_sub(1u32);
        while i < (*asoc).mapping_array_base_tsn
            && (*asoc).mapping_array_base_tsn.wrapping_sub(i) > (1u32) << 31i32
            || i > (*asoc).mapping_array_base_tsn
                && i.wrapping_sub((*asoc).mapping_array_base_tsn) < (1u32) << 31i32
            || i == (*asoc).mapping_array_base_tsn
        {
            if i >= (*asoc).mapping_array_base_tsn {
                gap = i.wrapping_sub((*asoc).mapping_array_base_tsn)
            } else {
                gap = (0xffffffffu32)
                    .wrapping_sub((*asoc).mapping_array_base_tsn)
                    .wrapping_add(i)
                    .wrapping_add(1u32)
            }
            if *(*asoc).mapping_array.offset((gap >> 3i32) as isize) as libc::c_int
                >> (gap & 0x7u32)
                & 0x1i32
                != 0
            {
                (*asoc).highest_tsn_inside_map = i;
                fnd = 1i32;
                break;
            } else {
                i = i.wrapping_sub(1)
            }
        }
        if fnd == 0 {
            (*asoc).highest_tsn_inside_map = (*asoc).mapping_array_base_tsn.wrapping_sub(1u32)
        }
    };
}
unsafe extern "C" fn sctp_place_control_in_stream(
    mut strm: *mut sctp_stream_in,
    mut asoc: *mut sctp_association,
    mut control: *mut sctp_queued_to_read,
) -> libc::c_int {
    let mut q = 0 as *mut sctp_readhead;
    let mut flags = 0;
    let mut unordered = 0;
    flags = ((*control).sinfo_flags as libc::c_int >> 8i32) as uint8_t;
    unordered = (flags as libc::c_int & 0x4i32) as uint8_t;
    if unordered != 0 {
        q = &mut (*strm).uno_inqueue;
        if (*asoc).idata_supported as libc::c_int == 0i32 {
            if !(*q).tqh_first.is_null() {
                /* Only one stream can be here in old style  -- abort */
                return -(1i32);
            }
            (*control).next_instrm.tqe_next = 0 as *mut sctp_queued_to_read;
            (*control).next_instrm.tqe_prev = (*q).tqh_last;
            *(*q).tqh_last = control;
            (*q).tqh_last = &mut (*control).next_instrm.tqe_next;
            (*control).on_strm_q = 2u8;
            return 0i32;
        }
    } else {
        q = &mut (*strm).inqueue
    }
    if flags as libc::c_int & 0x3i32 == 0x3i32 {
        (*control).end_added = 1u8;
        (*control).first_frag_seen = 1u8;
        (*control).last_frag_seen = 1u8
    }
    if (*q).tqh_first.is_null() {
        /* Empty queue */
        (*control).next_instrm.tqe_next = (*q).tqh_first;
        if !(*control).next_instrm.tqe_next.is_null() {
            (*(*q).tqh_first).next_instrm.tqe_prev = &mut (*control).next_instrm.tqe_next
        } else {
            (*q).tqh_last = &mut (*control).next_instrm.tqe_next
        }
        (*q).tqh_first = control;
        (*control).next_instrm.tqe_prev = &mut (*q).tqh_first;
        if unordered != 0 {
            (*control).on_strm_q = 2u8
        } else {
            (*control).on_strm_q = 1u8
        }
        return 0i32;
    } else {
        let mut at = 0 as *mut sctp_queued_to_read;
        at = (*q).tqh_first;
        while !at.is_null() {
            if if (*asoc).idata_supported as libc::c_int == 1i32 {
                ((*at).mid < (*control).mid
                    && (*control).mid.wrapping_sub((*at).mid) > (1u32) << 31i32
                    || (*at).mid > (*control).mid
                        && (*at).mid.wrapping_sub((*control).mid) < (1u32) << 31i32)
                    as libc::c_int
            } else {
                (((*at).mid as uint16_t as libc::c_int) < (*control).mid as uint16_t as libc::c_int
                    && ((*control).mid as uint16_t as libc::c_int
                        - (*at).mid as uint16_t as libc::c_int) as uint16_t
                        as libc::c_uint
                        > (1u32) << 15i32
                    || (*at).mid as uint16_t as libc::c_int
                        > (*control).mid as uint16_t as libc::c_int
                        && (((*at).mid as uint16_t as libc::c_int
                            - (*control).mid as uint16_t as libc::c_int)
                            as uint16_t as libc::c_uint)
                            < (1u32) << 15i32) as libc::c_int
            } != 0
            {
                /*
                 * one in queue is bigger than the
                 * new one, insert before this one
                 */
                (*control).next_instrm.tqe_prev = (*at).next_instrm.tqe_prev;
                (*control).next_instrm.tqe_next = at;
                *(*at).next_instrm.tqe_prev = control;
                (*at).next_instrm.tqe_prev = &mut (*control).next_instrm.tqe_next;
                if unordered != 0 {
                    (*control).on_strm_q = 2u8
                } else {
                    (*control).on_strm_q = 1u8
                }
                break;
            } else if if (*asoc).idata_supported as libc::c_int == 1i32 {
                ((*at).mid == (*control).mid) as libc::c_int
            } else {
                ((*at).mid as uint16_t as libc::c_int == (*control).mid as uint16_t as libc::c_int)
                    as libc::c_int
            } != 0
            {
                /*
                 * Gak, He sent me a duplicate msg
                 * id number?? return -1 to abort.
                 */
                return -(1i32);
            } else if (*at).next_instrm.tqe_next.is_null() {
                /*
                 * We are at the end, insert
                 * it after this one
                 */
                if system_base_info.sctpsysctl.sctp_logging_level & 0x20000u32 != 0 {
                    sctp_log_strm_del(control, at, 14i32);
                }
                (*control).next_instrm.tqe_next = (*at).next_instrm.tqe_next;
                if !(*control).next_instrm.tqe_next.is_null() {
                    (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                        &mut (*control).next_instrm.tqe_next
                } else {
                    (*q).tqh_last = &mut (*control).next_instrm.tqe_next
                }
                (*at).next_instrm.tqe_next = control;
                (*control).next_instrm.tqe_prev = &mut (*at).next_instrm.tqe_next;
                if unordered != 0 {
                    (*control).on_strm_q = 2u8
                } else {
                    (*control).on_strm_q = 1u8
                }
                break;
            } else {
                at = (*at).next_instrm.tqe_next
            }
        }
    }
    return 0i32;
}
unsafe extern "C" fn sctp_abort_in_reasm(
    mut stcb: *mut sctp_tcb,
    mut control: *mut sctp_queued_to_read,
    mut chk: *mut sctp_tmit_chunk,
    mut abort_flag: *mut libc::c_int,
    mut opspot: libc::c_int,
) {
    let mut msg = [0; 128];
    let mut oper = 0 as *mut mbuf;
    if (*stcb).asoc.idata_supported != 0 {
        snprintf(
            msg.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            b"Reass %x,CF:%x,TSN=%8.8x,SID=%4.4x,FSN=%8.8x,MID:%8.8x\x00" as *const u8
                as *const libc::c_char,
            opspot,
            (*control).fsn_included,
            (*chk).rec.data.tsn,
            (*chk).rec.data.sid as libc::c_int,
            (*chk).rec.data.fsn,
            (*chk).rec.data.mid,
        );
    } else {
        snprintf(
            msg.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            b"Reass %x,CI:%x,TSN=%8.8x,SID=%4.4x,FSN=%4.4x,SSN:%4.4x\x00" as *const u8
                as *const libc::c_char,
            opspot,
            (*control).fsn_included,
            (*chk).rec.data.tsn,
            (*chk).rec.data.sid as libc::c_int,
            (*chk).rec.data.fsn,
            (*chk).rec.data.mid as uint16_t as libc::c_int,
        );
    }
    oper = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
    m_freem((*chk).data);
    (*chk).data = 0 as *mut mbuf;
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
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        } else {
            (*chk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
            (*chk).sctp_next.tqe_prev = (*stcb).asoc.free_chunks.tqh_last;
            *(*stcb).asoc.free_chunks.tqh_last = chk;
            (*stcb).asoc.free_chunks.tqh_last = &mut (*chk).sctp_next.tqe_next;
            (*stcb).asoc.free_chunk_cnt = (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
            ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_free_chunks, 1u32);
        }
    } else {
        free(chk as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
    }
    (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x1i32) as uint32_t;
    sctp_abort_an_association((*stcb).sctp_ep, stcb, oper, 0i32);
    *abort_flag = 1i32;
}
unsafe extern "C" fn sctp_clean_up_control(
    mut stcb: *mut sctp_tcb,
    mut control: *mut sctp_queued_to_read,
) {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut nchk = 0 as *mut sctp_tmit_chunk;
    chk = (*control).reasm.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*control).reasm.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        if !(*chk).data.is_null() {
            m_freem((*chk).data);
        }
        (*chk).data = 0 as *mut mbuf;
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
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        }
        chk = nchk
    }
    if !(*control).whoFrom.is_null() {
        if ::std::intrinsics::atomic_xadd(
            &mut (*(*control).whoFrom).ref_count as *mut libc::c_int,
            -(1i32),
        ) == 1i32
        {
            sctp_os_timer_stop(&mut (*(*control).whoFrom).rxt_timer.timer);
            sctp_os_timer_stop(&mut (*(*control).whoFrom).pmtu_timer.timer);
            sctp_os_timer_stop(&mut (*(*control).whoFrom).hb_timer.timer);
            if !(*(*control).whoFrom).ro.ro_rt.is_null() {
                if (*(*(*control).whoFrom).ro.ro_rt).rt_refcnt <= 1i64 {
                    sctp_userspace_rtfree((*(*control).whoFrom).ro.ro_rt);
                } else {
                    (*(*(*control).whoFrom).ro.ro_rt).rt_refcnt -= 1
                }
                (*(*control).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                (*(*control).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t
            }
            if (*(*control).whoFrom).src_addr_selected != 0 {
                sctp_free_ifa((*(*control).whoFrom).ro._s_addr);
                (*(*control).whoFrom).ro._s_addr = 0 as *mut sctp_ifa
            }
            (*(*control).whoFrom).src_addr_selected = 0u8;
            (*(*control).whoFrom).dest_state =
                ((*(*control).whoFrom).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
            free((*control).whoFrom as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_raddr, 1u32);
        }
    }
    if !(*control).data.is_null() {
        m_freem((*control).data);
        (*control).data = 0 as *mut mbuf
    }
    free(control as *mut libc::c_void);
    ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
}
/*
 * Queue the chunk either right into the socket buffer if it is the next one
 * to go OR put it in the correct place in the delivery queue.  If we do
 * append to the so_buf, keep doing so until we are out of order as
 * long as the control's entered are non-fragmented.
 */
unsafe extern "C" fn sctp_queue_data_to_stream(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut control: *mut sctp_queued_to_read,
    mut abort_flag: *mut libc::c_int,
    mut need_reasm: *mut libc::c_int,
) {
    let mut queue_needed = 0;
    let mut nxt_todel = 0;
    let mut op_err = 0 as *mut mbuf;
    let mut strm = 0 as *mut sctp_stream_in;
    let mut msg = [0; 128];
    strm = &mut *(*asoc).strmin.offset((*control).sinfo_stream as isize) as *mut sctp_stream_in;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x20000u32 != 0 {
        sctp_log_strm_del(control, 0 as *mut sctp_queued_to_read, 10i32);
    }
    if if (*asoc).idata_supported as libc::c_int == 1i32 {
        ((*strm).last_mid_delivered < (*control).mid
            && (*control).mid.wrapping_sub((*strm).last_mid_delivered) > (1u32) << 31i32
            || (*strm).last_mid_delivered > (*control).mid
                && (*strm).last_mid_delivered.wrapping_sub((*control).mid) < (1u32) << 31i32)
            as libc::c_int
    } else {
        (((*strm).last_mid_delivered as uint16_t as libc::c_int)
            < (*control).mid as uint16_t as libc::c_int
            && ((*control).mid as uint16_t as libc::c_int
                - (*strm).last_mid_delivered as uint16_t as libc::c_int) as uint16_t
                as libc::c_uint
                > (1u32) << 15i32
            || (*strm).last_mid_delivered as uint16_t as libc::c_int
                > (*control).mid as uint16_t as libc::c_int
                && (((*strm).last_mid_delivered as uint16_t as libc::c_int
                    - (*control).mid as uint16_t as libc::c_int) as uint16_t
                    as libc::c_uint)
                    < (1u32) << 15i32) as libc::c_int
    } != 0
    {
        /* The incoming sseq is behind where we last delivered? */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x1000000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Duplicate S-SEQ: %u delivered: %u from peer, Abort association\n\x00"
                        as *const u8 as *const libc::c_char,
                    (*strm).last_mid_delivered,
                    (*control).mid,
                );
            }
        }
        /*
         * throw it in the stream so it gets cleaned up in
         * association destruction
         */
        (*control).next_instrm.tqe_next = (*strm).inqueue.tqh_first;
        if !(*control).next_instrm.tqe_next.is_null() {
            (*(*strm).inqueue.tqh_first).next_instrm.tqe_prev = &mut (*control).next_instrm.tqe_next
        } else {
            (*strm).inqueue.tqh_last = &mut (*control).next_instrm.tqe_next
        }
        (*strm).inqueue.tqh_first = control;
        (*control).next_instrm.tqe_prev = &mut (*strm).inqueue.tqh_first;
        if (*asoc).idata_supported != 0 {
            snprintf(
                msg.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                b"Delivered MID=%8.8x, got TSN=%8.8x, SID=%4.4x, MID=%8.8x\x00" as *const u8
                    as *const libc::c_char,
                (*strm).last_mid_delivered,
                (*control).sinfo_tsn,
                (*control).sinfo_stream as libc::c_int,
                (*control).mid,
            );
        } else {
            snprintf(
                msg.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                b"Delivered SSN=%4.4x, got TSN=%8.8x, SID=%4.4x, SSN=%4.4x\x00" as *const u8
                    as *const libc::c_char,
                (*strm).last_mid_delivered as uint16_t as libc::c_int,
                (*control).sinfo_tsn,
                (*control).sinfo_stream as libc::c_int,
                (*control).mid as uint16_t as libc::c_int,
            );
        }
        op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
        (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x2i32) as uint32_t;
        sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
        *abort_flag = 1i32;
        return;
    }
    queue_needed = 1i32;
    (*asoc).size_on_all_streams = (*asoc).size_on_all_streams.wrapping_add((*control).length);
    (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_add(1);
    nxt_todel = (*strm).last_mid_delivered.wrapping_add(1u32);
    if if (*asoc).idata_supported as libc::c_int == 1i32 {
        (nxt_todel == (*control).mid) as libc::c_int
    } else {
        (nxt_todel as uint16_t as libc::c_int == (*control).mid as uint16_t as libc::c_int)
            as libc::c_int
    } != 0
    {
        let mut at = 0 as *mut sctp_queued_to_read;
        if system_base_info.sctpsysctl.sctp_logging_level & 0x20000u32 != 0 {
            sctp_log_strm_del(control, 0 as *mut sctp_queued_to_read, 11i32);
        }
        /* EY it wont be queued if it could be delivered directly */
        queue_needed = 0i32;
        if (*asoc).size_on_all_streams >= (*control).length {
            (*asoc).size_on_all_streams =
                (*asoc).size_on_all_streams.wrapping_sub((*control).length)
        } else {
            (*asoc).size_on_all_streams = 0u32
        }
        if (*asoc).cnt_on_all_streams > 0u32 {
            (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
        } else {
            (*asoc).cnt_on_all_streams = 0u32
        }
        (*strm).last_mid_delivered = (*strm).last_mid_delivered.wrapping_add(1);
        sctp_mark_non_revokable(asoc, (*control).sinfo_tsn);
        sctp_add_to_readq(
            (*stcb).sctp_ep,
            stcb,
            control,
            &mut (*(*stcb).sctp_socket).so_rcv,
            1i32,
            0i32,
            1i32,
        );
        control = (*strm).inqueue.tqh_first;
        while !control.is_null() && {
            at = (*control).next_instrm.tqe_next;
            (1i32) != 0
        } {
            /* all delivered */
            nxt_todel = (*strm).last_mid_delivered.wrapping_add(1u32);
            if (if (*asoc).idata_supported as libc::c_int == 1i32 {
                (nxt_todel == (*control).mid) as libc::c_int
            } else {
                (nxt_todel as uint16_t as libc::c_int == (*control).mid as uint16_t as libc::c_int)
                    as libc::c_int
            }) != 0
                && (*control).sinfo_flags as libc::c_int >> 8i32 & 0x3i32 == 0x3i32
            {
                if (*control).on_strm_q as libc::c_int == 1i32 {
                    if !(*control).next_instrm.tqe_next.is_null() {
                        (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                            (*control).next_instrm.tqe_prev
                    } else {
                        (*strm).inqueue.tqh_last = (*control).next_instrm.tqe_prev
                    }
                    *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                    if (*asoc).size_on_all_streams >= (*control).length {
                        (*asoc).size_on_all_streams =
                            (*asoc).size_on_all_streams.wrapping_sub((*control).length)
                    } else {
                        (*asoc).size_on_all_streams = 0u32
                    }
                    if (*asoc).cnt_on_all_streams > 0u32 {
                        (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
                    } else {
                        (*asoc).cnt_on_all_streams = 0u32
                    }
                }
                (*control).on_strm_q = 0u8;
                (*strm).last_mid_delivered = (*strm).last_mid_delivered.wrapping_add(1);
                /*
                 * We ignore the return of deliver_data here
                 * since we always can hold the chunk on the
                 * d-queue. And we have a finite number that
                 * can be delivered from the strq.
                 */
                if system_base_info.sctpsysctl.sctp_logging_level & 0x20000u32 != 0 {
                    sctp_log_strm_del(control, 0 as *mut sctp_queued_to_read, 11i32);
                }
                sctp_mark_non_revokable(asoc, (*control).sinfo_tsn);
                sctp_add_to_readq(
                    (*stcb).sctp_ep,
                    stcb,
                    control,
                    &mut (*(*stcb).sctp_socket).so_rcv,
                    1i32,
                    0i32,
                    1i32,
                );
                control = at
            } else {
                if if (*asoc).idata_supported as libc::c_int == 1i32 {
                    (nxt_todel == (*control).mid) as libc::c_int
                } else {
                    (nxt_todel as uint16_t as libc::c_int
                        == (*control).mid as uint16_t as libc::c_int)
                        as libc::c_int
                } != 0
                {
                    *need_reasm = 1i32
                }
                break;
            }
        }
    }
    if queue_needed != 0 {
        /*
         * Ok, we did not deliver this guy, find the correct place
         * to put it on the queue.
         */
        if sctp_place_control_in_stream(strm, asoc, control) != 0 {
            snprintf(
                msg.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                b"Queue to str MID: %u duplicate\x00" as *const u8 as *const libc::c_char,
                (*control).mid,
            );
            sctp_clean_up_control(stcb, control);
            op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
            (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x3i32) as uint32_t;
            sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
            *abort_flag = 1i32
        }
    };
}
unsafe extern "C" fn sctp_setup_tail_pointer(mut control: *mut sctp_queued_to_read) {
    let mut m = 0 as *mut mbuf;
    let mut prev = 0 as *mut mbuf;
    let mut stcb = 0 as *mut sctp_tcb;
    stcb = (*control).stcb;
    (*control).held_length = 0u32;
    (*control).length = 0u32;
    m = (*control).data;
    while !m.is_null() {
        if (*m).m_hdr.mh_len == 0i32 {
            /* Skip mbufs with NO length */
            if prev.is_null() {
                /* First one */
                (*control).data = m_free(m);
                m = (*control).data
            } else {
                (*prev).m_hdr.mh_next = m_free(m);
                m = (*prev).m_hdr.mh_next
            }
            if m.is_null() {
                (*control).tail_mbuf = prev
            }
        } else {
            prev = m;
            ::std::intrinsics::atomic_xadd(&mut (*control).length, (*m).m_hdr.mh_len as uint32_t);
            if (*control).on_read_q != 0 {
                /*
                 * On read queue so we must increment the
                 * SB stuff, we assume caller has done any locks of SB.
                 */
                ::std::intrinsics::atomic_xadd(
                    &mut (*(*stcb).sctp_socket).so_rcv.sb_cc,
                    (*m).m_hdr.mh_len as u_int,
                );
                ::std::intrinsics::atomic_xadd(&mut (*(*stcb).sctp_socket).so_rcv.sb_mbcnt, 256u32);
                if !stcb.is_null() {
                    ::std::intrinsics::atomic_xadd(
                        &mut (*stcb).asoc.sb_cc,
                        (*m).m_hdr.mh_len as uint32_t,
                    );
                    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.my_rwnd_control_len, 256u32);
                }
            }
            m = (*m).m_hdr.mh_next
        }
    }
    if !prev.is_null() {
        (*control).tail_mbuf = prev
    };
}
unsafe extern "C" fn sctp_add_to_tail_pointer(
    mut control: *mut sctp_queued_to_read,
    mut m: *mut mbuf,
    mut added: *mut uint32_t,
) {
    let mut prev = 0 as *mut mbuf;
    let mut stcb = 0 as *mut sctp_tcb;
    stcb = (*control).stcb;
    if stcb.is_null() {
        return;
    }
    if (*control).tail_mbuf.is_null() {
        /* TSNH */
        m_freem((*control).data);
        (*control).data = m;
        sctp_setup_tail_pointer(control);
        return;
    }
    (*(*control).tail_mbuf).m_hdr.mh_next = m;
    while !m.is_null() {
        if (*m).m_hdr.mh_len == 0i32 {
            /* Skip mbufs with NO length */
            if prev.is_null() {
                /* First one */
                (*(*control).tail_mbuf).m_hdr.mh_next = m_free(m);
                m = (*(*control).tail_mbuf).m_hdr.mh_next
            } else {
                (*prev).m_hdr.mh_next = m_free(m);
                m = (*prev).m_hdr.mh_next
            }
            if m.is_null() {
                (*control).tail_mbuf = prev
            }
        } else {
            prev = m;
            if (*control).on_read_q != 0 {
                /*
                 * On read queue so we must increment the
                 * SB stuff, we assume caller has done any locks of SB.
                 */
                ::std::intrinsics::atomic_xadd(
                    &mut (*(*stcb).sctp_socket).so_rcv.sb_cc,
                    (*m).m_hdr.mh_len as u_int,
                );
                ::std::intrinsics::atomic_xadd(&mut (*(*stcb).sctp_socket).so_rcv.sb_mbcnt, 256u32);
                if !stcb.is_null() {
                    ::std::intrinsics::atomic_xadd(
                        &mut (*stcb).asoc.sb_cc,
                        (*m).m_hdr.mh_len as uint32_t,
                    );
                    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.my_rwnd_control_len, 256u32);
                }
            }
            *added = (*added).wrapping_add((*m).m_hdr.mh_len as libc::c_uint);
            ::std::intrinsics::atomic_xadd(&mut (*control).length, (*m).m_hdr.mh_len as uint32_t);
            m = (*m).m_hdr.mh_next
        }
    }
    if !prev.is_null() {
        (*control).tail_mbuf = prev
    };
}
unsafe extern "C" fn sctp_build_readq_entry_from_ctl(
    mut nc: *mut sctp_queued_to_read,
    mut control: *mut sctp_queued_to_read,
) {
    memset(
        nc as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_queued_to_read>() as libc::c_ulong,
    );
    (*nc).sinfo_stream = (*control).sinfo_stream;
    (*nc).mid = (*control).mid;
    (*nc).reasm.tqh_first = 0 as *mut sctp_tmit_chunk;
    (*nc).reasm.tqh_last = &mut (*nc).reasm.tqh_first;
    (*nc).top_fsn = (*control).top_fsn;
    (*nc).mid = (*control).mid;
    (*nc).sinfo_flags = (*control).sinfo_flags;
    (*nc).sinfo_ppid = (*control).sinfo_ppid;
    (*nc).sinfo_context = (*control).sinfo_context;
    (*nc).fsn_included = 0xffffffffu32;
    (*nc).sinfo_tsn = (*control).sinfo_tsn;
    (*nc).sinfo_cumtsn = (*control).sinfo_cumtsn;
    (*nc).sinfo_assoc_id = (*control).sinfo_assoc_id;
    (*nc).whoFrom = (*control).whoFrom;
    ::std::intrinsics::atomic_xadd(&mut (*(*nc).whoFrom).ref_count, 1i32);
    (*nc).stcb = (*control).stcb;
    (*nc).port_from = (*control).port_from;
}
unsafe extern "C" fn sctp_reset_a_control(
    mut control: *mut sctp_queued_to_read,
    mut inp: *mut sctp_inpcb,
    mut tsn: uint32_t,
) {
    (*control).fsn_included = tsn;
    if (*control).on_read_q != 0 {
        /*
         * We have to purge it from there,
         * hopefully this will work :-)
         */
        if !(*control).next.tqe_next.is_null() {
            (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
        } else {
            (*inp).read_queue.tqh_last = (*control).next.tqe_prev
        }
        *(*control).next.tqe_prev = (*control).next.tqe_next;
        (*control).on_read_q = 0u8
    };
}
unsafe extern "C" fn sctp_handle_old_unordered_data(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strm: *mut sctp_stream_in,
    mut control: *mut sctp_queued_to_read,
    mut pd_point: uint32_t,
    mut inp_read_lock_held: libc::c_int,
) -> libc::c_int {
    let mut cnt_added = 0;
    if (*control).first_frag_seen as libc::c_int == 0i32 {
        /* Nothing we can do, we have not seen the first piece yet */
        return 1i32;
    }
    /* Collapse any we can */
    cnt_added = 0i32;
    'c_30306: loop {
        let mut chk = 0 as *mut sctp_tmit_chunk;
        let mut fsn = 0;
        fsn = (*control).fsn_included.wrapping_add(1u32);
        /* Now what can we add? */
        chk = (*control).reasm.tqh_first;
        loop {
            let mut lchk = 0 as *mut sctp_tmit_chunk;
            let mut nc = 0 as *mut sctp_queued_to_read;
            if !(!chk.is_null() && {
                lchk = (*chk).sctp_next.tqe_next;
                (1i32) != 0
            }) {
                break 'c_30306;
            }
            if !((*chk).rec.data.fsn == fsn) {
                break 'c_30306;
            }
            /* Ok lets add it */
            nc = malloc(system_base_info.sctppcbinfo.ipi_zone_readq) as *mut sctp_queued_to_read;
            if !nc.is_null() {
                ::std::intrinsics::atomic_xadd(
                    &mut system_base_info.sctppcbinfo.ipi_count_readq,
                    1u32,
                );
            }
            if nc.is_null() {
                break 'c_30306;
            }
            memset(
                nc as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sctp_queued_to_read>() as libc::c_ulong,
            );
            if !(*chk).sctp_next.tqe_next.is_null() {
                (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
            } else {
                (*control).reasm.tqh_last = (*chk).sctp_next.tqe_prev
            }
            *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
            sctp_add_chk_to_control(control, strm, stcb, asoc, chk, 0i32);
            fsn = fsn.wrapping_add(1);
            cnt_added += 1;
            chk = 0 as *mut sctp_tmit_chunk;
            if (*control).end_added != 0 {
                /* We are done */
                if !(*control).reasm.tqh_first.is_null() {
                    let mut tchk = 0 as *mut sctp_tmit_chunk;
                    sctp_build_readq_entry_from_ctl(nc, control);
                    tchk = (*control).reasm.tqh_first;
                    if (*tchk).rec.data.rcv_flags as libc::c_int & 0x2i32 != 0 {
                        if !(*tchk).sctp_next.tqe_next.is_null() {
                            (*(*tchk).sctp_next.tqe_next).sctp_next.tqe_prev =
                                (*tchk).sctp_next.tqe_prev
                        } else {
                            (*control).reasm.tqh_last = (*tchk).sctp_next.tqe_prev
                        }
                        *(*tchk).sctp_next.tqe_prev = (*tchk).sctp_next.tqe_next;
                        if (*asoc).size_on_reasm_queue >= (*tchk).send_size as libc::c_uint {
                            (*asoc).size_on_reasm_queue = (*asoc)
                                .size_on_reasm_queue
                                .wrapping_sub((*tchk).send_size as libc::c_uint)
                        } else {
                            (*asoc).size_on_reasm_queue = 0u32
                        }
                        if (*asoc).cnt_on_reasm_queue > 0u32 {
                            (*asoc).cnt_on_reasm_queue = (*asoc).cnt_on_reasm_queue.wrapping_sub(1)
                        } else {
                            (*asoc).cnt_on_reasm_queue = 0u32
                        }
                        (*nc).first_frag_seen = 1u8;
                        (*nc).fsn_included = (*tchk).rec.data.fsn;
                        (*nc).data = (*tchk).data;
                        (*nc).sinfo_ppid = (*tchk).rec.data.ppid;
                        (*nc).sinfo_tsn = (*tchk).rec.data.tsn;
                        sctp_mark_non_revokable(asoc, (*tchk).rec.data.tsn);
                        (*tchk).data = 0 as *mut mbuf;
                        if (*tchk).holds_key_ref != 0 {
                            sctp_auth_key_release(stcb, (*tchk).auth_keyid, 0i32);
                            (*tchk).holds_key_ref = 0u8
                        }
                        if !stcb.is_null() {
                            if !(*tchk).whoTo.is_null() {
                                if !(*tchk).whoTo.is_null() {
                                    if ::std::intrinsics::atomic_xadd(
                                        &mut (*(*tchk).whoTo).ref_count as *mut libc::c_int,
                                        -(1i32),
                                    ) == 1i32
                                    {
                                        sctp_os_timer_stop(&mut (*(*tchk).whoTo).rxt_timer.timer);
                                        sctp_os_timer_stop(&mut (*(*tchk).whoTo).pmtu_timer.timer);
                                        sctp_os_timer_stop(&mut (*(*tchk).whoTo).hb_timer.timer);
                                        if !(*(*tchk).whoTo).ro.ro_rt.is_null() {
                                            if (*(*(*tchk).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                                                sctp_userspace_rtfree((*(*tchk).whoTo).ro.ro_rt);
                                            } else {
                                                (*(*(*tchk).whoTo).ro.ro_rt).rt_refcnt -= 1
                                            }
                                            (*(*tchk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                                            (*(*tchk).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                                        }
                                        if (*(*tchk).whoTo).src_addr_selected != 0 {
                                            sctp_free_ifa((*(*tchk).whoTo).ro._s_addr);
                                            (*(*tchk).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                                        }
                                        (*(*tchk).whoTo).src_addr_selected = 0u8;
                                        (*(*tchk).whoTo).dest_state = ((*(*tchk).whoTo).dest_state
                                            as libc::c_int
                                            & !(0x1i32))
                                            as uint16_t;
                                        free((*tchk).whoTo as *mut libc::c_void);
                                        ::std::intrinsics::atomic_xsub(
                                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                            1u32,
                                        );
                                    }
                                }
                                (*tchk).whoTo = 0 as *mut sctp_nets
                            }
                            if (*stcb).asoc.free_chunk_cnt as libc::c_uint
                                > system_base_info.sctpsysctl.sctp_asoc_free_resc_limit
                                || system_base_info.sctppcbinfo.ipi_free_chunks
                                    > system_base_info.sctpsysctl.sctp_system_free_resc_limit
                            {
                                free(tchk as *mut libc::c_void);
                                ::std::intrinsics::atomic_xsub(
                                    &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                                    1u32,
                                );
                            } else {
                                (*tchk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
                                (*tchk).sctp_next.tqe_prev = (*stcb).asoc.free_chunks.tqh_last;
                                *(*stcb).asoc.free_chunks.tqh_last = tchk;
                                (*stcb).asoc.free_chunks.tqh_last = &mut (*tchk).sctp_next.tqe_next;
                                (*stcb).asoc.free_chunk_cnt =
                                    (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
                                ::std::intrinsics::atomic_xadd(
                                    &mut system_base_info.sctppcbinfo.ipi_free_chunks,
                                    1u32,
                                );
                            }
                        } else {
                            free(tchk as *mut libc::c_void);
                            ::std::intrinsics::atomic_xsub(
                                &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                                1u32,
                            );
                        }
                        sctp_setup_tail_pointer(nc);
                        tchk = (*control).reasm.tqh_first
                    }
                    /* Spin the rest onto the queue */
                    while !tchk.is_null() {
                        if !(*tchk).sctp_next.tqe_next.is_null() {
                            (*(*tchk).sctp_next.tqe_next).sctp_next.tqe_prev =
                                (*tchk).sctp_next.tqe_prev
                        } else {
                            (*control).reasm.tqh_last = (*tchk).sctp_next.tqe_prev
                        }
                        *(*tchk).sctp_next.tqe_prev = (*tchk).sctp_next.tqe_next;
                        (*tchk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
                        (*tchk).sctp_next.tqe_prev = (*nc).reasm.tqh_last;
                        *(*nc).reasm.tqh_last = tchk;
                        (*nc).reasm.tqh_last = &mut (*tchk).sctp_next.tqe_next;
                        tchk = (*control).reasm.tqh_first
                    }
                    /* Now lets add it to the queue after removing control */
                    (*nc).next_instrm.tqe_next = 0 as *mut sctp_queued_to_read;
                    (*nc).next_instrm.tqe_prev = (*strm).uno_inqueue.tqh_last;
                    *(*strm).uno_inqueue.tqh_last = nc;
                    (*strm).uno_inqueue.tqh_last = &mut (*nc).next_instrm.tqe_next;
                    (*nc).on_strm_q = 2u8;
                    if (*control).on_strm_q != 0 {
                        if !(*control).next_instrm.tqe_next.is_null() {
                            (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                                (*control).next_instrm.tqe_prev
                        } else {
                            (*strm).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
                        }
                        *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                        (*control).on_strm_q = 0u8
                    }
                }
                if (*control).pdapi_started != 0 {
                    (*strm).pd_api_started = 0u8;
                    (*control).pdapi_started = 0u8
                }
                if (*control).on_strm_q != 0 {
                    if !(*control).next_instrm.tqe_next.is_null() {
                        (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                            (*control).next_instrm.tqe_prev
                    } else {
                        (*strm).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
                    }
                    *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                    (*control).on_strm_q = 0u8;
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_reasmusrmsgs,
                        1u32,
                    );
                }
                if (*control).on_read_q as libc::c_int == 0i32 {
                    sctp_add_to_readq(
                        (*stcb).sctp_ep,
                        stcb,
                        control,
                        &mut (*(*stcb).sctp_socket).so_rcv,
                        (*control).end_added as libc::c_int,
                        inp_read_lock_held,
                        0i32,
                    );
                } else {
                    sctp_invoke_recv_callback((*stcb).sctp_ep, stcb, control, inp_read_lock_held);
                }
                sctp_wakeup_the_read_socket((*stcb).sctp_ep, stcb, 0i32);
                if (*nc).first_frag_seen as libc::c_int != 0 && !(*nc).reasm.tqh_first.is_null() {
                    /* Switch to the new guy and continue */
                    control = nc;
                    break;
                } else {
                    if (*nc).on_strm_q as libc::c_int == 0i32 {
                        free(nc as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_readq,
                            1u32,
                        );
                    }
                    return 1i32;
                }
            } else {
                free(nc as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_readq,
                    1u32,
                );
                chk = lchk
            }
        }
    }
    /* Can't add more */
    if cnt_added != 0 && (*strm).pd_api_started as libc::c_int != 0 {
        sctp_invoke_recv_callback((*stcb).sctp_ep, stcb, control, 0i32);
        sctp_wakeup_the_read_socket((*stcb).sctp_ep, stcb, 0i32);
    }
    if (*control).length > pd_point && (*strm).pd_api_started as libc::c_int == 0i32 {
        (*strm).pd_api_started = 1u8;
        (*control).pdapi_started = 1u8;
        sctp_add_to_readq(
            (*stcb).sctp_ep,
            stcb,
            control,
            &mut (*(*stcb).sctp_socket).so_rcv,
            (*control).end_added as libc::c_int,
            inp_read_lock_held,
            0i32,
        );
        sctp_wakeup_the_read_socket((*stcb).sctp_ep, stcb, 0i32);
        return 0i32;
    } else {
        return 1i32;
    };
}
unsafe extern "C" fn sctp_inject_old_unordered_data(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut control: *mut sctp_queued_to_read,
    mut chk: *mut sctp_tmit_chunk,
    mut abort_flag: *mut libc::c_int,
) {
    let mut at = 0 as *mut sctp_tmit_chunk;
    let mut inserted = 0;
    /*
     * Here we need to place the chunk into the control structure
     * sorted in the correct order.
     */
    if (*chk).rec.data.rcv_flags as libc::c_int & 0x2i32 != 0 {
        /* Its the very first one. */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"chunk is a first fsn: %u becomes fsn_included\n\x00" as *const u8
                        as *const libc::c_char,
                    (*chk).rec.data.fsn,
                );
            }
        }
        at = (*control).reasm.tqh_first;
        if !(!at.is_null()
            && ((*chk).rec.data.fsn < (*at).rec.data.fsn
                && (*at).rec.data.fsn.wrapping_sub((*chk).rec.data.fsn) > (1u32) << 31i32
                || (*chk).rec.data.fsn > (*at).rec.data.fsn
                    && (*chk).rec.data.fsn.wrapping_sub((*at).rec.data.fsn) < (1u32) << 31i32))
        {
            if (*control).first_frag_seen != 0 {
                if !((*chk).rec.data.fsn < (*control).fsn_included
                    && (*control).fsn_included.wrapping_sub((*chk).rec.data.fsn) > (1u32) << 31i32
                    || (*chk).rec.data.fsn > (*control).fsn_included
                        && (*chk).rec.data.fsn.wrapping_sub((*control).fsn_included)
                            < (1u32) << 31i32)
                {
                    let mut tdata = 0 as *mut mbuf;
                    let mut tmp = 0;
                    if (*chk).rec.data.fsn == (*control).fsn_included
                        || (*control).pdapi_started as libc::c_int != 0
                    {
                        /*
                         * Ok this should not happen, if it does
                         * we started the pd-api on the higher TSN (since
                         * the equals part is a TSN failure it must be that).
                         *
                         * We are completly hosed in that case since I have
                         * no way to recover. This really will only happen
                         * if we can get more TSN's higher before the pd-api-point.
                         */
                        sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0x4i32);
                        return;
                    }
                    /*
                     * Ok we have two firsts and the one we just got
                     * is smaller than the one we previously placed.. yuck!
                     * We must swap them out.
                     */
                    /* swap the mbufs */
                    tdata = (*control).data;
                    (*control).data = (*chk).data;
                    (*chk).data = tdata;
                    /* Save the lengths */
                    (*chk).send_size = (*control).length as uint16_t;
                    /* Recompute length of control and tail pointer */
                    sctp_setup_tail_pointer(control);
                    /* Fix the FSN included */
                    tmp = (*control).fsn_included;
                    (*control).fsn_included = (*chk).rec.data.fsn;
                    (*chk).rec.data.fsn = tmp;
                    /* Fix the TSN included */
                    tmp = (*control).sinfo_tsn;
                    (*control).sinfo_tsn = (*chk).rec.data.tsn;
                    (*chk).rec.data.tsn = tmp;
                    /* Fix the PPID included */
                    tmp = (*control).sinfo_ppid;
                    (*control).sinfo_ppid = (*chk).rec.data.ppid;
                    (*chk).rec.data.ppid = tmp
                }
            } else {
                (*control).first_frag_seen = 1u8;
                (*control).fsn_included = (*chk).rec.data.fsn;
                (*control).top_fsn = (*chk).rec.data.fsn;
                (*control).sinfo_tsn = (*chk).rec.data.tsn;
                (*control).sinfo_ppid = (*chk).rec.data.ppid;
                (*control).data = (*chk).data;
                sctp_mark_non_revokable(asoc, (*chk).rec.data.tsn);
                (*chk).data = 0 as *mut mbuf;
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
                                    ((*(*chk).whoTo).dest_state as libc::c_int & !(0x1i32))
                                        as uint16_t;
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
                sctp_setup_tail_pointer(control);
                return;
            }
        }
    }
    /* Fix tail pointer */
    inserted = 0i32;
    at = (*control).reasm.tqh_first;
    while !at.is_null() {
        if (*at).rec.data.fsn < (*chk).rec.data.fsn
            && (*chk).rec.data.fsn.wrapping_sub((*at).rec.data.fsn) > (1u32) << 31i32
            || (*at).rec.data.fsn > (*chk).rec.data.fsn
                && (*at).rec.data.fsn.wrapping_sub((*chk).rec.data.fsn) < (1u32) << 31i32
        {
            /*
             * This one in queue is bigger than the new one, insert
             * the new one before at.
             */
            (*asoc).size_on_reasm_queue = (*asoc)
                .size_on_reasm_queue
                .wrapping_add((*chk).send_size as libc::c_uint);
            (*asoc).cnt_on_reasm_queue = (*asoc).cnt_on_reasm_queue.wrapping_add(1);
            inserted = 1i32;
            (*chk).sctp_next.tqe_prev = (*at).sctp_next.tqe_prev;
            (*chk).sctp_next.tqe_next = at;
            *(*at).sctp_next.tqe_prev = chk;
            (*at).sctp_next.tqe_prev = &mut (*chk).sctp_next.tqe_next;
            break;
        } else {
            if (*at).rec.data.fsn == (*chk).rec.data.fsn {
                /*
                 * They sent a duplicate fsn number. This
                 * really should not happen since the FSN is
                 * a TSN and it should have been dropped earlier.
                 */
                sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0x5i32);
                return;
            }
            at = (*at).sctp_next.tqe_next
        }
    }
    if inserted == 0i32 {
        /* Its at the end */
        (*asoc).size_on_reasm_queue = (*asoc)
            .size_on_reasm_queue
            .wrapping_add((*chk).send_size as libc::c_uint);
        (*asoc).cnt_on_reasm_queue = (*asoc).cnt_on_reasm_queue.wrapping_add(1);
        (*control).top_fsn = (*chk).rec.data.fsn;
        (*chk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
        (*chk).sctp_next.tqe_prev = (*control).reasm.tqh_last;
        *(*control).reasm.tqh_last = chk;
        (*control).reasm.tqh_last = &mut (*chk).sctp_next.tqe_next
    };
}
unsafe extern "C" fn sctp_deliver_reasm_check(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut strm: *mut sctp_stream_in,
    mut inp_read_lock_held: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut nctl = 0 as *mut sctp_queued_to_read;
    let mut pd_point = 0;
    let mut ret = 0i32;
    if !(*stcb).sctp_socket.is_null() {
        pd_point = if (*(*stcb).sctp_socket).so_rcv.sb_hiwat >> 1i32
            > (*(*stcb).sctp_ep).partial_delivery_point
        {
            (*(*stcb).sctp_ep).partial_delivery_point
        } else {
            ((*(*stcb).sctp_socket).so_rcv.sb_hiwat) >> 1i32
        }
    } else {
        pd_point = (*(*stcb).sctp_ep).partial_delivery_point
    }
    control = (*strm).uno_inqueue.tqh_first;
    if !control.is_null() && (*asoc).idata_supported as libc::c_int == 0i32 {
        /* Special handling needed for "old" data format */
        if sctp_handle_old_unordered_data(stcb, asoc, strm, control, pd_point, inp_read_lock_held)
            != 0
        {
            current_block = 10215780332799617192;
        } else {
            current_block = 13536709405535804910;
        }
    } else {
        current_block = 13536709405535804910;
    }
    match current_block {
        13536709405535804910 => {
            if (*strm).pd_api_started != 0 {
                /* Can't add more */
                return 0i32;
            }
            while !control.is_null() {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info.debug_printf.expect("non-null function pointer")(b"Looking at control: %p e(%d) ssn: %u top_fsn: %u inc_fsn: %u -uo\n\x00"
                                                                                              as
                                                                                              *const u8
                                                                                              as
                                                                                              *const libc::c_char,
                                                                                          control,
                                                                                          (*control).end_added
                                                                                              as
                                                                                              libc::c_int,
                                                                                          (*control).mid,
                                                                                          (*control).top_fsn,
                                                                                          (*control).fsn_included);
                    }
                }
                nctl = (*control).next_instrm.tqe_next;
                if (*control).end_added != 0 {
                    /* We just put the last bit on */
                    if (*control).on_strm_q != 0 {
                        ::std::intrinsics::atomic_xadd(
                            &mut system_base_info.sctpstat.sctps_reasmusrmsgs,
                            1u32,
                        );
                        if !(*control).next_instrm.tqe_next.is_null() {
                            (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                                (*control).next_instrm.tqe_prev
                        } else {
                            (*strm).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
                        }
                        *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                        (*control).on_strm_q = 0u8
                    }
                    if (*control).on_read_q as libc::c_int == 0i32 {
                        sctp_add_to_readq(
                            (*stcb).sctp_ep,
                            stcb,
                            control,
                            &mut (*(*stcb).sctp_socket).so_rcv,
                            (*control).end_added as libc::c_int,
                            inp_read_lock_held,
                            0i32,
                        );
                    }
                } else if (*control).length >= pd_point
                    && (*strm).pd_api_started as libc::c_int == 0i32
                {
                    (*strm).pd_api_started = 1u8;
                    (*control).pdapi_started = 1u8;
                    sctp_add_to_readq(
                        (*stcb).sctp_ep,
                        stcb,
                        control,
                        &mut (*(*stcb).sctp_socket).so_rcv,
                        (*control).end_added as libc::c_int,
                        inp_read_lock_held,
                        0i32,
                    );
                    break;
                }
                control = nctl
            }
        }
        _ => {}
    }
    control = (*strm).inqueue.tqh_first;
    if (*strm).pd_api_started != 0 {
        /* Can we do a PD-API for this un-ordered guy? */
        /* Can't add more */
        return 0i32;
    }
    if control.is_null() {
        return ret;
    }
    if if (*asoc).idata_supported as libc::c_int == 1i32 {
        ((*strm).last_mid_delivered == (*control).mid) as libc::c_int
    } else {
        ((*strm).last_mid_delivered as uint16_t as libc::c_int
            == (*control).mid as uint16_t as libc::c_int) as libc::c_int
    } != 0
    {
        /* Ok the guy at the top was being partially delivered
         * completed, so we remove it. Note
         * the pd_api flag was taken off when the
         * chunk was merged on in sctp_queue_data_for_reasm below.
         */
        nctl = (*control).next_instrm.tqe_next;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info.debug_printf.expect("non-null function pointer")(b"Looking at control: %p e(%d) ssn: %u top_fsn: %u inc_fsn: %u (lastdel: %u)- o\n\x00"
                                                                                      as
                                                                                      *const u8
                                                                                      as
                                                                                      *const libc::c_char,
                                                                                  control,
                                                                                  (*control).end_added
                                                                                      as
                                                                                      libc::c_int,
                                                                                  (*control).mid,
                                                                                  (*control).top_fsn,
                                                                                  (*control).fsn_included,
                                                                                  (*strm).last_mid_delivered);
            }
        }
        if (*control).end_added != 0 {
            if (*control).on_strm_q != 0 {
                ::std::intrinsics::atomic_xadd(
                    &mut system_base_info.sctpstat.sctps_reasmusrmsgs,
                    1u32,
                );
                if !(*control).next_instrm.tqe_next.is_null() {
                    (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                        (*control).next_instrm.tqe_prev
                } else {
                    (*strm).inqueue.tqh_last = (*control).next_instrm.tqe_prev
                }
                *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                if (*asoc).size_on_all_streams >= (*control).length {
                    (*asoc).size_on_all_streams =
                        (*asoc).size_on_all_streams.wrapping_sub((*control).length)
                } else {
                    (*asoc).size_on_all_streams = 0u32
                }
                if (*asoc).cnt_on_all_streams > 0u32 {
                    (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
                } else {
                    (*asoc).cnt_on_all_streams = 0u32
                }
                (*control).on_strm_q = 0u8
            }
            if (*strm).pd_api_started as libc::c_int != 0
                && (*control).pdapi_started as libc::c_int != 0
            {
                (*control).pdapi_started = 0u8;
                (*strm).pd_api_started = 0u8
            }
            if (*control).on_read_q as libc::c_int == 0i32 {
                sctp_add_to_readq(
                    (*stcb).sctp_ep,
                    stcb,
                    control,
                    &mut (*(*stcb).sctp_socket).so_rcv,
                    (*control).end_added as libc::c_int,
                    inp_read_lock_held,
                    0i32,
                );
            }
            control = nctl
        }
    }
    if (*strm).pd_api_started != 0 {
        /* Can't add more must have gotten an un-ordered above being partially delivered. */
        return 0i32;
    }
    loop {
        let mut next_to_del = 0;
        let mut done = 0;
        next_to_del = (*strm).last_mid_delivered.wrapping_add(1u32);
        if control.is_null() {
            break;
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info.debug_printf.expect("non-null function pointer")(b"Looking at control: %p e(%d) ssn: %u top_fsn: %u inc_fsn: %u (nxtdel: %u)- o\n\x00"
                                                                                      as
                                                                                      *const u8
                                                                                      as
                                                                                      *const libc::c_char,
                                                                                  control,
                                                                                  (*control).end_added
                                                                                      as
                                                                                      libc::c_int,
                                                                                  (*control).mid,
                                                                                  (*control).top_fsn,
                                                                                  (*control).fsn_included,
                                                                                  next_to_del);
            }
        }
        nctl = (*control).next_instrm.tqe_next;
        if !((if (*asoc).idata_supported as libc::c_int == 1i32 {
            ((*control).mid == next_to_del) as libc::c_int
        } else {
            ((*control).mid as uint16_t as libc::c_int == next_to_del as uint16_t as libc::c_int)
                as libc::c_int
        }) != 0
            && (*control).first_frag_seen as libc::c_int != 0)
        {
            break;
        }

        /* Ok we can deliver it onto the stream. */
        if (*control).end_added != 0 {
            /* We are done with it afterwards */
            if (*control).on_strm_q != 0 {
                ::std::intrinsics::atomic_xadd(
                    &mut system_base_info.sctpstat.sctps_reasmusrmsgs,
                    1u32,
                );
                if !(*control).next_instrm.tqe_next.is_null() {
                    (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                        (*control).next_instrm.tqe_prev
                } else {
                    (*strm).inqueue.tqh_last = (*control).next_instrm.tqe_prev
                }
                *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                if (*asoc).size_on_all_streams >= (*control).length {
                    (*asoc).size_on_all_streams =
                        (*asoc).size_on_all_streams.wrapping_sub((*control).length)
                } else {
                    (*asoc).size_on_all_streams = 0u32
                }
                if (*asoc).cnt_on_all_streams > 0u32 {
                    (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
                } else {
                    (*asoc).cnt_on_all_streams = 0u32
                }
                (*control).on_strm_q = 0u8
            }
            ret += 1
        }
        if (*control).sinfo_flags as libc::c_int >> 8i32 & 0x3i32 == 0x3i32 {
            /* A singleton now slipping through - mark it non-revokable too */
            sctp_mark_non_revokable(asoc, (*control).sinfo_tsn);
        } else if (*control).end_added as libc::c_int == 0i32 {
            /* Check if we can defer adding until its all there */
            if (*control).length < pd_point || (*strm).pd_api_started as libc::c_int != 0 {
                break;
            }
        }
        done = ((*control).end_added as libc::c_int != 0
            && (*control).last_frag_seen as libc::c_int != 0) as libc::c_int;
        if (*control).on_read_q as libc::c_int == 0i32 {
            if done == 0 {
                if (*asoc).size_on_all_streams >= (*control).length {
                    (*asoc).size_on_all_streams =
                        (*asoc).size_on_all_streams.wrapping_sub((*control).length)
                } else {
                    (*asoc).size_on_all_streams = 0u32
                }
                (*strm).pd_api_started = 1u8;
                (*control).pdapi_started = 1u8
            }
            sctp_add_to_readq(
                (*stcb).sctp_ep,
                stcb,
                control,
                &mut (*(*stcb).sctp_socket).so_rcv,
                (*control).end_added as libc::c_int,
                inp_read_lock_held,
                0i32,
            );
        }
        (*strm).last_mid_delivered = next_to_del;
        if !(done != 0) {
            break;
        }
        control = nctl
    }
    /* Don't need it or cannot add more (one being delivered that way) */
    return ret;
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
 * NOTES: On the outbound side of things I need to check the sack timer to
 * see if I should generate a sack into the chunk queue (if I have data to
 * send that is and will be sending it .. for bundling.
 *
 * The callback in sctp_usrreq.c will get called when the socket is read from.
 * This will cause sctp_service_queues() to get called on the top entry in
 * the list.
 */
unsafe extern "C" fn sctp_add_chk_to_control(
    mut control: *mut sctp_queued_to_read,
    mut strm: *mut sctp_stream_in,
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut chk: *mut sctp_tmit_chunk,
    mut hold_rlock: libc::c_int,
) -> uint32_t {
    let mut added = 0u32;
    let mut i_locked = 0i32;
    if (*control).on_read_q as libc::c_int != 0 && hold_rlock == 0i32 {
        /*
         * Its being pd-api'd so we must
         * do some locks.
         */
        pthread_mutex_lock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
        i_locked = 1i32
    }
    if (*control).data.is_null() {
        (*control).data = (*chk).data;
        sctp_setup_tail_pointer(control);
    } else {
        sctp_add_to_tail_pointer(control, (*chk).data, &mut added);
    }
    (*control).fsn_included = (*chk).rec.data.fsn;
    (*asoc).size_on_reasm_queue = (*asoc)
        .size_on_reasm_queue
        .wrapping_sub((*chk).send_size as libc::c_uint);
    if (*asoc).cnt_on_reasm_queue > 0u32 {
        (*asoc).cnt_on_reasm_queue = (*asoc).cnt_on_reasm_queue.wrapping_sub(1)
    } else {
        (*asoc).cnt_on_reasm_queue = 0u32
    }
    sctp_mark_non_revokable(asoc, (*chk).rec.data.tsn);
    (*chk).data = 0 as *mut mbuf;
    if (*chk).rec.data.rcv_flags as libc::c_int & 0x2i32 != 0 {
        (*control).first_frag_seen = 1u8;
        (*control).sinfo_tsn = (*chk).rec.data.tsn;
        (*control).sinfo_ppid = (*chk).rec.data.ppid
    }
    if (*chk).rec.data.rcv_flags as libc::c_int & 0x1i32 != 0 {
        /* Its complete */
        if (*control).on_strm_q as libc::c_int != 0 && (*control).on_read_q as libc::c_int != 0 {
            if (*control).pdapi_started != 0 {
                (*control).pdapi_started = 0u8;
                (*strm).pd_api_started = 0u8
            }
            if (*control).on_strm_q as libc::c_int == 2i32 {
                /* Unordered */
                if !(*control).next_instrm.tqe_next.is_null() {
                    (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                        (*control).next_instrm.tqe_prev
                } else {
                    (*strm).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
                }
                *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                (*control).on_strm_q = 0u8
            } else if (*control).on_strm_q as libc::c_int == 1i32 {
                /* Ordered */
                if !(*control).next_instrm.tqe_next.is_null() {
                    (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                        (*control).next_instrm.tqe_prev
                } else {
                    (*strm).inqueue.tqh_last = (*control).next_instrm.tqe_prev
                }
                *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                /*
                 * Don't need to decrement size_on_all_streams,
                 * since control is on the read queue.
                 */
                if (*asoc).cnt_on_all_streams > 0u32 {
                    (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
                } else {
                    (*asoc).cnt_on_all_streams = 0u32
                }
                (*control).on_strm_q = 0u8
            }
        }
        (*control).end_added = 1u8;
        (*control).last_frag_seen = 1u8
    }
    if i_locked != 0 {
        pthread_mutex_unlock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
    }
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
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        } else {
            (*chk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
            (*chk).sctp_next.tqe_prev = (*stcb).asoc.free_chunks.tqh_last;
            *(*stcb).asoc.free_chunks.tqh_last = chk;
            (*stcb).asoc.free_chunks.tqh_last = &mut (*chk).sctp_next.tqe_next;
            (*stcb).asoc.free_chunk_cnt = (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
            ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_free_chunks, 1u32);
        }
    } else {
        free(chk as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
    }
    return added;
}
/*
 * Dump onto the re-assembly queue, in its proper place. After dumping on the
 * queue, see if anthing can be delivered. If so pull it off (or as much as
 * we can. If we run out of space then we must dump what we can and set the
 * appropriate flag to say we queued what we could.
 */
unsafe extern "C" fn sctp_queue_data_for_reasm(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut control: *mut sctp_queued_to_read,
    mut chk: *mut sctp_tmit_chunk,
    mut created_control: libc::c_int,
    mut abort_flag: *mut libc::c_int,
    mut tsn: uint32_t,
) {
    let mut at = 0 as *mut sctp_tmit_chunk;
    let mut strm = 0 as *mut sctp_stream_in;
    let mut do_wakeup = 0;
    let mut unordered = 0;
    strm = &mut *(*asoc).strmin.offset((*control).sinfo_stream as isize) as *mut sctp_stream_in;
    /*
     * For old un-ordered data chunks.
     */
    if (*control).sinfo_flags as libc::c_int >> 8i32 & 0x4i32 != 0 {
        unordered = 1i32
    } else {
        unordered = 0i32
    }
    /* Must be added to the stream-in queue */
    if created_control != 0 {
        if unordered == 0i32 {
            (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_add(1)
        }
        if sctp_place_control_in_stream(strm, asoc, control) != 0 {
            /* Duplicate SSN? */
            sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0x6i32);
            sctp_clean_up_control(stcb, control);
            return;
        }
        if tsn == (*asoc).cumulative_tsn.wrapping_add(1u32)
            && (*asoc).idata_supported as libc::c_int == 0i32
        {
            /* Ok we created this control and now
             * lets validate that its legal i.e. there
             * is a B bit set, if not and we have
             * up to the cum-ack then its invalid.
             */
            if (*chk).rec.data.rcv_flags as libc::c_int & 0x2i32 == 0i32 {
                sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0x7i32);
                return;
            }
        }
    }
    if (*asoc).idata_supported as libc::c_int == 0i32 && unordered == 1i32 {
        sctp_inject_old_unordered_data(stcb, asoc, control, chk, abort_flag);
        return;
    }
    /*
     * Ok we must queue the chunk into the reasembly portion:
     *  o if its the first it goes to the control mbuf.
     *  o if its not first but the next in sequence it goes to the control,
     *    and each succeeding one in order also goes.
     *  o if its not in order we place it on the list in its place.
     */
    if (*chk).rec.data.rcv_flags as libc::c_int & 0x2i32 != 0 {
        /* Its the very first one. */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"chunk is a first fsn: %u becomes fsn_included\n\x00" as *const u8
                        as *const libc::c_char,
                    (*chk).rec.data.fsn,
                );
            }
        }
        if (*control).first_frag_seen != 0 {
            /*
             * Error on senders part, they either
             * sent us two data chunks with FIRST,
             * or they sent two un-ordered chunks that
             * were fragmented at the same time in the same stream.
             */
            sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0x8i32);
            return;
        }
        (*control).first_frag_seen = 1u8;
        (*control).sinfo_ppid = (*chk).rec.data.ppid;
        (*control).sinfo_tsn = (*chk).rec.data.tsn;
        (*control).fsn_included = (*chk).rec.data.fsn;
        (*control).data = (*chk).data;
        sctp_mark_non_revokable(asoc, (*chk).rec.data.tsn);
        (*chk).data = 0 as *mut mbuf;
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
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        }
        sctp_setup_tail_pointer(control);
        (*asoc).size_on_all_streams = (*asoc).size_on_all_streams.wrapping_add((*control).length)
    } else {
        let mut inserted = 0i32;
        if (*control).last_frag_seen as libc::c_int == 0i32 {
            /* Still willing to raise highest FSN seen */
            if (*chk).rec.data.fsn < (*control).top_fsn
                && (*control).top_fsn.wrapping_sub((*chk).rec.data.fsn) > (1u32) << 31i32
                || (*chk).rec.data.fsn > (*control).top_fsn
                    && (*chk).rec.data.fsn.wrapping_sub((*control).top_fsn) < (1u32) << 31i32
            {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"We have a new top_fsn: %u\n\x00" as *const u8 as *const libc::c_char,
                            (*chk).rec.data.fsn,
                        );
                    }
                }
                (*control).top_fsn = (*chk).rec.data.fsn
            }
            if (*chk).rec.data.rcv_flags as libc::c_int & 0x1i32 != 0 {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"The last fsn is now in place fsn: %u\n\x00" as *const u8
                                as *const libc::c_char,
                            (*chk).rec.data.fsn,
                        );
                    }
                }
                (*control).last_frag_seen = 1u8;
                if (*control).top_fsn < (*chk).rec.data.fsn
                    && (*chk).rec.data.fsn.wrapping_sub((*control).top_fsn) > (1u32) << 31i32
                    || (*control).top_fsn > (*chk).rec.data.fsn
                        && (*control).top_fsn.wrapping_sub((*chk).rec.data.fsn) < (1u32) << 31i32
                {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"New fsn: %u is not at top_fsn: %u -- abort\n\x00" as *const u8
                                    as *const libc::c_char,
                                (*chk).rec.data.fsn,
                                (*control).top_fsn,
                            );
                        }
                    }
                    sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0x9i32);
                    return;
                }
            }
            if (*asoc).idata_supported as libc::c_int != 0
                || (*control).first_frag_seen as libc::c_int != 0
            {
                /*
                 * For IDATA we always check since we know that
                 * the first fragment is 0. For old DATA we have
                 * to receive the first before we know the first FSN
                 * (which is the TSN).
                 */
                if (*control).fsn_included < (*chk).rec.data.fsn
                    && (*chk).rec.data.fsn.wrapping_sub((*control).fsn_included) > (1u32) << 31i32
                    || (*control).fsn_included > (*chk).rec.data.fsn
                        && (*control).fsn_included.wrapping_sub((*chk).rec.data.fsn)
                            < (1u32) << 31i32
                    || (*control).fsn_included == (*chk).rec.data.fsn
                {
                    /* We have already delivered up to this so its a dup */
                    sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0xai32);
                    return;
                }
            }
        } else {
            if (*chk).rec.data.rcv_flags as libc::c_int & 0x1i32 != 0 {
                /* Second last? huh? */
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Duplicate last fsn: %u (top: %u) -- abort\n\x00" as *const u8
                                as *const libc::c_char,
                            (*chk).rec.data.fsn,
                            (*control).top_fsn,
                        );
                    }
                }
                sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0xbi32);
                return;
            }
            if (*asoc).idata_supported as libc::c_int != 0
                || (*control).first_frag_seen as libc::c_int != 0
            {
                /*
                 * For IDATA we always check since we know that
                 * the first fragment is 0. For old DATA we have
                 * to receive the first before we know the first FSN
                 * (which is the TSN).
                 */
                if (*control).fsn_included < (*chk).rec.data.fsn
                    && (*chk).rec.data.fsn.wrapping_sub((*control).fsn_included) > (1u32) << 31i32
                    || (*control).fsn_included > (*chk).rec.data.fsn
                        && (*control).fsn_included.wrapping_sub((*chk).rec.data.fsn)
                            < (1u32) << 31i32
                    || (*control).fsn_included == (*chk).rec.data.fsn
                {
                    /* We have already delivered up to this so its a dup */
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"New fsn: %u is already seen in included_fsn: %u -- abort\n\x00"
                                    as *const u8
                                    as *const libc::c_char,
                                (*chk).rec.data.fsn,
                                (*control).fsn_included,
                            );
                        }
                    }
                    sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0xci32);
                    return;
                }
            }
            /* validate not beyond top FSN if we have seen last one */
            if (*chk).rec.data.fsn < (*control).top_fsn
                && (*control).top_fsn.wrapping_sub((*chk).rec.data.fsn) > (1u32) << 31i32
                || (*chk).rec.data.fsn > (*control).top_fsn
                    && (*chk).rec.data.fsn.wrapping_sub((*control).top_fsn) < (1u32) << 31i32
            {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"New fsn: %u is beyond or at top_fsn: %u -- abort\n\x00" as *const u8
                                as *const libc::c_char,
                            (*chk).rec.data.fsn,
                            (*control).top_fsn,
                        );
                    }
                }
                sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0xdi32);
                return;
            }
        }
        /*
         * If we reach here, we need to place the
         * new chunk in the reassembly for this
         * control.
         */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"chunk is a not first fsn: %u needs to be inserted\n\x00" as *const u8
                        as *const libc::c_char,
                    (*chk).rec.data.fsn,
                );
            }
        }
        at = (*control).reasm.tqh_first;
        while !at.is_null() {
            if (*at).rec.data.fsn < (*chk).rec.data.fsn
                && (*chk).rec.data.fsn.wrapping_sub((*at).rec.data.fsn) > (1u32) << 31i32
                || (*at).rec.data.fsn > (*chk).rec.data.fsn
                    && (*at).rec.data.fsn.wrapping_sub((*chk).rec.data.fsn) < (1u32) << 31i32
            {
                /*
                 * This one in queue is bigger than the new one, insert
                 * the new one before at.
                 */
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Insert it before fsn: %u\n\x00" as *const u8 as *const libc::c_char,
                            (*at).rec.data.fsn,
                        );
                    }
                }
                (*asoc).size_on_reasm_queue = (*asoc)
                    .size_on_reasm_queue
                    .wrapping_add((*chk).send_size as libc::c_uint);
                (*asoc).cnt_on_reasm_queue = (*asoc).cnt_on_reasm_queue.wrapping_add(1);
                (*chk).sctp_next.tqe_prev = (*at).sctp_next.tqe_prev;
                (*chk).sctp_next.tqe_next = at;
                *(*at).sctp_next.tqe_prev = chk;
                (*at).sctp_next.tqe_prev = &mut (*chk).sctp_next.tqe_next;
                inserted = 1i32;
                break;
            } else {
                if (*at).rec.data.fsn == (*chk).rec.data.fsn {
                    /* Gak, He sent me a duplicate str seq number */
                    /*
                     * foo bar, I guess I will just free this new guy,
                     * should we abort too? FIX ME MAYBE? Or it COULD be
                     * that the SSN's have wrapped. Maybe I should
                     * compare to TSN somehow... sigh for now just blow
                     * away the chunk!
                     */
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"Duplicate to fsn: %u -- abort\n\x00" as *const u8
                                    as *const libc::c_char,
                                (*at).rec.data.fsn,
                            );
                        }
                    }
                    sctp_abort_in_reasm(stcb, control, chk, abort_flag, 0x30000000i32 + 0xei32);
                    return;
                }
                at = (*at).sctp_next.tqe_next
            }
        }
        if inserted == 0i32 {
            /* Goes on the end */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Inserting at tail of list fsn: %u\n\x00" as *const u8
                            as *const libc::c_char,
                        (*chk).rec.data.fsn,
                    );
                }
            }
            (*asoc).size_on_reasm_queue = (*asoc)
                .size_on_reasm_queue
                .wrapping_add((*chk).send_size as libc::c_uint);
            (*asoc).cnt_on_reasm_queue = (*asoc).cnt_on_reasm_queue.wrapping_add(1);
            (*chk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
            (*chk).sctp_next.tqe_prev = (*control).reasm.tqh_last;
            *(*control).reasm.tqh_last = chk;
            (*control).reasm.tqh_last = &mut (*chk).sctp_next.tqe_next
        }
    }
    /*
     * Ok lets see if we can suck any up into the control
     * structure that are in seq if it makes sense.
     */
    do_wakeup = 0i32;
    /*
     * If the first fragment has not been
     * seen there is no sense in looking.
     */
    if (*control).first_frag_seen != 0 {
        let mut next_fsn = 0;
        let mut nat = 0 as *mut sctp_tmit_chunk;
        next_fsn = (*control).fsn_included.wrapping_add(1u32);
        at = (*control).reasm.tqh_first;
        while !at.is_null() && {
            nat = (*at).sctp_next.tqe_next;
            (1i32) != 0
        } {
            let mut lenadded = 0;
            if !((*at).rec.data.fsn == next_fsn) {
                break;
            }
            /* We can add this one now to the control */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Adding more to control: %p at: %p fsn: %u next_fsn: %u included: %u\n\x00"
                            as *const u8 as *const libc::c_char,
                        control,
                        at,
                        (*at).rec.data.fsn,
                        next_fsn,
                        (*control).fsn_included,
                    );
                }
            }
            if !(*at).sctp_next.tqe_next.is_null() {
                (*(*at).sctp_next.tqe_next).sctp_next.tqe_prev = (*at).sctp_next.tqe_prev
            } else {
                (*control).reasm.tqh_last = (*at).sctp_next.tqe_prev
            }
            *(*at).sctp_next.tqe_prev = (*at).sctp_next.tqe_next;
            lenadded = sctp_add_chk_to_control(control, strm, stcb, asoc, at, 0i32);
            if (*control).on_read_q != 0 {
                do_wakeup = 1i32
            } else {
                /*
                 * We only add to the size-on-all-streams
                 * if its not on the read q. The read q
                 * flag will cause a sballoc so its accounted
                 * for there.
                 */
                (*asoc).size_on_all_streams = (*asoc).size_on_all_streams.wrapping_add(lenadded)
            }
            next_fsn = next_fsn.wrapping_add(1);
            if (*control).end_added as libc::c_int != 0
                && (*control).pdapi_started as libc::c_int != 0
            {
                if (*strm).pd_api_started != 0 {
                    (*strm).pd_api_started = 0u8;
                    (*control).pdapi_started = 0u8
                }
                if (*control).on_read_q as libc::c_int == 0i32 {
                    sctp_add_to_readq(
                        (*stcb).sctp_ep,
                        stcb,
                        control,
                        &mut (*(*stcb).sctp_socket).so_rcv,
                        (*control).end_added as libc::c_int,
                        0i32,
                        0i32,
                    );
                }
                break;
            } else {
                at = nat
            }
        }
    }
    if do_wakeup != 0 {
        sctp_invoke_recv_callback((*stcb).sctp_ep, stcb, control, 0i32);
        /* Need to wakeup the reader */
        sctp_wakeup_the_read_socket((*stcb).sctp_ep, stcb, 0i32); /* make gcc happy */
    };
}
unsafe extern "C" fn sctp_find_reasm_entry(
    mut strm: *mut sctp_stream_in,
    mut mid: uint32_t,
    mut ordered: libc::c_int,
    mut idata_supported: libc::c_int,
) -> *mut sctp_queued_to_read {
    let mut control = 0 as *mut sctp_queued_to_read;
    if ordered != 0 {
        control = (*strm).inqueue.tqh_first;
        while !control.is_null() {
            if if idata_supported == 1i32 {
                ((*control).mid == mid) as libc::c_int
            } else {
                ((*control).mid as uint16_t as libc::c_int == mid as uint16_t as libc::c_int)
                    as libc::c_int
            } != 0
            {
                break;
            }
            control = (*control).next_instrm.tqe_next
        }
    } else if idata_supported != 0 {
        control = (*strm).uno_inqueue.tqh_first;
        while !control.is_null() {
            if if idata_supported == 1i32 {
                ((*control).mid == mid) as libc::c_int
            } else {
                ((*control).mid as uint16_t as libc::c_int == mid as uint16_t as libc::c_int)
                    as libc::c_int
            } != 0
            {
                break;
            }
            control = (*control).next_instrm.tqe_next
        }
    } else {
        control = (*strm).uno_inqueue.tqh_first
    }
    return control;
}
unsafe extern "C" fn sctp_process_a_data_chunk(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut m: *mut *mut mbuf,
    mut offset: libc::c_int,
    mut chk_length: libc::c_int,
    mut net: *mut sctp_nets,
    mut high_tsn: *mut uint32_t,
    mut abort_flag: *mut libc::c_int,
    mut break_flag: *mut libc::c_int,
    mut last_chunk: libc::c_int,
    mut chk_type: uint8_t,
) -> libc::c_int {
    let mut tsn = 0;
    let mut fsn = 0;
    let mut gap = 0;
    let mut mid = 0;
    let mut sid = 0;
    let mut op_err = 0 as *mut mbuf;
    let mut msg = [0; 128];
    let mut ppid = 0;
    let mut chk_flags = 0;
    let mut ordered = 0;
    let mut clen = 0;
    if chk_type as libc::c_int == 0x40i32 {
        let mut chunk = 0 as *mut sctp_idata_chunk;
        let mut chunk_buf = sctp_idata_chunk {
            ch: sctp_chunkhdr {
                chunk_type: 0,
                chunk_flags: 0,
                chunk_length: 0,
            },
            dp: sctp_idata {
                tsn: 0,
                sid: 0,
                reserved: 0,
                mid: 0,
                ppid_fsn: C2RustUnnamed_324 { ppid: 0 },
            },
        };
        chunk = sctp_m_getptr(
            *m,
            offset,
            ::std::mem::size_of::<sctp_idata_chunk>() as libc::c_int,
            &mut chunk_buf as *mut sctp_idata_chunk as *mut uint8_t,
        ) as *mut sctp_idata_chunk;
        chk_flags = (*chunk).ch.chunk_flags;
        clen = ::std::mem::size_of::<sctp_idata_chunk>() as libc::c_ulong;
        tsn = ntohl((*chunk).dp.tsn);
        sid = ntohs((*chunk).dp.sid);
        mid = ntohl((*chunk).dp.mid);
        if chk_flags as libc::c_int & 0x2i32 != 0 {
            fsn = 0u32;
            ppid = (*chunk).dp.ppid_fsn.ppid
        } else {
            fsn = ntohl((*chunk).dp.ppid_fsn.fsn);
            ppid = 0xffffffffu32
            /* Use as an invalid value. */
        }
    } else {
        let mut chunk_0 = 0 as *mut sctp_data_chunk;
        let mut chunk_buf_0 = sctp_data_chunk {
            ch: sctp_chunkhdr {
                chunk_type: 0,
                chunk_flags: 0,
                chunk_length: 0,
            },
            dp: sctp_data {
                tsn: 0,
                sid: 0,
                ssn: 0,
                ppid: 0,
            },
        };
        chunk_0 = sctp_m_getptr(
            *m,
            offset,
            ::std::mem::size_of::<sctp_data_chunk>() as libc::c_int,
            &mut chunk_buf_0 as *mut sctp_data_chunk as *mut uint8_t,
        ) as *mut sctp_data_chunk;
        chk_flags = (*chunk_0).ch.chunk_flags;
        clen = ::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong;
        tsn = ntohl((*chunk_0).dp.tsn);
        sid = ntohs((*chunk_0).dp.sid);
        mid = ntohs((*chunk_0).dp.ssn) as uint32_t;
        fsn = tsn;
        ppid = (*chunk_0).dp.ppid
    }
    if chk_length as size_t == clen {
        /*
         * Need to send an abort since we had a
         * empty data chunk.
         */
        op_err = sctp_generate_no_user_data_cause(tsn);
        (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0xei32) as uint32_t;
        sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
        *abort_flag = 1i32;
        return 0i32;
    }
    if chk_flags as libc::c_int & 0x8i32 == 0x8i32 {
        (*asoc).send_sack = 1u8
    }
    ordered = (chk_flags as libc::c_int & 0x4i32 == 0i32) as libc::c_int;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x100u32 != 0 {
        sctp_log_map(
            tsn,
            (*asoc).cumulative_tsn,
            (*asoc).highest_tsn_inside_map,
            119i32,
        );
    }
    if stcb.is_null() {
        return 0i32;
    }
    if (*asoc).cumulative_tsn < tsn && tsn.wrapping_sub((*asoc).cumulative_tsn) > (1u32) << 31i32
        || (*asoc).cumulative_tsn > tsn
            && (*asoc).cumulative_tsn.wrapping_sub(tsn) < (1u32) << 31i32
        || (*asoc).cumulative_tsn == tsn
    {
        /* It is a duplicate */
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvdupdata, 1u32);
        if (*asoc).numduptsns < 20u32 {
            /* Record a dup for the next outbound sack */
            (*asoc).dup_tsns[(*asoc).numduptsns as usize] = tsn as libc::c_int;
            (*asoc).numduptsns = (*asoc).numduptsns.wrapping_add(1)
        }
        (*asoc).send_sack = 1u8;
        return 0i32;
    }
    /* Calculate the number of TSN's between the base and this TSN */
    if tsn >= (*asoc).mapping_array_base_tsn {
        gap = tsn.wrapping_sub((*asoc).mapping_array_base_tsn)
    } else {
        gap = (0xffffffffu32)
            .wrapping_sub((*asoc).mapping_array_base_tsn)
            .wrapping_add(tsn)
            .wrapping_add(1u32)
    }
    if gap >= ((512i32) << 3i32) as libc::c_uint {
        /* Can't hold the bit in the mapping at max array, toss it */
        return 0i32;
    }
    if gap >= (((*asoc).mapping_array_size as libc::c_int) << 3i32) as uint32_t {
        if sctp_expand_mapping_array(asoc, gap) != 0 {
            /* Can't expand, drop it */
            return 0i32;
        }
    }
    if tsn < *high_tsn && (*high_tsn).wrapping_sub(tsn) > (1u32) << 31i32
        || tsn > *high_tsn && tsn.wrapping_sub(*high_tsn) < (1u32) << 31i32
    {
        *high_tsn = tsn
    }
    /* See if we have received this one already */
    if *(*asoc).mapping_array.offset((gap >> 3i32) as isize) as libc::c_int >> (gap & 0x7u32)
        & 0x1i32
        != 0
        || *(*asoc).nr_mapping_array.offset((gap >> 3i32) as isize) as libc::c_int >> (gap & 0x7u32)
            & 0x1i32
            != 0
    {
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvdupdata, 1u32);
        if (*asoc).numduptsns < 20u32 {
            /* Record a dup for the next outbound sack */
            (*asoc).dup_tsns[(*asoc).numduptsns as usize] = tsn as libc::c_int;
            (*asoc).numduptsns = (*asoc).numduptsns.wrapping_add(1)
        }
        (*asoc).send_sack = 1u8;
        return 0i32;
    }
    /*
     * Check to see about the GONE flag, duplicates would cause a sack
     * to be sent up above
     */
    if (*(*stcb).sctp_ep).sctp_flags & 0x10000000u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0
        || (*stcb).asoc.state & 0x100i32 != 0
    {
        /*
         * wait a minute, this guy is gone, there is no longer a
         * receiver. Send peer an ABORT!
         */
        op_err = sctp_generate_cause(0x4u16, b"\x00" as *const u8 as *mut libc::c_char);
        sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
        *abort_flag = 1i32;
        return 0i32;
    }
    /*
     * Now before going further we see if there is room. If NOT then we
     * MAY let one through only IF this TSN is the one we are waiting
     * for on a partial delivery API.
     */
    /* Is the stream valid? */
    if sid as libc::c_int >= (*asoc).streamincnt as libc::c_int {
        op_err = sctp_get_mbuf_for_msg(
            ::std::mem::size_of::<sctp_error_invalid_stream>() as libc::c_uint,
            0i32,
            0x1i32,
            1i32,
            1i32,
        );
        if !op_err.is_null() {
            let mut cause = 0 as *mut sctp_error_invalid_stream;
            (*op_err).m_hdr.mh_data = (*op_err)
                .m_hdr
                .mh_data
                .offset(::std::mem::size_of::<sctp_chunkhdr>() as isize);
            cause = (*op_err).m_hdr.mh_data as *mut sctp_error_invalid_stream;
            /*
             * Error causes are just param's and this one has
             * two back to back phdr, one with the error type
             * and size, the other with the streamid and a rsvd
             */
            (*op_err).m_hdr.mh_len =
                ::std::mem::size_of::<sctp_error_invalid_stream>() as libc::c_int;
            (*cause).cause.code = htons(0x1u16);
            (*cause).cause.length =
                htons(::std::mem::size_of::<sctp_error_invalid_stream>() as uint16_t);
            (*cause).stream_id = htons(sid);
            (*cause).reserved = htons(0u16);
            sctp_queue_op_err(stcb, op_err);
        }
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_badsid, 1u32);
        let ref mut fresh2 = *(*asoc).nr_mapping_array.offset((gap >> 3i32) as isize);
        *fresh2 = (*fresh2 as libc::c_int | (0x1i32) << (gap & 0x7u32)) as uint8_t;
        if tsn < (*asoc).highest_tsn_inside_nr_map
            && (*asoc).highest_tsn_inside_nr_map.wrapping_sub(tsn) > (1u32) << 31i32
            || tsn > (*asoc).highest_tsn_inside_nr_map
                && tsn.wrapping_sub((*asoc).highest_tsn_inside_nr_map) < (1u32) << 31i32
        {
            (*asoc).highest_tsn_inside_nr_map = tsn
        }
        if tsn == (*asoc).cumulative_tsn.wrapping_add(1u32) {
            /* Update cum-ack */
            (*asoc).cumulative_tsn = tsn
        }
        return 0i32;
    }
    /*
     * If its a fragmented message, lets see if we can
     * find the control on the reassembly queues.
     */
    if chk_type as libc::c_int == 0x40i32
        && chk_flags as libc::c_int & 0x2i32 == 0i32
        && fsn == 0u32
    {
        /*
         *  The first *must* be fsn 0, and other
         *  (middle/end) pieces can *not* be fsn 0.
         * XXX: This can happen in case of a wrap around.
         *      Ignore is for now.
         */
        snprintf(
            msg.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            b"FSN zero for MID=%8.8x, but flags=%2.2x\x00" as *const u8 as *const libc::c_char,
            mid,
            chk_flags as libc::c_int,
        );
    } else {
        let mut current_block: u64;
        let mut control = 0 as *mut sctp_queued_to_read;
        control = sctp_find_reasm_entry(
            &mut *(*asoc).strmin.offset(sid as isize),
            mid,
            ordered,
            (*asoc).idata_supported as libc::c_int,
        );
        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"chunk_flags:0x%x look for control on queues %p\n\x00" as *const u8
                        as *const libc::c_char,
                    chk_flags as libc::c_int,
                    control,
                );
            }
        }
        if chk_flags as libc::c_int & 0x3i32 != 0x3i32 {
            /* See if we can find the re-assembly entity */
            if !control.is_null() {
                /* We found something, does it belong? */
                if ordered != 0 && mid != (*control).mid {
                    snprintf(
                        msg.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                        b"Reassembly problem (MID=%8.8x)\x00" as *const u8 as *const libc::c_char,
                        mid,
                    );
                    current_block = 5809864161283831096;
                } else if ordered != 0
                    && (*control).sinfo_flags as libc::c_int >> 8i32 & 0x4i32 != 0
                {
                    /* We can't have a switched order with an unordered chunk */
                    snprintf(msg.as_mut_ptr(),
                             ::std::mem::size_of::<[libc::c_char; 128]>() as
                                 libc::c_ulong,
                             b"All fragments of a user message must be ordered or unordered (TSN=%8.8x)\x00"
                                 as *const u8 as *const libc::c_char, tsn);
                    current_block = 5809864161283831096;
                } else if ordered == 0
                    && (*control).sinfo_flags as libc::c_int >> 8i32 & 0x4i32 == 0i32
                {
                    /* We can't have a switched unordered with a ordered chunk */
                    snprintf(msg.as_mut_ptr(),
                             ::std::mem::size_of::<[libc::c_char; 128]>() as
                                 libc::c_ulong,
                             b"All fragments of a user message must be ordered or unordered (TSN=%8.8x)\x00"
                                 as *const u8 as *const libc::c_char, tsn);
                    current_block = 5809864161283831096;
                } else {
                    current_block = 5832582820025303349;
                }
            } else {
                current_block = 5832582820025303349;
            }
        } else if !control.is_null() {
            if ordered != 0 || (*asoc).idata_supported as libc::c_int != 0 {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"chunk_flags: 0x%x dup detected on MID: %u\n\x00" as *const u8
                                as *const libc::c_char,
                            chk_flags as libc::c_int,
                            mid,
                        );
                    }
                }
                snprintf(
                    msg.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    b"Duplicate MID=%8.8x detected.\x00" as *const u8 as *const libc::c_char,
                    mid,
                );
                current_block = 5809864161283831096;
            } else if tsn == (*control).fsn_included.wrapping_add(1u32)
                && (*control).end_added as libc::c_int == 0i32
            {
                snprintf(
                    msg.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    b"Illegal message sequence, missing end for MID: %8.8x\x00" as *const u8
                        as *const libc::c_char,
                    (*control).fsn_included,
                );
                current_block = 5809864161283831096;
            } else {
                control = 0 as *mut sctp_queued_to_read;
                current_block = 5832582820025303349;
            }
        } else {
            current_block = 5832582820025303349;
        }
        match current_block {
            5809864161283831096 => {}
            _ =>
            /* Its a complete segment. Lets validate we
             * don't have a re-assembly going on with
             * the same Stream/Seq (for ordered) or in
             * the same Stream for unordered.
             */
            /* now do the tests */
            {
                let mut dmbuf = 0 as *mut mbuf;
                let mut the_len = 0;
                let mut need_reasm_check = 0i32;
                let mut liste = 0 as *mut sctp_stream_reset_list;
                let mut created_control = 0i32;
                if (*asoc)
                    .cnt_on_all_streams
                    .wrapping_add((*asoc).cnt_on_reasm_queue)
                    .wrapping_add((*asoc).cnt_msg_on_sb)
                    >= system_base_info.sctpsysctl.sctp_max_chunks_on_queue
                    || (*asoc).my_rwnd as libc::c_int <= 0i32
                {
                    /*
                     * When we have NO room in the rwnd we check to make sure
                     * the reader is doing its job...
                     */
                    if (*(*stcb).sctp_socket).so_rcv.sb_cc != 0 {
                        /* some to read, wake-up */
                        if (*(*stcb).sctp_ep).sctp_flags & 0x800000u32 != 0 {
                            (*(*stcb).sctp_ep).sctp_flags |= 0x2000000u32
                        } else {
                            pthread_mutex_lock(&mut (*(*stcb).sctp_socket).so_rcv.sb_mtx);
                            if (*(*stcb).sctp_socket).so_rcv.sb_flags as libc::c_int
                                & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                                != 0i32
                            {
                                sowakeup((*stcb).sctp_socket, &mut (*(*stcb).sctp_socket).so_rcv);
                            } else {
                                pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_rcv.sb_mtx);
                            }
                        }
                    }
                    /* now is it in the mapping array of what we have accepted? */
                    if chk_type as libc::c_int == 0i32 {
                        if (tsn < (*asoc).highest_tsn_inside_map
                            && (*asoc).highest_tsn_inside_map.wrapping_sub(tsn) > (1u32) << 31i32
                            || tsn > (*asoc).highest_tsn_inside_map
                                && tsn.wrapping_sub((*asoc).highest_tsn_inside_map)
                                    < (1u32) << 31i32)
                            && (tsn < (*asoc).highest_tsn_inside_nr_map
                                && (*asoc).highest_tsn_inside_nr_map.wrapping_sub(tsn)
                                    > (1u32) << 31i32
                                || tsn > (*asoc).highest_tsn_inside_nr_map
                                    && tsn.wrapping_sub((*asoc).highest_tsn_inside_nr_map)
                                        < (1u32) << 31i32)
                        {
                            current_block = 13234003882380184839;
                        } else {
                            current_block = 1176253869785344635;
                        }
                    } else if control.is_null() {
                        current_block = 13234003882380184839;
                    } else if fsn < (*control).top_fsn
                        && (*control).top_fsn.wrapping_sub(fsn) > (1u32) << 31i32
                        || fsn > (*control).top_fsn
                            && fsn.wrapping_sub((*control).top_fsn) < (1u32) << 31i32
                    {
                        current_block = 13234003882380184839;
                    } else {
                        current_block = 1176253869785344635;
                    }
                    match current_block {
                        1176253869785344635 => {}
                        _ =>
                        /* Nope not in the valid range dump it */
                        {
                            sctp_set_rwnd(stcb, asoc);
                            if (*asoc)
                                .cnt_on_all_streams
                                .wrapping_add((*asoc).cnt_on_reasm_queue)
                                .wrapping_add((*asoc).cnt_msg_on_sb)
                                >= system_base_info.sctpsysctl.sctp_max_chunks_on_queue
                            {
                                ::std::intrinsics::atomic_xadd(
                                    &mut system_base_info.sctpstat.sctps_datadropchklmt,
                                    1u32,
                                );
                            } else {
                                ::std::intrinsics::atomic_xadd(
                                    &mut system_base_info.sctpstat.sctps_datadroprwnd,
                                    1u32,
                                );
                            }
                            *break_flag = 1i32;
                            return 0i32;
                        }
                    }
                }
                /*
                 * Before we continue lets validate that we are not being fooled by
                 * an evil attacker. We can only have Nk chunks based on our TSN
                 * spread allowed by the mapping array N * 8 bits, so there is no
                 * way our stream sequence numbers could have wrapped. We of course
                 * only validate the FIRST fragment so the bit must be set.
                 */
                if chk_flags as libc::c_int & 0x2i32 != 0
                    && (*asoc).resetHead.tqh_first.is_null()
                    && chk_flags as libc::c_int & 0x4i32 == 0i32
                    && (if (*asoc).idata_supported as libc::c_int == 1i32 {
                        ((*(*asoc).strmin.offset(sid as isize)).last_mid_delivered < mid
                            && mid.wrapping_sub(
                                (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered,
                            ) > (1u32) << 31i32
                            || (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered > mid
                                && (*(*asoc).strmin.offset(sid as isize))
                                    .last_mid_delivered
                                    .wrapping_sub(mid)
                                    < (1u32) << 31i32
                            || (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered == mid)
                            as libc::c_int
                    } else {
                        (((*(*asoc).strmin.offset(sid as isize)).last_mid_delivered as uint16_t
                            as libc::c_int)
                            < mid as uint16_t as libc::c_int
                            && (mid as uint16_t as libc::c_int
                                - (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered
                                    as uint16_t as libc::c_int)
                                as uint16_t as libc::c_uint
                                > (1u32) << 15i32
                            || (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered as uint16_t
                                as libc::c_int
                                > mid as uint16_t as libc::c_int
                                && (((*(*asoc).strmin.offset(sid as isize)).last_mid_delivered
                                    as uint16_t as libc::c_int
                                    - mid as uint16_t as libc::c_int)
                                    as uint16_t
                                    as libc::c_uint)
                                    < (1u32) << 15i32
                            || (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered as uint16_t
                                as libc::c_int
                                == mid as uint16_t as libc::c_int)
                            as libc::c_int
                    }) != 0
                {
                    /* The incoming sseq is behind where we last delivered? */
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x1000000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"EVIL/Broken-Dup S-SEQ: %u delivered: %u from peer, Abort!\n\x00"
                                    as *const u8
                                    as *const libc::c_char,
                                mid,
                                (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered,
                            );
                        }
                    }
                    if (*asoc).idata_supported != 0 {
                        snprintf(
                            msg.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                            b"Delivered MID=%8.8x, got TSN=%8.8x, SID=%4.4x, MID=%8.8x\x00"
                                as *const u8 as *const libc::c_char,
                            (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered,
                            tsn,
                            sid as libc::c_int,
                            mid,
                        );
                    } else {
                        snprintf(
                            msg.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                            b"Delivered SSN=%4.4x, got TSN=%8.8x, SID=%4.4x, SSN=%4.4x\x00"
                                as *const u8 as *const libc::c_char,
                            (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered as uint16_t
                                as libc::c_int,
                            tsn,
                            sid as libc::c_int,
                            mid as uint16_t as libc::c_int,
                        );
                    }
                    op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
                    (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x10i32) as uint32_t;
                    sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
                    *abort_flag = 1i32;
                    return 0i32;
                }
                if chk_type as libc::c_int == 0x40i32 {
                    the_len = (chk_length as libc::c_ulong)
                        .wrapping_sub(::std::mem::size_of::<sctp_idata_chunk>() as libc::c_ulong)
                        as libc::c_int
                } else {
                    the_len = (chk_length as libc::c_ulong)
                        .wrapping_sub(::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong)
                        as libc::c_int
                }
                if last_chunk == 0i32 {
                    if chk_type as libc::c_int == 0x40i32 {
                        dmbuf = m_copym(
                            *m,
                            (offset as libc::c_ulong)
                                .wrapping_add(
                                    ::std::mem::size_of::<sctp_idata_chunk>() as libc::c_ulong
                                ) as libc::c_int,
                            the_len,
                            0x1i32,
                        )
                    } else {
                        dmbuf = m_copym(
                            *m,
                            (offset as libc::c_ulong)
                                .wrapping_add(
                                    ::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong
                                ) as libc::c_int,
                            the_len,
                            0x1i32,
                        )
                    }
                } else {
                    let mut l_len = 0;
                    dmbuf = *m;
                    /* lop off the top part */
                    if chk_type as libc::c_int == 0x40i32 {
                        m_adj(
                            dmbuf,
                            (offset as libc::c_ulong)
                                .wrapping_add(
                                    ::std::mem::size_of::<sctp_idata_chunk>() as libc::c_ulong
                                ) as libc::c_int,
                        );
                    } else {
                        m_adj(
                            dmbuf,
                            (offset as libc::c_ulong)
                                .wrapping_add(
                                    ::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong
                                ) as libc::c_int,
                        );
                    }
                    if (*dmbuf).m_hdr.mh_next.is_null() {
                        l_len = (*dmbuf).m_hdr.mh_len
                    } else {
                        let mut lat = 0 as *mut mbuf;
                        l_len = 0i32;
                        lat = dmbuf;
                        while !lat.is_null() {
                            l_len += (*lat).m_hdr.mh_len;
                            lat = (*lat).m_hdr.mh_next
                        }
                    }
                    if l_len > the_len {
                        /* Trim the end round bytes off  too */
                        m_adj(dmbuf, -(l_len - the_len));
                    }
                }
                if dmbuf.is_null() {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_nomem,
                        1u32,
                    );
                    return 0i32;
                }
                /*
                 * Now no matter what, we need a control, get one
                 * if we don't have one (we may have gotten it
                 * above when we found the message was fragmented
                 */
                if control.is_null() {
                    control = malloc(system_base_info.sctppcbinfo.ipi_zone_readq)
                        as *mut sctp_queued_to_read;
                    if !control.is_null() {
                        ::std::intrinsics::atomic_xadd(
                            &mut system_base_info.sctppcbinfo.ipi_count_readq,
                            1u32,
                        );
                    }
                    if !control.is_null() {
                        ::std::intrinsics::atomic_xadd(&mut (*net).ref_count, 1i32);
                        memset(
                            control as *mut libc::c_void,
                            0i32,
                            ::std::mem::size_of::<sctp_queued_to_read>() as libc::c_ulong,
                        );
                        (*control).sinfo_stream = sid;
                        (*control).reasm.tqh_first = 0 as *mut sctp_tmit_chunk;
                        (*control).reasm.tqh_last = &mut (*control).reasm.tqh_first;
                        (*control).top_fsn = fsn;
                        (*control).mid = mid;
                        (*control).sinfo_flags = ((chk_flags as libc::c_int) << 8i32) as uint16_t;
                        (*control).sinfo_ppid = ppid;
                        (*control).sinfo_context = (*asoc).context;
                        (*control).fsn_included = 0xffffffffu32;
                        (*control).sinfo_tsn = tsn;
                        (*control).sinfo_cumtsn = tsn;
                        (*control).sinfo_assoc_id = (*stcb).asoc.assoc_id;
                        (*control).whoFrom = net;
                        (*control).data = 0 as *mut mbuf;
                        (*control).stcb = stcb;
                        (*control).port_from = (*stcb).rport
                    }
                    if control.is_null() {
                        ::std::intrinsics::atomic_xadd(
                            &mut system_base_info.sctpstat.sctps_nomem,
                            1u32,
                        );
                        return 0i32;
                    }
                    if chk_flags as libc::c_int & 0x3i32 == 0x3i32 {
                        let mut mm = 0 as *mut mbuf;
                        (*control).data = dmbuf;
                        (*control).tail_mbuf = 0 as *mut mbuf;
                        mm = (*control).data;
                        while !mm.is_null() {
                            (*control).length = ((*control).length)
                                .wrapping_add((*mm).m_hdr.mh_len as libc::c_uint);
                            if (*mm).m_hdr.mh_next.is_null() {
                                (*control).tail_mbuf = mm
                            }
                            mm = (*mm).m_hdr.mh_next
                        }
                        (*control).end_added = 1u8;
                        (*control).last_frag_seen = 1u8;
                        (*control).first_frag_seen = 1u8;
                        (*control).fsn_included = fsn;
                        (*control).top_fsn = fsn
                    }
                    created_control = 1i32
                }
                if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"chunk_flags: 0x%x ordered: %d MID: %u control: %p\n\x00" as *const u8
                                as *const libc::c_char,
                            chk_flags as libc::c_int,
                            ordered,
                            mid,
                            control,
                        );
                    }
                }
                if chk_flags as libc::c_int & 0x3i32 == 0x3i32
                    && (*asoc).resetHead.tqh_first.is_null()
                    && (ordered == 0i32
                        || (if (*asoc).idata_supported as libc::c_int == 1i32 {
                            ((*(*asoc).strmin.offset(sid as isize))
                                .last_mid_delivered
                                .wrapping_add(1u32)
                                == mid) as libc::c_int
                        } else {
                            ((*(*asoc).strmin.offset(sid as isize)).last_mid_delivered as uint16_t
                                as libc::c_int
                                + 1i32
                                == mid as uint16_t as libc::c_int)
                                as libc::c_int
                        }) != 0
                            && (*(*asoc).strmin.offset(sid as isize))
                                .inqueue
                                .tqh_first
                                .is_null())
                {
                    /* Candidate for express delivery */
                    /*
                     * Its not fragmented, No PD-API is up, Nothing in the
                     * delivery queue, Its un-ordered OR ordered and the next to
                     * deliver AND nothing else is stuck on the stream queue,
                     * And there is room for it in the socket buffer. Lets just
                     * stuff it up the buffer....
                     */
                    let ref mut fresh3 = *(*asoc).nr_mapping_array.offset((gap >> 3i32) as isize);
                    *fresh3 = (*fresh3 as libc::c_int | (0x1i32) << (gap & 0x7u32)) as uint8_t;
                    if tsn < (*asoc).highest_tsn_inside_nr_map
                        && (*asoc).highest_tsn_inside_nr_map.wrapping_sub(tsn) > (1u32) << 31i32
                        || tsn > (*asoc).highest_tsn_inside_nr_map
                            && tsn.wrapping_sub((*asoc).highest_tsn_inside_nr_map) < (1u32) << 31i32
                    {
                        (*asoc).highest_tsn_inside_nr_map = tsn
                    }
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"Injecting control: %p to be read (MID: %u)\n\x00" as *const u8
                                    as *const libc::c_char,
                                control,
                                mid,
                            );
                        }
                    }
                    sctp_add_to_readq(
                        (*stcb).sctp_ep,
                        stcb,
                        control,
                        &mut (*(*stcb).sctp_socket).so_rcv,
                        1i32,
                        0i32,
                        0i32,
                    );
                    if chk_flags as libc::c_int & 0x4i32 == 0i32 {
                        /* for ordered, bump what we delivered */
                        let ref mut fresh4 =
                            (*(*asoc).strmin.offset(sid as isize)).last_mid_delivered;
                        *fresh4 = (*fresh4).wrapping_add(1)
                    }
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_recvexpress,
                        1u32,
                    );
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x20000u32 != 0 {
                        sctp_log_strm_del_alt(stcb, tsn, mid as uint16_t, sid, 16i32);
                    }
                    control = 0 as *mut sctp_queued_to_read
                } else {
                    let mut chk = 0 as *mut sctp_tmit_chunk;
                    if chk_flags as libc::c_int & 0x3i32 != 0x3i32 {
                        if (*stcb).asoc.free_chunks.tqh_first.is_null() {
                            chk = malloc(system_base_info.sctppcbinfo.ipi_zone_chunk)
                                as *mut sctp_tmit_chunk;
                            if !chk.is_null() {
                                ::std::intrinsics::atomic_xadd(
                                    &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                                    1u32,
                                );
                                (*chk).whoTo = 0 as *mut sctp_nets;
                                (*chk).holds_key_ref = 0u8
                            }
                        } else {
                            chk = (*stcb).asoc.free_chunks.tqh_first;
                            if !(*chk).sctp_next.tqe_next.is_null() {
                                (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev =
                                    (*chk).sctp_next.tqe_prev
                            } else {
                                (*stcb).asoc.free_chunks.tqh_last = (*chk).sctp_next.tqe_prev
                            }
                            *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
                            ::std::intrinsics::atomic_xsub(
                                &mut system_base_info.sctppcbinfo.ipi_free_chunks,
                                1u32,
                            );
                            (*chk).holds_key_ref = 0u8;
                            ::std::intrinsics::atomic_xadd(
                                &mut system_base_info.sctpstat.sctps_cached_chk,
                                1u32,
                            );
                            (*stcb).asoc.free_chunk_cnt =
                                (*stcb).asoc.free_chunk_cnt.wrapping_sub(1)
                        }
                        if chk.is_null() {
                            /* No memory so we drop the chunk */
                            ::std::intrinsics::atomic_xadd(
                                &mut system_base_info.sctpstat.sctps_nomem,
                                1u32,
                            );
                            if last_chunk == 0i32 {
                                /* we copied it, free the copy */
                                m_freem(dmbuf);
                            }
                            return 0i32;
                        }
                        (*chk).rec.data.tsn = tsn;
                        (*chk).no_fr_allowed = 0u8;
                        (*chk).rec.data.fsn = fsn;
                        (*chk).rec.data.mid = mid;
                        (*chk).rec.data.sid = sid;
                        (*chk).rec.data.ppid = ppid;
                        (*chk).rec.data.context = (*stcb).asoc.context;
                        (*chk).rec.data.doing_fast_retransmit = 0u8;
                        (*chk).rec.data.rcv_flags = chk_flags;
                        (*chk).asoc = asoc;
                        (*chk).send_size = the_len as uint16_t;
                        (*chk).whoTo = net;
                        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                            if system_base_info.debug_printf.is_some() {
                                system_base_info
                                    .debug_printf
                                    .expect("non-null function pointer")(
                                    b"Building ck: %p for control: %p to be read (MID: %u)\n\x00"
                                        as *const u8
                                        as *const libc::c_char,
                                    chk,
                                    control,
                                    mid,
                                );
                            }
                        }
                        ::std::intrinsics::atomic_xadd(&mut (*net).ref_count, 1i32);
                        (*chk).data = dmbuf
                    }
                    /* Set the appropriate TSN mark */
                    if system_base_info.sctpsysctl.sctp_do_drain == 0u32 {
                        let ref mut fresh5 =
                            *(*asoc).nr_mapping_array.offset((gap >> 3i32) as isize);
                        *fresh5 = (*fresh5 as libc::c_int | (0x1i32) << (gap & 0x7u32)) as uint8_t;
                        if tsn < (*asoc).highest_tsn_inside_nr_map
                            && (*asoc).highest_tsn_inside_nr_map.wrapping_sub(tsn) > (1u32) << 31i32
                            || tsn > (*asoc).highest_tsn_inside_nr_map
                                && tsn.wrapping_sub((*asoc).highest_tsn_inside_nr_map)
                                    < (1u32) << 31i32
                        {
                            (*asoc).highest_tsn_inside_nr_map = tsn
                        }
                    } else {
                        let ref mut fresh6 = *(*asoc).mapping_array.offset((gap >> 3i32) as isize);
                        *fresh6 = (*fresh6 as libc::c_int | (0x1i32) << (gap & 0x7u32)) as uint8_t;
                        if tsn < (*asoc).highest_tsn_inside_map
                            && (*asoc).highest_tsn_inside_map.wrapping_sub(tsn) > (1u32) << 31i32
                            || tsn > (*asoc).highest_tsn_inside_map
                                && tsn.wrapping_sub((*asoc).highest_tsn_inside_map)
                                    < (1u32) << 31i32
                        {
                            (*asoc).highest_tsn_inside_map = tsn
                        }
                    }
                    /* Now is it complete (i.e. not fragmented)? */
                    if chk_flags as libc::c_int & 0x3i32 == 0x3i32 {
                        /*
                         * Special check for when streams are resetting. We
                         * could be more smart about this and check the
                         * actual stream to see if it is not being reset..
                         * that way we would not create a HOLB when amongst
                         * streams being reset and those not being reset.
                         *
                         */
                        liste = (*asoc).resetHead.tqh_first;
                        if !liste.is_null()
                            && (tsn < (*liste).tsn
                                && (*liste).tsn.wrapping_sub(tsn) > (1u32) << 31i32
                                || tsn > (*liste).tsn
                                    && tsn.wrapping_sub((*liste).tsn) < (1u32) << 31i32)
                        {
                            /*
                             * yep its past where we need to reset... go
                             * ahead and queue it.
                             */
                            if (*asoc).pending_reply_queue.tqh_first.is_null() {
                                /* first one on */
                                (*control).next.tqe_next = 0 as *mut sctp_queued_to_read;
                                (*control).next.tqe_prev = (*asoc).pending_reply_queue.tqh_last;
                                *(*asoc).pending_reply_queue.tqh_last = control;
                                (*asoc).pending_reply_queue.tqh_last = &mut (*control).next.tqe_next
                            } else {
                                let mut lcontrol = 0 as *mut sctp_queued_to_read;
                                let mut nlcontrol = 0 as *mut sctp_queued_to_read;
                                let mut inserted = 0u8;
                                lcontrol = (*asoc).pending_reply_queue.tqh_first;
                                while !lcontrol.is_null() && {
                                    nlcontrol = (*lcontrol).next.tqe_next;
                                    (1i32) != 0
                                } {
                                    if (*control).sinfo_tsn < (*lcontrol).sinfo_tsn
                                        && (*lcontrol).sinfo_tsn.wrapping_sub((*control).sinfo_tsn)
                                            > (1u32) << 31i32
                                        || (*control).sinfo_tsn > (*lcontrol).sinfo_tsn
                                            && (*control)
                                                .sinfo_tsn
                                                .wrapping_sub((*lcontrol).sinfo_tsn)
                                                < (1u32) << 31i32
                                    {
                                        lcontrol = nlcontrol
                                    } else {
                                        /* found it */
                                        (*control).next.tqe_prev = (*lcontrol).next.tqe_prev;
                                        (*control).next.tqe_next = lcontrol;
                                        *(*lcontrol).next.tqe_prev = control;
                                        (*lcontrol).next.tqe_prev = &mut (*control).next.tqe_next;
                                        inserted = 1u8;
                                        break;
                                    }
                                }
                                if inserted as libc::c_int == 0i32 {
                                    /*
                                     * must be put at end, use
                                     * prevP (all setup from
                                     * loop) to setup nextP.
                                     */
                                    (*control).next.tqe_next = 0 as *mut sctp_queued_to_read;
                                    (*control).next.tqe_prev = (*asoc).pending_reply_queue.tqh_last;
                                    *(*asoc).pending_reply_queue.tqh_last = control;
                                    (*asoc).pending_reply_queue.tqh_last =
                                        &mut (*control).next.tqe_next
                                }
                            }
                        } else if chk_flags as libc::c_int & 0x4i32 != 0 {
                            /* queue directly into socket buffer */
                            if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                                if system_base_info.debug_printf.is_some() {
                                    system_base_info
                                        .debug_printf
                                        .expect("non-null function pointer")(
                                        b"Unordered data to be read control: %p MID: %u\n\x00"
                                            as *const u8
                                            as *const libc::c_char,
                                        control,
                                        mid,
                                    );
                                }
                            }
                            sctp_mark_non_revokable(asoc, (*control).sinfo_tsn);
                            sctp_add_to_readq(
                                (*stcb).sctp_ep,
                                stcb,
                                control,
                                &mut (*(*stcb).sctp_socket).so_rcv,
                                1i32,
                                0i32,
                                0i32,
                            );
                        } else {
                            if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                                if system_base_info.debug_printf.is_some() {
                                    system_base_info
                                        .debug_printf
                                        .expect("non-null function pointer")(
                                        b"Queue control: %p for reordering MID: %u\n\x00"
                                            as *const u8
                                            as *const libc::c_char,
                                        control,
                                        mid,
                                    );
                                }
                            }
                            sctp_queue_data_to_stream(
                                stcb,
                                asoc,
                                control,
                                abort_flag,
                                &mut need_reasm_check,
                            );
                            if *abort_flag != 0 {
                                if last_chunk != 0 {
                                    *m = 0 as *mut mbuf
                                }
                                return 0i32;
                            }
                        }
                    } else {
                        /* If we reach here its a reassembly */
                        need_reasm_check = 1i32;
                        if system_base_info.sctpsysctl.sctp_debug_on & 0x80000u32 != 0 {
                            if system_base_info.debug_printf.is_some() {
                                system_base_info
                                    .debug_printf
                                    .expect("non-null function pointer")(
                                    b"Queue data to stream for reasm control: %p MID: %u\n\x00"
                                        as *const u8
                                        as *const libc::c_char,
                                    control,
                                    mid,
                                );
                            }
                        }
                        sctp_queue_data_for_reasm(
                            stcb,
                            asoc,
                            control,
                            chk,
                            created_control,
                            abort_flag,
                            tsn,
                        );
                        if *abort_flag != 0 {
                            /*
                             * the assoc is now gone and chk was put onto the
                             * reasm queue, which has all been freed.
                             */
                            if last_chunk != 0 {
                                *m = 0 as *mut mbuf
                            }
                            return 0i32;
                        }
                    }
                }
                /* Here we tidy up things */
                if tsn == (*asoc).cumulative_tsn.wrapping_add(1u32) {
                    /* Update cum-ack */
                    (*asoc).cumulative_tsn = tsn
                }
                if last_chunk != 0 {
                    *m = 0 as *mut mbuf
                }
                if ordered != 0 {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_inorderchunks,
                        1u32,
                    );
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_inunorderchunks,
                        1u32,
                    );
                }
                ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvdata, 1u32);
                /* Set it present please */
                if system_base_info.sctpsysctl.sctp_logging_level & 0x20000u32 != 0 {
                    sctp_log_strm_del_alt(stcb, tsn, mid as uint16_t, sid, 15i32);
                }
                if system_base_info.sctpsysctl.sctp_logging_level & 0x100u32 != 0 {
                    sctp_log_map(
                        (*asoc).mapping_array_base_tsn,
                        (*asoc).cumulative_tsn,
                        (*asoc).highest_tsn_inside_map,
                        21i32,
                    );
                }
                if need_reasm_check != 0 {
                    sctp_deliver_reasm_check(
                        stcb,
                        asoc,
                        &mut *(*asoc).strmin.offset(sid as isize),
                        0i32,
                    );
                    need_reasm_check = 0i32
                }
                /* check the special flag for stream resets */
                liste = (*asoc).resetHead.tqh_first;
                if !liste.is_null()
                    && ((*asoc).cumulative_tsn < (*liste).tsn
                        && (*liste).tsn.wrapping_sub((*asoc).cumulative_tsn) > (1u32) << 31i32
                        || (*asoc).cumulative_tsn > (*liste).tsn
                            && (*asoc).cumulative_tsn.wrapping_sub((*liste).tsn) < (1u32) << 31i32
                        || (*asoc).cumulative_tsn == (*liste).tsn)
                {
                    let mut ncontrol = 0 as *mut sctp_queued_to_read;
                    sctp_reset_in_stream(
                        stcb,
                        (*liste).number_entries,
                        (*liste).list_of_streams.as_mut_ptr(),
                    );
                    if !(*liste).next_resp.tqe_next.is_null() {
                        (*(*liste).next_resp.tqe_next).next_resp.tqe_prev =
                            (*liste).next_resp.tqe_prev
                    } else {
                        (*asoc).resetHead.tqh_last = (*liste).next_resp.tqe_prev
                    }
                    *(*liste).next_resp.tqe_prev = (*liste).next_resp.tqe_next;
                    sctp_send_deferred_reset_response(stcb, liste, 0x1i32);
                    free(liste as *mut libc::c_void);
                    /*sa_ignore FREED_MEMORY*/
                    liste = (*asoc).resetHead.tqh_first;
                    if (*asoc).resetHead.tqh_first.is_null() {
                        /* All can be removed */
                        control = (*asoc).pending_reply_queue.tqh_first;
                        while !control.is_null() && {
                            ncontrol = (*control).next.tqe_next;
                            (1i32) != 0
                        } {
                            if !(*control).next.tqe_next.is_null() {
                                (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
                            } else {
                                (*asoc).pending_reply_queue.tqh_last = (*control).next.tqe_prev
                            }
                            *(*control).next.tqe_prev = (*control).next.tqe_next;
                            sctp_queue_data_to_stream(
                                stcb,
                                asoc,
                                control,
                                abort_flag,
                                &mut need_reasm_check,
                            );
                            if *abort_flag != 0 {
                                return 0i32;
                            }
                            if need_reasm_check != 0 {
                                sctp_deliver_reasm_check(
                                    stcb,
                                    asoc,
                                    &mut *(*asoc).strmin.offset((*control).sinfo_stream as isize),
                                    0i32,
                                );
                                need_reasm_check = 0i32
                            }
                            control = ncontrol
                        }
                    } else {
                        control = (*asoc).pending_reply_queue.tqh_first;
                        while !control.is_null() && {
                            ncontrol = (*control).next.tqe_next;
                            (1i32) != 0
                        } {
                            if (*control).sinfo_tsn < (*liste).tsn
                                && (*liste).tsn.wrapping_sub((*control).sinfo_tsn) > (1u32) << 31i32
                                || (*control).sinfo_tsn > (*liste).tsn
                                    && (*control).sinfo_tsn.wrapping_sub((*liste).tsn)
                                        < (1u32) << 31i32
                            {
                                break;
                            }
                            /*
                             * if control->sinfo_tsn is <= liste->tsn we can
                             * process it which is the NOT of
                             * control->sinfo_tsn > liste->tsn
                             */
                            if !(*control).next.tqe_next.is_null() {
                                (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
                            } else {
                                (*asoc).pending_reply_queue.tqh_last = (*control).next.tqe_prev
                            }
                            *(*control).next.tqe_prev = (*control).next.tqe_next;
                            sctp_queue_data_to_stream(
                                stcb,
                                asoc,
                                control,
                                abort_flag,
                                &mut need_reasm_check,
                            );
                            if *abort_flag != 0 {
                                return 0i32;
                            }
                            if need_reasm_check != 0 {
                                sctp_deliver_reasm_check(
                                    stcb,
                                    asoc,
                                    &mut *(*asoc).strmin.offset((*control).sinfo_stream as isize),
                                    0i32,
                                );
                                need_reasm_check = 0i32
                            }
                            control = ncontrol
                        }
                    }
                }
                return 1i32;
            }
        }
    }
    op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
    (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0xfi32) as uint32_t;
    sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
    *abort_flag = 1i32;
    return 0i32;
}
static mut sctp_map_lookup_tab: [int8_t; 256] = [
    0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 4i8, 0i8, 1i8, 0i8,
    2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 5i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8,
    0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 4i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8,
    1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 6i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8,
    0i8, 1i8, 0i8, 4i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8,
    5i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 4i8, 0i8, 1i8,
    0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 7i8, 0i8, 1i8, 0i8, 2i8, 0i8,
    1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 4i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8,
    0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 5i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8,
    2i8, 0i8, 1i8, 0i8, 4i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8,
    0i8, 6i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 4i8, 0i8,
    1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 5i8, 0i8, 1i8, 0i8, 2i8,
    0i8, 1i8, 0i8, 3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 4i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8,
    3i8, 0i8, 1i8, 0i8, 2i8, 0i8, 1i8, 0i8, 8i8,
];
#[no_mangle]
pub unsafe extern "C" fn sctp_slide_mapping_arrays(mut stcb: *mut sctp_tcb) {
    let mut asoc = 0 as *mut sctp_association;
    let mut at = 0;
    let mut slide_from = 0;
    let mut old_cumack = 0;
    let mut old_base = 0;
    let mut old_highest = 0;
    let mut highest_tsn = 0;
    asoc = &mut (*stcb).asoc;
    old_cumack = (*asoc).cumulative_tsn;
    old_base = (*asoc).mapping_array_base_tsn;
    old_highest = (*asoc).highest_tsn_inside_map;
    /*
     * We could probably improve this a small bit by calculating the
     * offset of the current cum-ack as the starting point.
     */
    at = 0i32;
    slide_from = 0i32;
    while slide_from < (*stcb).asoc.mapping_array_size as libc::c_int {
        let mut val = 0;
        val = (*(*asoc).nr_mapping_array.offset(slide_from as isize) as libc::c_int
            | *(*asoc).mapping_array.offset(slide_from as isize) as libc::c_int)
            as uint8_t;
        if val as libc::c_int == 0xffi32 {
            at += 8i32;
            slide_from += 1
        } else {
            /* there is a 0 bit */
            at += sctp_map_lookup_tab[val as usize] as libc::c_int;
            break;
        }
    }
    (*asoc).cumulative_tsn = (*asoc)
        .mapping_array_base_tsn
        .wrapping_add((at - 1i32) as libc::c_uint);
    if ((*asoc).cumulative_tsn < (*asoc).highest_tsn_inside_map
        && (*asoc)
            .highest_tsn_inside_map
            .wrapping_sub((*asoc).cumulative_tsn)
            > (1u32) << 31i32
        || (*asoc).cumulative_tsn > (*asoc).highest_tsn_inside_map
            && (*asoc)
                .cumulative_tsn
                .wrapping_sub((*asoc).highest_tsn_inside_map)
                < (1u32) << 31i32)
        && ((*asoc).cumulative_tsn < (*asoc).highest_tsn_inside_nr_map
            && (*asoc)
                .highest_tsn_inside_nr_map
                .wrapping_sub((*asoc).cumulative_tsn)
                > (1u32) << 31i32
            || (*asoc).cumulative_tsn > (*asoc).highest_tsn_inside_nr_map
                && (*asoc)
                    .cumulative_tsn
                    .wrapping_sub((*asoc).highest_tsn_inside_nr_map)
                    < (1u32) << 31i32)
    {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"huh, cumack 0x%x greater than high-tsn 0x%x in map - should panic?\n\x00"
                    as *const u8 as *const libc::c_char,
                (*asoc).cumulative_tsn,
                (*asoc).highest_tsn_inside_map,
            );
        }
        sctp_print_mapping_array(asoc);
        if system_base_info.sctpsysctl.sctp_logging_level & 0x100u32 != 0 {
            sctp_log_map(0u32, 6u32, (*asoc).highest_tsn_inside_map, 23i32);
        }
        (*asoc).highest_tsn_inside_map = (*asoc).cumulative_tsn;
        (*asoc).highest_tsn_inside_nr_map = (*asoc).cumulative_tsn
    }
    if (*asoc).highest_tsn_inside_nr_map < (*asoc).highest_tsn_inside_map
        && (*asoc)
            .highest_tsn_inside_map
            .wrapping_sub((*asoc).highest_tsn_inside_nr_map)
            > (1u32) << 31i32
        || (*asoc).highest_tsn_inside_nr_map > (*asoc).highest_tsn_inside_map
            && (*asoc)
                .highest_tsn_inside_nr_map
                .wrapping_sub((*asoc).highest_tsn_inside_map)
                < (1u32) << 31i32
    {
        highest_tsn = (*asoc).highest_tsn_inside_nr_map
    } else {
        highest_tsn = (*asoc).highest_tsn_inside_map
    }
    if (*asoc).cumulative_tsn == highest_tsn && at >= 8i32 {
        let mut clr = 0;
        /* clear the array */
        clr = at + 7i32 >> 3i32;
        if clr > (*asoc).mapping_array_size as libc::c_int {
            clr = (*asoc).mapping_array_size as libc::c_int
        }
        memset(
            (*asoc).mapping_array as *mut libc::c_void,
            0i32,
            clr as libc::c_ulong,
        );
        memset(
            (*asoc).nr_mapping_array as *mut libc::c_void,
            0i32,
            clr as libc::c_ulong,
        );
        (*asoc).mapping_array_base_tsn = (*asoc).cumulative_tsn.wrapping_add(1u32);
        (*asoc).highest_tsn_inside_map = (*asoc).cumulative_tsn;
        (*asoc).highest_tsn_inside_nr_map = (*asoc).highest_tsn_inside_map
    } else if at >= 8i32 {
        let mut slide_end = 0;
        let mut lgap = 0;
        let mut distance = 0;
        if highest_tsn >= (*asoc).mapping_array_base_tsn {
            lgap = highest_tsn.wrapping_sub((*asoc).mapping_array_base_tsn) as libc::c_int
        } else {
            lgap = (0xffffffffu32)
                .wrapping_sub((*asoc).mapping_array_base_tsn)
                .wrapping_add(highest_tsn)
                .wrapping_add(1u32) as libc::c_int
        }
        slide_end = lgap >> 3i32;
        if slide_end < slide_from {
            sctp_print_mapping_array(asoc);
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"impossible slide lgap: %x slide_end: %x slide_from: %x? at: %d\n\x00"
                        as *const u8 as *const libc::c_char,
                    lgap,
                    slide_end,
                    slide_from,
                    at,
                );
            }
            return;
        }
        if slide_end > (*asoc).mapping_array_size as libc::c_int {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Gak, would have overrun map end: %d slide_end: %d\n\x00" as *const u8
                        as *const libc::c_char,
                    (*asoc).mapping_array_size as libc::c_int,
                    slide_end,
                );
            }
            slide_end = (*asoc).mapping_array_size as libc::c_int
        }
        distance = slide_end - slide_from + 1i32;
        if system_base_info.sctpsysctl.sctp_logging_level & 0x100u32 != 0 {
            sctp_log_map(old_base, old_cumack, old_highest, 21i32);
            sctp_log_map(
                slide_from as uint32_t,
                slide_end as uint32_t,
                lgap as uint32_t,
                22i32,
            );
        }
        if distance + slide_from > (*asoc).mapping_array_size as libc::c_int || distance < 0i32 {
            /*
             * Here we do NOT slide forward the array so that
             * hopefully when more data comes in to fill it up
             * we will be able to slide it forward. Really I
             * don't think this should happen :-0
             */
            if system_base_info.sctpsysctl.sctp_logging_level & 0x100u32 != 0 {
                sctp_log_map(
                    distance as uint32_t,
                    slide_from as uint32_t,
                    (*asoc).mapping_array_size as uint32_t,
                    25i32,
                );
            }
        } else {
            for ii in 0i32..distance {
                *(*asoc).mapping_array.offset(ii as isize) =
                    *(*asoc).mapping_array.offset((slide_from + ii) as isize);

                *(*asoc).nr_mapping_array.offset(ii as isize) =
                    *(*asoc).nr_mapping_array.offset((slide_from + ii) as isize);
            }
            for ii in distance..(*asoc).mapping_array_size as libc::c_int {
                *(*asoc).mapping_array.offset(ii as isize) = 0u8;

                *(*asoc).nr_mapping_array.offset(ii as isize) = 0u8;
            }
            if (*asoc).highest_tsn_inside_map.wrapping_add(1u32) == (*asoc).mapping_array_base_tsn {
                (*asoc).highest_tsn_inside_map = ((*asoc).highest_tsn_inside_map)
                    .wrapping_add((slide_from << 3i32) as libc::c_uint)
            }
            if (*asoc).highest_tsn_inside_nr_map.wrapping_add(1u32)
                == (*asoc).mapping_array_base_tsn
            {
                (*asoc).highest_tsn_inside_nr_map = ((*asoc).highest_tsn_inside_nr_map)
                    .wrapping_add((slide_from << 3i32) as libc::c_uint)
            }
            (*asoc).mapping_array_base_tsn =
                ((*asoc).mapping_array_base_tsn).wrapping_add((slide_from << 3i32) as libc::c_uint);
            if system_base_info.sctpsysctl.sctp_logging_level & 0x100u32 != 0 {
                sctp_log_map(
                    (*asoc).mapping_array_base_tsn,
                    (*asoc).cumulative_tsn,
                    (*asoc).highest_tsn_inside_map,
                    23i32,
                );
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_sack_check(mut stcb: *mut sctp_tcb, mut was_a_gap: libc::c_int) {
    let mut asoc = 0 as *mut sctp_association;
    let mut highest_tsn = 0;
    let mut is_a_gap = 0;
    sctp_slide_mapping_arrays(stcb);
    asoc = &mut (*stcb).asoc;
    if (*asoc).highest_tsn_inside_nr_map < (*asoc).highest_tsn_inside_map
        && (*asoc)
            .highest_tsn_inside_map
            .wrapping_sub((*asoc).highest_tsn_inside_nr_map)
            > (1u32) << 31i32
        || (*asoc).highest_tsn_inside_nr_map > (*asoc).highest_tsn_inside_map
            && (*asoc)
                .highest_tsn_inside_nr_map
                .wrapping_sub((*asoc).highest_tsn_inside_map)
                < (1u32) << 31i32
    {
        highest_tsn = (*asoc).highest_tsn_inside_nr_map
    } else {
        highest_tsn = (*asoc).highest_tsn_inside_map
    }
    /* Is there a gap now? */
    is_a_gap = (highest_tsn < (*stcb).asoc.cumulative_tsn
        && (*stcb).asoc.cumulative_tsn.wrapping_sub(highest_tsn) > (1u32) << 31i32
        || highest_tsn > (*stcb).asoc.cumulative_tsn
            && highest_tsn.wrapping_sub((*stcb).asoc.cumulative_tsn) < (1u32) << 31i32)
        as libc::c_int;
    /*
     * Now we need to see if we need to queue a sack or just start the
     * timer (if allowed).
     */
    if (*stcb).asoc.state & 0x7fi32 == 0x10i32 {
        /*
         * Ok special case, in SHUTDOWN-SENT case. here we
         * maker sure SACK timer is off and instead send a
         * SHUTDOWN and a SACK
         */
        if (*stcb).asoc.dack_timer.timer.c_flags & 0x4i32 != 0 {
            sctp_timer_stop(
                3i32,
                (*stcb).sctp_ep,
                stcb,
                0 as *mut sctp_nets,
                (0x30000000i32 + 0x11i32) as uint32_t,
            );
        }
        sctp_send_shutdown(
            stcb,
            if !(*stcb).asoc.alternate.is_null() {
                (*stcb).asoc.alternate
            } else {
                (*stcb).asoc.primary_destination
            },
        );
        if is_a_gap != 0 {
            sctp_send_sack(stcb, 0i32);
        }
    } else {
        /*
         * CMT DAC algorithm: increase number of packets
         * received since last ack
         */
        (*stcb).asoc.cmt_dac_pkts_rcvd = (*stcb).asoc.cmt_dac_pkts_rcvd.wrapping_add(1);
        if (*stcb).asoc.send_sack as libc::c_int == 1i32
            || was_a_gap != 0 && is_a_gap == 0i32
            || (*stcb).asoc.numduptsns != 0
            || is_a_gap != 0
            || (*stcb).asoc.delayed_ack == 0u32
            || (*stcb).asoc.data_pkts_seen >= (*stcb).asoc.sack_freq
        {
            /* hit limit of pkts */
            if (*stcb).asoc.sctp_cmt_on_off as libc::c_int > 0i32
                && system_base_info.sctpsysctl.sctp_cmt_use_dac != 0
                && (*stcb).asoc.send_sack as libc::c_int == 0i32
                && (*stcb).asoc.numduptsns == 0u32
                && (*stcb).asoc.delayed_ack != 0
                && (*stcb).asoc.dack_timer.timer.c_flags & 0x4i32 == 0
            {
                /*
                * CMT DAC algorithm: With CMT,
                * delay acks even in the face of

                * reordering. Therefore, if acks
                * that do not have to be sent
                * because of the above reasons,
                * will be delayed. That is, acks
                * that would have been sent due to
                * gap reports will be delayed with
                * DAC. Start the delayed ack timer.
                */
                sctp_timer_start(3i32, (*stcb).sctp_ep, stcb, 0 as *mut sctp_nets);
            } else {
                /*
                 * Ok we must build a SACK since the
                 * timer is pending, we got our
                 * first packet OR there are gaps or
                 * duplicates.
                 */
                sctp_os_timer_stop(&mut (*stcb).asoc.dack_timer.timer); /* number of control chunks processed */
                sctp_send_sack(stcb, 0i32);
            }
        } else if (*stcb).asoc.dack_timer.timer.c_flags & 0x4i32 == 0 {
            sctp_timer_start(3i32, (*stcb).sctp_ep, stcb, 0 as *mut sctp_nets);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_process_data(
    mut mm: *mut *mut mbuf,
    mut iphlen: libc::c_int,
    mut offset: *mut libc::c_int,
    mut length: libc::c_int,
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut high_tsn: *mut uint32_t,
) -> libc::c_int {
    let mut ch = 0 as *mut sctp_chunkhdr;
    let mut chunk_buf = sctp_chunkhdr {
        chunk_type: 0,
        chunk_flags: 0,
        chunk_length: 0,
    };
    let mut asoc = 0 as *mut sctp_association;
    let mut num_chunks = 0i32;
    let mut stop_proc = 0i32;
    let mut break_flag = 0;
    let mut was_a_gap = 0;
    let mut m = 0 as *mut mbuf;
    let mut highest_tsn = 0;
    /* set the rwnd */
    sctp_set_rwnd(stcb, &mut (*stcb).asoc);
    m = *mm;
    asoc = &mut (*stcb).asoc;
    if (*asoc).highest_tsn_inside_nr_map < (*asoc).highest_tsn_inside_map
        && (*asoc)
            .highest_tsn_inside_map
            .wrapping_sub((*asoc).highest_tsn_inside_nr_map)
            > (1u32) << 31i32
        || (*asoc).highest_tsn_inside_nr_map > (*asoc).highest_tsn_inside_map
            && (*asoc)
                .highest_tsn_inside_nr_map
                .wrapping_sub((*asoc).highest_tsn_inside_map)
                < (1u32) << 31i32
    {
        highest_tsn = (*asoc).highest_tsn_inside_nr_map
    } else {
        highest_tsn = (*asoc).highest_tsn_inside_map
    }
    was_a_gap = (highest_tsn < (*stcb).asoc.cumulative_tsn
        && (*stcb).asoc.cumulative_tsn.wrapping_sub(highest_tsn) > (1u32) << 31i32
        || highest_tsn > (*stcb).asoc.cumulative_tsn
            && highest_tsn.wrapping_sub((*stcb).asoc.cumulative_tsn) < (1u32) << 31i32)
        as libc::c_int;
    /*
     * setup where we got the last DATA packet from for any SACK that
     * may need to go out. Don't bump the net. This is done ONLY when a
     * chunk is assigned.
     */
    (*asoc).last_data_chunk_from = net;
    /*-
     * Now before we proceed we must figure out if this is a wasted
     * cluster... i.e. it is a small packet sent in and yet the driver
     * underneath allocated a full cluster for it. If so we must copy it
     * to a smaller mbuf and free up the cluster mbuf. This will help
     * with cluster starvation. Note for __Panda__ we don't do this
     * since it has clusters all the way down to 64 bytes.
     */
    if ((*m).m_hdr.mh_len as libc::c_long)
        < (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_int
            as libc::c_long
        && (*m).m_hdr.mh_next.is_null()
    {
        /* we only handle mbufs that are singletons.. not chains */
        m = sctp_get_mbuf_for_msg((*m).m_hdr.mh_len as libc::c_uint, 0i32, 0x1i32, 1i32, 1i32);
        if !m.is_null() {
            let mut from = 0 as *mut caddr_t;
            let mut to = 0 as *mut caddr_t;
            /* get the pointers and copy */
            to = (*m).m_hdr.mh_data as *mut caddr_t;
            from = (**mm).m_hdr.mh_data as *mut caddr_t;
            memcpy(
                to as *mut libc::c_void,
                from as *const libc::c_void,
                (**mm).m_hdr.mh_len as libc::c_ulong,
            );
            /* copy the length and free up the old */
            (*m).m_hdr.mh_len = (**mm).m_hdr.mh_len;
            m_freem(*mm);
            /* success, back copy */
            *mm = m
        } else {
            /* We are in trouble in the mbuf world .. yikes */
            m = *mm
        }
    }
    /* get pointer to the first chunk header */
    ch = sctp_m_getptr(
        m,
        *offset,
        ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_int,
        &mut chunk_buf as *mut sctp_chunkhdr as *mut uint8_t,
    ) as *mut sctp_chunkhdr;
    if ch.is_null() {
        return 1i32;
    }
    /*
     * process all DATA chunks...
     */
    *high_tsn = (*asoc).cumulative_tsn;
    break_flag = 0i32;
    (*asoc).data_pkts_seen = (*asoc).data_pkts_seen.wrapping_add(1);
    while stop_proc == 0i32 {
        let mut chk_length = 0;
        chk_length = ntohs((*ch).chunk_length);
        if length - *offset < chk_length as libc::c_int {
            /* all done, mutulated chunk */
            stop_proc = 1i32
        } else {
            if (*asoc).idata_supported as libc::c_int == 1i32
                && (*ch).chunk_type as libc::c_int == 0i32
            {
                let mut op_err = 0 as *mut mbuf;
                let mut msg = [0; 128];
                snprintf(
                    msg.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    b"%s\x00" as *const u8 as *const libc::c_char,
                    b"I-DATA chunk received when DATA was negotiated\x00" as *const u8
                        as *const libc::c_char,
                );
                op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
                (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x12i32) as uint32_t;
                sctp_abort_an_association(inp, stcb, op_err, 0i32);
                return 2i32;
            }
            if (*asoc).idata_supported as libc::c_int == 0i32
                && (*ch).chunk_type as libc::c_int == 0x40i32
            {
                let mut op_err_0 = 0 as *mut mbuf;
                let mut msg_0 = [0; 128];
                snprintf(
                    msg_0.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    b"%s\x00" as *const u8 as *const libc::c_char,
                    b"DATA chunk received when I-DATA was negotiated\x00" as *const u8
                        as *const libc::c_char,
                );
                op_err_0 = sctp_generate_cause(0xdu16, msg_0.as_mut_ptr());
                (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x13i32) as uint32_t;
                sctp_abort_an_association(inp, stcb, op_err_0, 0i32);
                return 2i32;
            }
            if (*ch).chunk_type as libc::c_int == 0i32 || (*ch).chunk_type as libc::c_int == 0x40i32
            {
                let mut last_chunk = 0;
                let mut abort_flag = 0i32;
                let mut clen = 0;
                if (*ch).chunk_type as libc::c_int == 0i32 {
                    clen = ::std::mem::size_of::<sctp_data_chunk>() as uint16_t
                } else {
                    clen = ::std::mem::size_of::<sctp_idata_chunk>() as uint16_t
                }
                if (chk_length as libc::c_int) < clen as libc::c_int {
                    let mut op_err_1 = 0 as *mut mbuf;
                    let mut msg_1 = [0; 128];
                    snprintf(
                        msg_1.as_mut_ptr(),
                        ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                        b"%s chunk of length %u\x00" as *const u8 as *const libc::c_char,
                        if (*ch).chunk_type as libc::c_int == 0i32 {
                            b"DATA\x00" as *const u8 as *const libc::c_char
                        } else {
                            b"I-DATA\x00" as *const u8 as *const libc::c_char
                        },
                        chk_length as libc::c_int,
                    );
                    op_err_1 = sctp_generate_cause(0xdu16, msg_1.as_mut_ptr());
                    (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x14i32) as uint32_t;
                    sctp_abort_an_association(inp, stcb, op_err_1, 0i32);
                    return 2i32;
                }
                if (chk_length as libc::c_int + 3i32 >> 2i32) << 2i32 == length - *offset {
                    last_chunk = 1i32
                } else {
                    last_chunk = 0i32
                }
                if sctp_process_a_data_chunk(
                    stcb,
                    asoc,
                    mm,
                    *offset,
                    chk_length as libc::c_int,
                    net,
                    high_tsn,
                    &mut abort_flag,
                    &mut break_flag,
                    last_chunk,
                    (*ch).chunk_type,
                ) != 0
                {
                    num_chunks += 1
                }
                if abort_flag != 0 {
                    return 2i32;
                }
                if break_flag != 0 {
                    /*
                     * Set because of out of rwnd space and no
                     * drop rep space left.
                     */
                    stop_proc = 1i32;
                    continue;
                }
            } else {
                /* not a data chunk in the data region */
                match (*ch).chunk_type as libc::c_int {
                    1 | 2 | 3 | 16 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 128
                    | 129 | 130 | 192 | 193 => {
                        let mut op_err_2 = 0 as *mut mbuf;
                        let mut msg_2 = [0; 128];
                        snprintf(
                            msg_2.as_mut_ptr(),
                            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                            b"DATA chunk followed by chunk of type %2.2x\x00" as *const u8
                                as *const libc::c_char,
                            (*ch).chunk_type as libc::c_int,
                        );
                        op_err_2 = sctp_generate_cause(0xdu16, msg_2.as_mut_ptr());
                        sctp_abort_an_association(inp, stcb, op_err_2, 0i32);
                        return 2i32;
                    }
                    _ => {
                        /*
                         * Unknown chunk type: use bit rules after
                         * checking length
                         */
                        if (chk_length as libc::c_ulong)
                            < ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_ulong
                        {
                            let mut op_err_3 = 0 as *mut mbuf;
                            let mut msg_3 = [0; 128];
                            snprintf(
                                msg_3.as_mut_ptr(),
                                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                                b"Chunk of length %u\x00" as *const u8 as *const libc::c_char,
                                chk_length as libc::c_int,
                            );
                            op_err_3 = sctp_generate_cause(0xdu16, msg_3.as_mut_ptr());
                            (*(*stcb).sctp_ep).last_abort_code =
                                (0x30000000i32 + 0x14i32) as uint32_t;
                            sctp_abort_an_association(inp, stcb, op_err_3, 0i32);
                            return 2i32;
                        }
                        if (*ch).chunk_type as libc::c_int & 0x40i32 != 0 {
                            let mut op_err_4 = 0 as *mut mbuf;
                            op_err_4 = sctp_get_mbuf_for_msg(
                                ::std::mem::size_of::<sctp_gen_error_cause>() as libc::c_uint,
                                0i32,
                                0x1i32,
                                1i32,
                                1i32,
                            );
                            if !op_err_4.is_null() {
                                let mut cause = 0 as *mut sctp_gen_error_cause;
                                cause = (*op_err_4).m_hdr.mh_data as *mut sctp_gen_error_cause;
                                (*cause).code = htons(0x6u16);
                                (*cause).length = htons(
                                    (chk_length as libc::c_ulong)
                                        .wrapping_add(::std::mem::size_of::<sctp_gen_error_cause>()
                                            as libc::c_ulong)
                                        as uint16_t,
                                );
                                (*op_err_4).m_hdr.mh_len =
                                    ::std::mem::size_of::<sctp_gen_error_cause>() as libc::c_int;
                                (*op_err_4).m_hdr.mh_next =
                                    m_copym(m, *offset, chk_length as libc::c_int, 0x1i32);
                                if !(*op_err_4).m_hdr.mh_next.is_null() {
                                    sctp_queue_op_err(stcb, op_err_4);
                                } else {
                                    m_freem(op_err_4);
                                }
                            }
                        }
                        if (*ch).chunk_type as libc::c_int & 0x80i32 == 0i32 {
                            /* discard the rest of this packet */
                            stop_proc = 1i32
                        }
                    }
                }
                /* switch of chunk type */
            }
            *offset += (chk_length as libc::c_int + 3i32 >> 2i32) << 2i32;
            if *offset >= length || stop_proc != 0 {
                /* no more data left in the mbuf chain */
                stop_proc = 1i32
            } else {
                ch = sctp_m_getptr(
                    m,
                    *offset,
                    ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_int,
                    &mut chunk_buf as *mut sctp_chunkhdr as *mut uint8_t,
                ) as *mut sctp_chunkhdr;
                if !ch.is_null() {
                    continue;
                }
                *offset = length;
                stop_proc = 1i32
            }
        }
    }
    if break_flag != 0 {
        /*
         * we need to report rwnd overrun drops.
         */
        sctp_send_packet_dropped(stcb, net, *mm, length, iphlen, 0i32);
    }
    if num_chunks != 0 {
        /*
         * Did we get data, if so update the time for auto-close and
         * give peer credit for being alive.
         */
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvpktwithdata, 1u32);
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2000000u32 != 0 {
            sctp_misc_ints(
                120u8,
                (*stcb).asoc.overall_error_count,
                0u32,
                0x30000000u32,
                2943u32,
            );
        }
        (*stcb).asoc.overall_error_count = 0u32;
        gettimeofday(&mut (*stcb).asoc.time_last_rcvd, 0 as *mut timezone);
    }
    /* now service all of the reassm queue if needed */
    if (*stcb).asoc.state & 0x7fi32 == 0x10i32 {
        /* Assure that we ack right away */
        (*stcb).asoc.send_sack = 1u8
    }
    /* Start a sack timer or QUEUE a SACK for sending */
    sctp_sack_check(stcb, was_a_gap);
    return 0i32;
}
unsafe extern "C" fn sctp_process_segment_range(
    mut stcb: *mut sctp_tcb,
    mut p_tp1: *mut *mut sctp_tmit_chunk,
    mut last_tsn: uint32_t,
    mut frag_strt: uint16_t,
    mut frag_end: uint16_t,
    mut nr_sacking: libc::c_int,
    mut num_frs: *mut libc::c_int,
    mut biggest_newly_acked_tsn: *mut uint32_t,
    mut this_sack_lowest_newack: *mut uint32_t,
    mut rto_ok: *mut libc::c_int,
) -> libc::c_int {
    let mut tp1 = 0 as *mut sctp_tmit_chunk;
    let mut wake_him = 0i32;
    /* Recover the tp1 we last saw */
    tp1 = *p_tp1; /* end for (j = fragStart */
    if tp1.is_null() {
        tp1 = (*stcb).asoc.sent_queue.tqh_first
    }

    for j in frag_strt as libc::c_int..=frag_end as libc::c_int {
        let mut theTSN = 0;
        let mut circled = 0i32;
        theTSN = (j as libc::c_uint).wrapping_add(last_tsn);
        /* In case the fragments were not in order we must reset */
        while !tp1.is_null() {
            if (*tp1).rec.data.doing_fast_retransmit != 0 {
                *num_frs += 1i32
            } /* end while (tp1) */
            /*-
             * CMT: CUCv2 algorithm. For each TSN being
             * processed from the sent queue, track the
             * next expected pseudo-cumack, or
             * rtx_pseudo_cumack, if required. Separate
             * cumack trackers for first transmissions,
             * and retransmissions.
             */
            if (*tp1).sent < 4i32
                && (*(*tp1).whoTo).find_pseudo_cumack as libc::c_int == 1i32
                && (*tp1).snd_count as libc::c_int == 1i32
            {
                (*(*tp1).whoTo).pseudo_cumack = (*tp1).rec.data.tsn; /* if (tp1->tsn == theTSN) */
                (*(*tp1).whoTo).find_pseudo_cumack = 0u8
            }
            if (*tp1).sent < 4i32
                && (*(*tp1).whoTo).find_rtx_pseudo_cumack as libc::c_int == 1i32
                && (*tp1).snd_count as libc::c_int > 1i32
            {
                (*(*tp1).whoTo).rtx_pseudo_cumack = (*tp1).rec.data.tsn;
                (*(*tp1).whoTo).find_rtx_pseudo_cumack = 0u8
            }
            if (*tp1).rec.data.tsn == theTSN {
                if (*tp1).sent != 0i32 {
                    /*-
                     * must be held until
                     * cum-ack passes
                     */
                    if (*tp1).sent < 4i32 {
                        /*-
                         * If it is less than RESEND, it is
                         * now no-longer in flight.
                         * Higher values may already be set
                         * via previous Gap Ack Blocks...
                         * i.e. ACKED or RESEND.
                         */
                        if (*tp1).rec.data.tsn < *biggest_newly_acked_tsn
                            && (*biggest_newly_acked_tsn).wrapping_sub((*tp1).rec.data.tsn)
                                > (1u32) << 31i32
                            || (*tp1).rec.data.tsn > *biggest_newly_acked_tsn
                                && (*tp1).rec.data.tsn.wrapping_sub(*biggest_newly_acked_tsn)
                                    < (1u32) << 31i32
                        {
                            *biggest_newly_acked_tsn = (*tp1).rec.data.tsn
                        }
                        /*-
                         * CMT: SFR algo (and HTNA) - set
                         * saw_newack to 1 for dest being
                         * newly acked. update
                         * this_sack_highest_newack if
                         * appropriate.
                         */
                        if (*tp1).rec.data.chunk_was_revoked as libc::c_int == 0i32 {
                            (*(*tp1).whoTo).saw_newack = 1u8
                        }
                        if (*tp1).rec.data.tsn < (*(*tp1).whoTo).this_sack_highest_newack
                            && (*(*tp1).whoTo)
                                .this_sack_highest_newack
                                .wrapping_sub((*tp1).rec.data.tsn)
                                > (1u32) << 31i32
                            || (*tp1).rec.data.tsn > (*(*tp1).whoTo).this_sack_highest_newack
                                && (*tp1)
                                    .rec
                                    .data
                                    .tsn
                                    .wrapping_sub((*(*tp1).whoTo).this_sack_highest_newack)
                                    < (1u32) << 31i32
                        {
                            (*(*tp1).whoTo).this_sack_highest_newack = (*tp1).rec.data.tsn
                        }
                        /*-
                         * CMT DAC algo: also update
                         * this_sack_lowest_newack
                         */
                        if *this_sack_lowest_newack == 0u32 {
                            if system_base_info.sctpsysctl.sctp_logging_level & 0x4000u32 != 0 {
                                sctp_log_sack(
                                    *this_sack_lowest_newack,
                                    last_tsn,
                                    (*tp1).rec.data.tsn,
                                    0u16,
                                    0u16,
                                    43i32,
                                );
                            }
                            *this_sack_lowest_newack = (*tp1).rec.data.tsn
                        }
                        /*-
                         * CMT: CUCv2 algorithm. If (rtx-)pseudo-cumack for corresp
                         * dest is being acked, then we have a new (rtx-)pseudo-cumack. Set
                         * new_(rtx_)pseudo_cumack to TRUE so that the cwnd for this dest can be
                         * updated. Also trigger search for the next expected (rtx-)pseudo-cumack.
                         * Separate pseudo_cumack trackers for first transmissions and
                         * retransmissions.
                         */
                        if (*tp1).rec.data.tsn == (*(*tp1).whoTo).pseudo_cumack {
                            if (*tp1).rec.data.chunk_was_revoked as libc::c_int == 0i32 {
                                (*(*tp1).whoTo).new_pseudo_cumack = 1u8
                            }
                            (*(*tp1).whoTo).find_pseudo_cumack = 1u8
                        }
                        if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                            sctp_log_cwnd(
                                stcb,
                                (*tp1).whoTo,
                                (*tp1).rec.data.tsn as libc::c_int,
                                64u8,
                            );
                        }
                        if (*tp1).rec.data.tsn == (*(*tp1).whoTo).rtx_pseudo_cumack {
                            if (*tp1).rec.data.chunk_was_revoked as libc::c_int == 0i32 {
                                (*(*tp1).whoTo).new_pseudo_cumack = 1u8
                            }
                            (*(*tp1).whoTo).find_rtx_pseudo_cumack = 1u8
                        }
                        if system_base_info.sctpsysctl.sctp_logging_level & 0x4000u32 != 0 {
                            sctp_log_sack(
                                *biggest_newly_acked_tsn,
                                last_tsn,
                                (*tp1).rec.data.tsn,
                                frag_strt,
                                frag_end,
                                43i32,
                            );
                        }
                        if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
                            sctp_misc_ints(
                                109u8,
                                (*(*tp1).whoTo).flight_size,
                                (*tp1).book_size as uint32_t,
                                (*tp1).whoTo as uint32_t,
                                (*tp1).rec.data.tsn,
                            );
                        }
                        if (*(*tp1).whoTo).flight_size >= (*tp1).book_size as libc::c_uint {
                            (*(*tp1).whoTo).flight_size = ((*(*tp1).whoTo).flight_size)
                                .wrapping_sub((*tp1).book_size as libc::c_uint)
                        } else {
                            (*(*tp1).whoTo).flight_size = 0u32
                        }
                        if (*stcb)
                            .asoc
                            .cc_functions
                            .sctp_cwnd_update_tsn_acknowledged
                            .is_some()
                        {
                            Some(
                                (*stcb)
                                    .asoc
                                    .cc_functions
                                    .sctp_cwnd_update_tsn_acknowledged
                                    .expect("non-null function pointer"),
                            )
                            .expect("non-null function pointer")(
                                (*tp1).whoTo, tp1
                            );
                        }
                        (*tp1).window_probe = 0u8;
                        if (*stcb).asoc.total_flight >= (*tp1).book_size as libc::c_uint {
                            (*stcb).asoc.total_flight = (*stcb)
                                .asoc
                                .total_flight
                                .wrapping_sub((*tp1).book_size as libc::c_uint);
                            if (*stcb).asoc.total_flight_count > 0u32 {
                                (*stcb).asoc.total_flight_count =
                                    (*stcb).asoc.total_flight_count.wrapping_sub(1)
                            }
                        } else {
                            (*stcb).asoc.total_flight = 0u32;
                            (*stcb).asoc.total_flight_count = 0u32
                        }
                        (*(*tp1).whoTo).net_ack = (*(*tp1).whoTo)
                            .net_ack
                            .wrapping_add((*tp1).send_size as libc::c_uint);
                        if ((*tp1).snd_count as libc::c_int) < 2i32 {
                            /*-
                             * True non-retransmitted chunk
                             */
                            (*(*tp1).whoTo).net_ack2 = (*(*tp1).whoTo)
                                .net_ack2
                                .wrapping_add((*tp1).send_size as libc::c_uint);
                            /*-
                             * update RTO too ?
                             */
                            if (*tp1).do_rtt != 0 {
                                if *rto_ok != 0
                                    && sctp_calculate_rto(
                                        stcb,
                                        &mut (*stcb).asoc,
                                        (*tp1).whoTo,
                                        &mut (*tp1).sent_rcv_time,
                                        1i32,
                                    ) != 0
                                {
                                    *rto_ok = 0i32
                                }
                                if (*(*tp1).whoTo).rto_needed as libc::c_int == 0i32 {
                                    (*(*tp1).whoTo).rto_needed = 1u8
                                }
                                (*tp1).do_rtt = 0u8
                            }
                        }
                    }
                    if (*tp1).sent <= 4i32 {
                        if (*tp1).rec.data.tsn < (*stcb).asoc.this_sack_highest_gap
                            && (*stcb)
                                .asoc
                                .this_sack_highest_gap
                                .wrapping_sub((*tp1).rec.data.tsn)
                                > (1u32) << 31i32
                            || (*tp1).rec.data.tsn > (*stcb).asoc.this_sack_highest_gap
                                && (*tp1)
                                    .rec
                                    .data
                                    .tsn
                                    .wrapping_sub((*stcb).asoc.this_sack_highest_gap)
                                    < (1u32) << 31i32
                        {
                            (*stcb).asoc.this_sack_highest_gap = (*tp1).rec.data.tsn
                        }
                        if (*tp1).sent == 4i32 {
                            if (*stcb).asoc.sent_queue_retran_cnt > 0u32 {
                                (*stcb).asoc.sent_queue_retran_cnt =
                                    (*stcb).asoc.sent_queue_retran_cnt.wrapping_sub(1)
                            } else {
                                (*stcb).asoc.sent_queue_retran_cnt = 0u32
                            }
                        }
                    }
                    /*-
                     * All chunks NOT UNSENT fall through here and are marked
                     * (leave PR-SCTP ones that are to skip alone though)
                     */
                    if (*tp1).sent != 30010i32 && (*tp1).sent != 40010i32 {
                        (*tp1).sent = 20010i32
                    }
                    if (*tp1).rec.data.chunk_was_revoked != 0 {
                        /* deflate the cwnd */
                        (*(*tp1).whoTo).cwnd =
                            ((*(*tp1).whoTo).cwnd).wrapping_sub((*tp1).book_size as libc::c_uint);
                        (*tp1).rec.data.chunk_was_revoked = 0u8
                    }
                    /* NR Sack code here */
                    if nr_sacking != 0 && (*tp1).sent != 40010i32 {
                        if (*(*stcb).asoc.strmout.offset((*tp1).rec.data.sid as isize))
                            .chunks_on_queues
                            > 0u32
                        {
                            let ref mut fresh7 =
                                (*(*stcb).asoc.strmout.offset((*tp1).rec.data.sid as isize))
                                    .chunks_on_queues;
                            *fresh7 = (*fresh7).wrapping_sub(1)
                        }
                        if (*(*stcb).asoc.strmout.offset((*tp1).rec.data.sid as isize))
                            .chunks_on_queues
                            == 0u32
                            && (*(*stcb).asoc.strmout.offset((*tp1).rec.data.sid as isize)).state
                                as libc::c_int
                                == 0x3i32
                            && (*(*stcb).asoc.strmout.offset((*tp1).rec.data.sid as isize))
                                .outqueue
                                .tqh_first
                                .is_null()
                        {
                            (*stcb).asoc.trigger_reset = 1u8
                        }
                        (*tp1).sent = 40010i32;
                        if !(*tp1).data.is_null() {
                            /* sa_ignore NO_NULL_CHK */
                            if !(*tp1).data.is_null() {
                                ::std::intrinsics::atomic_xsub(
                                    &mut (*stcb).asoc.chunks_on_out_queue,
                                    1u32,
                                );
                                if (*stcb).asoc.total_output_queue_size
                                    >= (*tp1).book_size as libc::c_uint
                                {
                                    ::std::intrinsics::atomic_xsub(
                                        &mut (*stcb).asoc.total_output_queue_size,
                                        (*tp1).book_size as uint32_t,
                                    );
                                } else {
                                    (*stcb).asoc.total_output_queue_size = 0u32
                                }
                                if !(*stcb).sctp_socket.is_null()
                                    && ((*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
                                        || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0)
                                {
                                    if (*(*stcb).sctp_socket).so_snd.sb_cc
                                        >= (*tp1).book_size as libc::c_uint
                                    {
                                        ::std::intrinsics::atomic_xsub(
                                            &mut (*(*stcb).sctp_socket).so_snd.sb_cc,
                                            (*tp1).book_size as u_int,
                                        );
                                    } else {
                                        (*(*stcb).sctp_socket).so_snd.sb_cc = 0u32
                                    }
                                }
                            }
                            m_freem((*tp1).data);
                            (*tp1).data = 0 as *mut mbuf
                        }
                        wake_him += 1
                    }
                }
                break;
            } else {
                if (*tp1).rec.data.tsn < theTSN
                    && theTSN.wrapping_sub((*tp1).rec.data.tsn) > (1u32) << 31i32
                    || (*tp1).rec.data.tsn > theTSN
                        && (*tp1).rec.data.tsn.wrapping_sub(theTSN) < (1u32) << 31i32
                {
                    break;
                }
                tp1 = (*tp1).sctp_next.tqe_next;
                if tp1.is_null() && circled == 0i32 {
                    circled += 1;
                    tp1 = (*stcb).asoc.sent_queue.tqh_first
                }
            }
        }

        if tp1.is_null() {
            circled = 0i32;
            tp1 = (*stcb).asoc.sent_queue.tqh_first
        }
    }
    *p_tp1 = tp1;
    return wake_him;
    /* Return value only used for nr-sack */
}
unsafe extern "C" fn sctp_handle_segments(
    mut m: *mut mbuf,
    mut offset: *mut libc::c_int,
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut last_tsn: uint32_t,
    mut biggest_tsn_acked: *mut uint32_t,
    mut biggest_newly_acked_tsn: *mut uint32_t,
    mut this_sack_lowest_newack: *mut uint32_t,
    mut num_seg: libc::c_int,
    mut num_nr_seg: libc::c_int,
    mut rto_ok: *mut libc::c_int,
) -> libc::c_int {
    let mut tp1 = 0 as *mut sctp_tmit_chunk;
    let mut num_frs = 0i32;
    let mut chunk_freed = 0;
    let mut prev_frag_end = 0;
    tp1 = (*asoc).sent_queue.tqh_first;
    prev_frag_end = 0u16;
    chunk_freed = 0i32;

    for i in 0i32..num_seg + num_nr_seg {
        let mut frag = 0 as *mut sctp_gap_ack_block;
        let mut block = sctp_gap_ack_block { start: 0, end: 0 };
        let mut frag_strt = 0;
        let mut frag_end = 0;
        if i == num_seg {
            prev_frag_end = 0u16;
            tp1 = (*asoc).sent_queue.tqh_first
        }

        frag = sctp_m_getptr(
            m,
            *offset,
            ::std::mem::size_of::<sctp_gap_ack_block>() as libc::c_int,
            &mut block as *mut sctp_gap_ack_block as *mut uint8_t,
        ) as *mut sctp_gap_ack_block;

        *offset = (*offset as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_gap_ack_block>() as libc::c_ulong)
            as libc::c_int;

        if frag.is_null() {
            return chunk_freed;
        }

        frag_strt = ntohs((*frag).start);

        frag_end = ntohs((*frag).end);

        if !(frag_strt as libc::c_int > frag_end as libc::c_int) {
            let mut non_revocable = 0;
            if frag_strt as libc::c_int <= prev_frag_end as libc::c_int {
                /* This gap report is not in order, so restart. */
                tp1 = (*asoc).sent_queue.tqh_first
            }
            if last_tsn.wrapping_add(frag_end as libc::c_uint) < *biggest_tsn_acked
                && (*biggest_tsn_acked)
                    .wrapping_sub(last_tsn.wrapping_add(frag_end as libc::c_uint))
                    > (1u32) << 31i32
                || last_tsn.wrapping_add(frag_end as libc::c_uint) > *biggest_tsn_acked
                    && last_tsn
                        .wrapping_add(frag_end as libc::c_uint)
                        .wrapping_sub(*biggest_tsn_acked)
                        < (1u32) << 31i32
            {
                *biggest_tsn_acked = last_tsn.wrapping_add(frag_end as libc::c_uint)
            }
            if i < num_seg {
                non_revocable = 0i32
            } else {
                non_revocable = 1i32
            }
            if sctp_process_segment_range(
                stcb,
                &mut tp1,
                last_tsn,
                frag_strt,
                frag_end,
                non_revocable,
                &mut num_frs,
                biggest_newly_acked_tsn,
                this_sack_lowest_newack,
                rto_ok,
            ) != 0
            {
                chunk_freed = 1i32
            }
            prev_frag_end = frag_end
        }
    }
    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
        if num_frs != 0 {
            sctp_log_fr(
                *biggest_tsn_acked,
                *biggest_newly_acked_tsn,
                last_tsn,
                17i32,
            );
        }
    }
    return chunk_freed;
}
unsafe extern "C" fn sctp_check_for_revoked(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut cumack: uint32_t,
    mut biggest_tsn_acked: uint32_t,
) {
    let mut tp1 = 0 as *mut sctp_tmit_chunk;
    tp1 = (*asoc).sent_queue.tqh_first;
    while !tp1.is_null() {
        if (*tp1).rec.data.tsn < cumack
            && cumack.wrapping_sub((*tp1).rec.data.tsn) > (1u32) << 31i32
            || (*tp1).rec.data.tsn > cumack
                && (*tp1).rec.data.tsn.wrapping_sub(cumack) < (1u32) << 31i32
        {
            /*
             * ok this guy is either ACK or MARKED. If it is
             * ACKED it has been previously acked but not this
             * time i.e. revoked.  If it is MARKED it was ACK'ed
             * again.
             */
            if (*tp1).rec.data.tsn < biggest_tsn_acked
                && biggest_tsn_acked.wrapping_sub((*tp1).rec.data.tsn) > (1u32) << 31i32
                || (*tp1).rec.data.tsn > biggest_tsn_acked
                    && (*tp1).rec.data.tsn.wrapping_sub(biggest_tsn_acked) < (1u32) << 31i32
            {
                break;
            }
            if (*tp1).sent == 10010i32 {
                /* it has been revoked */
                (*tp1).sent = 1i32;
                (*tp1).rec.data.chunk_was_revoked = 1u8;
                /* We must add this stuff back in to
                 * assure timers and such get started.
                 */
                if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
                    sctp_misc_ints(
                        114u8,
                        (*(*tp1).whoTo).flight_size,
                        (*tp1).book_size as uint32_t,
                        (*tp1).whoTo as uint32_t,
                        (*tp1).rec.data.tsn,
                    );
                }
                (*(*tp1).whoTo).flight_size =
                    ((*(*tp1).whoTo).flight_size).wrapping_add((*tp1).book_size as libc::c_uint);
                (*stcb).asoc.total_flight_count = (*stcb).asoc.total_flight_count.wrapping_add(1);
                (*stcb).asoc.total_flight = (*stcb)
                    .asoc
                    .total_flight
                    .wrapping_add((*tp1).book_size as libc::c_uint);
                /* We inflate the cwnd to compensate for our
                 * artificial inflation of the flight_size.
                 */
                (*(*tp1).whoTo).cwnd =
                    ((*(*tp1).whoTo).cwnd).wrapping_add((*tp1).book_size as libc::c_uint);
                if system_base_info.sctpsysctl.sctp_logging_level & 0x4000u32 != 0 {
                    sctp_log_sack(
                        (*asoc).last_acked_seq,
                        cumack,
                        (*tp1).rec.data.tsn,
                        0u16,
                        0u16,
                        44i32,
                    );
                }
            } else if (*tp1).sent == 20010i32 {
                /* it has been re-acked in this SACK */
                (*tp1).sent = 10010i32
            }
        }
        if (*tp1).sent == 0i32 {
            break;
        }
        tp1 = (*tp1).sctp_next.tqe_next
    }
}
unsafe extern "C" fn sctp_strike_gap_ack_chunks(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut biggest_tsn_acked: uint32_t,
    mut biggest_tsn_newly_acked: uint32_t,
    mut this_sack_lowest_newack: uint32_t,
    mut accum_moved: libc::c_int,
) {
    let mut tp1 = 0 as *mut sctp_tmit_chunk;
    let mut now = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut sending_seq = 0;
    let mut num_dests_sacked = 0i32;
    /*
     * select the sending_seq, this is either the next thing ready to be
     * sent but not transmitted, OR, the next seq we assign.
     */
    tp1 = (*stcb).asoc.send_queue.tqh_first;
    if tp1.is_null() {
        sending_seq = (*asoc).sending_seq
    } else {
        sending_seq = (*tp1).rec.data.tsn
    }
    /* CMT DAC algo: finding out if SACK is a mixed SACK */
    if (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
        && system_base_info.sctpsysctl.sctp_cmt_use_dac != 0
    {
        let mut net = 0 as *mut sctp_nets;
        net = (*asoc).nets.tqh_first;
        while !net.is_null() {
            if (*net).saw_newack != 0 {
                num_dests_sacked += 1
            }
            net = (*net).sctp_next.tqe_next
        }
    }
    if (*stcb).asoc.prsctp_supported != 0 {
        gettimeofday(&mut now, 0 as *mut timezone);
    }

    tp1 = (*asoc).sent_queue.tqh_first;
    while !tp1.is_null() {
        let mut strike_flag = 0i32;
        strike_flag = 0i32;
        if !((*tp1).no_fr_allowed != 0) {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0 {
                if (*tp1).sent < 4i32 {
                    sctp_log_fr(
                        biggest_tsn_newly_acked,
                        (*tp1).rec.data.tsn,
                        (*tp1).sent as uint32_t,
                        67i32,
                    );
                }
            }
            if (*tp1).rec.data.tsn < biggest_tsn_acked
                && biggest_tsn_acked.wrapping_sub((*tp1).rec.data.tsn) > (1u32) << 31i32
                || (*tp1).rec.data.tsn > biggest_tsn_acked
                    && (*tp1).rec.data.tsn.wrapping_sub(biggest_tsn_acked) < (1u32) << 31i32
                || (*tp1).sent == 0i32
            {
                /* done */
                break;
            } else {
                let mut current_block_202: u64;
                if (*stcb).asoc.prsctp_supported != 0 {
                    if (*tp1).flags as libc::c_int & 0xfi32 == 0x1i32 && (*tp1).sent < 10010i32 {
                        /* Is it expired? */
                        if if now.tv_sec == (*tp1).rec.data.timetodrop.tv_sec {
                            (now.tv_usec > (*tp1).rec.data.timetodrop.tv_usec) as libc::c_int
                        } else {
                            (now.tv_sec > (*tp1).rec.data.timetodrop.tv_sec) as libc::c_int
                        } != 0
                        {
                            /* Yes so drop it */
                            if !(*tp1).data.is_null() {
                                sctp_release_pr_sctp_chunk(stcb, tp1, 1u8, 0i32);
                            }
                            current_block_202 = 4808432441040389987;
                        } else {
                            current_block_202 = 6417057564578538666;
                        }
                    } else {
                        current_block_202 = 6417057564578538666;
                    }
                } else {
                    current_block_202 = 6417057564578538666;
                }
                match current_block_202 {
                    4808432441040389987 => {}
                    _ => {
                        if ((*tp1).rec.data.tsn < (*asoc).this_sack_highest_gap
                            && (*asoc)
                                .this_sack_highest_gap
                                .wrapping_sub((*tp1).rec.data.tsn)
                                > (1u32) << 31i32
                            || (*tp1).rec.data.tsn > (*asoc).this_sack_highest_gap
                                && (*tp1)
                                    .rec
                                    .data
                                    .tsn
                                    .wrapping_sub((*asoc).this_sack_highest_gap)
                                    < (1u32) << 31i32)
                            && !(accum_moved != 0
                                && (*asoc).fast_retran_loss_recovery as libc::c_int != 0)
                        {
                            break;
                        }
                        if (*tp1).sent >= 4i32 {
                            /* either a RESEND, ACKED, or MARKED */
                            /* skip */
                            if (*tp1).sent == 30010i32 {
                                /* Continue strikin FWD-TSN chunks */
                                (*tp1).rec.data.fwd_tsn_cnt =
                                    (*tp1).rec.data.fwd_tsn_cnt.wrapping_add(1)
                            }
                        } else if !(!(*tp1).whoTo.is_null()
                            && (*(*tp1).whoTo).saw_newack as libc::c_int == 0i32)
                        {
                            if !(!(*tp1).whoTo.is_null()
                                && ((*tp1).rec.data.tsn < (*(*tp1).whoTo).this_sack_highest_newack
                                    && (*(*tp1).whoTo)
                                        .this_sack_highest_newack
                                        .wrapping_sub((*tp1).rec.data.tsn)
                                        > (1u32) << 31i32
                                    || (*tp1).rec.data.tsn
                                        > (*(*tp1).whoTo).this_sack_highest_newack
                                        && (*tp1).rec.data.tsn.wrapping_sub(
                                            (*(*tp1).whoTo).this_sack_highest_newack,
                                        ) < (1u32) << 31i32)
                                && !(accum_moved != 0
                                    && (*asoc).fast_retran_loss_recovery as libc::c_int != 0))
                            {
                                /*
                                 * CMT : SFR algo (covers part of DAC and HTNA as well)
                                 */
                                /*
                                 * Here we check to see if we were have already done a FR
                                 * and if so we see if the biggest TSN we saw in the sack is
                                 * smaller than the recovery point. If so we don't strike
                                 * the tsn... otherwise we CAN strike the TSN.
                                 */
                                /*
                                 * @@@ JRI: Check for CMT
                                 * if (accum_moved && asoc->fast_retran_loss_recovery && (sctp_cmt_on_off == 0)) {
                                 */
                                if accum_moved != 0
                                    && (*asoc).fast_retran_loss_recovery as libc::c_int != 0
                                {
                                    /*
                                     * Strike the TSN if in fast-recovery and cum-ack
                                     * moved.
                                     */
                                    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0
                                    {
                                        sctp_log_fr(
                                            biggest_tsn_newly_acked,
                                            (*tp1).rec.data.tsn,
                                            (*tp1).sent as uint32_t,
                                            19i32,
                                        );
                                    }
                                    if (*tp1).sent < 4i32 {
                                        (*tp1).sent += 1
                                    }
                                    if (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
                                        && system_base_info.sctpsysctl.sctp_cmt_use_dac != 0
                                    {
                                        /*
                                         * CMT DAC algorithm: If SACK flag is set to
                                         * 0, then lowest_newack test will not pass
                                         * because it would have been set to the
                                         * cumack earlier. If not already to be
                                         * rtx'd, If not a mixed sack and if tp1 is
                                         * not between two sacked TSNs, then mark by
                                         * one more.
                                         * NOTE that we are marking by one additional time since the SACK DAC flag indicates that
                                         * two packets have been received after this missing TSN.
                                         */
                                        if (*tp1).sent < 4i32
                                            && num_dests_sacked == 1i32
                                            && (this_sack_lowest_newack < (*tp1).rec.data.tsn
                                                && (*tp1)
                                                    .rec
                                                    .data
                                                    .tsn
                                                    .wrapping_sub(this_sack_lowest_newack)
                                                    > (1u32) << 31i32
                                                || this_sack_lowest_newack > (*tp1).rec.data.tsn
                                                    && this_sack_lowest_newack
                                                        .wrapping_sub((*tp1).rec.data.tsn)
                                                        < (1u32) << 31i32)
                                        {
                                            if system_base_info.sctpsysctl.sctp_logging_level
                                                & 0x40u32
                                                != 0
                                            {
                                                sctp_log_fr(
                                                    (16i32 + num_dests_sacked) as uint32_t,
                                                    (*tp1).rec.data.tsn,
                                                    (*tp1).sent as uint32_t,
                                                    19i32,
                                                );
                                            }
                                            (*tp1).sent += 1
                                        }
                                    }
                                } else if (*tp1).rec.data.doing_fast_retransmit as libc::c_int != 0
                                    && (*asoc).sctp_cmt_on_off as libc::c_int == 0i32
                                {
                                    /*
                                     * For those that have done a FR we must take
                                     * special consideration if we strike. I.e the
                                     * biggest_newly_acked must be higher than the
                                     * sending_seq at the time we did the FR.
                                     */
                                    if biggest_tsn_newly_acked < (*tp1).rec.data.fast_retran_tsn
                                        && (*tp1)
                                            .rec
                                            .data
                                            .fast_retran_tsn
                                            .wrapping_sub(biggest_tsn_newly_acked)
                                            > (1u32) << 31i32
                                        || biggest_tsn_newly_acked > (*tp1).rec.data.fast_retran_tsn
                                            && biggest_tsn_newly_acked
                                                .wrapping_sub((*tp1).rec.data.fast_retran_tsn)
                                                < (1u32) << 31i32
                                        || biggest_tsn_newly_acked
                                            == (*tp1).rec.data.fast_retran_tsn
                                    {
                                        /*
                                         * Strike the TSN, since this ack is
                                         * beyond where things were when we
                                         * did a FR.
                                         */
                                        if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32
                                            != 0
                                        {
                                            sctp_log_fr(
                                                biggest_tsn_newly_acked,
                                                (*tp1).rec.data.tsn,
                                                (*tp1).sent as uint32_t,
                                                19i32,
                                            );
                                        }
                                        if (*tp1).sent < 4i32 {
                                            (*tp1).sent += 1
                                        }
                                        strike_flag = 1i32;
                                        if (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
                                            && system_base_info.sctpsysctl.sctp_cmt_use_dac != 0
                                        {
                                            /*
                                             * CMT DAC algorithm: If
                                             * SACK flag is set to 0,
                                             * then lowest_newack test
                                             * will not pass because it
                                             * would have been set to
                                             * the cumack earlier. If
                                             * not already to be rtx'd,
                                             * If not a mixed sack and
                                             * if tp1 is not between two
                                             * sacked TSNs, then mark by
                                             * one more.
                                             * NOTE that we are marking by one additional time since the SACK DAC flag indicates that
                                             * two packets have been received after this missing TSN.
                                             */
                                            if (*tp1).sent < 4i32
                                                && num_dests_sacked == 1i32
                                                && (this_sack_lowest_newack < (*tp1).rec.data.tsn
                                                    && (*tp1)
                                                        .rec
                                                        .data
                                                        .tsn
                                                        .wrapping_sub(this_sack_lowest_newack)
                                                        > (1u32) << 31i32
                                                    || this_sack_lowest_newack
                                                        > (*tp1).rec.data.tsn
                                                        && this_sack_lowest_newack
                                                            .wrapping_sub((*tp1).rec.data.tsn)
                                                            < (1u32) << 31i32)
                                            {
                                                if system_base_info.sctpsysctl.sctp_logging_level
                                                    & 0x40u32
                                                    != 0
                                                {
                                                    sctp_log_fr(
                                                        (32i32 + num_dests_sacked) as uint32_t,
                                                        (*tp1).rec.data.tsn,
                                                        (*tp1).sent as uint32_t,
                                                        19i32,
                                                    );
                                                }
                                                if (*tp1).sent < 4i32 {
                                                    (*tp1).sent += 1
                                                }
                                            }
                                        }
                                    }
                                /*
                                 * JRI: TODO: remove code for HTNA algo. CMT's
                                 * SFR algo covers HTNA.
                                 */
                                } else if !((*tp1).rec.data.tsn < biggest_tsn_newly_acked
                                    && biggest_tsn_newly_acked.wrapping_sub((*tp1).rec.data.tsn)
                                        > (1u32) << 31i32
                                    || (*tp1).rec.data.tsn > biggest_tsn_newly_acked
                                        && (*tp1)
                                            .rec
                                            .data
                                            .tsn
                                            .wrapping_sub(biggest_tsn_newly_acked)
                                            < (1u32) << 31i32)
                                {
                                    /* Strike the TSN */
                                    if system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0
                                    {
                                        sctp_log_fr(
                                            biggest_tsn_newly_acked,
                                            (*tp1).rec.data.tsn,
                                            (*tp1).sent as uint32_t,
                                            19i32,
                                        );
                                    }
                                    if (*tp1).sent < 4i32 {
                                        (*tp1).sent += 1
                                    }
                                    if (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
                                        && system_base_info.sctpsysctl.sctp_cmt_use_dac != 0
                                    {
                                        /*
                                         * CMT DAC algorithm: If SACK flag is set to
                                         * 0, then lowest_newack test will not pass
                                         * because it would have been set to the
                                         * cumack earlier. If not already to be
                                         * rtx'd, If not a mixed sack and if tp1 is
                                         * not between two sacked TSNs, then mark by
                                         * one more.
                                         * NOTE that we are marking by one additional time since the SACK DAC flag indicates that
                                         * two packets have been received after this missing TSN.
                                         */
                                        if (*tp1).sent < 4i32
                                            && num_dests_sacked == 1i32
                                            && (this_sack_lowest_newack < (*tp1).rec.data.tsn
                                                && (*tp1)
                                                    .rec
                                                    .data
                                                    .tsn
                                                    .wrapping_sub(this_sack_lowest_newack)
                                                    > (1u32) << 31i32
                                                || this_sack_lowest_newack > (*tp1).rec.data.tsn
                                                    && this_sack_lowest_newack
                                                        .wrapping_sub((*tp1).rec.data.tsn)
                                                        < (1u32) << 31i32)
                                        {
                                            if system_base_info.sctpsysctl.sctp_logging_level
                                                & 0x40u32
                                                != 0
                                            {
                                                sctp_log_fr(
                                                    (48i32 + num_dests_sacked) as uint32_t,
                                                    (*tp1).rec.data.tsn,
                                                    (*tp1).sent as uint32_t,
                                                    19i32,
                                                );
                                            }
                                            (*tp1).sent += 1
                                        }
                                    }
                                }
                                if (*tp1).sent == 4i32 {
                                    /* fix counts and things */
                                    if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0
                                    {
                                        sctp_misc_ints(
                                            110u8,
                                            if !(*tp1).whoTo.is_null() {
                                                (*(*tp1).whoTo).flight_size
                                            } else {
                                                0u32
                                            },
                                            (*tp1).book_size as uint32_t,
                                            (*tp1).whoTo as uint32_t,
                                            (*tp1).rec.data.tsn,
                                        );
                                    }
                                    if !(*tp1).whoTo.is_null() {
                                        (*(*tp1).whoTo).net_ack =
                                            (*(*tp1).whoTo).net_ack.wrapping_add(1);
                                        if (*(*tp1).whoTo).flight_size
                                            >= (*tp1).book_size as libc::c_uint
                                        {
                                            (*(*tp1).whoTo).flight_size = ((*(*tp1).whoTo)
                                                .flight_size)
                                                .wrapping_sub((*tp1).book_size as libc::c_uint)
                                        } else {
                                            (*(*tp1).whoTo).flight_size = 0u32
                                        }
                                        if (*stcb)
                                            .asoc
                                            .cc_functions
                                            .sctp_cwnd_update_tsn_acknowledged
                                            .is_some()
                                        {
                                            Some(
                                                (*stcb)
                                                    .asoc
                                                    .cc_functions
                                                    .sctp_cwnd_update_tsn_acknowledged
                                                    .expect("non-null function pointer"),
                                            )
                                            .expect("non-null function pointer")(
                                                (*tp1).whoTo, tp1
                                            );
                                        }
                                    }
                                    if system_base_info.sctpsysctl.sctp_logging_level & 0x100000u32
                                        != 0
                                    {
                                        sctp_log_rwnd(
                                            36u8,
                                            (*asoc).peers_rwnd,
                                            (*tp1).send_size as uint32_t,
                                            system_base_info.sctpsysctl.sctp_peer_chunk_oh,
                                        );
                                    }
                                    /* add back to the rwnd */
                                    (*asoc).peers_rwnd = ((*asoc).peers_rwnd).wrapping_add(
                                        ((*tp1).send_size as libc::c_uint).wrapping_add(
                                            system_base_info.sctpsysctl.sctp_peer_chunk_oh,
                                        ),
                                    );
                                    /* remove from the total flight */
                                    (*tp1).window_probe = 0u8;
                                    if (*stcb).asoc.total_flight >= (*tp1).book_size as libc::c_uint
                                    {
                                        (*stcb).asoc.total_flight = (*stcb)
                                            .asoc
                                            .total_flight
                                            .wrapping_sub((*tp1).book_size as libc::c_uint);
                                        if (*stcb).asoc.total_flight_count > 0u32 {
                                            (*stcb).asoc.total_flight_count =
                                                (*stcb).asoc.total_flight_count.wrapping_sub(1)
                                        }
                                    } else {
                                        (*stcb).asoc.total_flight = 0u32;
                                        (*stcb).asoc.total_flight_count = 0u32
                                    }
                                    if (*stcb).asoc.prsctp_supported as libc::c_int != 0
                                        && (*tp1).flags as libc::c_int & 0xfi32 == 0x3i32
                                    {
                                        /* Has it been retransmitted tv_sec times? - we store the retran count there. */
                                        if (*tp1).snd_count as libc::c_long
                                            > (*tp1).rec.data.timetodrop.tv_sec
                                        {
                                            /* Yes, so drop it */
                                            if !(*tp1).data.is_null() {
                                                sctp_release_pr_sctp_chunk(stcb, tp1, 1u8, 0i32);
                                            }
                                            /* Make sure to flag we had a FR */
                                            if !(*tp1).whoTo.is_null() {
                                                (*(*tp1).whoTo).net_ack =
                                                    (*(*tp1).whoTo).net_ack.wrapping_add(1)
                                            }
                                            current_block_202 = 4808432441040389987;
                                        } else {
                                            current_block_202 = 15650704408606443395;
                                        }
                                    } else {
                                        current_block_202 = 15650704408606443395;
                                    }
                                    match current_block_202 {
                                        4808432441040389987 => {}
                                        _ => {
                                            let mut tot_retrans = 0i32;
                                            let mut alt = 0 as *mut sctp_nets;
                                            if system_base_info.sctpsysctl.sctp_logging_level
                                                & 0x40u32
                                                != 0
                                            {
                                                sctp_log_fr(
                                                    (*tp1).rec.data.tsn,
                                                    (*tp1).snd_count as uint32_t,
                                                    0u32,
                                                    30i32,
                                                );
                                            }
                                            if strike_flag != 0 {
                                                /* This is a subsequent FR */
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut system_base_info
                                                        .sctpstat
                                                        .sctps_sendmultfastretrans,
                                                    1u32,
                                                ); /* CMT is OFF */
                                            }
                                            (*stcb).asoc.sent_queue_retran_cnt =
                                                (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1);
                                            if (*asoc).sctp_cmt_on_off as libc::c_int > 0i32 {
                                                /*
                                                 * CMT: Using RTX_SSTHRESH policy for CMT.
                                                 * If CMT is being used, then pick dest with
                                                 * largest ssthresh for any retransmission.
                                                 */
                                                (*tp1).no_fr_allowed = 1u8;
                                                alt = (*tp1).whoTo;
                                                /*sa_ignore NO_NULL_CHK*/
                                                if (*asoc).sctp_cmt_pf as libc::c_int > 0i32 {
                                                    /* JRS 5/18/07 - If CMT PF is on, use the PF version of find_alt_net() */
                                                    alt = sctp_find_alternate_net(stcb, alt, 2i32)
                                                } else {
                                                    /* JRS 5/18/07 - If only CMT is on, use the CMT version of find_alt_net() */
                                                    /*sa_ignore NO_NULL_CHK*/
                                                    alt = sctp_find_alternate_net(stcb, alt, 1i32)
                                                }
                                                if alt.is_null() {
                                                    alt = (*tp1).whoTo
                                                }
                                                /*
                                                 * CUCv2: If a different dest is picked for
                                                 * the retransmission, then new
                                                 * (rtx-)pseudo_cumack needs to be tracked
                                                 * for orig dest. Let CUCv2 track new (rtx-)
                                                 * pseudo-cumack always.
                                                 */
                                                if !(*tp1).whoTo.is_null() {
                                                    (*(*tp1).whoTo).find_pseudo_cumack = 1u8;
                                                    (*(*tp1).whoTo).find_rtx_pseudo_cumack = 1u8
                                                }
                                            } else {
                                                /*
                                                 * default behavior is to NOT retransmit
                                                 * FR's to an alternate. Armando Caro's
                                                 * paper details why.
                                                 */
                                                alt = (*tp1).whoTo
                                            }
                                            (*tp1).rec.data.doing_fast_retransmit = 1u8;
                                            tot_retrans += 1;
                                            /* mark the sending seq for possible subsequent FR's */
                                            /*
                                             * SCTP_PRINTF("Marking TSN for FR new value %x\n",
                                             * (uint32_t)tpi->rec.data.tsn);
                                             */
                                            if (*asoc).send_queue.tqh_first.is_null() {
                                                /*
                                                 * If the queue of send is empty then its
                                                 * the next sequence number that will be
                                                 * assigned so we subtract one from this to
                                                 * get the one we last sent.
                                                 */
                                                (*tp1).rec.data.fast_retran_tsn = sending_seq
                                            } else {
                                                let mut ttt = 0 as *mut sctp_tmit_chunk;
                                                ttt = (*asoc).send_queue.tqh_first;
                                                (*tp1).rec.data.fast_retran_tsn =
                                                    (*ttt).rec.data.tsn
                                            }
                                            if (*tp1).do_rtt != 0 {
                                                /*
                                                 * this guy had a RTO calculation pending on
                                                 * it, cancel it
                                                 */
                                                if !(*tp1).whoTo.is_null()
                                                    && (*(*tp1).whoTo).rto_needed as libc::c_int
                                                        == 0i32
                                                {
                                                    (*(*tp1).whoTo).rto_needed = 1u8
                                                }
                                                (*tp1).do_rtt = 0u8
                                            }
                                            if alt != (*tp1).whoTo {
                                                /* yes, there is an alternate. */
                                                if !(*tp1).whoTo.is_null() {
                                                    if ::std::intrinsics::atomic_xadd(
                                                        &mut (*(*tp1).whoTo).ref_count
                                                            as *mut libc::c_int,
                                                        -(1i32),
                                                    ) == 1i32
                                                    {
                                                        sctp_os_timer_stop(
                                                            &mut (*(*tp1).whoTo).rxt_timer.timer,
                                                        );
                                                        sctp_os_timer_stop(
                                                            &mut (*(*tp1).whoTo).pmtu_timer.timer,
                                                        );
                                                        sctp_os_timer_stop(
                                                            &mut (*(*tp1).whoTo).hb_timer.timer,
                                                        );
                                                        if !(*(*tp1).whoTo).ro.ro_rt.is_null() {
                                                            if (*(*(*tp1).whoTo).ro.ro_rt).rt_refcnt
                                                                <= 1i64
                                                            {
                                                                sctp_userspace_rtfree(
                                                                    (*(*tp1).whoTo).ro.ro_rt,
                                                                );
                                                            } else {
                                                                (*(*(*tp1).whoTo).ro.ro_rt)
                                                                    .rt_refcnt -= 1
                                                            }
                                                            (*(*tp1).whoTo).ro.ro_rt =
                                                                0 as *mut sctp_rtentry_t;
                                                            (*(*tp1).whoTo).ro.ro_rt =
                                                                0 as *mut sctp_rtentry_t
                                                        }
                                                        if (*(*tp1).whoTo).src_addr_selected != 0 {
                                                            sctp_free_ifa(
                                                                (*(*tp1).whoTo).ro._s_addr,
                                                            );
                                                            (*(*tp1).whoTo).ro._s_addr =
                                                                0 as *mut sctp_ifa
                                                        }
                                                        (*(*tp1).whoTo).src_addr_selected = 0u8;
                                                        (*(*tp1).whoTo).dest_state =
                                                            ((*(*tp1).whoTo).dest_state
                                                                as libc::c_int
                                                                & !(0x1i32))
                                                                as uint16_t;
                                                        free((*tp1).whoTo as *mut libc::c_void);
                                                        ::std::intrinsics::atomic_xsub(
                                                            &mut system_base_info
                                                                .sctppcbinfo
                                                                .ipi_count_raddr,
                                                            1u32,
                                                        );
                                                    }
                                                }
                                                /*sa_ignore FREED_MEMORY*/
                                                (*tp1).whoTo = alt;
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*alt).ref_count,
                                                    1i32,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /*
         * CMT: New acks were receieved for data sent to
         * this dest. But no new acks were seen for data
         * sent after tp1. Therefore, according to the SFR
         * algo for CMT, tp1 cannot be marked for FR using
         * this SACK. This step covers part of the DAC algo
         * and the HTNA algo as well.
         */
        tp1 = (*tp1).sctp_next.tqe_next
    }
}
#[no_mangle]
pub unsafe extern "C" fn sctp_try_advance_peer_ack_point(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
) -> *mut sctp_tmit_chunk {
    let mut tp1 = 0 as *mut sctp_tmit_chunk;
    let mut tp2 = 0 as *mut sctp_tmit_chunk;
    let mut a_adv = 0 as *mut sctp_tmit_chunk;
    if (*asoc).prsctp_supported as libc::c_int == 0i32 {
        return 0 as *mut sctp_tmit_chunk;
    }
    tp1 = (*asoc).sent_queue.tqh_first;
    while !tp1.is_null() && {
        tp2 = (*tp1).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if (*tp1).sent != 30010i32 && (*tp1).sent != 4i32 && (*tp1).sent != 40010i32 {
            /* no chance to advance, out of here */
            break;
        } else {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x10000000u32 != 0 {
                if (*tp1).sent == 30010i32 || (*tp1).sent == 40010i32 {
                    sctp_misc_ints(
                        123u8,
                        (*asoc).advanced_peer_ack_point,
                        (*tp1).rec.data.tsn,
                        0u32,
                        0u32,
                    );
                }
            }
            if !((*tp1).flags as libc::c_int & 0xfi32 != 0i32
                && (*tp1).flags as libc::c_int & 0xfi32 != 0xfi32)
            {
                /*
                 * We can't fwd-tsn past any that are reliable aka
                 * retransmitted until the asoc fails.
                 */
                break;
            } else {
                let mut now = timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                };
                let mut now_filled = 0i32;
                if now_filled == 0 {
                    gettimeofday(&mut now, 0 as *mut timezone);
                    now_filled = 1i32
                }
                /*
                 * now we got a chunk which is marked for another
                 * retransmission to a PR-stream but has run out its chances
                 * already maybe OR has been marked to skip now. Can we skip
                 * it if its a resend?
                 */
                if (*tp1).sent == 4i32 && (*tp1).flags as libc::c_int & 0xfi32 == 0x1i32 {
                    /*
                     * Now is this one marked for resend and its time is
                     * now up?
                     */
                    if if now.tv_sec == (*tp1).rec.data.timetodrop.tv_sec {
                        (now.tv_usec > (*tp1).rec.data.timetodrop.tv_usec) as libc::c_int
                    } else {
                        (now.tv_sec > (*tp1).rec.data.timetodrop.tv_sec) as libc::c_int
                    } != 0
                    {
                        /* Yes so drop it */
                        if !(*tp1).data.is_null() {
                            sctp_release_pr_sctp_chunk(stcb, tp1, 1u8, 0i32);
                        }
                    } else {
                        /*
                         * No, we are done when hit one for resend
                         * whos time as not expired.
                         */
                        break;
                    }
                }
                /*
                 * Ok now if this chunk is marked to drop it we can clean up
                 * the chunk, advance our peer ack point and we can check
                 * the next chunk.
                 */
                if !((*tp1).sent == 30010i32 || (*tp1).sent == 40010i32) {
                    break;
                }
                /* advance PeerAckPoint goes forward */
                if (*tp1).rec.data.tsn < (*asoc).advanced_peer_ack_point
                    && (*asoc)
                        .advanced_peer_ack_point
                        .wrapping_sub((*tp1).rec.data.tsn)
                        > (1u32) << 31i32
                    || (*tp1).rec.data.tsn > (*asoc).advanced_peer_ack_point
                        && (*tp1)
                            .rec
                            .data
                            .tsn
                            .wrapping_sub((*asoc).advanced_peer_ack_point)
                            < (1u32) << 31i32
                {
                    (*asoc).advanced_peer_ack_point = (*tp1).rec.data.tsn;
                    a_adv = tp1
                } else if (*tp1).rec.data.tsn == (*asoc).advanced_peer_ack_point {
                    /* No update but we do save the chk */
                    a_adv = tp1
                }
                tp1 = tp2
            }
        }
    }
    return a_adv;
}
unsafe extern "C" fn sctp_fs_audit(mut asoc: *mut sctp_association) -> libc::c_int {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut inflight = 0i32;
    let mut resend = 0i32;
    let mut inbetween = 0i32;
    let mut acked = 0i32;
    let mut above = 0i32;
    let mut ret = 0;
    let mut entry_flight = 0;
    let mut entry_cnt = 0;
    ret = 0i32;
    entry_flight = (*asoc).total_flight as libc::c_int;
    entry_cnt = (*asoc).total_flight_count as libc::c_int;
    if (*asoc).pr_sctp_cnt >= (*asoc).sent_queue_cnt {
        return 0i32;
    }
    chk = (*asoc).sent_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).sent < 4i32 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Chk TSN: %u size: %d inflight cnt: %d\n\x00" as *const u8
                        as *const libc::c_char,
                    (*chk).rec.data.tsn,
                    (*chk).send_size as libc::c_int,
                    (*chk).snd_count as libc::c_int,
                );
            }
            inflight += 1
        } else if (*chk).sent == 4i32 {
            resend += 1
        } else if (*chk).sent < 10010i32 {
            inbetween += 1
        } else if (*chk).sent > 10010i32 {
            above += 1
        } else {
            acked += 1
        }
        chk = (*chk).sctp_next.tqe_next
    }
    if inflight > 0i32 || inbetween > 0i32 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"asoc->total_flight: %d cnt: %d\n\x00" as *const u8 as *const libc::c_char,
                entry_flight,
                entry_cnt,
            );
        }
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Flight size-express incorrect F: %d I: %d R: %d Ab: %d ACK: %d\n\x00" as *const u8
                    as *const libc::c_char,
                inflight,
                inbetween,
                resend,
                above,
                acked,
            );
        }
        ret = 1i32
    }
    return ret;
}
unsafe extern "C" fn sctp_window_probe_recovery(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut tp1: *mut sctp_tmit_chunk,
) {
    (*tp1).window_probe = 0u8;
    if (*tp1).sent >= 10010i32 || (*tp1).data.is_null() {
        /* TSN's skipped we do NOT move back. */
        sctp_misc_ints(
            122u8,
            if !(*tp1).whoTo.is_null() {
                (*(*tp1).whoTo).flight_size
            } else {
                0u32
            },
            (*tp1).book_size as uint32_t,
            (*tp1).whoTo as uint32_t,
            (*tp1).rec.data.tsn,
        );
        return;
    }
    /* First setup this by shrinking flight */
    if (*stcb)
        .asoc
        .cc_functions
        .sctp_cwnd_update_tsn_acknowledged
        .is_some()
    {
        Some(
            (*stcb)
                .asoc
                .cc_functions
                .sctp_cwnd_update_tsn_acknowledged
                .expect("non-null function pointer"),
        )
        .expect("non-null function pointer")((*tp1).whoTo, tp1);
    }
    if (*(*tp1).whoTo).flight_size >= (*tp1).book_size as libc::c_uint {
        (*(*tp1).whoTo).flight_size =
            ((*(*tp1).whoTo).flight_size).wrapping_sub((*tp1).book_size as libc::c_uint)
    } else {
        (*(*tp1).whoTo).flight_size = 0u32
    }
    (*tp1).window_probe = 0u8;
    if (*stcb).asoc.total_flight >= (*tp1).book_size as libc::c_uint {
        (*stcb).asoc.total_flight = (*stcb)
            .asoc
            .total_flight
            .wrapping_sub((*tp1).book_size as libc::c_uint);
        if (*stcb).asoc.total_flight_count > 0u32 {
            (*stcb).asoc.total_flight_count = (*stcb).asoc.total_flight_count.wrapping_sub(1)
        }
    } else {
        (*stcb).asoc.total_flight = 0u32;
        (*stcb).asoc.total_flight_count = 0u32
    }
    /* Now mark for resend */
    (*tp1).sent = 4i32;
    (*asoc).sent_queue_retran_cnt = (*asoc).sent_queue_retran_cnt.wrapping_add(1);
    if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
        sctp_misc_ints(
            113u8,
            (*(*tp1).whoTo).flight_size,
            (*tp1).book_size as uint32_t,
            (*tp1).whoTo as uint32_t,
            (*tp1).rec.data.tsn,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_express_handle_sack(
    mut stcb: *mut sctp_tcb,
    mut cumack: uint32_t,
    mut rwnd: uint32_t,
    mut abort_now: *mut libc::c_int,
    mut ecne_seen: libc::c_int,
) {
    let mut asoc = 0 as *mut sctp_association;
    let mut old_rwnd = 0;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x200000u32 != 0 {
        sctp_misc_ints(
            118u8,
            cumack,
            rwnd,
            (*stcb).asoc.last_acked_seq,
            (*stcb).asoc.peers_rwnd,
        );
    }
    asoc = &mut (*stcb).asoc;
    old_rwnd = (*asoc).peers_rwnd;
    if (*asoc).last_acked_seq < cumack
        && cumack.wrapping_sub((*asoc).last_acked_seq) > (1u32) << 31i32
        || (*asoc).last_acked_seq > cumack
            && (*asoc).last_acked_seq.wrapping_sub(cumack) < (1u32) << 31i32
    {
        /* old ack */
        return;
    } else {
        let mut net = 0 as *mut sctp_nets;
        let mut tp1 = 0 as *mut sctp_tmit_chunk;
        let mut win_probe_recovery = 0i32;
        if (*asoc).last_acked_seq == cumack {
            /* Window update sack */
            (*asoc).peers_rwnd = if rwnd
                > (*asoc).total_flight.wrapping_add(
                    (*asoc)
                        .total_flight_count
                        .wrapping_mul(system_base_info.sctpsysctl.sctp_peer_chunk_oh),
                ) {
                rwnd.wrapping_sub(
                    (*asoc).total_flight.wrapping_add(
                        (*asoc)
                            .total_flight_count
                            .wrapping_mul(system_base_info.sctpsysctl.sctp_peer_chunk_oh),
                    ),
                )
            } else {
                0u32
            };
            if (*asoc).peers_rwnd < (*(*stcb).sctp_ep).sctp_ep.sctp_sws_sender {
                /* SWS sender side engages */
                (*asoc).peers_rwnd = 0u32
            }
            if !((*asoc).peers_rwnd > old_rwnd) {
                return;
            }
        } else {
            let mut send_s = 0;
            net = (*asoc).nets.tqh_first;
            while !net.is_null() {
                if cumack < (*net).cwr_window_tsn
                    && (*net).cwr_window_tsn.wrapping_sub(cumack) > (1u32) << 31i32
                    || cumack > (*net).cwr_window_tsn
                        && cumack.wrapping_sub((*net).cwr_window_tsn) < (1u32) << 31i32
                {
                    /* Drag along the window_tsn for cwr's */
                    (*net).cwr_window_tsn = cumack
                }
                (*net).prev_cwnd = (*net).cwnd;
                (*net).net_ack = 0u32;
                (*net).net_ack2 = 0u32;
                /*
                 * CMT: Reset CUC and Fast recovery algo variables before
                 * SACK processing
                 */
                (*net).new_pseudo_cumack = 0u8;
                (*net).will_exit_fast_recovery = 0u8;
                if (*stcb)
                    .asoc
                    .cc_functions
                    .sctp_cwnd_prepare_net_for_sack
                    .is_some()
                {
                    Some(
                        (*stcb)
                            .asoc
                            .cc_functions
                            .sctp_cwnd_prepare_net_for_sack
                            .expect("non-null function pointer"),
                    )
                    .expect("non-null function pointer")(stcb, net);
                }
                net = (*net).sctp_next.tqe_next
            }
            if !(*asoc).sent_queue.tqh_first.is_null() {
                tp1 = *(*((*asoc).sent_queue.tqh_last as *mut sctpchunk_listhead)).tqh_last;
                send_s = (*tp1).rec.data.tsn.wrapping_add(1u32)
            } else {
                send_s = (*asoc).sending_seq
            }
            if cumack < send_s && send_s.wrapping_sub(cumack) > (1u32) << 31i32
                || cumack > send_s && cumack.wrapping_sub(send_s) < (1u32) << 31i32
                || cumack == send_s
            {
                let mut op_err = 0 as *mut mbuf;
                let mut msg = [0; 128];
                *abort_now = 1i32;
                /* XXX */
                snprintf(
                    msg.as_mut_ptr(),
                    ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                    b"Cum ack %8.8x greater or equal than TSN %8.8x\x00" as *const u8
                        as *const libc::c_char,
                    cumack,
                    send_s,
                );
                op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
                (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x15i32) as uint32_t;
                sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
                return;
            }
            (*asoc).this_sack_highest_gap = cumack;
            if system_base_info.sctpsysctl.sctp_logging_level & 0x2000000u32 != 0 {
                sctp_misc_ints(
                    120u8,
                    (*stcb).asoc.overall_error_count,
                    0u32,
                    0x30000000u32,
                    4021u32,
                );
            }
            (*stcb).asoc.overall_error_count = 0u32;
            if cumack < (*asoc).last_acked_seq
                && (*asoc).last_acked_seq.wrapping_sub(cumack) > (1u32) << 31i32
                || cumack > (*asoc).last_acked_seq
                    && cumack.wrapping_sub((*asoc).last_acked_seq) < (1u32) << 31i32
            {
                let mut tp2 = 0 as *mut sctp_tmit_chunk;
                tp1 = (*asoc).sent_queue.tqh_first;
                while !tp1.is_null() && {
                    tp2 = (*tp1).sctp_next.tqe_next;
                    (1i32) != 0
                } {
                    if !(cumack < (*tp1).rec.data.tsn
                        && (*tp1).rec.data.tsn.wrapping_sub(cumack) > (1u32) << 31i32
                        || cumack > (*tp1).rec.data.tsn
                            && cumack.wrapping_sub((*tp1).rec.data.tsn) < (1u32) << 31i32
                        || cumack == (*tp1).rec.data.tsn)
                    {
                        break;
                    }
                    if (*tp1).sent == 0i32 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"Warning, an unsent is now acked?\n\x00" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    }
                    if (*tp1).sent < 10010i32 {
                        /*
                         * If it is less than ACKED, it is
                         * now no-longer in flight. Higher
                         * values may occur during marking
                         */
                        if (*tp1).sent < 4i32 {
                            if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
                                sctp_misc_ints(
                                    107u8,
                                    (*(*tp1).whoTo).flight_size,
                                    (*tp1).book_size as uint32_t,
                                    (*tp1).whoTo as uint32_t,
                                    (*tp1).rec.data.tsn,
                                );
                            }
                            if (*(*tp1).whoTo).flight_size >= (*tp1).book_size as libc::c_uint {
                                (*(*tp1).whoTo).flight_size = ((*(*tp1).whoTo).flight_size)
                                    .wrapping_sub((*tp1).book_size as libc::c_uint)
                            } else {
                                (*(*tp1).whoTo).flight_size = 0u32
                            }
                            if (*stcb)
                                .asoc
                                .cc_functions
                                .sctp_cwnd_update_tsn_acknowledged
                                .is_some()
                            {
                                Some(
                                    (*stcb)
                                        .asoc
                                        .cc_functions
                                        .sctp_cwnd_update_tsn_acknowledged
                                        .expect("non-null function pointer"),
                                )
                                .expect("non-null function pointer")(
                                    (*tp1).whoTo, tp1
                                );
                            }
                            /* sa_ignore NO_NULL_CHK */
                            (*tp1).window_probe = 0u8;
                            if (*stcb).asoc.total_flight >= (*tp1).book_size as libc::c_uint {
                                (*stcb).asoc.total_flight = (*stcb)
                                    .asoc
                                    .total_flight
                                    .wrapping_sub((*tp1).book_size as libc::c_uint);
                                if (*stcb).asoc.total_flight_count > 0u32 {
                                    (*stcb).asoc.total_flight_count =
                                        (*stcb).asoc.total_flight_count.wrapping_sub(1)
                                }
                            } else {
                                (*stcb).asoc.total_flight = 0u32;
                                (*stcb).asoc.total_flight_count = 0u32
                            }
                        }
                        (*(*tp1).whoTo).net_ack = (*(*tp1).whoTo)
                            .net_ack
                            .wrapping_add((*tp1).send_size as libc::c_uint);
                        if ((*tp1).snd_count as libc::c_int) < 2i32 {
                            /*
                             * True non-retransmitted
                             * chunk
                             */
                            (*(*tp1).whoTo).net_ack2 = (*(*tp1).whoTo)
                                .net_ack2
                                .wrapping_add((*tp1).send_size as libc::c_uint);
                            /* update RTO too? */
                            if (*tp1).do_rtt != 0 {
                                let mut rto_ok = 1i32;
                                if rto_ok != 0
                                    && sctp_calculate_rto(
                                        stcb,
                                        &mut (*stcb).asoc,
                                        (*tp1).whoTo,
                                        &mut (*tp1).sent_rcv_time,
                                        1i32,
                                    ) != 0
                                {
                                    rto_ok = 0i32
                                }
                                if (*(*tp1).whoTo).rto_needed as libc::c_int == 0i32 {
                                    (*(*tp1).whoTo).rto_needed = 1u8
                                }
                                (*tp1).do_rtt = 0u8
                            }
                        }
                        /*
                         * CMT: CUCv2 algorithm. From the
                         * cumack'd TSNs, for each TSN being
                         * acked for the first time, set the
                         * following variables for the
                         * corresp destination.
                         * new_pseudo_cumack will trigger a
                         * cwnd update.
                         * find_(rtx_)pseudo_cumack will
                         * trigger search for the next
                         * expected (rtx-)pseudo-cumack.
                         */
                        (*(*tp1).whoTo).new_pseudo_cumack = 1u8;
                        (*(*tp1).whoTo).find_pseudo_cumack = 1u8;
                        (*(*tp1).whoTo).find_rtx_pseudo_cumack = 1u8;
                        if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                            /* sa_ignore NO_NULL_CHK */
                            sctp_log_cwnd(
                                stcb,
                                (*tp1).whoTo,
                                (*tp1).rec.data.tsn as libc::c_int,
                                64u8,
                            );
                        }
                    }
                    if (*tp1).sent == 4i32 {
                        if (*asoc).sent_queue_retran_cnt > 0u32 {
                            (*asoc).sent_queue_retran_cnt =
                                (*asoc).sent_queue_retran_cnt.wrapping_sub(1)
                        } else {
                            (*asoc).sent_queue_retran_cnt = 0u32
                        }
                    }
                    if (*tp1).rec.data.chunk_was_revoked != 0 {
                        /* deflate the cwnd */
                        (*(*tp1).whoTo).cwnd =
                            ((*(*tp1).whoTo).cwnd).wrapping_sub((*tp1).book_size as libc::c_uint);
                        (*tp1).rec.data.chunk_was_revoked = 0u8
                    }
                    if (*tp1).sent != 40010i32 {
                        if (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize)).chunks_on_queues
                            > 0u32
                        {
                            let ref mut fresh8 =
                                (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize))
                                    .chunks_on_queues;
                            *fresh8 = (*fresh8).wrapping_sub(1)
                        }
                    }
                    if (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize)).chunks_on_queues
                        == 0u32
                        && (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize)).state
                            as libc::c_int
                            == 0x3i32
                        && (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize))
                            .outqueue
                            .tqh_first
                            .is_null()
                    {
                        (*asoc).trigger_reset = 1u8
                    }
                    if !(*tp1).sctp_next.tqe_next.is_null() {
                        (*(*tp1).sctp_next.tqe_next).sctp_next.tqe_prev = (*tp1).sctp_next.tqe_prev
                    } else {
                        (*asoc).sent_queue.tqh_last = (*tp1).sctp_next.tqe_prev
                    }
                    *(*tp1).sctp_next.tqe_prev = (*tp1).sctp_next.tqe_next;
                    if !(*tp1).data.is_null() {
                        /* sa_ignore NO_NULL_CHK */
                        if !(*tp1).data.is_null() {
                            ::std::intrinsics::atomic_xsub(&mut (*asoc).chunks_on_out_queue, 1u32);
                            if (*asoc).total_output_queue_size >= (*tp1).book_size as libc::c_uint {
                                ::std::intrinsics::atomic_xsub(
                                    &mut (*asoc).total_output_queue_size,
                                    (*tp1).book_size as uint32_t,
                                );
                            } else {
                                (*asoc).total_output_queue_size = 0u32
                            }
                            if !(*stcb).sctp_socket.is_null()
                                && ((*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
                                    || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0)
                            {
                                if (*(*stcb).sctp_socket).so_snd.sb_cc
                                    >= (*tp1).book_size as libc::c_uint
                                {
                                    ::std::intrinsics::atomic_xsub(
                                        &mut (*(*stcb).sctp_socket).so_snd.sb_cc,
                                        (*tp1).book_size as u_int,
                                    );
                                } else {
                                    (*(*stcb).sctp_socket).so_snd.sb_cc = 0u32
                                }
                            }
                        }
                        m_freem((*tp1).data);
                        (*tp1).data = 0 as *mut mbuf
                    }
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x4000u32 != 0 {
                        sctp_log_sack(
                            (*asoc).last_acked_seq,
                            cumack,
                            (*tp1).rec.data.tsn,
                            0u16,
                            0u16,
                            71i32,
                        );
                    }
                    (*asoc).sent_queue_cnt = (*asoc).sent_queue_cnt.wrapping_sub(1);
                    if (*tp1).holds_key_ref != 0 {
                        sctp_auth_key_release(stcb, (*tp1).auth_keyid, 0i32);
                        (*tp1).holds_key_ref = 0u8
                    }
                    if !stcb.is_null() {
                        if !(*tp1).whoTo.is_null() {
                            if !(*tp1).whoTo.is_null() {
                                if ::std::intrinsics::atomic_xadd(
                                    &mut (*(*tp1).whoTo).ref_count as *mut libc::c_int,
                                    -(1i32),
                                ) == 1i32
                                {
                                    sctp_os_timer_stop(&mut (*(*tp1).whoTo).rxt_timer.timer);
                                    sctp_os_timer_stop(&mut (*(*tp1).whoTo).pmtu_timer.timer);
                                    sctp_os_timer_stop(&mut (*(*tp1).whoTo).hb_timer.timer);
                                    if !(*(*tp1).whoTo).ro.ro_rt.is_null() {
                                        if (*(*(*tp1).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                                            sctp_userspace_rtfree((*(*tp1).whoTo).ro.ro_rt);
                                        } else {
                                            (*(*(*tp1).whoTo).ro.ro_rt).rt_refcnt -= 1
                                        }
                                        (*(*tp1).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                                        (*(*tp1).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                                    }
                                    if (*(*tp1).whoTo).src_addr_selected != 0 {
                                        sctp_free_ifa((*(*tp1).whoTo).ro._s_addr);
                                        (*(*tp1).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                                    }
                                    (*(*tp1).whoTo).src_addr_selected = 0u8;
                                    (*(*tp1).whoTo).dest_state =
                                        ((*(*tp1).whoTo).dest_state as libc::c_int & !(0x1i32))
                                            as uint16_t;
                                    free((*tp1).whoTo as *mut libc::c_void);
                                    ::std::intrinsics::atomic_xsub(
                                        &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                        1u32,
                                    );
                                }
                            }
                            (*tp1).whoTo = 0 as *mut sctp_nets
                        }
                        if (*stcb).asoc.free_chunk_cnt as libc::c_uint
                            > system_base_info.sctpsysctl.sctp_asoc_free_resc_limit
                            || system_base_info.sctppcbinfo.ipi_free_chunks
                                > system_base_info.sctpsysctl.sctp_system_free_resc_limit
                        {
                            free(tp1 as *mut libc::c_void);
                            ::std::intrinsics::atomic_xsub(
                                &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                                1u32,
                            );
                        } else {
                            (*tp1).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
                            (*tp1).sctp_next.tqe_prev = (*stcb).asoc.free_chunks.tqh_last;
                            *(*stcb).asoc.free_chunks.tqh_last = tp1;
                            (*stcb).asoc.free_chunks.tqh_last = &mut (*tp1).sctp_next.tqe_next;
                            (*stcb).asoc.free_chunk_cnt =
                                (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
                            ::std::intrinsics::atomic_xadd(
                                &mut system_base_info.sctppcbinfo.ipi_free_chunks,
                                1u32,
                            );
                        }
                    } else {
                        free(tp1 as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                            1u32,
                        );
                    }
                    tp1 = tp2
                }
            }
            if (*(*stcb).sctp_ep).recv_callback.is_some() {
                if !(*stcb).sctp_socket.is_null() {
                    let mut inqueue_bytes = 0;
                    let mut sb_free_now = 0;
                    let mut inp = 0 as *mut sctp_inpcb;
                    inp = (*stcb).sctp_ep;
                    inqueue_bytes =
                        ((*stcb).asoc.total_output_queue_size as libc::c_ulong).wrapping_sub(
                            ((*stcb).asoc.chunks_on_out_queue as libc::c_ulong).wrapping_mul(
                                ::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong,
                            ),
                        ) as uint32_t;
                    sb_free_now = (*(*stcb).sctp_socket)
                        .so_snd
                        .sb_hiwat
                        .wrapping_sub(inqueue_bytes.wrapping_add((*stcb).asoc.sb_send_resv));
                    /* check if the amount free in the send socket buffer crossed the threshold */
                    if (*inp).send_callback.is_some()
                        && ((*inp).send_sb_threshold > 0u32
                            && sb_free_now >= (*inp).send_sb_threshold
                            && (*stcb).asoc.chunks_on_out_queue
                                <= system_base_info.sctpsysctl.sctp_max_chunks_on_queue
                            || (*inp).send_sb_threshold == 0u32)
                    {
                        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        (*inp).send_callback.expect("non-null function pointer")(
                            (*stcb).sctp_socket,
                            sb_free_now,
                        );
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                        ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.refcnt, 1u32);
                    }
                }
            } else if !(*stcb).sctp_socket.is_null() {
                pthread_mutex_lock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
                if system_base_info.sctpsysctl.sctp_logging_level & 0x40000u32 != 0 {
                    /* sa_ignore NO_NULL_CHK */
                    sctp_wakeup_log(stcb, 1u32, 74i32);
                }
                if (*(*stcb).sctp_ep).sctp_flags & 0x800000u32 != 0 {
                    pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
                    (*(*stcb).sctp_ep).sctp_flags |= 0x1000000u32
                } else if (*(*stcb).sctp_socket).so_snd.sb_flags as libc::c_int
                    & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                    != 0i32
                {
                    sowakeup((*stcb).sctp_socket, &mut (*(*stcb).sctp_socket).so_snd);
                } else {
                    pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
                }
            } else if system_base_info.sctpsysctl.sctp_logging_level & 0x40000u32 != 0 {
                sctp_wakeup_log(stcb, 1u32, 76i32);
            }
            /* JRS - Use the congestion control given in the CC module */
            if (*asoc).last_acked_seq != cumack && ecne_seen == 0i32 {
                net = (*asoc).nets.tqh_first;
                while !net.is_null() {
                    if (*net).net_ack2 > 0u32 {
                        /*
                         * Karn's rule applies to clearing error count, this
                         * is optional.
                         */
                        (*net).error_count = 0u16;
                        if (*net).dest_state as libc::c_int & 0x1i32 == 0 {
                            /* addr came good */
                            (*net).dest_state =
                                ((*net).dest_state as libc::c_int | 0x1i32) as uint16_t;
                            sctp_ulp_notify(4u32, stcb, 0u32, net as *mut libc::c_void, 0i32);
                        }
                        if net == (*stcb).asoc.primary_destination {
                            if !(*stcb).asoc.alternate.is_null() {
                                /* release the alternate, primary is good */
                                if !(*stcb).asoc.alternate.is_null() {
                                    if ::std::intrinsics::atomic_xadd(
                                        &mut (*(*stcb).asoc.alternate).ref_count
                                            as *mut libc::c_int,
                                        -(1i32),
                                    ) == 1i32
                                    {
                                        sctp_os_timer_stop(
                                            &mut (*(*stcb).asoc.alternate).rxt_timer.timer,
                                        );
                                        sctp_os_timer_stop(
                                            &mut (*(*stcb).asoc.alternate).pmtu_timer.timer,
                                        );
                                        sctp_os_timer_stop(
                                            &mut (*(*stcb).asoc.alternate).hb_timer.timer,
                                        );
                                        if !(*(*stcb).asoc.alternate).ro.ro_rt.is_null() {
                                            if (*(*(*stcb).asoc.alternate).ro.ro_rt).rt_refcnt
                                                <= 1i64
                                            {
                                                sctp_userspace_rtfree(
                                                    (*(*stcb).asoc.alternate).ro.ro_rt,
                                                );
                                            } else {
                                                (*(*(*stcb).asoc.alternate).ro.ro_rt).rt_refcnt -= 1
                                            }
                                            (*(*stcb).asoc.alternate).ro.ro_rt =
                                                0 as *mut sctp_rtentry_t;
                                            (*(*stcb).asoc.alternate).ro.ro_rt =
                                                0 as *mut sctp_rtentry_t
                                        }
                                        if (*(*stcb).asoc.alternate).src_addr_selected != 0 {
                                            sctp_free_ifa((*(*stcb).asoc.alternate).ro._s_addr);
                                            (*(*stcb).asoc.alternate).ro._s_addr =
                                                0 as *mut sctp_ifa
                                        }
                                        (*(*stcb).asoc.alternate).src_addr_selected = 0u8;
                                        (*(*stcb).asoc.alternate).dest_state =
                                            ((*(*stcb).asoc.alternate).dest_state as libc::c_int
                                                & !(0x1i32))
                                                as uint16_t;
                                        free((*stcb).asoc.alternate as *mut libc::c_void);
                                        ::std::intrinsics::atomic_xsub(
                                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                            1u32,
                                        );
                                    }
                                }
                                (*stcb).asoc.alternate = 0 as *mut sctp_nets
                            }
                        }
                        if (*net).dest_state as libc::c_int & 0x800i32 != 0 {
                            (*net).dest_state =
                                ((*net).dest_state as libc::c_int & !(0x800i32)) as uint16_t;
                            sctp_timer_stop(
                                5i32,
                                (*stcb).sctp_ep,
                                stcb,
                                net,
                                (0x30000000i32 + 0x16i32) as uint32_t,
                            );
                            sctp_timer_start(5i32, (*stcb).sctp_ep, stcb, net);
                            (*asoc)
                                .cc_functions
                                .sctp_cwnd_update_exit_pf
                                .expect("non-null function pointer")(
                                stcb, net
                            );
                            /* Done with this net */
                            (*net).net_ack = 0u32
                        }
                        /* restore any doubled timers */
                        (*net).RTO = (((*net).lastsa >> 3i32) + (*net).lastsv) as libc::c_uint;
                        if (*net).RTO < (*stcb).asoc.minrto {
                            (*net).RTO = (*stcb).asoc.minrto
                        }
                        if (*net).RTO > (*stcb).asoc.maxrto {
                            (*net).RTO = (*stcb).asoc.maxrto
                        }
                    }
                    net = (*net).sctp_next.tqe_next
                }
                (*asoc)
                    .cc_functions
                    .sctp_cwnd_update_after_sack
                    .expect("non-null function pointer")(
                    stcb, asoc, 1i32, 0i32, 0i32
                );
            }
            (*asoc).last_acked_seq = cumack;
            if (*asoc).sent_queue.tqh_first.is_null() {
                /* nothing left in-flight */
                net = (*asoc).nets.tqh_first;
                while !net.is_null() {
                    (*net).flight_size = 0u32;
                    (*net).partial_bytes_acked = 0u32;
                    net = (*net).sctp_next.tqe_next
                }
                (*asoc).total_flight = 0u32;
                (*asoc).total_flight_count = 0u32
            }
            /* RWND update */
            (*asoc).peers_rwnd = if rwnd
                > (*asoc).total_flight.wrapping_add(
                    (*asoc)
                        .total_flight_count
                        .wrapping_mul(system_base_info.sctpsysctl.sctp_peer_chunk_oh),
                ) {
                rwnd.wrapping_sub(
                    (*asoc).total_flight.wrapping_add(
                        (*asoc)
                            .total_flight_count
                            .wrapping_mul(system_base_info.sctpsysctl.sctp_peer_chunk_oh),
                    ),
                )
            } else {
                0u32
            };
            if (*asoc).peers_rwnd < (*(*stcb).sctp_ep).sctp_ep.sctp_sws_sender {
                /* SWS sender side engages */
                (*asoc).peers_rwnd = 0u32
            }
            if (*asoc).peers_rwnd > old_rwnd {
                win_probe_recovery = 1i32
            }
        }
        loop
        /* Now assure a timer where data is queued at */
        {
            let mut win_probe_recovered = 0i32;
            let mut j = 0;
            let mut done_once = 0i32;
            j = 0i32;
            net = (*asoc).nets.tqh_first;
            while !net.is_null() {
                if win_probe_recovery != 0 && (*net).window_probe as libc::c_int != 0 {
                    win_probe_recovered = 1i32;
                    /*
                     * Find first chunk that was used with window probe
                     * and clear the sent
                     */
                    /* sa_ignore FREED_MEMORY */
                    tp1 = (*asoc).sent_queue.tqh_first;
                    while !tp1.is_null() {
                        if (*tp1).window_probe != 0 {
                            /* move back to data send queue */
                            sctp_window_probe_recovery(stcb, asoc, tp1);
                            break;
                        } else {
                            tp1 = (*tp1).sctp_next.tqe_next
                        }
                    }
                }
                if (*net).flight_size != 0 {
                    j += 1;
                    sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, net);
                    if (*net).window_probe != 0 {
                        (*net).window_probe = 0u8
                    }
                } else if (*net).window_probe != 0 {
                    /* In window probes we must assure a timer is still running there */
                    (*net).window_probe = 0u8;
                    if (*net).rxt_timer.timer.c_flags & 0x4i32 == 0 {
                        sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, net);
                    }
                } else if (*net).rxt_timer.timer.c_flags & 0x4i32 != 0 {
                    sctp_timer_stop(
                        1i32,
                        (*stcb).sctp_ep,
                        stcb,
                        net,
                        (0x30000000i32 + 0x17i32) as uint32_t,
                    );
                }
                net = (*net).sctp_next.tqe_next
            }
            if !(j == 0i32
                && !(*asoc).sent_queue.tqh_first.is_null()
                && (*asoc).sent_queue_retran_cnt == 0u32
                && win_probe_recovered == 0i32
                && done_once == 0i32)
            {
                break;
            }
            /* huh, this should not happen unless all packets
             * are PR-SCTP and marked to skip of course.
             */
            if sctp_fs_audit(asoc) != 0 {
                net = (*asoc).nets.tqh_first;
                while !net.is_null() {
                    (*net).flight_size = 0u32;
                    net = (*net).sctp_next.tqe_next
                }
                (*asoc).total_flight = 0u32;
                (*asoc).total_flight_count = 0u32;
                (*asoc).sent_queue_retran_cnt = 0u32;
                tp1 = (*asoc).sent_queue.tqh_first;
                while !tp1.is_null() {
                    if (*tp1).sent < 4i32 {
                        (*(*tp1).whoTo).flight_size = ((*(*tp1).whoTo).flight_size)
                            .wrapping_add((*tp1).book_size as libc::c_uint);
                        (*stcb).asoc.total_flight_count =
                            (*stcb).asoc.total_flight_count.wrapping_add(1);
                        (*stcb).asoc.total_flight = (*stcb)
                            .asoc
                            .total_flight
                            .wrapping_add((*tp1).book_size as libc::c_uint)
                    } else if (*tp1).sent == 4i32 {
                        (*asoc).sent_queue_retran_cnt =
                            (*asoc).sent_queue_retran_cnt.wrapping_add(1)
                    }
                    tp1 = (*tp1).sctp_next.tqe_next
                }
            }
            done_once = 1i32
        }
        /* *********************************/
        /* Now what about shutdown issues */
        /* *********************************/
        if (*asoc).send_queue.tqh_first.is_null() && (*asoc).sent_queue.tqh_first.is_null() {
            /* nothing left on sendqueue.. consider done */
            /* clean up */
            if (*asoc).stream_queue_cnt == 1u32
                && ((*asoc).state & 0x80i32 != 0 || (*stcb).asoc.state & 0x7fi32 == 0x20i32)
                && Some(
                    (*asoc)
                        .ss_functions
                        .sctp_ss_is_user_msgs_incomplete
                        .expect("non-null function pointer"),
                )
                .expect("non-null function pointer")(stcb, asoc)
                    != 0
            {
                sctp_add_substate(stcb, 0x400i32);
            }
            if ((*asoc).state & 0x80i32 != 0 || (*stcb).asoc.state & 0x7fi32 == 0x20i32)
                && (*asoc).stream_queue_cnt == 1u32
                && (*asoc).state & 0x400i32 != 0
            {
                let mut op_err_0 = 0 as *mut mbuf;
                *abort_now = 1i32;
                /* XXX */
                op_err_0 = sctp_generate_cause(0xcu16, b"\x00" as *const u8 as *mut libc::c_char);
                (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x18i32) as uint32_t;
                sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err_0, 0i32);
                return;
            }
            if (*asoc).state & 0x80i32 != 0 && (*asoc).stream_queue_cnt == 0u32 {
                let mut netp = 0 as *mut sctp_nets;
                if (*stcb).asoc.state & 0x7fi32 == 0x8i32 || (*stcb).asoc.state & 0x7fi32 == 0x20i32
                {
                    ::std::intrinsics::atomic_xsub(
                        &mut system_base_info.sctpstat.sctps_currestab,
                        1u32,
                    );
                }
                sctp_set_state(stcb, 0x10i32);
                sctp_stop_timers_for_shutdown(stcb);
                if !(*asoc).alternate.is_null() {
                    netp = (*asoc).alternate
                } else {
                    netp = (*asoc).primary_destination
                }
                sctp_send_shutdown(stcb, netp);
                sctp_timer_start(4i32, (*stcb).sctp_ep, stcb, netp);
                sctp_timer_start(11i32, (*stcb).sctp_ep, stcb, netp);
            } else if (*stcb).asoc.state & 0x7fi32 == 0x20i32 && (*asoc).stream_queue_cnt == 0u32 {
                let mut netp_0 = 0 as *mut sctp_nets;
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctpstat.sctps_currestab,
                    1u32,
                );
                sctp_set_state(stcb, 0x40i32);
                sctp_stop_timers_for_shutdown(stcb);
                if !(*asoc).alternate.is_null() {
                    netp_0 = (*asoc).alternate
                } else {
                    netp_0 = (*asoc).primary_destination
                }
                sctp_send_shutdown_ack(stcb, netp_0);
                sctp_timer_start(9i32, (*stcb).sctp_ep, stcb, netp_0);
            }
        }
        /* ********************************************/
        /* Here we perform PR-SCTP procedures        */
        /* (section 4.2)                             */
        /* ********************************************/
        /* C1. update advancedPeerAckPoint */
        if cumack < (*asoc).advanced_peer_ack_point
            && (*asoc).advanced_peer_ack_point.wrapping_sub(cumack) > (1u32) << 31i32
            || cumack > (*asoc).advanced_peer_ack_point
                && cumack.wrapping_sub((*asoc).advanced_peer_ack_point) < (1u32) << 31i32
        {
            (*asoc).advanced_peer_ack_point = cumack
        }
        /* PR-Sctp issues need to be addressed too */
        if (*asoc).prsctp_supported as libc::c_int != 0 && (*asoc).pr_sctp_cnt > 0u32 {
            let mut lchk = 0 as *mut sctp_tmit_chunk;
            let mut old_adv_peer_ack_point = 0;
            old_adv_peer_ack_point = (*asoc).advanced_peer_ack_point;
            lchk = sctp_try_advance_peer_ack_point(stcb, asoc);
            /* C3. See if we need to send a Fwd-TSN */
            if (*asoc).advanced_peer_ack_point < cumack
                && cumack.wrapping_sub((*asoc).advanced_peer_ack_point) > (1u32) << 31i32
                || (*asoc).advanced_peer_ack_point > cumack
                    && (*asoc).advanced_peer_ack_point.wrapping_sub(cumack) < (1u32) << 31i32
            {
                /*
                 * ISSUE with ECN, see FWD-TSN processing.
                 */
                if (*asoc).advanced_peer_ack_point < old_adv_peer_ack_point
                    && old_adv_peer_ack_point.wrapping_sub((*asoc).advanced_peer_ack_point)
                        > (1u32) << 31i32
                    || (*asoc).advanced_peer_ack_point > old_adv_peer_ack_point
                        && (*asoc)
                            .advanced_peer_ack_point
                            .wrapping_sub(old_adv_peer_ack_point)
                            < (1u32) << 31i32
                {
                    send_forward_tsn(stcb, asoc);
                } else if !lchk.is_null() {
                    /* try to FR fwd-tsn's that get lost too */
                    if (*lchk).rec.data.fwd_tsn_cnt as libc::c_int >= 3i32 {
                        send_forward_tsn(stcb, asoc);
                    }
                }
            }
            if !lchk.is_null() {
                /* Assure a timer is up */
                sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, (*lchk).whoTo);
            }
        }
        if system_base_info.sctpsysctl.sctp_logging_level & 0x8000u32 != 0 {
            sctp_misc_ints(
                87u8,
                rwnd,
                (*stcb).asoc.peers_rwnd,
                (*stcb).asoc.total_flight,
                (*stcb).asoc.total_output_queue_size,
            );
        }
        return;
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_handle_sack(
    mut m: *mut mbuf,
    mut offset_seg: libc::c_int,
    mut offset_dup: libc::c_int,
    mut stcb: *mut sctp_tcb,
    mut num_seg: uint16_t,
    mut num_nr_seg: uint16_t,
    mut num_dup: uint16_t,
    mut abort_now: *mut libc::c_int,
    mut flags: uint8_t,
    mut cum_ack: uint32_t,
    mut rwnd: uint32_t,
    mut ecne_seen: libc::c_int,
) {
    let mut op_err = 0 as *mut mbuf;
    let mut msg = [0; 128];
    let mut asoc = 0 as *mut sctp_association;
    let mut tp1 = 0 as *mut sctp_tmit_chunk;
    let mut last_tsn = 0;
    let mut this_sack_lowest_newack = 0;
    let mut send_s = 0u32;
    let mut a_rwnd = 0;
    let mut old_rwnd = 0;
    let mut cmt_dac_flag = 0;
    /*
     * we take any chance we can to service our queues since we cannot
     * get awoken when the socket is read from :<
     */
    /*
     * Now perform the actual SACK handling: 1) Verify that it is not an
     * old sack, if so discard. 2) If there is nothing left in the send
     * queue (cum-ack is equal to last acked) then you have a duplicate
     * too, update any rwnd change and verify no timers are running.
     * then return. 3) Process any new consequtive data i.e. cum-ack
     * moved process these first and note that it moved. 4) Process any
     * sack blocks. 5) Drop any acked from the queue. 6) Check for any
     * revoked blocks and mark. 7) Update the cwnd. 8) Nothing left,
     * sync up flightsizes and things, stop all timers and also check
     * for shutdown_pending state. If so then go ahead and send off the
     * shutdown. If in shutdown recv, send off the shutdown-ack and
     * start that timer, Ret. 9) Strike any non-acked things and do FR
     * procedure if needed being sure to set the FR flag. 10) Do pr-sctp
     * procedures. 11) Apply any FR penalties. 12) Assure we will SACK
     * if in shutdown_recv state.
     */
    /* CMT DAC algo */
    this_sack_lowest_newack = 0u32;
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_slowpath_sack, 1u32);
    last_tsn = cum_ack;
    cmt_dac_flag = (flags as libc::c_int & 0x80i32) as uint8_t;
    a_rwnd = rwnd;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x200000u32 != 0 {
        sctp_misc_ints(
            117u8,
            cum_ack,
            rwnd,
            (*stcb).asoc.last_acked_seq,
            (*stcb).asoc.peers_rwnd,
        );
    }
    old_rwnd = (*stcb).asoc.peers_rwnd;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x2000000u32 != 0 {
        sctp_misc_ints(
            120u8,
            (*stcb).asoc.overall_error_count,
            0u32,
            0x30000000u32,
            4512u32,
        );
    }
    (*stcb).asoc.overall_error_count = 0u32;
    asoc = &mut (*stcb).asoc;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x4000u32 != 0 {
        sctp_log_sack(
            (*asoc).last_acked_seq,
            cum_ack,
            0u32,
            num_seg,
            num_dup,
            42i32,
        );
    }
    if num_dup as libc::c_int != 0 && system_base_info.sctpsysctl.sctp_logging_level & 0x40u32 != 0
    {
        let mut i = 0;
        i = 0u16;
        while (i as libc::c_int) < num_dup as libc::c_int {
            let mut dupdata = 0 as *mut uint32_t;
            let mut dblock = 0u32;
            dupdata = sctp_m_getptr(
                m,
                (offset_dup as libc::c_ulong).wrapping_add(
                    (i as libc::c_ulong)
                        .wrapping_mul(::std::mem::size_of::<uint32_t>() as libc::c_ulong),
                ) as libc::c_int,
                ::std::mem::size_of::<uint32_t>() as libc::c_int,
                &mut dblock as *mut uint32_t as *mut uint8_t,
            ) as *mut uint32_t;
            if dupdata.is_null() {
                break;
            }
            sctp_log_fr(*dupdata, 0u32, 0u32, 56i32);
            i = i.wrapping_add(1)
        }
    }
    /* reality check */
    if !(*asoc).sent_queue.tqh_first.is_null() {
        tp1 = *(*((*asoc).sent_queue.tqh_last as *mut sctpchunk_listhead)).tqh_last;
        send_s = (*tp1).rec.data.tsn.wrapping_add(1u32)
    } else {
        tp1 = 0 as *mut sctp_tmit_chunk;
        send_s = (*asoc).sending_seq
    }
    if cum_ack < send_s && send_s.wrapping_sub(cum_ack) > (1u32) << 31i32
        || cum_ack > send_s && cum_ack.wrapping_sub(send_s) < (1u32) << 31i32
        || cum_ack == send_s
    {
        op_err = 0 as *mut mbuf;
        msg = [0; 128];
        /*
         * no way, we have not even sent this TSN out yet.
         * Peer is hopelessly messed up with us.
         */
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"NEW cum_ack:%x send_s:%x is smaller or equal\n\x00" as *const u8
                    as *const libc::c_char,
                cum_ack,
                send_s,
            );
        }
        if !tp1.is_null() {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Got send_s from tsn:%x + 1 of tp1: %p\n\x00" as *const u8
                        as *const libc::c_char,
                    (*tp1).rec.data.tsn,
                    tp1 as *mut libc::c_void,
                );
            }
        }
    } else {
        let mut current_block: u64;
        let mut biggest_tsn_acked = 0;
        let mut biggest_tsn_newly_acked = 0;
        let mut wake_him = 0u16;
        let mut accum_moved = 0i32;
        let mut net = 0 as *mut sctp_nets;
        let mut rto_ok = 1i32;
        if (*asoc).last_acked_seq < last_tsn
            && last_tsn.wrapping_sub((*asoc).last_acked_seq) > (1u32) << 31i32
            || (*asoc).last_acked_seq > last_tsn
                && (*asoc).last_acked_seq.wrapping_sub(last_tsn) < (1u32) << 31i32
        {
            /* acking something behind */
            return;
        }
        /* update the Rwnd of the peer */
        if (*asoc).sent_queue.tqh_first.is_null()
            && (*asoc).send_queue.tqh_first.is_null()
            && (*asoc).stream_queue_cnt == 0u32
        {
            /* nothing left on send/sent and strmq */
            if system_base_info.sctpsysctl.sctp_logging_level & 0x100000u32 != 0 {
                sctp_log_rwnd_set(38u8, (*asoc).peers_rwnd, 0u32, 0u32, a_rwnd);
            }
            (*asoc).peers_rwnd = a_rwnd;
            if (*asoc).sent_queue_retran_cnt != 0 {
                (*asoc).sent_queue_retran_cnt = 0u32
            }
            if (*asoc).peers_rwnd < (*(*stcb).sctp_ep).sctp_ep.sctp_sws_sender {
                /* SWS sender side engages */
                (*asoc).peers_rwnd = 0u32
            }
            /* stop any timers */
            net = (*asoc).nets.tqh_first;
            while !net.is_null() {
                sctp_timer_stop(
                    1i32,
                    (*stcb).sctp_ep,
                    stcb,
                    net,
                    (0x30000000i32 + 0x1ai32) as uint32_t,
                );
                (*net).partial_bytes_acked = 0u32;
                (*net).flight_size = 0u32;
                net = (*net).sctp_next.tqe_next
            }
            (*asoc).total_flight = 0u32;
            (*asoc).total_flight_count = 0u32;
            return;
        }
        /*
         * We init netAckSz and netAckSz2 to 0. These are used to track 2
         * things. The total byte count acked is tracked in netAckSz AND
         * netAck2 is used to track the total bytes acked that are un-
         * amibguious and were never retransmitted. We track these on a per
         * destination address basis.
         */
        net = (*asoc).nets.tqh_first;
        while !net.is_null() {
            if cum_ack < (*net).cwr_window_tsn
                && (*net).cwr_window_tsn.wrapping_sub(cum_ack) > (1u32) << 31i32
                || cum_ack > (*net).cwr_window_tsn
                    && cum_ack.wrapping_sub((*net).cwr_window_tsn) < (1u32) << 31i32
            {
                /* Drag along the window_tsn for cwr's */
                (*net).cwr_window_tsn = cum_ack
            }
            (*net).prev_cwnd = (*net).cwnd;
            (*net).net_ack = 0u32;
            (*net).net_ack2 = 0u32;
            /*
             * CMT: Reset CUC and Fast recovery algo variables before
             * SACK processing
             */
            (*net).new_pseudo_cumack = 0u8;
            (*net).will_exit_fast_recovery = 0u8;
            if (*stcb)
                .asoc
                .cc_functions
                .sctp_cwnd_prepare_net_for_sack
                .is_some()
            {
                Some(
                    (*stcb)
                        .asoc
                        .cc_functions
                        .sctp_cwnd_prepare_net_for_sack
                        .expect("non-null function pointer"),
                )
                .expect("non-null function pointer")(stcb, net);
            }
            /*
             * CMT: SFR algo (and HTNA) - this_sack_highest_newack has
             * to be greater than the cumack. Also reset saw_newack to 0
             * for all dests.
             */
            (*net).saw_newack = 0u8;
            (*net).this_sack_highest_newack = last_tsn;
            net = (*net).sctp_next.tqe_next
        }
        /* process the new consecutive TSN first */
        tp1 = (*asoc).sent_queue.tqh_first;
        while !tp1.is_null() {
            if !(last_tsn < (*tp1).rec.data.tsn
                && (*tp1).rec.data.tsn.wrapping_sub(last_tsn) > (1u32) << 31i32
                || last_tsn > (*tp1).rec.data.tsn
                    && last_tsn.wrapping_sub((*tp1).rec.data.tsn) < (1u32) << 31i32
                || last_tsn == (*tp1).rec.data.tsn)
            {
                break;
            }
            if (*tp1).sent != 0i32 {
                accum_moved = 1i32;
                if (*tp1).sent < 10010i32 {
                    /*
                     * If it is less than ACKED, it is
                     * now no-longer in flight. Higher
                     * values may occur during marking
                     */
                    if (*(*tp1).whoTo).dest_state as libc::c_int & 0x200i32 != 0
                        && ((*tp1).snd_count as libc::c_int) < 2i32
                    {
                        /*
                         * If there was no retran
                         * and the address is
                         * un-confirmed and we sent
                         * there and are now
                         * sacked.. its confirmed,
                         * mark it so.
                         */
                        (*(*tp1).whoTo).dest_state =
                            ((*(*tp1).whoTo).dest_state as libc::c_int & !(0x200i32)) as uint16_t
                    }
                    if (*tp1).sent < 4i32 {
                        if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
                            sctp_misc_ints(
                                107u8,
                                (*(*tp1).whoTo).flight_size,
                                (*tp1).book_size as uint32_t,
                                (*tp1).whoTo as uint32_t,
                                (*tp1).rec.data.tsn,
                            );
                        }
                        if (*(*tp1).whoTo).flight_size >= (*tp1).book_size as libc::c_uint {
                            (*(*tp1).whoTo).flight_size = ((*(*tp1).whoTo).flight_size)
                                .wrapping_sub((*tp1).book_size as libc::c_uint)
                        } else {
                            (*(*tp1).whoTo).flight_size = 0u32
                        }
                        (*tp1).window_probe = 0u8;
                        if (*stcb).asoc.total_flight >= (*tp1).book_size as libc::c_uint {
                            (*stcb).asoc.total_flight = (*stcb)
                                .asoc
                                .total_flight
                                .wrapping_sub((*tp1).book_size as libc::c_uint);
                            if (*stcb).asoc.total_flight_count > 0u32 {
                                (*stcb).asoc.total_flight_count =
                                    (*stcb).asoc.total_flight_count.wrapping_sub(1)
                            }
                        } else {
                            (*stcb).asoc.total_flight = 0u32;
                            (*stcb).asoc.total_flight_count = 0u32
                        }
                        if (*stcb)
                            .asoc
                            .cc_functions
                            .sctp_cwnd_update_tsn_acknowledged
                            .is_some()
                        {
                            Some(
                                (*stcb)
                                    .asoc
                                    .cc_functions
                                    .sctp_cwnd_update_tsn_acknowledged
                                    .expect("non-null function pointer"),
                            )
                            .expect("non-null function pointer")(
                                (*tp1).whoTo, tp1
                            );
                        }
                    }
                    (*(*tp1).whoTo).net_ack = (*(*tp1).whoTo)
                        .net_ack
                        .wrapping_add((*tp1).send_size as libc::c_uint);
                    /* CMT SFR and DAC algos */
                    this_sack_lowest_newack = (*tp1).rec.data.tsn;
                    (*(*tp1).whoTo).saw_newack = 1u8;
                    if ((*tp1).snd_count as libc::c_int) < 2i32 {
                        /*
                         * True non-retransmitted
                         * chunk
                         */
                        (*(*tp1).whoTo).net_ack2 = (*(*tp1).whoTo)
                            .net_ack2
                            .wrapping_add((*tp1).send_size as libc::c_uint);
                        /* update RTO too? */
                        if (*tp1).do_rtt != 0 {
                            if rto_ok != 0
                                && sctp_calculate_rto(
                                    stcb,
                                    &mut (*stcb).asoc,
                                    (*tp1).whoTo,
                                    &mut (*tp1).sent_rcv_time,
                                    1i32,
                                ) != 0
                            {
                                rto_ok = 0i32
                            }
                            if (*(*tp1).whoTo).rto_needed as libc::c_int == 0i32 {
                                (*(*tp1).whoTo).rto_needed = 1u8
                            }
                            (*tp1).do_rtt = 0u8
                        }
                    }
                    /*
                     * CMT: CUCv2 algorithm. From the
                     * cumack'd TSNs, for each TSN being
                     * acked for the first time, set the
                     * following variables for the
                     * corresp destination.
                     * new_pseudo_cumack will trigger a
                     * cwnd update.
                     * find_(rtx_)pseudo_cumack will
                     * trigger search for the next
                     * expected (rtx-)pseudo-cumack.
                     */
                    (*(*tp1).whoTo).new_pseudo_cumack = 1u8;
                    (*(*tp1).whoTo).find_pseudo_cumack = 1u8;
                    (*(*tp1).whoTo).find_rtx_pseudo_cumack = 1u8;
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x4000u32 != 0 {
                        sctp_log_sack(
                            (*asoc).last_acked_seq,
                            cum_ack,
                            (*tp1).rec.data.tsn,
                            0u16,
                            0u16,
                            43i32,
                        );
                    }
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x4u32 != 0 {
                        sctp_log_cwnd(stcb, (*tp1).whoTo, (*tp1).rec.data.tsn as libc::c_int, 64u8);
                    }
                }
                if (*tp1).sent == 4i32 {
                    if (*asoc).sent_queue_retran_cnt > 0u32 {
                        (*asoc).sent_queue_retran_cnt =
                            (*asoc).sent_queue_retran_cnt.wrapping_sub(1)
                    } else {
                        (*asoc).sent_queue_retran_cnt = 0u32
                    }
                }
                if (*tp1).rec.data.chunk_was_revoked != 0 {
                    /* deflate the cwnd */
                    (*(*tp1).whoTo).cwnd =
                        ((*(*tp1).whoTo).cwnd).wrapping_sub((*tp1).book_size as libc::c_uint);
                    (*tp1).rec.data.chunk_was_revoked = 0u8
                }
                if (*tp1).sent != 40010i32 {
                    (*tp1).sent = 10010i32
                }
            }
            tp1 = (*tp1).sctp_next.tqe_next
        }
        biggest_tsn_acked = last_tsn;
        biggest_tsn_newly_acked = biggest_tsn_acked;
        /* always set this up to cum-ack */
        (*asoc).this_sack_highest_gap = last_tsn;
        if num_seg as libc::c_int > 0i32 || num_nr_seg as libc::c_int > 0i32 {
            /*
             * thisSackHighestGap will increase while handling NEW
             * segments this_sack_highest_newack will increase while
             * handling NEWLY ACKED chunks. this_sack_lowest_newack is
             * used for CMT DAC algo. saw_newack will also change.
             */
            if sctp_handle_segments(
                m,
                &mut offset_seg,
                stcb,
                asoc,
                last_tsn,
                &mut biggest_tsn_acked,
                &mut biggest_tsn_newly_acked,
                &mut this_sack_lowest_newack,
                num_seg as libc::c_int,
                num_nr_seg as libc::c_int,
                &mut rto_ok,
            ) != 0
            {
                wake_him = wake_him.wrapping_add(1)
            }
            /*
             * validate the biggest_tsn_acked in the gap acks if
             * strict adherence is wanted.
             */
            if biggest_tsn_acked < send_s
                && send_s.wrapping_sub(biggest_tsn_acked) > (1u32) << 31i32
                || biggest_tsn_acked > send_s
                    && biggest_tsn_acked.wrapping_sub(send_s) < (1u32) << 31i32
                || biggest_tsn_acked == send_s
            {
                /*
                 * peer is either confused or we are under
                 * attack. We must abort.
                 */
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Hopeless peer! biggest_tsn_acked:%x largest seq:%x\n\x00" as *const u8
                            as *const libc::c_char,
                        biggest_tsn_acked,
                        send_s,
                    );
                }
                current_block = 16315573805384458252;
            } else {
                current_block = 13598848910332274892;
            }
        } else {
            current_block = 13598848910332274892;
        }
        match current_block {
            16315573805384458252 => {}
            _ => {
                let mut tp2 = 0 as *mut sctp_tmit_chunk;
                let mut will_exit_fast_recovery = 0i32;
                let mut win_probe_recovery = 0i32;
                let mut done_once = 0;
                let mut reneged_all = 0u8;
                if (*asoc).sctp_cmt_on_off as libc::c_int > 0i32 {
                    net = (*asoc).nets.tqh_first;
                    while !net.is_null() {
                        if (*net).new_pseudo_cumack != 0 {
                            sctp_timer_stop(
                                1i32,
                                (*stcb).sctp_ep,
                                stcb,
                                net,
                                (0x30000000i32 + 0x1bi32) as uint32_t,
                            );
                        }
                        net = (*net).sctp_next.tqe_next
                    }
                } else if accum_moved != 0 {
                    net = (*asoc).nets.tqh_first;
                    while !net.is_null() {
                        sctp_timer_stop(
                            1i32,
                            (*stcb).sctp_ep,
                            stcb,
                            net,
                            (0x30000000i32 + 0x1ci32) as uint32_t,
                        );
                        net = (*net).sctp_next.tqe_next
                    }
                }
                /* *******************************************/
                /* drop the acked chunks from the sentqueue */
                /* *******************************************/
                (*asoc).last_acked_seq = cum_ack;
                tp1 = (*asoc).sent_queue.tqh_first;
                while !tp1.is_null() && {
                    tp2 = (*tp1).sctp_next.tqe_next;
                    (1i32) != 0
                } {
                    if (*tp1).rec.data.tsn < cum_ack
                        && cum_ack.wrapping_sub((*tp1).rec.data.tsn) > (1u32) << 31i32
                        || (*tp1).rec.data.tsn > cum_ack
                            && (*tp1).rec.data.tsn.wrapping_sub(cum_ack) < (1u32) << 31i32
                    {
                        break;
                    }
                    if (*tp1).sent != 40010i32 {
                        if (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize)).chunks_on_queues
                            > 0u32
                        {
                            let ref mut fresh9 =
                                (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize))
                                    .chunks_on_queues;
                            *fresh9 = (*fresh9).wrapping_sub(1)
                        }
                    }
                    if (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize)).chunks_on_queues
                        == 0u32
                        && (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize)).state
                            as libc::c_int
                            == 0x3i32
                        && (*(*asoc).strmout.offset((*tp1).rec.data.sid as isize))
                            .outqueue
                            .tqh_first
                            .is_null()
                    {
                        (*asoc).trigger_reset = 1u8
                    }
                    if !(*tp1).sctp_next.tqe_next.is_null() {
                        (*(*tp1).sctp_next.tqe_next).sctp_next.tqe_prev = (*tp1).sctp_next.tqe_prev
                    } else {
                        (*asoc).sent_queue.tqh_last = (*tp1).sctp_next.tqe_prev
                    }
                    *(*tp1).sctp_next.tqe_prev = (*tp1).sctp_next.tqe_next;
                    if (*tp1).flags as libc::c_int & 0xfi32 != 0i32
                        && (*tp1).flags as libc::c_int & 0xfi32 != 0xfi32
                    {
                        if (*asoc).pr_sctp_cnt != 0u32 {
                            (*asoc).pr_sctp_cnt = (*asoc).pr_sctp_cnt.wrapping_sub(1)
                        }
                    }
                    (*asoc).sent_queue_cnt = (*asoc).sent_queue_cnt.wrapping_sub(1);
                    if !(*tp1).data.is_null() {
                        /* sa_ignore NO_NULL_CHK */
                        if !(*tp1).data.is_null() {
                            ::std::intrinsics::atomic_xsub(&mut (*asoc).chunks_on_out_queue, 1u32);
                            if (*asoc).total_output_queue_size >= (*tp1).book_size as libc::c_uint {
                                ::std::intrinsics::atomic_xsub(
                                    &mut (*asoc).total_output_queue_size,
                                    (*tp1).book_size as uint32_t,
                                );
                            } else {
                                (*asoc).total_output_queue_size = 0u32
                            }
                            if !(*stcb).sctp_socket.is_null()
                                && ((*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
                                    || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0)
                            {
                                if (*(*stcb).sctp_socket).so_snd.sb_cc
                                    >= (*tp1).book_size as libc::c_uint
                                {
                                    ::std::intrinsics::atomic_xsub(
                                        &mut (*(*stcb).sctp_socket).so_snd.sb_cc,
                                        (*tp1).book_size as u_int,
                                    );
                                } else {
                                    (*(*stcb).sctp_socket).so_snd.sb_cc = 0u32
                                }
                            }
                        }
                        m_freem((*tp1).data);
                        (*tp1).data = 0 as *mut mbuf;
                        if (*asoc).prsctp_supported as libc::c_int != 0
                            && (*tp1).flags as libc::c_int & 0xfi32 == 0x2i32
                        {
                            (*asoc).sent_queue_cnt_removeable =
                                (*asoc).sent_queue_cnt_removeable.wrapping_sub(1)
                        }
                    }
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x4000u32 != 0 {
                        sctp_log_sack(
                            (*asoc).last_acked_seq,
                            cum_ack,
                            (*tp1).rec.data.tsn,
                            0u16,
                            0u16,
                            71i32,
                        );
                    }
                    if (*tp1).holds_key_ref != 0 {
                        sctp_auth_key_release(stcb, (*tp1).auth_keyid, 0i32);
                        (*tp1).holds_key_ref = 0u8
                    }
                    if !stcb.is_null() {
                        if !(*tp1).whoTo.is_null() {
                            if !(*tp1).whoTo.is_null() {
                                if ::std::intrinsics::atomic_xadd(
                                    &mut (*(*tp1).whoTo).ref_count as *mut libc::c_int,
                                    -(1i32),
                                ) == 1i32
                                {
                                    sctp_os_timer_stop(&mut (*(*tp1).whoTo).rxt_timer.timer);
                                    sctp_os_timer_stop(&mut (*(*tp1).whoTo).pmtu_timer.timer);
                                    sctp_os_timer_stop(&mut (*(*tp1).whoTo).hb_timer.timer);
                                    if !(*(*tp1).whoTo).ro.ro_rt.is_null() {
                                        if (*(*(*tp1).whoTo).ro.ro_rt).rt_refcnt <= 1i64 {
                                            sctp_userspace_rtfree((*(*tp1).whoTo).ro.ro_rt);
                                        } else {
                                            (*(*(*tp1).whoTo).ro.ro_rt).rt_refcnt -= 1
                                        }
                                        (*(*tp1).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                                        (*(*tp1).whoTo).ro.ro_rt = 0 as *mut sctp_rtentry_t
                                    }
                                    if (*(*tp1).whoTo).src_addr_selected != 0 {
                                        sctp_free_ifa((*(*tp1).whoTo).ro._s_addr);
                                        (*(*tp1).whoTo).ro._s_addr = 0 as *mut sctp_ifa
                                    }
                                    (*(*tp1).whoTo).src_addr_selected = 0u8;
                                    (*(*tp1).whoTo).dest_state =
                                        ((*(*tp1).whoTo).dest_state as libc::c_int & !(0x1i32))
                                            as uint16_t;
                                    free((*tp1).whoTo as *mut libc::c_void);
                                    ::std::intrinsics::atomic_xsub(
                                        &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                        1u32,
                                    );
                                }
                            }
                            (*tp1).whoTo = 0 as *mut sctp_nets
                        }
                        if (*stcb).asoc.free_chunk_cnt as libc::c_uint
                            > system_base_info.sctpsysctl.sctp_asoc_free_resc_limit
                            || system_base_info.sctppcbinfo.ipi_free_chunks
                                > system_base_info.sctpsysctl.sctp_system_free_resc_limit
                        {
                            free(tp1 as *mut libc::c_void);
                            ::std::intrinsics::atomic_xsub(
                                &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                                1u32,
                            );
                        } else {
                            (*tp1).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
                            (*tp1).sctp_next.tqe_prev = (*stcb).asoc.free_chunks.tqh_last;
                            *(*stcb).asoc.free_chunks.tqh_last = tp1;
                            (*stcb).asoc.free_chunks.tqh_last = &mut (*tp1).sctp_next.tqe_next;
                            (*stcb).asoc.free_chunk_cnt =
                                (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
                            ::std::intrinsics::atomic_xadd(
                                &mut system_base_info.sctppcbinfo.ipi_free_chunks,
                                1u32,
                            );
                        }
                    } else {
                        free(tp1 as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_chunk,
                            1u32,
                        );
                    }
                    wake_him = wake_him.wrapping_add(1);
                    tp1 = tp2
                }
                if (*asoc).sent_queue.tqh_first.is_null() && (*asoc).total_flight > 0u32 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Warning flight size incorrect should be 0 is %d\n\x00" as *const u8
                                as *const libc::c_char,
                            (*asoc).total_flight,
                        );
                    }
                    (*asoc).total_flight = 0u32
                }
                if (*(*stcb).sctp_ep).recv_callback.is_some() {
                    if !(*stcb).sctp_socket.is_null() {
                        let mut inqueue_bytes = 0;
                        let mut sb_free_now = 0;
                        let mut inp = 0 as *mut sctp_inpcb;
                        inp = (*stcb).sctp_ep;
                        inqueue_bytes = ((*stcb).asoc.total_output_queue_size as libc::c_ulong)
                            .wrapping_sub(
                                ((*stcb).asoc.chunks_on_out_queue as libc::c_ulong).wrapping_mul(
                                    ::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong,
                                ),
                            ) as uint32_t;
                        sb_free_now = (*(*stcb).sctp_socket)
                            .so_snd
                            .sb_hiwat
                            .wrapping_sub(inqueue_bytes.wrapping_add((*stcb).asoc.sb_send_resv));
                        /* check if the amount free in the send socket buffer crossed the threshold */
                        if (*inp).send_callback.is_some()
                            && ((*inp).send_sb_threshold > 0u32
                                && sb_free_now >= (*inp).send_sb_threshold
                                || (*inp).send_sb_threshold == 0u32)
                        {
                            ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            (*inp).send_callback.expect("non-null function pointer")(
                                (*stcb).sctp_socket,
                                sb_free_now,
                            );
                            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                            ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.refcnt, 1u32);
                        }
                    }
                } else if wake_him as libc::c_int != 0 && !(*stcb).sctp_socket.is_null() {
                    pthread_mutex_lock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x40000u32 != 0 {
                        sctp_wakeup_log(stcb, wake_him as uint32_t, 74i32);
                    }
                    if (*(*stcb).sctp_ep).sctp_flags & 0x800000u32 != 0 {
                        pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
                        (*(*stcb).sctp_ep).sctp_flags |= 0x1000000u32
                    } else if (*(*stcb).sctp_socket).so_snd.sb_flags as libc::c_int
                        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                        != 0i32
                    {
                        sowakeup((*stcb).sctp_socket, &mut (*(*stcb).sctp_socket).so_snd);
                    } else {
                        pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
                    }
                } else if system_base_info.sctpsysctl.sctp_logging_level & 0x40000u32 != 0 {
                    sctp_wakeup_log(stcb, wake_him as uint32_t, 76i32);
                }
                if (*asoc).fast_retran_loss_recovery as libc::c_int != 0 && accum_moved != 0 {
                    if (*asoc).last_acked_seq < (*asoc).fast_recovery_tsn
                        && (*asoc)
                            .fast_recovery_tsn
                            .wrapping_sub((*asoc).last_acked_seq)
                            > (1u32) << 31i32
                        || (*asoc).last_acked_seq > (*asoc).fast_recovery_tsn
                            && (*asoc)
                                .last_acked_seq
                                .wrapping_sub((*asoc).fast_recovery_tsn)
                                < (1u32) << 31i32
                        || (*asoc).last_acked_seq == (*asoc).fast_recovery_tsn
                    {
                        /* Setup so we will exit RFC2582 fast recovery */
                        will_exit_fast_recovery = 1i32
                    }
                }
                /*
                 * Check for revoked fragments:
                 *
                 * if Previous sack - Had no frags then we can't have any revoked if
                 * Previous sack - Had frag's then - If we now have frags aka
                 * num_seg > 0 call sctp_check_for_revoked() to tell if peer revoked
                 * some of them. else - The peer revoked all ACKED fragments, since
                 * we had some before and now we have NONE.
                 */
                if num_seg != 0 {
                    sctp_check_for_revoked(stcb, asoc, cum_ack, biggest_tsn_acked);
                    (*asoc).saw_sack_with_frags = 1u8
                } else if (*asoc).saw_sack_with_frags != 0 {
                    let mut cnt_revoked = 0i32;
                    /* Peer revoked all dg's marked or acked */
                    tp1 = (*asoc).sent_queue.tqh_first;
                    while !tp1.is_null() {
                        if (*tp1).sent == 10010i32 {
                            (*tp1).sent = 1i32;
                            if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
                                sctp_misc_ints(
                                    114u8,
                                    (*(*tp1).whoTo).flight_size,
                                    (*tp1).book_size as uint32_t,
                                    (*tp1).whoTo as uint32_t,
                                    (*tp1).rec.data.tsn,
                                );
                            }
                            (*(*tp1).whoTo).flight_size = ((*(*tp1).whoTo).flight_size)
                                .wrapping_add((*tp1).book_size as libc::c_uint);
                            (*stcb).asoc.total_flight_count =
                                (*stcb).asoc.total_flight_count.wrapping_add(1);
                            (*stcb).asoc.total_flight = (*stcb)
                                .asoc
                                .total_flight
                                .wrapping_add((*tp1).book_size as libc::c_uint);
                            (*tp1).rec.data.chunk_was_revoked = 1u8;
                            /*
                             * To ensure that this increase in
                             * flightsize, which is artificial,
                             * does not throttle the sender, we
                             * also increase the cwnd
                             * artificially.
                             */
                            (*(*tp1).whoTo).cwnd = ((*(*tp1).whoTo).cwnd)
                                .wrapping_add((*tp1).book_size as libc::c_uint);
                            cnt_revoked += 1
                        }
                        tp1 = (*tp1).sctp_next.tqe_next
                    }
                    if cnt_revoked != 0 {
                        reneged_all = 1u8
                    }
                    (*asoc).saw_sack_with_frags = 0u8
                }
                if num_nr_seg as libc::c_int > 0i32 {
                    (*asoc).saw_sack_with_nr_frags = 1u8
                } else {
                    (*asoc).saw_sack_with_nr_frags = 0u8
                }
                /* JRS - Use the congestion control given in the CC module */
                if ecne_seen == 0i32 {
                    net = (*asoc).nets.tqh_first;
                    while !net.is_null() {
                        if (*net).net_ack2 > 0u32 {
                            /*
                             * Karn's rule applies to clearing error count, this
                             * is optional.
                             */
                            (*net).error_count = 0u16;
                            if (*net).dest_state as libc::c_int & 0x1i32 == 0 {
                                /* addr came good */
                                (*net).dest_state =
                                    ((*net).dest_state as libc::c_int | 0x1i32) as uint16_t;
                                sctp_ulp_notify(4u32, stcb, 0u32, net as *mut libc::c_void, 0i32);
                            }
                            if net == (*stcb).asoc.primary_destination {
                                if !(*stcb).asoc.alternate.is_null() {
                                    /* release the alternate, primary is good */
                                    if !(*stcb).asoc.alternate.is_null() {
                                        if ::std::intrinsics::atomic_xadd(
                                            &mut (*(*stcb).asoc.alternate).ref_count
                                                as *mut libc::c_int,
                                            -(1i32),
                                        ) == 1i32
                                        {
                                            sctp_os_timer_stop(
                                                &mut (*(*stcb).asoc.alternate).rxt_timer.timer,
                                            );
                                            sctp_os_timer_stop(
                                                &mut (*(*stcb).asoc.alternate).pmtu_timer.timer,
                                            );
                                            sctp_os_timer_stop(
                                                &mut (*(*stcb).asoc.alternate).hb_timer.timer,
                                            );
                                            if !(*(*stcb).asoc.alternate).ro.ro_rt.is_null() {
                                                if (*(*(*stcb).asoc.alternate).ro.ro_rt).rt_refcnt
                                                    <= 1i64
                                                {
                                                    sctp_userspace_rtfree(
                                                        (*(*stcb).asoc.alternate).ro.ro_rt,
                                                    );
                                                } else {
                                                    (*(*(*stcb).asoc.alternate).ro.ro_rt)
                                                        .rt_refcnt -= 1
                                                }
                                                (*(*stcb).asoc.alternate).ro.ro_rt =
                                                    0 as *mut sctp_rtentry_t;
                                                (*(*stcb).asoc.alternate).ro.ro_rt =
                                                    0 as *mut sctp_rtentry_t
                                            }
                                            if (*(*stcb).asoc.alternate).src_addr_selected != 0 {
                                                sctp_free_ifa((*(*stcb).asoc.alternate).ro._s_addr);
                                                (*(*stcb).asoc.alternate).ro._s_addr =
                                                    0 as *mut sctp_ifa
                                            }
                                            (*(*stcb).asoc.alternate).src_addr_selected = 0u8;
                                            (*(*stcb).asoc.alternate).dest_state =
                                                ((*(*stcb).asoc.alternate).dest_state
                                                    as libc::c_int
                                                    & !(0x1i32))
                                                    as uint16_t;
                                            free((*stcb).asoc.alternate as *mut libc::c_void);
                                            ::std::intrinsics::atomic_xsub(
                                                &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                                1u32,
                                            );
                                        }
                                    }
                                    (*stcb).asoc.alternate = 0 as *mut sctp_nets
                                }
                            }
                            if (*net).dest_state as libc::c_int & 0x800i32 != 0 {
                                (*net).dest_state =
                                    ((*net).dest_state as libc::c_int & !(0x800i32)) as uint16_t;
                                sctp_timer_stop(
                                    5i32,
                                    (*stcb).sctp_ep,
                                    stcb,
                                    net,
                                    (0x30000000i32 + 0x1di32) as uint32_t,
                                );
                                sctp_timer_start(5i32, (*stcb).sctp_ep, stcb, net);
                                (*asoc)
                                    .cc_functions
                                    .sctp_cwnd_update_exit_pf
                                    .expect("non-null function pointer")(
                                    stcb, net
                                );
                                /* Done with this net */
                                (*net).net_ack = 0u32
                            }
                            /* restore any doubled timers */
                            (*net).RTO = (((*net).lastsa >> 3i32) + (*net).lastsv) as libc::c_uint;
                            if (*net).RTO < (*stcb).asoc.minrto {
                                (*net).RTO = (*stcb).asoc.minrto
                            }
                            if (*net).RTO > (*stcb).asoc.maxrto {
                                (*net).RTO = (*stcb).asoc.maxrto
                            }
                        }
                        net = (*net).sctp_next.tqe_next
                    }
                    (*asoc)
                        .cc_functions
                        .sctp_cwnd_update_after_sack
                        .expect("non-null function pointer")(
                        stcb,
                        asoc,
                        accum_moved,
                        reneged_all as libc::c_int,
                        will_exit_fast_recovery,
                    );
                }
                if (*asoc).sent_queue.tqh_first.is_null() {
                    /* nothing left in-flight */
                    net = (*asoc).nets.tqh_first;
                    while !net.is_null() {
                        /* stop all timers */
                        sctp_timer_stop(
                            1i32,
                            (*stcb).sctp_ep,
                            stcb,
                            net,
                            (0x30000000i32 + 0x1ei32) as uint32_t,
                        );
                        (*net).flight_size = 0u32;
                        (*net).partial_bytes_acked = 0u32;
                        net = (*net).sctp_next.tqe_next
                    }
                    (*asoc).total_flight = 0u32;
                    (*asoc).total_flight_count = 0u32
                }
                /* *********************************/
                /* Now what about shutdown issues */
                /* *********************************/
                if (*asoc).send_queue.tqh_first.is_null() && (*asoc).sent_queue.tqh_first.is_null()
                {
                    /* nothing left on sendqueue.. consider done */
                    if system_base_info.sctpsysctl.sctp_logging_level & 0x100000u32 != 0 {
                        sctp_log_rwnd_set(38u8, (*asoc).peers_rwnd, 0u32, 0u32, a_rwnd);
                    }
                    (*asoc).peers_rwnd = a_rwnd;
                    if (*asoc).peers_rwnd < (*(*stcb).sctp_ep).sctp_ep.sctp_sws_sender {
                        /* SWS sender side engages */
                        (*asoc).peers_rwnd = 0u32
                    }
                    /* clean up */
                    if (*asoc).stream_queue_cnt == 1u32
                        && ((*asoc).state & 0x80i32 != 0 || (*stcb).asoc.state & 0x7fi32 == 0x20i32)
                        && Some(
                            (*asoc)
                                .ss_functions
                                .sctp_ss_is_user_msgs_incomplete
                                .expect("non-null function pointer"),
                        )
                        .expect("non-null function pointer")(stcb, asoc)
                            != 0
                    {
                        sctp_add_substate(stcb, 0x400i32);
                    }
                    if ((*asoc).state & 0x80i32 != 0 || (*stcb).asoc.state & 0x7fi32 == 0x20i32)
                        && (*asoc).stream_queue_cnt == 1u32
                        && (*asoc).state & 0x400i32 != 0
                    {
                        let mut op_err_0 = 0 as *mut mbuf;
                        *abort_now = 1i32;
                        /* XXX */
                        op_err_0 =
                            sctp_generate_cause(0xcu16, b"\x00" as *const u8 as *mut libc::c_char);
                        (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x18i32) as uint32_t;
                        sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err_0, 0i32);
                        return;
                    }
                    if (*asoc).state & 0x80i32 != 0 && (*asoc).stream_queue_cnt == 0u32 {
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
                        if !(*asoc).alternate.is_null() {
                            netp = (*asoc).alternate
                        } else {
                            netp = (*asoc).primary_destination
                        }
                        sctp_send_shutdown(stcb, netp);
                        sctp_timer_start(4i32, (*stcb).sctp_ep, stcb, netp);
                        sctp_timer_start(11i32, (*stcb).sctp_ep, stcb, netp);
                        return;
                    } else {
                        if (*stcb).asoc.state & 0x7fi32 == 0x20i32
                            && (*asoc).stream_queue_cnt == 0u32
                        {
                            let mut netp_0 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xsub(
                                &mut system_base_info.sctpstat.sctps_currestab,
                                1u32,
                            );
                            sctp_set_state(stcb, 0x40i32);
                            sctp_stop_timers_for_shutdown(stcb);
                            if !(*asoc).alternate.is_null() {
                                netp_0 = (*asoc).alternate
                            } else {
                                netp_0 = (*asoc).primary_destination
                            }
                            sctp_send_shutdown_ack(stcb, netp_0);
                            sctp_timer_start(9i32, (*stcb).sctp_ep, stcb, netp_0);
                            return;
                        }
                    }
                }
                /*
                 * Now here we are going to recycle net_ack for a different use...
                 * HEADS UP.
                 */
                net = (*asoc).nets.tqh_first;
                while !net.is_null() {
                    (*net).net_ack = 0u32;
                    net = (*net).sctp_next.tqe_next
                }
                /*
                 * CMT DAC algorithm: If SACK DAC flag was 0, then no extra marking
                 * to be done. Setting this_sack_lowest_newack to the cum_ack will
                 * automatically ensure that.
                 */
                if (*asoc).sctp_cmt_on_off as libc::c_int > 0i32
                    && system_base_info.sctpsysctl.sctp_cmt_use_dac != 0
                    && cmt_dac_flag as libc::c_int == 0i32
                {
                    this_sack_lowest_newack = cum_ack
                }
                if num_seg as libc::c_int > 0i32 || num_nr_seg as libc::c_int > 0i32 {
                    sctp_strike_gap_ack_chunks(
                        stcb,
                        asoc,
                        biggest_tsn_acked,
                        biggest_tsn_newly_acked,
                        this_sack_lowest_newack,
                        accum_moved,
                    );
                }
                /* JRS - Use the congestion control given in the CC module */
                (*asoc)
                    .cc_functions
                    .sctp_cwnd_update_after_fr
                    .expect("non-null function pointer")(stcb, asoc);
                /* Now are we exiting loss recovery ? */
                if will_exit_fast_recovery != 0 {
                    /* Ok, we must exit fast recovery */
                    (*asoc).fast_retran_loss_recovery = 0u8
                }
                if (*asoc).sat_t3_loss_recovery as libc::c_int != 0
                    && ((*asoc).last_acked_seq < (*asoc).sat_t3_recovery_tsn
                        && (*asoc)
                            .sat_t3_recovery_tsn
                            .wrapping_sub((*asoc).last_acked_seq)
                            > (1u32) << 31i32
                        || (*asoc).last_acked_seq > (*asoc).sat_t3_recovery_tsn
                            && (*asoc)
                                .last_acked_seq
                                .wrapping_sub((*asoc).sat_t3_recovery_tsn)
                                < (1u32) << 31i32
                        || (*asoc).last_acked_seq == (*asoc).sat_t3_recovery_tsn)
                {
                    /* end satellite t3 loss recovery */
                    (*asoc).sat_t3_loss_recovery = 0u8
                }
                /*
                 * CMT Fast recovery
                 */
                net = (*asoc).nets.tqh_first;
                while !net.is_null() {
                    if (*net).will_exit_fast_recovery != 0 {
                        /* Ok, we must exit fast recovery */
                        (*net).fast_retran_loss_recovery = 0u8
                    }
                    net = (*net).sctp_next.tqe_next
                }
                /* Adjust and set the new rwnd value */
                if system_base_info.sctpsysctl.sctp_logging_level & 0x100000u32 != 0 {
                    sctp_log_rwnd_set(
                        38u8,
                        (*asoc).peers_rwnd,
                        (*asoc).total_flight,
                        (*asoc)
                            .total_flight_count
                            .wrapping_mul(system_base_info.sctpsysctl.sctp_peer_chunk_oh),
                        a_rwnd,
                    );
                }
                (*asoc).peers_rwnd = if a_rwnd
                    > (*asoc).total_flight.wrapping_add(
                        (*asoc)
                            .total_flight_count
                            .wrapping_mul(system_base_info.sctpsysctl.sctp_peer_chunk_oh),
                    ) {
                    a_rwnd.wrapping_sub(
                        (*asoc).total_flight.wrapping_add(
                            (*asoc)
                                .total_flight_count
                                .wrapping_mul(system_base_info.sctpsysctl.sctp_peer_chunk_oh),
                        ),
                    )
                } else {
                    0u32
                };
                if (*asoc).peers_rwnd < (*(*stcb).sctp_ep).sctp_ep.sctp_sws_sender {
                    /* SWS sender side engages */
                    (*asoc).peers_rwnd = 0u32
                }
                if (*asoc).peers_rwnd > old_rwnd {
                    win_probe_recovery = 1i32
                }
                /*
                 * Now we must setup so we have a timer up for anyone with
                 * outstanding data.
                 */
                done_once = 0i32;
                loop {
                    let mut j = 0;
                    let mut win_probe_recovered = 0i32;
                    j = 0i64;
                    net = (*asoc).nets.tqh_first;
                    while !net.is_null() {
                        if win_probe_recovery != 0 && (*net).window_probe as libc::c_int != 0 {
                            win_probe_recovered = 1i32;
                            /*-
                             * Find first chunk that was used with
                             * window probe and clear the event. Put
                             * it back into the send queue as if has
                             * not been sent.
                             */
                            tp1 = (*asoc).sent_queue.tqh_first;
                            while !tp1.is_null() {
                                if (*tp1).window_probe != 0 {
                                    sctp_window_probe_recovery(stcb, asoc, tp1);
                                    break;
                                } else {
                                    tp1 = (*tp1).sctp_next.tqe_next
                                }
                            }
                        }
                        if (*net).flight_size != 0 {
                            j += 1;
                            if (*net).rxt_timer.timer.c_flags & 0x4i32 == 0 {
                                sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, net);
                            }
                            if (*net).window_probe != 0 {
                                (*net).window_probe = 0u8
                            }
                        } else if (*net).window_probe != 0 {
                            /* In window probes we must assure a timer is still running there */
                            if (*net).rxt_timer.timer.c_flags & 0x4i32 == 0 {
                                sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, net);
                            }
                        } else if (*net).rxt_timer.timer.c_flags & 0x4i32 != 0 {
                            sctp_timer_stop(
                                1i32,
                                (*stcb).sctp_ep,
                                stcb,
                                net,
                                (0x30000000i32 + 0x20i32) as uint32_t,
                            );
                        }
                        net = (*net).sctp_next.tqe_next
                    }
                    if !(j == 0i64
                        && !(*asoc).sent_queue.tqh_first.is_null()
                        && (*asoc).sent_queue_retran_cnt == 0u32
                        && win_probe_recovered == 0i32
                        && done_once == 0i32)
                    {
                        break;
                    }
                    /* huh, this should not happen unless all packets
                     * are PR-SCTP and marked to skip of course.
                     */
                    if sctp_fs_audit(asoc) != 0 {
                        net = (*asoc).nets.tqh_first;
                        while !net.is_null() {
                            (*net).flight_size = 0u32;
                            net = (*net).sctp_next.tqe_next
                        }
                        (*asoc).total_flight = 0u32;
                        (*asoc).total_flight_count = 0u32;
                        (*asoc).sent_queue_retran_cnt = 0u32;
                        tp1 = (*asoc).sent_queue.tqh_first;
                        while !tp1.is_null() {
                            if (*tp1).sent < 4i32 {
                                (*(*tp1).whoTo).flight_size = ((*(*tp1).whoTo).flight_size)
                                    .wrapping_add((*tp1).book_size as libc::c_uint);
                                (*stcb).asoc.total_flight_count =
                                    (*stcb).asoc.total_flight_count.wrapping_add(1);
                                (*stcb).asoc.total_flight = (*stcb)
                                    .asoc
                                    .total_flight
                                    .wrapping_add((*tp1).book_size as libc::c_uint)
                            } else if (*tp1).sent == 4i32 {
                                (*asoc).sent_queue_retran_cnt =
                                    (*asoc).sent_queue_retran_cnt.wrapping_add(1)
                            }
                            tp1 = (*tp1).sctp_next.tqe_next
                        }
                    }
                    done_once = 1i32
                }
                /* ********************************************/
                /* Here we perform PR-SCTP procedures        */
                /* (section 4.2)                             */
                /* ********************************************/
                /* C1. update advancedPeerAckPoint */
                if cum_ack < (*asoc).advanced_peer_ack_point
                    && (*asoc).advanced_peer_ack_point.wrapping_sub(cum_ack) > (1u32) << 31i32
                    || cum_ack > (*asoc).advanced_peer_ack_point
                        && cum_ack.wrapping_sub((*asoc).advanced_peer_ack_point) < (1u32) << 31i32
                {
                    (*asoc).advanced_peer_ack_point = cum_ack
                }
                /* C2. try to further move advancedPeerAckPoint ahead */
                if (*asoc).prsctp_supported as libc::c_int != 0 && (*asoc).pr_sctp_cnt > 0u32 {
                    let mut lchk = 0 as *mut sctp_tmit_chunk;
                    let mut old_adv_peer_ack_point = 0;
                    old_adv_peer_ack_point = (*asoc).advanced_peer_ack_point;
                    lchk = sctp_try_advance_peer_ack_point(stcb, asoc);
                    /* C3. See if we need to send a Fwd-TSN */
                    if (*asoc).advanced_peer_ack_point < cum_ack
                        && cum_ack.wrapping_sub((*asoc).advanced_peer_ack_point) > (1u32) << 31i32
                        || (*asoc).advanced_peer_ack_point > cum_ack
                            && (*asoc).advanced_peer_ack_point.wrapping_sub(cum_ack)
                                < (1u32) << 31i32
                    {
                        /*
                         * ISSUE with ECN, see FWD-TSN processing.
                         */
                        if system_base_info.sctpsysctl.sctp_logging_level & 0x10000000u32 != 0 {
                            sctp_misc_ints(
                                123u8,
                                0xeeu32,
                                cum_ack,
                                (*asoc).advanced_peer_ack_point,
                                old_adv_peer_ack_point,
                            );
                        }
                        if (*asoc).advanced_peer_ack_point < old_adv_peer_ack_point
                            && old_adv_peer_ack_point.wrapping_sub((*asoc).advanced_peer_ack_point)
                                > (1u32) << 31i32
                            || (*asoc).advanced_peer_ack_point > old_adv_peer_ack_point
                                && (*asoc)
                                    .advanced_peer_ack_point
                                    .wrapping_sub(old_adv_peer_ack_point)
                                    < (1u32) << 31i32
                        {
                            send_forward_tsn(stcb, asoc);
                        } else if !lchk.is_null() {
                            /* try to FR fwd-tsn's that get lost too */
                            if (*lchk).rec.data.fwd_tsn_cnt as libc::c_int >= 3i32 {
                                send_forward_tsn(stcb, asoc);
                            }
                        }
                    }
                    if !lchk.is_null() {
                        /* Assure a timer is up */
                        sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, (*lchk).whoTo);
                    }
                }
                if system_base_info.sctpsysctl.sctp_logging_level & 0x8000u32 != 0 {
                    sctp_misc_ints(
                        87u8,
                        a_rwnd,
                        (*stcb).asoc.peers_rwnd,
                        (*stcb).asoc.total_flight,
                        (*stcb).asoc.total_output_queue_size,
                    );
                }
                return;
            }
        }
    }
    *abort_now = 1i32;
    /* XXX */
    snprintf(
        msg.as_mut_ptr(),
        ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        b"Cum ack %8.8x greater or equal than TSN %8.8x\x00" as *const u8 as *const libc::c_char,
        cum_ack,
        send_s,
    );
    op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
    (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x19i32) as uint32_t;
    sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_update_acked(
    mut stcb: *mut sctp_tcb,
    mut cp: *mut sctp_shutdown_chunk,
    mut abort_flag: *mut libc::c_int,
) {
    let mut cum_ack = 0;
    let mut a_rwnd = 0;
    cum_ack = ntohl((*cp).cumulative_tsn_ack);
    /* Arrange so a_rwnd does NOT change */
    a_rwnd = (*stcb)
        .asoc
        .peers_rwnd
        .wrapping_add((*stcb).asoc.total_flight);
    /* Now call the express sack handling */
    sctp_express_handle_sack(stcb, cum_ack, a_rwnd, abort_flag, 0i32);
}
unsafe extern "C" fn sctp_kick_prsctp_reorder_queue(
    mut stcb: *mut sctp_tcb,
    mut strmin: *mut sctp_stream_in,
) {
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut ncontrol = 0 as *mut sctp_queued_to_read;
    let mut asoc = 0 as *mut sctp_association;
    let mut mid = 0;
    let mut need_reasm_check = 0i32;
    asoc = &mut (*stcb).asoc;
    mid = (*strmin).last_mid_delivered;
    /*
     * First deliver anything prior to and including the stream no that
     * came in.
     */
    control = (*strmin).inqueue.tqh_first;
    while !control.is_null() && {
        ncontrol = (*control).next_instrm.tqe_next;
        (1i32) != 0
    } {
        if !(if (*asoc).idata_supported as libc::c_int == 1i32 {
            (mid < (*control).mid && (*control).mid.wrapping_sub(mid) > (1u32) << 31i32
                || mid > (*control).mid && mid.wrapping_sub((*control).mid) < (1u32) << 31i32
                || mid == (*control).mid) as libc::c_int
        } else {
            ((mid as uint16_t as libc::c_int) < (*control).mid as uint16_t as libc::c_int
                && ((*control).mid as uint16_t as libc::c_int - mid as uint16_t as libc::c_int)
                    as uint16_t as libc::c_uint
                    > (1u32) << 15i32
                || mid as uint16_t as libc::c_int > (*control).mid as uint16_t as libc::c_int
                    && ((mid as uint16_t as libc::c_int - (*control).mid as uint16_t as libc::c_int)
                        as uint16_t as libc::c_uint)
                        < (1u32) << 15i32
                || mid as uint16_t as libc::c_int == (*control).mid as uint16_t as libc::c_int)
                as libc::c_int
        } != 0)
        {
            break;
        }
        /* this is deliverable now */
        if (*control).sinfo_flags as libc::c_int >> 8i32 & 0x3i32 == 0x3i32 {
            if (*control).on_strm_q != 0 {
                if (*control).on_strm_q as libc::c_int == 1i32 {
                    if !(*control).next_instrm.tqe_next.is_null() {
                        (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                            (*control).next_instrm.tqe_prev
                    } else {
                        (*strmin).inqueue.tqh_last = (*control).next_instrm.tqe_prev
                    }
                    *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next
                } else if (*control).on_strm_q as libc::c_int == 2i32 {
                    if !(*control).next_instrm.tqe_next.is_null() {
                        (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                            (*control).next_instrm.tqe_prev
                    } else {
                        (*strmin).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
                    }
                    *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next
                }
                (*control).on_strm_q = 0u8
            }
            /* subtract pending on streams */
            if (*asoc).size_on_all_streams >= (*control).length {
                (*asoc).size_on_all_streams =
                    (*asoc).size_on_all_streams.wrapping_sub((*control).length)
            } else {
                (*asoc).size_on_all_streams = 0u32
            }
            if (*asoc).cnt_on_all_streams > 0u32 {
                (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
            } else {
                (*asoc).cnt_on_all_streams = 0u32
            }
            /* deliver it to at least the delivery-q */
            if !(*stcb).sctp_socket.is_null() {
                sctp_mark_non_revokable(asoc, (*control).sinfo_tsn);
                sctp_add_to_readq(
                    (*stcb).sctp_ep,
                    stcb,
                    control,
                    &mut (*(*stcb).sctp_socket).so_rcv,
                    1i32,
                    1i32,
                    0i32,
                );
            }
        } else if (*control).first_frag_seen != 0 {
            /* Its a fragmented message */
            /* Make it so this is next to deliver, we restore later */
            (*strmin).last_mid_delivered = (*control).mid.wrapping_sub(1u32);
            need_reasm_check = 1i32;
            break;
        }
        control = ncontrol
    }
    if need_reasm_check != 0 {
        let mut ret = 0;
        ret = sctp_deliver_reasm_check(stcb, &mut (*stcb).asoc, strmin, 1i32);
        if if (*asoc).idata_supported as libc::c_int == 1i32 {
            (mid < (*strmin).last_mid_delivered
                && (*strmin).last_mid_delivered.wrapping_sub(mid) > (1u32) << 31i32
                || mid > (*strmin).last_mid_delivered
                    && mid.wrapping_sub((*strmin).last_mid_delivered) < (1u32) << 31i32)
                as libc::c_int
        } else {
            ((mid as uint16_t as libc::c_int)
                < (*strmin).last_mid_delivered as uint16_t as libc::c_int
                && ((*strmin).last_mid_delivered as uint16_t as libc::c_int
                    - mid as uint16_t as libc::c_int) as uint16_t
                    as libc::c_uint
                    > (1u32) << 15i32
                || mid as uint16_t as libc::c_int
                    > (*strmin).last_mid_delivered as uint16_t as libc::c_int
                    && ((mid as uint16_t as libc::c_int
                        - (*strmin).last_mid_delivered as uint16_t as libc::c_int)
                        as uint16_t as libc::c_uint)
                        < (1u32) << 15i32) as libc::c_int
        } != 0
        {
            /* Restore the next to deliver unless we are ahead */
            (*strmin).last_mid_delivered = mid
        }
        if ret == 0i32 {
            /* Left the front Partial one on */
            return;
        }
        need_reasm_check = 0i32
    }
    /*
     * now we must deliver things in queue the normal way  if any are
     * now ready.
     */
    mid = (*strmin).last_mid_delivered.wrapping_add(1u32);
    control = (*strmin).inqueue.tqh_first;
    while !control.is_null() && {
        ncontrol = (*control).next_instrm.tqe_next;
        (1i32) != 0
    } {
        if !(if (*asoc).idata_supported as libc::c_int == 1i32 {
            (mid == (*control).mid) as libc::c_int
        } else {
            (mid as uint16_t as libc::c_int == (*control).mid as uint16_t as libc::c_int)
                as libc::c_int
        } != 0)
        {
            break;
        }
        if (*control).sinfo_flags as libc::c_int >> 8i32 & 0x3i32 == 0x3i32 {
            /* this is deliverable now */
            if (*control).on_strm_q != 0 {
                if (*control).on_strm_q as libc::c_int == 1i32 {
                    if !(*control).next_instrm.tqe_next.is_null() {
                        (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                            (*control).next_instrm.tqe_prev
                    } else {
                        (*strmin).inqueue.tqh_last = (*control).next_instrm.tqe_prev
                    }
                    *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next
                } else if (*control).on_strm_q as libc::c_int == 2i32 {
                    if !(*control).next_instrm.tqe_next.is_null() {
                        (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                            (*control).next_instrm.tqe_prev
                    } else {
                        (*strmin).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
                    }
                    *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next
                }
                (*control).on_strm_q = 0u8
            }
            /* subtract pending on streams */
            if (*asoc).size_on_all_streams >= (*control).length {
                (*asoc).size_on_all_streams =
                    (*asoc).size_on_all_streams.wrapping_sub((*control).length)
            } else {
                (*asoc).size_on_all_streams = 0u32
            }
            if (*asoc).cnt_on_all_streams > 0u32 {
                (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
            } else {
                (*asoc).cnt_on_all_streams = 0u32
            }
            /* deliver it to at least the delivery-q */
            (*strmin).last_mid_delivered = (*control).mid;
            if !(*stcb).sctp_socket.is_null() {
                sctp_mark_non_revokable(asoc, (*control).sinfo_tsn);
                sctp_add_to_readq(
                    (*stcb).sctp_ep,
                    stcb,
                    control,
                    &mut (*(*stcb).sctp_socket).so_rcv,
                    1i32,
                    1i32,
                    0i32,
                );
            }
            mid = (*strmin).last_mid_delivered.wrapping_add(1u32)
        } else if (*control).first_frag_seen != 0 {
            /* Its a fragmented message */
            /* Make it so this is next to deliver */
            (*strmin).last_mid_delivered = (*control).mid.wrapping_sub(1u32);
            need_reasm_check = 1i32;
            break;
        }
        control = ncontrol
    }
    if need_reasm_check != 0 {
        sctp_deliver_reasm_check(stcb, &mut (*stcb).asoc, strmin, 1i32);
    };
}
unsafe extern "C" fn sctp_flush_reassm_for_str_seq(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut stream: uint16_t,
    mut mid: uint32_t,
    mut ordered: libc::c_int,
    mut cumtsn: uint32_t,
) {
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut strm = 0 as *mut sctp_stream_in;
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut nchk = 0 as *mut sctp_tmit_chunk;
    /*
     * For now large messages held on the stream reasm that are
     * complete will be tossed too. We could in theory do more
     * work to spin through and stop after dumping one msg aka
     * seeing the start of a new msg at the head, and call the
     * delivery function... to see if it can be delivered... But
     * for now we just dump everything on the queue.
     */
    strm = &mut *(*asoc).strmin.offset(stream as isize) as *mut sctp_stream_in;
    control = sctp_find_reasm_entry(strm, mid, ordered, (*asoc).idata_supported as libc::c_int);
    if control.is_null() {
        /* Not found */
        return;
    }
    if (*asoc).idata_supported == 0
        && ordered == 0
        && ((*control).fsn_included < cumtsn
            && cumtsn.wrapping_sub((*control).fsn_included) > (1u32) << 31i32
            || (*control).fsn_included > cumtsn
                && (*control).fsn_included.wrapping_sub(cumtsn) < (1u32) << 31i32)
    {
        return;
    }
    chk = (*control).reasm.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        let mut cnt_removed = 0i32;
        if (*asoc).idata_supported == 0 && ordered == 0i32 {
            if (*chk).rec.data.tsn < cumtsn
                && cumtsn.wrapping_sub((*chk).rec.data.tsn) > (1u32) << 31i32
                || (*chk).rec.data.tsn > cumtsn
                    && (*chk).rec.data.tsn.wrapping_sub(cumtsn) < (1u32) << 31i32
            {
                break;
            }
        }
        cnt_removed += 1;
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*control).reasm.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        if (*asoc).size_on_reasm_queue >= (*chk).send_size as libc::c_uint {
            (*asoc).size_on_reasm_queue = (*asoc)
                .size_on_reasm_queue
                .wrapping_sub((*chk).send_size as libc::c_uint)
        } else {
            (*asoc).size_on_reasm_queue = 0u32
        }
        if (*asoc).cnt_on_reasm_queue > 0u32 {
            (*asoc).cnt_on_reasm_queue = (*asoc).cnt_on_reasm_queue.wrapping_sub(1)
        } else {
            (*asoc).cnt_on_reasm_queue = 0u32
        }
        if !(*chk).data.is_null() {
            m_freem((*chk).data);
            (*chk).data = 0 as *mut mbuf
        }
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
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        }
        chk = nchk
    }
    if !(*control).reasm.tqh_first.is_null() {
        /* This has to be old data, unordered */
        if !(*control).data.is_null() {
            m_freem((*control).data);
            (*control).data = 0 as *mut mbuf
        }
        sctp_reset_a_control(control, (*stcb).sctp_ep, cumtsn);
        chk = (*control).reasm.tqh_first;
        if (*chk).rec.data.rcv_flags as libc::c_int & 0x2i32 != 0 {
            if !(*chk).sctp_next.tqe_next.is_null() {
                (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
            } else {
                (*control).reasm.tqh_last = (*chk).sctp_next.tqe_prev
            }
            *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
            sctp_add_chk_to_control(control, strm, stcb, asoc, chk, 1i32);
        }
        sctp_deliver_reasm_check(stcb, asoc, strm, 1i32);
        return;
    }
    if (*control).on_strm_q as libc::c_int == 1i32 {
        if !(*control).next_instrm.tqe_next.is_null() {
            (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                (*control).next_instrm.tqe_prev
        } else {
            (*strm).inqueue.tqh_last = (*control).next_instrm.tqe_prev
        }
        *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
        if (*asoc).size_on_all_streams >= (*control).length {
            (*asoc).size_on_all_streams =
                (*asoc).size_on_all_streams.wrapping_sub((*control).length)
        } else {
            (*asoc).size_on_all_streams = 0u32
        }
        if (*asoc).cnt_on_all_streams > 0u32 {
            (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
        } else {
            (*asoc).cnt_on_all_streams = 0u32
        }
        (*control).on_strm_q = 0u8
    } else if (*control).on_strm_q as libc::c_int == 2i32 {
        if !(*control).next_instrm.tqe_next.is_null() {
            (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                (*control).next_instrm.tqe_prev
        } else {
            (*strm).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
        }
        *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
        (*control).on_strm_q = 0u8
    }
    (*control).on_strm_q = 0u8;
    if (*control).on_read_q as libc::c_int == 0i32 {
        if !(*control).whoFrom.is_null() {
            if ::std::intrinsics::atomic_xadd(
                &mut (*(*control).whoFrom).ref_count as *mut libc::c_int,
                -(1i32),
            ) == 1i32
            {
                sctp_os_timer_stop(&mut (*(*control).whoFrom).rxt_timer.timer);
                sctp_os_timer_stop(&mut (*(*control).whoFrom).pmtu_timer.timer);
                sctp_os_timer_stop(&mut (*(*control).whoFrom).hb_timer.timer);
                if !(*(*control).whoFrom).ro.ro_rt.is_null() {
                    if (*(*(*control).whoFrom).ro.ro_rt).rt_refcnt <= 1i64 {
                        sctp_userspace_rtfree((*(*control).whoFrom).ro.ro_rt);
                    } else {
                        (*(*(*control).whoFrom).ro.ro_rt).rt_refcnt -= 1
                    }
                    (*(*control).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                    (*(*control).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t
                }
                if (*(*control).whoFrom).src_addr_selected != 0 {
                    sctp_free_ifa((*(*control).whoFrom).ro._s_addr);
                    (*(*control).whoFrom).ro._s_addr = 0 as *mut sctp_ifa
                }
                (*(*control).whoFrom).src_addr_selected = 0u8;
                (*(*control).whoFrom).dest_state =
                    ((*(*control).whoFrom).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                free((*control).whoFrom as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                    1u32,
                );
            }
        }
        if !(*control).data.is_null() {
            m_freem((*control).data);
            (*control).data = 0 as *mut mbuf
        }
        free(control as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
    };
}
/* draft-ietf-tsvwg-usctp */
#[no_mangle]
pub unsafe extern "C" fn sctp_handle_forward_tsn(
    mut stcb: *mut sctp_tcb,
    mut fwd: *mut sctp_forward_tsn_chunk,
    mut abort_flag: *mut libc::c_int,
    mut m: *mut mbuf,
    mut offset: libc::c_int,
) {
    /* The pr-sctp fwd tsn */
    /*
     * here we will perform all the data receiver side steps for
     * processing FwdTSN, as required in by pr-sctp draft:
     *
     * Assume we get FwdTSN(x):
     *
     * 1) update local cumTSN to x
     * 2) try to further advance cumTSN to x + others we have
     * 3) examine and update re-ordering queue on pr-in-streams
     * 4) clean up re-assembly queue
     * 5) Send a sack to report where we are.
     */

    let mut asoc = 0 as *mut sctp_association;
    let mut new_cum_tsn = 0;
    let mut gap = 0;
    let mut i = 0;
    let mut fwd_sz = 0;
    let mut m_size = 0;
    asoc = &mut (*stcb).asoc;
    fwd_sz = ntohs((*fwd).ch.chunk_length) as libc::c_uint;
    if (fwd_sz as libc::c_ulong) < ::std::mem::size_of::<sctp_forward_tsn_chunk>() as libc::c_ulong
    {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x1000000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Bad size too small/big fwd-tsn\n\x00" as *const u8 as *const libc::c_char,
                );
            }
        }
        return;
    }
    m_size = (((*stcb).asoc.mapping_array_size as libc::c_int) << 3i32) as libc::c_uint;
    /* ************************************************************/
    /* 1. Here we update local cumTSN and shift the bitmap array */
    /* ************************************************************/
    new_cum_tsn = ntohl((*fwd).new_cumulative_tsn);
    if (*asoc).cumulative_tsn < new_cum_tsn
        && new_cum_tsn.wrapping_sub((*asoc).cumulative_tsn) > (1u32) << 31i32
        || (*asoc).cumulative_tsn > new_cum_tsn
            && (*asoc).cumulative_tsn.wrapping_sub(new_cum_tsn) < (1u32) << 31i32
        || (*asoc).cumulative_tsn == new_cum_tsn
    {
        /* Already got there ... */
        return;
    }
    /*
     * now we know the new TSN is more advanced, let's find the actual
     * gap
     */
    if new_cum_tsn >= (*asoc).mapping_array_base_tsn {
        gap = new_cum_tsn.wrapping_sub((*asoc).mapping_array_base_tsn)
    } else {
        gap = (0xffffffffu32)
            .wrapping_sub((*asoc).mapping_array_base_tsn)
            .wrapping_add(new_cum_tsn)
            .wrapping_add(1u32)
    }
    (*asoc).cumulative_tsn = new_cum_tsn;
    if gap >= m_size {
        if gap as libc::c_long
            > (if (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
                (*(*stcb).sctp_socket).so_rcv.sb_hiwat
            } else {
                4096u32
            }) > (*stcb).asoc.sb_cc
            {
                (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
                    (*(*stcb).sctp_socket).so_rcv.sb_hiwat
                } else {
                    4096u32
                })
                .wrapping_sub((*stcb).asoc.sb_cc)
            } else {
                0u32
            }) as libc::c_long
        {
            let mut op_err = 0 as *mut mbuf;
            let mut msg = [0; 128];
            /*
             * out of range (of single byte chunks in the rwnd I
             * give out). This must be an attacker.
             */
            *abort_flag = 1i32;
            snprintf(
                msg.as_mut_ptr(),
                ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
                b"New cum ack %8.8x too high, highest TSN %8.8x\x00" as *const u8
                    as *const libc::c_char,
                new_cum_tsn,
                (*asoc).highest_tsn_inside_map,
            );
            op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
            (*(*stcb).sctp_ep).last_abort_code = (0x30000000i32 + 0x21i32) as uint32_t;
            sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
            return;
        }
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_fwdtsn_map_over, 1u32);
        memset(
            (*stcb).asoc.mapping_array as *mut libc::c_void,
            0i32,
            (*stcb).asoc.mapping_array_size as libc::c_ulong,
        );
        (*asoc).mapping_array_base_tsn = new_cum_tsn.wrapping_add(1u32);
        (*asoc).highest_tsn_inside_map = new_cum_tsn;
        memset(
            (*stcb).asoc.nr_mapping_array as *mut libc::c_void,
            0i32,
            (*stcb).asoc.mapping_array_size as libc::c_ulong,
        );
        (*asoc).highest_tsn_inside_nr_map = new_cum_tsn;
        if system_base_info.sctpsysctl.sctp_logging_level & 0x100u32 != 0 {
            sctp_log_map(0u32, 3u32, (*asoc).highest_tsn_inside_map, 23i32);
        }
    } else {
        i = 0u32;
        while i <= gap {
            if *(*asoc).mapping_array.offset((i >> 3i32) as isize) as libc::c_int >> (i & 0x7u32)
                & 0x1i32
                == 0
                && *(*asoc).nr_mapping_array.offset((i >> 3i32) as isize) as libc::c_int
                    >> (i & 0x7u32)
                    & 0x1i32
                    == 0
            {
                let ref mut fresh10 = *(*asoc).nr_mapping_array.offset((i >> 3i32) as isize);
                *fresh10 = (*fresh10 as libc::c_int | (0x1i32) << (i & 0x7u32)) as uint8_t;
                if (*asoc).mapping_array_base_tsn.wrapping_add(i)
                    < (*asoc).highest_tsn_inside_nr_map
                    && (*asoc)
                        .highest_tsn_inside_nr_map
                        .wrapping_sub((*asoc).mapping_array_base_tsn)
                        .wrapping_add(i)
                        > (1u32) << 31i32
                    || (*asoc).mapping_array_base_tsn.wrapping_add(i)
                        > (*asoc).highest_tsn_inside_nr_map
                        && (*asoc)
                            .mapping_array_base_tsn
                            .wrapping_add(i)
                            .wrapping_sub((*asoc).highest_tsn_inside_nr_map)
                            < (1u32) << 31i32
                {
                    (*asoc).highest_tsn_inside_nr_map =
                        (*asoc).mapping_array_base_tsn.wrapping_add(i)
                }
            }
            i = i.wrapping_add(1)
        }
    }
    /* ************************************************************/
    /* 2. Clear up re-assembly queue                             */
    /* ************************************************************/
    /* This is now done as part of clearing up the stream/seq */
    if (*asoc).idata_supported as libc::c_int == 0i32 {
        let mut sid = 0;
        /* Flush all the un-ordered data based on cum-tsn */
        pthread_mutex_lock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
        sid = 0u16;
        while (sid as libc::c_int) < (*asoc).streamincnt as libc::c_int {
            sctp_flush_reassm_for_str_seq(stcb, asoc, sid, 0u32, 0i32, new_cum_tsn);
            sid = sid.wrapping_add(1)
        }
        pthread_mutex_unlock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
    }
    /* ******************************************************/
    /* 3. Update the PR-stream re-ordering queues and fix  */
    /*    delivery issues as needed.                       */
    /* ******************************************************/
    fwd_sz = (fwd_sz as libc::c_ulong)
        .wrapping_sub(::std::mem::size_of::<sctp_forward_tsn_chunk>() as libc::c_ulong)
        as libc::c_uint;
    if !m.is_null() && fwd_sz != 0 {
        let mut num_str = 0;
        offset = (offset as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_forward_tsn_chunk>() as libc::c_ulong)
            as libc::c_int;
        pthread_mutex_lock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
        if (*asoc).idata_supported != 0 {
            num_str = (fwd_sz as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<sctp_strseq_mid>() as libc::c_ulong)
                as libc::c_uint
        } else {
            num_str = (fwd_sz as libc::c_ulong)
                .wrapping_div(::std::mem::size_of::<sctp_strseq>() as libc::c_ulong)
                as libc::c_uint
        }
        i = 0u32;
        while i < num_str {
            let mut strm = 0 as *mut sctp_stream_in;
            let mut control = 0 as *mut sctp_queued_to_read;
            let mut mid = 0;
            let mut cur_mid = 0;
            let mut sid_0 = 0;
            let mut ordered = 0;
            if (*asoc).idata_supported != 0 {
                let mut flags = 0;
                let mut stseq_m = 0 as *mut sctp_strseq_mid;
                let mut strseqbuf_m = sctp_strseq_mid {
                    sid: 0,
                    flags: 0,
                    mid: 0,
                };
                stseq_m = sctp_m_getptr(
                    m,
                    offset,
                    ::std::mem::size_of::<sctp_strseq_mid>() as libc::c_int,
                    &mut strseqbuf_m as *mut sctp_strseq_mid as *mut uint8_t,
                ) as *mut sctp_strseq_mid;
                offset = (offset as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<sctp_strseq_mid>() as libc::c_ulong)
                    as libc::c_int;
                if stseq_m.is_null() {
                    break;
                }
                sid_0 = ntohs((*stseq_m).sid);
                mid = ntohl((*stseq_m).mid);
                flags = ntohs((*stseq_m).flags);
                if flags as libc::c_int & 0x1i32 != 0 {
                    ordered = 0u16
                } else {
                    ordered = 1u16
                }
            } else {
                let mut stseq = 0 as *mut sctp_strseq;
                let mut strseqbuf = sctp_strseq { sid: 0, ssn: 0 };
                stseq = sctp_m_getptr(
                    m,
                    offset,
                    ::std::mem::size_of::<sctp_strseq>() as libc::c_int,
                    &mut strseqbuf as *mut sctp_strseq as *mut uint8_t,
                ) as *mut sctp_strseq;
                offset = (offset as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<sctp_strseq>() as libc::c_ulong)
                    as libc::c_int;
                if stseq.is_null() {
                    break;
                }
                sid_0 = ntohs((*stseq).sid);
                mid = ntohs((*stseq).ssn) as uint32_t;
                ordered = 1u16
            }
            /* Convert */
            /* now process */
            /*
             * Ok we now look for the stream/seq on the read queue
             * where its not all delivered. If we find it we transmute the
             * read entry into a PDI_ABORTED.
             */
            if sid_0 as libc::c_int >= (*asoc).streamincnt as libc::c_int {
                break;
            }
            if (*asoc).str_of_pdapi as libc::c_int == sid_0 as libc::c_int
                && (*asoc).ssn_of_pdapi as libc::c_uint == mid
            {
                /* If this is the one we were partially delivering
                 * now then we no longer are. Note this will change
                 * with the reassembly re-write.
                 */
                (*asoc).fragmented_delivery_inprogress = 0u8
            }
            strm = &mut *(*asoc).strmin.offset(sid_0 as isize) as *mut sctp_stream_in;
            cur_mid = (*strm).last_mid_delivered;
            while if (*asoc).idata_supported as libc::c_int == 1i32 {
                (mid < cur_mid && cur_mid.wrapping_sub(mid) > (1u32) << 31i32
                    || mid > cur_mid && mid.wrapping_sub(cur_mid) < (1u32) << 31i32
                    || mid == cur_mid) as libc::c_int
            } else {
                ((mid as uint16_t as libc::c_int) < cur_mid as uint16_t as libc::c_int
                    && (cur_mid as uint16_t as libc::c_int - mid as uint16_t as libc::c_int)
                        as uint16_t as libc::c_uint
                        > (1u32) << 15i32
                    || mid as uint16_t as libc::c_int > cur_mid as uint16_t as libc::c_int
                        && ((mid as uint16_t as libc::c_int - cur_mid as uint16_t as libc::c_int)
                            as uint16_t as libc::c_uint)
                            < (1u32) << 15i32
                    || mid as uint16_t as libc::c_int == cur_mid as uint16_t as libc::c_int)
                    as libc::c_int
            } != 0
            {
                sctp_flush_reassm_for_str_seq(
                    stcb,
                    asoc,
                    sid_0,
                    cur_mid,
                    ordered as libc::c_int,
                    new_cum_tsn,
                );
                cur_mid = cur_mid.wrapping_add(1)
            }
            control = (*(*stcb).sctp_ep).read_queue.tqh_first;
            while !control.is_null() {
                if (*control).sinfo_stream as libc::c_int == sid_0 as libc::c_int
                    && (if (*asoc).idata_supported as libc::c_int == 1i32 {
                        ((*control).mid == mid) as libc::c_int
                    } else {
                        ((*control).mid as uint16_t as libc::c_int
                            == mid as uint16_t as libc::c_int)
                            as libc::c_int
                    }) != 0
                {
                    let mut str_seq = 0;
                    let mut sv = 0 as *mut sctp_queued_to_read;
                    str_seq = ((sid_0 as libc::c_int) << 16i32) as libc::c_uint | 0xffffu32 & mid;
                    (*control).pdapi_aborted = 1u8;
                    sv = (*stcb).asoc.control_pdapi;
                    (*control).end_added = 1u8;
                    if (*control).on_strm_q as libc::c_int == 1i32 {
                        if !(*control).next_instrm.tqe_next.is_null() {
                            (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                                (*control).next_instrm.tqe_prev
                        } else {
                            (*strm).inqueue.tqh_last = (*control).next_instrm.tqe_prev
                        }
                        *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                        if (*asoc).size_on_all_streams >= (*control).length {
                            (*asoc).size_on_all_streams =
                                (*asoc).size_on_all_streams.wrapping_sub((*control).length)
                        } else {
                            (*asoc).size_on_all_streams = 0u32
                        }
                        if (*asoc).cnt_on_all_streams > 0u32 {
                            (*asoc).cnt_on_all_streams = (*asoc).cnt_on_all_streams.wrapping_sub(1)
                        } else {
                            (*asoc).cnt_on_all_streams = 0u32
                        }
                    } else if (*control).on_strm_q as libc::c_int == 2i32 {
                        if !(*control).next_instrm.tqe_next.is_null() {
                            (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                                (*control).next_instrm.tqe_prev
                        } else {
                            (*strm).uno_inqueue.tqh_last = (*control).next_instrm.tqe_prev
                        }
                        *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next
                    }
                    (*control).on_strm_q = 0u8;
                    (*stcb).asoc.control_pdapi = control;
                    sctp_ulp_notify(
                        15u32,
                        stcb,
                        0x1u32,
                        &mut str_seq as *mut uint32_t as *mut libc::c_void,
                        0i32,
                    );
                    (*stcb).asoc.control_pdapi = sv;
                    break;
                } else {
                    if (*control).sinfo_stream as libc::c_int == sid_0 as libc::c_int
                        && (if (*asoc).idata_supported as libc::c_int == 1i32 {
                            ((*control).mid < mid
                                && mid.wrapping_sub((*control).mid) > (1u32) << 31i32
                                || (*control).mid > mid
                                    && (*control).mid.wrapping_sub(mid) < (1u32) << 31i32)
                                as libc::c_int
                        } else {
                            (((*control).mid as uint16_t as libc::c_int)
                                < mid as uint16_t as libc::c_int
                                && (mid as uint16_t as libc::c_int
                                    - (*control).mid as uint16_t as libc::c_int)
                                    as uint16_t as libc::c_uint
                                    > (1u32) << 15i32
                                || (*control).mid as uint16_t as libc::c_int
                                    > mid as uint16_t as libc::c_int
                                    && (((*control).mid as uint16_t as libc::c_int
                                        - mid as uint16_t as libc::c_int)
                                        as uint16_t
                                        as libc::c_uint)
                                        < (1u32) << 15i32)
                                as libc::c_int
                        }) != 0
                    {
                        break;
                    }
                    control = (*control).next.tqe_next
                }
            }
            if if (*asoc).idata_supported as libc::c_int == 1i32 {
                (mid < (*strm).last_mid_delivered
                    && (*strm).last_mid_delivered.wrapping_sub(mid) > (1u32) << 31i32
                    || mid > (*strm).last_mid_delivered
                        && mid.wrapping_sub((*strm).last_mid_delivered) < (1u32) << 31i32)
                    as libc::c_int
            } else {
                ((mid as uint16_t as libc::c_int)
                    < (*strm).last_mid_delivered as uint16_t as libc::c_int
                    && ((*strm).last_mid_delivered as uint16_t as libc::c_int
                        - mid as uint16_t as libc::c_int) as uint16_t
                        as libc::c_uint
                        > (1u32) << 15i32
                    || mid as uint16_t as libc::c_int
                        > (*strm).last_mid_delivered as uint16_t as libc::c_int
                        && ((mid as uint16_t as libc::c_int
                            - (*strm).last_mid_delivered as uint16_t as libc::c_int)
                            as uint16_t as libc::c_uint)
                            < (1u32) << 15i32) as libc::c_int
            } != 0
            {
                /* Update the sequence number */
                (*strm).last_mid_delivered = mid
            }
            /* now kick the stream the new way */
            /*sa_ignore NO_NULL_CHK*/
            sctp_kick_prsctp_reorder_queue(stcb, strm);
            i = i.wrapping_add(1)
        }
        pthread_mutex_unlock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
    }
    /*
     * Now slide thing forward.
     */
    sctp_slide_mapping_arrays(stcb);
}
