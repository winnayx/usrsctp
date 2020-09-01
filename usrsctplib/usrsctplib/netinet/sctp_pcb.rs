use ::c2rust_bitfields;
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
    /* temp compatibility */
    pub type icmp6_filter;
    pub type ip6_pktopts;
    pub type ip_moptions;
    pub type uma_zone;
    #[no_mangle]
    fn pthread_join(__th: pthread_t, __thread_return: *mut *mut libc::c_void) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutexattr_init(__attr: *mut pthread_mutexattr_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutexattr_destroy(__attr: *mut pthread_mutexattr_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_cond_init(
        __cond: *mut pthread_cond_t,
        __cond_attr: *const pthread_condattr_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn pthread_cond_destroy(__cond: *mut pthread_cond_t) -> libc::c_int;
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
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    static mut M_PCB: [malloc_type; 1];
    #[no_mangle]
    fn socantsendmore(so: *mut socket);
    #[no_mangle]
    fn socantrcvmore_locked(so: *mut socket);
    #[no_mangle]
    fn sowakeup(so: *mut socket, sb: *mut sockbuf);
    #[no_mangle]
    fn wakeup(ident: *mut libc::c_void, so: *mut socket);
    /* int hz; is declared in sys/kern/subr_param.c and refers to kernel timer frequency.
     * See http://ivoras.sharanet.org/freebsd/vmware.html for additional info about kern.hz
     * hz is initialized in void init_param1(void) in that file.
     */
    #[no_mangle]
    static mut hz: libc::c_int;
    /* The following two ints define a range of available ephemeral ports. */
    #[no_mangle]
    static mut ipport_firstauto: libc::c_int;
    #[no_mangle]
    static mut ipport_lastauto: libc::c_int;
    #[no_mangle]
    fn read_random(buf: *mut libc::c_void, count: libc::c_int) -> libc::c_int;
    /* necessary for sctp_pcb.c */
    #[no_mangle]
    static mut ip_defttl: libc::c_int;
    #[no_mangle]
    fn m_free(m: *mut mbuf) -> *mut mbuf;
    #[no_mangle]
    fn mbuf_initialize(_: *mut libc::c_void);
    #[no_mangle]
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
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
    #[no_mangle]
    fn sctp_hashinit_flags(
        elements: libc::c_int,
        type_0: *mut malloc_type,
        hashmask: *mut u_long,
        flags: libc::c_int,
    ) -> *mut libc::c_void;
    #[no_mangle]
    fn sctp_hashdestroy(vhashtbl: *mut libc::c_void, type_0: *mut malloc_type, hashmask: u_long);
    /* callout is currently active */
    /* callout is waiting for timeout */
    #[no_mangle]
    fn sctp_os_timer_init(tmr: *mut sctp_os_timer_t);
    #[no_mangle]
    fn sctp_os_timer_stop(_: *mut sctp_os_timer_t) -> libc::c_int;
    /*-
     * Copyright (c) 2012 Michael Tuexen
     * Copyright (c) 2012 Irene Ruengeler
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
     */
    #[no_mangle]
    fn recv_thread_init();
    #[no_mangle]
    fn sctp_userspace_get_mtu_from_ifn(if_index: uint32_t, af: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn sctp_init_vrf_list(vrfid: libc::c_int);
    #[no_mangle]
    fn sctp_pathmtu_adjustment(_: *mut sctp_tcb, _: uint16_t);
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
    #[no_mangle]
    fn sctp_auth_add_chunk(chunk: uint8_t, list: *mut sctp_auth_chklist_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_clear_chunklist(chklist: *mut sctp_auth_chklist_t);
    #[no_mangle]
    fn sctp_alloc_chunklist() -> *mut sctp_auth_chklist_t;
    #[no_mangle]
    fn sctp_alloc_key(keylen: uint32_t) -> *mut sctp_key_t;
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_clear_cachedkeys(stcb: *mut sctp_tcb, keyid: uint16_t);
    #[no_mangle]
    fn sctp_free_key(key: *mut sctp_key_t);
    #[no_mangle]
    fn sctp_free_chunklist(chklist: *mut sctp_auth_chklist_t);
    #[no_mangle]
    fn sctp_auth_add_hmacid(list: *mut sctp_hmaclist_t, hmac_id: uint16_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_free_authinfo(authinfo: *mut sctp_authinfo_t);
    #[no_mangle]
    fn sctp_verify_hmac_param(hmacs: *mut sctp_auth_hmac_algo, num_hmacs: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_default_supported_hmaclist() -> *mut sctp_hmaclist_t;
    #[no_mangle]
    fn sctp_auth_key_release(stcb: *mut sctp_tcb, keyid: uint16_t, so_locked: libc::c_int);
    #[no_mangle]
    fn sctp_free_hmaclist(list: *mut sctp_hmaclist_t);
    #[no_mangle]
    fn sctp_alloc_hmaclist(num_hmacs: uint16_t) -> *mut sctp_hmaclist_t;
    #[no_mangle]
    fn sctp_insert_sharedkey(
        shared_keys: *mut sctp_keyhead,
        new_skey: *mut sctp_sharedkey_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_free_sharedkey(skey: *mut sctp_sharedkey_t);
    #[no_mangle]
    fn sctp_alloc_sharedkey() -> *mut sctp_sharedkey_t;
    #[no_mangle]
    fn sctp_initialize_auth_params(inp: *mut sctp_inpcb, stcb: *mut sctp_tcb);
    #[no_mangle]
    fn sctp_get_ifa_hash_val(addr: *mut sockaddr) -> uint32_t;
    #[no_mangle]
    fn sctp_find_ifa_by_addr(
        addr: *mut sockaddr,
        vrf_id: uint32_t,
        holds_lock: libc::c_int,
    ) -> *mut sctp_ifa;
    #[no_mangle]
    fn sctp_select_initial_TSN(_: *mut sctp_pcb) -> uint32_t;
    #[no_mangle]
    fn sctp_init_asoc(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: uint32_t,
        _: uint32_t,
        _: uint16_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_fill_random_store(_: *mut sctp_pcb);
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
    fn sctp_cmpaddr(_: *mut sockaddr, _: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp_print_address(_: *mut sockaddr);
    #[no_mangle]
    fn sctp_generate_cause(_: uint16_t, _: *mut libc::c_char) -> *mut mbuf;
    #[no_mangle]
    fn sctp_set_state(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_add_substate(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_is_addr_pending(_: *mut sctp_tcb, _: *mut sctp_ifa) -> libc::c_int;
    #[no_mangle]
    fn sctp_is_addr_restricted(_: *mut sctp_tcb, _: *mut sctp_ifa) -> libc::c_int;
    #[no_mangle]
    fn sctp_send_shutdown(_: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_chunk_output(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: libc::c_int, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_abort_tcb(_: *mut sctp_tcb, _: *mut mbuf, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_sack(_: *mut sctp_tcb, _: libc::c_int);
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
    fn sctp_find_alternate_net(
        _: *mut sctp_tcb,
        _: *mut sctp_nets,
        mode: libc::c_int,
    ) -> *mut sctp_nets;
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
    static mut sctp_it_ctl: iterator_control;
    #[no_mangle]
    fn sctp_wakeup_iterator();
    #[no_mangle]
    fn sctp_startup_iterator();
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
    pub c2rust_unnamed: C2RustUnnamed_444,
    pub c2rust_unnamed_0: C2RustUnnamed_442,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_442 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_443,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_443 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_444 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_445,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_445 {
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
pub union pthread_condattr_t {
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
    pub __in6_u: C2RustUnnamed_446,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_446 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct proc_0 {
    pub stub: libc::c_int,
}

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
    pub so_incomp: C2RustUnnamed_454,
    pub so_comp: C2RustUnnamed_453,
    pub so_list: C2RustUnnamed_452,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_451,
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
    pub M_dat: C2RustUnnamed_447,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_447 {
    pub MH: C2RustUnnamed_448,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_448 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_449,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_449 {
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
    pub m_tag_link: C2RustUnnamed_450,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_450 {
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
pub struct C2RustUnnamed_451 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_452 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_453 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_454 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}
pub type sctp_zone_t = size_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_455,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_455 {
    pub ifu_broadaddr: sockaddr,
    pub ifu_dstaddr: sockaddr,
}

#[repr(C)]
#[derive(Copy, Clone, BitfieldStruct)]
pub struct ip {
    #[bitfield(name = "ip_hl", ty = "libc::c_uint", bits = "0..=3")]
    #[bitfield(name = "ip_v", ty = "libc::c_uint", bits = "4..=7")]
    pub ip_hl_ip_v: [u8; 1],
    pub ip_tos: uint8_t,
    pub ip_len: libc::c_ushort,
    pub ip_id: libc::c_ushort,
    pub ip_off: libc::c_ushort,
    pub ip_ttl: uint8_t,
    pub ip_p: uint8_t,
    pub ip_sum: libc::c_ushort,
    pub ip_src: in_addr,
    pub ip_dst: in_addr,
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
    pub inp_hash: C2RustUnnamed_463,
    pub inp_list: C2RustUnnamed_462,
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
    pub inp_depend4: C2RustUnnamed_459,
    pub inp_depend6: C2RustUnnamed_458,
    pub inp_portlist: C2RustUnnamed_457,
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
    pub phd_hash: C2RustUnnamed_456,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_456 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_457 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_458 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_459 {
    pub inp4_ip_tos: u_char,
    pub inp4_options: *mut mbuf,
    pub inp4_moptions: *mut ip_moptions,
}
/*
 * XXX The defines for inc_* are hacks and should be changed to direct
 * references.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_conninfo {
    pub inc_flags: u_int8_t,
    pub inc_len: u_int8_t,
    pub inc_pad: u_int16_t,
    pub inc_ie: in_endpoints,
}
/*
 * NOTE: ipv6 addrs should be 64-bit aligned, per RFC 2553.  in_conninfo has
 * some extra padding to accomplish this.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_endpoints {
    pub ie_fport: u_int16_t,
    pub ie_lport: u_int16_t,
    pub ie_dependfaddr: C2RustUnnamed_461,
    pub ie_dependladdr: C2RustUnnamed_460,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_460 {
    pub ie46_local: in_addr_4in6,
    pub ie6_local: in6_addr,
}
/*
 * PCB with AF_INET6 null bind'ed laddr can receive AF_INET input packet.
 * So, AF_INET6 null laddr is also used as AF_INET null laddr, by utilizing
 * the following structure.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_addr_4in6 {
    pub ia46_pad32: [u_int32_t; 3],
    pub ia46_addr4: in_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_461 {
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
pub struct C2RustUnnamed_462 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_463 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ip6_hdr {
    pub ip6_ctlun: C2RustUnnamed_464,
    pub ip6_src: in6_addr,
    pub ip6_dst: in6_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_464 {
    pub ip6_un1: ip6_hdrctl,
    pub ip6_un2_vfc: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ip6_hdrctl {
    pub ip6_un1_flow: uint32_t,
    pub ip6_un1_plen: uint16_t,
    pub ip6_un1_nxt: uint8_t,
    pub ip6_un1_hlim: uint8_t,
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
    pub tqe: C2RustUnnamed_465,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_465 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tmit_chunk {
    pub rec: C2RustUnnamed_494,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_466,
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
pub struct C2RustUnnamed_466 {
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
    pub sctp_next: C2RustUnnamed_472,
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
    pub next_ifa: C2RustUnnamed_471,
    pub next_bucket: C2RustUnnamed_470,
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
    pub next_ifn: C2RustUnnamed_468,
    pub next_bucket: C2RustUnnamed_467,
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
pub struct C2RustUnnamed_467 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_468 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_469,
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
pub struct C2RustUnnamed_469 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_470 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_471 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_472 {
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
    pub next: C2RustUnnamed_473,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_473 {
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
    pub next: C2RustUnnamed_475,
    pub next_instrm: C2RustUnnamed_474,
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
pub struct C2RustUnnamed_474 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_475 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_479,
    pub sctp_tcblist: C2RustUnnamed_478,
    pub sctp_tcbasocidhash: C2RustUnnamed_477,
    pub sctp_asocs: C2RustUnnamed_476,
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
pub struct C2RustUnnamed_476 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_477 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_478 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_479 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_484,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_483,
    pub sctp_hash: C2RustUnnamed_482,
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
    pub sctp_nxt_itr: C2RustUnnamed_480,
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
pub struct C2RustUnnamed_480 {
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
    pub sctp_nxt_addr: C2RustUnnamed_481,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_481 {
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
pub struct C2RustUnnamed_482 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_483 {
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
pub union C2RustUnnamed_484 {
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
/* Fair Bandwidth scheduler */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_fb {
    pub next_spoke: C2RustUnnamed_485,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_485 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}
/* Priority scheduler */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_486,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_486 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}
/* Round-robin schedulers */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_487,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_487 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_streamhead {
    pub tqh_first: *mut sctp_stream_queue_pending,
    pub tqh_last: *mut *mut sctp_stream_queue_pending,
}
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_queue_pending {
    pub data: *mut mbuf,
    pub tail_mbuf: *mut mbuf,
    pub ts: timeval,
    pub net: *mut sctp_nets,
    pub next: C2RustUnnamed_489,
    pub ss_next: C2RustUnnamed_488,
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
pub struct C2RustUnnamed_488 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_489 {
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
    pub next_resp: C2RustUnnamed_490,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_490 {
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
    pub next: C2RustUnnamed_491,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_491 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}
/*
 * This union holds all data necessary for
 * different stream schedulers.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_492,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_492 {
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
    pub next: C2RustUnnamed_493,
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
pub struct C2RustUnnamed_493 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_494 {
    pub data: sctp_data_chunkrec,
    pub chunk_id: chk_id,
}
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
pub struct sctp_tagblock {
    pub sctp_nxt_tagblock: C2RustUnnamed_495,
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
pub struct C2RustUnnamed_495 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_auth_hmac_algo {
    pub ph: sctp_paramhdr,
    pub hmac_ids: [uint16_t; 0],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_auth_random {
    pub ph: sctp_paramhdr,
    pub random_data: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctppcbhead {
    pub lh_first: *mut sctp_inpcb,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_auth_chunk_list {
    pub ph: sctp_paramhdr,
    pub chunk_types: [uint8_t; 0],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_ipv4addr_param {
    pub ph: sctp_paramhdr,
    pub addr: uint32_t,
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
pub struct sctp_pcbinfo {
    pub ep_count: uint32_t,
    pub asoc_count: uint32_t,
    pub laddr_count: uint32_t,
    pub raddr_count: uint32_t,
    pub chk_count: uint32_t,
    pub readq_count: uint32_t,
    pub free_chunks: uint32_t,
    pub stream_oque: uint32_t,
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
pub struct sctp_vrflist {
    pub lh_first: *mut sctp_vrf,
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
pub type __timezone_ptr_t = *mut timezone;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addrv4_param {
    pub aph: sctp_asconf_paramhdr,
    pub addrp: sctp_ipv4addr_param,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_supported_chunk_types_param {
    pub ph: sctp_paramhdr,
    pub chunk_types: [uint8_t; 0],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_init {
    pub initiate_tag: uint32_t,
    pub a_rwnd: uint32_t,
    pub num_outbound_streams: uint16_t,
    pub num_inbound_streams: uint16_t,
    pub initial_tsn: uint32_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_state_cookie {
    pub identification: [uint8_t; 16],
    pub time_entered: timeval,
    pub cookie_life: uint32_t,
    pub tie_tag_my_vtag: uint32_t,
    pub tie_tag_peer_vtag: uint32_t,
    pub peers_vtag: uint32_t,
    pub my_vtag: uint32_t,
    pub address: [uint32_t; 4],
    pub addr_type: uint32_t,
    pub laddress: [uint32_t; 4],
    pub laddr_type: uint32_t,
    pub scope_id: uint32_t,
    pub peerport: uint16_t,
    pub myport: uint16_t,
    pub ipv4_addr_legal: uint8_t,
    pub ipv6_addr_legal: uint8_t,
    pub conn_addr_legal: uint8_t,
    pub local_scope: uint8_t,
    pub site_scope: uint8_t,
    pub ipv4_scope: uint8_t,
    pub loopback_scope: uint8_t,
    pub reserved: [uint8_t; 5],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_init_chunk {
    pub ch: sctp_chunkhdr,
    pub init: sctp_init,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_init_msg {
    pub sh: sctphdr,
    pub msg: sctp_init_chunk,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_adaptation_layer_indication {
    pub ph: sctp_paramhdr,
    pub indication: uint32_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_chunk {
    pub ch: sctp_chunkhdr,
    pub serial_number: uint32_t,
}
pub type sctp_sharedkey_t = sctp_shared_key;

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
/*
 * JRS - Structure to hold function pointers to the functions responsible
 * for congestion control.
 */
/*
 * RS - Structure to hold function pointers to the functions responsible
 * for stream scheduling.
 */
/* used to save ASCONF chunks for retransmission */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf {
    pub next: C2RustUnnamed_496,
    pub serial_number: uint32_t,
    pub snd_count: uint16_t,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_496 {
    pub tqe_next: *mut sctp_asconf,
    pub tqe_prev: *mut *mut sctp_asconf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct udphdr {
    pub c2rust_unnamed: C2RustUnnamed_497,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_497 {
    pub c2rust_unnamed: C2RustUnnamed_499,
    pub c2rust_unnamed_0: C2RustUnnamed_498,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_498 {
    pub source: uint16_t,
    pub dest: uint16_t,
    pub len: uint16_t,
    pub check: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_499 {
    pub uh_sport: uint16_t,
    pub uh_dport: uint16_t,
    pub uh_ulen: uint16_t,
    pub uh_sum: uint16_t,
}
/*-
 * Copyright (c) 2009-2010 Brad Penoff
 * Copyright (c) 2009-2010 Humaira Kamal
 * Copyright (c) 2011-2012 Irene Ruengeler
 * Copyright (c) 2011-2012 Michael Tuexen
 *
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
 */
/* __Userspace__ version of sys/i386/include/atomic.h goes here */
/* TODO In the future, might want to not use i386 specific assembly.
 *    The options include:
 *       - implement them generically (but maybe not truly atomic?) in userspace
 *       - have ifdef's for __Userspace_arch_ perhaps (OS isn't enough...)
 */
/* Using gcc built-in functions for atomic memory operations
  Reference: http://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Atomic-Builtins.html
  Requires gcc version 4.1.0
  compile with -march=i486
*/
/*Atomically add V to *P.*/
/*Atomically subtrace V from *P.*/
/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
/* Following explanation from src/sys/i386/include/atomic.h,
 * for atomic compare and set
 *
 * if (*dst == exp) *dst = src (all 32 bit words)
 *
 * Returns 0 on failure, non-zero on success
 */
#[inline]
unsafe extern "C" fn atomic_init() {}
#[inline]
unsafe extern "C" fn sctp_userspace_rtalloc(mut ro: *mut sctp_route_t) {
    if !(*ro).ro_rt.is_null() {
        (*(*ro).ro_rt).rt_refcnt += 1;
        return;
    }
    (*ro).ro_rt =
        malloc(::std::mem::size_of::<sctp_rtentry_t>() as libc::c_ulong) as *mut sctp_rtentry_t;
    if (*ro).ro_rt.is_null() {
        return;
    }
    /* initialize */
    memset(
        (*ro).ro_rt as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_rtentry_t>() as libc::c_ulong,
    );
    (*(*ro).ro_rt).rt_refcnt = 1i64;
    /* set MTU */
    /* TODO set this based on the ro->ro_dst, looking up MTU with routing socket */
    (*(*ro).ro_rt).rt_rmx.rmx_mtu = 1500u32;
    /* FIXME temporary solution */
    /* TODO enable the ability to obtain interface index of route for
     *  SCTP_GET_IF_INDEX_FROM_ROUTE macro.
     */
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
#[no_mangle]
pub static mut system_base_info: sctp_base_info = sctp_base_info {
    sctppcbinfo: sctp_epinfo {
        sctp_asochash: 0 as *mut sctpasochead,
        hashasocmark: 0,
        sctp_ephash: 0 as *mut sctppcbhead,
        hashmark: 0,
        sctp_tcpephash: 0 as *mut sctppcbhead,
        hashtcpmark: 0,
        hashtblsize: 0,
        sctp_vrfhash: 0 as *mut sctp_vrflist,
        hashvrfmark: 0,
        vrf_ifn_hash: 0 as *mut sctp_ifnlist,
        vrf_ifn_hashmark: 0,
        listhead: sctppcbhead {
            lh_first: 0 as *mut sctp_inpcb,
        },
        addr_wq: sctpladdr {
            lh_first: 0 as *mut sctp_laddr,
        },
        ipi_zone_ep: 0,
        ipi_zone_asoc: 0,
        ipi_zone_laddr: 0,
        ipi_zone_net: 0,
        ipi_zone_chunk: 0,
        ipi_zone_readq: 0,
        ipi_zone_strmoq: 0,
        ipi_zone_asconf: 0,
        ipi_zone_asconf_ack: 0,
        ipi_ep_mtx: pthread_mutex_t {
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
        ipi_addr_mtx: pthread_mutex_t {
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
        ipi_count_mtx: pthread_mutex_t {
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
        ipi_pktlog_mtx: pthread_mutex_t {
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
        wq_addr_mtx: pthread_mutex_t {
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
        ipi_count_ep: 0,
        ipi_count_asoc: 0,
        ipi_count_laddr: 0,
        ipi_count_raddr: 0,
        ipi_count_chunk: 0,
        ipi_count_readq: 0,
        ipi_count_strmoq: 0,
        ipi_count_vrfs: 0,
        ipi_count_ifns: 0,
        ipi_count_ifas: 0,
        ipi_free_chunks: 0,
        ipi_free_strmoq: 0,
        vtag_timewait: [sctpvtaghead {
            lh_first: 0 as *mut sctp_tagblock,
        }; 32],
        addr_wq_timer: sctp_timer {
            timer: sctp_os_timer_t {
                tqe: C2RustUnnamed_465 {
                    tqe_next: 0 as *mut sctp_callout,
                    tqe_prev: 0 as *mut *mut sctp_callout,
                },
                c_time: 0,
                c_arg: 0 as *mut libc::c_void,
                c_func: None,
                c_flags: 0,
            },
            type_0: 0,
            ep: 0 as *mut libc::c_void,
            tcb: 0 as *mut libc::c_void,
            net: 0 as *mut libc::c_void,
            self_0: 0 as *mut libc::c_void,
            ticks: 0,
            stopped_from: 0,
        },
        callqueue: calloutlist {
            tqh_first: 0 as *mut sctp_callout,
            tqh_last: 0 as *mut *mut sctp_callout,
        },
    },
    sctpstat: sctpstat {
        sctps_discontinuitytime: sctp_timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        sctps_currestab: 0,
        sctps_activeestab: 0,
        sctps_restartestab: 0,
        sctps_collisionestab: 0,
        sctps_passiveestab: 0,
        sctps_aborted: 0,
        sctps_shutdown: 0,
        sctps_outoftheblue: 0,
        sctps_checksumerrors: 0,
        sctps_outcontrolchunks: 0,
        sctps_outorderchunks: 0,
        sctps_outunorderchunks: 0,
        sctps_incontrolchunks: 0,
        sctps_inorderchunks: 0,
        sctps_inunorderchunks: 0,
        sctps_fragusrmsgs: 0,
        sctps_reasmusrmsgs: 0,
        sctps_outpackets: 0,
        sctps_inpackets: 0,
        sctps_recvpackets: 0,
        sctps_recvdatagrams: 0,
        sctps_recvpktwithdata: 0,
        sctps_recvsacks: 0,
        sctps_recvdata: 0,
        sctps_recvdupdata: 0,
        sctps_recvheartbeat: 0,
        sctps_recvheartbeatack: 0,
        sctps_recvecne: 0,
        sctps_recvauth: 0,
        sctps_recvauthmissing: 0,
        sctps_recvivalhmacid: 0,
        sctps_recvivalkeyid: 0,
        sctps_recvauthfailed: 0,
        sctps_recvexpress: 0,
        sctps_recvexpressm: 0,
        sctps_recv_spare: 0,
        sctps_recvswcrc: 0,
        sctps_recvhwcrc: 0,
        sctps_sendpackets: 0,
        sctps_sendsacks: 0,
        sctps_senddata: 0,
        sctps_sendretransdata: 0,
        sctps_sendfastretrans: 0,
        sctps_sendmultfastretrans: 0,
        sctps_sendheartbeat: 0,
        sctps_sendecne: 0,
        sctps_sendauth: 0,
        sctps_senderrors: 0,
        sctps_send_spare: 0,
        sctps_sendswcrc: 0,
        sctps_sendhwcrc: 0,
        sctps_pdrpfmbox: 0,
        sctps_pdrpfehos: 0,
        sctps_pdrpmbda: 0,
        sctps_pdrpmbct: 0,
        sctps_pdrpbwrpt: 0,
        sctps_pdrpcrupt: 0,
        sctps_pdrpnedat: 0,
        sctps_pdrppdbrk: 0,
        sctps_pdrptsnnf: 0,
        sctps_pdrpdnfnd: 0,
        sctps_pdrpdiwnp: 0,
        sctps_pdrpdizrw: 0,
        sctps_pdrpbadd: 0,
        sctps_pdrpmark: 0,
        sctps_timoiterator: 0,
        sctps_timodata: 0,
        sctps_timowindowprobe: 0,
        sctps_timoinit: 0,
        sctps_timosack: 0,
        sctps_timoshutdown: 0,
        sctps_timoheartbeat: 0,
        sctps_timocookie: 0,
        sctps_timosecret: 0,
        sctps_timopathmtu: 0,
        sctps_timoshutdownack: 0,
        sctps_timoshutdownguard: 0,
        sctps_timostrmrst: 0,
        sctps_timoearlyfr: 0,
        sctps_timoasconf: 0,
        sctps_timodelprim: 0,
        sctps_timoautoclose: 0,
        sctps_timoassockill: 0,
        sctps_timoinpkill: 0,
        sctps_spare: [0; 11],
        sctps_hdrops: 0,
        sctps_badsum: 0,
        sctps_noport: 0,
        sctps_badvtag: 0,
        sctps_badsid: 0,
        sctps_nomem: 0,
        sctps_fastretransinrtt: 0,
        sctps_markedretrans: 0,
        sctps_naglesent: 0,
        sctps_naglequeued: 0,
        sctps_maxburstqueued: 0,
        sctps_ifnomemqueued: 0,
        sctps_windowprobed: 0,
        sctps_lowlevelerr: 0,
        sctps_lowlevelerrusr: 0,
        sctps_datadropchklmt: 0,
        sctps_datadroprwnd: 0,
        sctps_ecnereducedcwnd: 0,
        sctps_vtagexpress: 0,
        sctps_vtagbogus: 0,
        sctps_primary_randry: 0,
        sctps_cmt_randry: 0,
        sctps_slowpath_sack: 0,
        sctps_wu_sacks_sent: 0,
        sctps_sends_with_flags: 0,
        sctps_sends_with_unord: 0,
        sctps_sends_with_eof: 0,
        sctps_sends_with_abort: 0,
        sctps_protocol_drain_calls: 0,
        sctps_protocol_drains_done: 0,
        sctps_read_peeks: 0,
        sctps_cached_chk: 0,
        sctps_cached_strmoq: 0,
        sctps_left_abandon: 0,
        sctps_send_burst_avoid: 0,
        sctps_send_cwnd_avoid: 0,
        sctps_fwdtsn_map_over: 0,
        sctps_queue_upd_ecne: 0,
        sctps_reserved: [0; 31],
    },
    sctpsysctl: sctp_sysctl {
        sctp_sendspace: 0,
        sctp_recvspace: 0,
        sctp_auto_asconf: 0,
        sctp_multiple_asconfs: 0,
        sctp_ecn_enable: 0,
        sctp_pr_enable: 0,
        sctp_auth_enable: 0,
        sctp_asconf_enable: 0,
        sctp_reconfig_enable: 0,
        sctp_nrsack_enable: 0,
        sctp_pktdrop_enable: 0,
        sctp_fr_max_burst_default: 0,
        sctp_no_csum_on_loopback: 0,
        sctp_peer_chunk_oh: 0,
        sctp_max_burst_default: 0,
        sctp_max_chunks_on_queue: 0,
        sctp_hashtblsize: 0,
        sctp_pcbtblsize: 0,
        sctp_min_split_point: 0,
        sctp_chunkscale: 0,
        sctp_delayed_sack_time_default: 0,
        sctp_sack_freq_default: 0,
        sctp_system_free_resc_limit: 0,
        sctp_asoc_free_resc_limit: 0,
        sctp_heartbeat_interval_default: 0,
        sctp_pmtu_raise_time_default: 0,
        sctp_shutdown_guard_time_default: 0,
        sctp_secret_lifetime_default: 0,
        sctp_rto_max_default: 0,
        sctp_rto_min_default: 0,
        sctp_rto_initial_default: 0,
        sctp_init_rto_max_default: 0,
        sctp_valid_cookie_life_default: 0,
        sctp_init_rtx_max_default: 0,
        sctp_assoc_rtx_max_default: 0,
        sctp_path_rtx_max_default: 0,
        sctp_path_pf_threshold: 0,
        sctp_add_more_threshold: 0,
        sctp_nr_incoming_streams_default: 0,
        sctp_nr_outgoing_streams_default: 0,
        sctp_cmt_on_off: 0,
        sctp_cmt_use_dac: 0,
        sctp_use_cwnd_based_maxburst: 0,
        sctp_nat_friendly: 0,
        sctp_L2_abc_variable: 0,
        sctp_mbuf_threshold_count: 0,
        sctp_do_drain: 0,
        sctp_hb_maxburst: 0,
        sctp_abort_if_one_2_one_hits_limit: 0,
        sctp_min_residual: 0,
        sctp_max_retran_chunk: 0,
        sctp_logging_level: 0,
        sctp_default_cc_module: 0,
        sctp_default_ss_module: 0,
        sctp_default_frag_interleave: 0,
        sctp_mobility_base: 0,
        sctp_mobility_fasthandoff: 0,
        sctp_inits_include_nat_friendly: 0,
        sctp_rttvar_bw: 0,
        sctp_rttvar_rtt: 0,
        sctp_rttvar_eqret: 0,
        sctp_steady_step: 0,
        sctp_use_dccc_ecn: 0,
        sctp_diag_info_code: 0,
        sctp_udp_tunneling_port: 0,
        sctp_enable_sack_immediately: 0,
        sctp_vtag_time_wait: 0,
        sctp_buffer_splitting: 0,
        sctp_initial_cwnd: 0,
        sctp_blackhole: 0,
        sctp_sendall_limit: 0,
        sctp_debug_on: 0,
    },
    first_time: 0,
    sctp_pcb_initialized: 0,
    timer_mtx: pthread_mutex_t {
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
    timer_thread: 0,
    timer_thread_should_exit: 0,
    mtx_attr: pthread_mutexattr_t { __size: [0; 4] },
    userspace_route: 0,
    recvthreadroute: 0,
    userspace_rawsctp: 0,
    userspace_udpsctp: 0,
    recvthreadraw: 0,
    recvthreadudp: 0,
    userspace_rawsctp6: 0,
    userspace_udpsctp6: 0,
    recvthreadraw6: 0,
    recvthreadudp6: 0,
    conn_output: None,
    debug_printf: None,
    crc32c_offloaded: 0,
};
/* FIX: we don't handle multiple link local scopes */
/* "scopeless" replacement IN6_ARE_ADDR_EQUAL */
#[no_mangle]
pub unsafe extern "C" fn SCTP6_ARE_ADDR_EQUAL(
    mut a: *mut sockaddr_in6,
    mut b: *mut sockaddr_in6,
) -> libc::c_int {
    return ({
        let mut __a = &mut (*a).sin6_addr as *mut in6_addr as *const in6_addr;
        let mut __b = &mut (*b).sin6_addr as *mut in6_addr as *const in6_addr;
        ((*__a).__in6_u.__u6_addr32[0usize] == (*__b).__in6_u.__u6_addr32[0usize]
            && (*__a).__in6_u.__u6_addr32[1usize] == (*__b).__in6_u.__u6_addr32[1usize]
            && (*__a).__in6_u.__u6_addr32[2usize] == (*__b).__in6_u.__u6_addr32[2usize]
            && (*__a).__in6_u.__u6_addr32[3usize] == (*__b).__in6_u.__u6_addr32[3usize])
            as libc::c_int
    });
    /* SCTP_EMBEDDED_V6_SCOPE */
}
#[no_mangle]
pub unsafe extern "C" fn sctp_fill_pcbinfo(mut spcb: *mut sctp_pcbinfo) {
    /*
     * We really don't need to lock this, but I will just because it
     * does not hurt.
     */
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    (*spcb).ep_count = system_base_info.sctppcbinfo.ipi_count_ep;
    (*spcb).asoc_count = system_base_info.sctppcbinfo.ipi_count_asoc;
    (*spcb).laddr_count = system_base_info.sctppcbinfo.ipi_count_laddr;
    (*spcb).raddr_count = system_base_info.sctppcbinfo.ipi_count_raddr;
    (*spcb).chk_count = system_base_info.sctppcbinfo.ipi_count_chunk;
    (*spcb).readq_count = system_base_info.sctppcbinfo.ipi_count_readq;
    (*spcb).stream_oque = system_base_info.sctppcbinfo.ipi_count_strmoq;
    (*spcb).free_chunks = system_base_info.sctppcbinfo.ipi_free_chunks;
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
}
/*-
 * Addresses are added to VRF's (Virtual Router's). For BSD we
 * have only the default VRF 0. We maintain a hash list of
 * VRF's. Each VRF has its own list of sctp_ifn's. Each of
 * these has a list of addresses. When we add a new address
 * to a VRF we lookup the ifn/ifn_index, if the ifn does
 * not exist we create it and add it to the list of IFN's
 * within the VRF. Once we have the sctp_ifn, we add the
 * address to the list. So we look something like:
 *
 * hash-vrf-table
 *   vrf-> ifn-> ifn -> ifn
 *   vrf    |
 *    ...   +--ifa-> ifa -> ifa
 *   vrf
 *
 * We keep these separate lists since the SCTP subsystem will
 * point to these from its source address selection nets structure.
 * When an address is deleted it does not happen right away on
 * the SCTP side, it gets scheduled. What we do when a
 * delete happens is immediately remove the address from
 * the master list and decrement the refcount. As our
 * addip iterator works through and frees the src address
 * selection pointing to the sctp_ifa, eventually the refcount
 * will reach 0 and we will delete it. Note that it is assumed
 * that any locking on system level ifn/ifa is done at the
 * caller of these functions and these routines will only
 * lock the SCTP structures as they add or delete things.
 *
 * Other notes on VRF concepts.
 *  - An endpoint can be in multiple VRF's
 *  - An association lives within a VRF and only one VRF.
 *  - Any incoming packet we can deduce the VRF for by
 *    looking at the mbuf/pak inbound (for BSD its VRF=0 :D)
 *  - Any downward send call or connect call must supply the
 *    VRF via ancillary data or via some sort of set default
 *    VRF socket option call (again for BSD no brainer since
 *    the VRF is always 0).
 *  - An endpoint may add multiple VRF's to it.
 *  - Listening sockets can accept associations in any
 *    of the VRF's they are in but the assoc will end up
 *    in only one VRF (gotten from the packet or connect/send).
 *
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_allocate_vrf(mut vrf_id: libc::c_int) -> *mut sctp_vrf {
    let mut vrf = 0 as *mut sctp_vrf;
    let mut bucket = 0 as *mut sctp_vrflist;
    /* First allocate the VRF structure */
    vrf = sctp_find_vrf(vrf_id as uint32_t);
    if !vrf.is_null() {
        /* Already allocated */
        return vrf;
    }
    vrf = malloc(::std::mem::size_of::<sctp_vrf>() as libc::c_ulong) as *mut sctp_vrf;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            vrf as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_vrf>() as libc::c_ulong,
        );
    }
    if vrf.is_null() {
        /* No memory */
        return 0 as *mut sctp_vrf;
    }
    /* setup the VRF */
    memset(
        vrf as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_vrf>() as libc::c_ulong,
    );
    (*vrf).vrf_id = vrf_id as uint32_t;
    (*vrf).ifnlist.lh_first = 0 as *mut sctp_ifn;
    (*vrf).total_ifa_count = 0u32;
    (*vrf).refcount = 0u32;
    /* now also setup table ids */
    /* Init the HASH of addresses */
    (*vrf).vrf_addr_hash = sctp_hashinit_flags(
        16i32,
        M_PCB.as_mut_ptr(),
        &mut (*vrf).vrf_addr_hashmark,
        0x1i32,
    ) as *mut sctp_ifalist;
    if (*vrf).vrf_addr_hash.is_null() {
        /* No memory */
        free(vrf as *mut libc::c_void);
        return 0 as *mut sctp_vrf;
    }
    /* Add it to the hash table */
    bucket = &mut *system_base_info
        .sctppcbinfo
        .sctp_vrfhash
        .offset((vrf_id as libc::c_ulong & system_base_info.sctppcbinfo.hashvrfmark) as isize)
        as *mut sctp_vrflist;
    (*vrf).next_vrf.le_next = (*bucket).lh_first;
    if !(*vrf).next_vrf.le_next.is_null() {
        (*(*bucket).lh_first).next_vrf.le_prev = &mut (*vrf).next_vrf.le_next
    }
    (*bucket).lh_first = vrf;
    (*vrf).next_vrf.le_prev = &mut (*bucket).lh_first;
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_vrfs, 1u32);
    return vrf;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_find_ifn(
    mut ifn: *mut libc::c_void,
    mut ifn_index: uint32_t,
) -> *mut sctp_ifn {
    let mut sctp_ifnp = 0 as *mut sctp_ifn;
    let mut hash_ifn_head = 0 as *mut sctp_ifnlist;
    /* We assume the lock is held for the addresses
     * if that's wrong problems could occur :-)
     */
    hash_ifn_head = &mut *system_base_info.sctppcbinfo.vrf_ifn_hash.offset(
        (ifn_index as libc::c_ulong & system_base_info.sctppcbinfo.vrf_ifn_hashmark) as isize,
    ) as *mut sctp_ifnlist;
    sctp_ifnp = (*hash_ifn_head).lh_first;
    while !sctp_ifnp.is_null() {
        if (*sctp_ifnp).ifn_index == ifn_index {
            return sctp_ifnp;
        }
        if !(*sctp_ifnp).ifn_p.is_null() && !ifn.is_null() && (*sctp_ifnp).ifn_p == ifn {
            return sctp_ifnp;
        }
        sctp_ifnp = (*sctp_ifnp).next_bucket.le_next
    }
    return 0 as *mut sctp_ifn;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_find_vrf(mut vrf_id: uint32_t) -> *mut sctp_vrf {
    let mut bucket = 0 as *mut sctp_vrflist;
    let mut liste = 0 as *mut sctp_vrf;
    bucket = &mut *system_base_info
        .sctppcbinfo
        .sctp_vrfhash
        .offset((vrf_id as libc::c_ulong & system_base_info.sctppcbinfo.hashvrfmark) as isize)
        as *mut sctp_vrflist;
    liste = (*bucket).lh_first;
    while !liste.is_null() {
        if vrf_id == (*liste).vrf_id {
            return liste;
        }
        liste = (*liste).next_vrf.le_next
    }
    return 0 as *mut sctp_vrf;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_vrf(mut vrf: *mut sctp_vrf) {
    if ::std::intrinsics::atomic_xadd(&mut (*vrf).refcount as *mut uint32_t, -(1i32) as uint32_t)
        == 1u32
    {
        if !(*vrf).vrf_addr_hash.is_null() {
            sctp_hashdestroy(
                (*vrf).vrf_addr_hash as *mut libc::c_void,
                M_PCB.as_mut_ptr(),
                (*vrf).vrf_addr_hashmark,
            );
            (*vrf).vrf_addr_hash = 0 as *mut sctp_ifalist
        }
        /* We zero'd the count */
        if !(*vrf).next_vrf.le_next.is_null() {
            (*(*vrf).next_vrf.le_next).next_vrf.le_prev = (*vrf).next_vrf.le_prev
        }
        *(*vrf).next_vrf.le_prev = (*vrf).next_vrf.le_next;
        free(vrf as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_vrfs, 1u32);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_ifn(mut sctp_ifnp: *mut sctp_ifn) {
    if ::std::intrinsics::atomic_xadd(
        &mut (*sctp_ifnp).refcount as *mut uint32_t,
        -(1i32) as uint32_t,
    ) == 1u32
    {
        /* We zero'd the count */
        if !(*sctp_ifnp).vrf.is_null() {
            sctp_free_vrf((*sctp_ifnp).vrf);
        }
        free(sctp_ifnp as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_ifns, 1u32);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_update_ifn_mtu(mut ifn_index: uint32_t, mut mtu: uint32_t) {
    let mut sctp_ifnp = 0 as *mut sctp_ifn;
    sctp_ifnp = sctp_find_ifn(0 as *mut libc::c_void, ifn_index);
    if !sctp_ifnp.is_null() {
        (*sctp_ifnp).ifn_mtu = mtu
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_free_ifa(mut sctp_ifap: *mut sctp_ifa) {
    if ::std::intrinsics::atomic_xadd(
        &mut (*sctp_ifap).refcount as *mut uint32_t,
        -(1i32) as uint32_t,
    ) == 1u32
    {
        /* We zero'd the count */
        if !(*sctp_ifap).ifn_p.is_null() {
            sctp_free_ifn((*sctp_ifap).ifn_p);
        }
        free(sctp_ifap as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_ifas, 1u32);
    };
}
unsafe extern "C" fn sctp_delete_ifn(
    mut sctp_ifnp: *mut sctp_ifn,
    mut hold_addr_lock: libc::c_int,
) {
    let mut found = 0 as *mut sctp_ifn;
    found = sctp_find_ifn((*sctp_ifnp).ifn_p, (*sctp_ifnp).ifn_index);
    if found.is_null() {
        /* Not in the list.. sorry */
        return;
    }
    if hold_addr_lock == 0i32 {
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    }
    if !(*sctp_ifnp).next_bucket.le_next.is_null() {
        (*(*sctp_ifnp).next_bucket.le_next).next_bucket.le_prev = (*sctp_ifnp).next_bucket.le_prev
    }
    *(*sctp_ifnp).next_bucket.le_prev = (*sctp_ifnp).next_bucket.le_next;
    if !(*sctp_ifnp).next_ifn.le_next.is_null() {
        (*(*sctp_ifnp).next_ifn.le_next).next_ifn.le_prev = (*sctp_ifnp).next_ifn.le_prev
    }
    *(*sctp_ifnp).next_ifn.le_prev = (*sctp_ifnp).next_ifn.le_next;
    if hold_addr_lock == 0i32 {
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    }
    /* Take away the reference, and possibly free it */
    sctp_free_ifn(sctp_ifnp);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_mark_ifa_addr_down(
    mut vrf_id: uint32_t,
    mut addr: *mut sockaddr,
    mut if_name: *const libc::c_char,
    mut ifn_index: uint32_t,
) {
    let mut vrf = 0 as *mut sctp_vrf;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    vrf = sctp_find_vrf(vrf_id);
    if vrf.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Can\'t find vrf_id 0x%x\n\x00" as *const u8 as *const libc::c_char,
                    vrf_id,
                );
            }
        }
    } else {
        let mut sctp_ifap = 0 as *mut sctp_ifa;
        sctp_ifap = sctp_find_ifa_by_addr(addr, (*vrf).vrf_id, 1i32);
        if sctp_ifap.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Can\'t find sctp_ifap for address\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        } else if (*sctp_ifap).ifn_p.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"IFA has no IFN - can\'t mark unusable\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        } else {
            let mut current_block: u64;
            if !if_name.is_null() {
                if strncmp(if_name, (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(), 16u64) != 0i32 {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"IFN %s of IFA not the same as %s\n\x00" as *const u8
                                    as *const libc::c_char,
                                (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(),
                                if_name,
                            );
                        }
                    }
                    current_block = 1450149954976595302;
                } else {
                    current_block = 12930649117290160518;
                }
            } else if (*(*sctp_ifap).ifn_p).ifn_index != ifn_index {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info.debug_printf.expect("non-null function pointer")(b"IFA owned by ifn_index:%d down command for ifn_index:%d - ignored\n\x00"
                                                                                              as
                                                                                              *const u8
                                                                                              as
                                                                                              *const libc::c_char,
                                                                                          (*(*sctp_ifap).ifn_p).ifn_index,
                                                                                          ifn_index);
                    }
                }
                current_block = 1450149954976595302;
            } else {
                current_block = 12930649117290160518;
            }
            match current_block {
                1450149954976595302 => {}
                _ => {
                    (*sctp_ifap).localifa_flags &= !(0x1i32) as libc::c_uint;
                    (*sctp_ifap).localifa_flags |= 0x8u32
                }
            }
        }
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_mark_ifa_addr_up(
    mut vrf_id: uint32_t,
    mut addr: *mut sockaddr,
    mut if_name: *const libc::c_char,
    mut ifn_index: uint32_t,
) {
    let mut vrf = 0 as *mut sctp_vrf;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    vrf = sctp_find_vrf(vrf_id);
    if vrf.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Can\'t find vrf_id 0x%x\n\x00" as *const u8 as *const libc::c_char,
                    vrf_id,
                );
            }
        }
    } else {
        let mut sctp_ifap = 0 as *mut sctp_ifa;
        sctp_ifap = sctp_find_ifa_by_addr(addr, (*vrf).vrf_id, 1i32);
        if sctp_ifap.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Can\'t find sctp_ifap for address\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        } else if (*sctp_ifap).ifn_p.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"IFA has no IFN - can\'t mark unusable\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        } else {
            let mut current_block: u64;
            if !if_name.is_null() {
                if strncmp(if_name, (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(), 16u64) != 0i32 {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"IFN %s of IFA not the same as %s\n\x00" as *const u8
                                    as *const libc::c_char,
                                (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(),
                                if_name,
                            );
                        }
                    }
                    current_block = 3165533173648882419;
                } else {
                    current_block = 12930649117290160518;
                }
            } else if (*(*sctp_ifap).ifn_p).ifn_index != ifn_index {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info.debug_printf.expect("non-null function pointer")(b"IFA owned by ifn_index:%d down command for ifn_index:%d - ignored\n\x00"
                                                                                              as
                                                                                              *const u8
                                                                                              as
                                                                                              *const libc::c_char,
                                                                                          (*(*sctp_ifap).ifn_p).ifn_index,
                                                                                          ifn_index);
                    }
                }
                current_block = 3165533173648882419;
            } else {
                current_block = 12930649117290160518;
            }
            match current_block {
                3165533173648882419 => {}
                _ => {
                    (*sctp_ifap).localifa_flags &= !(0x8i32) as libc::c_uint;
                    (*sctp_ifap).localifa_flags |= 0x1u32
                }
            }
        }
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
}
/*-
 * Add an ifa to an ifn.
 * Register the interface as necessary.
 * NOTE: ADDR write lock MUST be held.
 */
unsafe extern "C" fn sctp_add_ifa_to_ifn(
    mut sctp_ifnp: *mut sctp_ifn,
    mut sctp_ifap: *mut sctp_ifa,
) {
    let mut ifa_af = 0;
    (*sctp_ifap).next_ifa.le_next = (*sctp_ifnp).ifalist.lh_first;
    if !(*sctp_ifap).next_ifa.le_next.is_null() {
        (*(*sctp_ifnp).ifalist.lh_first).next_ifa.le_prev = &mut (*sctp_ifap).next_ifa.le_next
    }
    (*sctp_ifnp).ifalist.lh_first = sctp_ifap;
    (*sctp_ifap).next_ifa.le_prev = &mut (*sctp_ifnp).ifalist.lh_first;
    (*sctp_ifap).ifn_p = sctp_ifnp;
    ::std::intrinsics::atomic_xadd(&mut (*(*sctp_ifap).ifn_p).refcount, 1u32);
    /* update address counts */
    (*sctp_ifnp).ifa_count = (*sctp_ifnp).ifa_count.wrapping_add(1);
    ifa_af = (*sctp_ifap).address.sa.sa_family as libc::c_int;
    match ifa_af {
        2 => (*sctp_ifnp).num_v4 = (*sctp_ifnp).num_v4.wrapping_add(1),
        10 => (*sctp_ifnp).num_v6 = (*sctp_ifnp).num_v6.wrapping_add(1),
        _ => {}
    }
    if (*sctp_ifnp).ifa_count == 1u32 {
        /* register the new interface */
        (*sctp_ifnp).registered_af = ifa_af as uint32_t
    };
}
/*-
 * Remove an ifa from its ifn.
 * If no more addresses exist, remove the ifn too. Otherwise, re-register
 * the interface based on the remaining address families left.
 * NOTE: ADDR write lock MUST be held.
 */
unsafe extern "C" fn sctp_remove_ifa_from_ifn(mut sctp_ifap: *mut sctp_ifa) {
    if !(*sctp_ifap).next_ifa.le_next.is_null() {
        (*(*sctp_ifap).next_ifa.le_next).next_ifa.le_prev = (*sctp_ifap).next_ifa.le_prev
    }
    *(*sctp_ifap).next_ifa.le_prev = (*sctp_ifap).next_ifa.le_next;
    if !(*sctp_ifap).ifn_p.is_null() {
        /* update address counts */
        (*(*sctp_ifap).ifn_p).ifa_count = (*(*sctp_ifap).ifn_p).ifa_count.wrapping_sub(1);
        match (*sctp_ifap).address.sa.sa_family as libc::c_int {
            2 => (*(*sctp_ifap).ifn_p).num_v4 = (*(*sctp_ifap).ifn_p).num_v4.wrapping_sub(1),
            10 => (*(*sctp_ifap).ifn_p).num_v6 = (*(*sctp_ifap).ifn_p).num_v6.wrapping_sub(1),
            _ => {}
        }
        if (*(*sctp_ifap).ifn_p).ifalist.lh_first.is_null() {
            /* remove the ifn, possibly freeing it */
            sctp_delete_ifn((*sctp_ifap).ifn_p, 1i32);
        } else {
            /* re-register address family type, if needed */
            if (*(*sctp_ifap).ifn_p).num_v6 == 0u32 && (*(*sctp_ifap).ifn_p).registered_af == 10u32
            {
                (*(*sctp_ifap).ifn_p).registered_af = 2u32
            } else if (*(*sctp_ifap).ifn_p).num_v4 == 0u32
                && (*(*sctp_ifap).ifn_p).registered_af == 2u32
            {
                (*(*sctp_ifap).ifn_p).registered_af = 10u32
            }
            /* free the ifn refcount */
            sctp_free_ifn((*sctp_ifap).ifn_p);
        }
        (*sctp_ifap).ifn_p = 0 as *mut sctp_ifn
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_add_addr_to_vrf(
    mut vrf_id: uint32_t,
    mut ifn: *mut libc::c_void,
    mut ifn_index: uint32_t,
    mut ifn_type: uint32_t,
    mut if_name: *const libc::c_char,
    mut ifa: *mut libc::c_void,
    mut addr: *mut sockaddr,
    mut ifa_flags: uint32_t,
    mut dynamic_add: libc::c_int,
) -> *mut sctp_ifa {
    let mut vrf = 0 as *mut sctp_vrf;
    let mut sctp_ifnp = 0 as *mut sctp_ifn;
    let mut sctp_ifap = 0 as *mut sctp_ifa;
    let mut new_ifn_af = 0i32;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"vrf_id 0x%x: adding address: \x00" as *const u8 as *const libc::c_char,
                vrf_id,
            );
        }
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
        sctp_print_address(addr);
    }
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    sctp_ifnp = sctp_find_ifn(ifn, ifn_index);
    if !sctp_ifnp.is_null() {
        vrf = (*sctp_ifnp).vrf
    } else {
        vrf = sctp_find_vrf(vrf_id);
        if vrf.is_null() {
            vrf = sctp_allocate_vrf(vrf_id as libc::c_int);
            if vrf.is_null() {
                pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
                return 0 as *mut sctp_ifa;
            }
        }
    }
    if sctp_ifnp.is_null() {
        let mut hash_ifn_head = 0 as *mut sctp_ifnlist;
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        sctp_ifnp = malloc(::std::mem::size_of::<sctp_ifn>() as libc::c_ulong) as *mut sctp_ifn;
        if 0x1i32 & 0x100i32 != 0 {
            memset(
                sctp_ifnp as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sctp_ifn>() as libc::c_ulong,
            );
        }
        if sctp_ifnp.is_null() {
            return 0 as *mut sctp_ifa;
        }
        memset(
            sctp_ifnp as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_ifn>() as libc::c_ulong,
        );
        (*sctp_ifnp).ifn_index = ifn_index;
        (*sctp_ifnp).ifn_p = ifn;
        (*sctp_ifnp).ifn_type = ifn_type;
        (*sctp_ifnp).refcount = 0u32;
        (*sctp_ifnp).vrf = vrf;
        ::std::intrinsics::atomic_xadd(&mut (*vrf).refcount, 1u32);
        (*sctp_ifnp).ifn_mtu =
            sctp_userspace_get_mtu_from_ifn(ifn_index, (*addr).sa_family as libc::c_int)
                as uint32_t;
        if !if_name.is_null() {
            snprintf(
                (*sctp_ifnp).ifn_name.as_mut_ptr(),
                16u64,
                b"%s\x00" as *const u8 as *const libc::c_char,
                if_name,
            );
        } else {
            snprintf(
                (*sctp_ifnp).ifn_name.as_mut_ptr(),
                16u64,
                b"%s\x00" as *const u8 as *const libc::c_char,
                b"unknown\x00" as *const u8 as *const libc::c_char,
            );
        }
        hash_ifn_head = &mut *system_base_info.sctppcbinfo.vrf_ifn_hash.offset(
            (ifn_index as libc::c_ulong & system_base_info.sctppcbinfo.vrf_ifn_hashmark) as isize,
        ) as *mut sctp_ifnlist;
        (*sctp_ifnp).ifalist.lh_first = 0 as *mut sctp_ifa;
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        (*sctp_ifnp).next_bucket.le_next = (*hash_ifn_head).lh_first;
        if !(*sctp_ifnp).next_bucket.le_next.is_null() {
            (*(*hash_ifn_head).lh_first).next_bucket.le_prev = &mut (*sctp_ifnp).next_bucket.le_next
        }
        (*hash_ifn_head).lh_first = sctp_ifnp;
        (*sctp_ifnp).next_bucket.le_prev = &mut (*hash_ifn_head).lh_first;
        (*sctp_ifnp).next_ifn.le_next = (*vrf).ifnlist.lh_first;
        if !(*sctp_ifnp).next_ifn.le_next.is_null() {
            (*(*vrf).ifnlist.lh_first).next_ifn.le_prev = &mut (*sctp_ifnp).next_ifn.le_next
        }
        (*vrf).ifnlist.lh_first = sctp_ifnp;
        (*sctp_ifnp).next_ifn.le_prev = &mut (*vrf).ifnlist.lh_first;
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_ifns, 1u32);
        new_ifn_af = 1i32
    }
    sctp_ifap = sctp_find_ifa_by_addr(addr, (*vrf).vrf_id, 1i32);
    if !sctp_ifap.is_null() {
        /* Hmm, it already exists? */
        if !(*sctp_ifap).ifn_p.is_null() && (*(*sctp_ifap).ifn_p).ifn_index == ifn_index {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Using existing ifn %s (0x%x) for ifa %p\n\x00" as *const u8
                            as *const libc::c_char,
                        (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(),
                        ifn_index,
                        sctp_ifap as *mut libc::c_void,
                    );
                }
            }
            if new_ifn_af != 0 {
                /* Remove the created one that we don't want */
                sctp_delete_ifn(sctp_ifnp, 1i32);
            }
            if (*sctp_ifap).localifa_flags & 0x2u32 != 0 {
                /* easy to solve, just switch back to active */
                if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Clearing deleted ifa flag\n\x00" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                (*sctp_ifap).localifa_flags = 0x1u32;
                (*sctp_ifap).ifn_p = sctp_ifnp;
                ::std::intrinsics::atomic_xadd(&mut (*(*sctp_ifap).ifn_p).refcount, 1u32);
            }
        } else if !(*sctp_ifap).ifn_p.is_null() {
            /*
             * The last IFN gets the address, remove the
             * old one
             */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Moving ifa %p from %s (0x%x) to %s (0x%x)\n\x00" as *const u8
                            as *const libc::c_char,
                        sctp_ifap as *mut libc::c_void,
                        (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(),
                        (*(*sctp_ifap).ifn_p).ifn_index,
                        if_name,
                        ifn_index,
                    );
                }
            }
            /* remove the address from the old ifn */
            sctp_remove_ifa_from_ifn(sctp_ifap);
            /* move the address over to the new ifn */
            sctp_add_ifa_to_ifn(sctp_ifnp, sctp_ifap);
        } else {
            /* repair ifnp which was NULL ? */
            (*sctp_ifap).localifa_flags = 0x1u32;
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Repairing ifn %p for ifa %p\n\x00" as *const u8 as *const libc::c_char,
                        sctp_ifnp as *mut libc::c_void,
                        sctp_ifap as *mut libc::c_void,
                    );
                }
            }
            sctp_add_ifa_to_ifn(sctp_ifnp, sctp_ifap);
        }
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        return sctp_ifap;
    } else {
        let mut hash_addr_head = 0 as *mut sctp_ifalist;
        let mut hash_of_addr = 0;
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        sctp_ifap = malloc(::std::mem::size_of::<sctp_ifa>() as libc::c_ulong) as *mut sctp_ifa;
        if 0x1i32 & 0x100i32 != 0 {
            memset(
                sctp_ifap as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sctp_ifa>() as libc::c_ulong,
            );
        }
        if sctp_ifap.is_null() {
            return 0 as *mut sctp_ifa;
        }
        memset(
            sctp_ifap as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_ifa>() as libc::c_ulong,
        );
        (*sctp_ifap).ifn_p = sctp_ifnp;
        ::std::intrinsics::atomic_xadd(&mut (*sctp_ifnp).refcount, 1u32);
        (*sctp_ifap).vrf_id = vrf_id;
        (*sctp_ifap).ifa = ifa;
        match (*addr).sa_family as libc::c_int {
            2 => {
                memcpy(
                    &mut (*sctp_ifap).address as *mut sctp_sockstore as *mut libc::c_void,
                    addr as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                );
            }
            10 => {
                memcpy(
                    &mut (*sctp_ifap).address as *mut sctp_sockstore as *mut libc::c_void,
                    addr as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                );
            }
            123 => {
                memcpy(
                    &mut (*sctp_ifap).address as *mut sctp_sockstore as *mut libc::c_void,
                    addr as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
                );
            }
            _ => {}
        }
        (*sctp_ifap).localifa_flags = (0x1i32 | 0x4i32) as uint32_t;
        (*sctp_ifap).flags = ifa_flags;
        /* Set scope */
        match (*sctp_ifap).address.sa.sa_family as libc::c_int {
            2 => {
                let mut sin = 0 as *mut sockaddr_in;
                sin = &mut (*sctp_ifap).address.sin;
                if strncmp(
                    (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(),
                    b"lo\x00" as *const u8 as *const libc::c_char,
                    2u64,
                ) == 0i32
                    || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(0isize) as libc::c_int
                        == 127i32
                {
                    (*sctp_ifap).src_is_loop = 1u8
                }
                if *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t).offset(0isize)
                    as libc::c_int
                    == 10i32
                    || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(0isize) as libc::c_int
                        == 172i32
                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                            .offset(1isize) as libc::c_int
                            >= 16i32
                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                            .offset(1isize) as libc::c_int
                            <= 32i32
                    || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(0isize) as libc::c_int
                        == 192i32
                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                            .offset(1isize) as libc::c_int
                            == 168i32
                {
                    (*sctp_ifap).src_is_priv = 1u8
                }
                (*sctp_ifnp).num_v4 = (*sctp_ifnp).num_v4.wrapping_add(1);
                if new_ifn_af != 0 {
                    new_ifn_af = 2i32
                }
            }
            10 => {
                let mut sin6 = 0 as *mut sockaddr_in6;
                sin6 = &mut (*sctp_ifap).address.sin6;
                if strncmp(
                    (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(),
                    b"lo\x00" as *const u8 as *const libc::c_char,
                    2u64,
                ) == 0i32
                    || ({
                        let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                        ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                            && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                            && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                            && (*__a).__in6_u.__u6_addr32[3usize] == htonl(1u32))
                            as libc::c_int
                    }) != 0
                {
                    (*sctp_ifap).src_is_loop = 1u8
                }
                if ({
                    let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                        == htonl(0xfe800000u32)) as libc::c_int
                }) != 0
                {
                    (*sctp_ifap).src_is_priv = 1u8
                }
                (*sctp_ifnp).num_v6 = (*sctp_ifnp).num_v6.wrapping_add(1);
                if new_ifn_af != 0 {
                    new_ifn_af = 10i32
                }
            }
            123 => {
                if new_ifn_af != 0 {
                    new_ifn_af = 123i32
                }
            }
            _ => new_ifn_af = 0i32,
        }
        hash_of_addr = sctp_get_ifa_hash_val(&mut (*sctp_ifap).address.sa);
        if (*sctp_ifap).src_is_priv as libc::c_int == 0i32
            && (*sctp_ifap).src_is_loop as libc::c_int == 0i32
        {
            (*sctp_ifap).src_is_glob = 1u8
        }
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        hash_addr_head = &mut *(*vrf)
            .vrf_addr_hash
            .offset((hash_of_addr as libc::c_ulong & (*vrf).vrf_addr_hashmark) as isize)
            as *mut sctp_ifalist;
        (*sctp_ifap).next_bucket.le_next = (*hash_addr_head).lh_first;
        if !(*sctp_ifap).next_bucket.le_next.is_null() {
            (*(*hash_addr_head).lh_first).next_bucket.le_prev =
                &mut (*sctp_ifap).next_bucket.le_next
        }
        (*hash_addr_head).lh_first = sctp_ifap;
        (*sctp_ifap).next_bucket.le_prev = &mut (*hash_addr_head).lh_first;
        (*sctp_ifap).refcount = 1u32;
        (*sctp_ifap).next_ifa.le_next = (*sctp_ifnp).ifalist.lh_first;
        if !(*sctp_ifap).next_ifa.le_next.is_null() {
            (*(*sctp_ifnp).ifalist.lh_first).next_ifa.le_prev = &mut (*sctp_ifap).next_ifa.le_next
        }
        (*sctp_ifnp).ifalist.lh_first = sctp_ifap;
        (*sctp_ifap).next_ifa.le_prev = &mut (*sctp_ifnp).ifalist.lh_first;
        (*sctp_ifnp).ifa_count = (*sctp_ifnp).ifa_count.wrapping_add(1);
        (*vrf).total_ifa_count = (*vrf).total_ifa_count.wrapping_add(1);
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_ifas, 1u32);
        if new_ifn_af != 0 {
            (*sctp_ifnp).registered_af = new_ifn_af as uint32_t
        }
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        if dynamic_add != 0 {
            let mut wi = 0 as *mut sctp_laddr;
            ::std::intrinsics::atomic_xadd(&mut (*sctp_ifap).refcount, 1u32);
            wi = malloc(system_base_info.sctppcbinfo.ipi_zone_laddr) as *mut sctp_laddr;
            if wi.is_null() {
                /*
                 * Gak, what can we do? We have lost an address
                 * change can you say HOSED?
                 */
                if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Lost an address change?\n\x00" as *const u8 as *const libc::c_char,
                        );
                    }
                }
                /* Opps, must decrement the count */
                sctp_del_addr_from_vrf(vrf_id, addr, ifn_index, if_name);
                return 0 as *mut sctp_ifa;
            }
            ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
            memset(
                wi as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sctp_laddr>() as libc::c_ulong,
            );
            gettimeofday(&mut (*wi).start_time, 0 as *mut timezone);
            (*wi).ifa = sctp_ifap;
            (*wi).action = 0xc001u32;
            pthread_mutex_lock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
            (*wi).sctp_nxt_addr.le_next = system_base_info.sctppcbinfo.addr_wq.lh_first;
            if !(*wi).sctp_nxt_addr.le_next.is_null() {
                (*system_base_info.sctppcbinfo.addr_wq.lh_first)
                    .sctp_nxt_addr
                    .le_prev = &mut (*wi).sctp_nxt_addr.le_next
            }
            system_base_info.sctppcbinfo.addr_wq.lh_first = wi;
            (*wi).sctp_nxt_addr.le_prev = &mut system_base_info.sctppcbinfo.addr_wq.lh_first;
            sctp_timer_start(
                17i32,
                0 as *mut sctp_inpcb,
                0 as *mut sctp_tcb,
                0 as *mut sctp_nets,
            );
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
        } else {
            /* it's ready for use */
            (*sctp_ifap).localifa_flags &= !(0x4i32) as libc::c_uint
        }
        return sctp_ifap;
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_del_addr_from_vrf(
    mut vrf_id: uint32_t,
    mut addr: *mut sockaddr,
    mut ifn_index: uint32_t,
    mut if_name: *const libc::c_char,
) {
    let mut vrf = 0 as *mut sctp_vrf;
    let mut sctp_ifap = 0 as *mut sctp_ifa;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    vrf = sctp_find_vrf(vrf_id);
    if vrf.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Can\'t find vrf_id 0x%x\n\x00" as *const u8 as *const libc::c_char,
                    vrf_id,
                );
            }
        }
    } else {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"vrf_id 0x%x: deleting address:\x00" as *const u8 as *const libc::c_char,
                    vrf_id,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
            sctp_print_address(addr);
        }
        sctp_ifap = sctp_find_ifa_by_addr(addr, (*vrf).vrf_id, 1i32);
        if !sctp_ifap.is_null() {
            /* Validate the delete */
            if !(*sctp_ifap).ifn_p.is_null() {
                let mut valid = 0i32;
                /*-
                 * The name has priority over the ifn_index
                 * if its given. We do this especially for
                 * panda who might recycle indexes fast.
                 */
                if !if_name.is_null() {
                    if strncmp(if_name, (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(), 16u64) == 0i32
                    {
                        /* They match its a correct delete */
                        valid = 1i32
                    }
                }
                if valid == 0 {
                    /* last ditch check ifn_index */
                    if ifn_index == (*(*sctp_ifap).ifn_p).ifn_index {
                        valid = 1i32
                    }
                }
                if valid == 0 {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"ifn:%d ifname:%s does not match addresses\n\x00" as *const u8
                                    as *const libc::c_char,
                                ifn_index,
                                if if_name.is_null() {
                                    b"NULL\x00" as *const u8 as *const libc::c_char
                                } else {
                                    if_name
                                },
                            );
                        }
                    }
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"ifn:%d ifname:%s - ignoring delete\n\x00" as *const u8
                                    as *const libc::c_char,
                                (*(*sctp_ifap).ifn_p).ifn_index,
                                (*(*sctp_ifap).ifn_p).ifn_name.as_mut_ptr(),
                            );
                        }
                    }
                    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
                    return;
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Deleting ifa %p\n\x00" as *const u8 as *const libc::c_char,
                        sctp_ifap as *mut libc::c_void,
                    );
                }
            }
            (*sctp_ifap).localifa_flags &= 0x1u32;
            /*
             * We don't set the flag. This means that the structure will
             * hang around in EP's that have bound specific to it until
             * they close. This gives us TCP like behavior if someone
             * removes an address (or for that matter adds it right back).
             */
            /* sctp_ifap->localifa_flags |= SCTP_BEING_DELETED; */
            (*vrf).total_ifa_count = (*vrf).total_ifa_count.wrapping_sub(1);
            if !(*sctp_ifap).next_bucket.le_next.is_null() {
                (*(*sctp_ifap).next_bucket.le_next).next_bucket.le_prev =
                    (*sctp_ifap).next_bucket.le_prev
            }
            *(*sctp_ifap).next_bucket.le_prev = (*sctp_ifap).next_bucket.le_next;
            sctp_remove_ifa_from_ifn(sctp_ifap);
        } else {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Del Addr-ifn:%d Could not find address:\x00" as *const u8
                            as *const libc::c_char,
                        ifn_index,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                sctp_print_address(addr);
            }
        }
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    if !sctp_ifap.is_null() {
        let mut wi = 0 as *mut sctp_laddr;
        wi = malloc(system_base_info.sctppcbinfo.ipi_zone_laddr) as *mut sctp_laddr;
        if wi.is_null() {
            /*
             * Gak, what can we do? We have lost an address
             * change can you say HOSED?
             */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x800000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Lost an address change?\n\x00" as *const u8 as *const libc::c_char,
                    );
                }
            }
            /* Oops, must decrement the count */
            sctp_free_ifa(sctp_ifap);
            return;
        }
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
        memset(
            wi as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_laddr>() as libc::c_ulong,
        );
        gettimeofday(&mut (*wi).start_time, 0 as *mut timezone);
        (*wi).ifa = sctp_ifap;
        (*wi).action = 0xc002u32;
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
        /*
         * Should this really be a tailq? As it is we will process the
         * newest first :-0
         */
        (*wi).sctp_nxt_addr.le_next = system_base_info.sctppcbinfo.addr_wq.lh_first;
        if !(*wi).sctp_nxt_addr.le_next.is_null() {
            (*system_base_info.sctppcbinfo.addr_wq.lh_first)
                .sctp_nxt_addr
                .le_prev = &mut (*wi).sctp_nxt_addr.le_next
        }
        system_base_info.sctppcbinfo.addr_wq.lh_first = wi;
        (*wi).sctp_nxt_addr.le_prev = &mut system_base_info.sctppcbinfo.addr_wq.lh_first;
        sctp_timer_start(
            17i32,
            0 as *mut sctp_inpcb,
            0 as *mut sctp_tcb,
            0 as *mut sctp_nets,
        );
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
    };
}
unsafe extern "C" fn sctp_does_stcb_own_this_addr(
    mut stcb: *mut sctp_tcb,
    mut to: *mut sockaddr,
) -> libc::c_int {
    let mut loopback_scope = 0;
    let mut ipv4_local_scope = 0;
    let mut ipv4_addr_legal = 0;
    let mut local_scope = 0;
    let mut site_scope = 0;
    let mut ipv6_addr_legal = 0;
    let mut conn_addr_legal = 0;
    let mut vrf = 0 as *mut sctp_vrf;
    loopback_scope = (*stcb).asoc.scope.loopback_scope as libc::c_int;
    ipv4_local_scope = (*stcb).asoc.scope.ipv4_local_scope as libc::c_int;
    ipv4_addr_legal = (*stcb).asoc.scope.ipv4_addr_legal as libc::c_int;
    local_scope = (*stcb).asoc.scope.local_scope as libc::c_int;
    site_scope = (*stcb).asoc.scope.site_scope as libc::c_int;
    ipv6_addr_legal = (*stcb).asoc.scope.ipv6_addr_legal as libc::c_int;
    conn_addr_legal = (*stcb).asoc.scope.conn_addr_legal as libc::c_int;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    vrf = sctp_find_vrf((*stcb).asoc.vrf_id);
    if vrf.is_null() {
        /* no vrf, no addresses */
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        return 0i32;
    }
    if (*(*stcb).sctp_ep).sctp_flags & 0x4u32 != 0 {
        let mut sctp_ifn = 0 as *mut sctp_ifn;
        sctp_ifn = (*vrf).ifnlist.lh_first;
        while !sctp_ifn.is_null() {
            if !(loopback_scope == 0i32
                && strncmp(
                    (*sctp_ifn).ifn_name.as_mut_ptr(),
                    b"lo\x00" as *const u8 as *const libc::c_char,
                    2u64,
                ) == 0i32)
            {
                let mut sctp_ifa = 0 as *mut sctp_ifa;
                sctp_ifa = (*sctp_ifn).ifalist.lh_first;
                while !sctp_ifa.is_null() {
                    if !(sctp_is_addr_restricted(stcb, sctp_ifa) != 0
                        && sctp_is_addr_pending(stcb, sctp_ifa) == 0)
                    {
                        if !((*sctp_ifa).address.sa.sa_family as libc::c_int
                            != (*to).sa_family as libc::c_int)
                        {
                            let mut current_block_34: u64;
                            match (*sctp_ifa).address.sa.sa_family as libc::c_int {
                                2 => {
                                    current_block_34 = 15885410163891778031;
                                    match current_block_34 {
                                        3859176954901031106 => {
                                            if conn_addr_legal != 0 {
                                                let mut sconn = 0 as *mut sockaddr_conn;
                                                let mut rsconn = 0 as *mut sockaddr_conn;
                                                sconn = &mut (*sctp_ifa).address.sconn;
                                                rsconn = to as *mut sockaddr_conn;
                                                if (*sconn).sconn_addr == (*rsconn).sconn_addr {
                                                    pthread_mutex_unlock(
                                                        &mut system_base_info
                                                            .sctppcbinfo
                                                            .ipi_addr_mtx,
                                                    );
                                                    return 1i32;
                                                }
                                            }
                                        }
                                        15885410163891778031 => {
                                            if ipv4_addr_legal != 0 {
                                                let mut sin = 0 as *mut sockaddr_in;
                                                let mut rsin = 0 as *mut sockaddr_in;
                                                sin = &mut (*sctp_ifa).address.sin;
                                                rsin = to as *mut sockaddr_in;
                                                if !(ipv4_local_scope == 0i32
                                                    && (*(&mut (*sin).sin_addr.s_addr
                                                        as *mut in_addr_t
                                                        as *mut uint8_t)
                                                        .offset(0isize)
                                                        as libc::c_int
                                                        == 10i32
                                                        || *(&mut (*sin).sin_addr.s_addr
                                                            as *mut in_addr_t
                                                            as *mut uint8_t)
                                                            .offset(0isize)
                                                            as libc::c_int
                                                            == 172i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                >= 16i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                <= 32i32
                                                        || *(&mut (*sin).sin_addr.s_addr
                                                            as *mut in_addr_t
                                                            as *mut uint8_t)
                                                            .offset(0isize)
                                                            as libc::c_int
                                                            == 192i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                == 168i32))
                                                {
                                                    if (*sin).sin_addr.s_addr
                                                        == (*rsin).sin_addr.s_addr
                                                    {
                                                        pthread_mutex_unlock(
                                                            &mut system_base_info
                                                                .sctppcbinfo
                                                                .ipi_addr_mtx,
                                                        );
                                                        return 1i32;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {
                                            if ipv6_addr_legal != 0 {
                                                let mut sin6 = 0 as *mut sockaddr_in6;
                                                let mut rsin6 = 0 as *mut sockaddr_in6;
                                                sin6 = &mut (*sctp_ifa).address.sin6;
                                                rsin6 = to as *mut sockaddr_in6;
                                                if ({
                                                    let mut __a = &mut (*sin6).sin6_addr
                                                        as *mut in6_addr
                                                        as *const in6_addr;
                                                    ((*__a).__in6_u.__u6_addr32[0usize]
                                                        & htonl(0xffc00000u32)
                                                        == htonl(0xfe800000u32))
                                                        as libc::c_int
                                                }) != 0
                                                {
                                                    if local_scope == 0i32 {
                                                        current_block_34 = 4808432441040389987;
                                                    } else {
                                                        current_block_34 = 10891380440665537214;
                                                    }
                                                /* SCTP_EMBEDDED_V6_SCOPE */
                                                } else {
                                                    current_block_34 = 10891380440665537214;
                                                }
                                                match current_block_34 {
                                                    4808432441040389987 => {}
                                                    _ => {
                                                        if !(site_scope == 0i32
                                                            && ({
                                                                let mut __a = &mut (*sin6).sin6_addr
                                                                    as *mut in6_addr
                                                                    as *const in6_addr;
                                                                ((*__a).__in6_u.__u6_addr32[0usize]
                                                                    & htonl(0xffc00000u32)
                                                                    == htonl(0xfec00000u32))
                                                                    as libc::c_int
                                                            }) != 0)
                                                        {
                                                            if SCTP6_ARE_ADDR_EQUAL(sin6, rsin6)
                                                                != 0
                                                            {
                                                                pthread_mutex_unlock(
                                                                    &mut system_base_info
                                                                        .sctppcbinfo
                                                                        .ipi_addr_mtx,
                                                                );
                                                                return 1i32;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                10 => {
                                    current_block_34 = 10332508473234791970;
                                    match current_block_34 {
                                        3859176954901031106 => {
                                            if conn_addr_legal != 0 {
                                                let mut sconn = 0 as *mut sockaddr_conn;
                                                let mut rsconn = 0 as *mut sockaddr_conn;
                                                sconn = &mut (*sctp_ifa).address.sconn;
                                                rsconn = to as *mut sockaddr_conn;
                                                if (*sconn).sconn_addr == (*rsconn).sconn_addr {
                                                    pthread_mutex_unlock(
                                                        &mut system_base_info
                                                            .sctppcbinfo
                                                            .ipi_addr_mtx,
                                                    );
                                                    return 1i32;
                                                }
                                            }
                                        }
                                        15885410163891778031 => {
                                            if ipv4_addr_legal != 0 {
                                                let mut sin = 0 as *mut sockaddr_in;
                                                let mut rsin = 0 as *mut sockaddr_in;
                                                sin = &mut (*sctp_ifa).address.sin;
                                                rsin = to as *mut sockaddr_in;
                                                if !(ipv4_local_scope == 0i32
                                                    && (*(&mut (*sin).sin_addr.s_addr
                                                        as *mut in_addr_t
                                                        as *mut uint8_t)
                                                        .offset(0isize)
                                                        as libc::c_int
                                                        == 10i32
                                                        || *(&mut (*sin).sin_addr.s_addr
                                                            as *mut in_addr_t
                                                            as *mut uint8_t)
                                                            .offset(0isize)
                                                            as libc::c_int
                                                            == 172i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                >= 16i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                <= 32i32
                                                        || *(&mut (*sin).sin_addr.s_addr
                                                            as *mut in_addr_t
                                                            as *mut uint8_t)
                                                            .offset(0isize)
                                                            as libc::c_int
                                                            == 192i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                == 168i32))
                                                {
                                                    if (*sin).sin_addr.s_addr
                                                        == (*rsin).sin_addr.s_addr
                                                    {
                                                        pthread_mutex_unlock(
                                                            &mut system_base_info
                                                                .sctppcbinfo
                                                                .ipi_addr_mtx,
                                                        );
                                                        return 1i32;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {
                                            if ipv6_addr_legal != 0 {
                                                let mut sin6 = 0 as *mut sockaddr_in6;
                                                let mut rsin6 = 0 as *mut sockaddr_in6;
                                                sin6 = &mut (*sctp_ifa).address.sin6;
                                                rsin6 = to as *mut sockaddr_in6;
                                                if ({
                                                    let mut __a = &mut (*sin6).sin6_addr
                                                        as *mut in6_addr
                                                        as *const in6_addr;
                                                    ((*__a).__in6_u.__u6_addr32[0usize]
                                                        & htonl(0xffc00000u32)
                                                        == htonl(0xfe800000u32))
                                                        as libc::c_int
                                                }) != 0
                                                {
                                                    if local_scope == 0i32 {
                                                        current_block_34 = 4808432441040389987;
                                                    } else {
                                                        current_block_34 = 10891380440665537214;
                                                    }
                                                } else {
                                                    current_block_34 = 10891380440665537214;
                                                }
                                                match current_block_34 {
                                                    4808432441040389987 => {}
                                                    _ => {
                                                        if !(site_scope == 0i32
                                                            && ({
                                                                let mut __a = &mut (*sin6).sin6_addr
                                                                    as *mut in6_addr
                                                                    as *const in6_addr;
                                                                ((*__a).__in6_u.__u6_addr32[0usize]
                                                                    & htonl(0xffc00000u32)
                                                                    == htonl(0xfec00000u32))
                                                                    as libc::c_int
                                                            }) != 0)
                                                        {
                                                            if SCTP6_ARE_ADDR_EQUAL(sin6, rsin6)
                                                                != 0
                                                            {
                                                                pthread_mutex_unlock(
                                                                    &mut system_base_info
                                                                        .sctppcbinfo
                                                                        .ipi_addr_mtx,
                                                                );
                                                                return 1i32;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                123 => {
                                    current_block_34 = 3859176954901031106;
                                    match current_block_34 {
                                        3859176954901031106 => {
                                            if conn_addr_legal != 0 {
                                                let mut sconn = 0 as *mut sockaddr_conn;
                                                let mut rsconn = 0 as *mut sockaddr_conn;
                                                sconn = &mut (*sctp_ifa).address.sconn;
                                                rsconn = to as *mut sockaddr_conn;
                                                if (*sconn).sconn_addr == (*rsconn).sconn_addr {
                                                    pthread_mutex_unlock(
                                                        &mut system_base_info
                                                            .sctppcbinfo
                                                            .ipi_addr_mtx,
                                                    );
                                                    return 1i32;
                                                }
                                            }
                                        }
                                        15885410163891778031 => {
                                            if ipv4_addr_legal != 0 {
                                                let mut sin = 0 as *mut sockaddr_in;
                                                let mut rsin = 0 as *mut sockaddr_in;
                                                sin = &mut (*sctp_ifa).address.sin;
                                                rsin = to as *mut sockaddr_in;
                                                if !(ipv4_local_scope == 0i32
                                                    && (*(&mut (*sin).sin_addr.s_addr
                                                        as *mut in_addr_t
                                                        as *mut uint8_t)
                                                        .offset(0isize)
                                                        as libc::c_int
                                                        == 10i32
                                                        || *(&mut (*sin).sin_addr.s_addr
                                                            as *mut in_addr_t
                                                            as *mut uint8_t)
                                                            .offset(0isize)
                                                            as libc::c_int
                                                            == 172i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                >= 16i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                <= 32i32
                                                        || *(&mut (*sin).sin_addr.s_addr
                                                            as *mut in_addr_t
                                                            as *mut uint8_t)
                                                            .offset(0isize)
                                                            as libc::c_int
                                                            == 192i32
                                                            && *(&mut (*sin).sin_addr.s_addr
                                                                as *mut in_addr_t
                                                                as *mut uint8_t)
                                                                .offset(1isize)
                                                                as libc::c_int
                                                                == 168i32))
                                                {
                                                    if (*sin).sin_addr.s_addr
                                                        == (*rsin).sin_addr.s_addr
                                                    {
                                                        pthread_mutex_unlock(
                                                            &mut system_base_info
                                                                .sctppcbinfo
                                                                .ipi_addr_mtx,
                                                        );
                                                        return 1i32;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {
                                            if ipv6_addr_legal != 0 {
                                                let mut sin6 = 0 as *mut sockaddr_in6;
                                                let mut rsin6 = 0 as *mut sockaddr_in6;
                                                sin6 = &mut (*sctp_ifa).address.sin6;
                                                rsin6 = to as *mut sockaddr_in6;
                                                if ({
                                                    let mut __a = &mut (*sin6).sin6_addr
                                                        as *mut in6_addr
                                                        as *const in6_addr;
                                                    ((*__a).__in6_u.__u6_addr32[0usize]
                                                        & htonl(0xffc00000u32)
                                                        == htonl(0xfe800000u32))
                                                        as libc::c_int
                                                }) != 0
                                                {
                                                    if local_scope == 0i32 {
                                                        current_block_34 = 4808432441040389987;
                                                    } else {
                                                        current_block_34 = 10891380440665537214;
                                                    }
                                                } else {
                                                    current_block_34 = 10891380440665537214;
                                                }
                                                match current_block_34 {
                                                    4808432441040389987 => {}
                                                    _ => {
                                                        if !(site_scope == 0i32
                                                            && ({
                                                                let mut __a = &mut (*sin6).sin6_addr
                                                                    as *mut in6_addr
                                                                    as *const in6_addr;
                                                                ((*__a).__in6_u.__u6_addr32[0usize]
                                                                    & htonl(0xffc00000u32)
                                                                    == htonl(0xfec00000u32))
                                                                    as libc::c_int
                                                            }) != 0)
                                                        {
                                                            if SCTP6_ARE_ADDR_EQUAL(sin6, rsin6)
                                                                != 0
                                                            {
                                                                pthread_mutex_unlock(
                                                                    &mut system_base_info
                                                                        .sctppcbinfo
                                                                        .ipi_addr_mtx,
                                                                );
                                                                return 1i32;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    /* TSNH */
                    sctp_ifa = (*sctp_ifa).next_ifa.le_next
                }
            }
            sctp_ifn = (*sctp_ifn).next_ifn.le_next
        }
    } else {
        let mut laddr = 0 as *mut sctp_laddr;
        laddr = (*(*stcb).sctp_ep).sctp_addr_list.lh_first;
        while !laddr.is_null() {
            if (*(*laddr).ifa).localifa_flags & 0x2u32 != 0 {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"ifa being deleted\n\x00" as *const u8 as *const libc::c_char,
                        );
                    }
                }
            } else if !(sctp_is_addr_restricted(stcb, (*laddr).ifa) != 0
                && sctp_is_addr_pending(stcb, (*laddr).ifa) == 0)
            {
                if !((*(*laddr).ifa).address.sa.sa_family as libc::c_int
                    != (*to).sa_family as libc::c_int)
                {
                    match (*to).sa_family as libc::c_int {
                        2 => {
                            let mut sin_0 = 0 as *mut sockaddr_in;
                            let mut rsin_0 = 0 as *mut sockaddr_in;
                            sin_0 = &mut (*(*laddr).ifa).address.sin;
                            rsin_0 = to as *mut sockaddr_in;
                            if (*sin_0).sin_addr.s_addr == (*rsin_0).sin_addr.s_addr {
                                pthread_mutex_unlock(
                                    &mut system_base_info.sctppcbinfo.ipi_addr_mtx,
                                );
                                return 1i32;
                            }
                        }
                        10 => {
                            let mut sin6_0 = 0 as *mut sockaddr_in6;
                            let mut rsin6_0 = 0 as *mut sockaddr_in6;
                            sin6_0 = &mut (*(*laddr).ifa).address.sin6;
                            rsin6_0 = to as *mut sockaddr_in6;
                            if SCTP6_ARE_ADDR_EQUAL(sin6_0, rsin6_0) != 0 {
                                pthread_mutex_unlock(
                                    &mut system_base_info.sctppcbinfo.ipi_addr_mtx,
                                );
                                return 1i32;
                            }
                        }
                        123 => {
                            let mut sconn_0 = 0 as *mut sockaddr_conn;
                            let mut rsconn_0 = 0 as *mut sockaddr_conn;
                            sconn_0 = &mut (*(*laddr).ifa).address.sconn;
                            rsconn_0 = to as *mut sockaddr_conn;
                            if (*sconn_0).sconn_addr == (*rsconn_0).sconn_addr {
                                pthread_mutex_unlock(
                                    &mut system_base_info.sctppcbinfo.ipi_addr_mtx,
                                );
                                return 1i32;
                            }
                        }
                        _ => {}
                    }
                }
            }
            /* We allow pending addresses, where we
             * have sent an asconf-add to be considered
             * valid.
             */
            laddr = (*laddr).sctp_nxt_addr.le_next
        }
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    return 0i32;
}
unsafe extern "C" fn sctp_tcb_special_locate(
    mut inp_p: *mut *mut sctp_inpcb,
    mut from: *mut sockaddr,
    mut to: *mut sockaddr,
    mut netp: *mut *mut sctp_nets,
    mut vrf_id: uint32_t,
) -> *mut sctp_tcb {
    /* *** ASSUMES THE CALLER holds the INP_INFO_RLOCK */
    /*
     * If we support the TCP model, then we must now dig through to see
     * if we can find our endpoint in the list of tcp ep's.
     */

    let mut lport = 0;
    let mut rport = 0;
    let mut ephead = 0 as *mut sctppcbhead;
    let mut inp = 0 as *mut sctp_inpcb;
    if to.is_null() || from.is_null() {
        return 0 as *mut sctp_tcb;
    }
    match (*to).sa_family as libc::c_int {
        2 => {
            if (*from).sa_family as libc::c_int == 2i32 {
                lport = (*(to as *mut sockaddr_in)).sin_port;
                rport = (*(from as *mut sockaddr_in)).sin_port
            } else {
                return 0 as *mut sctp_tcb;
            }
        }
        10 => {
            if (*from).sa_family as libc::c_int == 10i32 {
                lport = (*(to as *mut sockaddr_in6)).sin6_port;
                rport = (*(from as *mut sockaddr_in6)).sin6_port
            } else {
                return 0 as *mut sctp_tcb;
            }
        }
        123 => {
            if (*from).sa_family as libc::c_int == 123i32 {
                lport = (*(to as *mut sockaddr_conn)).sconn_port;
                rport = (*(from as *mut sockaddr_conn)).sconn_port
            } else {
                return 0 as *mut sctp_tcb;
            }
        }
        _ => return 0 as *mut sctp_tcb,
    }
    ephead = &mut *system_base_info.sctppcbinfo.sctp_tcpephash.offset(
        ((lport as libc::c_int | rport as libc::c_int) as libc::c_ulong
            & system_base_info.sctppcbinfo.hashtcpmark) as isize,
    ) as *mut sctppcbhead;

    /*
     * Ok now for each of the guys in this bucket we must look and see:
     * - Does the remote port match. - Does there single association's
     * addresses match this address (to). If so we update p_ep to point
     * to this ep and return the tcb from it.
     */
    inp = (*ephead).lh_first;
    while !inp.is_null() {
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        if (*inp).sctp_flags & 0x20000000u32 != 0 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        } else if lport as libc::c_int != (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        } else if (*inp).def_vrf_id != vrf_id {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        } else {
            let mut current_block_106: u64;
            if (*inp).sctp_flags & 0x4u32 == 0u32 {
                let mut laddr = 0 as *mut sctp_laddr;
                let mut match_0 = 0i32;
                laddr = (*inp).sctp_addr_list.lh_first;
                while !laddr.is_null() {
                    if (*laddr).ifa.is_null() {
                        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                            if system_base_info.debug_printf.is_some() {
                                system_base_info
                                    .debug_printf
                                    .expect("non-null function pointer")(
                                    b"%s: NULL ifa\n\x00" as *const u8 as *const libc::c_char,
                                    (*::std::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                        b"sctp_tcb_special_locate\x00",
                                    ))
                                    .as_ptr(),
                                );
                            }
                        }
                    } else if (*(*laddr).ifa).localifa_flags & 0x2u32 != 0 {
                        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                            if system_base_info.debug_printf.is_some() {
                                system_base_info
                                    .debug_printf
                                    .expect("non-null function pointer")(
                                    b"ifa being deleted\n\x00" as *const u8 as *const libc::c_char,
                                );
                            }
                        }
                    } else if (*(*laddr).ifa).address.sa.sa_family as libc::c_int
                        == (*to).sa_family as libc::c_int
                    {
                        /* see if it matches */
                        if (*from).sa_family as libc::c_int == 2i32 {
                            let mut intf_addr = 0 as *mut sockaddr_in;
                            let mut sin = 0 as *mut sockaddr_in;
                            intf_addr = &mut (*(*laddr).ifa).address.sin;
                            sin = to as *mut sockaddr_in;
                            if (*sin).sin_addr.s_addr == (*intf_addr).sin_addr.s_addr {
                                match_0 = 1i32;
                                break;
                            }
                        }
                        if (*from).sa_family as libc::c_int == 10i32 {
                            let mut intf_addr6 = 0 as *mut sockaddr_in6;
                            let mut sin6 = 0 as *mut sockaddr_in6;
                            sin6 = to as *mut sockaddr_in6;
                            intf_addr6 = &mut (*(*laddr).ifa).address.sin6;
                            if SCTP6_ARE_ADDR_EQUAL(sin6, intf_addr6) != 0 {
                                match_0 = 1i32;
                                break;
                            }
                        }
                        if (*from).sa_family as libc::c_int == 123i32 {
                            let mut intf_addr_0 = 0 as *mut sockaddr_conn;
                            let mut sconn = 0 as *mut sockaddr_conn;
                            intf_addr_0 = &mut (*(*laddr).ifa).address.sconn;
                            sconn = to as *mut sockaddr_conn;
                            if (*sconn).sconn_addr == (*intf_addr_0).sconn_addr {
                                match_0 = 1i32;
                                break;
                            }
                        }
                    }
                    laddr = (*laddr).sctp_nxt_addr.le_next
                }
                if match_0 == 0i32 {
                    /* This endpoint does not have this address */
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_106 = 14763689060501151050;
                } else {
                    current_block_106 = 16791665189521845338;
                }
            } else {
                current_block_106 = 16791665189521845338;
            }
            match current_block_106 {
                14763689060501151050 => {}
                _ => {
                    let mut stcb = 0 as *mut sctp_tcb;
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if stcb.is_null() {
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    } else {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                        if sctp_does_stcb_own_this_addr(stcb, to) == 0 {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else if (*stcb).rport as libc::c_int != rport as libc::c_int {
                            /* remote port does not match. */
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else if (*stcb).asoc.state & 0x200i32 != 0 {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else if sctp_does_stcb_own_this_addr(stcb, to) == 0 {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            let mut net = 0 as *mut sctp_nets;
                            net = (*stcb).asoc.nets.tqh_first;
                            while !net.is_null() {
                                if !((*net).ro._l_addr.sa.sa_family as libc::c_int
                                    != (*from).sa_family as libc::c_int)
                                {
                                    match (*from).sa_family as libc::c_int {
                                        2 => {
                                            let mut sin_0 = 0 as *mut sockaddr_in;
                                            let mut rsin = 0 as *mut sockaddr_in;
                                            sin_0 = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                                as *mut sockaddr_in;
                                            rsin = from as *mut sockaddr_in;
                                            if (*sin_0).sin_addr.s_addr == (*rsin).sin_addr.s_addr {
                                                /* found it */
                                                if !netp.is_null() {
                                                    *netp = net
                                                }
                                                /* Update the endpoint pointer */
                                                *inp_p = inp;
                                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                                return stcb;
                                            }
                                        }
                                        10 => {
                                            let mut sin6_0 = 0 as *mut sockaddr_in6;
                                            let mut rsin6 = 0 as *mut sockaddr_in6;
                                            sin6_0 = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                                as *mut sockaddr_in6;
                                            rsin6 = from as *mut sockaddr_in6;
                                            if SCTP6_ARE_ADDR_EQUAL(sin6_0, rsin6) != 0 {
                                                /* found it */
                                                if !netp.is_null() {
                                                    *netp = net
                                                }
                                                /* Update the endpoint pointer */
                                                *inp_p = inp;
                                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                                return stcb;
                                            }
                                        }
                                        123 => {
                                            let mut sconn_0 = 0 as *mut sockaddr_conn;
                                            let mut rsconn = 0 as *mut sockaddr_conn;
                                            sconn_0 = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                                as *mut sockaddr_conn;
                                            rsconn = from as *mut sockaddr_conn;
                                            if (*sconn_0).sconn_addr == (*rsconn).sconn_addr {
                                                /* found it */
                                                if !netp.is_null() {
                                                    *netp = net
                                                }
                                                /* Update the endpoint pointer */
                                                *inp_p = inp;
                                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                                return stcb;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                /* not the same family, can't be a match */
                                net = (*net).sctp_next.tqe_next
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        }
                    }
                }
            }
        }
        inp = (*inp).sctp_hash.le_next
    }
    return 0 as *mut sctp_tcb;
}
/*
 * rules for use
 *
 * 1) If I return a NULL you must decrement any INP ref cnt. 2) If I find an
 * stcb, both will be locked (locked_tcb and stcb) but decrement will be done
 * (if locked == NULL). 3) Decrement happens on return ONLY if locked ==
 * NULL.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_findassociation_ep_addr(
    mut inp_p: *mut *mut sctp_inpcb,
    mut remote: *mut sockaddr,
    mut netp: *mut *mut sctp_nets,
    mut local: *mut sockaddr,
    mut locked_tcb: *mut sctp_tcb,
) -> *mut sctp_tcb {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut net = 0 as *mut sctp_nets;
    let mut rport = 0;
    inp = *inp_p;
    match (*remote).sa_family as libc::c_int {
        2 => rport = (*(remote as *mut sockaddr_in)).sin_port,
        10 => rport = (*(remote as *mut sockaddr_in6)).sin6_port,
        123 => rport = (*(remote as *mut sockaddr_conn)).sconn_port,
        _ => return 0 as *mut sctp_tcb,
    }
    if !locked_tcb.is_null() {
        /*
         * UN-lock so we can do proper locking here this occurs when
         * called from load_addresses_from_init.
         */
        ::std::intrinsics::atomic_xadd(&mut (*locked_tcb).asoc.refcnt, 1u32);
        pthread_mutex_unlock(&mut (*locked_tcb).tcb_mtx);
    }
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
        /*-
         * Now either this guy is our listener or it's the
         * connector. If it is the one that issued the connect, then
         * it's only chance is to be the first TCB in the list. If
         * it is the acceptor, then do the special_lookup to hash
         * and find the real inp.
         */
        if !(*inp).sctp_socket.is_null() && (*inp).sctp_flags & 0x8u32 != 0u32 {
            /* to is peer addr, from is my addr */
            stcb = sctp_tcb_special_locate(inp_p, remote, local, netp, (*inp).def_vrf_id);
            if !stcb.is_null() && locked_tcb.is_null() {
                /* we have a locked tcb, lower refcount */
                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
            }
            if !locked_tcb.is_null() && locked_tcb != stcb {
                pthread_mutex_lock(&mut (*(*locked_tcb).sctp_ep).inp_mtx);
                pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
                ::std::intrinsics::atomic_xsub(&mut (*locked_tcb).asoc.refcnt, 1u32);
                pthread_mutex_unlock(&mut (*(*locked_tcb).sctp_ep).inp_mtx);
            }
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
            return stcb;
        } else {
            pthread_mutex_lock(&mut (*inp).inp_mtx);
            if !((*inp).sctp_flags & 0x20000000u32 != 0) {
                stcb = (*inp).sctp_asoc_list.lh_first;
                if !stcb.is_null() {
                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    if (*stcb).rport as libc::c_int != rport as libc::c_int {
                        /* remote port does not match. */
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    } else if (*stcb).asoc.state & 0x200i32 != 0 {
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    } else if !local.is_null() && sctp_does_stcb_own_this_addr(stcb, local) == 0 {
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    } else {
                        /* now look at the list of remote addresses */
                        net = (*stcb).asoc.nets.tqh_first;
                        while !net.is_null() {
                            if !((*net).ro._l_addr.sa.sa_family as libc::c_int
                                != (*remote).sa_family as libc::c_int)
                            {
                                match (*remote).sa_family as libc::c_int {
                                    2 => {
                                        let mut sin = 0 as *mut sockaddr_in;
                                        let mut rsin = 0 as *mut sockaddr_in;
                                        sin = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                            as *mut sockaddr_in;
                                        rsin = remote as *mut sockaddr_in;
                                        if (*sin).sin_addr.s_addr == (*rsin).sin_addr.s_addr {
                                            /* found it */
                                            if !netp.is_null() {
                                                *netp = net
                                            }
                                            if locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*inp).refcount,
                                                    -(1i32),
                                                );
                                            } else if locked_tcb != stcb {
                                                pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
                                            }
                                            if !locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xsub(
                                                    &mut (*locked_tcb).asoc.refcnt,
                                                    1u32,
                                                );
                                            }
                                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                            pthread_mutex_unlock(
                                                &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
                                            );
                                            return stcb;
                                        }
                                    }
                                    10 => {
                                        let mut sin6 = 0 as *mut sockaddr_in6;
                                        let mut rsin6 = 0 as *mut sockaddr_in6;
                                        sin6 = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                            as *mut sockaddr_in6;
                                        rsin6 = remote as *mut sockaddr_in6;
                                        if SCTP6_ARE_ADDR_EQUAL(sin6, rsin6) != 0 {
                                            /* found it */
                                            if !netp.is_null() {
                                                *netp = net
                                            }
                                            if locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*inp).refcount,
                                                    -(1i32),
                                                );
                                            } else if locked_tcb != stcb {
                                                pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
                                            }
                                            if !locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xsub(
                                                    &mut (*locked_tcb).asoc.refcnt,
                                                    1u32,
                                                );
                                            }
                                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                            pthread_mutex_unlock(
                                                &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
                                            );
                                            return stcb;
                                        }
                                    }
                                    123 => {
                                        let mut sconn = 0 as *mut sockaddr_conn;
                                        let mut rsconn = 0 as *mut sockaddr_conn;
                                        sconn = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                            as *mut sockaddr_conn;
                                        rsconn = remote as *mut sockaddr_conn;
                                        if (*sconn).sconn_addr == (*rsconn).sconn_addr {
                                            /* found it */
                                            if !netp.is_null() {
                                                *netp = net
                                            }
                                            if locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*inp).refcount,
                                                    -(1i32),
                                                );
                                            } else if locked_tcb != stcb {
                                                pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
                                            }
                                            if !locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xsub(
                                                    &mut (*locked_tcb).asoc.refcnt,
                                                    1u32,
                                                );
                                            }
                                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                            pthread_mutex_unlock(
                                                &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
                                            );
                                            return stcb;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            /* not the same family */
                            net = (*net).sctp_next.tqe_next
                        }
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    }
                }
            }
        }
    } else {
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        if !((*inp).sctp_flags & 0x20000000u32 != 0) {
            let mut head = 0 as *mut sctpasochead;
            head = &mut *(*inp)
                .sctp_tcbhash
                .offset((rport as libc::c_ulong & (*inp).sctp_hashmark) as isize)
                as *mut sctpasochead;
            stcb = (*head).lh_first;
            while !stcb.is_null() {
                if !((*stcb).rport as libc::c_int != rport as libc::c_int) {
                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    if (*stcb).asoc.state & 0x200i32 != 0 {
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    } else if !local.is_null() && sctp_does_stcb_own_this_addr(stcb, local) == 0 {
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    } else {
                        /* now look at the list of remote addresses */
                        net = (*stcb).asoc.nets.tqh_first;
                        while !net.is_null() {
                            if !((*net).ro._l_addr.sa.sa_family as libc::c_int
                                != (*remote).sa_family as libc::c_int)
                            {
                                match (*remote).sa_family as libc::c_int {
                                    2 => {
                                        let mut sin_0 = 0 as *mut sockaddr_in;
                                        let mut rsin_0 = 0 as *mut sockaddr_in;
                                        sin_0 = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                            as *mut sockaddr_in;
                                        rsin_0 = remote as *mut sockaddr_in;
                                        if (*sin_0).sin_addr.s_addr == (*rsin_0).sin_addr.s_addr {
                                            /* found it */
                                            if !netp.is_null() {
                                                *netp = net
                                            }
                                            if locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*inp).refcount,
                                                    -(1i32),
                                                );
                                            } else if locked_tcb != stcb {
                                                pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
                                            }
                                            if !locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xsub(
                                                    &mut (*locked_tcb).asoc.refcnt,
                                                    1u32,
                                                );
                                            }
                                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                            pthread_mutex_unlock(
                                                &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
                                            );
                                            return stcb;
                                        }
                                    }
                                    10 => {
                                        let mut sin6_0 = 0 as *mut sockaddr_in6;
                                        let mut rsin6_0 = 0 as *mut sockaddr_in6;
                                        sin6_0 = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                            as *mut sockaddr_in6;
                                        rsin6_0 = remote as *mut sockaddr_in6;
                                        if SCTP6_ARE_ADDR_EQUAL(sin6_0, rsin6_0) != 0 {
                                            /* found it */
                                            if !netp.is_null() {
                                                *netp = net
                                            }
                                            if locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*inp).refcount,
                                                    -(1i32),
                                                );
                                            } else if locked_tcb != stcb {
                                                pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
                                            }
                                            if !locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xsub(
                                                    &mut (*locked_tcb).asoc.refcnt,
                                                    1u32,
                                                );
                                            }
                                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                            pthread_mutex_unlock(
                                                &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
                                            );
                                            return stcb;
                                        }
                                    }
                                    123 => {
                                        let mut sconn_0 = 0 as *mut sockaddr_conn;
                                        let mut rsconn_0 = 0 as *mut sockaddr_conn;
                                        sconn_0 = &mut (*net).ro._l_addr as *mut sctp_sockstore
                                            as *mut sockaddr_conn;
                                        rsconn_0 = remote as *mut sockaddr_conn;
                                        if (*sconn_0).sconn_addr == (*rsconn_0).sconn_addr {
                                            /* found it */
                                            if !netp.is_null() {
                                                *netp = net
                                            }
                                            if locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xadd(
                                                    &mut (*inp).refcount,
                                                    -(1i32),
                                                );
                                            } else if locked_tcb != stcb {
                                                pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
                                            }
                                            if !locked_tcb.is_null() {
                                                ::std::intrinsics::atomic_xsub(
                                                    &mut (*locked_tcb).asoc.refcnt,
                                                    1u32,
                                                );
                                            }
                                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                            pthread_mutex_unlock(
                                                &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
                                            );
                                            return stcb;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            /* not the same family */
                            net = (*net).sctp_next.tqe_next
                        }
                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    }
                }
                /* remote port does not match */
                stcb = (*stcb).sctp_tcbhash.le_next
            }
        }
    }
    /* clean up for returning null */
    if !locked_tcb.is_null() {
        pthread_mutex_lock(&mut (*locked_tcb).tcb_mtx);
        ::std::intrinsics::atomic_xsub(&mut (*locked_tcb).asoc.refcnt, 1u32);
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    /* not found */
    return 0 as *mut sctp_tcb;
}
/*
 * Find an association for a specific endpoint using the association id given
 * out in the COMM_UP notification
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_findasoc_ep_asocid_locked(
    mut inp: *mut sctp_inpcb,
    mut asoc_id: sctp_assoc_t,
    mut want_lock: libc::c_int,
) -> *mut sctp_tcb {
    let mut head = 0 as *mut sctpasochead;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut id = 0;
    if inp.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"TSNH ep_associd\n\x00" as *const u8 as *const libc::c_char,
            );
        }
        return 0 as *mut sctp_tcb;
    }
    if (*inp).sctp_flags & 0x20000000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"TSNH ep_associd0\n\x00" as *const u8 as *const libc::c_char,
            );
        }
        return 0 as *mut sctp_tcb;
    }
    id = asoc_id;
    head = &mut *(*inp)
        .sctp_asocidhash
        .offset((id as libc::c_ulong & (*inp).hashasocidmark) as isize)
        as *mut sctpasochead;
    if head.is_null() {
        /* invalid id TSNH */
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"TSNH ep_associd1\n\x00" as *const u8 as *const libc::c_char,
            );
        }
        return 0 as *mut sctp_tcb;
    }
    stcb = (*head).lh_first;
    while !stcb.is_null() {
        if (*stcb).asoc.assoc_id == id {
            if inp != (*stcb).sctp_ep {
                /*
                 * some other guy has the same id active (id
                 * collision ??).
                 */
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"TSNH ep_associd2\n\x00" as *const u8 as *const libc::c_char,
                    );
                }
            } else if !((*stcb).asoc.state & 0x200i32 != 0) {
                if want_lock != 0 {
                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                }
                return stcb;
            }
        }
        stcb = (*stcb).sctp_tcbasocidhash.le_next
    }
    return 0 as *mut sctp_tcb;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_findassociation_ep_asocid(
    mut inp: *mut sctp_inpcb,
    mut asoc_id: sctp_assoc_t,
    mut want_lock: libc::c_int,
) -> *mut sctp_tcb {
    let mut stcb = 0 as *mut sctp_tcb;
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    stcb = sctp_findasoc_ep_asocid_locked(inp, asoc_id, want_lock);
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return stcb;
}
/*
 * Endpoint probe expects that the INP_INFO is locked.
 */
unsafe extern "C" fn sctp_endpoint_probe(
    mut nam: *mut sockaddr,
    mut head: *mut sctppcbhead,
    mut lport: uint16_t,
    mut vrf_id: uint32_t,
) -> *mut sctp_inpcb {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut sin = 0 as *mut sockaddr_in;
    let mut sin6 = 0 as *mut sockaddr_in6;
    let mut sconn = 0 as *mut sockaddr_conn;
    let mut fnd = 0;
    sin = 0 as *mut sockaddr_in;
    sin6 = 0 as *mut sockaddr_in6;
    sconn = 0 as *mut sockaddr_conn;
    match (*nam).sa_family as libc::c_int {
        2 => sin = nam as *mut sockaddr_in,
        10 => sin6 = nam as *mut sockaddr_in6,
        123 => sconn = nam as *mut sockaddr_conn,
        _ => {
            /* unsupported family */
            return 0 as *mut sctp_inpcb;
        }
    }
    if head.is_null() {
        return 0 as *mut sctp_inpcb;
    }

    inp = (*head).lh_first;
    while !inp.is_null() {
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        if (*inp).sctp_flags & 0x20000000u32 != 0 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        } else if (*inp).sctp_flags & 0x4u32 != 0
            && (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int == lport as libc::c_int
        {
            let mut current_block_20: u64;
            match (*nam).sa_family as libc::c_int {
                2 => {
                    if (*inp).sctp_flags & 0x4000000u32 != 0
                        && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
                    {
                        /* IPv4 on a IPv6 socket with ONLY IPv6 set */
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        current_block_20 = 8831408221741692167;
                    } else {
                        current_block_20 = 11932355480408055363;
                    }
                }
                10 => {
                    /* A V6 address and the endpoint is NOT bound V6 */
                    if (*inp).sctp_flags & 0x4000000u32 == 0u32 {
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        current_block_20 = 8831408221741692167;
                    } else {
                        current_block_20 = 11932355480408055363;
                    }
                }
                _ => {
                    current_block_20 = 11932355480408055363;
                }
            }
            match current_block_20 {
                8831408221741692167 => {}
                _ => {
                    /* does a VRF id match? */
                    fnd = 0i32;
                    if (*inp).def_vrf_id == vrf_id {
                        fnd = 1i32
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    if !(fnd == 0) {
                        return inp;
                    }
                }
            }
        } else {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        }
        inp = (*inp).sctp_hash.le_next
    }
    match (*nam).sa_family as libc::c_int {
        2 => {
            if (*sin).sin_addr.s_addr == 0u32 {
                /* Can't hunt for one that has no address specified */
                return 0 as *mut sctp_inpcb;
            }
        }
        10 => {
            if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[3usize] == 0u32) as libc::c_int
            }) != 0
            {
                /* Can't hunt for one that has no address specified */
                return 0 as *mut sctp_inpcb;
            }
        }
        123 => {
            if (*sconn).sconn_addr.is_null() {
                return 0 as *mut sctp_inpcb;
            }
        }
        _ => {}
    }
    /*
     * ok, not bound to all so see if we can find a EP bound to this
     * address.
     */
    inp = (*head).lh_first;
    while !inp.is_null() {
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        if (*inp).sctp_flags & 0x20000000u32 != 0 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        } else if (*inp).sctp_flags & 0x4u32 != 0 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        } else if (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int != lport as libc::c_int {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        } else {
            /*
             * Ok this could be a likely candidate, look at all of its
             * addresses
             */
            /* does a VRF id match? */
            fnd = 0i32;
            if (*inp).def_vrf_id == vrf_id {
                fnd = 1i32
            }
            if fnd == 0 {
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            } else {
                let mut laddr = 0 as *mut sctp_laddr;
                laddr = (*inp).sctp_addr_list.lh_first;
                while !laddr.is_null() {
                    if (*laddr).ifa.is_null() {
                        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                            if system_base_info.debug_printf.is_some() {
                                system_base_info
                                    .debug_printf
                                    .expect("non-null function pointer")(
                                    b"%s: NULL ifa\n\x00" as *const u8 as *const libc::c_char,
                                    (*::std::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                        b"sctp_endpoint_probe\x00",
                                    ))
                                    .as_ptr(),
                                );
                            }
                        }
                    } else {
                        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                            if system_base_info.debug_printf.is_some() {
                                system_base_info
                                    .debug_printf
                                    .expect("non-null function pointer")(
                                    b"Ok laddr->ifa:%p is possible, \x00" as *const u8
                                        as *const libc::c_char,
                                    (*laddr).ifa as *mut libc::c_void,
                                );
                            }
                        }
                        if (*(*laddr).ifa).localifa_flags & 0x2u32 != 0 {
                            if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                                if system_base_info.debug_printf.is_some() {
                                    system_base_info
                                        .debug_printf
                                        .expect("non-null function pointer")(
                                        b"Huh IFA being deleted\n\x00" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                            }
                        } else if (*(*laddr).ifa).address.sa.sa_family as libc::c_int
                            == (*nam).sa_family as libc::c_int
                        {
                            /* possible, see if it matches */
                            match (*nam).sa_family as libc::c_int {
                                2 => {
                                    if (*sin).sin_addr.s_addr
                                        == (*(*laddr).ifa).address.sin.sin_addr.s_addr
                                    {
                                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                        return inp;
                                    }
                                }
                                10 => {
                                    let mut intf_addr6 = 0 as *mut sockaddr_in6;
                                    intf_addr6 = &mut (*(*laddr).ifa).address.sin6;
                                    if SCTP6_ARE_ADDR_EQUAL(sin6, intf_addr6) != 0 {
                                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                        return inp;
                                    }
                                }
                                123 => {
                                    if (*sconn).sconn_addr
                                        == (*(*laddr).ifa).address.sconn.sconn_addr
                                    {
                                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                        return inp;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    laddr = (*laddr).sctp_nxt_addr.le_next
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        inp = (*inp).sctp_hash.le_next
    }
    return 0 as *mut sctp_inpcb;
}
unsafe extern "C" fn sctp_isport_inuse(
    mut inp: *mut sctp_inpcb,
    mut lport: uint16_t,
    mut vrf_id: uint32_t,
) -> *mut sctp_inpcb {
    let mut head = 0 as *mut sctppcbhead;
    let mut t_inp = 0 as *mut sctp_inpcb;
    head = &mut *system_base_info
        .sctppcbinfo
        .sctp_ephash
        .offset((lport as libc::c_ulong & system_base_info.sctppcbinfo.hashmark) as isize)
        as *mut sctppcbhead;
    t_inp = (*head).lh_first;
    while !t_inp.is_null() {
        if !((*t_inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int != lport as libc::c_int) {
            let mut fnd = 0;
            fnd = 0i32;
            if (*t_inp).def_vrf_id == vrf_id {
                fnd = 1i32
            }
            if !(fnd == 0) {
                /* This one is in use. */
                /* check the v6/v4 binding issue */
                if (*t_inp).sctp_flags & 0x4000000u32 != 0
                    && (*t_inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
                {
                    if (*inp).sctp_flags & 0x4000000u32 != 0 {
                        /* collision in V6 space */
                        return t_inp;
                    }
                } else if (*t_inp).sctp_flags & 0x4000000u32 != 0 {
                    /* t_inp is bound v4 and v6, conflict always */
                    return t_inp;
                } else if !((*inp).sctp_flags & 0x4000000u32 != 0
                    && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0)
                {
                    return t_inp;
                }
            }
        }
        /* t_inp is bound only V4 */
        /* else fall through to conflict */
        /* no conflict */
        t_inp = (*t_inp).sctp_hash.le_next
    }
    return 0 as *mut sctp_inpcb;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_swap_inpcb_for_listen(mut inp: *mut sctp_inpcb) -> libc::c_int {
    let mut head = 0 as *mut sctppcbhead;
    let mut tinp = 0 as *mut sctp_inpcb;
    let mut ninp = 0 as *mut sctp_inpcb;
    if (*inp).sctp_features & 0x2000000u64 == 0u64 {
        /* only works with port reuse on */
        return -(1i32);
    }
    if (*inp).sctp_flags & 0x400000u32 == 0u32 {
        return 0i32;
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    head = &mut *system_base_info.sctppcbinfo.sctp_ephash.offset(
        ((*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_ulong
            & system_base_info.sctppcbinfo.hashmark) as isize,
    ) as *mut sctppcbhead;
    /* Kick out all non-listeners to the TCP hash */
    tinp = (*head).lh_first;
    while !tinp.is_null() && {
        ninp = (*tinp).sctp_hash.le_next;
        (1i32) != 0
    } {
        if !((*tinp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int
            != (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int)
        {
            if !((*tinp).sctp_flags & 0x20000000u32 != 0) {
                if !((*tinp).sctp_flags & 0x10000000u32 != 0) {
                    if !((*tinp).sctp_flags & 0x8u32 != 0u32) {
                        pthread_mutex_lock(&mut (*tinp).inp_mtx);
                        if !(*tinp).sctp_hash.le_next.is_null() {
                            (*(*tinp).sctp_hash.le_next).sctp_hash.le_prev =
                                (*tinp).sctp_hash.le_prev
                        }
                        *(*tinp).sctp_hash.le_prev = (*tinp).sctp_hash.le_next;
                        head = &mut *system_base_info.sctppcbinfo.sctp_tcpephash.offset(
                            ((*tinp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_ulong
                                & system_base_info.sctppcbinfo.hashtcpmark)
                                as isize,
                        ) as *mut sctppcbhead;
                        (*tinp).sctp_flags |= 0x400000u32;
                        (*tinp).sctp_hash.le_next = (*head).lh_first;
                        if !(*tinp).sctp_hash.le_next.is_null() {
                            (*(*head).lh_first).sctp_hash.le_prev = &mut (*tinp).sctp_hash.le_next
                        }
                        (*head).lh_first = tinp;
                        (*tinp).sctp_hash.le_prev = &mut (*head).lh_first;
                        pthread_mutex_unlock(&mut (*tinp).inp_mtx);
                    }
                }
            }
        }
        tinp = ninp
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    /* Pull from where he was */
    if !(*inp).sctp_hash.le_next.is_null() {
        (*(*inp).sctp_hash.le_next).sctp_hash.le_prev = (*inp).sctp_hash.le_prev
    }
    *(*inp).sctp_hash.le_prev = (*inp).sctp_hash.le_next;
    (*inp).sctp_flags &= !(0x400000i32) as libc::c_uint;
    head = &mut *system_base_info.sctppcbinfo.sctp_ephash.offset(
        ((*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_ulong
            & system_base_info.sctppcbinfo.hashmark) as isize,
    ) as *mut sctppcbhead;
    (*inp).sctp_hash.le_next = (*head).lh_first;
    if !(*inp).sctp_hash.le_next.is_null() {
        (*(*head).lh_first).sctp_hash.le_prev = &mut (*inp).sctp_hash.le_next
    }
    (*head).lh_first = inp;
    (*inp).sctp_hash.le_prev = &mut (*head).lh_first;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_pcb_findep(
    mut nam: *mut sockaddr,
    mut find_tcp_pool: libc::c_int,
    mut have_lock: libc::c_int,
    mut vrf_id: uint32_t,
) -> *mut sctp_inpcb {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut head = 0 as *mut sctppcbhead;
    let mut lport = 0;
    match (*nam).sa_family as libc::c_int {
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            sin = nam as *mut sockaddr_in;
            lport = (*sin).sin_port as libc::c_int
        }
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 = nam as *mut sockaddr_in6;
            lport = (*sin6).sin6_port as libc::c_int
        }
        123 => {
            let mut sconn = 0 as *mut sockaddr_conn;
            sconn = nam as *mut sockaddr_conn;
            lport = (*sconn).sconn_port as libc::c_int
        }
        _ => return 0 as *mut sctp_inpcb,
    }
    /*
     * I could cheat here and just cast to one of the types but we will
     * do it right. It also provides the check against an Unsupported
     * type too.
     */
    /* Find the head of the ALLADDR chain */
    if have_lock == 0i32 {
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    }
    head = &mut *system_base_info
        .sctppcbinfo
        .sctp_ephash
        .offset((lport as libc::c_ulong & system_base_info.sctppcbinfo.hashmark) as isize)
        as *mut sctppcbhead;
    inp = sctp_endpoint_probe(nam, head, lport as uint16_t, vrf_id);
    /*
     * If the TCP model exists it could be that the main listening
     * endpoint is gone but there still exists a connected socket for this
     * guy. If so we can return the first one that we find. This may NOT
     * be the correct one so the caller should be wary on the returned INP.
     * Currently the only caller that sets find_tcp_pool is in bindx where
     * we are verifying that a user CAN bind the address. He either
     * has bound it already, or someone else has, or its open to bind,
     * so this is good enough.
     */
    if inp.is_null() && find_tcp_pool != 0 {
        let mut i = 0;
        i = 0u32;
        while (i as libc::c_ulong) < system_base_info.sctppcbinfo.hashtcpmark.wrapping_add(1u64) {
            head = &mut *system_base_info
                .sctppcbinfo
                .sctp_tcpephash
                .offset(i as isize) as *mut sctppcbhead;
            inp = sctp_endpoint_probe(nam, head, lport as uint16_t, vrf_id);
            if !inp.is_null() {
                break;
            }
            i = i.wrapping_add(1)
        }
    }
    if !inp.is_null() {
        ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
    }
    if have_lock == 0i32 {
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    }
    return inp;
}
/*
 * Find an association for an endpoint with the pointer to whom you want to
 * send to and the endpoint pointer. The address can be IPv4 or IPv6. We may
 * need to change the *to to some other struct like a mbuf...
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_findassociation_addr_sa(
    mut from: *mut sockaddr,
    mut to: *mut sockaddr,
    mut inp_p: *mut *mut sctp_inpcb,
    mut netp: *mut *mut sctp_nets,
    mut find_tcp_pool: libc::c_int,
    mut vrf_id: uint32_t,
) -> *mut sctp_tcb {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut stcb = 0 as *mut sctp_tcb;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    if find_tcp_pool != 0 {
        if !inp_p.is_null() {
            stcb = sctp_tcb_special_locate(inp_p, from, to, netp, vrf_id)
        } else {
            stcb = sctp_tcb_special_locate(&mut inp, from, to, netp, vrf_id)
        }
        if !stcb.is_null() {
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
            return stcb;
        }
    }
    inp = sctp_pcb_findep(to, 0i32, 1i32, vrf_id);
    if !inp_p.is_null() {
        *inp_p = inp
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    if inp.is_null() {
        return 0 as *mut sctp_tcb;
    }
    /*
     * ok, we have an endpoint, now lets find the assoc for it (if any)
     * we now place the source address or from in the to of the find
     * endpoint call. Since in reality this chain is used from the
     * inbound packet side.
     */
    if !inp_p.is_null() {
        stcb = sctp_findassociation_ep_addr(inp_p, from, netp, to, 0 as *mut sctp_tcb)
    } else {
        stcb = sctp_findassociation_ep_addr(&mut inp, from, netp, to, 0 as *mut sctp_tcb)
    }
    return stcb;
}
/*
 * This routine will grub through the mbuf that is a INIT or INIT-ACK and
 * find all addresses that the sender has specified in any address list. Each
 * address will be used to lookup the TCB and see if one exits.
 */
unsafe extern "C" fn sctp_findassociation_special_addr(
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut sh: *mut sctphdr,
    mut inp_p: *mut *mut sctp_inpcb,
    mut netp: *mut *mut sctp_nets,
    mut dst: *mut sockaddr,
) -> *mut sctp_tcb {
    let mut phdr = 0 as *mut sctp_paramhdr;
    let mut param_buf = sctp_paramhdr {
        param_type: 0,
        param_length: 0,
    };
    let mut sin4 = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut sin6 = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            __in6_u: C2RustUnnamed_446 {
                __u6_addr8: [0; 16],
            },
        },
        sin6_scope_id: 0,
    };
    memset(
        &mut sin4 as *mut sockaddr_in as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
    );
    sin4.sin_family = 2u16;
    sin4.sin_port = (*sh).src_port;
    memset(
        &mut sin6 as *mut sockaddr_in6 as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
    );
    sin6.sin6_family = 10u16;
    sin6.sin6_port = (*sh).src_port;
    offset = (offset as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_init_chunk>() as libc::c_ulong)
        as libc::c_int;
    phdr = sctp_get_next_param(
        m,
        offset,
        &mut param_buf,
        ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
    );
    while !phdr.is_null() {
        let mut stcb = 0 as *mut sctp_tcb;
        let mut ptype = 0;
        let mut plen = 0;
        ptype = ntohs((*phdr).param_type);
        plen = ntohs((*phdr).param_length);
        if plen as libc::c_int == 0i32 {
            break;
        }
        if ptype as libc::c_int == 0x5i32
            && plen as libc::c_ulong
                == ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
        {
            let mut ip4_param = sctp_ipv4addr_param {
                ph: sctp_paramhdr {
                    param_type: 0,
                    param_length: 0,
                },
                addr: 0,
            };
            let mut p4 = 0 as *mut sctp_ipv4addr_param;
            phdr = sctp_get_next_param(
                m,
                offset,
                &mut ip4_param as *mut sctp_ipv4addr_param as *mut sctp_paramhdr,
                ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_int,
            );
            if phdr.is_null() {
                return 0 as *mut sctp_tcb;
            }
            p4 = phdr as *mut sctp_ipv4addr_param;
            memcpy(
                &mut sin4.sin_addr as *mut in_addr as *mut libc::c_void,
                &mut (*p4).addr as *mut uint32_t as *const libc::c_void,
                ::std::mem::size_of::<uint32_t>() as libc::c_ulong,
            );
            /* look it up */
            stcb = sctp_findassociation_ep_addr(
                inp_p,
                &mut sin4 as *mut sockaddr_in as *mut sockaddr,
                netp,
                dst,
                0 as *mut sctp_tcb,
            );
            if !stcb.is_null() {
                return stcb;
            }
        }
        if ptype as libc::c_int == 0x6i32
            && plen as libc::c_ulong
                == ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
        {
            let mut ip6_param = sctp_ipv6addr_param {
                ph: sctp_paramhdr {
                    param_type: 0,
                    param_length: 0,
                },
                addr: [0; 16],
            };
            let mut p6 = 0 as *mut sctp_ipv6addr_param;
            phdr = sctp_get_next_param(
                m,
                offset,
                &mut ip6_param as *mut sctp_ipv6addr_param as *mut sctp_paramhdr,
                ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_int,
            );
            if phdr.is_null() {
                return 0 as *mut sctp_tcb;
            }
            p6 = phdr as *mut sctp_ipv6addr_param;
            memcpy(
                &mut sin6.sin6_addr as *mut in6_addr as *mut libc::c_void,
                &mut (*p6).addr as *mut [uint8_t; 16] as *const libc::c_void,
                ::std::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
            );
            /* look it up */
            stcb = sctp_findassociation_ep_addr(
                inp_p,
                &mut sin6 as *mut sockaddr_in6 as *mut sockaddr,
                netp,
                dst,
                0 as *mut sctp_tcb,
            );
            if !stcb.is_null() {
                return stcb;
            }
        }
        offset += (plen as libc::c_int + 3i32 >> 2i32) << 2i32;
        phdr = sctp_get_next_param(
            m,
            offset,
            &mut param_buf,
            ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
        )
    }
    return 0 as *mut sctp_tcb;
}
unsafe extern "C" fn sctp_findassoc_by_vtag(
    mut from: *mut sockaddr,
    mut to: *mut sockaddr,
    mut vtag: uint32_t,
    mut inp_p: *mut *mut sctp_inpcb,
    mut netp: *mut *mut sctp_nets,
    mut rport: uint16_t,
    mut lport: uint16_t,
    mut skip_src_check: libc::c_int,
    mut vrf_id: uint32_t,
    mut remote_tag: uint32_t,
) -> *mut sctp_tcb {
    let mut head = 0 as *mut sctpasochead;
    let mut stcb = 0 as *mut sctp_tcb;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    head = &mut *system_base_info
        .sctppcbinfo
        .sctp_asochash
        .offset((vtag as libc::c_ulong & system_base_info.sctppcbinfo.hashasocmark) as isize)
        as *mut sctpasochead;

    stcb = (*head).lh_first;
    while !stcb.is_null() {
        pthread_mutex_lock(&mut (*(*stcb).sctp_ep).inp_mtx);
        if (*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0 {
            pthread_mutex_unlock(&mut (*(*stcb).sctp_ep).inp_mtx);
        } else if (*(*stcb).sctp_ep).def_vrf_id != vrf_id {
            pthread_mutex_unlock(&mut (*(*stcb).sctp_ep).inp_mtx);
        } else {
            let mut current_block_31: u64;
            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
            pthread_mutex_unlock(&mut (*(*stcb).sctp_ep).inp_mtx);
            if (*stcb).asoc.my_vtag == vtag {
                /* candidate */
                if (*stcb).rport as libc::c_int != rport as libc::c_int {
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    current_block_31 = 17179679302217393232;
                } else if (*(*stcb).sctp_ep).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int
                    != lport as libc::c_int
                {
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    current_block_31 = 17179679302217393232;
                } else if (*stcb).asoc.state & 0x200i32 != 0 {
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    current_block_31 = 17179679302217393232;
                } else if sctp_does_stcb_own_this_addr(stcb, to) == 0i32 {
                    /* RRS:Need toaddr check here */
                    /* Endpoint does not own this address */
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    current_block_31 = 17179679302217393232;
                } else {
                    if remote_tag != 0 {
                        /* If we have both vtags that's all we match on */
                        if (*stcb).asoc.peer_vtag == remote_tag {
                            current_block_31 = 13700178175854514454;
                        } else {
                            current_block_31 = 14763689060501151050;
                        }
                    } else {
                        current_block_31 = 14763689060501151050;
                    }
                    match current_block_31 {
                        14763689060501151050 => {
                            if skip_src_check != 0 {
                                current_block_31 = 13700178175854514454;
                            } else {
                                let mut net = 0 as *mut sctp_nets;
                                net = sctp_findnet(stcb, from);
                                if !net.is_null() {
                                    /* yep its him. */
                                    *netp = net;
                                    ::std::intrinsics::atomic_xadd(
                                        &mut system_base_info.sctpstat.sctps_vtagexpress,
                                        1u32,
                                    );
                                    *inp_p = (*stcb).sctp_ep;
                                    pthread_mutex_unlock(
                                        &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
                                    );
                                    return stcb;
                                } else {
                                    /*
                                     * not him, this should only happen in rare
                                     * cases so I peg it.
                                     */
                                    ::std::intrinsics::atomic_xadd(
                                        &mut system_base_info.sctpstat.sctps_vtagbogus,
                                        1u32,
                                    );
                                }
                                current_block_31 = 12381812505308290051;
                            }
                        }
                        _ => {}
                    }
                    match current_block_31 {
                        12381812505308290051 => {}
                        _ =>
                        /* If both tags match we consider it conclusive
                         * and check NO source/destination addresses
                         */
                        {
                            if !from.is_null() {
                                *netp = sctp_findnet(stcb, from)
                            } else {
                                *netp = 0 as *mut sctp_nets
                                /* unknown */
                            }
                            if !inp_p.is_null() {
                                *inp_p = (*stcb).sctp_ep
                            }
                            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                            return stcb;
                        }
                    }
                }
            } else {
                current_block_31 = 12381812505308290051;
            }
            match current_block_31 {
                17179679302217393232 => {}
                _ => {
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                }
            }
        }
        stcb = (*stcb).sctp_asocs.le_next
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    return 0 as *mut sctp_tcb;
}
/*
 * Find an association with the pointer to the inbound IP packet. This can be
 * a IPv4 or IPv6 packet.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_findassociation_addr(
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut src: *mut sockaddr,
    mut dst: *mut sockaddr,
    mut sh: *mut sctphdr,
    mut ch: *mut sctp_chunkhdr,
    mut inp_p: *mut *mut sctp_inpcb,
    mut netp: *mut *mut sctp_nets,
    mut vrf_id: uint32_t,
) -> *mut sctp_tcb {
    let mut stcb = 0 as *mut sctp_tcb;
    let mut inp = 0 as *mut sctp_inpcb;
    if (*sh).v_tag != 0 {
        /* we only go down this path if vtag is non-zero */
        stcb = sctp_findassoc_by_vtag(
            src,
            dst,
            ntohl((*sh).v_tag),
            inp_p,
            netp,
            (*sh).src_port,
            (*sh).dest_port,
            0i32,
            vrf_id,
            0u32,
        );
        if !stcb.is_null() {
            return stcb;
        }
    }
    if !inp_p.is_null() {
        stcb = sctp_findassociation_addr_sa(src, dst, inp_p, netp, 1i32, vrf_id);
        inp = *inp_p
    } else {
        stcb = sctp_findassociation_addr_sa(src, dst, &mut inp, netp, 1i32, vrf_id)
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"stcb:%p inp:%p\n\x00" as *const u8 as *const libc::c_char,
                stcb as *mut libc::c_void,
                inp as *mut libc::c_void,
            );
        }
    }
    if stcb.is_null() && !inp.is_null() {
        /* Found a EP but not this address */
        if (*ch).chunk_type as libc::c_int == 0x1i32 || (*ch).chunk_type as libc::c_int == 0x2i32 {
            /*-
             * special hook, we do NOT return linp or an
             * association that is linked to an existing
             * association that is under the TCP pool (i.e. no
             * listener exists). The endpoint finding routine
             * will always find a listener before examining the
             * TCP pool.
             */
            if (*inp).sctp_flags & 0x400000u32 != 0 {
                if !inp_p.is_null() {
                    *inp_p = 0 as *mut sctp_inpcb
                }
                return 0 as *mut sctp_tcb;
            }
            stcb = sctp_findassociation_special_addr(m, offset, sh, &mut inp, netp, dst);
            if !inp_p.is_null() {
                *inp_p = inp
            }
        }
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"stcb is %p\n\x00" as *const u8 as *const libc::c_char,
                stcb as *mut libc::c_void,
            );
        }
    }
    return stcb;
}
/*
 * lookup an association by an ASCONF lookup address.
 * if the lookup address is 0.0.0.0 or ::0, use the vtag to do the lookup
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_findassociation_ep_asconf(
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut dst: *mut sockaddr,
    mut sh: *mut sctphdr,
    mut inp_p: *mut *mut sctp_inpcb,
    mut netp: *mut *mut sctp_nets,
    mut vrf_id: uint32_t,
) -> *mut sctp_tcb {
    let mut stcb = 0 as *mut sctp_tcb;
    let mut remote_store = sctp_sockstore {
        sin: sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        },
    };
    let mut param_buf = sctp_paramhdr {
        param_type: 0,
        param_length: 0,
    };
    let mut phdr = 0 as *mut sctp_paramhdr;
    let mut ptype = 0;
    let mut zero_address = 0i32;
    memset(
        &mut remote_store as *mut sctp_sockstore as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
    );
    phdr = sctp_get_next_param(
        m,
        (offset as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_ulong)
            as libc::c_int,
        &mut param_buf,
        ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
    );
    if phdr.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x4000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%s: failed to get asconf lookup addr\n\x00" as *const u8
                        as *const libc::c_char,
                    (*::std::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"sctp_findassociation_ep_asconf\x00",
                    ))
                    .as_ptr(),
                );
            }
        }
        return 0 as *mut sctp_tcb;
    }
    ptype = ntohs((*phdr).param_type) as libc::c_int;
    /* get the correlation address */
    match ptype {
        6 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            let mut p6 = 0 as *mut sctp_ipv6addr_param;
            let mut p6_buf = sctp_ipv6addr_param {
                ph: sctp_paramhdr {
                    param_type: 0,
                    param_length: 0,
                },
                addr: [0; 16],
            };
            if ntohs((*phdr).param_length) as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
            {
                return 0 as *mut sctp_tcb;
            }
            p6 = sctp_get_next_param(
                m,
                (offset as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_ulong)
                    as libc::c_int,
                &mut p6_buf.ph,
                ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_int,
            ) as *mut sctp_ipv6addr_param;
            if p6.is_null() {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x4000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"%s: failed to get asconf v6 lookup addr\n\x00" as *const u8
                                as *const libc::c_char,
                            (*::std::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                                b"sctp_findassociation_ep_asconf\x00",
                            ))
                            .as_ptr(),
                        );
                    }
                }
                return 0 as *mut sctp_tcb;
            }
            sin6 = &mut remote_store.sin6;
            (*sin6).sin6_family = 10u16;
            (*sin6).sin6_port = (*sh).src_port;
            memcpy(
                &mut (*sin6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                &mut (*p6).addr as *mut [uint8_t; 16] as *const libc::c_void,
                ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
            );
            if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[3usize] == 0u32) as libc::c_int
            }) != 0
            {
                zero_address = 1i32
            }
        }
        5 => {
            let mut sin = 0 as *mut sockaddr_in;
            let mut p4 = 0 as *mut sctp_ipv4addr_param;
            let mut p4_buf = sctp_ipv4addr_param {
                ph: sctp_paramhdr {
                    param_type: 0,
                    param_length: 0,
                },
                addr: 0,
            };
            if ntohs((*phdr).param_length) as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
            {
                return 0 as *mut sctp_tcb;
            }
            p4 = sctp_get_next_param(
                m,
                (offset as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_ulong)
                    as libc::c_int,
                &mut p4_buf.ph,
                ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_int,
            ) as *mut sctp_ipv4addr_param;
            if p4.is_null() {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x4000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"%s: failed to get asconf v4 lookup addr\n\x00" as *const u8
                                as *const libc::c_char,
                            (*::std::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                                b"sctp_findassociation_ep_asconf\x00",
                            ))
                            .as_ptr(),
                        );
                    }
                }
                return 0 as *mut sctp_tcb;
            }
            sin = &mut remote_store.sin;
            (*sin).sin_family = 2u16;
            (*sin).sin_port = (*sh).src_port;
            memcpy(
                &mut (*sin).sin_addr as *mut in_addr as *mut libc::c_void,
                &mut (*p4).addr as *mut uint32_t as *const libc::c_void,
                ::std::mem::size_of::<in_addr>() as libc::c_ulong,
            );
            if (*sin).sin_addr.s_addr == 0u32 {
                zero_address = 1i32
            }
        }
        _ => {
            /* invalid address param type */
            return 0 as *mut sctp_tcb;
        }
    }
    if zero_address != 0 {
        stcb = sctp_findassoc_by_vtag(
            0 as *mut sockaddr,
            dst,
            ntohl((*sh).v_tag),
            inp_p,
            netp,
            (*sh).src_port,
            (*sh).dest_port,
            1i32,
            vrf_id,
            0u32,
        );
        if !stcb.is_null() {
            ::std::intrinsics::atomic_xadd(&mut (**inp_p).refcount, -(1i32));
        }
    } else {
        stcb =
            sctp_findassociation_ep_addr(inp_p, &mut remote_store.sa, netp, dst, 0 as *mut sctp_tcb)
    }
    return stcb;
}
/*
 * allocate a sctp_inpcb and setup a temporary binding to a port/all
 * addresses. This way if we don't get a bind we by default pick a ephemeral
 * port with all addresses bound.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_inpcb_alloc(
    mut so: *mut socket,
    mut vrf_id: uint32_t,
) -> libc::c_int {
    let mut error = 0;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut m = 0 as *mut sctp_pcb;
    let mut time = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut null_key = 0 as *mut sctp_sharedkey_t;
    error = 0i32;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    inp = malloc(system_base_info.sctppcbinfo.ipi_zone_ep) as *mut sctp_inpcb;
    if inp.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Out of SCTP-INPCB structures - no resources\n\x00" as *const u8
                    as *const libc::c_char,
            );
        }
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        return 105i32;
    }
    /* zap it */
    memset(
        inp as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_inpcb>() as libc::c_ulong,
    );
    /* bump generations */
    /* setup socket pointers */
    (*inp).sctp_socket = so;
    (*inp).ip_inp.inp.inp_socket = so;
    (*inp).sctp_associd_counter = 1u32;
    (*inp).partial_delivery_point = (*so).so_rcv.sb_hiwat >> 1i32;
    (*inp).sctp_frag_point = 65535u32;
    (*inp).max_cwnd = 0u32;
    (*inp).sctp_cmt_on_off = system_base_info.sctpsysctl.sctp_cmt_on_off;
    (*inp).ecn_supported = system_base_info.sctpsysctl.sctp_ecn_enable as uint8_t;
    (*inp).prsctp_supported = system_base_info.sctpsysctl.sctp_pr_enable as uint8_t;
    (*inp).auth_supported = system_base_info.sctpsysctl.sctp_auth_enable as uint8_t;
    (*inp).asconf_supported = system_base_info.sctpsysctl.sctp_asconf_enable as uint8_t;
    (*inp).reconfig_supported = system_base_info.sctpsysctl.sctp_reconfig_enable as uint8_t;
    (*inp).nrsack_supported = system_base_info.sctpsysctl.sctp_nrsack_enable as uint8_t;
    (*inp).pktdrop_supported = system_base_info.sctpsysctl.sctp_pktdrop_enable as uint8_t;
    (*inp).idata_supported = 0u8;
    (*inp).fibnum = 0u16;
    (*inp).ulp_info = 0 as *mut libc::c_void;
    (*inp).recv_callback = None;
    (*inp).send_callback = None;
    (*inp).send_sb_threshold = 0u32;
    /* init the small hash table we use to track asocid <-> tcb */
    (*inp).sctp_asocidhash = sctp_hashinit_flags(
        32i32,
        M_PCB.as_mut_ptr(),
        &mut (*inp).hashasocidmark,
        0x1i32,
    ) as *mut sctpasochead;
    if (*inp).sctp_asocidhash.is_null() {
        free(inp as *mut libc::c_void);
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        return 105i32;
    }
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_ep, 1u32);
    (*inp).ip_inp.inp.inp_ip_ttl = ip_defttl as u_char;
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    (*so).so_pcb = inp as *mut libc::c_void;
    if (*so).so_type as libc::c_int == SOCK_SEQPACKET as libc::c_int {
        /* UDP style socket */
        (*inp).sctp_flags = (0x1i32 | 0x10i32) as uint32_t
    /* Be sure it is NON-BLOCKING IO for UDP */
    /* SCTP_SET_SO_NBIO(so); */
    } else if (*so).so_type as libc::c_int == SOCK_STREAM as libc::c_int {
        /* TCP style socket */
        (*inp).sctp_flags = (0x2i32 | 0x10i32) as uint32_t;
        /* Be sure we have blocking IO by default */
        pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
        (*so).so_state = ((*so).so_state as libc::c_int & !(0x100i32)) as libc::c_short;
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    } else {
        /*
         * unsupported socket type (RAW, etc)- in case we missed it
         * in protosw
         */
        (*so).so_pcb = 0 as *mut libc::c_void;
        free(inp as *mut libc::c_void);
        return 95i32;
    }
    if system_base_info.sctpsysctl.sctp_default_frag_interleave == 0x1u32 {
        (*inp).sctp_features |= 0x8u64;
        (*inp).sctp_features &= !(0x10i32) as libc::c_ulong
    } else if system_base_info.sctpsysctl.sctp_default_frag_interleave == 0x2u32 {
        (*inp).sctp_features |= 0x8u64;
        (*inp).sctp_features |= 0x10u64
    } else if system_base_info.sctpsysctl.sctp_default_frag_interleave == 0u32 {
        (*inp).sctp_features &= !(0x8i32) as libc::c_ulong;
        (*inp).sctp_features &= !(0x10i32) as libc::c_ulong
    }
    (*inp).sctp_tcbhash = sctp_hashinit_flags(
        system_base_info.sctpsysctl.sctp_pcbtblsize as libc::c_int,
        M_PCB.as_mut_ptr(),
        &mut (*inp).sctp_hashmark,
        0x1i32,
    ) as *mut sctpasochead;
    if (*inp).sctp_tcbhash.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Out of SCTP-INPCB->hashinit - no resources\n\x00" as *const u8
                    as *const libc::c_char,
            );
        }
        (*so).so_pcb = 0 as *mut libc::c_void;
        free(inp as *mut libc::c_void);
        return 105i32;
    }
    (*inp).def_vrf_id = vrf_id;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    pthread_mutex_init(&mut (*inp).inp_mtx, &mut system_base_info.mtx_attr);
    pthread_mutex_init(&mut (*inp).inp_rdata_mtx, &mut system_base_info.mtx_attr);
    pthread_mutex_init(&mut (*inp).inp_create_mtx, &mut system_base_info.mtx_attr);
    /* lock the new ep */
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    /* add it to the info area */
    (*inp).sctp_list.le_next = system_base_info.sctppcbinfo.listhead.lh_first;
    if !(*inp).sctp_list.le_next.is_null() {
        (*system_base_info.sctppcbinfo.listhead.lh_first)
            .sctp_list
            .le_prev = &mut (*inp).sctp_list.le_next
    }
    system_base_info.sctppcbinfo.listhead.lh_first = inp;
    (*inp).sctp_list.le_prev = &mut system_base_info.sctppcbinfo.listhead.lh_first;
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    (*inp).read_queue.tqh_first = 0 as *mut sctp_queued_to_read;
    (*inp).read_queue.tqh_last = &mut (*inp).read_queue.tqh_first;
    (*inp).sctp_addr_list.lh_first = 0 as *mut sctp_laddr;
    (*inp).sctp_asoc_list.lh_first = 0 as *mut sctp_tcb;
    /* Init the timer structure for signature change */
    sctp_os_timer_init(&mut (*inp).sctp_ep.signature_change.timer);
    (*inp).sctp_ep.signature_change.type_0 = 7i32;
    /* now init the actual endpoint default data */
    m = &mut (*inp).sctp_ep;
    /* setup the base timeout information */
    (*m).sctp_timeoutticks[2usize] = (1i32 * hz) as libc::c_uint; /* needed ? */
    (*m).sctp_timeoutticks[0usize] = (1i32 * hz) as libc::c_uint; /* needed ? */
    (*m).sctp_timeoutticks[1usize] = if hz == 1000i32 {
        system_base_info.sctpsysctl.sctp_delayed_sack_time_default
    } else {
        system_base_info
            .sctpsysctl
            .sctp_delayed_sack_time_default
            .wrapping_mul(hz as libc::c_uint)
            .wrapping_add(999u32)
            .wrapping_div(1000u32)
    };
    (*m).sctp_timeoutticks[3usize] = if hz == 1000i32 {
        system_base_info.sctpsysctl.sctp_heartbeat_interval_default
    } else {
        system_base_info
            .sctpsysctl
            .sctp_heartbeat_interval_default
            .wrapping_mul(hz as libc::c_uint)
            .wrapping_add(999u32)
            .wrapping_div(1000u32)
    };
    (*m).sctp_timeoutticks[4usize] = system_base_info
        .sctpsysctl
        .sctp_pmtu_raise_time_default
        .wrapping_mul(hz as libc::c_uint);
    (*m).sctp_timeoutticks[5usize] = system_base_info
        .sctpsysctl
        .sctp_shutdown_guard_time_default
        .wrapping_mul(hz as libc::c_uint);
    (*m).sctp_timeoutticks[6usize] = system_base_info
        .sctpsysctl
        .sctp_secret_lifetime_default
        .wrapping_mul(hz as libc::c_uint);
    /* all max/min max are in ms */
    (*m).sctp_maxrto = system_base_info.sctpsysctl.sctp_rto_max_default;
    (*m).sctp_minrto = system_base_info.sctpsysctl.sctp_rto_min_default;
    (*m).initial_rto = system_base_info.sctpsysctl.sctp_rto_initial_default;
    (*m).initial_init_rto_max =
        system_base_info.sctpsysctl.sctp_init_rto_max_default as libc::c_int;
    (*m).sctp_sack_freq = system_base_info.sctpsysctl.sctp_sack_freq_default;
    (*m).max_init_times = system_base_info.sctpsysctl.sctp_init_rtx_max_default as uint16_t;
    (*m).max_send_times = system_base_info.sctpsysctl.sctp_assoc_rtx_max_default as uint16_t;
    (*m).def_net_failure = system_base_info.sctpsysctl.sctp_path_rtx_max_default as uint16_t;
    (*m).def_net_pf_threshold = system_base_info.sctpsysctl.sctp_path_pf_threshold as uint16_t;
    (*m).sctp_sws_sender = 1420u32;
    (*m).sctp_sws_receiver = 3000u32;
    (*m).max_burst = system_base_info.sctpsysctl.sctp_max_burst_default;
    (*m).fr_max_burst = system_base_info.sctpsysctl.sctp_fr_max_burst_default;
    (*m).sctp_default_cc_module = system_base_info.sctpsysctl.sctp_default_cc_module;
    (*m).sctp_default_ss_module = system_base_info.sctpsysctl.sctp_default_ss_module;
    (*m).max_open_streams_intome =
        system_base_info.sctpsysctl.sctp_nr_incoming_streams_default as uint16_t;
    /* number of streams to pre-open on a association */
    (*m).pre_open_stream_count =
        system_base_info.sctpsysctl.sctp_nr_outgoing_streams_default as uint16_t;
    (*m).default_mtu = 0u32;
    /* Add adaptation cookie */
    (*m).adaptation_layer_indicator = 0u32;
    (*m).adaptation_layer_indicator_provided = 0u8;
    /* seed random number generator */
    (*m).random_counter = 1u32;
    (*m).store_at = 20u32;
    read_random(
        (*m).random_numbers.as_mut_ptr() as *mut libc::c_void,
        ::std::mem::size_of::<[uint8_t; 20]>() as libc::c_int,
    );
    sctp_fill_random_store(m);
    /* Minimum cookie size */
    (*m).size_of_a_cookie = (::std::mem::size_of::<sctp_init_msg>() as libc::c_ulong)
        .wrapping_mul(2u64)
        .wrapping_add(::std::mem::size_of::<sctp_state_cookie>() as libc::c_ulong)
        as libc::c_uint;
    (*m).size_of_a_cookie = (*m).size_of_a_cookie.wrapping_add(20u32);
    /* Setup the initial secret */
    gettimeofday(&mut time, 0 as *mut timezone);
    (*m).time_of_secret_change = time.tv_sec as libc::c_uint;

    for i in 0i32..8i32 {
        (*m).secret_key[0usize][i as usize] = sctp_select_initial_TSN(m);
    }
    sctp_timer_start(7i32, inp, 0 as *mut sctp_tcb, 0 as *mut sctp_nets);
    /* How long is a cookie good for ? */
    (*m).def_cookie_life = if hz == 1000i32 {
        system_base_info.sctpsysctl.sctp_valid_cookie_life_default
    } else {
        system_base_info
            .sctpsysctl
            .sctp_valid_cookie_life_default
            .wrapping_mul(hz as libc::c_uint)
            .wrapping_add(999u32)
            .wrapping_div(1000u32)
    };
    /*
     * Initialize authentication parameters
     */
    (*m).local_hmacs = sctp_default_supported_hmaclist(); /* encapsulation disabled by default */
    (*m).local_auth_chunks = sctp_alloc_chunklist();
    if (*inp).asconf_supported != 0 {
        sctp_auth_add_chunk(0xc1u8, (*m).local_auth_chunks);
        sctp_auth_add_chunk(0x80u8, (*m).local_auth_chunks);
    }
    (*m).default_dscp = 0u8;
    (*m).default_flowlabel = 0u32;
    (*m).port = 0u16;
    (*m).shared_keys.lh_first = 0 as *mut sctp_shared_key;
    /* add default NULL key as key id 0 */
    null_key = sctp_alloc_sharedkey();
    sctp_insert_sharedkey(&mut (*m).shared_keys, null_key);
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return error;
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
/* number of seconds from
 * timeval.tv_sec */
/* authentication related fields */
/* various thresholds */
/* Max times I will init at a guy */
/* Max times I will send before we consider someone dead */
/* number of streams to pre-open on a association */
/* random number generator */
/*
 * This timer is kept running per endpoint.  When it fires it will
 * change the secret key.  The default is once a hour
 */
/* defaults to 0 */
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
/*-
 * Change address state, can be used if
 * O/S supports telling transports about
 * changes to IFA/IFN's (link layer triggers).
 * If a ifn goes down, we will do src-addr-selection
 * and NOT use that, as a source address. This does
 * not stop the routing system from routing out
 * that interface, but we won't put it as a source.
 */
/* struct proc is a dummy for __Userspace__ */
#[no_mangle]
pub unsafe extern "C" fn sctp_move_pcb_and_assoc(
    mut old_inp: *mut sctp_inpcb,
    mut new_inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
) {
    let mut net = 0 as *mut sctp_nets;
    let mut lport = 0;
    let mut rport = 0;
    let mut head = 0 as *mut sctppcbhead;
    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    pthread_mutex_lock(&mut (*old_inp).inp_mtx);
    pthread_mutex_lock(&mut (*new_inp).inp_mtx);
    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
    ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.refcnt, 1u32);
    (*new_inp).sctp_ep.time_of_secret_change = (*old_inp).sctp_ep.time_of_secret_change;
    memcpy(
        (*new_inp).sctp_ep.secret_key.as_mut_ptr() as *mut libc::c_void,
        (*old_inp).sctp_ep.secret_key.as_mut_ptr() as *const libc::c_void,
        ::std::mem::size_of::<[[uint32_t; 8]; 2]>() as libc::c_ulong,
    );
    (*new_inp).sctp_ep.current_secret_number = (*old_inp).sctp_ep.current_secret_number;
    (*new_inp).sctp_ep.last_secret_number = (*old_inp).sctp_ep.last_secret_number;
    (*new_inp).sctp_ep.size_of_a_cookie = (*old_inp).sctp_ep.size_of_a_cookie;
    /* make it so new data pours into the new socket */
    (*stcb).sctp_socket = (*new_inp).sctp_socket;
    (*stcb).sctp_ep = new_inp;
    /* Copy the port across */
    (*new_inp).ip_inp.inp.inp_inc.inc_ie.ie_lport = (*old_inp).ip_inp.inp.inp_inc.inc_ie.ie_lport;
    lport = (*new_inp).ip_inp.inp.inp_inc.inc_ie.ie_lport;
    rport = (*stcb).rport;
    /* Pull the tcb from the old association */
    if !(*stcb).sctp_tcbhash.le_next.is_null() {
        (*(*stcb).sctp_tcbhash.le_next).sctp_tcbhash.le_prev = (*stcb).sctp_tcbhash.le_prev
    }
    *(*stcb).sctp_tcbhash.le_prev = (*stcb).sctp_tcbhash.le_next;
    if !(*stcb).sctp_tcblist.le_next.is_null() {
        (*(*stcb).sctp_tcblist.le_next).sctp_tcblist.le_prev = (*stcb).sctp_tcblist.le_prev
    }
    *(*stcb).sctp_tcblist.le_prev = (*stcb).sctp_tcblist.le_next;
    if (*stcb).asoc.in_asocid_hash != 0 {
        if !(*stcb).sctp_tcbasocidhash.le_next.is_null() {
            (*(*stcb).sctp_tcbasocidhash.le_next)
                .sctp_tcbasocidhash
                .le_prev = (*stcb).sctp_tcbasocidhash.le_prev
        }
        *(*stcb).sctp_tcbasocidhash.le_prev = (*stcb).sctp_tcbasocidhash.le_next
    }
    /* Now insert the new_inp into the TCP connected hash */
    head = &mut *system_base_info.sctppcbinfo.sctp_tcpephash.offset(
        ((lport as libc::c_int | rport as libc::c_int) as libc::c_ulong
            & system_base_info.sctppcbinfo.hashtcpmark) as isize,
    ) as *mut sctppcbhead;
    (*new_inp).sctp_hash.le_next = (*head).lh_first;
    if !(*new_inp).sctp_hash.le_next.is_null() {
        (*(*head).lh_first).sctp_hash.le_prev = &mut (*new_inp).sctp_hash.le_next
    }
    (*head).lh_first = new_inp;
    (*new_inp).sctp_hash.le_prev = &mut (*head).lh_first;
    /* Its safe to access */
    (*new_inp).sctp_flags &= !(0x10i32) as libc::c_uint;
    /* Now move the tcb into the endpoint list */
    (*stcb).sctp_tcblist.le_next = (*new_inp).sctp_asoc_list.lh_first;
    if !(*stcb).sctp_tcblist.le_next.is_null() {
        (*(*new_inp).sctp_asoc_list.lh_first).sctp_tcblist.le_prev =
            &mut (*stcb).sctp_tcblist.le_next
    }
    (*new_inp).sctp_asoc_list.lh_first = stcb;
    (*stcb).sctp_tcblist.le_prev = &mut (*new_inp).sctp_asoc_list.lh_first;
    /*
     * Question, do we even need to worry about the ep-hash since we
     * only have one connection? Probably not :> so lets get rid of it
     * and not suck up any kernel memory in that.
     */
    if (*stcb).asoc.in_asocid_hash != 0 {
        let mut lhd = 0 as *mut sctpasochead;
        lhd = &mut *(*new_inp)
            .sctp_asocidhash
            .offset(((*stcb).asoc.assoc_id as libc::c_ulong & (*new_inp).hashasocidmark) as isize)
            as *mut sctpasochead;
        (*stcb).sctp_tcbasocidhash.le_next = (*lhd).lh_first;
        if !(*stcb).sctp_tcbasocidhash.le_next.is_null() {
            (*(*lhd).lh_first).sctp_tcbasocidhash.le_prev = &mut (*stcb).sctp_tcbasocidhash.le_next
        }
        (*lhd).lh_first = stcb;
        (*stcb).sctp_tcbasocidhash.le_prev = &mut (*lhd).lh_first
    }
    /* Ok. Let's restart timer. */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        sctp_timer_start(8i32, new_inp, stcb, net);
        net = (*net).sctp_next.tqe_next
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    if !(*new_inp).sctp_tcbhash.is_null() {
        sctp_hashdestroy(
            (*new_inp).sctp_tcbhash as *mut libc::c_void,
            M_PCB.as_mut_ptr(),
            (*new_inp).sctp_hashmark,
        );
        (*new_inp).sctp_tcbhash = 0 as *mut sctpasochead
    }
    if (*new_inp).sctp_flags & 0x4u32 == 0u32 {
        let mut oladdr = 0 as *mut sctp_laddr;
        oladdr = (*old_inp).sctp_addr_list.lh_first;
        while !oladdr.is_null() {
            let mut laddr = 0 as *mut sctp_laddr;
            laddr = malloc(system_base_info.sctppcbinfo.ipi_zone_laddr) as *mut sctp_laddr;
            if laddr.is_null() {
                /*
                 * Gak, what can we do? This assoc is really
                 * HOSED. We probably should send an abort
                 * here.
                 */
                if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Association hosed in TCP model, out of laddr memory\n\x00"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                }
            } else {
                ::std::intrinsics::atomic_xadd(
                    &mut system_base_info.sctppcbinfo.ipi_count_laddr,
                    1u32,
                );
                memset(
                    laddr as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<sctp_laddr>() as libc::c_ulong,
                );
                gettimeofday(&mut (*laddr).start_time, 0 as *mut timezone);
                (*laddr).ifa = (*oladdr).ifa;
                ::std::intrinsics::atomic_xadd(&mut (*(*laddr).ifa).refcount, 1u32);
                (*laddr).sctp_nxt_addr.le_next = (*new_inp).sctp_addr_list.lh_first;
                if !(*laddr).sctp_nxt_addr.le_next.is_null() {
                    (*(*new_inp).sctp_addr_list.lh_first).sctp_nxt_addr.le_prev =
                        &mut (*laddr).sctp_nxt_addr.le_next
                }
                (*new_inp).sctp_addr_list.lh_first = laddr;
                (*laddr).sctp_nxt_addr.le_prev = &mut (*new_inp).sctp_addr_list.lh_first;
                (*new_inp).laddr_count += 1;
                if oladdr == (*stcb).asoc.last_used_address {
                    (*stcb).asoc.last_used_address = laddr
                }
            }
            oladdr = (*oladdr).sctp_nxt_addr.le_next
        }
    }
    /* Now any running timers need to be adjusted
     * since we really don't care if they are running
     * or not just blast in the new_inp into all of
     * them.
     */
    (*stcb).asoc.dack_timer.ep = new_inp as *mut libc::c_void;
    (*stcb).asoc.asconf_timer.ep = new_inp as *mut libc::c_void;
    (*stcb).asoc.strreset_timer.ep = new_inp as *mut libc::c_void;
    (*stcb).asoc.shut_guard_timer.ep = new_inp as *mut libc::c_void;
    (*stcb).asoc.autoclose_timer.ep = new_inp as *mut libc::c_void;
    (*stcb).asoc.delayed_event_timer.ep = new_inp as *mut libc::c_void;
    (*stcb).asoc.delete_prim_timer.ep = new_inp as *mut libc::c_void;
    /* now what about the nets? */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        (*net).pmtu_timer.ep = new_inp as *mut libc::c_void;
        (*net).hb_timer.ep = new_inp as *mut libc::c_void;
        (*net).rxt_timer.ep = new_inp as *mut libc::c_void;
        net = (*net).sctp_next.tqe_next
    }
    pthread_mutex_unlock(&mut (*new_inp).inp_mtx);
    pthread_mutex_unlock(&mut (*old_inp).inp_mtx);
}
/*
 * insert an laddr entry with the given ifa for the desired list
 */
unsafe extern "C" fn sctp_insert_laddr(
    mut list: *mut sctpladdr,
    mut ifa: *mut sctp_ifa,
    mut act: uint32_t,
) -> libc::c_int {
    let mut laddr = 0 as *mut sctp_laddr;
    laddr = malloc(system_base_info.sctppcbinfo.ipi_zone_laddr) as *mut sctp_laddr;
    if laddr.is_null() {
        /* out of memory? */
        return 22i32;
    }
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
    memset(
        laddr as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_laddr>() as libc::c_ulong,
    );
    gettimeofday(&mut (*laddr).start_time, 0 as *mut timezone);
    (*laddr).ifa = ifa;
    (*laddr).action = act;
    ::std::intrinsics::atomic_xadd(&mut (*ifa).refcount, 1u32);
    /* insert it */
    (*laddr).sctp_nxt_addr.le_next = (*list).lh_first;
    if !(*laddr).sctp_nxt_addr.le_next.is_null() {
        (*(*list).lh_first).sctp_nxt_addr.le_prev = &mut (*laddr).sctp_nxt_addr.le_next
    }
    (*list).lh_first = laddr;
    (*laddr).sctp_nxt_addr.le_prev = &mut (*list).lh_first;
    return 0i32;
}
/*
 * Remove an laddr entry from the local address list (on an assoc)
 */
unsafe extern "C" fn sctp_remove_laddr(mut laddr: *mut sctp_laddr) {
    /* remove from the list */
    if !(*laddr).sctp_nxt_addr.le_next.is_null() {
        (*(*laddr).sctp_nxt_addr.le_next).sctp_nxt_addr.le_prev = (*laddr).sctp_nxt_addr.le_prev
    }
    *(*laddr).sctp_nxt_addr.le_prev = (*laddr).sctp_nxt_addr.le_next;
    sctp_free_ifa((*laddr).ifa);
    free(laddr as *mut libc::c_void);
    ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
}
/* sctp_ifap is used to bypass normal local address validation checks */
#[no_mangle]
pub unsafe extern "C" fn sctp_inpcb_bind(
    mut so: *mut socket,
    mut addr: *mut sockaddr,
    mut sctp_ifap: *mut sctp_ifa,
    mut p: *mut proc_0,
) -> libc::c_int {
    let mut head = 0 as *mut sctppcbhead;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut port_reuse_active = 0i32;
    let mut bindall = 0;
    let mut lport = 0;
    let mut error = 0;
    let mut vrf_id = 0;
    lport = 0u16;
    bindall = 1i32;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if !addr.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Bind called port: %d\n\x00" as *const u8 as *const libc::c_char,
                    ntohs((*(addr as *mut sockaddr_in)).sin_port) as libc::c_int,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Addr: \x00" as *const u8 as *const libc::c_char,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
            sctp_print_address(addr);
        }
    }
    if (*inp).sctp_flags & 0x10u32 == 0u32 {
        /* already did a bind, subsequent binds NOT allowed ! */
        return 22i32;
    }
    if !addr.is_null() {
        match (*addr).sa_family as libc::c_int {
            2 => {
                let mut sin = 0 as *mut sockaddr_in;
                /* IPV6_V6ONLY socket? */
                if (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0 {
                    return 22i32;
                }
                sin = addr as *mut sockaddr_in;
                lport = (*sin).sin_port;
                if (*sin).sin_addr.s_addr != 0u32 {
                    bindall = 0i32
                }
            }
            10 => {
                let mut sin6 = 0 as *mut sockaddr_in6;
                sin6 = addr as *mut sockaddr_in6;
                lport = (*sin6).sin6_port;
                if ({
                    let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                        as libc::c_int
                }) == 0
                {
                    bindall = 0i32
                    /* SCTP_EMBEDDED_V6_SCOPE */
                }
                /* this must be cleared for ifa_ifwithaddr() */
                (*sin6).sin6_scope_id = 0u32
            }
            123 => {
                let mut sconn = 0 as *mut sockaddr_conn;
                sconn = addr as *mut sockaddr_conn;
                lport = (*sconn).sconn_port;
                if !(*sconn).sconn_addr.is_null() {
                    bindall = 0i32
                }
            }
            _ => return 97i32,
        }
    }
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    /* Setup a vrf_id to be the default for the non-bind-all case. */
    vrf_id = (*inp).def_vrf_id;
    /* increase our count due to the unlock we do */
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
    if lport != 0 {
        let mut inp_tmp = 0 as *mut sctp_inpcb;
        if (ntohs(lport) as libc::c_int) < 1024i32 {
            if !p.is_null() && {
                error = 1i32;
                (error) != 0i32
            } {
                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                return error;
            }
        }
        /* __Windows__ */
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        if bindall != 0 {
            vrf_id = (*inp).def_vrf_id;
            inp_tmp = sctp_pcb_findep(addr, 0i32, 1i32, vrf_id);
            if !inp_tmp.is_null() {
                /*
                 * lock guy returned and lower count
                 * note that we are not bound so
                 * inp_tmp should NEVER be inp. And
                 * it is this inp (inp_tmp) that gets
                 * the reference bump, so we must
                 * lower it.
                 */
                ::std::intrinsics::atomic_xadd(&mut (*inp_tmp).refcount, -(1i32));
                /* unlock info */
                if (*inp).sctp_features & 0x2000000u64 == 0x2000000u64
                    && (*inp_tmp).sctp_features & 0x2000000u64 == 0x2000000u64
                {
                    /* Ok, must be one-2-one and allowing port re-use */
                    port_reuse_active = 1i32
                } else {
                    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                    return 98i32;
                }
            }
        } else {
            inp_tmp = sctp_pcb_findep(addr, 0i32, 1i32, vrf_id);
            if !inp_tmp.is_null() {
                /*
                 * lock guy returned and lower count note
                 * that we are not bound so inp_tmp should
                 * NEVER be inp. And it is this inp (inp_tmp)
                 * that gets the reference bump, so we must
                 * lower it.
                 */
                ::std::intrinsics::atomic_xadd(&mut (*inp_tmp).refcount, -(1i32));
                /* unlock info */
                if (*inp).sctp_features & 0x2000000u64 == 0x2000000u64
                    && (*inp_tmp).sctp_features & 0x2000000u64 == 0x2000000u64
                {
                    /* Ok, must be one-2-one and allowing port re-use */
                    port_reuse_active = 1i32
                } else {
                    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                    return 98i32;
                }
            }
        }
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        if bindall != 0 {
            /* verify that no lport is not used by a singleton */
            if port_reuse_active == 0i32 && {
                inp_tmp = sctp_isport_inuse(inp, lport, vrf_id);
                !inp_tmp.is_null()
            } {
                /* Sorry someone already has this one bound */
                if (*inp).sctp_features & 0x2000000u64 == 0x2000000u64
                    && (*inp_tmp).sctp_features & 0x2000000u64 == 0x2000000u64
                {
                    port_reuse_active = 1i32
                } else {
                    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                    return 98i32;
                }
            }
        }
    } else {
        let mut first = 0;
        let mut last = 0;
        let mut candidate = 0;
        let mut count = 0;
        let mut done = 0;
        /* TODO ensure uid is 0, etc... */
        first = ipport_firstauto as uint16_t;
        last = ipport_lastauto as uint16_t;
        /* __Windows__ */
        if first as libc::c_int > last as libc::c_int {
            let mut temp = 0; /* number of candidates */
            temp = first;
            first = last;
            last = temp
        }
        count = (last as libc::c_int - first as libc::c_int + 1i32) as uint16_t;
        candidate = (first as libc::c_uint).wrapping_add(
            sctp_select_initial_TSN(&mut (*inp).sctp_ep).wrapping_rem(count as libc::c_uint),
        ) as uint16_t;
        done = 0i32;
        while done == 0 {
            if sctp_isport_inuse(inp, htons(candidate), (*inp).def_vrf_id).is_null() {
                done = 1i32
            }
            if done == 0 {
                count = count.wrapping_sub(1);
                if count as libc::c_int == 0i32 {
                    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                    return 98i32;
                }
                if candidate as libc::c_int == last as libc::c_int {
                    candidate = first
                } else {
                    candidate = (candidate as libc::c_int + 1i32) as uint16_t
                }
            }
        }
        lport = htons(candidate)
    }
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
    if (*inp).sctp_flags & (0x10000000i32 | 0x20000000i32) as libc::c_uint != 0 {
        /*
         * this really should not happen. The guy did a non-blocking
         * bind and then did a close at the same time.
         */
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        return 22i32;
    }
    /* ok we look clear to give out this port, so lets setup the binding */
    if bindall != 0 {
        /* binding to all addresses, so just set in the proper flags */
        (*inp).sctp_flags |= 0x4u32;
        /* set the automatic addr changes from kernel flag */
        if system_base_info.sctpsysctl.sctp_auto_asconf == 0u32 {
            (*inp).sctp_features &= !(0x20i32) as libc::c_ulong;
            (*inp).sctp_features &= !(0x40i32) as libc::c_ulong
        } else {
            (*inp).sctp_features |= 0x20u64;
            (*inp).sctp_features |= 0x40u64
        }
        if system_base_info.sctpsysctl.sctp_multiple_asconfs == 0u32 {
            (*inp).sctp_features &= !(0x1000000i32) as libc::c_ulong
        } else {
            (*inp).sctp_features |= 0x1000000u64
        }
        /* set the automatic mobility_base from kernel
           flag (by micchie)
        */
        if system_base_info.sctpsysctl.sctp_mobility_base == 0u32 {
            (*inp).sctp_mobility_features &= !(0x1i32) as libc::c_uint;
            (*inp).sctp_mobility_features &= !(0x4i32) as libc::c_uint
        } else {
            (*inp).sctp_mobility_features |= 0x1u32;
            (*inp).sctp_mobility_features &= !(0x4i32) as libc::c_uint
        }
        /* set the automatic mobility_fasthandoff from kernel
           flag (by micchie)
        */
        if system_base_info.sctpsysctl.sctp_mobility_fasthandoff == 0u32 {
            (*inp).sctp_mobility_features &= !(0x2i32) as libc::c_uint;
            (*inp).sctp_mobility_features &= !(0x4i32) as libc::c_uint
        } else {
            (*inp).sctp_mobility_features |= 0x2u32;
            (*inp).sctp_mobility_features &= !(0x4i32) as libc::c_uint
        }
    } else {
        let mut ifa = 0 as *mut sctp_ifa;
        let mut store = sctp_sockstore {
            sin: sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            },
        };
        memset(
            &mut store as *mut sctp_sockstore as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
        );
        match (*addr).sa_family as libc::c_int {
            2 => {
                memcpy(
                    &mut store.sin as *mut sockaddr_in as *mut libc::c_void,
                    addr as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                );
                store.sin.sin_port = 0u16
            }
            10 => {
                memcpy(
                    &mut store.sin6 as *mut sockaddr_in6 as *mut libc::c_void,
                    addr as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                );
                store.sin6.sin6_port = 0u16
            }
            123 => {
                memcpy(
                    &mut store.sconn as *mut sockaddr_conn as *mut libc::c_void,
                    addr as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
                );
                store.sconn.sconn_port = 0u16
            }
            _ => {}
        }
        /*
         * first find the interface with the bound address need to
         * zero out the port to find the address! yuck! can't do
         * this earlier since need port for sctp_pcb_findep()
         */
        if !sctp_ifap.is_null() {
            ifa = sctp_ifap
        } else {
            /* Note for BSD we hit here always other
             * O/S's will pass things in via the
             * sctp_ifap argument (Panda).
             */
            ifa = sctp_find_ifa_by_addr(&mut store.sa, vrf_id, 0i32)
        }
        if ifa.is_null() {
            /* Can't find an interface with that address */
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
            return 99i32;
        }
        if (*addr).sa_family as libc::c_int == 10i32 {
            /* GAK, more FIXME IFA lock? */
            if (*ifa).localifa_flags & 0x8u32 != 0 {
                /* Can't bind a non-existent addr. */
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                return 22i32;
            }
        }
        /* we're not bound all */
        (*inp).sctp_flags &= !(0x4i32) as libc::c_uint;
        /* allow bindx() to send ASCONF's for binding changes */
        (*inp).sctp_features |= 0x20u64;
        /* clear automatic addr changes from kernel flag */
        (*inp).sctp_features &= !(0x40i32) as libc::c_ulong;
        /* add this address to the endpoint list */
        error = sctp_insert_laddr(&mut (*inp).sctp_addr_list, ifa, 0u32);
        if error != 0i32 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
            return error;
        }
        (*inp).laddr_count += 1
    }
    /* find the bucket */
    if port_reuse_active != 0 {
        /* Put it into tcp 1-2-1 hash */
        head =
            &mut *system_base_info.sctppcbinfo.sctp_tcpephash.offset(
                (lport as libc::c_ulong & system_base_info.sctppcbinfo.hashtcpmark) as isize,
            ) as *mut sctppcbhead;
        (*inp).sctp_flags |= 0x400000u32
    } else {
        head = &mut *system_base_info
            .sctppcbinfo
            .sctp_ephash
            .offset((lport as libc::c_ulong & system_base_info.sctppcbinfo.hashmark) as isize)
            as *mut sctppcbhead
    }
    /* put it in the bucket */
    (*inp).sctp_hash.le_next = (*head).lh_first;
    if !(*inp).sctp_hash.le_next.is_null() {
        (*(*head).lh_first).sctp_hash.le_prev = &mut (*inp).sctp_hash.le_next
    }
    (*head).lh_first = inp;
    (*inp).sctp_hash.le_prev = &mut (*head).lh_first;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Main hash to bind at head:%p, bound port:%d - in tcp_pool=%d\n\x00" as *const u8
                    as *const libc::c_char,
                head as *mut libc::c_void,
                ntohs(lport) as libc::c_int,
                port_reuse_active,
            );
        }
    }
    /* set in the port */
    (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport = lport;
    /* turn off just the unbound flag */
    (*inp).sctp_flags &= !(0x10i32) as libc::c_uint;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    return 0i32;
}
unsafe extern "C" fn sctp_iterator_inp_being_freed(mut inp: *mut sctp_inpcb) {
    let mut it = 0 as *mut sctp_iterator;
    let mut nit = 0 as *mut sctp_iterator;
    /*
     * We enter with the only the ITERATOR_LOCK in place and a write
     * lock on the inp_info stuff.
     */
    it = sctp_it_ctl.cur_it;
    if !it.is_null() && (*it).inp == inp {
        /*
         * This is tricky and we hold the iterator lock,
         * but when it returns and gets the lock (when we
         * release it) the iterator will try to operate on
         * inp. We need to stop that from happening. But
         * of course the iterator has a reference on the
         * stcb and inp. We can mark it and it will stop.
         *
         * If its a single iterator situation, we
         * set the end iterator flag. Otherwise
         * we set the iterator to go to the next inp.
         *
         */
        if (*it).iterator_flags & 0x2u32 != 0 {
            sctp_it_ctl.iterator_flags |= 0x4u32
        } else {
            sctp_it_ctl.iterator_flags |= 0x8u32
        }
    }
    /* Now go through and remove any single reference to
     * our inp that may be still pending on the list
     */
    pthread_mutex_lock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    it = sctp_it_ctl.iteratorhead.tqh_first;
    while !it.is_null() && {
        nit = (*it).sctp_nxt_itr.tqe_next;
        (1i32) != 0
    } {
        if (*it).inp == inp {
            /* This one points to me is it inp specific? */
            if (*it).iterator_flags & 0x2u32 != 0 {
                /* Remove and free this one */
                if !(*it).sctp_nxt_itr.tqe_next.is_null() {
                    (*(*it).sctp_nxt_itr.tqe_next).sctp_nxt_itr.tqe_prev =
                        (*it).sctp_nxt_itr.tqe_prev
                } else {
                    sctp_it_ctl.iteratorhead.tqh_last = (*it).sctp_nxt_itr.tqe_prev
                }
                *(*it).sctp_nxt_itr.tqe_prev = (*it).sctp_nxt_itr.tqe_next;
                if (*it).function_atend.is_some() {
                    Some((*it).function_atend.expect("non-null function pointer"))
                        .expect("non-null function pointer")(
                        (*it).pointer, (*it).val
                    );
                }
                free(it as *mut libc::c_void);
            } else {
                (*it).inp = (*(*it).inp).sctp_list.le_next;
                if !(*it).inp.is_null() {
                    ::std::intrinsics::atomic_xadd(&mut (*(*it).inp).refcount, 1i32);
                }
            }
            /* When its put in the refcnt is incremented so decr it */
            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
        }
        it = nit
    }
    pthread_mutex_unlock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
}
/* release sctp_inpcb unbind the port */
#[no_mangle]
pub unsafe extern "C" fn sctp_inpcb_free(
    mut inp: *mut sctp_inpcb,
    mut immediate: libc::c_int,
    mut from: libc::c_int,
) {
    let mut asoc = 0 as *mut sctp_tcb;
    let mut nasoc = 0 as *mut sctp_tcb;
    let mut laddr = 0 as *mut sctp_laddr;
    let mut nladdr = 0 as *mut sctp_laddr;
    let mut ip_pcb = 0 as *mut inpcb;
    let mut so = 0 as *mut socket;
    let mut being_refed = 0i32;
    let mut sq = 0 as *mut sctp_queued_to_read;
    let mut nsq = 0 as *mut sctp_queued_to_read;
    let mut cnt = 0;
    let mut shared_key = 0 as *mut sctp_sharedkey_t;
    let mut nshared_key = 0 as *mut sctp_sharedkey_t;
    pthread_mutex_lock(&mut sctp_it_ctl.it_mtx);
    /* mark any iterators on the list or being processed */
    sctp_iterator_inp_being_freed(inp);
    pthread_mutex_unlock(&mut sctp_it_ctl.it_mtx);
    so = (*inp).sctp_socket;
    if (*inp).sctp_flags & 0x20000000u32 != 0 {
        /* been here before.. eeks.. get out of here */
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"This conflict in free SHOULD not be happening! from %d, imm %d\n\x00" as *const u8
                    as *const libc::c_char,
                from,
                immediate,
            );
        }
        return;
    }
    pthread_mutex_lock(&mut (*inp).inp_create_mtx);
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    if from == 1i32 {
        (*inp).sctp_flags &= !(0x40000i32) as libc::c_uint;
        /* socket is gone, so no more wakeups allowed */
        (*inp).sctp_flags |= 0x800000u32;
        (*inp).sctp_flags &= !(0x2000000i32) as libc::c_uint;
        (*inp).sctp_flags &= !(0x1000000i32) as libc::c_uint
    }
    /* First time through we have the socket lock, after that no more. */
    sctp_timer_stop(
        7i32,
        inp,
        0 as *mut sctp_tcb,
        0 as *mut sctp_nets,
        (0x20000000i32 + 0x1i32) as uint32_t,
    ); /* we could just cast the main pointer
        * here but I will be nice :> (i.e.
        * ip_pcb = ep;) */
    if !(*inp).control.is_null() {
        m_freem((*inp).control);
        (*inp).control = 0 as *mut mbuf
    }
    if !(*inp).pkt.is_null() {
        m_freem((*inp).pkt);
        (*inp).pkt = 0 as *mut mbuf
    }
    ip_pcb = &mut (*inp).ip_inp.inp;
    if immediate == 0i32 {
        let mut cnt_in_sd = 0;
        cnt_in_sd = 0i32;

        asoc = (*inp).sctp_asoc_list.lh_first;
        while !asoc.is_null() && {
            nasoc = (*asoc).sctp_tcblist.le_next;
            (1i32) != 0
        } {
            pthread_mutex_lock(&mut (*asoc).tcb_mtx);
            if (*asoc).asoc.state & 0x200i32 != 0 {
                /* Skip guys being freed */
                cnt_in_sd += 1;
                if (*asoc).asoc.state & 0x1000i32 != 0 {
                    /*
                     * Special case - we did not start a kill
                     * timer on the asoc due to it was not
                     * closed. So go ahead and start it now.
                     */
                    (*asoc).asoc.state &= !(0x1000i32);
                    sctp_timer_start(16i32, inp, asoc, 0 as *mut sctp_nets);
                }
                pthread_mutex_unlock(&mut (*asoc).tcb_mtx);
            } else if ((*asoc).asoc.state & 0x7fi32 == 0x2i32
                || (*asoc).asoc.state & 0x7fi32 == 0x4i32)
                && (*asoc).asoc.total_output_queue_size == 0u32
            {
                /* If we have data in queue, we don't want to just
                 * free since the app may have done, send()/close
                 * or connect/send/close. And it wants the data
                 * to get across first.
                 */
                /* Just abandon things in the front states */
                if sctp_free_assoc(inp, asoc, 1i32, 0x20000000i32 + 0x2i32) == 0i32 {
                    cnt_in_sd += 1
                }
            } else {
                /* Disconnect the socket please */
                (*asoc).sctp_socket = 0 as *mut socket;
                sctp_add_substate(asoc, 0x100i32);
                if (*asoc).asoc.size_on_reasm_queue > 0u32
                    || !(*asoc).asoc.control_pdapi.is_null()
                    || (*asoc).asoc.size_on_all_streams > 0u32
                    || !so.is_null() && (*so).so_rcv.sb_cc > 0u32
                {
                    let mut op_err = 0 as *mut mbuf;
                    op_err = sctp_generate_cause(0xcu16, b"\x00" as *const u8 as *mut libc::c_char);
                    (*(*asoc).sctp_ep).last_abort_code = (0x20000000i32 + 0x3i32) as uint32_t;
                    sctp_send_abort_tcb(asoc, op_err, 1i32);
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_aborted,
                        1u32,
                    );
                    if (*asoc).asoc.state & 0x7fi32 == 0x8i32
                        || (*asoc).asoc.state & 0x7fi32 == 0x20i32
                    {
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctpstat.sctps_currestab,
                            1u32,
                        );
                    }
                    if sctp_free_assoc(inp, asoc, 1i32, 0x20000000i32 + 0x4i32) == 0i32 {
                        cnt_in_sd += 1
                    }
                } else {
                    let mut op_err_0 = 0 as *mut mbuf;
                    let mut current_block_88: u64;
                    if (*asoc).asoc.send_queue.tqh_first.is_null()
                        && (*asoc).asoc.sent_queue.tqh_first.is_null()
                        && (*asoc).asoc.stream_queue_cnt == 0u32
                    {
                        if Some(
                            (*asoc)
                                .asoc
                                .ss_functions
                                .sctp_ss_is_user_msgs_incomplete
                                .expect("non-null function pointer"),
                        )
                        .expect("non-null function pointer")(
                            asoc, &mut (*asoc).asoc
                        ) != 0
                        {
                            current_block_88 = 1214839029032782076;
                        } else {
                            if (*asoc).asoc.state & 0x7fi32 != 0x10i32
                                && (*asoc).asoc.state & 0x7fi32 != 0x40i32
                            {
                                let mut netp = 0 as *mut sctp_nets;
                                /*
                                 * there is nothing queued to send,
                                 * so I send shutdown
                                 */
                                if (*asoc).asoc.state & 0x7fi32 == 0x8i32
                                    || (*asoc).asoc.state & 0x7fi32 == 0x20i32
                                {
                                    ::std::intrinsics::atomic_xsub(
                                        &mut system_base_info.sctpstat.sctps_currestab,
                                        1u32,
                                    );
                                }
                                sctp_set_state(asoc, 0x10i32);
                                sctp_stop_timers_for_shutdown(asoc);
                                if !(*asoc).asoc.alternate.is_null() {
                                    netp = (*asoc).asoc.alternate
                                } else {
                                    netp = (*asoc).asoc.primary_destination
                                }
                                sctp_send_shutdown(asoc, netp);
                                sctp_timer_start(4i32, (*asoc).sctp_ep, asoc, netp);
                                sctp_timer_start(
                                    11i32,
                                    (*asoc).sctp_ep,
                                    asoc,
                                    (*asoc).asoc.primary_destination,
                                );
                                sctp_chunk_output(inp, asoc, 5i32, 1i32);
                            }
                            current_block_88 = 6406431739208918833;
                        }
                    } else {
                        /* mark into shutdown pending */
                        sctp_add_substate(asoc, 0x80i32);
                        sctp_timer_start(
                            11i32,
                            (*asoc).sctp_ep,
                            asoc,
                            (*asoc).asoc.primary_destination,
                        );
                        if Some(
                            (*asoc)
                                .asoc
                                .ss_functions
                                .sctp_ss_is_user_msgs_incomplete
                                .expect("non-null function pointer"),
                        )
                        .expect("non-null function pointer")(
                            asoc, &mut (*asoc).asoc
                        ) != 0
                        {
                            sctp_add_substate(asoc, 0x400i32);
                        }
                        if (*asoc).asoc.send_queue.tqh_first.is_null()
                            && (*asoc).asoc.sent_queue.tqh_first.is_null()
                            && (*asoc).asoc.state & 0x400i32 != 0
                        {
                            op_err_0 = 0 as *mut mbuf;
                            current_block_88 = 1214839029032782076;
                        } else {
                            sctp_chunk_output(inp, asoc, 16i32, 1i32);
                            current_block_88 = 6406431739208918833;
                        }
                    }
                    match current_block_88 {
                        6406431739208918833 => {
                            cnt_in_sd += 1;
                            pthread_mutex_unlock(&mut (*asoc).tcb_mtx);
                        }
                        _ => {
                            op_err_0 = sctp_generate_cause(
                                0xcu16,
                                b"\x00" as *const u8 as *mut libc::c_char,
                            );
                            (*(*asoc).sctp_ep).last_abort_code =
                                (0x20000000i32 + 0x5i32) as uint32_t;
                            sctp_send_abort_tcb(asoc, op_err_0, 1i32);
                            ::std::intrinsics::atomic_xadd(
                                &mut system_base_info.sctpstat.sctps_aborted,
                                1u32,
                            );
                            if (*asoc).asoc.state & 0x7fi32 == 0x8i32
                                || (*asoc).asoc.state & 0x7fi32 == 0x20i32
                            {
                                ::std::intrinsics::atomic_xsub(
                                    &mut system_base_info.sctpstat.sctps_currestab,
                                    1u32,
                                );
                            }
                            if sctp_free_assoc(inp, asoc, 1i32, 0x20000000i32 + 0x6i32) == 0i32 {
                                cnt_in_sd += 1
                            }
                        }
                    }
                }
            }
            asoc = nasoc
        }
        /* now is there some left in our SHUTDOWN state? */
        if cnt_in_sd != 0 {
            (*inp).sctp_socket = 0 as *mut socket;
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            pthread_mutex_unlock(&mut (*inp).inp_create_mtx);
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
            return;
        }
    }
    (*inp).sctp_socket = 0 as *mut socket;
    if (*inp).sctp_flags & 0x10u32 != 0x10u32 {
        /*
         * ok, this guy has been bound. It's port is
         * somewhere in the SCTP_BASE_INFO(hash table). Remove
         * it!
         */
        if !(*inp).sctp_hash.le_next.is_null() {
            (*(*inp).sctp_hash.le_next).sctp_hash.le_prev = (*inp).sctp_hash.le_prev
        }
        *(*inp).sctp_hash.le_prev = (*inp).sctp_hash.le_next;
        (*inp).sctp_flags |= 0x10u32
    }
    /* If there is a timer running to kill us,
     * forget it, since it may have a contest
     * on the INP lock.. which would cause us
     * to die ...
     */
    cnt = 0i32;

    asoc = (*inp).sctp_asoc_list.lh_first;
    while !asoc.is_null() && {
        nasoc = (*asoc).sctp_tcblist.le_next;
        (1i32) != 0
    } {
        pthread_mutex_lock(&mut (*asoc).tcb_mtx);
        if (*asoc).asoc.state & 0x200i32 != 0 {
            if (*asoc).asoc.state & 0x1000i32 != 0 {
                (*asoc).asoc.state &= !(0x1000i32);
                sctp_timer_start(16i32, inp, asoc, 0 as *mut sctp_nets);
            }
            cnt += 1;
            pthread_mutex_unlock(&mut (*asoc).tcb_mtx);
        } else {
            let mut current_block_129: u64;
            if (*asoc).asoc.state & 0x7fi32 != 0x2i32 && (*asoc).asoc.state & 0x200i32 == 0i32 {
                let mut op_err_1 = 0 as *mut mbuf;
                op_err_1 = sctp_generate_cause(0xcu16, b"\x00" as *const u8 as *mut libc::c_char);
                (*(*asoc).sctp_ep).last_abort_code = (0x20000000i32 + 0x7i32) as uint32_t;
                sctp_send_abort_tcb(asoc, op_err_1, 1i32);
                ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_aborted, 1u32);
                current_block_129 = 914440069034635393;
            } else if (*asoc).asoc.state & 0x200i32 != 0 {
                cnt += 1;
                pthread_mutex_unlock(&mut (*asoc).tcb_mtx);
                current_block_129 = 18002345992382212654;
            } else {
                current_block_129 = 914440069034635393;
            }
            match current_block_129 {
                18002345992382212654 => {}
                _ => {
                    if (*asoc).asoc.state & 0x7fi32 == 0x8i32
                        || (*asoc).asoc.state & 0x7fi32 == 0x20i32
                    {
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctpstat.sctps_currestab,
                            1u32,
                        );
                    }
                    if sctp_free_assoc(inp, asoc, 2i32, 0x20000000i32 + 0x8i32) == 0i32 {
                        cnt += 1
                    }
                }
            }
        }
        asoc = nasoc
    }
    if cnt != 0 {
        /* Ok we have someone out there that will kill us */
        sctp_os_timer_stop(&mut (*inp).sctp_ep.signature_change.timer);
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        pthread_mutex_unlock(&mut (*inp).inp_create_mtx);
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        return;
    }
    if (*inp).refcount != 0 || being_refed != 0 || (*inp).sctp_flags & 0x40000u32 != 0 {
        sctp_os_timer_stop(&mut (*inp).sctp_ep.signature_change.timer);
        sctp_timer_start(15i32, inp, 0 as *mut sctp_tcb, 0 as *mut sctp_nets);
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        pthread_mutex_unlock(&mut (*inp).inp_create_mtx);
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        return;
    }
    (*inp).sctp_ep.signature_change.type_0 = 0i32;
    (*inp).sctp_flags |= 0x20000000u32;
    /* Remove it from the list .. last thing we need a
     * lock for.
     */
    if !(*inp).sctp_list.le_next.is_null() {
        (*(*inp).sctp_list.le_next).sctp_list.le_prev = (*inp).sctp_list.le_prev
    }
    *(*inp).sctp_list.le_prev = (*inp).sctp_list.le_next;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    pthread_mutex_unlock(&mut (*inp).inp_create_mtx);
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    /* Now we release all locks. Since this INP
     * cannot be found anymore except possibly by the
     * kill timer that might be running. We call
     * the drain function here. It should hit the case
     * were it sees the ACTIVE flag cleared and exit
     * out freeing us to proceed and destroy everything.
     */
    if from != 2i32 {
        sctp_os_timer_stop(&mut (*inp).sctp_ep.signature_change.timer);
    } else {
        /* Probably un-needed */
        sctp_os_timer_stop(&mut (*inp).sctp_ep.signature_change.timer);
    }
    if !(*inp).sctp_asocidhash.is_null() {
        sctp_hashdestroy(
            (*inp).sctp_asocidhash as *mut libc::c_void,
            M_PCB.as_mut_ptr(),
            (*inp).hashasocidmark,
        );
        (*inp).sctp_asocidhash = 0 as *mut sctpasochead
    }
    /*sa_ignore FREED_MEMORY*/
    sq = (*inp).read_queue.tqh_first;
    while !sq.is_null() && {
        nsq = (*sq).next.tqe_next;
        (1i32) != 0
    } {
        /* Its only abandoned if it had data left */
        if (*sq).length != 0 {
            ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_left_abandon, 1u32);
        }
        if !(*sq).next.tqe_next.is_null() {
            (*(*sq).next.tqe_next).next.tqe_prev = (*sq).next.tqe_prev
        } else {
            (*inp).read_queue.tqh_last = (*sq).next.tqe_prev
        }
        *(*sq).next.tqe_prev = (*sq).next.tqe_next;
        if !(*sq).whoFrom.is_null() {
            if ::std::intrinsics::atomic_xadd(
                &mut (*(*sq).whoFrom).ref_count as *mut libc::c_int,
                -(1i32),
            ) == 1i32
            {
                sctp_os_timer_stop(&mut (*(*sq).whoFrom).rxt_timer.timer);
                sctp_os_timer_stop(&mut (*(*sq).whoFrom).pmtu_timer.timer);
                sctp_os_timer_stop(&mut (*(*sq).whoFrom).hb_timer.timer);
                if !(*(*sq).whoFrom).ro.ro_rt.is_null() {
                    if (*(*(*sq).whoFrom).ro.ro_rt).rt_refcnt <= 1i64 {
                        sctp_userspace_rtfree((*(*sq).whoFrom).ro.ro_rt);
                    } else {
                        (*(*(*sq).whoFrom).ro.ro_rt).rt_refcnt -= 1
                    }
                    (*(*sq).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                    (*(*sq).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t
                }
                if (*(*sq).whoFrom).src_addr_selected != 0 {
                    sctp_free_ifa((*(*sq).whoFrom).ro._s_addr);
                    (*(*sq).whoFrom).ro._s_addr = 0 as *mut sctp_ifa
                }
                (*(*sq).whoFrom).src_addr_selected = 0u8;
                (*(*sq).whoFrom).dest_state =
                    ((*(*sq).whoFrom).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                free((*sq).whoFrom as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                    1u32,
                );
            }
        }
        if !so.is_null() {
            (*so).so_rcv.sb_cc = ((*so).so_rcv.sb_cc).wrapping_sub((*sq).length)
        }
        if !(*sq).data.is_null() {
            m_freem((*sq).data);
            (*sq).data = 0 as *mut mbuf
        }
        /*
         * no need to free the net count, since at this point all
         * assoc's are gone.
         */
        free(sq as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
        sq = nsq
    }
    /* Now the sctp_pcb things */
    /*
     * free each asoc if it is not already closed/free. we can't use the
     * macro here since le_next will get freed as part of the
     * sctp_free_assoc() call.
     */
    if !(*ip_pcb).inp_depend4.inp4_options.is_null() {
        m_free((*ip_pcb).inp_depend4.inp4_options);
        (*ip_pcb).inp_depend4.inp4_options = 0 as *mut mbuf
    }
    /* INET6 */
    (*ip_pcb).inp_vflag = 0u8;
    /* free up authentication fields */
    if !(*inp).sctp_ep.local_auth_chunks.is_null() {
        sctp_free_chunklist((*inp).sctp_ep.local_auth_chunks);
    }
    if !(*inp).sctp_ep.local_hmacs.is_null() {
        sctp_free_hmaclist((*inp).sctp_ep.local_hmacs);
    }
    shared_key = (*inp).sctp_ep.shared_keys.lh_first;
    while !shared_key.is_null() && {
        nshared_key = (*shared_key).next.le_next;
        (1i32) != 0
    } {
        if !(*shared_key).next.le_next.is_null() {
            (*(*shared_key).next.le_next).next.le_prev = (*shared_key).next.le_prev
        }
        *(*shared_key).next.le_prev = (*shared_key).next.le_next;
        sctp_free_sharedkey(shared_key);
        shared_key = nshared_key
        /*sa_ignore FREED_MEMORY*/
    }
    /*
     * if we have an address list the following will free the list of
     * ifaddr's that are set into this ep. Again macro limitations here,
     * since the LIST_FOREACH could be a bad idea.
     */
    laddr = (*inp).sctp_addr_list.lh_first;
    while !laddr.is_null() && {
        nladdr = (*laddr).sctp_nxt_addr.le_next;
        (1i32) != 0
    } {
        sctp_remove_laddr(laddr);
        laddr = nladdr
    }
    /* Now lets see about freeing the EP hash table. */
    if !(*inp).sctp_tcbhash.is_null() {
        sctp_hashdestroy(
            (*inp).sctp_tcbhash as *mut libc::c_void,
            M_PCB.as_mut_ptr(),
            (*inp).sctp_hashmark,
        );
        (*inp).sctp_tcbhash = 0 as *mut sctpasochead
    }
    /* Now we must put the ep memory back into the zone pool */
    pthread_mutex_destroy(&mut (*inp).inp_mtx);
    pthread_mutex_destroy(&mut (*inp).inp_rdata_mtx);
    pthread_mutex_destroy(&mut (*inp).inp_create_mtx);
    free(inp as *mut libc::c_void);
    ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_ep, 1u32);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_findnet(
    mut stcb: *mut sctp_tcb,
    mut addr: *mut sockaddr,
) -> *mut sctp_nets {
    let mut net = 0 as *mut sctp_nets;
    /* locate the address */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        if sctp_cmpaddr(
            addr,
            &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr,
        ) != 0
        {
            return net;
        }
        net = (*net).sctp_next.tqe_next
    }
    return 0 as *mut sctp_nets;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_is_address_on_local_host(
    mut addr: *mut sockaddr,
    mut vrf_id: uint32_t,
) -> libc::c_int {
    let mut sctp_ifa = 0 as *mut sctp_ifa;
    sctp_ifa = sctp_find_ifa_by_addr(addr, vrf_id, 0i32);
    if !sctp_ifa.is_null() {
        return 1i32;
    } else {
        return 0i32;
    };
}
/*
 * add's a remote endpoint address, done with the INIT/INIT-ACK as well as
 * when a ASCONF arrives that adds it. It will also initialize all the cwnd
 * stats of stuff.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_add_remote_addr(
    mut stcb: *mut sctp_tcb,
    mut newaddr: *mut sockaddr,
    mut netp: *mut *mut sctp_nets,
    mut port: uint16_t,
    mut set_scope: libc::c_int,
    mut from: libc::c_int,
) -> libc::c_int {
    let mut net = 0 as *mut sctp_nets;
    let mut netfirst = 0 as *mut sctp_nets;
    let mut addr_inscope = 0;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Adding an address (from:%d) to the peer: \x00" as *const u8
                    as *const libc::c_char,
                from,
            );
        }
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
        sctp_print_address(newaddr);
    }
    netfirst = sctp_findnet(stcb, newaddr);
    if !netfirst.is_null() {
        /*
         * Lie and return ok, we don't want to make the association
         * go away for this behavior. It will happen in the TCP
         * model in a connected socket. It does not reach the hash
         * table until after the association is built so it can't be
         * found. Mark as reachable, since the initial creation will
         * have been cleared and the NOT_IN_ASSOC flag will have
         * been added... and we don't want to end up removing it
         * back out.
         */
        if (*netfirst).dest_state as libc::c_int & 0x200i32 != 0 {
            (*netfirst).dest_state = (0x1i32 | 0x200i32) as uint16_t
        } else {
            (*netfirst).dest_state = 0x1u16
        }
        return 0i32;
    }
    addr_inscope = 1i32;
    match (*newaddr).sa_family as libc::c_int {
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            sin = newaddr as *mut sockaddr_in;
            if (*sin).sin_addr.s_addr == 0u32 {
                /* Invalid address */
                return -(1i32);
            }
            /* zero out the zero area */
            memset(
                &mut (*sin).sin_zero as *mut [libc::c_uchar; 8] as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<[libc::c_uchar; 8]>() as libc::c_ulong,
            );
            /* assure len is set */
            if set_scope != 0 {
                if *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t).offset(0isize)
                    as libc::c_int
                    == 10i32
                    || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(0isize) as libc::c_int
                        == 172i32
                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                            .offset(1isize) as libc::c_int
                            >= 16i32
                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                            .offset(1isize) as libc::c_int
                            <= 32i32
                    || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(0isize) as libc::c_int
                        == 192i32
                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                            .offset(1isize) as libc::c_int
                            == 168i32
                {
                    (*stcb).asoc.scope.ipv4_local_scope = 1u8
                }
            } else if (*(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                .offset(0isize) as libc::c_int
                == 10i32
                || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t).offset(0isize)
                    as libc::c_int
                    == 172i32
                    && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(1isize) as libc::c_int
                        >= 16i32
                    && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(1isize) as libc::c_int
                        <= 32i32
                || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t).offset(0isize)
                    as libc::c_int
                    == 192i32
                    && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                        .offset(1isize) as libc::c_int
                        == 168i32)
                && (*stcb).asoc.scope.ipv4_local_scope as libc::c_int == 0i32
            {
                addr_inscope = 0i32
            }
        }
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 = newaddr as *mut sockaddr_in6;
            if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[3usize] == 0u32) as libc::c_int
            }) != 0
            {
                /* Validate the address is in scope */
                /* Invalid address */
                return -(1i32);
            }
            /* assure len is set */
            if set_scope != 0 {
                if sctp_is_address_on_local_host(newaddr, (*stcb).asoc.vrf_id) != 0 {
                    (*stcb).asoc.scope.loopback_scope = 1u8;
                    (*stcb).asoc.scope.local_scope = 0u8;
                    (*stcb).asoc.scope.ipv4_local_scope = 1u8;
                    (*stcb).asoc.scope.site_scope = 1u8
                } else if ({
                    let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                        == htonl(0xfe800000u32)) as libc::c_int
                }) != 0
                {
                    /*
                     * If the new destination is a LINK_LOCAL we
                     * must have common site scope. Don't set
                     * the local scope since we may not share
                     * all links, only loopback can do this.
                     * Links on the local network would also be
                     * on our private network for v4 too.
                     */
                    (*stcb).asoc.scope.ipv4_local_scope = 1u8;
                    (*stcb).asoc.scope.site_scope = 1u8
                } else if ({
                    let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                        == htonl(0xfec00000u32)) as libc::c_int
                }) != 0
                {
                    /*
                     * If the new destination is SITE_LOCAL then
                     * we must have site scope in common.
                     */
                    (*stcb).asoc.scope.site_scope = 1u8
                }
            } else if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[3usize] == htonl(1u32))
                    as libc::c_int
            }) != 0
                && (*stcb).asoc.scope.loopback_scope as libc::c_int == 0i32
            {
                addr_inscope = 0i32
            } else if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32) == htonl(0xfe800000u32))
                    as libc::c_int
            }) != 0
                && (*stcb).asoc.scope.local_scope as libc::c_int == 0i32
            {
                addr_inscope = 0i32
            } else if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32) == htonl(0xfec00000u32))
                    as libc::c_int
            }) != 0
                && (*stcb).asoc.scope.site_scope as libc::c_int == 0i32
            {
                addr_inscope = 0i32
            }
        }
        123 => {
            let mut sconn = 0 as *mut sockaddr_conn;
            sconn = newaddr as *mut sockaddr_conn;
            if (*sconn).sconn_addr.is_null() {
                /* Validate the address is in scope */
                /* Invalid address */
                return -(1i32);
            }
        }
        _ => {
            /* not supported family type */
            return -(1i32);
        }
    }
    net = malloc(system_base_info.sctppcbinfo.ipi_zone_net) as *mut sctp_nets;
    if net.is_null() {
        return -(1i32);
    }
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_raddr, 1u32);
    memset(
        net as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_nets>() as libc::c_ulong,
    );
    gettimeofday(&mut (*net).start_time, 0 as *mut timezone);
    match (*newaddr).sa_family as libc::c_int {
        2 => {
            memcpy(
                &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut libc::c_void,
                newaddr as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
            );
            (*(&mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr_in)).sin_port =
                (*stcb).rport
        }
        10 => {
            memcpy(
                &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut libc::c_void,
                newaddr as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            );
            (*(&mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr_in6)).sin6_port =
                (*stcb).rport
        }
        123 => {
            memcpy(
                &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut libc::c_void,
                newaddr as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
            );
            (*(&mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr_conn)).sconn_port =
                (*stcb).rport
        }
        _ => {}
    }
    (*net).addr_is_local = sctp_is_address_on_local_host(newaddr, (*stcb).asoc.vrf_id) as uint8_t;
    if (*net).addr_is_local as libc::c_int != 0 && (set_scope != 0 || from == 8i32) {
        (*stcb).asoc.scope.loopback_scope = 1u8;
        (*stcb).asoc.scope.ipv4_local_scope = 1u8;
        (*stcb).asoc.scope.local_scope = 0u8;
        (*stcb).asoc.scope.site_scope = 1u8;
        addr_inscope = 1i32
    }
    (*net).failure_threshold = (*stcb).asoc.def_net_failure;
    (*net).pf_threshold = (*stcb).asoc.def_net_pf_threshold;
    if addr_inscope == 0i32 {
        (*net).dest_state = (0x1i32 | 0x80i32) as uint16_t
    } else if from == 8i32 {
        /* SCTP_ADDR_IS_CONFIRMED is passed by connect_x */
        (*net).dest_state = 0x1u16
    } else {
        (*net).dest_state = (0x1i32 | 0x200i32) as uint16_t
    }
    /* We set this to 0, the timer code knows that
     * this means its an initial value
     */
    (*net).rto_needed = 1u8;
    (*net).RTO = 0u32;
    (*net).RTO_measured = 0u8;
    (*stcb).asoc.numnets = (*stcb).asoc.numnets.wrapping_add(1);
    (*net).ref_count = 1i32;
    (*net).last_cwr_tsn = (*stcb).asoc.sending_seq.wrapping_sub(1u32);
    (*net).cwr_window_tsn = (*net).last_cwr_tsn;
    (*net).port = port;
    (*net).dscp = (*stcb).asoc.default_dscp;
    (*net).flowlabel = (*stcb).asoc.default_flowlabel;
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x4u64 == 0x4u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x4u64 == 0x4u64
    {
        (*net).dest_state = ((*net).dest_state as libc::c_int | 0x4i32) as uint16_t
    } else {
        (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x4i32)) as uint16_t
    }
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x1u64 == 0x1u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x1u64 == 0x1u64
    {
        (*net).dest_state = ((*net).dest_state as libc::c_int | 0x2i32) as uint16_t
    } else {
        (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x2i32)) as uint16_t
    }
    (*net).heart_beat_delay = (*stcb).asoc.heart_beat_delay;
    /* Init the timer structure */
    sctp_os_timer_init(&mut (*net).rxt_timer.timer);
    sctp_os_timer_init(&mut (*net).pmtu_timer.timer);
    sctp_os_timer_init(&mut (*net).hb_timer.timer);
    /* Now generate a route for this guy */
    /* SCTP_EMBEDDED_V6_SCOPE */
    sctp_userspace_rtalloc(&mut (*net).ro as *mut sctp_net_route as *mut sctp_route_t);
    (*net).src_addr_selected = 0u8;
    if (*net).mtu == 0u32 {
        if (*stcb).asoc.default_mtu > 0u32 {
            (*net).mtu = (*stcb).asoc.default_mtu;
            match (*net).ro._l_addr.sa.sa_family as libc::c_int {
                2 => {
                    (*net).mtu = ((*net).mtu as libc::c_ulong).wrapping_add(
                        (::std::mem::size_of::<ip>() as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong),
                    ) as uint32_t
                }
                10 => {
                    (*net).mtu = ((*net).mtu as libc::c_ulong).wrapping_add(
                        (::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong),
                    ) as uint32_t
                }
                123 => {
                    (*net).mtu = ((*net).mtu as libc::c_ulong)
                        .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                        as uint32_t
                }
                _ => {}
            }
            if (*net).port != 0 {
                (*net).mtu = ((*net).mtu).wrapping_add(::std::mem::size_of::<udphdr>() as uint32_t)
            }
        } else {
            match (*newaddr).sa_family as libc::c_int {
                2 => (*net).mtu = 1500u32,
                10 => (*net).mtu = 1280u32,
                123 => (*net).mtu = 1280u32,
                _ => {}
            }
        }
    }
    if (*net).port != 0 {
        (*net).mtu = ((*net).mtu).wrapping_sub(::std::mem::size_of::<udphdr>() as uint32_t)
    }
    if from == 1i32 {
        (*stcb).asoc.smallest_mtu = (*net).mtu
    }
    if (*stcb).asoc.smallest_mtu > (*net).mtu {
        sctp_pathmtu_adjustment(stcb, (*net).mtu as uint16_t);
    }
    /* SCTP_EMBEDDED_V6_SCOPE */
    /* JRS - Use the congestion control given in the CC module */
    if (*stcb)
        .asoc
        .cc_functions
        .sctp_set_initial_cc_param
        .is_some()
    {
        Some(
            (*stcb)
                .asoc
                .cc_functions
                .sctp_set_initial_cc_param
                .expect("non-null function pointer"),
        )
        .expect("non-null function pointer")(stcb, net);
    }
    /*
     * CMT: CUC algo - set find_pseudo_cumack to TRUE (1) at beginning
     * of assoc (2005/06/27, iyengar@cis.udel.edu)
     */
    (*net).find_pseudo_cumack = 1u8;
    (*net).find_rtx_pseudo_cumack = 1u8;
    if !netp.is_null() {
        *netp = net
    }
    netfirst = (*stcb).asoc.nets.tqh_first;
    if (*net).ro.ro_rt.is_null() {
        /* Since we have no route put it at the back */
        (*net).sctp_next.tqe_next = 0 as *mut sctp_nets;
        (*net).sctp_next.tqe_prev = (*stcb).asoc.nets.tqh_last;
        *(*stcb).asoc.nets.tqh_last = net;
        (*stcb).asoc.nets.tqh_last = &mut (*net).sctp_next.tqe_next
    } else if netfirst.is_null() {
        /* We are the first one in the pool. */
        (*net).sctp_next.tqe_next = (*stcb).asoc.nets.tqh_first;
        if !(*net).sctp_next.tqe_next.is_null() {
            (*(*stcb).asoc.nets.tqh_first).sctp_next.tqe_prev = &mut (*net).sctp_next.tqe_next
        } else {
            (*stcb).asoc.nets.tqh_last = &mut (*net).sctp_next.tqe_next
        }
        (*stcb).asoc.nets.tqh_first = net;
        (*net).sctp_next.tqe_prev = &mut (*stcb).asoc.nets.tqh_first
    } else if (*netfirst).ro.ro_rt.is_null() {
        /*
         * First one has NO route. Place this one ahead of the first
         * one.
         */
        (*net).sctp_next.tqe_next = (*stcb).asoc.nets.tqh_first;
        if !(*net).sctp_next.tqe_next.is_null() {
            (*(*stcb).asoc.nets.tqh_first).sctp_next.tqe_prev = &mut (*net).sctp_next.tqe_next
        } else {
            (*stcb).asoc.nets.tqh_last = &mut (*net).sctp_next.tqe_next
        }
        (*stcb).asoc.nets.tqh_first = net;
        (*net).sctp_next.tqe_prev = &mut (*stcb).asoc.nets.tqh_first
    } else if (*(*net).ro.ro_rt).rt_ifp != (*(*netfirst).ro.ro_rt).rt_ifp {
        /*
         * This one has a different interface than the one at the
         * top of the list. Place it ahead.
         */
        (*net).sctp_next.tqe_next = (*stcb).asoc.nets.tqh_first;
        if !(*net).sctp_next.tqe_next.is_null() {
            (*(*stcb).asoc.nets.tqh_first).sctp_next.tqe_prev = &mut (*net).sctp_next.tqe_next
        } else {
            (*stcb).asoc.nets.tqh_last = &mut (*net).sctp_next.tqe_next
        }
        (*stcb).asoc.nets.tqh_first = net;
        (*net).sctp_next.tqe_prev = &mut (*stcb).asoc.nets.tqh_first
    } else {
        loop {
            let mut netlook = 0 as *mut sctp_nets;
            netlook = (*netfirst).sctp_next.tqe_next;
            if netlook.is_null() {
                /* End of the list */
                (*net).sctp_next.tqe_next = 0 as *mut sctp_nets;
                (*net).sctp_next.tqe_prev = (*stcb).asoc.nets.tqh_last;
                *(*stcb).asoc.nets.tqh_last = net;
                (*stcb).asoc.nets.tqh_last = &mut (*net).sctp_next.tqe_next;
                break;
            } else if (*netlook).ro.ro_rt.is_null() {
                /* next one has NO route */
                (*net).sctp_next.tqe_prev = (*netfirst).sctp_next.tqe_prev;
                (*net).sctp_next.tqe_next = netfirst;
                *(*netfirst).sctp_next.tqe_prev = net;
                (*netfirst).sctp_next.tqe_prev = &mut (*net).sctp_next.tqe_next;
                break;
            } else if (*(*netlook).ro.ro_rt).rt_ifp != (*(*net).ro.ro_rt).rt_ifp {
                (*net).sctp_next.tqe_next = (*netlook).sctp_next.tqe_next;
                if !(*net).sctp_next.tqe_next.is_null() {
                    (*(*net).sctp_next.tqe_next).sctp_next.tqe_prev = &mut (*net).sctp_next.tqe_next
                } else {
                    (*stcb).asoc.nets.tqh_last = &mut (*net).sctp_next.tqe_next
                }
                (*netlook).sctp_next.tqe_next = net;
                (*net).sctp_next.tqe_prev = &mut (*netlook).sctp_next.tqe_next;
                break;
            } else {
                /* Shift forward */
                netfirst = netlook;
                if netlook.is_null() {
                    break;
                }
            }
        }
    }
    /* got to have a primary set */
    if (*stcb).asoc.primary_destination.is_null() {
        (*stcb).asoc.primary_destination = net
    } else if (*(*stcb).asoc.primary_destination).ro.ro_rt.is_null()
        && !(*net).ro.ro_rt.is_null()
        && (*net).dest_state as libc::c_int & 0x200i32 == 0i32
    {
        /* No route to current primary adopt new primary */
        (*stcb).asoc.primary_destination = net
    }
    /* Validate primary is first */
    net = (*stcb).asoc.nets.tqh_first;
    if net != (*stcb).asoc.primary_destination && !(*stcb).asoc.primary_destination.is_null() {
        /* first one on the list is NOT the primary
         * sctp_cmpaddr() is much more efficient if
         * the primary is the first on the list, make it
         * so.
         */
        if !(*(*stcb).asoc.primary_destination)
            .sctp_next
            .tqe_next
            .is_null()
        {
            (*(*(*stcb).asoc.primary_destination).sctp_next.tqe_next)
                .sctp_next
                .tqe_prev = (*(*stcb).asoc.primary_destination).sctp_next.tqe_prev
        } else {
            (*stcb).asoc.nets.tqh_last = (*(*stcb).asoc.primary_destination).sctp_next.tqe_prev
        }
        *(*(*stcb).asoc.primary_destination).sctp_next.tqe_prev =
            (*(*stcb).asoc.primary_destination).sctp_next.tqe_next;
        (*(*stcb).asoc.primary_destination).sctp_next.tqe_next = (*stcb).asoc.nets.tqh_first;
        if !(*(*stcb).asoc.primary_destination)
            .sctp_next
            .tqe_next
            .is_null()
        {
            (*(*stcb).asoc.nets.tqh_first).sctp_next.tqe_prev =
                &mut (*(*stcb).asoc.primary_destination).sctp_next.tqe_next
        } else {
            (*stcb).asoc.nets.tqh_last = &mut (*(*stcb).asoc.primary_destination).sctp_next.tqe_next
        }
        (*stcb).asoc.nets.tqh_first = (*stcb).asoc.primary_destination;
        (*(*stcb).asoc.primary_destination).sctp_next.tqe_prev = &mut (*stcb).asoc.nets.tqh_first
    }
    return 0i32;
}
unsafe extern "C" fn sctp_aloc_a_assoc_id(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
) -> uint32_t {
    let mut id = 0;
    let mut head = 0 as *mut sctpasochead;
    loop {
        let mut lstcb = 0 as *mut sctp_tcb;
        if (*inp).sctp_flags & 0x20000000u32 != 0 {
            /* TSNH */
            return 0u32;
        }
        /*
         * We don't allow assoc id to be one of SCTP_FUTURE_ASSOC,
         * SCTP_CURRENT_ASSOC and SCTP_ALL_ASSOC.
         */
        if (*inp).sctp_associd_counter <= 2u32 {
            (*inp).sctp_associd_counter = (2i32 + 1i32) as uint32_t
        }
        id = (*inp).sctp_associd_counter;
        (*inp).sctp_associd_counter = (*inp).sctp_associd_counter.wrapping_add(1);
        lstcb = sctp_findasoc_ep_asocid_locked(inp, id, 0i32);
        if lstcb.is_null() {
            break;
        }
    }
    head = &mut *(*inp)
        .sctp_asocidhash
        .offset((id as libc::c_ulong & (*inp).hashasocidmark) as isize)
        as *mut sctpasochead;
    (*stcb).sctp_tcbasocidhash.le_next = (*head).lh_first;
    if !(*stcb).sctp_tcbasocidhash.le_next.is_null() {
        (*(*head).lh_first).sctp_tcbasocidhash.le_prev = &mut (*stcb).sctp_tcbasocidhash.le_next
    }
    (*head).lh_first = stcb;
    (*stcb).sctp_tcbasocidhash.le_prev = &mut (*head).lh_first;
    (*stcb).asoc.in_asocid_hash = 1u8;
    return id;
}
/*
 * allocate an association and add it to the endpoint. The caller must be
 * careful to add all additional addresses once they are know right away or
 * else the assoc will be may experience a blackout scenario.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_aloc_assoc(
    mut inp: *mut sctp_inpcb,
    mut firstaddr: *mut sockaddr,
    mut error: *mut libc::c_int,
    mut override_tag: uint32_t,
    mut vrf_id: uint32_t,
    mut o_streams: uint16_t,
    mut port: uint16_t,
    mut p: *mut proc_0,
    mut initialize_auth_params: libc::c_int,
) -> *mut sctp_tcb {
    let mut stcb = 0 as *mut sctp_tcb;
    let mut asoc = 0 as *mut sctp_association;
    let mut head = 0 as *mut sctpasochead;
    let mut rport = 0;
    let mut err = 0;
    /*
     * Assumption made here: Caller has done a
     * sctp_findassociation_ep_addr(ep, addr's); to make sure the
     * address does not exist already.
     */
    if system_base_info.sctppcbinfo.ipi_count_asoc >= 40000u32 {
        /* Hit max assoc, sorry no more */
        *error = 105i32;
        return 0 as *mut sctp_tcb;
    }
    if firstaddr.is_null() {
        *error = 22i32;
        return 0 as *mut sctp_tcb;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    if (*inp).sctp_flags & 0x400000u32 != 0
        && ((*inp).sctp_features & 0x2000000u64 == 0u64 || (*inp).sctp_flags & 0x200000u32 != 0)
    {
        /*
         * If its in the TCP pool, its NOT allowed to create an
         * association. The parent listener needs to call
         * sctp_aloc_assoc.. or the one-2-many socket. If a peeled
         * off, or connected one does this.. its an error.
         */
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        *error = 22i32;
        return 0 as *mut sctp_tcb;
    }
    if (*inp).sctp_flags & 0x400000u32 != 0 || (*inp).sctp_flags & 0x2u32 != 0 {
        if (*inp).sctp_flags & 0x80000u32 != 0 || (*inp).sctp_flags & 0x100000u32 != 0 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            *error = 22i32;
            return 0 as *mut sctp_tcb;
        }
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x400000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Allocate an association for peer:\x00" as *const u8 as *const libc::c_char,
            );
        }
    }
    if !firstaddr.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x400000u32 != 0 {
            sctp_print_address(firstaddr);
        }
        match (*firstaddr).sa_family as libc::c_int {
            2 => {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x400000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Port:%d\n\x00" as *const u8 as *const libc::c_char,
                            ntohs((*(firstaddr as *mut sockaddr_in)).sin_port) as libc::c_int,
                        );
                    }
                }
            }
            10 => {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x400000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Port:%d\n\x00" as *const u8 as *const libc::c_char,
                            ntohs((*(firstaddr as *mut sockaddr_in6)).sin6_port) as libc::c_int,
                        );
                    }
                }
            }
            123 => {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x400000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"Port:%d\n\x00" as *const u8 as *const libc::c_char,
                            ntohs((*(firstaddr as *mut sockaddr_conn)).sconn_port) as libc::c_int,
                        );
                    }
                }
            }
            _ => {}
        }
    } else if system_base_info.sctpsysctl.sctp_debug_on & 0x400000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"None\n\x00" as *const u8 as *const libc::c_char,
            );
        }
    }
    /* SCTP_DEBUG */
    match (*firstaddr).sa_family as libc::c_int {
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            sin = firstaddr as *mut sockaddr_in;
            if ntohs((*sin).sin_port) as libc::c_int == 0i32
                || (*sin).sin_addr.s_addr == 0u32
                || (*sin).sin_addr.s_addr == 0xffffffffu32
                || ntohl((*sin).sin_addr.s_addr) & 0xf0000000u32 == 0xe0000000u32
            {
                /* Invalid address */
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *error = 22i32;
                return 0 as *mut sctp_tcb;
            }
            rport = (*sin).sin_port
        }
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 = firstaddr as *mut sockaddr_in6;
            if ntohs((*sin6).sin6_port) as libc::c_int == 0i32
                || ({
                    let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                        as libc::c_int
                }) != 0
                || *(&mut (*sin6).sin6_addr as *mut in6_addr as *const uint8_t).offset(0isize)
                    as libc::c_int
                    == 0xffi32
            {
                /* Invalid address */
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *error = 22i32;
                return 0 as *mut sctp_tcb;
            }
            rport = (*sin6).sin6_port
        }
        123 => {
            let mut sconn = 0 as *mut sockaddr_conn;
            sconn = firstaddr as *mut sockaddr_conn;
            if ntohs((*sconn).sconn_port) as libc::c_int == 0i32 || (*sconn).sconn_addr.is_null() {
                /* Invalid address */
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *error = 22i32;
                return 0 as *mut sctp_tcb;
            }
            rport = (*sconn).sconn_port
        }
        _ => {
            /* not supported family type */
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            *error = 22i32;
            return 0 as *mut sctp_tcb;
        }
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    if (*inp).sctp_flags & 0x10u32 != 0 {
        /*
         * If you have not performed a bind, then we need to do the
         * ephemeral bind for you.
         */
        err = sctp_inpcb_bind(
            (*inp).sctp_socket,
            0 as *mut sockaddr,
            0 as *mut sctp_ifa,
            p,
        );
        if err != 0 {
            /* bind error, probably perm */
            *error = err;
            return 0 as *mut sctp_tcb;
        }
    }
    stcb = malloc(system_base_info.sctppcbinfo.ipi_zone_asoc) as *mut sctp_tcb;
    if stcb.is_null() {
        /* out of memory? */
        *error = 12i32;
        return 0 as *mut sctp_tcb;
    }
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_asoc, 1u32);
    memset(
        stcb as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_tcb>() as libc::c_ulong,
    );
    asoc = &mut (*stcb).asoc;
    pthread_mutex_init(&mut (*stcb).tcb_mtx, &mut system_base_info.mtx_attr);
    pthread_mutex_init(&mut (*stcb).tcb_send_mtx, &mut system_base_info.mtx_attr);
    (*stcb).rport = rport;
    /* setup back pointer's */
    (*stcb).sctp_ep = inp;
    (*stcb).sctp_socket = (*inp).sctp_socket;
    err = sctp_init_asoc(inp, stcb, override_tag, vrf_id, o_streams);
    if err != 0 {
        /* failed */
        pthread_mutex_destroy(&mut (*stcb).tcb_mtx);
        pthread_mutex_destroy(&mut (*stcb).tcb_send_mtx);
        free(stcb as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_asoc, 1u32);
        *error = err;
        return 0 as *mut sctp_tcb;
    }
    /* and the port */
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    if (*inp).sctp_flags & (0x10000000i32 | 0x20000000i32) as libc::c_uint != 0 {
        /* inpcb freed while alloc going on */
        pthread_mutex_destroy(&mut (*stcb).tcb_mtx);
        pthread_mutex_destroy(&mut (*stcb).tcb_send_mtx);
        free(stcb as *mut libc::c_void);
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_asoc, 1u32);
        *error = 22i32;
        return 0 as *mut sctp_tcb;
    }
    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
    (*asoc).assoc_id = sctp_aloc_a_assoc_id(inp, stcb);
    /* now that my_vtag is set, add it to the hash */
    head = &mut *system_base_info.sctppcbinfo.sctp_asochash.offset(
        ((*stcb).asoc.my_vtag as libc::c_ulong & system_base_info.sctppcbinfo.hashasocmark)
            as isize,
    ) as *mut sctpasochead;
    /* put it in the bucket in the vtag hash of assoc's for the system */
    (*stcb).sctp_asocs.le_next = (*head).lh_first;
    if !(*stcb).sctp_asocs.le_next.is_null() {
        (*(*head).lh_first).sctp_asocs.le_prev = &mut (*stcb).sctp_asocs.le_next
    }
    (*head).lh_first = stcb;
    (*stcb).sctp_asocs.le_prev = &mut (*head).lh_first;
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    err = sctp_add_remote_addr(stcb, firstaddr, 0 as *mut *mut sctp_nets, port, 1i32, 1i32);
    if err != 0 {
        /* failure.. memory error? */
        if !(*asoc).strmout.is_null() {
            free((*asoc).strmout as *mut libc::c_void);
            (*asoc).strmout = 0 as *mut sctp_stream_out
        }
        if !(*asoc).mapping_array.is_null() {
            free((*asoc).mapping_array as *mut libc::c_void);
            (*asoc).mapping_array = 0 as *mut uint8_t
        }
        if !(*asoc).nr_mapping_array.is_null() {
            free((*asoc).nr_mapping_array as *mut libc::c_void);
            (*asoc).nr_mapping_array = 0 as *mut uint8_t
        }
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_asoc, 1u32);
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        pthread_mutex_destroy(&mut (*stcb).tcb_mtx);
        pthread_mutex_destroy(&mut (*stcb).tcb_send_mtx);
        if !(*stcb).sctp_tcbasocidhash.le_next.is_null() {
            (*(*stcb).sctp_tcbasocidhash.le_next)
                .sctp_tcbasocidhash
                .le_prev = (*stcb).sctp_tcbasocidhash.le_prev
        }
        *(*stcb).sctp_tcbasocidhash.le_prev = (*stcb).sctp_tcbasocidhash.le_next;
        free(stcb as *mut libc::c_void);
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        *error = 105i32;
        return 0 as *mut sctp_tcb;
    }
    /* Init all the timers */
    sctp_os_timer_init(&mut (*asoc).dack_timer.timer);
    sctp_os_timer_init(&mut (*asoc).strreset_timer.timer);
    sctp_os_timer_init(&mut (*asoc).asconf_timer.timer);
    sctp_os_timer_init(&mut (*asoc).shut_guard_timer.timer);
    sctp_os_timer_init(&mut (*asoc).autoclose_timer.timer);
    sctp_os_timer_init(&mut (*asoc).delayed_event_timer.timer);
    sctp_os_timer_init(&mut (*asoc).delete_prim_timer.timer);
    (*stcb).sctp_tcblist.le_next = (*inp).sctp_asoc_list.lh_first;
    if !(*stcb).sctp_tcblist.le_next.is_null() {
        (*(*inp).sctp_asoc_list.lh_first).sctp_tcblist.le_prev = &mut (*stcb).sctp_tcblist.le_next
    }
    (*inp).sctp_asoc_list.lh_first = stcb;
    (*stcb).sctp_tcblist.le_prev = &mut (*inp).sctp_asoc_list.lh_first;
    /* now file the port under the hash as well */
    if !(*inp).sctp_tcbhash.is_null() {
        head = &mut *(*inp)
            .sctp_tcbhash
            .offset(((*stcb).rport as libc::c_ulong & (*inp).sctp_hashmark) as isize)
            as *mut sctpasochead;
        (*stcb).sctp_tcbhash.le_next = (*head).lh_first;
        if !(*stcb).sctp_tcbhash.le_next.is_null() {
            (*(*head).lh_first).sctp_tcbhash.le_prev = &mut (*stcb).sctp_tcbhash.le_next
        }
        (*head).lh_first = stcb;
        (*stcb).sctp_tcbhash.le_prev = &mut (*head).lh_first
    }
    if initialize_auth_params == 1i32 {
        sctp_initialize_auth_params(inp, stcb);
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Association %p now allocated\n\x00" as *const u8 as *const libc::c_char,
                stcb as *mut libc::c_void,
            );
        }
    }
    return stcb;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_remove_net(mut stcb: *mut sctp_tcb, mut net: *mut sctp_nets) {
    let mut asoc = 0 as *mut sctp_association;
    asoc = &mut (*stcb).asoc;
    (*asoc).numnets = (*asoc).numnets.wrapping_sub(1);
    if !(*net).sctp_next.tqe_next.is_null() {
        (*(*net).sctp_next.tqe_next).sctp_next.tqe_prev = (*net).sctp_next.tqe_prev
    } else {
        (*asoc).nets.tqh_last = (*net).sctp_next.tqe_prev
    }
    *(*net).sctp_next.tqe_prev = (*net).sctp_next.tqe_next;
    if net == (*asoc).primary_destination {
        let mut lnet = 0 as *mut sctp_nets;
        lnet = (*asoc).nets.tqh_first;
        /* Mobility adaptation
          Ideally, if deleted destination is the primary, it becomes
          a fast retransmission trigger by the subsequent SET PRIMARY.
          (by micchie)
        */
        if (*(*stcb).sctp_ep).sctp_mobility_features & 0x1u32 != 0
            || (*(*stcb).sctp_ep).sctp_mobility_features & 0x2u32 != 0
        {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"remove_net: primary dst is deleting\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            if !(*asoc).deleted_primary.is_null() {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"remove_net: deleted primary may be already stored\n\x00" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
            } else {
                (*asoc).deleted_primary = net;
                ::std::intrinsics::atomic_xadd(&mut (*net).ref_count, 1i32);
                memset(
                    &mut (*net).lastsa as *mut libc::c_int as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<libc::c_int>() as libc::c_ulong,
                );
                memset(
                    &mut (*net).lastsv as *mut libc::c_int as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<libc::c_int>() as libc::c_ulong,
                );
                (*(*stcb).sctp_ep).sctp_mobility_features |= 0x4u32;
                sctp_timer_start(18i32, (*stcb).sctp_ep, stcb, 0 as *mut sctp_nets);
            }
        }
        /* Try to find a confirmed primary */
        (*asoc).primary_destination = sctp_find_alternate_net(stcb, lnet, 0i32)
    }
    if net == (*asoc).last_data_chunk_from {
        /* Reset primary */
        (*asoc).last_data_chunk_from = (*asoc).nets.tqh_first
    }
    if net == (*asoc).last_control_chunk_from {
        /* Clear net */
        (*asoc).last_control_chunk_from = 0 as *mut sctp_nets
    }
    if net == (*stcb).asoc.alternate {
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
                    ((*(*stcb).asoc.alternate).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                free((*stcb).asoc.alternate as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                    1u32,
                );
            }
        }
        (*stcb).asoc.alternate = 0 as *mut sctp_nets
    }
    if !net.is_null() {
        if ::std::intrinsics::atomic_xadd(&mut (*net).ref_count as *mut libc::c_int, -(1i32))
            == 1i32
        {
            sctp_os_timer_stop(&mut (*net).rxt_timer.timer);
            sctp_os_timer_stop(&mut (*net).pmtu_timer.timer);
            sctp_os_timer_stop(&mut (*net).hb_timer.timer);
            if !(*net).ro.ro_rt.is_null() {
                if (*(*net).ro.ro_rt).rt_refcnt <= 1i64 {
                    sctp_userspace_rtfree((*net).ro.ro_rt);
                } else {
                    (*(*net).ro.ro_rt).rt_refcnt -= 1
                }
                (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t
            }
            if (*net).src_addr_selected != 0 {
                sctp_free_ifa((*net).ro._s_addr);
                (*net).ro._s_addr = 0 as *mut sctp_ifa
            }
            (*net).src_addr_selected = 0u8;
            (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
            free(net as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_raddr, 1u32);
        }
    };
}
/*
 * remove a remote endpoint address from an association, it will fail if the
 * address does not exist.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_del_remote_addr(
    mut stcb: *mut sctp_tcb,
    mut remaddr: *mut sockaddr,
) -> libc::c_int {
    let mut asoc = 0 as *mut sctp_association;
    let mut net = 0 as *mut sctp_nets;
    let mut nnet = 0 as *mut sctp_nets;
    asoc = &mut (*stcb).asoc;
    /* locate the address */
    net = (*asoc).nets.tqh_first;
    while !net.is_null() && {
        nnet = (*net).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !((*net).ro._l_addr.sa.sa_family as libc::c_int != (*remaddr).sa_family as libc::c_int) {
            if sctp_cmpaddr(
                &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr,
                remaddr,
            ) != 0
            {
                /* we found the guy */
                if (*asoc).numnets < 2u32 {
                    /* Must have at LEAST two remote addresses */
                    return -(1i32);
                } else {
                    sctp_remove_net(stcb, net);
                    return 0i32;
                }
            }
        }
        net = nnet
    }
    /* not found. */
    return -(2i32);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_delete_from_timewait(
    mut tag: uint32_t,
    mut lport: uint16_t,
    mut rport: uint16_t,
) {
    let mut chain = 0 as *mut sctpvtaghead;
    let mut twait_block = 0 as *mut sctp_tagblock;
    chain = &mut *system_base_info
        .sctppcbinfo
        .vtag_timewait
        .as_mut_ptr()
        .offset(tag.wrapping_rem(32u32) as isize) as *mut sctpvtaghead;
    twait_block = (*chain).lh_first;
    while !twait_block.is_null() {
        let mut found = 0i32;
        let mut i = 0;
        i = 0i32;
        while i < 15i32 {
            if (*twait_block).vtag_block[i as usize].v_tag == tag
                && (*twait_block).vtag_block[i as usize].lport as libc::c_int
                    == lport as libc::c_int
                && (*twait_block).vtag_block[i as usize].rport as libc::c_int
                    == rport as libc::c_int
            {
                (*twait_block).vtag_block[i as usize].tv_sec_at_expire = 0u32;
                (*twait_block).vtag_block[i as usize].v_tag = 0u32;
                (*twait_block).vtag_block[i as usize].lport = 0u16;
                (*twait_block).vtag_block[i as usize].rport = 0u16;
                found = 1i32;
                break;
            } else {
                i += 1
            }
        }
        if found != 0 {
            break;
        }
        twait_block = (*twait_block).sctp_nxt_tagblock.le_next
    }
}
/*-
 * For this call ep_addr, the to is the destination endpoint address of the
 * peer (relative to outbound). The from field is only used if the TCP model
 * is enabled and helps distingush amongst the subset bound (non-boundall).
 * The TCP model MAY change the actual ep field, this is why it is passed.
 */
/* proc will be NULL for __Userspace__ */
#[no_mangle]
pub unsafe extern "C" fn sctp_is_in_timewait(
    mut tag: uint32_t,
    mut lport: uint16_t,
    mut rport: uint16_t,
) -> libc::c_int {
    let mut chain = 0 as *mut sctpvtaghead;
    let mut twait_block = 0 as *mut sctp_tagblock;
    let mut found = 0i32;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    chain = &mut *system_base_info
        .sctppcbinfo
        .vtag_timewait
        .as_mut_ptr()
        .offset(tag.wrapping_rem(32u32) as isize) as *mut sctpvtaghead;
    twait_block = (*chain).lh_first;
    while !twait_block.is_null() {
        let mut i = 0;
        i = 0i32;
        while i < 15i32 {
            if (*twait_block).vtag_block[i as usize].v_tag == tag
                && (*twait_block).vtag_block[i as usize].lport as libc::c_int
                    == lport as libc::c_int
                && (*twait_block).vtag_block[i as usize].rport as libc::c_int
                    == rport as libc::c_int
            {
                found = 1i32;
                break;
            } else {
                i += 1
            }
        }
        if found != 0 {
            break;
        }
        twait_block = (*twait_block).sctp_nxt_tagblock.le_next
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    return found;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_add_vtag_to_timewait(
    mut tag: uint32_t,
    mut time: uint32_t,
    mut lport: uint16_t,
    mut rport: uint16_t,
) {
    let mut chain = 0 as *mut sctpvtaghead;
    let mut twait_block = 0 as *mut sctp_tagblock;
    let mut now = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut set = 0;
    if time == 0u32 {
        /* Its disabled */
        return;
    }
    gettimeofday(&mut now, 0 as *mut timezone);
    chain = &mut *system_base_info
        .sctppcbinfo
        .vtag_timewait
        .as_mut_ptr()
        .offset(tag.wrapping_rem(32u32) as isize) as *mut sctpvtaghead;
    set = 0i32;
    twait_block = (*chain).lh_first;
    while !twait_block.is_null() {
        for i in 0i32..15i32 {
            if (*twait_block).vtag_block[i as usize].v_tag == 0u32 && set == 0 {
                (*twait_block).vtag_block[i as usize].tv_sec_at_expire =
                    (now.tv_sec + time as libc::c_long) as uint32_t;
                (*twait_block).vtag_block[i as usize].v_tag = tag;
                (*twait_block).vtag_block[i as usize].lport = lport;
                (*twait_block).vtag_block[i as usize].rport = rport;
                set = 1i32
            } else if (*twait_block).vtag_block[i as usize].v_tag != 0
                && ((*twait_block).vtag_block[i as usize].tv_sec_at_expire as libc::c_long)
                    < now.tv_sec
            {
                /* Audit expires this guy */
                (*twait_block).vtag_block[i as usize].tv_sec_at_expire = 0u32;
                (*twait_block).vtag_block[i as usize].v_tag = 0u32;
                (*twait_block).vtag_block[i as usize].lport = 0u16;
                (*twait_block).vtag_block[i as usize].rport = 0u16;
                if set == 0i32 {
                    /* Reuse it for my new tag */
                    (*twait_block).vtag_block[i as usize].tv_sec_at_expire =
                        (now.tv_sec + time as libc::c_long) as uint32_t;
                    (*twait_block).vtag_block[i as usize].v_tag = tag;
                    (*twait_block).vtag_block[i as usize].lport = lport;
                    (*twait_block).vtag_block[i as usize].rport = rport;
                    set = 1i32
                }
            }
        }
        if set != 0 {
            break;
        }
        twait_block = (*twait_block).sctp_nxt_tagblock.le_next
    }
    /* Need to add a new block to chain */
    if set == 0 {
        twait_block =
            malloc(::std::mem::size_of::<sctp_tagblock>() as libc::c_ulong) as *mut sctp_tagblock;
        if 0x1i32 & 0x100i32 != 0 {
            memset(
                twait_block as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sctp_tagblock>() as libc::c_ulong,
            );
        }
        if twait_block.is_null() {
            return;
        }
        memset(
            twait_block as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_tagblock>() as libc::c_ulong,
        );
        (*twait_block).sctp_nxt_tagblock.le_next = (*chain).lh_first;
        if !(*twait_block).sctp_nxt_tagblock.le_next.is_null() {
            (*(*chain).lh_first).sctp_nxt_tagblock.le_prev =
                &mut (*twait_block).sctp_nxt_tagblock.le_next
        }
        (*chain).lh_first = twait_block;
        (*twait_block).sctp_nxt_tagblock.le_prev = &mut (*chain).lh_first;
        (*twait_block).vtag_block[0usize].tv_sec_at_expire =
            (now.tv_sec + time as libc::c_long) as uint32_t;
        (*twait_block).vtag_block[0usize].v_tag = tag;
        (*twait_block).vtag_block[0usize].lport = lport;
        (*twait_block).vtag_block[0usize].rport = rport
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_clean_up_stream(mut stcb: *mut sctp_tcb, mut rh: *mut sctp_readhead) {
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut ncontrol = 0 as *mut sctp_queued_to_read;
    control = (*rh).tqh_first;
    while !control.is_null() && {
        ncontrol = (*control).next_instrm.tqe_next;
        (1i32) != 0
    } {
        let mut chk = 0 as *mut sctp_tmit_chunk;
        let mut nchk = 0 as *mut sctp_tmit_chunk;
        if !(*control).next_instrm.tqe_next.is_null() {
            (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                (*control).next_instrm.tqe_prev
        } else {
            (*rh).tqh_last = (*control).next_instrm.tqe_prev
        }
        *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
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
        }
        /* Reassembly free? */
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
                (*chk).data = 0 as *mut mbuf
            }
            if (*chk).holds_key_ref != 0 {
                sctp_auth_key_release(stcb, (*chk).auth_keyid, 1i32);
            }
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
            free(chk as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
            chk = nchk
            /*sa_ignore FREED_MEMORY*/
        }
        /*
         * We don't free the address here
         * since all the net's were freed
         * above.
         */
        if (*control).on_read_q as libc::c_int == 0i32 {
            free(control as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
        }
        control = ncontrol
    }
}
/*-
 * Free the association after un-hashing the remote port. This
 * function ALWAYS returns holding NO LOCK on the stcb. It DOES
 * expect that the input to this function IS a locked TCB.
 * It will return 0, if it did NOT destroy the association (instead
 * it unlocks it. It will return NON-zero if it either destroyed the
 * association OR the association is already destroyed.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_free_assoc(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut from_inpcbfree: libc::c_int,
    mut from_location: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut asoc = 0 as *mut sctp_association;
    let mut net = 0 as *mut sctp_nets;
    let mut nnet = 0 as *mut sctp_nets;
    let mut laddr = 0 as *mut sctp_laddr;
    let mut naddr = 0 as *mut sctp_laddr;
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut nchk = 0 as *mut sctp_tmit_chunk;
    let mut aparam = 0 as *mut sctp_asconf_addr;
    let mut naparam = 0 as *mut sctp_asconf_addr;
    let mut aack = 0 as *mut sctp_asconf_ack;
    let mut naack = 0 as *mut sctp_asconf_ack;
    let mut strrst = 0 as *mut sctp_stream_reset_list;
    let mut nstrrst = 0 as *mut sctp_stream_reset_list;
    let mut sq = 0 as *mut sctp_queued_to_read;
    let mut nsq = 0 as *mut sctp_queued_to_read;
    let mut shared_key = 0 as *mut sctp_sharedkey_t;
    let mut nshared_key = 0 as *mut sctp_sharedkey_t;
    let mut so = 0 as *mut socket;
    /* first, lets purge the entry from the hash table. */
    if (*stcb).asoc.state == 0i32 {
        /* there is no asoc, really TSNH :-0 */
        return 1i32;
    }
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
                    ((*(*stcb).asoc.alternate).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                free((*stcb).asoc.alternate as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                    1u32,
                );
            }
        }
        (*stcb).asoc.alternate = 0 as *mut sctp_nets
    }
    /* TEMP: moved to below */
    /* TEMP CODE */
    if (*stcb).freed_from_where == 0i32 {
        /* Only record the first place free happened from */
        (*stcb).freed_from_where = from_location
    }
    /* TEMP CODE */
    asoc = &mut (*stcb).asoc;
    if (*inp).sctp_flags & 0x20000000u32 != 0 || (*inp).sctp_flags & 0x10000000u32 != 0 {
        /* nothing around */
        so = 0 as *mut socket
    } else {
        so = (*inp).sctp_socket
    }
    /*
     * We used timer based freeing if a reader or writer is in the way.
     * So we first check if we are actually being called from a timer,
     * if so we abort early if a reader or writer is still in the way.
     */
    if (*stcb).asoc.state & 0x200i32 != 0 && from_inpcbfree == 0i32 {
        /*
         * is it the timer driving us? if so are the reader/writers
         * gone?
         */
        if (*stcb).asoc.refcnt != 0 {
            /* nope, reader or writer in the way */
            sctp_timer_start(16i32, inp, stcb, 0 as *mut sctp_nets);
            /* no asoc destroyed */
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            return 0i32;
        }
    }
    /* now clean up any other timers */
    sctp_os_timer_stop(&mut (*asoc).dack_timer.timer);
    (*asoc).dack_timer.self_0 = 0 as *mut libc::c_void;
    sctp_os_timer_stop(&mut (*asoc).strreset_timer.timer);
    /*-
     * For stream reset we don't blast this unless
     * it is a str-reset timer, it might be the
     * free-asoc timer which we DON'T want to
     * disturb.
     */
    if (*asoc).strreset_timer.type_0 == 14i32 {
        (*asoc).strreset_timer.self_0 = 0 as *mut libc::c_void
    }
    sctp_os_timer_stop(&mut (*asoc).asconf_timer.timer);
    (*asoc).asconf_timer.self_0 = 0 as *mut libc::c_void;
    sctp_os_timer_stop(&mut (*asoc).autoclose_timer.timer);
    (*asoc).autoclose_timer.self_0 = 0 as *mut libc::c_void;
    sctp_os_timer_stop(&mut (*asoc).shut_guard_timer.timer);
    (*asoc).shut_guard_timer.self_0 = 0 as *mut libc::c_void;
    sctp_os_timer_stop(&mut (*asoc).delayed_event_timer.timer);
    (*asoc).delayed_event_timer.self_0 = 0 as *mut libc::c_void;
    /* Mobility adaptation */
    sctp_os_timer_stop(&mut (*asoc).delete_prim_timer.timer);
    (*asoc).delete_prim_timer.self_0 = 0 as *mut libc::c_void;
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        sctp_os_timer_stop(&mut (*net).rxt_timer.timer);
        (*net).rxt_timer.self_0 = 0 as *mut libc::c_void;
        sctp_os_timer_stop(&mut (*net).pmtu_timer.timer);
        (*net).pmtu_timer.self_0 = 0 as *mut libc::c_void;
        sctp_os_timer_stop(&mut (*net).hb_timer.timer);
        (*net).hb_timer.self_0 = 0 as *mut libc::c_void;
        net = (*net).sctp_next.tqe_next
    }
    /* Now the read queue needs to be cleaned up (only once) */
    if (*stcb).asoc.state & 0x200i32 == 0i32 {
        sctp_add_substate(stcb, 0x200i32);
        pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
        sq = (*inp).read_queue.tqh_first;
        while !sq.is_null() {
            if (*sq).stcb == stcb {
                (*sq).do_not_ref_stcb = 1u8;
                (*sq).sinfo_cumtsn = (*stcb).asoc.cumulative_tsn;
                /* If there is no end, there never
                 * will be now.
                 */
                if (*sq).end_added as libc::c_int == 0i32 {
                    /* Held for PD-API clear that. */
                    (*sq).pdapi_aborted = 1u8;
                    (*sq).held_length = 0u32;
                    if (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x20000u64 == 0x20000u64
                        || stcb.is_null()
                            && !inp.is_null()
                            && (*inp).sctp_features & 0x20000u64 == 0x20000u64)
                        && !so.is_null()
                    {
                        let mut strseq = 0;
                        (*stcb).asoc.control_pdapi = sq;
                        strseq = (((*sq).sinfo_stream as libc::c_int) << 16i32) as libc::c_uint
                            | (*sq).mid & 0xffffu32;
                        sctp_ulp_notify(
                            15u32,
                            stcb,
                            0x1u32,
                            &mut strseq as *mut uint32_t as *mut libc::c_void,
                            1i32,
                        );
                        (*stcb).asoc.control_pdapi = 0 as *mut sctp_queued_to_read
                    }
                }
                /* Add an end to wake them */
                (*sq).end_added = 1u8
            }
            sq = (*sq).next.tqe_next
        }
        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
        if !(*stcb).block_entry.is_null() {
            (*(*stcb).block_entry).error = 104i32;
            (*stcb).block_entry = 0 as *mut sctp_block_entry
        }
    }
    if (*stcb).asoc.refcnt != 0 || (*stcb).asoc.state & 0x1000i32 != 0 {
        /* Someone holds a reference OR the socket is unaccepted yet.
        	*/
        if (*stcb).asoc.refcnt != 0
            || (*inp).sctp_flags & 0x20000000u32 != 0
            || (*inp).sctp_flags & 0x10000000u32 != 0
        {
            (*stcb).asoc.state &= !(0x1000i32);
            sctp_timer_start(16i32, inp, stcb, 0 as *mut sctp_nets);
        }
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        if (*inp).sctp_flags & 0x20000000u32 != 0 || (*inp).sctp_flags & 0x10000000u32 != 0 {
            /* nothing around */
            so = 0 as *mut socket
        }
        if !so.is_null() {
            /* Wake any reader/writers */
            if (*inp).sctp_flags & 0x800000u32 != 0 {
                (*inp).sctp_flags |= 0x2000000u32
            } else {
                pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
                if (*so).so_rcv.sb_flags as libc::c_int
                    & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                    != 0i32
                {
                    sowakeup(so, &mut (*so).so_rcv);
                } else {
                    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
                }
            }
            if (*inp).sctp_flags & 0x800000u32 != 0 {
                (*inp).sctp_flags |= 0x1000000u32
            } else {
                pthread_mutex_lock(&mut (*so).so_snd.sb_mtx);
                if (*so).so_snd.sb_flags as libc::c_int
                    & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                    != 0i32
                {
                    sowakeup(so, &mut (*so).so_snd);
                } else {
                    pthread_mutex_unlock(&mut (*so).so_snd.sb_mtx);
                }
            }
        }
        /* no asoc destroyed */
        return 0i32;
    }
    /* When I reach here, no others want
     * to kill the assoc yet.. and I own
     * the lock. Now its possible an abort
     * comes in when I do the lock exchange
     * below to grab all the locks to do
     * the final take out. to prevent this
     * we increment the count, which will
     * start a timer and blow out above thus
     * assuring us that we hold exclusive
     * killing of the asoc. Note that
     * after getting back the TCB lock
     * we will go ahead and increment the
     * counter back up and stop any timer
     * a passing stranger may have started :-S
     */
    if from_inpcbfree == 0i32 {
        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
    }
    /* Double check the GONE flag */
    if (*inp).sctp_flags & 0x20000000u32 != 0 || (*inp).sctp_flags & 0x10000000u32 != 0 {
        /* nothing around */
        so = 0 as *mut socket
    }
    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
        /*
         * For TCP type we need special handling when we are
         * connected. We also include the peel'ed off ones to.
         */
        if (*inp).sctp_flags & 0x200000u32 != 0 {
            (*inp).sctp_flags &= !(0x200000i32) as libc::c_uint;
            (*inp).sctp_flags |= 0x80000u32;
            if !so.is_null() {
                pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
                (*so).so_state = ((*so).so_state as libc::c_int
                    & !(0x4i32 | 0x8i32 | 0x400i32 | 0x2i32))
                    as libc::c_short;
                (*so).so_state = ((*so).so_state as libc::c_int | 0x2000i32) as libc::c_short;
                socantrcvmore_locked(so);
                socantsendmore(so);
                if (*inp).sctp_flags & 0x800000u32 != 0 {
                    (*inp).sctp_flags |= 0x1000000u32
                } else {
                    pthread_mutex_lock(&mut (*so).so_snd.sb_mtx);
                    if (*so).so_snd.sb_flags as libc::c_int
                        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                        != 0i32
                    {
                        sowakeup(so, &mut (*so).so_snd);
                    } else {
                        pthread_mutex_unlock(&mut (*so).so_snd.sb_mtx);
                    }
                }
                if (*inp).sctp_flags & 0x800000u32 != 0 {
                    (*inp).sctp_flags |= 0x2000000u32
                } else {
                    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
                    if (*so).so_rcv.sb_flags as libc::c_int
                        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                        != 0i32
                    {
                        sowakeup(so, &mut (*so).so_rcv);
                    } else {
                        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
                    }
                }
                wakeup(
                    &mut (*so).so_timeo as *mut libc::c_short as *mut libc::c_void,
                    so,
                );
            }
        }
    }
    /* Make it invalid too, that way if its
     * about to run it will abort and return.
     */
    /* re-increment the lock */
    if from_inpcbfree == 0i32 {
        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, -(1i32) as uint32_t);
    }
    if (*stcb).asoc.refcnt != 0 {
        (*stcb).asoc.state &= !(0x1000i32);
        sctp_timer_start(16i32, inp, stcb, 0 as *mut sctp_nets);
        if from_inpcbfree == 0i32 {
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
        }
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        return 0i32;
    }
    (*asoc).state = 0i32;
    if !(*inp).sctp_tcbhash.is_null() {
        if !(*stcb).sctp_tcbhash.le_next.is_null() {
            (*(*stcb).sctp_tcbhash.le_next).sctp_tcbhash.le_prev = (*stcb).sctp_tcbhash.le_prev
        }
        *(*stcb).sctp_tcbhash.le_prev = (*stcb).sctp_tcbhash.le_next
    }
    if (*stcb).asoc.in_asocid_hash != 0 {
        if !(*stcb).sctp_tcbasocidhash.le_next.is_null() {
            (*(*stcb).sctp_tcbasocidhash.le_next)
                .sctp_tcbasocidhash
                .le_prev = (*stcb).sctp_tcbasocidhash.le_prev
        }
        *(*stcb).sctp_tcbasocidhash.le_prev = (*stcb).sctp_tcbasocidhash.le_next
    }
    /* Now lets remove it from the list of ALL associations in the EP */
    if !(*stcb).sctp_tcblist.le_next.is_null() {
        (*(*stcb).sctp_tcblist.le_next).sctp_tcblist.le_prev = (*stcb).sctp_tcblist.le_prev
    }
    *(*stcb).sctp_tcblist.le_prev = (*stcb).sctp_tcblist.le_next;
    if from_inpcbfree == 0i32 {
        ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
    }
    /* pull from vtag hash */
    if !(*stcb).sctp_asocs.le_next.is_null() {
        (*(*stcb).sctp_asocs.le_next).sctp_asocs.le_prev = (*stcb).sctp_asocs.le_prev
    }
    *(*stcb).sctp_asocs.le_prev = (*stcb).sctp_asocs.le_next;
    sctp_add_vtag_to_timewait(
        (*asoc).my_vtag,
        system_base_info.sctpsysctl.sctp_vtag_time_wait,
        (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport,
        (*stcb).rport,
    );
    /* Now restop the timers to be sure
     * this is paranoia at is finest!
     */
    sctp_os_timer_stop(&mut (*asoc).strreset_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).dack_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).strreset_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).asconf_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).shut_guard_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).autoclose_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).delayed_event_timer.timer);
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        sctp_os_timer_stop(&mut (*net).rxt_timer.timer);
        sctp_os_timer_stop(&mut (*net).pmtu_timer.timer);
        sctp_os_timer_stop(&mut (*net).hb_timer.timer);
        net = (*net).sctp_next.tqe_next
    }
    (*asoc).strreset_timer.type_0 = 0i32;
    /*
     * The chunk lists and such SHOULD be empty but we check them just
     * in case.
     */
    /* anything on the wheel needs to be removed */
    pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);

    for i in 0i32..(*asoc).streamoutcnt as libc::c_int {
        let mut sp = 0 as *mut sctp_stream_queue_pending;
        let mut nsp = 0 as *mut sctp_stream_queue_pending;
        let mut outs = 0 as *mut sctp_stream_out;

        outs = &mut *(*asoc).strmout.offset(i as isize) as *mut sctp_stream_out;
        /* now clean up any chunks here */
        sp = (*outs).outqueue.tqh_first;

        while !sp.is_null() && {
            nsp = (*sp).next.tqe_next;
            (1i32) != 0
        } {
            ::std::intrinsics::atomic_xsub(&mut (*asoc).stream_queue_cnt, 1u32);
            if !(*sp).next.tqe_next.is_null() {
                (*(*sp).next.tqe_next).next.tqe_prev = (*sp).next.tqe_prev
            } else {
                (*outs).outqueue.tqh_last = (*sp).next.tqe_prev
            }
            *(*sp).next.tqe_prev = (*sp).next.tqe_next;
            (*stcb)
                .asoc
                .ss_functions
                .sctp_ss_remove_from_stream
                .expect("non-null function pointer")(stcb, asoc, outs, sp, 1i32);
            if !(*sp).data.is_null() {
                if (*asoc).total_output_queue_size >= (*sp).length {
                    ::std::intrinsics::atomic_xsub(
                        &mut (*asoc).total_output_queue_size,
                        (*sp).length,
                    );
                } else {
                    (*asoc).total_output_queue_size = 0u32
                }
                if !(*stcb).sctp_socket.is_null()
                    && ((*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
                        || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0)
                {
                    if (*(*stcb).sctp_socket).so_snd.sb_cc >= (*sp).length {
                        ::std::intrinsics::atomic_xsub(
                            &mut (*(*stcb).sctp_socket).so_snd.sb_cc,
                            (*sp).length,
                        );
                    } else {
                        (*(*stcb).sctp_socket).so_snd.sb_cc = 0u32
                    }
                }
            }
            if !(*sp).data.is_null() {
                if !so.is_null() {
                    /* Still an open socket - report */
                    sctp_ulp_notify(7u32, stcb, 0u32, sp as *mut libc::c_void, 1i32);
                }
                if !(*sp).data.is_null() {
                    m_freem((*sp).data);
                    (*sp).data = 0 as *mut mbuf;
                    (*sp).tail_mbuf = 0 as *mut mbuf;
                    (*sp).length = 0u32
                }
            }
            if !(*sp).net.is_null() {
                if !(*sp).net.is_null() {
                    if ::std::intrinsics::atomic_xadd(
                        &mut (*(*sp).net).ref_count as *mut libc::c_int,
                        -(1i32),
                    ) == 1i32
                    {
                        sctp_os_timer_stop(&mut (*(*sp).net).rxt_timer.timer);
                        sctp_os_timer_stop(&mut (*(*sp).net).pmtu_timer.timer);
                        sctp_os_timer_stop(&mut (*(*sp).net).hb_timer.timer);
                        if !(*(*sp).net).ro.ro_rt.is_null() {
                            if (*(*(*sp).net).ro.ro_rt).rt_refcnt <= 1i64 {
                                sctp_userspace_rtfree((*(*sp).net).ro.ro_rt);
                            } else {
                                (*(*(*sp).net).ro.ro_rt).rt_refcnt -= 1
                            }
                            (*(*sp).net).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                            (*(*sp).net).ro.ro_rt = 0 as *mut sctp_rtentry_t
                        }
                        if (*(*sp).net).src_addr_selected != 0 {
                            sctp_free_ifa((*(*sp).net).ro._s_addr);
                            (*(*sp).net).ro._s_addr = 0 as *mut sctp_ifa
                        }
                        (*(*sp).net).src_addr_selected = 0u8;
                        (*(*sp).net).dest_state =
                            ((*(*sp).net).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                        free((*sp).net as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                            1u32,
                        );
                    }
                }
                (*sp).net = 0 as *mut sctp_nets
            }
            if (*sp).holds_key_ref != 0 {
                sctp_auth_key_release(stcb, (*sp).auth_keyid, 1i32);
                (*sp).holds_key_ref = 0u8
            }
            free(sp as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(
                &mut system_base_info.sctppcbinfo.ipi_count_strmoq,
                1u32,
            );
            sp = nsp
        }
    }
    pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    /*sa_ignore FREED_MEMORY*/
    strrst = (*asoc).resetHead.tqh_first;
    while !strrst.is_null() && {
        nstrrst = (*strrst).next_resp.tqe_next;
        (1i32) != 0
    } {
        if !(*strrst).next_resp.tqe_next.is_null() {
            (*(*strrst).next_resp.tqe_next).next_resp.tqe_prev = (*strrst).next_resp.tqe_prev
        } else {
            (*asoc).resetHead.tqh_last = (*strrst).next_resp.tqe_prev
        }
        *(*strrst).next_resp.tqe_prev = (*strrst).next_resp.tqe_next;
        free(strrst as *mut libc::c_void);
        strrst = nstrrst
    }
    sq = (*asoc).pending_reply_queue.tqh_first;
    while !sq.is_null() && {
        nsq = (*sq).next.tqe_next;
        (1i32) != 0
    } {
        if !(*sq).next.tqe_next.is_null() {
            (*(*sq).next.tqe_next).next.tqe_prev = (*sq).next.tqe_prev
        } else {
            (*asoc).pending_reply_queue.tqh_last = (*sq).next.tqe_prev
        }
        *(*sq).next.tqe_prev = (*sq).next.tqe_next;
        if !(*sq).data.is_null() {
            m_freem((*sq).data);
            (*sq).data = 0 as *mut mbuf
        }
        if !(*sq).whoFrom.is_null() {
            if ::std::intrinsics::atomic_xadd(
                &mut (*(*sq).whoFrom).ref_count as *mut libc::c_int,
                -(1i32),
            ) == 1i32
            {
                sctp_os_timer_stop(&mut (*(*sq).whoFrom).rxt_timer.timer);
                sctp_os_timer_stop(&mut (*(*sq).whoFrom).pmtu_timer.timer);
                sctp_os_timer_stop(&mut (*(*sq).whoFrom).hb_timer.timer);
                if !(*(*sq).whoFrom).ro.ro_rt.is_null() {
                    if (*(*(*sq).whoFrom).ro.ro_rt).rt_refcnt <= 1i64 {
                        sctp_userspace_rtfree((*(*sq).whoFrom).ro.ro_rt);
                    } else {
                        (*(*(*sq).whoFrom).ro.ro_rt).rt_refcnt -= 1
                    }
                    (*(*sq).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                    (*(*sq).whoFrom).ro.ro_rt = 0 as *mut sctp_rtentry_t
                }
                if (*(*sq).whoFrom).src_addr_selected != 0 {
                    sctp_free_ifa((*(*sq).whoFrom).ro._s_addr);
                    (*(*sq).whoFrom).ro._s_addr = 0 as *mut sctp_ifa
                }
                (*(*sq).whoFrom).src_addr_selected = 0u8;
                (*(*sq).whoFrom).dest_state =
                    ((*(*sq).whoFrom).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                free((*sq).whoFrom as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                    1u32,
                );
            }
        }
        (*sq).whoFrom = 0 as *mut sctp_nets;
        (*sq).stcb = 0 as *mut sctp_tcb;
        /*sa_ignore FREED_MEMORY*/
        free(sq as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
        sq = nsq
    }
    chk = (*asoc).free_chunks.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*asoc).free_chunks.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        if !(*chk).data.is_null() {
            m_freem((*chk).data);
            (*chk).data = 0 as *mut mbuf
        }
        if (*chk).holds_key_ref != 0 {
            sctp_auth_key_release(stcb, (*chk).auth_keyid, 1i32);
        }
        free(chk as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_free_chunks, 1u32);
        (*asoc).free_chunk_cnt = (*asoc).free_chunk_cnt.wrapping_sub(1);
        chk = nchk
        /* Free the ctl entry */
        /*sa_ignore FREED_MEMORY*/
    }
    /* pending send queue SHOULD be empty */
    chk = (*asoc).send_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues > 0u32 {
            let ref mut fresh0 =
                (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues;
            *fresh0 = (*fresh0).wrapping_sub(1)
        }
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*asoc).send_queue.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        if !(*chk).data.is_null() {
            if !so.is_null() {
                /*sa_ignore FREED_MEMORY*/
                /* Still a socket? */
                sctp_ulp_notify(6u32, stcb, 0u32, chk as *mut libc::c_void, 1i32);
            }
            if !(*chk).data.is_null() {
                m_freem((*chk).data);
                (*chk).data = 0 as *mut mbuf
            }
        }
        if (*chk).holds_key_ref != 0 {
            sctp_auth_key_release(stcb, (*chk).auth_keyid, 1i32);
        }
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
        free(chk as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        chk = nchk
    }
    /* sent queue SHOULD be empty */
    chk = (*asoc).sent_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if (*chk).sent != 40010i32 {
            if (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues > 0u32 {
                let ref mut fresh1 =
                    (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues;
                *fresh1 = (*fresh1).wrapping_sub(1)
            }
        }
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*asoc).sent_queue.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        if !(*chk).data.is_null() {
            if !so.is_null() {
                /*sa_ignore FREED_MEMORY*/
                /* Still a socket? */
                sctp_ulp_notify(5u32, stcb, 0u32, chk as *mut libc::c_void, 1i32);
            }
            if !(*chk).data.is_null() {
                m_freem((*chk).data);
                (*chk).data = 0 as *mut mbuf
            }
        }
        if (*chk).holds_key_ref != 0 {
            sctp_auth_key_release(stcb, (*chk).auth_keyid, 1i32);
        }
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
        free(chk as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        chk = nchk
    }
    /* control queue MAY not be empty */
    chk = (*asoc).control_send_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*asoc).control_send_queue.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        if !(*chk).data.is_null() {
            m_freem((*chk).data);
            (*chk).data = 0 as *mut mbuf
        }
        if (*chk).holds_key_ref != 0 {
            sctp_auth_key_release(stcb, (*chk).auth_keyid, 1i32);
        }
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
        free(chk as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        chk = nchk
        /*sa_ignore FREED_MEMORY*/
    }
    /* ASCONF queue MAY not be empty */
    chk = (*asoc).asconf_send_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*asoc).asconf_send_queue.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        if !(*chk).data.is_null() {
            m_freem((*chk).data);
            (*chk).data = 0 as *mut mbuf
        }
        if (*chk).holds_key_ref != 0 {
            sctp_auth_key_release(stcb, (*chk).auth_keyid, 1i32);
        }
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
        free(chk as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_chunk, 1u32);
        chk = nchk
        /*sa_ignore FREED_MEMORY*/
    }
    if !(*asoc).mapping_array.is_null() {
        free((*asoc).mapping_array as *mut libc::c_void);
        (*asoc).mapping_array = 0 as *mut uint8_t
    }
    if !(*asoc).nr_mapping_array.is_null() {
        free((*asoc).nr_mapping_array as *mut libc::c_void);
        (*asoc).nr_mapping_array = 0 as *mut uint8_t
    }
    /* the stream outs */
    if !(*asoc).strmout.is_null() {
        free((*asoc).strmout as *mut libc::c_void);
        (*asoc).strmout = 0 as *mut sctp_stream_out
    }
    (*asoc).streamoutcnt = 0u16;
    (*asoc).strm_realoutsize = (*asoc).streamoutcnt;
    if !(*asoc).strmin.is_null() {
        for i in 0i32..(*asoc).streamincnt as libc::c_int {
            sctp_clean_up_stream(stcb, &mut (*(*asoc).strmin.offset(i as isize)).inqueue);

            sctp_clean_up_stream(stcb, &mut (*(*asoc).strmin.offset(i as isize)).uno_inqueue);
        }
        free((*asoc).strmin as *mut libc::c_void);
        (*asoc).strmin = 0 as *mut sctp_stream_in
    }
    (*asoc).streamincnt = 0u16;
    net = (*asoc).nets.tqh_first;
    while !net.is_null() && {
        nnet = (*net).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !(*net).sctp_next.tqe_next.is_null() {
            (*(*net).sctp_next.tqe_next).sctp_next.tqe_prev = (*net).sctp_next.tqe_prev
        } else {
            (*asoc).nets.tqh_last = (*net).sctp_next.tqe_prev
        }
        *(*net).sctp_next.tqe_prev = (*net).sctp_next.tqe_next;
        if !net.is_null() {
            if ::std::intrinsics::atomic_xadd(&mut (*net).ref_count as *mut libc::c_int, -(1i32))
                == 1i32
            {
                sctp_os_timer_stop(&mut (*net).rxt_timer.timer);
                sctp_os_timer_stop(&mut (*net).pmtu_timer.timer);
                sctp_os_timer_stop(&mut (*net).hb_timer.timer);
                if !(*net).ro.ro_rt.is_null() {
                    if (*(*net).ro.ro_rt).rt_refcnt <= 1i64 {
                        sctp_userspace_rtfree((*net).ro.ro_rt);
                    } else {
                        (*(*net).ro.ro_rt).rt_refcnt -= 1
                    }
                    (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                    (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t
                }
                if (*net).src_addr_selected != 0 {
                    sctp_free_ifa((*net).ro._s_addr);
                    (*net).ro._s_addr = 0 as *mut sctp_ifa
                }
                (*net).src_addr_selected = 0u8;
                (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                free(net as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                    1u32,
                );
            }
        }
        net = nnet
    }
    laddr = (*asoc).sctp_restricted_addrs.lh_first;
    while !laddr.is_null() && {
        naddr = (*laddr).sctp_nxt_addr.le_next;
        (1i32) != 0
    } {
        /*sa_ignore FREED_MEMORY*/
        sctp_remove_laddr(laddr);
        laddr = naddr
    }
    /* pending asconf (address) parameters */
    aparam = (*asoc).asconf_queue.tqh_first;
    while !aparam.is_null() && {
        naparam = (*aparam).next.tqe_next;
        (1i32) != 0
    } {
        /*sa_ignore FREED_MEMORY*/
        if !(*aparam).next.tqe_next.is_null() {
            (*(*aparam).next.tqe_next).next.tqe_prev = (*aparam).next.tqe_prev
        } else {
            (*asoc).asconf_queue.tqh_last = (*aparam).next.tqe_prev
        }
        *(*aparam).next.tqe_prev = (*aparam).next.tqe_next;
        free(aparam as *mut libc::c_void);
        aparam = naparam
    }
    aack = (*asoc).asconf_ack_sent.tqh_first;
    while !aack.is_null() && {
        naack = (*aack).next.tqe_next;
        (1i32) != 0
    } {
        /*sa_ignore FREED_MEMORY*/
        if !(*aack).next.tqe_next.is_null() {
            (*(*aack).next.tqe_next).next.tqe_prev = (*aack).next.tqe_prev
        } else {
            (*asoc).asconf_ack_sent.tqh_last = (*aack).next.tqe_prev
        }
        *(*aack).next.tqe_prev = (*aack).next.tqe_next;
        if !(*aack).data.is_null() {
            m_freem((*aack).data);
        }
        free(aack as *mut libc::c_void);
        aack = naack
    }
    /* clean up auth stuff */
    if !(*asoc).local_hmacs.is_null() {
        sctp_free_hmaclist((*asoc).local_hmacs);
    }
    if !(*asoc).peer_hmacs.is_null() {
        sctp_free_hmaclist((*asoc).peer_hmacs);
    }
    if !(*asoc).local_auth_chunks.is_null() {
        sctp_free_chunklist((*asoc).local_auth_chunks);
    }
    if !(*asoc).peer_auth_chunks.is_null() {
        sctp_free_chunklist((*asoc).peer_auth_chunks);
    }
    sctp_free_authinfo(&mut (*asoc).authinfo);
    shared_key = (*asoc).shared_keys.lh_first;
    while !shared_key.is_null() && {
        nshared_key = (*shared_key).next.le_next;
        (1i32) != 0
    } {
        if !(*shared_key).next.le_next.is_null() {
            (*(*shared_key).next.le_next).next.le_prev = (*shared_key).next.le_prev
        }
        *(*shared_key).next.le_prev = (*shared_key).next.le_next;
        sctp_free_sharedkey(shared_key);
        shared_key = nshared_key
        /*sa_ignore FREED_MEMORY*/
    }
    /* Insert new items here :> */
    /* Get rid of LOCK */
    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
    pthread_mutex_destroy(&mut (*stcb).tcb_mtx);
    pthread_mutex_destroy(&mut (*stcb).tcb_send_mtx);
    if from_inpcbfree == 0i32 {
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        pthread_mutex_lock(&mut (*inp).inp_mtx);
    }
    /* TEMP CODE */
    free(stcb as *mut libc::c_void);
    ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_asoc, 1u32);
    if from_inpcbfree == 0i32 {
        if (*inp).sctp_flags & 0x10000000u32 != 0 {
            /* If its NOT the inp_free calling us AND
             * sctp_close as been called, we
             * call back...
             */
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            /* This will start the kill timer (if we are
             * the last one) since we hold an increment yet. But
             * this is the only safe way to do this
             * since otherwise if the socket closes
             * at the same time we are here we might
             * collide in the cleanup.
             */
            sctp_inpcb_free(inp, 0i32, 0i32);
            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
            current_block = 3292817607802360715;
        } else {
            /* The socket is still open. */
            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
            current_block = 1846749606198814734;
        }
    } else {
        current_block = 1846749606198814734;
    }
    match current_block {
        1846749606198814734 => {
            if from_inpcbfree == 0i32 {
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        _ => {}
    }
    /* destroyed the asoc */
    return 1i32;
}
/* void sctp_drain(void); */
/*
 * determine if a destination is "reachable" based upon the addresses bound
 * to the current endpoint (e.g. only v4 or v6 currently bound)
 */
/*
 * FIX: if we allow assoc-level bindx(), then this needs to be fixed to use
 * assoc level v4/v6 flags, as the assoc *may* not have the same address
 * types bound as its endpoint
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_destination_is_reachable(
    mut stcb: *mut sctp_tcb,
    mut destaddr: *mut sockaddr,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut answer = 0;
    /*
     * No locks here, the TCB, in all cases is already locked and an
     * assoc is up. There is either a INP lock by the caller applied (in
     * asconf case when deleting an address) or NOT in the HB case,
     * however if HB then the INP increment is up and the INP will not
     * be removed (on top of the fact that we have a TCB lock). So we
     * only want to read the sctp_flags, which is either bound-all or
     * not.. no protection needed since once an assoc is up you can't be
     * changing your binding.
     */
    inp = (*stcb).sctp_ep;
    if (*inp).sctp_flags & 0x4u32 != 0 {
        /* if bound all, destination is not restricted */
        /*
         * RRS: Question during lock work: Is this correct? If you
         * are bound-all you still might need to obey the V4--V6
         * flags??? IMO this bound-all stuff needs to be removed!
         */
        return 1i32;
    }
    /* NOTE: all "scope" checks are done when local addresses are added */
    match (*destaddr).sa_family as libc::c_int {
        10 => answer = (*inp).ip_inp.inp.inp_vflag as libc::c_int & 0x2i32,
        2 => answer = (*inp).ip_inp.inp.inp_vflag as libc::c_int & 0x1i32,
        123 => answer = (*inp).ip_inp.inp.inp_vflag as libc::c_int & 0x80i32,
        _ => {
            /* invalid family, so it's unreachable */
            answer = 0i32
        }
    }
    return answer;
}
/*
 * update the inp_vflags on an endpoint
 */
unsafe extern "C" fn sctp_update_ep_vflag(mut inp: *mut sctp_inpcb) {
    let mut laddr = 0 as *mut sctp_laddr;
    /* first clear the flag */
    (*inp).ip_inp.inp.inp_vflag = 0u8;
    /* set the flag based on addresses on the ep list */
    laddr = (*inp).sctp_addr_list.lh_first;
    while !laddr.is_null() {
        if (*laddr).ifa.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"%s: NULL ifa\n\x00" as *const u8 as *const libc::c_char,
                        (*::std::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"sctp_update_ep_vflag\x00",
                        ))
                        .as_ptr(),
                    );
                }
            }
        } else if !((*(*laddr).ifa).localifa_flags & 0x2u32 != 0) {
            match (*(*laddr).ifa).address.sa.sa_family as libc::c_int {
                10 => {
                    (*inp).ip_inp.inp.inp_vflag =
                        ((*inp).ip_inp.inp.inp_vflag as libc::c_int | 0x2i32) as u_char
                }
                2 => {
                    (*inp).ip_inp.inp.inp_vflag =
                        ((*inp).ip_inp.inp.inp_vflag as libc::c_int | 0x1i32) as u_char
                }
                123 => {
                    (*inp).ip_inp.inp.inp_vflag =
                        ((*inp).ip_inp.inp.inp_vflag as libc::c_int | 0x80i32) as u_char
                }
                _ => {}
            }
        }
        laddr = (*laddr).sctp_nxt_addr.le_next
    }
}
/*
 * Add the address to the endpoint local address list There is nothing to be
 * done if we are bound to all addresses
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_add_local_addr_ep(
    mut inp: *mut sctp_inpcb,
    mut ifa: *mut sctp_ifa,
    mut action: uint32_t,
) {
    let mut laddr = 0 as *mut sctp_laddr;
    let mut fnd = 0;
    fnd = 0i32;
    if (*inp).sctp_flags & 0x4u32 != 0 {
        /* You are already bound to all. You have it already */
        return;
    }
    if (*ifa).address.sa.sa_family as libc::c_int == 10i32 {
        if (*ifa).localifa_flags & 0x8u32 != 0 {
            /* Can't bind a non-useable addr. */
            return;
        }
    }
    /* first, is it already present? */
    laddr = (*inp).sctp_addr_list.lh_first;
    while !laddr.is_null() {
        if (*laddr).ifa == ifa {
            fnd = 1i32;
            break;
        } else {
            laddr = (*laddr).sctp_nxt_addr.le_next
        }
    }
    if fnd == 0i32 {
        let mut stcb = 0 as *mut sctp_tcb;
        let mut error = 0i32;
        error = sctp_insert_laddr(&mut (*inp).sctp_addr_list, ifa, action);
        if error != 0i32 {
            return;
        }
        (*inp).laddr_count += 1;
        /* update inp_vflag flags */
        match (*ifa).address.sa.sa_family as libc::c_int {
            10 => {
                (*inp).ip_inp.inp.inp_vflag =
                    ((*inp).ip_inp.inp.inp_vflag as libc::c_int | 0x2i32) as u_char
            }
            2 => {
                (*inp).ip_inp.inp.inp_vflag =
                    ((*inp).ip_inp.inp.inp_vflag as libc::c_int | 0x1i32) as u_char
            }
            123 => {
                (*inp).ip_inp.inp.inp_vflag =
                    ((*inp).ip_inp.inp.inp_vflag as libc::c_int | 0x80i32) as u_char
            }
            _ => {}
        }
        stcb = (*inp).sctp_asoc_list.lh_first;
        while !stcb.is_null() {
            sctp_add_local_addr_restricted(stcb, ifa);
            stcb = (*stcb).sctp_tcblist.le_next
        }
    };
}
/*
 * select a new (hopefully reachable) destination net (should only be used
 * when we deleted an ep addr that is the only usable source address to reach
 * the destination net)
 */
unsafe extern "C" fn sctp_select_primary_destination(mut stcb: *mut sctp_tcb) {
    let mut net = 0 as *mut sctp_nets;
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        /* for now, we'll just pick the first reachable one we find */
        if !((*net).dest_state as libc::c_int & 0x200i32 != 0) {
            if sctp_destination_is_reachable(
                stcb,
                &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr,
            ) != 0
            {
                /* found a reachable destination */
                (*stcb).asoc.primary_destination = net
            }
        }
        net = (*net).sctp_next.tqe_next
    }
    /* I can't there from here! ...we're gonna die shortly... */
}
/*
 * Delete the address from the endpoint local address list. There is nothing
 * to be done if we are bound to all addresses
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_del_local_addr_ep(mut inp: *mut sctp_inpcb, mut ifa: *mut sctp_ifa) {
    let mut laddr = 0 as *mut sctp_laddr;
    let mut fnd = 0;
    fnd = 0i32;
    if (*inp).sctp_flags & 0x4u32 != 0 {
        /* You are already bound to all. You have it already */
        return;
    }
    laddr = (*inp).sctp_addr_list.lh_first;
    while !laddr.is_null() {
        if (*laddr).ifa == ifa {
            fnd = 1i32;
            break;
        } else {
            laddr = (*laddr).sctp_nxt_addr.le_next
        }
    }
    if fnd != 0 && (*inp).laddr_count < 2i32 {
        /* can't delete unless there are at LEAST 2 addresses */
        return;
    }
    if fnd != 0 {
        let mut stcb = 0 as *mut sctp_tcb;
        /* clean up "next_addr_touse" */
        if (*inp).next_addr_touse == laddr {
            /* delete this address */
            (*inp).next_addr_touse = 0 as *mut sctp_laddr
        }
        /* clean up "last_used_address" */
        stcb = (*inp).sctp_asoc_list.lh_first; /* for each tcb */
        while !stcb.is_null() {
            let mut net = 0 as *mut sctp_nets;
            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
            if (*stcb).asoc.last_used_address == laddr {
                /* delete this address */
                (*stcb).asoc.last_used_address = 0 as *mut sctp_laddr
            }
            /* Now spin through all the nets and purge any ref to laddr */
            net = (*stcb).asoc.nets.tqh_first;
            while !net.is_null() {
                if (*net).ro._s_addr == (*laddr).ifa {
                    let mut rt = 0 as *mut sctp_rtentry_t;
                    /* delete this address if cached */
                    rt = (*net).ro.ro_rt;
                    if !rt.is_null() {
                        if (*rt).rt_refcnt <= 1i64 {
                            sctp_userspace_rtfree(rt);
                        } else {
                            (*rt).rt_refcnt -= 1
                        }
                        rt = 0 as *mut sctp_rtentry_t;
                        (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t
                    }
                    sctp_free_ifa((*net).ro._s_addr);
                    (*net).ro._s_addr = 0 as *mut sctp_ifa;
                    (*net).src_addr_selected = 0u8
                }
                net = (*net).sctp_next.tqe_next
            }
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            stcb = (*stcb).sctp_tcblist.le_next
        }
        /* remove it from the ep list */
        sctp_remove_laddr(laddr);
        (*inp).laddr_count -= 1;
        /* update inp_vflag flags */
        sctp_update_ep_vflag(inp);
    };
}
/*
 * Add the address to the TCB local address restricted list.
 * This is a "pending" address list (eg. addresses waiting for an
 * ASCONF-ACK response) and cannot be used as a valid source address.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_add_local_addr_restricted(
    mut stcb: *mut sctp_tcb,
    mut ifa: *mut sctp_ifa,
) {
    let mut laddr = 0 as *mut sctp_laddr;
    let mut list = 0 as *mut sctpladdr;
    /*
     * Assumes TCB is locked.. and possibly the INP. May need to
     * confirm/fix that if we need it and is not the case.
     */
    list = &mut (*stcb).asoc.sctp_restricted_addrs;
    if (*ifa).address.sa.sa_family as libc::c_int == 10i32 {
        if (*ifa).localifa_flags & 0x8u32 != 0 {
            /* Can't bind a non-existent addr. */
            return;
        }
    }
    /* does the address already exist? */
    laddr = (*list).lh_first;
    while !laddr.is_null() {
        if (*laddr).ifa == ifa {
            return;
        }
        laddr = (*laddr).sctp_nxt_addr.le_next
    }
    /* add to the list */
    sctp_insert_laddr(list, ifa, 0u32);
}
/*
 * Remove a local address from the TCB local address restricted list
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_del_local_addr_restricted(
    mut stcb: *mut sctp_tcb,
    mut ifa: *mut sctp_ifa,
) {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut laddr = 0 as *mut sctp_laddr;
    /*
     * This is called by asconf work. It is assumed that a) The TCB is
     * locked and b) The INP is locked. This is true in as much as I can
     * trace through the entry asconf code where I did these locks.
     * Again, the ASCONF code is a bit different in that it does lock
     * the INP during its work often times. This must be since we don't
     * want other proc's looking up things while what they are looking
     * up is changing :-D
     */
    inp = (*stcb).sctp_ep;
    /* if subset bound and don't allow ASCONF's, can't delete last */
    if (*inp).sctp_flags & 0x4u32 == 0u32 && (*inp).sctp_features & 0x20u64 == 0u64 {
        if (*(*stcb).sctp_ep).laddr_count < 2i32 {
            /* can't delete last address */
            return;
        }
    }
    laddr = (*stcb).asoc.sctp_restricted_addrs.lh_first;
    while !laddr.is_null() {
        /* remove the address if it exists */
        if !(*laddr).ifa.is_null() {
            if (*laddr).ifa == ifa {
                sctp_remove_laddr(laddr);
                return;
            }
        }
        laddr = (*laddr).sctp_nxt_addr.le_next
    }
}
/* FreeBSD || APPLE */
#[no_mangle]
pub unsafe extern "C" fn sctp_pcb_init(mut start_threads: libc::c_int) {
    let mut tv = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    if system_base_info.sctp_pcb_initialized as libc::c_int != 0i32 {
        /* error I was called twice */
        return;
    }
    system_base_info.sctp_pcb_initialized = 1i8;
    pthread_mutexattr_init(&mut system_base_info.mtx_attr);
    gettimeofday(&mut tv, 0 as *mut timezone);
    memset(
        &mut system_base_info.sctpstat as *mut sctpstat as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctpstat>() as libc::c_ulong,
    );
    system_base_info.sctpstat.sctps_discontinuitytime.tv_sec = tv.tv_sec as uint32_t;
    system_base_info.sctpstat.sctps_discontinuitytime.tv_usec = tv.tv_usec as uint32_t;
    /* init the empty list of (All) Endpoints */
    system_base_info.sctppcbinfo.listhead.lh_first = 0 as *mut sctp_inpcb;
    /* init the hash table of endpoints */
    system_base_info.sctppcbinfo.sctp_asochash = sctp_hashinit_flags(
        system_base_info
            .sctpsysctl
            .sctp_hashtblsize
            .wrapping_mul(31u32) as libc::c_int,
        M_PCB.as_mut_ptr(),
        &mut system_base_info.sctppcbinfo.hashasocmark,
        0x1i32,
    ) as *mut sctpasochead;
    system_base_info.sctppcbinfo.sctp_ephash = sctp_hashinit_flags(
        system_base_info.sctpsysctl.sctp_hashtblsize as libc::c_int,
        M_PCB.as_mut_ptr(),
        &mut system_base_info.sctppcbinfo.hashmark,
        0x1i32,
    ) as *mut sctppcbhead;
    system_base_info.sctppcbinfo.sctp_tcpephash = sctp_hashinit_flags(
        system_base_info.sctpsysctl.sctp_hashtblsize as libc::c_int,
        M_PCB.as_mut_ptr(),
        &mut system_base_info.sctppcbinfo.hashtcpmark,
        0x1i32,
    ) as *mut sctppcbhead;
    system_base_info.sctppcbinfo.hashtblsize = system_base_info.sctpsysctl.sctp_hashtblsize;
    system_base_info.sctppcbinfo.sctp_vrfhash = sctp_hashinit_flags(
        3i32,
        M_PCB.as_mut_ptr(),
        &mut system_base_info.sctppcbinfo.hashvrfmark,
        0x1i32,
    ) as *mut sctp_vrflist;
    system_base_info.sctppcbinfo.vrf_ifn_hash = sctp_hashinit_flags(
        3i32,
        M_PCB.as_mut_ptr(),
        &mut system_base_info.sctppcbinfo.vrf_ifn_hashmark,
        0x1i32,
    ) as *mut sctp_ifnlist;
    /* init the zones */
    /*
     * FIX ME: Should check for NULL returns, but if it does fail we are
     * doomed to panic anyways... add later maybe.
     */
    system_base_info.sctppcbinfo.ipi_zone_ep = ::std::mem::size_of::<sctp_inpcb>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_asoc = ::std::mem::size_of::<sctp_tcb>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_laddr =
        ::std::mem::size_of::<sctp_laddr>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_net = ::std::mem::size_of::<sctp_nets>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_chunk =
        ::std::mem::size_of::<sctp_tmit_chunk>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_readq =
        ::std::mem::size_of::<sctp_queued_to_read>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_strmoq =
        ::std::mem::size_of::<sctp_stream_queue_pending>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_asconf =
        ::std::mem::size_of::<sctp_asconf>() as libc::c_ulong;
    system_base_info.sctppcbinfo.ipi_zone_asconf_ack =
        ::std::mem::size_of::<sctp_asconf_ack>() as libc::c_ulong;
    /* Master Lock INIT for info structure */
    pthread_mutex_init(
        &mut system_base_info.sctppcbinfo.ipi_ep_mtx,
        &mut system_base_info.mtx_attr,
    );
    pthread_mutex_init(
        &mut system_base_info.sctppcbinfo.ipi_addr_mtx,
        &mut system_base_info.mtx_attr,
    );
    system_base_info.sctppcbinfo.addr_wq.lh_first = 0 as *mut sctp_laddr;
    pthread_mutex_init(
        &mut system_base_info.sctppcbinfo.wq_addr_mtx,
        &mut system_base_info.mtx_attr,
    );
    /* not sure if we need all the counts */
    system_base_info.sctppcbinfo.ipi_count_ep = 0u32;
    /* assoc/tcb zone info */
    system_base_info.sctppcbinfo.ipi_count_asoc = 0u32;
    /* local addrlist zone info */
    system_base_info.sctppcbinfo.ipi_count_laddr = 0u32;
    /* remote addrlist zone info */
    system_base_info.sctppcbinfo.ipi_count_raddr = 0u32;
    /* chunk info */
    system_base_info.sctppcbinfo.ipi_count_chunk = 0u32;
    /* socket queue zone info */
    system_base_info.sctppcbinfo.ipi_count_readq = 0u32;
    /* stream out queue cont */
    system_base_info.sctppcbinfo.ipi_count_strmoq = 0u32;
    system_base_info.sctppcbinfo.ipi_free_strmoq = 0u32;
    system_base_info.sctppcbinfo.ipi_free_chunks = 0u32;
    sctp_os_timer_init(&mut system_base_info.sctppcbinfo.addr_wq_timer.timer);

    for i in 0i32..32i32 {
        system_base_info.sctppcbinfo.vtag_timewait[i as usize].lh_first = 0 as *mut sctp_tagblock;
    }
    pthread_cond_init(
        &mut sctp_it_ctl.iterator_wakeup,
        0 as *const pthread_condattr_t,
    );
    sctp_startup_iterator();
    /*
     * INIT the default VRF which for BSD is the only one, other O/S's
     * may have more. But initially they must start with one and then
     * add the VRF's as addresses are added.
     */
    sctp_init_vrf_list(0i32);
    /* allocate the lock for the callout/timer queue */
    pthread_mutex_init(
        &mut system_base_info.timer_mtx,
        &mut system_base_info.mtx_attr,
    );
    system_base_info.sctppcbinfo.callqueue.tqh_first = 0 as *mut sctp_callout;
    system_base_info.sctppcbinfo.callqueue.tqh_last =
        &mut system_base_info.sctppcbinfo.callqueue.tqh_first;
    mbuf_initialize(0 as *mut libc::c_void);
    atomic_init();
    if start_threads != 0 {
        recv_thread_init();
    };
}
/*
 * Assumes that the SCTP_BASE_INFO() lock is NOT held.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_pcb_finish() {
    let mut vrf_bucket = 0 as *mut sctp_vrflist;
    let mut vrf = 0 as *mut sctp_vrf;
    let mut nvrf = 0 as *mut sctp_vrf;
    let mut wi = 0 as *mut sctp_laddr;
    let mut nwi = 0 as *mut sctp_laddr;
    let mut it = 0 as *mut sctp_iterator;
    let mut nit = 0 as *mut sctp_iterator;
    if system_base_info.sctp_pcb_initialized as libc::c_int == 0i32 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%s: race condition on teardown.\n\x00" as *const u8 as *const libc::c_char,
                (*::std::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sctp_pcb_finish\x00"))
                    .as_ptr(),
            );
        }
        return;
    }
    system_base_info.sctp_pcb_initialized = 0i8;
    /* Notify the iterator to exit. */
    pthread_mutex_lock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    sctp_it_ctl.iterator_flags |= 0x1u32;
    sctp_wakeup_iterator();
    pthread_mutex_unlock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    if sctp_it_ctl.thread_proc != 0 {
        pthread_join(sctp_it_ctl.thread_proc, 0 as *mut *mut libc::c_void);
        sctp_it_ctl.thread_proc = 0u64
    }
    pthread_cond_destroy(&mut sctp_it_ctl.iterator_wakeup);
    pthread_mutexattr_destroy(&mut system_base_info.mtx_attr);
    /* In FreeBSD the iterator thread never exits
     * but we do clean up.
     * The only way FreeBSD reaches here is if we have VRF's
     * but we still add the ifdef to make it compile on old versions.
     */
    pthread_mutex_lock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    it = sctp_it_ctl.iteratorhead.tqh_first;
    while !it.is_null() && {
        nit = (*it).sctp_nxt_itr.tqe_next;
        (1i32) != 0
    } {
        if !(*it).sctp_nxt_itr.tqe_next.is_null() {
            (*(*it).sctp_nxt_itr.tqe_next).sctp_nxt_itr.tqe_prev = (*it).sctp_nxt_itr.tqe_prev
        } else {
            sctp_it_ctl.iteratorhead.tqh_last = (*it).sctp_nxt_itr.tqe_prev
        }
        *(*it).sctp_nxt_itr.tqe_prev = (*it).sctp_nxt_itr.tqe_next;
        if (*it).function_atend.is_some() {
            Some((*it).function_atend.expect("non-null function pointer"))
                .expect("non-null function pointer")((*it).pointer, (*it).val);
        }
        free(it as *mut libc::c_void);
        it = nit
    }
    pthread_mutex_unlock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    pthread_mutex_destroy(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    pthread_mutex_destroy(&mut sctp_it_ctl.it_mtx);
    sctp_os_timer_stop(&mut system_base_info.sctppcbinfo.addr_wq_timer.timer);
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
    wi = system_base_info.sctppcbinfo.addr_wq.lh_first;
    while !wi.is_null() && {
        nwi = (*wi).sctp_nxt_addr.le_next;
        (1i32) != 0
    } {
        if !(*wi).sctp_nxt_addr.le_next.is_null() {
            (*(*wi).sctp_nxt_addr.le_next).sctp_nxt_addr.le_prev = (*wi).sctp_nxt_addr.le_prev
        }
        *(*wi).sctp_nxt_addr.le_prev = (*wi).sctp_nxt_addr.le_next;
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
        if (*wi).action == 0xc002u32 {
            free((*wi).ifa as *mut libc::c_void);
        }
        free(wi as *mut libc::c_void);
        wi = nwi
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
    /*
     * free the vrf/ifn/ifa lists and hashes (be sure address monitor
     * is destroyed first).
     */
    vrf_bucket = &mut *system_base_info
        .sctppcbinfo
        .sctp_vrfhash
        .offset((0u64 & system_base_info.sctppcbinfo.hashvrfmark) as isize)
        as *mut sctp_vrflist;
    vrf = (*vrf_bucket).lh_first;
    while !vrf.is_null() && {
        nvrf = (*vrf).next_vrf.le_next;
        (1i32) != 0
    } {
        let mut ifn = 0 as *mut sctp_ifn;
        let mut nifn = 0 as *mut sctp_ifn;
        ifn = (*vrf).ifnlist.lh_first;
        while !ifn.is_null() && {
            nifn = (*ifn).next_ifn.le_next;
            (1i32) != 0
        } {
            let mut ifa = 0 as *mut sctp_ifa;
            let mut nifa = 0 as *mut sctp_ifa;
            ifa = (*ifn).ifalist.lh_first;
            while !ifa.is_null() && {
                nifa = (*ifa).next_ifa.le_next;
                (1i32) != 0
            } {
                /* free the ifa */
                if !(*ifa).next_bucket.le_next.is_null() {
                    (*(*ifa).next_bucket.le_next).next_bucket.le_prev = (*ifa).next_bucket.le_prev
                }
                *(*ifa).next_bucket.le_prev = (*ifa).next_bucket.le_next;
                if !(*ifa).next_ifa.le_next.is_null() {
                    (*(*ifa).next_ifa.le_next).next_ifa.le_prev = (*ifa).next_ifa.le_prev
                }
                *(*ifa).next_ifa.le_prev = (*ifa).next_ifa.le_next;
                free(ifa as *mut libc::c_void);
                ifa = nifa
            }
            /* free the ifn */
            if !(*ifn).next_bucket.le_next.is_null() {
                (*(*ifn).next_bucket.le_next).next_bucket.le_prev = (*ifn).next_bucket.le_prev
            }
            *(*ifn).next_bucket.le_prev = (*ifn).next_bucket.le_next;
            if !(*ifn).next_ifn.le_next.is_null() {
                (*(*ifn).next_ifn.le_next).next_ifn.le_prev = (*ifn).next_ifn.le_prev
            }
            *(*ifn).next_ifn.le_prev = (*ifn).next_ifn.le_next;
            free(ifn as *mut libc::c_void);
            ifn = nifn
        }
        sctp_hashdestroy(
            (*vrf).vrf_addr_hash as *mut libc::c_void,
            M_PCB.as_mut_ptr(),
            (*vrf).vrf_addr_hashmark,
        );
        /* free the vrf */
        if !(*vrf).next_vrf.le_next.is_null() {
            (*(*vrf).next_vrf.le_next).next_vrf.le_prev = (*vrf).next_vrf.le_prev
        }
        *(*vrf).next_vrf.le_prev = (*vrf).next_vrf.le_next;
        free(vrf as *mut libc::c_void);
        vrf = nvrf
    }
    /* free the vrf hashes */
    sctp_hashdestroy(
        system_base_info.sctppcbinfo.sctp_vrfhash as *mut libc::c_void,
        M_PCB.as_mut_ptr(),
        system_base_info.sctppcbinfo.hashvrfmark,
    );
    sctp_hashdestroy(
        system_base_info.sctppcbinfo.vrf_ifn_hash as *mut libc::c_void,
        M_PCB.as_mut_ptr(),
        system_base_info.sctppcbinfo.vrf_ifn_hashmark,
    );

    for i in 0i32..32i32 {
        let mut chain = 0 as *mut sctpvtaghead;
        chain = &mut *system_base_info
            .sctppcbinfo
            .vtag_timewait
            .as_mut_ptr()
            .offset(i as isize) as *mut sctpvtaghead;

        if !(*chain).lh_first.is_null() {
            let mut twait_block = 0 as *mut sctp_tagblock;
            let mut prev_twait_block = 0 as *mut sctp_tagblock;
            prev_twait_block = 0 as *mut sctp_tagblock;
            twait_block = (*chain).lh_first;
            while !twait_block.is_null() {
                if !prev_twait_block.is_null() {
                    free(prev_twait_block as *mut libc::c_void);
                }
                prev_twait_block = twait_block;
                twait_block = (*twait_block).sctp_nxt_tagblock.le_next
            }
            free(prev_twait_block as *mut libc::c_void);
        }
    }
    /* free the locks and mutexes */
    pthread_mutex_destroy(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    pthread_mutex_destroy(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    pthread_mutex_destroy(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
    pthread_mutex_destroy(&mut system_base_info.timer_mtx);
    /* Get rid of other stuff too. */
    if !system_base_info.sctppcbinfo.sctp_asochash.is_null() {
        sctp_hashdestroy(
            system_base_info.sctppcbinfo.sctp_asochash as *mut libc::c_void,
            M_PCB.as_mut_ptr(),
            system_base_info.sctppcbinfo.hashasocmark,
        );
    }
    if !system_base_info.sctppcbinfo.sctp_ephash.is_null() {
        sctp_hashdestroy(
            system_base_info.sctppcbinfo.sctp_ephash as *mut libc::c_void,
            M_PCB.as_mut_ptr(),
            system_base_info.sctppcbinfo.hashmark,
        );
    }
    if !system_base_info.sctppcbinfo.sctp_tcpephash.is_null() {
        sctp_hashdestroy(
            system_base_info.sctppcbinfo.sctp_tcpephash as *mut libc::c_void,
            M_PCB.as_mut_ptr(),
            system_base_info.sctppcbinfo.hashtcpmark,
        );
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_load_addresses_from_init(
    mut stcb: *mut sctp_tcb,
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut limit: libc::c_int,
    mut src: *mut sockaddr,
    mut dst: *mut sockaddr,
    mut altsa: *mut sockaddr,
    mut port: uint16_t,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut net = 0 as *mut sctp_nets;
    let mut nnet = 0 as *mut sctp_nets;
    let mut net_tmp = 0 as *mut sctp_nets;
    let mut phdr = 0 as *mut sctp_paramhdr;
    let mut param_buf = sctp_paramhdr {
        param_type: 0,
        param_length: 0,
    };
    let mut stcb_tmp = 0 as *mut sctp_tcb;
    let mut sa = 0 as *mut sockaddr;
    let mut p_random = 0 as *mut sctp_auth_random;
    let mut random_len = 0u16;
    let mut hmacs = 0 as *mut sctp_auth_hmac_algo;
    let mut hmacs_len = 0u16;
    let mut saw_asconf = 0u8;
    let mut saw_asconf_ack = 0u8;
    let mut chunks = 0 as *mut sctp_auth_chunk_list;
    let mut num_chunks = 0u16;
    let mut new_key = 0 as *mut sctp_key_t;
    let mut keylen = 0;
    let mut got_random = 0i32;
    let mut got_hmacs = 0i32;
    let mut got_chklist = 0i32;
    let mut peer_supports_ecn = 0;
    let mut peer_supports_prsctp = 0;
    let mut peer_supports_auth = 0;
    let mut peer_supports_asconf = 0;
    let mut peer_supports_asconf_ack = 0;
    let mut peer_supports_reconfig = 0;
    let mut peer_supports_nrsack = 0;
    let mut peer_supports_pktdrop = 0;
    let mut peer_supports_idata = 0;
    let mut sin = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut sin6 = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            __in6_u: C2RustUnnamed_446 {
                __u6_addr8: [0; 16],
            },
        },
        sin6_scope_id: 0,
    };
    /* First get the destination address setup too. */
    memset(
        &mut sin as *mut sockaddr_in as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
    );
    sin.sin_family = 2u16;
    sin.sin_port = (*stcb).rport;
    memset(
        &mut sin6 as *mut sockaddr_in6 as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
    );
    sin6.sin6_family = 10u16;
    sin6.sin6_port = (*stcb).rport;
    if !altsa.is_null() {
        sa = altsa
    } else {
        sa = src
    }
    peer_supports_idata = 0u8;
    peer_supports_ecn = 0u8;
    peer_supports_prsctp = 0u8;
    peer_supports_auth = 0u8;
    peer_supports_asconf = 0u8;
    peer_supports_reconfig = 0u8;
    peer_supports_nrsack = 0u8;
    peer_supports_pktdrop = 0u8;
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        /* mark all addresses that we have currently on the list */
        (*net).dest_state = ((*net).dest_state as libc::c_int | 0x10i32) as uint16_t;
        net = (*net).sctp_next.tqe_next
    }
    /* does the source address already exist? if so skip it */
    inp = (*stcb).sctp_ep;
    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
    stcb_tmp = sctp_findassociation_ep_addr(&mut inp, sa, &mut net_tmp, dst, stcb);
    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, -(1i32) as uint32_t);
    if stcb_tmp.is_null() && inp == (*stcb).sctp_ep || inp.is_null() {
        /* we must add the source address */
        /* no scope set here since we have a tcb already. */
        match (*sa).sa_family as libc::c_int {
            2 => {
                if (*stcb).asoc.scope.ipv4_addr_legal != 0 {
                    if sctp_add_remote_addr(stcb, sa, 0 as *mut *mut sctp_nets, port, 0i32, 2i32)
                        != 0
                    {
                        return -(1i32);
                    }
                }
            }
            10 => {
                if (*stcb).asoc.scope.ipv6_addr_legal != 0 {
                    if sctp_add_remote_addr(stcb, sa, 0 as *mut *mut sctp_nets, port, 0i32, 3i32)
                        != 0
                    {
                        return -(2i32);
                    }
                }
            }
            123 => {
                if (*stcb).asoc.scope.conn_addr_legal != 0 {
                    if sctp_add_remote_addr(stcb, sa, 0 as *mut *mut sctp_nets, port, 0i32, 3i32)
                        != 0
                    {
                        return -(2i32);
                    }
                }
            }
            _ => {}
        }
    } else if !net_tmp.is_null() && stcb_tmp == stcb {
        (*net_tmp).dest_state = ((*net_tmp).dest_state as libc::c_int & !(0x10i32)) as uint16_t
    } else if stcb_tmp != stcb {
        /* It belongs to another association? */
        if !stcb_tmp.is_null() {
            pthread_mutex_unlock(&mut (*stcb_tmp).tcb_mtx);
        }
        return -(3i32);
    }
    if (*stcb).asoc.state == 0i32 {
        /* the assoc was freed? */
        return -(4i32);
    }
    /* now we must go through each of the params. */
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
        /*
         * SCTP_PRINTF("ptype => %0x, plen => %d\n", (uint32_t)ptype,
         * (int)plen);
         */
        if offset + plen as libc::c_int > limit {
            break;
        }
        if (plen as libc::c_ulong) < ::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong {
            break;
        }
        if ptype as libc::c_int == 0x5i32 {
            if (*stcb).asoc.scope.ipv4_addr_legal != 0 {
                let mut p4 = 0 as *mut sctp_ipv4addr_param;
                let mut p4_buf = sctp_ipv4addr_param {
                    ph: sctp_paramhdr {
                        param_type: 0,
                        param_length: 0,
                    },
                    addr: 0,
                };
                /* ok get the v4 address and check/add */
                phdr = sctp_get_next_param(
                    m,
                    offset,
                    &mut p4_buf as *mut sctp_ipv4addr_param as *mut sctp_paramhdr,
                    ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_int,
                );
                if plen as libc::c_ulong
                    != ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
                    || phdr.is_null()
                {
                    return -(5i32);
                }
                p4 = phdr as *mut sctp_ipv4addr_param;
                sin.sin_addr.s_addr = (*p4).addr;
                if !(ntohl(sin.sin_addr.s_addr) & 0xf0000000u32 == 0xe0000000u32) {
                    if !(sin.sin_addr.s_addr == 0xffffffffu32 || sin.sin_addr.s_addr == 0u32) {
                        let mut current_block_91: u64;
                        sa = &mut sin as *mut sockaddr_in as *mut sockaddr;
                        inp = (*stcb).sctp_ep;
                        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
                        stcb_tmp = sctp_findassociation_ep_addr(&mut inp, sa, &mut net, dst, stcb);
                        ::std::intrinsics::atomic_xadd(
                            &mut (*stcb).asoc.refcnt,
                            -(1i32) as uint32_t,
                        );

                        if stcb_tmp.is_null() && inp == (*stcb).sctp_ep || inp.is_null() {
                            current_block_91 = 11687017093709255301;
                        } else if stcb_tmp == stcb {
                            if (*stcb).asoc.state == 0i32 {
                                /* the assoc was freed? */
                                return -(10i32);
                            }
                            if !net.is_null() {
                                /* clear flag */
                                (*net).dest_state =
                                    ((*net).dest_state as libc::c_int & !(0x10i32)) as uint16_t
                            }
                            current_block_91 = 14027225908442187354;
                        } else {
                            /*
                             * strange, address is in another
                             * assoc? straighten out locks.
                             */
                            if !stcb_tmp.is_null() {
                                if (*stcb_tmp).asoc.state & 0x7fi32 == 0x2i32 {
                                    let mut op_err = 0 as *mut mbuf;
                                    let mut msg = [0; 128];
                                    /* in setup state we abort this guy */
                                    snprintf(msg.as_mut_ptr(),
                                             ::std::mem::size_of::<[libc::c_char; 128]>()
                                                 as libc::c_ulong,
                                             b"%s:%d at %s\x00" as *const u8
                                                 as *const libc::c_char,
                                             b"/usr/local/google/home/winniexiao/chromium/src/third_party/usrsctp/usrsctplib/usrsctplib/netinet/sctp_pcb.c\x00"
                                                 as *const u8 as
                                                 *const libc::c_char,
                                             7322i32,
                                             (*::std::mem::transmute::<&[u8; 30],
                                                                       &[libc::c_char; 30]>(b"sctp_load_addresses_from_init\x00")).as_ptr());
                                    op_err = sctp_generate_cause(
                                        system_base_info.sctpsysctl.sctp_diag_info_code as uint16_t,
                                        msg.as_mut_ptr(),
                                    );
                                    sctp_abort_an_association(
                                        (*stcb_tmp).sctp_ep,
                                        stcb_tmp,
                                        op_err,
                                        0i32,
                                    );
                                    current_block_91 = 11687017093709255301;
                                } else {
                                    pthread_mutex_unlock(&mut (*stcb_tmp).tcb_mtx);
                                    current_block_91 = 16375338222180917333;
                                }
                            } else {
                                current_block_91 = 16375338222180917333;
                            }
                            match current_block_91 {
                                11687017093709255301 => {}
                                _ => {
                                    if (*stcb).asoc.state == 0i32 {
                                        /* the assoc was freed? */
                                        return -(12i32);
                                    }
                                    return -(13i32);
                                }
                            }
                        }
                        match current_block_91 {
                            11687017093709255301 =>
                            /* we must add the source address */
                            /*
                             * no scope set since we have a tcb
                             * already
                             */
                            /*
                             * we must validate the state again
                             * here
                             */
                            {
                                if (*stcb).asoc.state == 0i32 {
                                    /* the assoc was freed? */
                                    return -(7i32);
                                }
                                if sctp_add_remote_addr(
                                    stcb,
                                    sa,
                                    0 as *mut *mut sctp_nets,
                                    port,
                                    0i32,
                                    4i32,
                                ) != 0
                                {
                                    return -(8i32);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        } else if ptype as libc::c_int == 0x6i32 {
            if (*stcb).asoc.scope.ipv6_addr_legal != 0 {
                let mut p6 = 0 as *mut sctp_ipv6addr_param;
                let mut p6_buf = sctp_ipv6addr_param {
                    ph: sctp_paramhdr {
                        param_type: 0,
                        param_length: 0,
                    },
                    addr: [0; 16],
                };
                phdr = sctp_get_next_param(
                    m,
                    offset,
                    &mut p6_buf as *mut sctp_ipv6addr_param as *mut sctp_paramhdr,
                    ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_int,
                );
                if plen as libc::c_ulong
                    != ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
                    || phdr.is_null()
                {
                    return -(14i32);
                }
                p6 = phdr as *mut sctp_ipv6addr_param;
                memcpy(
                    &mut sin6.sin6_addr as *mut in6_addr as *mut libc::c_void,
                    (*p6).addr.as_mut_ptr() as *const libc::c_void,
                    ::std::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
                );
                if !(*(&mut sin6.sin6_addr as *mut in6_addr as *const uint8_t).offset(0isize)
                    as libc::c_int
                    == 0xffi32)
                {
                    if !(({
                        let mut __a = &mut sin6.sin6_addr as *mut in6_addr as *const in6_addr;
                        ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                            == htonl(0xfe800000u32)) as libc::c_int
                    }) != 0)
                    {
                        let mut current_block_124: u64;
                        sa = &mut sin6 as *mut sockaddr_in6 as *mut sockaddr;
                        inp = (*stcb).sctp_ep;
                        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
                        stcb_tmp = sctp_findassociation_ep_addr(&mut inp, sa, &mut net, dst, stcb);
                        ::std::intrinsics::atomic_xadd(
                            &mut (*stcb).asoc.refcnt,
                            -(1i32) as uint32_t,
                        );

                        if stcb_tmp.is_null() && (inp == (*stcb).sctp_ep || inp.is_null()) {
                            current_block_124 = 5569570958636604277;
                        } else if stcb_tmp == stcb {
                            /*
                             * we must validate the state again
                             * here
                             */
                            if (*stcb).asoc.state == 0i32 {
                                /* the assoc was freed? */
                                return -(19i32);
                            }
                            if !net.is_null() {
                                /* clear flag */
                                (*net).dest_state =
                                    ((*net).dest_state as libc::c_int & !(0x10i32)) as uint16_t
                            }
                            current_block_124 = 7173345243791314703;
                        } else {
                            /*
                             * strange, address is in another
                             * assoc? straighten out locks.
                             */
                            if !stcb_tmp.is_null() {
                                if (*stcb_tmp).asoc.state & 0x7fi32 == 0x2i32 {
                                    let mut op_err_0 = 0 as *mut mbuf;
                                    let mut msg_0 = [0; 128];
                                    /* in setup state we abort this guy */
                                    snprintf(msg_0.as_mut_ptr(),
                                             ::std::mem::size_of::<[libc::c_char; 128]>()
                                                 as libc::c_ulong,
                                             b"%s:%d at %s\x00" as *const u8
                                                 as *const libc::c_char,
                                             b"/usr/local/google/home/winniexiao/chromium/src/third_party/usrsctp/usrsctplib/usrsctplib/netinet/sctp_pcb.c\x00"
                                                 as *const u8 as
                                                 *const libc::c_char,
                                             7416i32,
                                             (*::std::mem::transmute::<&[u8; 30],
                                                                       &[libc::c_char; 30]>(b"sctp_load_addresses_from_init\x00")).as_ptr());
                                    op_err_0 = sctp_generate_cause(
                                        system_base_info.sctpsysctl.sctp_diag_info_code as uint16_t,
                                        msg_0.as_mut_ptr(),
                                    );
                                    sctp_abort_an_association(
                                        (*stcb_tmp).sctp_ep,
                                        stcb_tmp,
                                        op_err_0,
                                        0i32,
                                    );
                                    current_block_124 = 5569570958636604277;
                                } else {
                                    pthread_mutex_unlock(&mut (*stcb_tmp).tcb_mtx);
                                    current_block_124 = 2704538829018177290;
                                }
                            } else {
                                current_block_124 = 2704538829018177290;
                            }
                            match current_block_124 {
                                5569570958636604277 => {}
                                _ => {
                                    if (*stcb).asoc.state == 0i32 {
                                        /* the assoc was freed? */
                                        return -(21i32);
                                    }
                                    return -(22i32);
                                }
                            }
                        }
                        match current_block_124 {
                            5569570958636604277 =>
                            /*
                             * we must validate the state again
                             * here
                             */
                            {
                                if (*stcb).asoc.state == 0i32 {
                                    /* the assoc was freed? */
                                    return -(16i32);
                                }
                                /*
                                 * we must add the address, no scope
                                 * set
                                 */
                                if sctp_add_remote_addr(
                                    stcb,
                                    sa,
                                    0 as *mut *mut sctp_nets,
                                    port,
                                    0i32,
                                    5i32,
                                ) != 0
                                {
                                    return -(17i32);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        } else if ptype as libc::c_int == 0x8000i32 {
            peer_supports_ecn = 1u8
        } else if ptype as libc::c_int == 0xc006i32 {
            if (*stcb).asoc.state != 0x8i32 {
                let mut ai = sctp_adaptation_layer_indication {
                    ph: sctp_paramhdr {
                        param_type: 0,
                        param_length: 0,
                    },
                    indication: 0,
                };
                let mut aip = 0 as *mut sctp_adaptation_layer_indication;
                phdr = sctp_get_next_param(
                    m,
                    offset,
                    &mut ai as *mut sctp_adaptation_layer_indication as *mut sctp_paramhdr,
                    ::std::mem::size_of::<sctp_adaptation_layer_indication>() as libc::c_int,
                );
                aip = phdr as *mut sctp_adaptation_layer_indication;
                if !aip.is_null() {
                    (*stcb).asoc.peers_adaptation = ntohl((*aip).indication);
                    (*stcb).asoc.adaptation_needed = 1u8
                }
            }
        } else if ptype as libc::c_int == 0xc004i32 {
            let mut lstore = sctp_asconf_addr_param {
                aph: sctp_asconf_paramhdr {
                    ph: sctp_paramhdr {
                        param_type: 0,
                        param_length: 0,
                    },
                    correlation_id: 0,
                },
                addrp: sctp_ipv6addr_param {
                    ph: sctp_paramhdr {
                        param_type: 0,
                        param_length: 0,
                    },
                    addr: [0; 16],
                },
            };
            let mut fee = 0 as *mut sctp_asconf_addr_param;
            let mut lptype = 0;
            let mut lsa = 0 as *mut sockaddr;
            if (*stcb).asoc.asconf_supported as libc::c_int == 0i32 {
                return -(100i32);
            }
            if plen as libc::c_ulong
                > ::std::mem::size_of::<sctp_asconf_addr_param>() as libc::c_ulong
            {
                return -(23i32);
            }
            if (plen as libc::c_ulong)
                < ::std::mem::size_of::<sctp_asconf_addrv4_param>() as libc::c_ulong
            {
                return -(101i32);
            }
            phdr = sctp_get_next_param(
                m,
                offset,
                &mut lstore as *mut sctp_asconf_addr_param as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return -(24i32);
            }
            fee = phdr as *mut sctp_asconf_addr_param;
            lptype = ntohs((*fee).addrp.ph.param_type) as libc::c_int;
            match lptype {
                5 => {
                    if plen as libc::c_ulong
                        != ::std::mem::size_of::<sctp_asconf_addrv4_param>() as libc::c_ulong
                    {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"Sizeof setprim in init/init ack not %d but %d - ignored\n\x00"
                                    as *const u8
                                    as *const libc::c_char,
                                ::std::mem::size_of::<sctp_asconf_addrv4_param>() as libc::c_int,
                                plen as libc::c_int,
                            );
                        }
                    } else {
                        let mut fii = 0 as *mut sctp_asconf_addrv4_param;
                        fii = fee as *mut sctp_asconf_addrv4_param;
                        sin.sin_addr.s_addr = (*fii).addrp.addr;
                        lsa = &mut sin as *mut sockaddr_in as *mut sockaddr
                    }
                }
                6 => {
                    if plen as libc::c_ulong
                        != ::std::mem::size_of::<sctp_asconf_addr_param>() as libc::c_ulong
                    {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info.debug_printf.expect("non-null function pointer")(b"Sizeof setprim (v6) in init/init ack not %d but %d - ignored\n\x00"
                                                                                                  as
                                                                                                  *const u8
                                                                                                  as
                                                                                                  *const libc::c_char,

                                                                                              ::std::mem::size_of::<sctp_asconf_addr_param>()
                                                                                                  as
                                                                                                  libc::c_int,
                                                                                              plen
                                                                                                  as
                                                                                                  libc::c_int);
                        }
                    } else {
                        memcpy(
                            sin6.sin6_addr.__in6_u.__u6_addr8.as_mut_ptr() as *mut libc::c_void,
                            (*fee).addrp.addr.as_mut_ptr() as *const libc::c_void,
                            ::std::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong,
                        );
                        lsa = &mut sin6 as *mut sockaddr_in6 as *mut sockaddr
                    }
                }
                _ => {}
            }
            if !lsa.is_null() {
                sctp_set_primary_addr(stcb, sa, 0 as *mut sctp_nets);
            }
        } else if ptype as libc::c_int == 0xc007i32 {
            (*stcb).asoc.peer_supports_nat = 1u8
        } else if ptype as libc::c_int == 0xc000i32 {
            /* Peer supports pr-sctp */
            peer_supports_prsctp = 1u8
        } else if ptype as libc::c_int == 0x8008i32 {
            let mut pr_supported = 0 as *mut sctp_supported_chunk_types_param;
            let mut local_store = [0u8; 512];
            let mut num_ent = 0;
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                return -(35i32);
            }
            phdr = sctp_get_next_param(
                m,
                offset,
                &mut local_store as *mut [uint8_t; 512] as *mut sctp_paramhdr,
                plen as libc::c_int,
            );
            if phdr.is_null() {
                return -(25i32);
            }
            pr_supported = phdr as *mut sctp_supported_chunk_types_param;
            num_ent = (plen as libc::c_ulong)
                .wrapping_sub(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
                as libc::c_int;

            for i in 0i32..num_ent {
                match *(*pr_supported).chunk_types.as_mut_ptr().offset(i as isize) as libc::c_int {
                    193 => peer_supports_asconf = 1u8,
                    128 => peer_supports_asconf_ack = 1u8,
                    192 => peer_supports_prsctp = 1u8,
                    129 => peer_supports_pktdrop = 1u8,
                    16 => peer_supports_nrsack = 1u8,
                    130 => peer_supports_reconfig = 1u8,
                    15 => peer_supports_auth = 1u8,
                    64 => peer_supports_idata = 1u8,
                    _ => {}
                }
            }
        } else if ptype as libc::c_int == 0x8002i32 {
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                break;
            }
            if !(got_random != 0) {
                let mut random_store = [0; 512];
                phdr = sctp_get_next_param(
                    m,
                    offset,
                    random_store.as_mut_ptr() as *mut sctp_paramhdr,
                    plen as libc::c_int,
                );
                if phdr.is_null() {
                    return -(26i32);
                }
                p_random = phdr as *mut sctp_auth_random;
                random_len = (plen as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<sctp_auth_random>() as libc::c_ulong)
                    as uint16_t;
                /* enforce the random length */
                if random_len as libc::c_int != 32i32 {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x400u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"SCTP: invalid RANDOM len\n\x00" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    }
                    return -(27i32);
                }
                got_random = 1i32
            }
        } else if ptype as libc::c_int == 0x8004i32 {
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                break;
            }
            if !(got_hmacs != 0) {
                let mut hmacs_store = [0; 512];
                let mut num_hmacs = 0;
                phdr = sctp_get_next_param(
                    m,
                    offset,
                    hmacs_store.as_mut_ptr() as *mut sctp_paramhdr,
                    plen as libc::c_int,
                );
                if phdr.is_null() {
                    return -(28i32);
                }
                hmacs = phdr as *mut sctp_auth_hmac_algo;
                hmacs_len = (plen as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<sctp_auth_hmac_algo>() as libc::c_ulong)
                    as uint16_t;
                num_hmacs = (hmacs_len as libc::c_ulong)
                    .wrapping_div(::std::mem::size_of::<uint16_t>() as libc::c_ulong)
                    as uint16_t;
                /* validate the hmac list */
                if sctp_verify_hmac_param(hmacs, num_hmacs as uint32_t) != 0 {
                    return -(29i32);
                }
                if !(*stcb).asoc.peer_hmacs.is_null() {
                    sctp_free_hmaclist((*stcb).asoc.peer_hmacs);
                }
                (*stcb).asoc.peer_hmacs = sctp_alloc_hmaclist(num_hmacs);
                if !(*stcb).asoc.peer_hmacs.is_null() {
                    let mut i_0 = 0;
                    i_0 = 0u16;
                    while (i_0 as libc::c_int) < num_hmacs as libc::c_int {
                        sctp_auth_add_hmacid(
                            (*stcb).asoc.peer_hmacs,
                            ntohs(*(*hmacs).hmac_ids.as_mut_ptr().offset(i_0 as isize)),
                        );
                        i_0 = i_0.wrapping_add(1)
                    }
                }
                got_hmacs = 1i32
            }
        } else if ptype as libc::c_int == 0x8003i32 {
            if plen as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong {
                break;
            }
            if !(got_chklist != 0) {
                let mut chunks_store = [0; 512];
                phdr = sctp_get_next_param(
                    m,
                    offset,
                    chunks_store.as_mut_ptr() as *mut sctp_paramhdr,
                    plen as libc::c_int,
                );
                if phdr.is_null() {
                    return -(30i32);
                }
                chunks = phdr as *mut sctp_auth_chunk_list;
                num_chunks = (plen as libc::c_ulong)
                    .wrapping_sub(::std::mem::size_of::<sctp_auth_chunk_list>() as libc::c_ulong)
                    as uint16_t;
                if !(*stcb).asoc.peer_auth_chunks.is_null() {
                    sctp_clear_chunklist((*stcb).asoc.peer_auth_chunks);
                } else {
                    (*stcb).asoc.peer_auth_chunks = sctp_alloc_chunklist()
                }

                for i_1 in 0i32..num_chunks as libc::c_int {
                    sctp_auth_add_chunk(
                        *(*chunks).chunk_types.as_mut_ptr().offset(i_1 as isize),
                        (*stcb).asoc.peer_auth_chunks,
                    );
                    /* record asconf/asconf-ack if listed */
                    if *(*chunks).chunk_types.as_mut_ptr().offset(i_1 as isize) as libc::c_int
                        == 0xc1i32
                    {
                        saw_asconf = 1u8
                    }

                    if *(*chunks).chunk_types.as_mut_ptr().offset(i_1 as isize) as libc::c_int
                        == 0x80i32
                    {
                        saw_asconf_ack = 1u8
                    }
                }
                got_chklist = 1i32
            }
        } else if !(ptype as libc::c_int == 0x1i32
            || ptype as libc::c_int == 0x7i32
            || ptype as libc::c_int == 0x8i32
            || ptype as libc::c_int == 0x9i32
            || ptype as libc::c_int == 0xci32
            || ptype as libc::c_int == 0xc001i32
            || ptype as libc::c_int == 0xc002i32
            || ptype as libc::c_int == 0xc003i32
            || ptype as libc::c_int == 0xc005i32)
        {
            if ptype as libc::c_int & 0x8000i32 == 0i32 {
                break;
            }
        }
        /* don't care */
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
    /*
     * must stop processing the rest of the
     * param's. Any report bits were handled
     * with the call to
     * sctp_arethere_unrecognized_parameters()
     * when the INIT or INIT-ACK was first seen.
     */
    /* Now check to see if we need to purge any addresses */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() && {
        nnet = (*net).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if (*net).dest_state as libc::c_int & 0x10i32 == 0x10i32 {
            /* This address has been removed from the asoc */
            /* remove and free it */
            (*stcb).asoc.numnets = (*stcb).asoc.numnets.wrapping_sub(1);
            if !(*net).sctp_next.tqe_next.is_null() {
                (*(*net).sctp_next.tqe_next).sctp_next.tqe_prev = (*net).sctp_next.tqe_prev
            } else {
                (*stcb).asoc.nets.tqh_last = (*net).sctp_next.tqe_prev
            }
            *(*net).sctp_next.tqe_prev = (*net).sctp_next.tqe_next;
            if !net.is_null() {
                if ::std::intrinsics::atomic_xadd(
                    &mut (*net).ref_count as *mut libc::c_int,
                    -(1i32),
                ) == 1i32
                {
                    sctp_os_timer_stop(&mut (*net).rxt_timer.timer);
                    sctp_os_timer_stop(&mut (*net).pmtu_timer.timer);
                    sctp_os_timer_stop(&mut (*net).hb_timer.timer);
                    if !(*net).ro.ro_rt.is_null() {
                        if (*(*net).ro.ro_rt).rt_refcnt <= 1i64 {
                            sctp_userspace_rtfree((*net).ro.ro_rt);
                        } else {
                            (*(*net).ro.ro_rt).rt_refcnt -= 1
                        }
                        (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t;
                        (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t
                    }
                    if (*net).src_addr_selected != 0 {
                        sctp_free_ifa((*net).ro._s_addr);
                        (*net).ro._s_addr = 0 as *mut sctp_ifa
                    }
                    (*net).src_addr_selected = 0u8;
                    (*net).dest_state = ((*net).dest_state as libc::c_int & !(0x1i32)) as uint16_t;
                    free(net as *mut libc::c_void);
                    ::std::intrinsics::atomic_xsub(
                        &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                        1u32,
                    );
                }
            }
            if net == (*stcb).asoc.primary_destination {
                (*stcb).asoc.primary_destination = 0 as *mut sctp_nets;
                sctp_select_primary_destination(stcb);
            }
        }
        net = nnet
    }
    if (*stcb).asoc.ecn_supported as libc::c_int == 1i32 && peer_supports_ecn as libc::c_int == 0i32
    {
        (*stcb).asoc.ecn_supported = 0u8
    }
    if (*stcb).asoc.prsctp_supported as libc::c_int == 1i32
        && peer_supports_prsctp as libc::c_int == 0i32
    {
        (*stcb).asoc.prsctp_supported = 0u8
    }
    if (*stcb).asoc.auth_supported as libc::c_int == 1i32
        && (peer_supports_auth as libc::c_int == 0i32 || got_random == 0i32 || got_hmacs == 0i32)
    {
        (*stcb).asoc.auth_supported = 0u8
    }
    if (*stcb).asoc.asconf_supported as libc::c_int == 1i32
        && (peer_supports_asconf as libc::c_int == 0i32
            || peer_supports_asconf_ack as libc::c_int == 0i32
            || (*stcb).asoc.auth_supported as libc::c_int == 0i32
            || saw_asconf as libc::c_int == 0i32
            || saw_asconf_ack as libc::c_int == 0i32)
    {
        (*stcb).asoc.asconf_supported = 0u8
    }
    if (*stcb).asoc.reconfig_supported as libc::c_int == 1i32
        && peer_supports_reconfig as libc::c_int == 0i32
    {
        (*stcb).asoc.reconfig_supported = 0u8
    }
    if (*stcb).asoc.idata_supported as libc::c_int == 1i32
        && peer_supports_idata as libc::c_int == 0i32
    {
        (*stcb).asoc.idata_supported = 0u8
    }
    if (*stcb).asoc.nrsack_supported as libc::c_int == 1i32
        && peer_supports_nrsack as libc::c_int == 0i32
    {
        (*stcb).asoc.nrsack_supported = 0u8
    }
    if (*stcb).asoc.pktdrop_supported as libc::c_int == 1i32
        && peer_supports_pktdrop as libc::c_int == 0i32
    {
        (*stcb).asoc.pktdrop_supported = 0u8
    }
    /* validate authentication required parameters */
    if peer_supports_auth as libc::c_int == 0i32 && got_chklist == 1i32 {
        /* peer does not support auth but sent a chunks list? */
        return -(31i32);
    }
    if peer_supports_asconf as libc::c_int == 1i32 && peer_supports_auth as libc::c_int == 0i32 {
        /* peer supports asconf but not auth? */
        return -(32i32);
    } else {
        if peer_supports_asconf as libc::c_int == 1i32
            && peer_supports_auth as libc::c_int == 1i32
            && (saw_asconf as libc::c_int == 0i32 || saw_asconf_ack as libc::c_int == 0i32)
        {
            return -(33i32);
        }
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
    } else {
        /* failed to get memory for the key */
        return -(34i32);
    }
    if !(*stcb).asoc.authinfo.peer_random.is_null() {
        sctp_free_key((*stcb).asoc.authinfo.peer_random);
    }
    (*stcb).asoc.authinfo.peer_random = new_key;
    sctp_clear_cachedkeys(stcb, (*stcb).asoc.authinfo.assoc_keyid);
    sctp_clear_cachedkeys(stcb, (*stcb).asoc.authinfo.recv_keyid);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_set_primary_addr(
    mut stcb: *mut sctp_tcb,
    mut sa: *mut sockaddr,
    mut net: *mut sctp_nets,
) -> libc::c_int {
    /* make sure the requested primary address exists in the assoc */
    if net.is_null() && !sa.is_null() {
        net = sctp_findnet(stcb, sa)
    }
    if net.is_null() {
        /* didn't find the requested primary address! */
        return -(1i32);
    } else {
        /* set the primary address */
        if (*net).dest_state as libc::c_int & 0x200i32 != 0 {
            /* Must be confirmed, so queue to set */
            (*net).dest_state = ((*net).dest_state as libc::c_int | 0x400i32) as uint16_t;
            return 0i32;
        }
        (*stcb).asoc.primary_destination = net;
        if (*net).dest_state as libc::c_int & 0x800i32 == 0 && !(*stcb).asoc.alternate.is_null() {
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
            (*stcb).asoc.alternate = 0 as *mut sctp_nets
        }
        net = (*stcb).asoc.nets.tqh_first;
        if net != (*stcb).asoc.primary_destination {
            /* first one on the list is NOT the primary
             * sctp_cmpaddr() is much more efficient if
             * the primary is the first on the list, make it
             * so.
             */
            if !(*(*stcb).asoc.primary_destination)
                .sctp_next
                .tqe_next
                .is_null()
            {
                (*(*(*stcb).asoc.primary_destination).sctp_next.tqe_next)
                    .sctp_next
                    .tqe_prev = (*(*stcb).asoc.primary_destination).sctp_next.tqe_prev
            } else {
                (*stcb).asoc.nets.tqh_last = (*(*stcb).asoc.primary_destination).sctp_next.tqe_prev
            }
            *(*(*stcb).asoc.primary_destination).sctp_next.tqe_prev =
                (*(*stcb).asoc.primary_destination).sctp_next.tqe_next;
            (*(*stcb).asoc.primary_destination).sctp_next.tqe_next = (*stcb).asoc.nets.tqh_first;
            if !(*(*stcb).asoc.primary_destination)
                .sctp_next
                .tqe_next
                .is_null()
            {
                (*(*stcb).asoc.nets.tqh_first).sctp_next.tqe_prev =
                    &mut (*(*stcb).asoc.primary_destination).sctp_next.tqe_next
            } else {
                (*stcb).asoc.nets.tqh_last =
                    &mut (*(*stcb).asoc.primary_destination).sctp_next.tqe_next
            }
            (*stcb).asoc.nets.tqh_first = (*stcb).asoc.primary_destination;
            (*(*stcb).asoc.primary_destination).sctp_next.tqe_prev =
                &mut (*stcb).asoc.nets.tqh_first
        }
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_is_vtag_good(
    mut tag: uint32_t,
    mut lport: uint16_t,
    mut rport: uint16_t,
    mut now: *mut timeval,
) -> libc::c_int {
    let mut chain = 0 as *mut sctpvtaghead;
    let mut twait_block = 0 as *mut sctp_tagblock;
    let mut head = 0 as *mut sctpasochead;
    let mut stcb = 0 as *mut sctp_tcb;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    head = &mut *system_base_info
        .sctppcbinfo
        .sctp_asochash
        .offset((tag as libc::c_ulong & system_base_info.sctppcbinfo.hashasocmark) as isize)
        as *mut sctpasochead;
    stcb = (*head).lh_first;
    while !stcb.is_null() {
        /* We choose not to lock anything here. TCB's can't be
         * removed since we have the read lock, so they can't
         * be freed on us, same thing for the INP. I may
         * be wrong with this assumption, but we will go
         * with it for now :-)
         */
        if !((*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0) {
            if (*stcb).asoc.my_vtag == tag {
                /* candidate */
                if !((*stcb).rport as libc::c_int != rport as libc::c_int) {
                    if !((*(*stcb).sctp_ep).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int
                        != lport as libc::c_int)
                    {
                        /* Its a used tag set */
                        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                        return 0i32;
                    }
                }
            }
        }
        stcb = (*stcb).sctp_asocs.le_next
    }
    chain = &mut *system_base_info
        .sctppcbinfo
        .vtag_timewait
        .as_mut_ptr()
        .offset(tag.wrapping_rem(32u32) as isize) as *mut sctpvtaghead;
    /* Now what about timed wait ? */
    twait_block = (*chain).lh_first;
    while !twait_block.is_null() {
        for i in 0i32..15i32 {
            if !((*twait_block).vtag_block[i as usize].v_tag == 0u32) {
                if ((*twait_block).vtag_block[i as usize].tv_sec_at_expire as libc::c_long)
                    < (*now).tv_sec
                {
                    /* Audit expires this guy */
                    (*twait_block).vtag_block[i as usize].tv_sec_at_expire = 0u32;
                    (*twait_block).vtag_block[i as usize].v_tag = 0u32;
                    (*twait_block).vtag_block[i as usize].lport = 0u16;
                    (*twait_block).vtag_block[i as usize].rport = 0u16
                } else if (*twait_block).vtag_block[i as usize].v_tag == tag
                    && (*twait_block).vtag_block[i as usize].lport as libc::c_int
                        == lport as libc::c_int
                    && (*twait_block).vtag_block[i as usize].rport as libc::c_int
                        == rport as libc::c_int
                {
                    /* Bad tag, sorry :< */
                    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                    return 0i32;
                }
            }
        }
        twait_block = (*twait_block).sctp_nxt_tagblock.le_next
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    return 1i32;
}
unsafe extern "C" fn sctp_drain_mbufs(mut stcb: *mut sctp_tcb) {
    let mut asoc = 0 as *mut sctp_association;
    let mut cumulative_tsn_p1 = 0;
    let mut cnt = 0;
    let mut gap = 0;
    /* We look for anything larger than the cum-ack + 1 */
    asoc = &mut (*stcb).asoc;
    if (*asoc).cumulative_tsn == (*asoc).highest_tsn_inside_map {
        /* none we can reneg on. */
        return;
    }
    ::std::intrinsics::atomic_xadd(
        &mut system_base_info.sctpstat.sctps_protocol_drains_done,
        1u32,
    );
    cumulative_tsn_p1 = (*asoc).cumulative_tsn.wrapping_add(1u32);
    cnt = 0i32;

    for strmat in 0i32..(*asoc).streamincnt as libc::c_int {
        let mut chk = 0 as *mut sctp_tmit_chunk;
        let mut nchk = 0 as *mut sctp_tmit_chunk;
        let mut control = 0 as *mut sctp_queued_to_read;
        let mut ncontrol = 0 as *mut sctp_queued_to_read;
        control = (*(*asoc).strmin.offset(strmat as isize)).inqueue.tqh_first;

        while !control.is_null() && {
            ncontrol = (*control).next_instrm.tqe_next;
            (1i32) != 0
        } {
            if (*control).sinfo_tsn < cumulative_tsn_p1
                && cumulative_tsn_p1.wrapping_sub((*control).sinfo_tsn) > (1u32) << 31i32
                || (*control).sinfo_tsn > cumulative_tsn_p1
                    && (*control).sinfo_tsn.wrapping_sub(cumulative_tsn_p1) < (1u32) << 31i32
            {
                /* Yep it is above cum-ack */
                cnt += 1;
                if (*control).sinfo_tsn >= (*asoc).mapping_array_base_tsn {
                    gap = (*control)
                        .sinfo_tsn
                        .wrapping_sub((*asoc).mapping_array_base_tsn)
                } else {
                    gap = (0xffffffffu32)
                        .wrapping_sub((*asoc).mapping_array_base_tsn)
                        .wrapping_add((*control).sinfo_tsn)
                        .wrapping_add(1u32)
                }
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
                let ref mut fresh2 = *(*asoc).mapping_array.offset((gap >> 3i32) as isize);
                *fresh2 =
                    (*fresh2 as libc::c_int & (!((0x1i32) << (gap & 0x7u32)) & 0xffi32)) as uint8_t;
                if (*control).on_read_q != 0 {
                    if !(*control).next.tqe_next.is_null() {
                        (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
                    } else {
                        (*(*stcb).sctp_ep).read_queue.tqh_last = (*control).next.tqe_prev
                    }
                    *(*control).next.tqe_prev = (*control).next.tqe_next;
                    (*control).on_read_q = 0u8
                }
                if !(*control).next_instrm.tqe_next.is_null() {
                    (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                        (*control).next_instrm.tqe_prev
                } else {
                    let ref mut fresh3 = (*(*asoc).strmin.offset(strmat as isize)).inqueue.tqh_last;
                    *fresh3 = (*control).next_instrm.tqe_prev
                }
                *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                (*control).on_strm_q = 0u8;
                if !(*control).data.is_null() {
                    m_freem((*control).data);
                    (*control).data = 0 as *mut mbuf
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
                            ((*(*control).whoFrom).dest_state as libc::c_int & !(0x1i32))
                                as uint16_t;
                        free((*control).whoFrom as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                            1u32,
                        );
                    }
                }
                /* Now its reasm? */
                chk = (*control).reasm.tqh_first;
                while !chk.is_null() && {
                    nchk = (*chk).sctp_next.tqe_next;
                    (1i32) != 0
                } {
                    cnt += 1;
                    if (*chk).rec.data.tsn >= (*asoc).mapping_array_base_tsn {
                        gap = (*chk)
                            .rec
                            .data
                            .tsn
                            .wrapping_sub((*asoc).mapping_array_base_tsn)
                    } else {
                        gap = (0xffffffffu32)
                            .wrapping_sub((*asoc).mapping_array_base_tsn)
                            .wrapping_add((*chk).rec.data.tsn)
                            .wrapping_add(1u32)
                    }
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
                    let ref mut fresh4 = *(*asoc).mapping_array.offset((gap >> 3i32) as isize);
                    *fresh4 = (*fresh4 as libc::c_int & (!((0x1i32) << (gap & 0x7u32)) & 0xffi32))
                        as uint8_t;
                    if !(*chk).sctp_next.tqe_next.is_null() {
                        (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
                    } else {
                        (*control).reasm.tqh_last = (*chk).sctp_next.tqe_prev
                    }
                    *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
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
                            (*stcb).asoc.free_chunk_cnt =
                                (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
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
                    chk = nchk
                }
                free(control as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_readq,
                    1u32,
                );
            }
            control = ncontrol
        }

        control = (*(*asoc).strmin.offset(strmat as isize))
            .uno_inqueue
            .tqh_first;

        while !control.is_null() && {
            ncontrol = (*control).next_instrm.tqe_next;
            (1i32) != 0
        } {
            if (*control).sinfo_tsn < cumulative_tsn_p1
                && cumulative_tsn_p1.wrapping_sub((*control).sinfo_tsn) > (1u32) << 31i32
                || (*control).sinfo_tsn > cumulative_tsn_p1
                    && (*control).sinfo_tsn.wrapping_sub(cumulative_tsn_p1) < (1u32) << 31i32
            {
                /* Yep it is above cum-ack */
                cnt += 1;
                if (*control).sinfo_tsn >= (*asoc).mapping_array_base_tsn {
                    gap = (*control)
                        .sinfo_tsn
                        .wrapping_sub((*asoc).mapping_array_base_tsn)
                } else {
                    gap = (0xffffffffu32)
                        .wrapping_sub((*asoc).mapping_array_base_tsn)
                        .wrapping_add((*control).sinfo_tsn)
                        .wrapping_add(1u32)
                }
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
                let ref mut fresh5 = *(*asoc).mapping_array.offset((gap >> 3i32) as isize);
                *fresh5 =
                    (*fresh5 as libc::c_int & (!((0x1i32) << (gap & 0x7u32)) & 0xffi32)) as uint8_t;
                if (*control).on_read_q != 0 {
                    if !(*control).next.tqe_next.is_null() {
                        (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
                    } else {
                        (*(*stcb).sctp_ep).read_queue.tqh_last = (*control).next.tqe_prev
                    }
                    *(*control).next.tqe_prev = (*control).next.tqe_next;
                    (*control).on_read_q = 0u8
                }
                if !(*control).next_instrm.tqe_next.is_null() {
                    (*(*control).next_instrm.tqe_next).next_instrm.tqe_prev =
                        (*control).next_instrm.tqe_prev
                } else {
                    let ref mut fresh6 = (*(*asoc).strmin.offset(strmat as isize))
                        .uno_inqueue
                        .tqh_last;
                    *fresh6 = (*control).next_instrm.tqe_prev
                }
                *(*control).next_instrm.tqe_prev = (*control).next_instrm.tqe_next;
                (*control).on_strm_q = 0u8;
                if !(*control).data.is_null() {
                    m_freem((*control).data);
                    (*control).data = 0 as *mut mbuf
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
                            ((*(*control).whoFrom).dest_state as libc::c_int & !(0x1i32))
                                as uint16_t;
                        free((*control).whoFrom as *mut libc::c_void);
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                            1u32,
                        );
                    }
                }
                /* Now its reasm? */
                chk = (*control).reasm.tqh_first;
                while !chk.is_null() && {
                    nchk = (*chk).sctp_next.tqe_next;
                    (1i32) != 0
                } {
                    cnt += 1;
                    if (*chk).rec.data.tsn >= (*asoc).mapping_array_base_tsn {
                        gap = (*chk)
                            .rec
                            .data
                            .tsn
                            .wrapping_sub((*asoc).mapping_array_base_tsn)
                    } else {
                        gap = (0xffffffffu32)
                            .wrapping_sub((*asoc).mapping_array_base_tsn)
                            .wrapping_add((*chk).rec.data.tsn)
                            .wrapping_add(1u32)
                    }
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
                    let ref mut fresh7 = *(*asoc).mapping_array.offset((gap >> 3i32) as isize);
                    *fresh7 = (*fresh7 as libc::c_int & (!((0x1i32) << (gap & 0x7u32)) & 0xffi32))
                        as uint8_t;
                    if !(*chk).sctp_next.tqe_next.is_null() {
                        (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
                    } else {
                        (*control).reasm.tqh_last = (*chk).sctp_next.tqe_prev
                    }
                    *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
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
                            (*stcb).asoc.free_chunk_cnt =
                                (*stcb).asoc.free_chunk_cnt.wrapping_add(1);
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
                    chk = nchk
                }
                free(control as *mut libc::c_void);
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctppcbinfo.ipi_count_readq,
                    1u32,
                );
            }
            control = ncontrol
        }
    }
    if cnt != 0 {
        let mut i = 0;
        let mut fnd = 0i32;
        i = (*asoc).highest_tsn_inside_map;
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
        /*
         * Question, should we go through the delivery queue? The only
         * reason things are on here is the app not reading OR a p-d-api up.
         * An attacker COULD send enough in to initiate the PD-API and then
         * send a bunch of stuff to other streams... these would wind up on
         * the delivery queue.. and then we would not get to them. But in
         * order to do this I then have to back-track and un-deliver
         * sequence numbers in streams.. el-yucko. I think for now we will
         * NOT look at the delivery queue and leave it to be something to
         * consider later. An alternative would be to abort the P-D-API with
         * a notification and then deliver the data.... Or another method
         * might be to keep track of how many times the situation occurs and
         * if we see a possible attack underway just abort the association.
         */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Freed %d chunks from reneg harvest\n\x00" as *const u8 as *const libc::c_char,
                    cnt,
                );
            }
        }
        /*
         * Now do we need to find a new
         * asoc->highest_tsn_inside_map?
         */
        (*asoc).last_revoke_count = cnt as uint16_t;
        sctp_os_timer_stop(&mut (*stcb).asoc.dack_timer.timer);
        /*sa_ignore NO_NULL_CHK*/
        sctp_send_sack(stcb, 0i32);
        sctp_chunk_output((*stcb).sctp_ep, stcb, 15i32, 0i32);
    };
    /*
     * Another issue, in un-setting the TSN's in the mapping array we
     * DID NOT adjust the highest_tsn marker.  This will cause one of two
     * things to occur. It may cause us to do extra work in checking for
     * our mapping array movement. More importantly it may cause us to
     * SACK every datagram. This may not be a bad thing though since we
     * will recover once we get our cum-ack above and all this stuff we
     * dumped recovered.
     */
}
#[no_mangle]
pub unsafe extern "C" fn sctp_drain() {
    let mut inp = 0 as *mut sctp_inpcb;
    ::std::intrinsics::atomic_xadd(
        &mut system_base_info.sctpstat.sctps_protocol_drain_calls,
        1u32,
    );
    if system_base_info.sctpsysctl.sctp_do_drain == 0u32 {
        return;
    }
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    inp = system_base_info.sctppcbinfo.listhead.lh_first;
    while !inp.is_null() {
        let mut stcb = 0 as *mut sctp_tcb;
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        stcb = (*inp).sctp_asoc_list.lh_first;
        while !stcb.is_null() {
            /* For each association */
            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
            sctp_drain_mbufs(stcb);
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            stcb = (*stcb).sctp_tcblist.le_next
        }
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        inp = (*inp).sctp_list.le_next
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
}
/*-
 * Null in last arg inpcb indicate run on ALL ep's. Specific inp in last arg
 * indicates run on ONLY assoc's of the specified endpoint.
 */
/*
 * start a new iterator
 * iterates through all endpoints and associations based on the pcb_state
 * flags and asoc_state.  "af" (mandatory) is executed for all matching
 * assocs and "ef" (optional) is executed when the iterator completes.
 * "inpf" (optional) is executed for each new endpoint as it is being
 * iterated through. inpe (optional) is called when the inp completes
 * its way through all the stcbs.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_initiate_iterator(
    mut inpf: inp_func,
    mut af: asoc_func,
    mut inpe: inp_func,
    mut pcb_state: uint32_t,
    mut pcb_features: uint32_t,
    mut asoc_state: uint32_t,
    mut argp: *mut libc::c_void,
    mut argi: uint32_t,
    mut ef: end_func,
    mut s_inp: *mut sctp_inpcb,
    mut chunk_output_off: uint8_t,
) -> libc::c_int {
    let mut it = 0 as *mut sctp_iterator;
    if af.is_none() {
        return -(1i32);
    }
    if system_base_info.sctp_pcb_initialized as libc::c_int == 0i32 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%s: abort on initialize being %d\n\x00" as *const u8 as *const libc::c_char,
                (*::std::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"sctp_initiate_iterator\x00",
                ))
                .as_ptr(),
                system_base_info.sctp_pcb_initialized as libc::c_int,
            );
        }
        return -(1i32);
    }
    it = malloc(::std::mem::size_of::<sctp_iterator>() as libc::c_ulong) as *mut sctp_iterator;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            it as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_iterator>() as libc::c_ulong,
        );
    }
    if it.is_null() {
        return -(1i32);
    }
    memset(
        it as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_iterator>() as libc::c_ulong,
    );
    (*it).function_assoc = af;
    (*it).function_inp = inpf;
    if inpf.is_some() {
        (*it).done_current_ep = 0u8
    } else {
        (*it).done_current_ep = 1u8
    }
    (*it).function_atend = ef;
    (*it).pointer = argp;
    (*it).val = argi;
    (*it).pcb_flags = pcb_state;
    (*it).pcb_features = pcb_features;
    (*it).asoc_state = asoc_state;
    (*it).function_inp_end = inpe;
    (*it).no_chunk_output = chunk_output_off;
    if !s_inp.is_null() {
        /* Assume lock is held here */
        (*it).inp = s_inp;
        ::std::intrinsics::atomic_xadd(&mut (*(*it).inp).refcount, 1i32);
        (*it).iterator_flags = 0x2u32
    } else {
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        (*it).inp = system_base_info.sctppcbinfo.listhead.lh_first;
        if !(*it).inp.is_null() {
            ::std::intrinsics::atomic_xadd(&mut (*(*it).inp).refcount, 1i32);
        }
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
        (*it).iterator_flags = 0x1u32
    }
    pthread_mutex_lock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    if system_base_info.sctp_pcb_initialized as libc::c_int == 0i32 {
        pthread_mutex_unlock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%s: rollback on initialize being %d it=%p\n\x00" as *const u8
                    as *const libc::c_char,
                (*::std::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"sctp_initiate_iterator\x00",
                ))
                .as_ptr(),
                system_base_info.sctp_pcb_initialized as libc::c_int,
                it,
            );
        }
        free(it as *mut libc::c_void);
        return -(1i32);
    }
    (*it).sctp_nxt_itr.tqe_next = 0 as *mut sctp_iterator;
    (*it).sctp_nxt_itr.tqe_prev = sctp_it_ctl.iteratorhead.tqh_last;
    *sctp_it_ctl.iteratorhead.tqh_last = it;
    sctp_it_ctl.iteratorhead.tqh_last = &mut (*it).sctp_nxt_itr.tqe_next;
    if sctp_it_ctl.iterator_running == 0u32 {
        sctp_wakeup_iterator();
    }
    pthread_mutex_unlock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
    /* sa_ignore MEMLEAK {memory is put on the tailq for the iterator} */
    return 0i32;
}
