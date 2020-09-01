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
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    /*CONSTCOND*/
    /*
     * Global accept mutex to serialize access to accept queues and
     * fields associated with multiple sockets.  This allows us to
     * avoid defining a lock order between listen and accept sockets
     * until such time as it proves to be a good idea.
     */
    #[no_mangle]
    static mut accept_mtx: userland_mutex_t;
    #[no_mangle]
    fn socantrcvmore(so: *mut socket);
    #[no_mangle]
    fn socantsendmore(so: *mut socket);
    #[no_mangle]
    fn sofree(so: *mut socket);
    #[no_mangle]
    fn sowakeup(so: *mut socket, sb: *mut sockbuf);
    /*__Userspace__ */
    #[no_mangle]
    fn uiomove(cp: *mut libc::c_void, n: libc::c_int, uio: *mut uio) -> libc::c_int;
    #[no_mangle]
    fn sbwait(sb: *mut sockbuf) -> libc::c_int;
    /* int hz; is declared in sys/kern/subr_param.c and refers to kernel timer frequency.
     * See http://ivoras.sharanet.org/freebsd/vmware.html for additional info about kern.hz
     * hz is initialized in void init_param1(void) in that file.
     */
    #[no_mangle]
    static mut hz: libc::c_int;
    #[no_mangle]
    fn m_free(m: *mut mbuf) -> *mut mbuf;
    #[no_mangle]
    fn m_adj(_: *mut mbuf, _: libc::c_int);
    #[no_mangle]
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn m_copydata(_: *const mbuf, _: libc::c_int, _: libc::c_int, _: caddr_t);
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn sctp_get_tick_count() -> uint32_t;
    #[no_mangle]
    fn sctp_os_timer_start(
        _: *mut sctp_os_timer_t,
        _: uint32_t,
        _: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
        _: *mut libc::c_void,
    );
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
    /* TODO where to put non-_KERNEL things for __Userspace__? */
    /* Attention Julian, this is the extern that
     * goes with the base info. sctp_pcb.c has
     * the real definition.
     */
    #[no_mangle]
    fn SCTP6_ARE_ADDR_EQUAL(a: *mut sockaddr_in6, b: *mut sockaddr_in6) -> libc::c_int;
    #[no_mangle]
    fn sctp_find_vrf(vrfid: uint32_t) -> *mut sctp_vrf;
    #[no_mangle]
    fn sctp_pcb_findep(
        _: *mut sockaddr,
        _: libc::c_int,
        _: libc::c_int,
        _: uint32_t,
    ) -> *mut sctp_inpcb;
    /* struct proc is a dummy for __Userspace__ */
    #[no_mangle]
    fn sctp_inpcb_bind(
        _: *mut socket,
        _: *mut sockaddr,
        _: *mut sctp_ifa,
        _: *mut proc_0,
    ) -> libc::c_int;
    /*-
     * For this call ep_addr, the to is the destination endpoint address of the
     * peer (relative to outbound). The from field is only used if the TCP model
     * is enabled and helps distingush amongst the subset bound (non-boundall).
     * The TCP model MAY change the actual ep field, this is why it is passed.
     */
    #[no_mangle]
    fn sctp_findassociation_ep_addr(
        _: *mut *mut sctp_inpcb,
        _: *mut sockaddr,
        _: *mut *mut sctp_nets,
        _: *mut sockaddr,
        _: *mut sctp_tcb,
    ) -> *mut sctp_tcb;
    #[no_mangle]
    fn sctp_inpcb_free(_: *mut sctp_inpcb, _: libc::c_int, _: libc::c_int);
    #[no_mangle]
    fn sctp_free_assoc(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_add_remote_addr(
        _: *mut sctp_tcb,
        _: *mut sockaddr,
        _: *mut *mut sctp_nets,
        _: uint16_t,
        _: libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_is_vtag_good(
        _: uint32_t,
        lport: uint16_t,
        rport: uint16_t,
        _: *mut timeval,
    ) -> libc::c_int;
    /*-
     * Null in last arg inpcb indicate run on ALL ep's. Specific inp in last arg
     * indicates run on ONLY assoc's of the specified endpoint.
     */
    #[no_mangle]
    fn sctp_initiate_iterator(
        inpf: inp_func,
        af: asoc_func,
        inpe: inp_func,
        _: uint32_t,
        _: uint32_t,
        _: uint32_t,
        _: *mut libc::c_void,
        _: uint32_t,
        ef: end_func,
        _: *mut sctp_inpcb,
        co_off: uint8_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_hmac(
        hmac_algo: uint16_t,
        key: *mut uint8_t,
        keylen: uint32_t,
        text: *mut uint8_t,
        textlen: uint32_t,
        digest: *mut uint8_t,
    ) -> uint32_t;
    #[no_mangle]
    fn sctp_auth_key_release(stcb: *mut sctp_tcb, keyid: uint16_t, so_locked: libc::c_int);
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_free_ifa(sctp_ifap: *mut sctp_ifa);
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_notify_authentication(
        stcb: *mut sctp_tcb,
        indication: uint32_t,
        keyid: uint16_t,
        alt_keyid: uint16_t,
        so_locked: libc::c_int,
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
    fn in6_sin6_2_sin(_: *mut sockaddr_in, _: *mut sockaddr_in6);
    #[no_mangle]
    fn in6_sin_2_v4mapsin6(_: *const sockaddr_in, _: *mut sockaddr_in6);
    #[no_mangle]
    fn sctp_is_addr_restricted(_: *mut sctp_tcb, _: *mut sctp_ifa) -> libc::c_int;
    #[no_mangle]
    fn sctp_send_shutdown_complete2(
        _: *mut sockaddr,
        _: *mut sockaddr,
        _: *mut sctphdr,
        _: uint32_t,
        _: uint16_t,
    );
    #[no_mangle]
    fn sctp_fix_ecn_echo(_: *mut sctp_association);
    #[no_mangle]
    fn sctp_chunk_output(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: libc::c_int, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_abort_tcb(_: *mut sctp_tcb, _: *mut mbuf, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_sack(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_abort(
        _: *mut mbuf,
        _: libc::c_int,
        _: *mut sockaddr,
        _: *mut sockaddr,
        _: *mut sctphdr,
        _: uint32_t,
        _: *mut mbuf,
        _: uint32_t,
        _: uint16_t,
    );
    #[no_mangle]
    fn sctp_t3rxt_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets) -> libc::c_int;
    #[no_mangle]
    fn sctp_t1init_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets) -> libc::c_int;
    #[no_mangle]
    fn sctp_shutdown_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets) -> libc::c_int;
    #[no_mangle]
    fn sctp_heartbeat_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets)
        -> libc::c_int;
    #[no_mangle]
    fn sctp_cookie_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets) -> libc::c_int;
    #[no_mangle]
    fn sctp_pathmtu_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_shutdownack_timer(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: *mut sctp_nets,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_strreset_timer(
        inp: *mut sctp_inpcb,
        stcb: *mut sctp_tcb,
        net: *mut sctp_nets,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_asconf_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets) -> libc::c_int;
    #[no_mangle]
    fn sctp_delete_prim_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_autoclose_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, net: *mut sctp_nets);
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
    fn sctp_calc_rwnd(stcb: *mut sctp_tcb, asoc: *mut sctp_association) -> uint32_t;
    #[no_mangle]
    fn sctp_addr_mgmt_ep_sa(
        _: *mut sctp_inpcb,
        _: *mut sockaddr,
        _: uint32_t,
        _: uint32_t,
        _: *mut sctp_ifa,
    ) -> uint32_t;
    #[no_mangle]
    fn sctp_asconf_iterator_ep(
        inp: *mut sctp_inpcb,
        ptr: *mut libc::c_void,
        val: uint32_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_asconf_iterator_stcb(
        inp: *mut sctp_inpcb,
        stcb: *mut sctp_tcb,
        ptr: *mut libc::c_void,
        type_0: uint32_t,
    );
    #[no_mangle]
    fn sctp_asconf_iterator_end(ptr: *mut libc::c_void, val: uint32_t);
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
    static sctp_cc_functions: [sctp_cc_functions; 0];
    #[no_mangle]
    static sctp_ss_functions: [sctp_ss_functions; 0];
}
pub type size_t = libc::c_ulong;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut libc::c_void,
    pub iov_len: size_t,
}
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
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
pub type off_t = __off_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
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
    pub c2rust_unnamed: C2RustUnnamed_774,
    pub c2rust_unnamed_0: C2RustUnnamed_772,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_772 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_773,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_773 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_774 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_775,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_775 {
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
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
pub type C2RustUnnamed_776 = libc::c_uint;
pub const MSG_CMSG_CLOEXEC: C2RustUnnamed_776 = 1073741824;
pub const MSG_FASTOPEN: C2RustUnnamed_776 = 536870912;
pub const MSG_ZEROCOPY: C2RustUnnamed_776 = 67108864;
pub const MSG_BATCH: C2RustUnnamed_776 = 262144;
pub const MSG_WAITFORONE: C2RustUnnamed_776 = 65536;
pub const MSG_MORE: C2RustUnnamed_776 = 32768;
pub const MSG_NOSIGNAL: C2RustUnnamed_776 = 16384;
pub const MSG_ERRQUEUE: C2RustUnnamed_776 = 8192;
pub const MSG_RST: C2RustUnnamed_776 = 4096;
pub const MSG_CONFIRM: C2RustUnnamed_776 = 2048;
pub const MSG_SYN: C2RustUnnamed_776 = 1024;
pub const MSG_FIN: C2RustUnnamed_776 = 512;
pub const MSG_WAITALL: C2RustUnnamed_776 = 256;
pub const MSG_EOR: C2RustUnnamed_776 = 128;
pub const MSG_DONTWAIT: C2RustUnnamed_776 = 64;
pub const MSG_TRUNC: C2RustUnnamed_776 = 32;
pub const MSG_PROXY: C2RustUnnamed_776 = 16;
pub const MSG_CTRUNC: C2RustUnnamed_776 = 8;
pub const MSG_TRYHARD: C2RustUnnamed_776 = 4;
pub const MSG_DONTROUTE: C2RustUnnamed_776 = 4;
pub const MSG_PEEK: C2RustUnnamed_776 = 2;
pub const MSG_OOB: C2RustUnnamed_776 = 1;

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
    pub __in6_u: C2RustUnnamed_777,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_777 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct proc_0 {
    pub stub: libc::c_int,
}
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
    pub so_incomp: C2RustUnnamed_785,
    pub so_comp: C2RustUnnamed_784,
    pub so_list: C2RustUnnamed_783,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_782,
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
    pub M_dat: C2RustUnnamed_778,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_778 {
    pub MH: C2RustUnnamed_779,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_779 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_780,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_780 {
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
    pub m_tag_link: C2RustUnnamed_781,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_781 {
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
pub struct C2RustUnnamed_782 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_783 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_784 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_785 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}
pub type sctp_zone_t = size_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_786,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_786 {
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
    pub inp_hash: C2RustUnnamed_794,
    pub inp_list: C2RustUnnamed_793,
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
    pub inp_depend4: C2RustUnnamed_790,
    pub inp_depend6: C2RustUnnamed_789,
    pub inp_portlist: C2RustUnnamed_788,
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
    pub phd_hash: C2RustUnnamed_787,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_787 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_788 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_789 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_790 {
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
    pub ie_dependfaddr: C2RustUnnamed_792,
    pub ie_dependladdr: C2RustUnnamed_791,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_791 {
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
pub union C2RustUnnamed_792 {
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
pub struct C2RustUnnamed_793 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_794 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ip6_hdr {
    pub ip6_ctlun: C2RustUnnamed_795,
    pub ip6_src: in6_addr,
    pub ip6_dst: in6_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_795 {
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
pub struct generic {
    pub lh_first: *mut generic,
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
    pub next: C2RustUnnamed_825,
    pub next_instrm: C2RustUnnamed_824,
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
    pub rec: C2RustUnnamed_823,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_796,
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
pub struct C2RustUnnamed_796 {
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
    pub sctp_next: C2RustUnnamed_803,
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
    pub tqe: C2RustUnnamed_797,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_797 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_ifa {
    pub next_ifa: C2RustUnnamed_802,
    pub next_bucket: C2RustUnnamed_801,
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
    pub next_ifn: C2RustUnnamed_799,
    pub next_bucket: C2RustUnnamed_798,
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
pub struct C2RustUnnamed_798 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_799 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_800,
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
pub struct C2RustUnnamed_800 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_801 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_802 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}
pub type sctp_rtentry_t = sctp_rtentry;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_803 {
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
    pub next: C2RustUnnamed_804,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_804 {
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
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_808,
    pub sctp_tcblist: C2RustUnnamed_807,
    pub sctp_tcbasocidhash: C2RustUnnamed_806,
    pub sctp_asocs: C2RustUnnamed_805,
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
pub struct C2RustUnnamed_805 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_806 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_807 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_808 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_813,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_812,
    pub sctp_hash: C2RustUnnamed_811,
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
    pub sctp_nxt_itr: C2RustUnnamed_809,
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
pub struct C2RustUnnamed_809 {
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
    pub sctp_nxt_addr: C2RustUnnamed_810,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_810 {
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
pub struct C2RustUnnamed_811 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_812 {
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
pub union C2RustUnnamed_813 {
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
    pub next_spoke: C2RustUnnamed_814,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_814 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_815,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_815 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_816,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_816 {
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
    pub next: C2RustUnnamed_818,
    pub ss_next: C2RustUnnamed_817,
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
pub struct C2RustUnnamed_817 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_818 {
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
pub struct sctp_resethead {
    pub tqh_first: *mut sctp_stream_reset_list,
    pub tqh_last: *mut *mut sctp_stream_reset_list,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_reset_list {
    pub next_resp: C2RustUnnamed_819,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_819 {
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
    pub next: C2RustUnnamed_820,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_820 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_821,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_821 {
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
    pub next: C2RustUnnamed_822,
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
pub struct C2RustUnnamed_822 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_823 {
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
pub struct C2RustUnnamed_824 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_825 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
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
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_iterator {
    pub list_of_work: sctpladdr,
    pub cnt: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct generic_0 {
    pub lh_first: *mut generic_0,
}
/* ... used for Heartbeat Ack (HEARTBEAT ACK) */
/* Abort Asssociation (ABORT) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_abort_chunk {
    pub ch: sctp_chunkhdr,
}
/* Operation Error (ERROR) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_error_chunk {
    pub ch: sctp_chunkhdr,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_init_chunk {
    pub ch: sctp_chunkhdr,
    pub init: sctp_init,
}
/*
 * Structures for the control chunks
 */
/* Initiate (INIT)/Initiate Ack (INIT ACK) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_init {
    pub initiate_tag: uint32_t,
    pub a_rwnd: uint32_t,
    pub num_outbound_streams: uint16_t,
    pub num_inbound_streams: uint16_t,
    pub initial_tsn: uint32_t,
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
pub struct sctp_timeval {
    pub tv_sec: uint32_t,
    pub tv_usec: uint32_t,
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
pub struct calloutlist {
    pub tqh_first: *mut sctp_callout,
    pub tqh_last: *mut *mut sctp_callout,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctpvtaghead {
    pub lh_first: *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tagblock {
    pub sctp_nxt_tagblock: C2RustUnnamed_826,
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
pub struct C2RustUnnamed_826 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctppcbhead {
    pub lh_first: *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrflist {
    pub lh_first: *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct generic_1 {
    pub lh_first: *mut generic_1,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctphdr {
    pub src_port: uint16_t,
    pub dest_port: uint16_t,
    pub v_tag: uint32_t,
    pub checksum: uint32_t,
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
pub struct sctp_error_no_user_data {
    pub cause: sctp_error_cause,
    pub tsn: uint32_t,
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
pub struct sctp_sndinfo {
    pub snd_sid: uint16_t,
    pub snd_flags: uint16_t,
    pub snd_ppid: uint32_t,
    pub snd_context: uint32_t,
    pub snd_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_assoc_change {
    pub sac_type: uint16_t,
    pub sac_flags: uint16_t,
    pub sac_length: uint32_t,
    pub sac_state: uint16_t,
    pub sac_error: uint16_t,
    pub sac_outbound_streams: uint16_t,
    pub sac_inbound_streams: uint16_t,
    pub sac_assoc_id: sctp_assoc_t,
    pub sac_info: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_paddr_change {
    pub spc_type: uint16_t,
    pub spc_flags: uint16_t,
    pub spc_length: uint32_t,
    pub spc_aaddr: sockaddr_storage,
    pub spc_state: uint32_t,
    pub spc_error: uint32_t,
    pub spc_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_remote_error {
    pub sre_type: uint16_t,
    pub sre_flags: uint16_t,
    pub sre_length: uint32_t,
    pub sre_error: uint16_t,
    pub sre_assoc_id: sctp_assoc_t,
    pub sre_data: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_send_failed {
    pub ssf_type: uint16_t,
    pub ssf_flags: uint16_t,
    pub ssf_length: uint32_t,
    pub ssf_error: uint32_t,
    pub ssf_info: sctp_sndrcvinfo,
    pub ssf_assoc_id: sctp_assoc_t,
    pub ssf_data: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_send_failed_event {
    pub ssfe_type: uint16_t,
    pub ssfe_flags: uint16_t,
    pub ssfe_length: uint32_t,
    pub ssfe_error: uint32_t,
    pub ssfe_info: sctp_sndinfo,
    pub ssfe_assoc_id: sctp_assoc_t,
    pub ssfe_data: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_shutdown_event {
    pub sse_type: uint16_t,
    pub sse_flags: uint16_t,
    pub sse_length: uint32_t,
    pub sse_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_adaptation_event {
    pub sai_type: uint16_t,
    pub sai_flags: uint16_t,
    pub sai_length: uint32_t,
    pub sai_adaptation_ind: uint32_t,
    pub sai_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_adaption_event {
    pub sai_type: uint16_t,
    pub sai_flags: uint16_t,
    pub sai_length: uint32_t,
    pub sai_adaption_ind: uint32_t,
    pub sai_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_pdapi_event {
    pub pdapi_type: uint16_t,
    pub pdapi_flags: uint16_t,
    pub pdapi_length: uint32_t,
    pub pdapi_indication: uint32_t,
    pub pdapi_stream: uint16_t,
    pub pdapi_seq: uint16_t,
    pub pdapi_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_sender_dry_event {
    pub sender_dry_type: uint16_t,
    pub sender_dry_flags: uint16_t,
    pub sender_dry_length: uint32_t,
    pub sender_dry_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_reset_event {
    pub strreset_type: uint16_t,
    pub strreset_flags: uint16_t,
    pub strreset_length: uint32_t,
    pub strreset_assoc_id: sctp_assoc_t,
    pub strreset_stream_list: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_assoc_reset_event {
    pub assocreset_type: uint16_t,
    pub assocreset_flags: uint16_t,
    pub assocreset_length: uint32_t,
    pub assocreset_assoc_id: sctp_assoc_t,
    pub assocreset_local_tsn: uint32_t,
    pub assocreset_remote_tsn: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_change_event {
    pub strchange_type: uint16_t,
    pub strchange_flags: uint16_t,
    pub strchange_length: uint32_t,
    pub strchange_assoc_id: sctp_assoc_t,
    pub strchange_instrms: uint16_t,
    pub strchange_outstrms: uint16_t,
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
    pub ppid_fsn: C2RustUnnamed_827,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_827 {
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
pub unsafe extern "C" fn sctp_sblog(
    mut sb: *mut sockbuf,
    mut stcb: *mut sctp_tcb,
    mut from: libc::c_int,
    mut incr: libc::c_int,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_closing(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut loc: int16_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn rto_logging(mut net: *mut sctp_nets, mut from: libc::c_int) {}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_strm_del_alt(
    mut stcb: *mut sctp_tcb,
    mut tsn: uint32_t,
    mut sseq: uint16_t,
    mut stream: uint16_t,
    mut from: libc::c_int,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_nagle_event(mut stcb: *mut sctp_tcb, mut action: libc::c_int) {}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_sack(
    mut old_cumack: uint32_t,
    mut cumack: uint32_t,
    mut tsn: uint32_t,
    mut gaps: uint16_t,
    mut dups: uint16_t,
    mut from: libc::c_int,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_map(
    mut map: uint32_t,
    mut cum: uint32_t,
    mut high: uint32_t,
    mut from: libc::c_int,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_fr(
    mut biggest_tsn: uint32_t,
    mut biggest_new_tsn: uint32_t,
    mut tsn: uint32_t,
    mut from: libc::c_int,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_strm_del(
    mut control: *mut sctp_queued_to_read,
    mut poschk: *mut sctp_queued_to_read,
    mut from: libc::c_int,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_cwnd(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut augment: libc::c_int,
    mut from: uint8_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_lock(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut from: uint8_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_maxburst(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut error: libc::c_int,
    mut burst: libc::c_int,
    mut from: uint8_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_rwnd(
    mut from: uint8_t,
    mut peers_rwnd: uint32_t,
    mut snd_size: uint32_t,
    mut overhead: uint32_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_rwnd_set(
    mut from: uint8_t,
    mut peers_rwnd: uint32_t,
    mut flight_size: uint32_t,
    mut overhead: uint32_t,
    mut a_rwndval: uint32_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_misc_ints(
    mut from: uint8_t,
    mut a: uint32_t,
    mut b: uint32_t,
    mut c: uint32_t,
    mut d: uint32_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_wakeup_log(
    mut stcb: *mut sctp_tcb,
    mut wake_cnt: uint32_t,
    mut from: libc::c_int,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_log_block(
    mut from: uint8_t,
    mut asoc: *mut sctp_association,
    mut sendlen: ssize_t,
) {
}
#[no_mangle]
pub unsafe extern "C" fn sctp_fill_stat_log(
    mut optval: *mut libc::c_void,
    mut optsize: *mut size_t,
) -> libc::c_int {
    /* May need to fix this if ktrdump does not work */
    return 0i32;
}
/*
 * sctp_stop_timers_for_shutdown() should be called
 * when entering the SHUTDOWN_SENT or SHUTDOWN_ACK_SENT
 * state to make sure that all timers are stopped.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_stop_timers_for_shutdown(mut stcb: *mut sctp_tcb) {
    let mut asoc = 0 as *mut sctp_association;
    let mut net = 0 as *mut sctp_nets;
    asoc = &mut (*stcb).asoc;
    sctp_os_timer_stop(&mut (*asoc).dack_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).strreset_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).asconf_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).autoclose_timer.timer);
    sctp_os_timer_stop(&mut (*asoc).delayed_event_timer.timer);
    net = (*asoc).nets.tqh_first;
    while !net.is_null() {
        sctp_os_timer_stop(&mut (*net).pmtu_timer.timer);
        sctp_os_timer_stop(&mut (*net).hb_timer.timer);
        net = (*net).sctp_next.tqe_next
    }
}
/*
 * A list of sizes based on typical mtu's, used only if next hop size not
 * returned. These values MUST be multiples of 4 and MUST be ordered.
 */
static mut sctp_mtu_sizes: [uint32_t; 18] = [
    68u32, 296u32, 508u32, 512u32, 544u32, 576u32, 1004u32, 1492u32, 1500u32, 1536u32, 2000u32,
    2048u32, 4352u32, 4464u32, 8166u32, 17912u32, 32000u32, 65532u32,
];
/*
 * Return the largest MTU in sctp_mtu_sizes smaller than val.
 * If val is smaller than the minimum, just return the largest
 * multiple of 4 smaller or equal to val.
 * Ensure that the result is a multiple of 4.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_get_prev_mtu(mut val: uint32_t) -> uint32_t {
    let mut i = 0;
    val &= 0xfffffffcu32;
    if val <= sctp_mtu_sizes[0usize] {
        return val;
    }
    i = 1u32;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[uint32_t; 18]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<uint32_t>() as libc::c_ulong)
    {
        if val <= sctp_mtu_sizes[i as usize] {
            break;
        }
        i = i.wrapping_add(1)
    }
    return sctp_mtu_sizes[i.wrapping_sub(1u32) as usize];
}
/*
 * Return the smallest MTU in sctp_mtu_sizes larger than val.
 * If val is larger than the maximum, just return the largest multiple of 4 smaller
 * or equal to val.
 * Ensure that the result is a multiple of 4.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_get_next_mtu(mut val: uint32_t) -> uint32_t {
    let mut i = 0;
    val &= 0xfffffffcu32;
    i = 0u32;
    while (i as libc::c_ulong)
        < (::std::mem::size_of::<[uint32_t; 18]>() as libc::c_ulong)
            .wrapping_div(::std::mem::size_of::<uint32_t>() as libc::c_ulong)
    {
        if val < sctp_mtu_sizes[i as usize] {
            return sctp_mtu_sizes[i as usize];
        }
        i = i.wrapping_add(1)
    }
    return val;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_fill_random_store(mut m: *mut sctp_pcb) {
    /*
     * Here we use the MD5/SHA-1 to hash with our good randomNumbers and
     * our counter. The result becomes our good random numbers and we
     * then setup to give these out. Note that we do no locking to
     * protect this. This is ok, since if competing folks call this we
     * will get more gobbled gook in the random store which is what we
     * want. There is a danger that two guys will use the same random
     * numbers, but thats ok too since that is random as well :->
     */
    (*m).store_at = 0u32;
    sctp_hmac(
        0x1u16,
        (*m).random_numbers.as_mut_ptr(),
        ::std::mem::size_of::<[uint8_t; 20]>() as uint32_t,
        &mut (*m).random_counter as *mut uint32_t as *mut uint8_t,
        ::std::mem::size_of::<uint32_t>() as uint32_t,
        (*m).random_store.as_mut_ptr(),
    );
    (*m).random_counter = (*m).random_counter.wrapping_add(1);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_select_initial_TSN(mut inp: *mut sctp_pcb) -> uint32_t {
    let mut x = 0;
    let mut xp = 0 as *mut uint32_t;
    let mut p = 0 as *mut uint8_t;
    let mut store_at = 0;
    let mut new_store = 0;
    if (*inp).initial_sequence_debug != 0u32 {
        let mut ret = 0;
        ret = (*inp).initial_sequence_debug;
        (*inp).initial_sequence_debug = (*inp).initial_sequence_debug.wrapping_add(1);
        return ret;
    }
    loop {
        store_at = (*inp).store_at as libc::c_int;
        new_store = (store_at as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<uint32_t>() as libc::c_ulong)
            as libc::c_int;
        if new_store >= 20i32 - 3i32 {
            new_store = 0i32
        }
        if ::std::intrinsics::atomic_cxchg(
            &mut (*inp).store_at as *mut uint32_t,
            store_at as uint32_t,
            new_store as uint32_t,
        )
        .1
        {
            break;
        }
    }
    if new_store == 0i32 {
        /* Refill the random store */
        sctp_fill_random_store(inp);
    }
    p = &mut *(*inp).random_store.as_mut_ptr().offset(store_at as isize) as *mut uint8_t;
    xp = p as *mut uint32_t;
    x = *xp;
    return x;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_select_a_tag(
    mut inp: *mut sctp_inpcb,
    mut lport: uint16_t,
    mut rport: uint16_t,
    mut check: libc::c_int,
) -> uint32_t {
    let mut x = 0;
    let mut now = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    if check != 0 {
        gettimeofday(&mut now, 0 as *mut timezone);
    }
    loop
    /* we never use 0 */
    {
        x = sctp_select_initial_TSN(&mut (*inp).sctp_ep);
        if x == 0u32 {
            continue;
        }
        if check == 0 || sctp_is_vtag_good(x, lport, rport, &mut now) != 0 {
            break;
        }
    }
    return x;
}
/*
 * Function prototypes
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_map_assoc_state(mut kernel_state: libc::c_int) -> int32_t {
    let mut user_state = 0;
    if kernel_state & 0x800i32 != 0 {
        user_state = 0i32
    } else if kernel_state & 0x80i32 != 0 {
        user_state = 0x80i32
    } else {
        match kernel_state & 0x7fi32 {
            0 => user_state = 0i32,
            1 => user_state = 0i32,
            2 => user_state = 0x2i32,
            4 => user_state = 0x4i32,
            8 => user_state = 0x8i32,
            16 => user_state = 0x10i32,
            32 => user_state = 0x20i32,
            64 => user_state = 0x40i32,
            _ => user_state = 0i32,
        }
    }
    return user_state;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_init_asoc(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut override_tag: uint32_t,
    mut vrf_id: uint32_t,
    mut o_strms: uint16_t,
) -> libc::c_int {
    let mut asoc = 0 as *mut sctp_association;
    asoc = &mut (*stcb).asoc;
    /* init all variables to a known value. */
    sctp_set_state(stcb, 0x1i32);
    (*asoc).max_burst = (*inp).sctp_ep.max_burst;
    (*asoc).fr_max_burst = (*inp).sctp_ep.fr_max_burst;
    (*asoc).heart_beat_delay = if hz == 1000i32 {
        (*inp).sctp_ep.sctp_timeoutticks[3usize]
    } else {
        (*inp).sctp_ep.sctp_timeoutticks[3usize]
            .wrapping_mul(1000u32)
            .wrapping_add((hz - 1i32) as libc::c_uint)
            .wrapping_div(hz as libc::c_uint)
    };
    (*asoc).cookie_life = (*inp).sctp_ep.def_cookie_life;
    (*asoc).sctp_cmt_on_off = (*inp).sctp_cmt_on_off as uint8_t;
    (*asoc).ecn_supported = (*inp).ecn_supported;
    (*asoc).prsctp_supported = (*inp).prsctp_supported;
    (*asoc).idata_supported = (*inp).idata_supported;
    (*asoc).auth_supported = (*inp).auth_supported;
    (*asoc).asconf_supported = (*inp).asconf_supported;
    (*asoc).reconfig_supported = (*inp).reconfig_supported;
    (*asoc).nrsack_supported = (*inp).nrsack_supported;
    (*asoc).pktdrop_supported = (*inp).pktdrop_supported;
    (*asoc).idata_supported = (*inp).idata_supported;
    (*asoc).sctp_cmt_pf = 0u8;
    (*asoc).sctp_frag_point = (*inp).sctp_frag_point;
    (*asoc).sctp_features = (*inp).sctp_features;
    (*asoc).default_dscp = (*inp).sctp_ep.default_dscp;
    (*asoc).max_cwnd = (*inp).max_cwnd;
    if (*inp).sctp_ep.default_flowlabel != 0 {
        (*asoc).default_flowlabel = (*inp).sctp_ep.default_flowlabel
    } else if (*inp).ip_inp.inp.inp_flags & 0x800000i32 != 0 {
        (*asoc).default_flowlabel = sctp_select_initial_TSN(&mut (*inp).sctp_ep);
        (*asoc).default_flowlabel &= 0xfffffu32;
        (*asoc).default_flowlabel |= 0x80000000u32
    } else {
        (*asoc).default_flowlabel = 0u32
    }
    (*asoc).sb_send_resv = 0u32;
    if override_tag != 0 {
        (*asoc).my_vtag = override_tag
    } else {
        (*asoc).my_vtag = sctp_select_a_tag(
            inp,
            (*(*stcb).sctp_ep).ip_inp.inp.inp_inc.inc_ie.ie_lport,
            (*stcb).rport,
            1i32,
        )
    }
    /* Get the nonce tags */
    (*asoc).my_vtag_nonce = sctp_select_a_tag(
        inp,
        (*(*stcb).sctp_ep).ip_inp.inp.inp_inc.inc_ie.ie_lport,
        (*stcb).rport,
        0i32,
    );
    (*asoc).peer_vtag_nonce = sctp_select_a_tag(
        inp,
        (*(*stcb).sctp_ep).ip_inp.inp.inp_inc.inc_ie.ie_lport,
        (*stcb).rport,
        0i32,
    );
    (*asoc).vrf_id = vrf_id;
    (*asoc).refcnt = 0u32;
    (*asoc).assoc_up_sent = 0u8;
    (*asoc).sending_seq = sctp_select_initial_TSN(&mut (*inp).sctp_ep);
    (*asoc).init_seq_number = (*asoc).sending_seq;
    (*asoc).str_reset_seq_out = (*asoc).init_seq_number;
    (*asoc).asconf_seq_out = (*asoc).str_reset_seq_out;
    (*asoc).asconf_seq_out_acked = (*asoc).asconf_seq_out.wrapping_sub(1u32);
    /* we are optimisitic here */
    (*asoc).peer_supports_nat = 0u8;
    (*asoc).sent_queue_retran_cnt = 0u32;
    /* for CMT */
    (*asoc).last_net_cmt_send_started = 0 as *mut sctp_nets;
    /* This will need to be adjusted */
    (*asoc).last_acked_seq = (*asoc).init_seq_number.wrapping_sub(1u32);
    (*asoc).advanced_peer_ack_point = (*asoc).last_acked_seq;
    (*asoc).asconf_seq_in = (*asoc).last_acked_seq;
    /* here we are different, we hold the next one we expect */
    (*asoc).str_reset_seq_in = (*asoc).last_acked_seq.wrapping_add(1u32);
    (*asoc).initial_init_rto_max = (*inp).sctp_ep.initial_init_rto_max as libc::c_uint;
    (*asoc).initial_rto = (*inp).sctp_ep.initial_rto;
    (*asoc).default_mtu = (*inp).sctp_ep.default_mtu;
    (*asoc).max_init_times = (*inp).sctp_ep.max_init_times;
    (*asoc).max_send_times = (*inp).sctp_ep.max_send_times;
    (*asoc).def_net_failure = (*inp).sctp_ep.def_net_failure;
    (*asoc).def_net_pf_threshold = (*inp).sctp_ep.def_net_pf_threshold;
    (*asoc).free_chunk_cnt = 0u16;
    (*asoc).iam_blocking = 0u8;
    (*asoc).context = (*inp).sctp_context;
    (*asoc).local_strreset_support = (*inp).local_strreset_support;
    (*asoc).def_send = (*inp).def_send;
    (*asoc).delayed_ack = if hz == 1000i32 {
        (*inp).sctp_ep.sctp_timeoutticks[1usize]
    } else {
        (*inp).sctp_ep.sctp_timeoutticks[1usize]
            .wrapping_mul(1000u32)
            .wrapping_add((hz - 1i32) as libc::c_uint)
            .wrapping_div(hz as libc::c_uint)
    };
    (*asoc).sack_freq = (*inp).sctp_ep.sctp_sack_freq;
    (*asoc).pr_sctp_cnt = 0u32;
    (*asoc).total_output_queue_size = 0u32;
    if (*inp).sctp_flags & 0x4000000u32 != 0 {
        (*asoc).scope.ipv6_addr_legal = 1u8;
        if (*inp).ip_inp.inp.inp_flags & 0x8000i32 == 0i32 {
            (*asoc).scope.ipv4_addr_legal = 1u8
        } else {
            (*asoc).scope.ipv4_addr_legal = 0u8
        }
        (*asoc).scope.conn_addr_legal = 0u8
    } else {
        (*asoc).scope.ipv6_addr_legal = 0u8;
        if (*inp).sctp_flags & 0x80000000u32 != 0 {
            (*asoc).scope.conn_addr_legal = 1u8;
            (*asoc).scope.ipv4_addr_legal = 0u8
        } else {
            (*asoc).scope.conn_addr_legal = 0u8;
            (*asoc).scope.ipv4_addr_legal = 1u8
        }
    }
    (*asoc).my_rwnd = if (*(*inp).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
        (*(*inp).sctp_socket).so_rcv.sb_hiwat
    } else {
        4096u32
    };
    (*asoc).peers_rwnd = (*(*inp).sctp_socket).so_rcv.sb_hiwat;
    (*asoc).smallest_mtu = (*inp).sctp_frag_point;
    (*asoc).minrto = (*inp).sctp_ep.sctp_minrto;
    (*asoc).maxrto = (*inp).sctp_ep.sctp_maxrto;
    (*asoc).stream_locked_on = 0u16;
    (*asoc).ecn_echo_cnt_onq = 0u16;
    (*asoc).stream_locked = 0u8;
    (*asoc).send_sack = 1u8;
    (*asoc).sctp_restricted_addrs.lh_first = 0 as *mut sctp_laddr;
    (*asoc).nets.tqh_first = 0 as *mut sctp_nets;
    (*asoc).nets.tqh_last = &mut (*asoc).nets.tqh_first;
    (*asoc).pending_reply_queue.tqh_first = 0 as *mut sctp_queued_to_read;
    (*asoc).pending_reply_queue.tqh_last = &mut (*asoc).pending_reply_queue.tqh_first;
    (*asoc).asconf_ack_sent.tqh_first = 0 as *mut sctp_asconf_ack;
    (*asoc).asconf_ack_sent.tqh_last = &mut (*asoc).asconf_ack_sent.tqh_first;
    /* Setup to fill the hb random cache at first HB */
    (*asoc).hb_random_idx = 4u8;
    (*asoc).sctp_autoclose_ticks = (*inp).sctp_ep.auto_close_time as libc::c_uint;
    (*stcb).asoc.congestion_control_module = (*inp).sctp_ep.sctp_default_cc_module;
    (*stcb).asoc.cc_functions = *sctp_cc_functions
        .as_ptr()
        .offset((*inp).sctp_ep.sctp_default_cc_module as isize);
    (*stcb).asoc.stream_scheduling_module = (*inp).sctp_ep.sctp_default_ss_module;
    (*stcb).asoc.ss_functions = *sctp_ss_functions
        .as_ptr()
        .offset((*inp).sctp_ep.sctp_default_ss_module as isize);
    /*
     * Now the stream parameters, here we allocate space for all streams
     * that we request by default.
     */
    (*asoc).pre_open_streams = o_strms as libc::c_uint;
    (*asoc).streamoutcnt = (*asoc).pre_open_streams as uint16_t;
    (*asoc).strm_realoutsize = (*asoc).streamoutcnt;
    (*asoc).strmout = malloc(
        ((*asoc).streamoutcnt as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<sctp_stream_out>() as libc::c_ulong),
    ) as *mut sctp_stream_out;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            (*asoc).strmout as *mut libc::c_void,
            0i32,
            ((*asoc).streamoutcnt as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<sctp_stream_out>() as libc::c_ulong),
        );
    }
    if (*asoc).strmout.is_null() {
        /* big trouble no memory */
        return 12i32;
    }

    for i in 0i32..(*asoc).streamoutcnt as libc::c_int {
        /*
         * inbound side must be set to 0xffff, also NOTE when we get
         * the INIT-ACK back (for INIT sender) we MUST reduce the
         * count (streamoutcnt) but first check if we sent to any of
         * the upper streams that were dropped (if some were). Those
         * that were dropped must be notified to the upper layer as
         * failed to send.
         */
        (*(*asoc).strmout.offset(i as isize)).next_mid_ordered = 0u32;

        (*(*asoc).strmout.offset(i as isize)).next_mid_unordered = 0u32;

        let ref mut fresh0 = (*(*asoc).strmout.offset(i as isize)).outqueue.tqh_first;

        *fresh0 = 0 as *mut sctp_stream_queue_pending;

        let ref mut fresh1 = (*(*asoc).strmout.offset(i as isize)).outqueue.tqh_last;

        *fresh1 = &mut (*(*asoc).strmout.offset(i as isize)).outqueue.tqh_first;

        (*(*asoc).strmout.offset(i as isize)).chunks_on_queues = 0u32;

        (*(*asoc).strmout.offset(i as isize)).abandoned_sent[0usize] = 0u32;

        (*(*asoc).strmout.offset(i as isize)).abandoned_unsent[0usize] = 0u32;

        (*(*asoc).strmout.offset(i as isize)).sid = i as uint16_t;

        (*(*asoc).strmout.offset(i as isize)).last_msg_incomplete = 0u8;

        (*(*asoc).strmout.offset(i as isize)).state = 0x1u8;

        (*asoc)
            .ss_functions
            .sctp_ss_init_stream
            .expect("non-null function pointer")(
            stcb,
            &mut *(*asoc).strmout.offset(i as isize),
            0 as *mut sctp_stream_out,
        );
    }
    (*asoc)
        .ss_functions
        .sctp_ss_init
        .expect("non-null function pointer")(stcb, asoc, 0i32);
    /* Now the mapping array */
    (*asoc).mapping_array_size = 16u16;
    (*asoc).mapping_array = malloc((*asoc).mapping_array_size as u_long) as *mut uint8_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            (*asoc).mapping_array as *mut libc::c_void,
            0i32,
            (*asoc).mapping_array_size as libc::c_ulong,
        );
    }
    if (*asoc).mapping_array.is_null() {
        free((*asoc).strmout as *mut libc::c_void);
        return 12i32;
    }
    memset(
        (*asoc).mapping_array as *mut libc::c_void,
        0i32,
        (*asoc).mapping_array_size as libc::c_ulong,
    );
    (*asoc).nr_mapping_array = malloc((*asoc).mapping_array_size as u_long) as *mut uint8_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            (*asoc).nr_mapping_array as *mut libc::c_void,
            0i32,
            (*asoc).mapping_array_size as libc::c_ulong,
        );
    }
    if (*asoc).nr_mapping_array.is_null() {
        free((*asoc).strmout as *mut libc::c_void);
        free((*asoc).mapping_array as *mut libc::c_void);
        return 12i32;
    }
    memset(
        (*asoc).nr_mapping_array as *mut libc::c_void,
        0i32,
        (*asoc).mapping_array_size as libc::c_ulong,
    );
    /* Now the init of the other outqueues */
    (*asoc).free_chunks.tqh_first = 0 as *mut sctp_tmit_chunk;
    (*asoc).free_chunks.tqh_last = &mut (*asoc).free_chunks.tqh_first;
    (*asoc).control_send_queue.tqh_first = 0 as *mut sctp_tmit_chunk;
    (*asoc).control_send_queue.tqh_last = &mut (*asoc).control_send_queue.tqh_first;
    (*asoc).asconf_send_queue.tqh_first = 0 as *mut sctp_tmit_chunk;
    (*asoc).asconf_send_queue.tqh_last = &mut (*asoc).asconf_send_queue.tqh_first;
    (*asoc).send_queue.tqh_first = 0 as *mut sctp_tmit_chunk;
    (*asoc).send_queue.tqh_last = &mut (*asoc).send_queue.tqh_first;
    (*asoc).sent_queue.tqh_first = 0 as *mut sctp_tmit_chunk;
    (*asoc).sent_queue.tqh_last = &mut (*asoc).sent_queue.tqh_first;
    (*asoc).resetHead.tqh_first = 0 as *mut sctp_stream_reset_list;
    (*asoc).resetHead.tqh_last = &mut (*asoc).resetHead.tqh_first;
    (*asoc).max_inbound_streams = (*inp).sctp_ep.max_open_streams_intome as libc::c_uint;
    (*asoc).asconf_queue.tqh_first = 0 as *mut sctp_asconf_addr;
    (*asoc).asconf_queue.tqh_last = &mut (*asoc).asconf_queue.tqh_first;
    /* authentication fields */
    (*asoc).authinfo.random = 0 as *mut sctp_key_t;
    (*asoc).authinfo.active_keyid = 0u16;
    (*asoc).authinfo.assoc_key = 0 as *mut sctp_key_t;
    (*asoc).authinfo.assoc_keyid = 0u16;
    (*asoc).authinfo.recv_key = 0 as *mut sctp_key_t;
    (*asoc).authinfo.recv_keyid = 0u16;
    (*asoc).shared_keys.lh_first = 0 as *mut sctp_shared_key;
    (*asoc).marked_retrans = 0u32;
    (*asoc).port = (*inp).sctp_ep.port;
    (*asoc).timoinit = 0u32;
    (*asoc).timodata = 0u32;
    (*asoc).timosack = 0u32;
    (*asoc).timoshutdown = 0u32;
    (*asoc).timoheartbeat = 0u32;
    (*asoc).timocookie = 0u32;
    (*asoc).timoshutdownack = 0u32;
    gettimeofday(&mut (*asoc).start_time, 0 as *mut timezone);
    (*asoc).discontinuity_time = (*asoc).start_time;

    for i in 0i32..0x3i32 + 1i32 {
        (*asoc).abandoned_unsent[i as usize] = 0u64;

        (*asoc).abandoned_sent[i as usize] = 0u64;
    }
    /* sa_ignore MEMLEAK {memory is put in the assoc mapping array and freed later when
     * the association is freed.
     */
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_print_mapping_array(mut asoc: *mut sctp_association) {
    let mut i = 0;
    let mut limit = 0;
    if system_base_info.debug_printf.is_some() {
        system_base_info.debug_printf.expect("non-null function pointer")(b"Mapping array size: %d, baseTSN: %8.8x, cumAck: %8.8x, highestTSN: (%8.8x, %8.8x).\n\x00"
                                                                              as
                                                                              *const u8
                                                                              as
                                                                              *const libc::c_char,
                                                                          (*asoc).mapping_array_size
                                                                              as
                                                                              libc::c_int,
                                                                          (*asoc).mapping_array_base_tsn,
                                                                          (*asoc).cumulative_tsn,
                                                                          (*asoc).highest_tsn_inside_map,
                                                                          (*asoc).highest_tsn_inside_nr_map);
    }
    limit = (*asoc).mapping_array_size as libc::c_uint;
    while limit > 1u32 {
        if *(*asoc)
            .mapping_array
            .offset(limit.wrapping_sub(1u32) as isize) as libc::c_int
            != 0i32
        {
            break;
        }
        limit = limit.wrapping_sub(1)
    }
    if system_base_info.debug_printf.is_some() {
        system_base_info
            .debug_printf
            .expect("non-null function pointer")(
            b"Renegable mapping array (last %d entries are zero):\n\x00" as *const u8
                as *const libc::c_char,
            ((*asoc).mapping_array_size as libc::c_uint).wrapping_sub(limit),
        );
    }
    i = 0u32;
    while i < limit {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%2.2x%c\x00" as *const u8 as *const libc::c_char,
                *(*asoc).mapping_array.offset(i as isize) as libc::c_int,
                if i.wrapping_add(1u32).wrapping_rem(16u32) != 0 {
                    ' ' as i32
                } else {
                    '\n' as i32
                },
            );
        }
        i = i.wrapping_add(1)
    }
    if limit.wrapping_rem(16u32) != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"\n\x00" as *const u8 as *const libc::c_char
            );
        }
    }
    limit = (*asoc).mapping_array_size as libc::c_uint;
    while limit > 1u32 {
        if *(*asoc)
            .nr_mapping_array
            .offset(limit.wrapping_sub(1u32) as isize)
            != 0
        {
            break;
        }
        limit = limit.wrapping_sub(1)
    }
    if system_base_info.debug_printf.is_some() {
        system_base_info
            .debug_printf
            .expect("non-null function pointer")(
            b"Non renegable mapping array (last %d entries are zero):\n\x00" as *const u8
                as *const libc::c_char,
            ((*asoc).mapping_array_size as libc::c_uint).wrapping_sub(limit),
        );
    }
    i = 0u32;
    while i < limit {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%2.2x%c\x00" as *const u8 as *const libc::c_char,
                *(*asoc).nr_mapping_array.offset(i as isize) as libc::c_int,
                if i.wrapping_add(1u32).wrapping_rem(16u32) != 0 {
                    ' ' as i32
                } else {
                    '\n' as i32
                },
            );
        }
        i = i.wrapping_add(1)
    }
    if limit.wrapping_rem(16u32) != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"\n\x00" as *const u8 as *const libc::c_char
            );
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_expand_mapping_array(
    mut asoc: *mut sctp_association,
    mut needed: uint32_t,
) -> libc::c_int {
    let mut new_array1 = 0 as *mut uint8_t;
    let mut new_array2 = 0 as *mut uint8_t;
    let mut new_size = 0;
    new_size = ((*asoc).mapping_array_size as libc::c_uint).wrapping_add(
        needed
            .wrapping_add(7u32)
            .wrapping_div(8u32)
            .wrapping_add(32u32),
    );
    new_array1 = malloc(new_size as u_long) as *mut uint8_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            new_array1 as *mut libc::c_void,
            0i32,
            new_size as libc::c_ulong,
        );
    }
    new_array2 = malloc(new_size as u_long) as *mut uint8_t;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            new_array2 as *mut libc::c_void,
            0i32,
            new_size as libc::c_ulong,
        );
    }
    if new_array1.is_null() || new_array2.is_null() {
        /* can't get more, forget it */
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"No memory for expansion of SCTP mapping array %d\n\x00" as *const u8
                    as *const libc::c_char,
                new_size,
            );
        }
        if !new_array1.is_null() {
            free(new_array1 as *mut libc::c_void);
        }
        if !new_array2.is_null() {
            free(new_array2 as *mut libc::c_void);
        }
        return -(1i32);
    }
    memset(
        new_array1 as *mut libc::c_void,
        0i32,
        new_size as libc::c_ulong,
    );
    memset(
        new_array2 as *mut libc::c_void,
        0i32,
        new_size as libc::c_ulong,
    );
    memcpy(
        new_array1 as *mut libc::c_void,
        (*asoc).mapping_array as *const libc::c_void,
        (*asoc).mapping_array_size as libc::c_ulong,
    );
    memcpy(
        new_array2 as *mut libc::c_void,
        (*asoc).nr_mapping_array as *const libc::c_void,
        (*asoc).mapping_array_size as libc::c_ulong,
    );
    free((*asoc).mapping_array as *mut libc::c_void);
    free((*asoc).nr_mapping_array as *mut libc::c_void);
    (*asoc).mapping_array = new_array1;
    (*asoc).nr_mapping_array = new_array2;
    (*asoc).mapping_array_size = new_size as uint16_t;
    return 0i32;
}
unsafe extern "C" fn sctp_iterator_work(mut it: *mut sctp_iterator) {
    let mut current_block: u64;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    pthread_mutex_lock(&mut sctp_it_ctl.it_mtx);
    sctp_it_ctl.cur_it = it;
    if !(*it).inp.is_null() {
        pthread_mutex_lock(&mut (*(*it).inp).inp_mtx);
        ::std::intrinsics::atomic_xadd(&mut (*(*it).inp).refcount, -(1i32));
    }
    if (*it).inp.is_null() {
        current_block = 11001426723994513780;
    } else {
        current_block = 16076509824786758145;
    }
    'c_37360: loop {
        match current_block {
            11001426723994513780 =>
            /* iterator is complete */
            {
                sctp_it_ctl.cur_it = 0 as *mut sctp_iterator;
                break;
            }
            _ => {
                let mut inp_skip = 0i32;
                let mut first_in = 1i32;
                if first_in != 0 {
                    first_in = 0i32
                } else {
                    pthread_mutex_lock(&mut (*(*it).inp).inp_mtx);
                }
                while (*it).pcb_flags != 0
                    && (*(*it).inp).sctp_flags & (*it).pcb_flags != (*it).pcb_flags
                    || (*it).pcb_features != 0
                        && (*(*it).inp).sctp_features & (*it).pcb_features as libc::c_ulong
                            != (*it).pcb_features as libc::c_ulong
                {
                    /* endpoint flags or features don't match, so keep looking */
                    if (*it).iterator_flags & 0x2u32 != 0 {
                        pthread_mutex_unlock(&mut (*(*it).inp).inp_mtx);
                        current_block = 11001426723994513780;
                        continue 'c_37360;
                    } else {
                        let mut tinp = 0 as *mut sctp_inpcb;
                        tinp = (*it).inp;
                        (*it).inp = (*(*it).inp).sctp_list.le_next;
                        pthread_mutex_unlock(&mut (*tinp).inp_mtx);
                        if (*it).inp.is_null() {
                            current_block = 11001426723994513780;
                            continue 'c_37360;
                        }
                        pthread_mutex_lock(&mut (*(*it).inp).inp_mtx);
                    }
                }
                /* now go through each assoc which is in the desired state */
                if (*it).done_current_ep as libc::c_int == 0i32 {
                    if (*it).function_inp.is_some() {
                        inp_skip = Some((*it).function_inp.expect("non-null function pointer"))
                            .expect("non-null function pointer")(
                            (*it).inp,
                            (*it).pointer,
                            (*it).val,
                        )
                    }
                    (*it).done_current_ep = 1u8
                }
                if (*it).stcb.is_null() {
                    /* run the per instance function */
                    (*it).stcb = (*(*it).inp).sctp_asoc_list.lh_first
                }
                if inp_skip != 0 || (*it).stcb.is_null() {
                    if (*it).function_inp_end.is_some() {
                        inp_skip = Some((*it).function_inp_end.expect("non-null function pointer"))
                            .expect("non-null function pointer")(
                            (*it).inp,
                            (*it).pointer,
                            (*it).val,
                        )
                    }
                    pthread_mutex_unlock(&mut (*(*it).inp).inp_mtx);
                } else {
                    loop {
                        if (*it).stcb.is_null() {
                            current_block = 15237655884915618618;
                            break;
                        }
                        pthread_mutex_lock(&mut (*(*it).stcb).tcb_mtx);
                        if (*it).asoc_state != 0
                            && (*(*it).stcb).asoc.state as libc::c_uint & (*it).asoc_state
                                != (*it).asoc_state
                        {
                            /* not in the right state... keep looking */
                            pthread_mutex_unlock(&mut (*(*it).stcb).tcb_mtx);
                        } else {
                            let mut iteration_count = 0i32;
                            iteration_count += 1;
                            if iteration_count > 20i32 {
                                /* Pause to let others grab the lock */
                                ::std::intrinsics::atomic_xadd(
                                    &mut (*(*it).stcb).asoc.refcnt,
                                    1u32,
                                );
                                pthread_mutex_unlock(&mut (*(*it).stcb).tcb_mtx);
                                ::std::intrinsics::atomic_xadd(&mut (*(*it).inp).refcount, 1i32);
                                pthread_mutex_unlock(&mut (*(*it).inp).inp_mtx);
                                pthread_mutex_unlock(&mut sctp_it_ctl.it_mtx);
                                pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                                pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
                                pthread_mutex_lock(&mut sctp_it_ctl.it_mtx);
                                if sctp_it_ctl.iterator_flags != 0 {
                                    /* We won't be staying here */
                                    ::std::intrinsics::atomic_xadd(
                                        &mut (*(*it).inp).refcount,
                                        -(1i32),
                                    );
                                    ::std::intrinsics::atomic_xadd(
                                        &mut (*(*it).stcb).asoc.refcnt,
                                        -(1i32) as uint32_t,
                                    );
                                    if sctp_it_ctl.iterator_flags & 0x1u32 != 0 {
                                        current_block = 11001426723994513780;
                                        continue 'c_37360;
                                    }
                                    if sctp_it_ctl.iterator_flags & 0x4u32 != 0 {
                                        sctp_it_ctl.iterator_flags &= !(0x4i32) as libc::c_uint;
                                        current_block = 11001426723994513780;
                                        continue 'c_37360;
                                    } else if sctp_it_ctl.iterator_flags & 0x8u32 != 0 {
                                        sctp_it_ctl.iterator_flags &= !(0x8i32) as libc::c_uint;
                                        current_block = 4247167652607022228;
                                        break;
                                    } else {
                                        /* If we reach here huh? */
                                        if system_base_info.debug_printf.is_some() {
                                            system_base_info
                                                .debug_printf
                                                .expect("non-null function pointer")(
                                                b"Unknown it ctl flag %x\n\x00" as *const u8
                                                    as *const libc::c_char,
                                                sctp_it_ctl.iterator_flags,
                                            );
                                        }
                                        sctp_it_ctl.iterator_flags = 0u32
                                    }
                                }
                                pthread_mutex_lock(&mut (*(*it).inp).inp_mtx);
                                ::std::intrinsics::atomic_xadd(&mut (*(*it).inp).refcount, -(1i32));
                                pthread_mutex_lock(&mut (*(*it).stcb).tcb_mtx);
                                ::std::intrinsics::atomic_xadd(
                                    &mut (*(*it).stcb).asoc.refcnt,
                                    -(1i32) as uint32_t,
                                );
                                iteration_count = 0i32
                            }
                            /* run function on this one */
                            Some((*it).function_assoc.expect("non-null function pointer"))
                                .expect("non-null function pointer")(
                                (*it).inp,
                                (*it).stcb,
                                (*it).pointer,
                                (*it).val,
                            );
                            /*
                             * we lie here, it really needs to have its own type but
                             * first I must verify that this won't effect things :-0
                             */
                            if (*it).no_chunk_output as libc::c_int == 0i32 {
                                sctp_chunk_output((*it).inp, (*it).stcb, 1i32, 0i32);
                            }
                            pthread_mutex_unlock(&mut (*(*it).stcb).tcb_mtx);
                        }
                        (*it).stcb = (*(*it).stcb).sctp_tcblist.le_next;
                        if (*it).stcb.is_null() {
                            /* Run last function */
                            if (*it).function_inp_end.is_some() {
                                inp_skip =
                                    Some((*it).function_inp_end.expect("non-null function pointer"))
                                        .expect("non-null function pointer")(
                                        (*it).inp,
                                        (*it).pointer,
                                        (*it).val,
                                    )
                            }
                        }
                    }
                    match current_block {
                        4247167652607022228 => {}
                        _ => {
                            pthread_mutex_unlock(&mut (*(*it).inp).inp_mtx);
                        }
                    }
                }
                /* done with all assocs on this endpoint, move on to next endpoint */
                (*it).done_current_ep = 0u8;
                if (*it).iterator_flags & 0x2u32 != 0 {
                    (*it).inp = 0 as *mut sctp_inpcb
                } else {
                    (*it).inp = (*(*it).inp).sctp_list.le_next
                }
                if (*it).inp.is_null() {
                    current_block = 11001426723994513780;
                } else {
                    current_block = 16076509824786758145;
                }
            }
        }
    }
    pthread_mutex_unlock(&mut sctp_it_ctl.it_mtx);
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    if (*it).function_atend.is_some() {
        Some((*it).function_atend.expect("non-null function pointer"))
            .expect("non-null function pointer")((*it).pointer, (*it).val);
    }
    free(it as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_iterator_worker() {
    let mut it = 0 as *mut sctp_iterator;
    let mut nit = 0 as *mut sctp_iterator;
    /* This function is called with the WQ lock in place */
    sctp_it_ctl.iterator_running = 1u32;
    it = sctp_it_ctl.iteratorhead.tqh_first;
    while !it.is_null() && {
        nit = (*it).sctp_nxt_itr.tqe_next;
        (1i32) != 0
    } {
        /* now lets work on this one */
        if !(*it).sctp_nxt_itr.tqe_next.is_null() {
            (*(*it).sctp_nxt_itr.tqe_next).sctp_nxt_itr.tqe_prev = (*it).sctp_nxt_itr.tqe_prev
        } else {
            sctp_it_ctl.iteratorhead.tqh_last = (*it).sctp_nxt_itr.tqe_prev
        }
        *(*it).sctp_nxt_itr.tqe_prev = (*it).sctp_nxt_itr.tqe_next;
        pthread_mutex_unlock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
        sctp_iterator_work(it);
        pthread_mutex_lock(&mut sctp_it_ctl.ipi_iterator_wq_mtx);
        if sctp_it_ctl.iterator_flags & 0x1u32 != 0 {
            break;
        }
        it = nit
        /*sa_ignore FREED_MEMORY*/
    }
    sctp_it_ctl.iterator_running = 0u32;
}
unsafe extern "C" fn sctp_handle_addr_wq() {
    let mut wi = 0 as *mut sctp_laddr;
    let mut nwi = 0 as *mut sctp_laddr;
    let mut asc = 0 as *mut sctp_asconf_iterator;
    asc = malloc(::std::mem::size_of::<sctp_asconf_iterator>() as libc::c_ulong)
        as *mut sctp_asconf_iterator;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            asc as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_asconf_iterator>() as libc::c_ulong,
        );
    }
    if asc.is_null() {
        /* Try later, no memory */
        sctp_timer_start(
            17i32,
            0 as *mut sctp_inpcb,
            0 as *mut sctp_tcb,
            0 as *mut sctp_nets,
        );
        return;
    }
    (*asc).list_of_work.lh_first = 0 as *mut sctp_laddr;
    (*asc).cnt = 0i32;
    wi = system_base_info.sctppcbinfo.addr_wq.lh_first;
    while !wi.is_null() && {
        nwi = (*wi).sctp_nxt_addr.le_next;
        (1i32) != 0
    } {
        if !(*wi).sctp_nxt_addr.le_next.is_null() {
            (*(*wi).sctp_nxt_addr.le_next).sctp_nxt_addr.le_prev = (*wi).sctp_nxt_addr.le_prev
        }
        *(*wi).sctp_nxt_addr.le_prev = (*wi).sctp_nxt_addr.le_next;
        (*wi).sctp_nxt_addr.le_next = (*asc).list_of_work.lh_first;
        if !(*wi).sctp_nxt_addr.le_next.is_null() {
            (*(*asc).list_of_work.lh_first).sctp_nxt_addr.le_prev = &mut (*wi).sctp_nxt_addr.le_next
        }
        (*asc).list_of_work.lh_first = wi;
        (*wi).sctp_nxt_addr.le_prev = &mut (*asc).list_of_work.lh_first;
        (*asc).cnt += 1;
        wi = nwi
    }
    if (*asc).cnt == 0i32 {
        free(asc as *mut libc::c_void);
    } else {
        let mut ret = 0;
        ret = sctp_initiate_iterator(
            Some(
                sctp_asconf_iterator_ep
                    as unsafe extern "C" fn(
                        _: *mut sctp_inpcb,
                        _: *mut libc::c_void,
                        _: uint32_t,
                    ) -> libc::c_int,
            ),
            Some(
                sctp_asconf_iterator_stcb
                    as unsafe extern "C" fn(
                        _: *mut sctp_inpcb,
                        _: *mut sctp_tcb,
                        _: *mut libc::c_void,
                        _: uint32_t,
                    ) -> (),
            ),
            None,
            0x4u32,
            0u32,
            0u32,
            asc as *mut libc::c_void,
            0u32,
            Some(
                sctp_asconf_iterator_end
                    as unsafe extern "C" fn(_: *mut libc::c_void, _: uint32_t) -> (),
            ),
            0 as *mut sctp_inpcb,
            0u8,
        );
        if ret != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Failed to initiate iterator for handle_addr_wq\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
            /* Freeing if we are stopping or put back on the addr_wq. */
            if system_base_info.sctp_pcb_initialized as libc::c_int == 0i32 {
                sctp_asconf_iterator_end(asc as *mut libc::c_void, 0u32);
            } else {
                wi = (*asc).list_of_work.lh_first;
                while !wi.is_null() {
                    (*wi).sctp_nxt_addr.le_next = system_base_info.sctppcbinfo.addr_wq.lh_first;
                    if !(*wi).sctp_nxt_addr.le_next.is_null() {
                        (*system_base_info.sctppcbinfo.addr_wq.lh_first)
                            .sctp_nxt_addr
                            .le_prev = &mut (*wi).sctp_nxt_addr.le_next
                    }
                    system_base_info.sctppcbinfo.addr_wq.lh_first = wi;
                    (*wi).sctp_nxt_addr.le_prev =
                        &mut system_base_info.sctppcbinfo.addr_wq.lh_first;
                    wi = (*wi).sctp_nxt_addr.le_next
                }
                free(asc as *mut libc::c_void);
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_timeout_handler(mut t: *mut libc::c_void) {
    let mut current_block: u64;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut net = 0 as *mut sctp_nets;
    let mut tmr = 0 as *mut sctp_timer;
    let mut upcall_socket = 0 as *mut socket;
    let mut did_output = 0;
    let mut type_0 = 0;
    tmr = t as *mut sctp_timer;
    inp = (*tmr).ep as *mut sctp_inpcb;
    stcb = (*tmr).tcb as *mut sctp_tcb;
    net = (*tmr).net as *mut sctp_nets;
    did_output = 1i32;
    /* sanity checks... */
    if (*tmr).self_0 != tmr as *mut libc::c_void {
        /*
         * SCTP_PRINTF("Stale SCTP timer fired (%p), ignoring...\n",
         *             (void *)tmr);
         */
        return;
    }
    (*tmr).stopped_from = 0xa001u32;
    if !((*tmr).type_0 > 0i32 && (*tmr).type_0 < 19i32) {
        /*
         * SCTP_PRINTF("SCTP timer fired with invalid type: 0x%x\n",
         * tmr->type);
         */
        return;
    }
    (*tmr).stopped_from = 0xa002u32;
    if (*tmr).type_0 != 17i32 && inp.is_null() {
        return;
    }
    /* if this is an iterator timeout, get the struct and clear inp */
    (*tmr).stopped_from = 0xa003u32;
    if !inp.is_null() {
        ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
        if (*inp).sctp_socket.is_null()
            && ((*tmr).type_0 != 15i32
                && (*tmr).type_0 != 2i32
                && (*tmr).type_0 != 1i32
                && (*tmr).type_0 != 3i32
                && (*tmr).type_0 != 5i32
                && (*tmr).type_0 != 4i32
                && (*tmr).type_0 != 9i32
                && (*tmr).type_0 != 11i32
                && (*tmr).type_0 != 16i32)
        {
            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
            return;
        }
    }
    (*tmr).stopped_from = 0xa004u32;
    if !stcb.is_null() {
        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
        if (*stcb).asoc.state == 0i32 {
            ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, -(1i32) as uint32_t);
            if !inp.is_null() {
                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
            }
            return;
        }
    }
    type_0 = (*tmr).type_0;
    (*tmr).stopped_from = 0xa005u32;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Timer type %d goes off\n\x00" as *const u8 as *const libc::c_char,
                type_0,
            );
        }
    }
    if (*tmr).timer.c_flags & 0x2i32 == 0 {
        if !inp.is_null() {
            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
        }
        if !stcb.is_null() {
            ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, -(1i32) as uint32_t);
        }
        return;
    }
    (*tmr).stopped_from = 0xa006u32;
    if !stcb.is_null() {
        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, -(1i32) as uint32_t);
        if type_0 != 16i32 && ((*stcb).asoc.state == 0i32 || (*stcb).asoc.state & 0x200i32 != 0) {
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            if !inp.is_null() {
                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
            }
            return;
        }
    } else if !inp.is_null() {
        if type_0 != 15i32 {
            pthread_mutex_lock(&mut (*inp).inp_mtx);
        }
    } else {
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
    }
    /* record in stopped what t-o occurred */
    (*tmr).stopped_from = type_0 as uint32_t;
    /* mark as being serviced now */
    if (*tmr).timer.c_flags & 0x4i32 != 0 {
        /*
         * Callout has been rescheduled.
         */
        current_block = 11287197166876456010;
    } else if (*tmr).timer.c_flags & 0x2i32 == 0 {
        current_block = 11287197166876456010;
    } else {
        (*tmr).timer.c_flags &= !(0x2i32);
        if !stcb.is_null()
            && (*(*stcb).sctp_ep).sctp_flags & 0x10000000u32 == 0
            && !(*stcb).sctp_socket.is_null()
        {
            upcall_socket = (*stcb).sctp_socket;
            pthread_mutex_lock(&mut (*upcall_socket).so_rcv.sb_mtx);
            (*upcall_socket).so_count += 1;
            pthread_mutex_unlock(&mut (*upcall_socket).so_rcv.sb_mtx);
        }
        /* call the handler for the appropriate timer type */
        match type_0 {
            17 => {
                sctp_handle_addr_wq();
                current_block = 4497948414247713119;
            }
            1 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timodata,
                        1u32,
                    );
                    (*stcb).asoc.timodata = (*stcb).asoc.timodata.wrapping_add(1);
                    (*stcb).asoc.num_send_timers_up -= 1;
                    if ((*stcb).asoc.num_send_timers_up as libc::c_int) < 0i32 {
                        (*stcb).asoc.num_send_timers_up = 0i16
                    }
                    if sctp_t3rxt_timer(inp, stcb, net) != 0 {
                        /* no need to unlock on tcb its gone */
                        current_block = 14502359895342408557;
                    } else {
                        sctp_chunk_output(inp, stcb, 1i32, 0i32);
                        if (*stcb).asoc.num_send_timers_up as libc::c_int == 0i32
                            && (*stcb).asoc.sent_queue_cnt > 0u32
                        {
                            let mut chk = 0 as *mut sctp_tmit_chunk;
                            /*
                             * safeguard. If there on some on the sent queue
                             * somewhere but no timers running something is
                             * wrong... so we start a timer on the first chunk
                             * on the send queue on whatever net it is sent to.
                             */
                            chk = (*stcb).asoc.sent_queue.tqh_first;
                            sctp_timer_start(1i32, inp, stcb, (*chk).whoTo);
                        }
                        current_block = 4497948414247713119;
                    }
                }
            }
            2 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoinit,
                        1u32,
                    );
                    (*stcb).asoc.timoinit = (*stcb).asoc.timoinit.wrapping_add(1);
                    if sctp_t1init_timer(inp, stcb, net) != 0 {
                        /* no need to unlock on tcb its gone */
                        current_block = 14502359895342408557;
                    } else {
                        /* We do output but not here */
                        did_output = 0i32;
                        current_block = 4497948414247713119;
                    }
                }
            }
            3 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timosack,
                        1u32,
                    );
                    (*stcb).asoc.timosack = (*stcb).asoc.timosack.wrapping_add(1);
                    sctp_send_sack(stcb, 0i32);
                    sctp_chunk_output(inp, stcb, 4i32, 0i32);
                    current_block = 4497948414247713119;
                }
            }
            4 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else if sctp_shutdown_timer(inp, stcb, net) != 0 {
                    /* no need to unlock on tcb its gone */
                    current_block = 14502359895342408557;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoshutdown,
                        1u32,
                    );
                    (*stcb).asoc.timoshutdown = (*stcb).asoc.timoshutdown.wrapping_add(1);
                    sctp_chunk_output(inp, stcb, 5i32, 0i32);
                    current_block = 4497948414247713119;
                }
            }
            5 => {
                if stcb.is_null() || inp.is_null() || net.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoheartbeat,
                        1u32,
                    );
                    (*stcb).asoc.timoheartbeat = (*stcb).asoc.timoheartbeat.wrapping_add(1);
                    if sctp_heartbeat_timer(inp, stcb, net) != 0 {
                        /* no need to unlock on tcb its gone */
                        current_block = 14502359895342408557;
                    } else {
                        if (*net).dest_state as libc::c_int & 0x4i32 == 0 {
                            sctp_timer_start(5i32, inp, stcb, net);
                            sctp_chunk_output(inp, stcb, 6i32, 0i32);
                        }
                        current_block = 4497948414247713119;
                    }
                }
            }
            6 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else if sctp_cookie_timer(inp, stcb, net) != 0 {
                    /* no need to unlock on tcb its gone */
                    current_block = 14502359895342408557;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timocookie,
                        1u32,
                    );
                    (*stcb).asoc.timocookie = (*stcb).asoc.timocookie.wrapping_add(1);
                    /*
                     * We consider T3 and Cookie timer pretty much the same with
                     * respect to where from in chunk_output.
                     */
                    sctp_chunk_output(inp, stcb, 1i32, 0i32);
                    current_block = 4497948414247713119;
                }
            }
            7 => {
                if inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    let mut tv = timeval {
                        tv_sec: 0,
                        tv_usec: 0,
                    };
                    let mut secret = 0;
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timosecret,
                        1u32,
                    );
                    gettimeofday(&mut tv, 0 as *mut timezone);
                    (*inp).sctp_ep.time_of_secret_change = tv.tv_sec as libc::c_uint;
                    (*inp).sctp_ep.last_secret_number = (*inp).sctp_ep.current_secret_number;
                    (*inp).sctp_ep.current_secret_number += 1;
                    if (*inp).sctp_ep.current_secret_number as libc::c_int >= 2i32 {
                        (*inp).sctp_ep.current_secret_number = 0i8
                    }
                    secret = (*inp).sctp_ep.current_secret_number as libc::c_int;

                    for i in 0i32..8i32 {
                        (*inp).sctp_ep.secret_key[secret as usize][i as usize] =
                            sctp_select_initial_TSN(&mut (*inp).sctp_ep);
                    }
                    sctp_timer_start(7i32, inp, stcb, net);
                    did_output = 0i32;
                    current_block = 4497948414247713119;
                }
            }
            8 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timopathmtu,
                        1u32,
                    );
                    sctp_pathmtu_timer(inp, stcb, net);
                    did_output = 0i32;
                    current_block = 4497948414247713119;
                }
            }
            9 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else if sctp_shutdownack_timer(inp, stcb, net) != 0 {
                    /* no need to unlock on tcb its gone */
                    current_block = 14502359895342408557;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoshutdownack,
                        1u32,
                    );
                    (*stcb).asoc.timoshutdownack = (*stcb).asoc.timoshutdownack.wrapping_add(1);
                    sctp_chunk_output(inp, stcb, 7i32, 0i32);
                    current_block = 4497948414247713119;
                }
            }
            11 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    let mut op_err = 0 as *mut mbuf;
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoshutdownguard,
                        1u32,
                    );
                    op_err = sctp_generate_cause(
                        system_base_info.sctpsysctl.sctp_diag_info_code as uint16_t,
                        b"Shutdown guard timer expired\x00" as *const u8 as *mut libc::c_char,
                    );
                    sctp_abort_an_association(inp, stcb, op_err, 0i32);
                    /* no need to unlock on tcb its gone */
                    current_block = 14502359895342408557;
                }
            }
            14 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else if sctp_strreset_timer(inp, stcb, net) != 0 {
                    /* no need to unlock on tcb its gone */
                    current_block = 14502359895342408557;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timostrmrst,
                        1u32,
                    );
                    sctp_chunk_output(inp, stcb, 9i32, 0i32);
                    current_block = 4497948414247713119;
                }
            }
            10 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else if sctp_asconf_timer(inp, stcb, net) != 0 {
                    current_block = 14502359895342408557;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoasconf,
                        1u32,
                    );
                    sctp_chunk_output(inp, stcb, 8i32, 0i32);
                    current_block = 4497948414247713119;
                }
            }
            18 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    sctp_delete_prim_timer(inp, stcb, net);
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timodelprim,
                        1u32,
                    );
                    current_block = 4497948414247713119;
                }
            }
            12 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoautoclose,
                        1u32,
                    );
                    sctp_autoclose_timer(inp, stcb, net);
                    sctp_chunk_output(inp, stcb, 10i32, 0i32);
                    did_output = 0i32;
                    current_block = 4497948414247713119;
                }
            }
            16 => {
                if stcb.is_null() || inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_timoassockill,
                        1u32,
                    );
                    /* Can we free it yet? */
                    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                    sctp_timer_stop(
                        16i32,
                        inp,
                        stcb,
                        0 as *mut sctp_nets,
                        (0x60000000i32 + 0x1i32) as uint32_t,
                    );
                    sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0x2i32);
                    /*
                     * free asoc, always unlocks (or destroy's) so prevent
                     * duplicate unlock or unlock of a free mtx :-0
                     */
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 84095175127814242;
                }
            }
            15 => {
                ::std::intrinsics::atomic_xadd(
                    &mut system_base_info.sctpstat.sctps_timoinpkill,
                    1u32,
                );
                if inp.is_null() {
                    current_block = 4497948414247713119;
                } else {
                    /*
                     * special case, take away our increment since WE are the
                     * killer
                     */
                    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                    sctp_timer_stop(
                        15i32,
                        inp,
                        0 as *mut sctp_tcb,
                        0 as *mut sctp_nets,
                        (0x60000000i32 + 0x3i32) as uint32_t,
                    );
                    sctp_inpcb_free(inp, 1i32, 2i32);
                    inp = 0 as *mut sctp_inpcb;
                    current_block = 84095175127814242;
                }
            }
            _ => {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"sctp_timeout_handler:unknown timer %d\n\x00" as *const u8
                                as *const libc::c_char,
                            type_0,
                        );
                    }
                }
                current_block = 4497948414247713119;
            }
        }
        match current_block {
            14502359895342408557 => {}
            84095175127814242 => {}
            _ => {
                if did_output != 0 && !stcb.is_null() {
                    /*
                     * Now we need to clean up the control chunk chain if an
                     * ECNE is on it. It must be marked as UNSENT again so next
                     * call will continue to send it until such time that we get
                     * a CWR, to remove it. It is, however, less likely that we
                     * will find a ecn echo on the chain though.
                     */
                    sctp_fix_ecn_echo(&mut (*stcb).asoc);
                }
                current_block = 11287197166876456010;
            }
        }
    }
    match current_block {
        11287197166876456010 =>
        /*
         * Not active, so no action.
         */
        {
            if !stcb.is_null() {
                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            } else if !inp.is_null() {
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            } else {
                pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.wq_addr_mtx);
            }
            current_block = 14502359895342408557;
        }
        _ => {}
    }
    match current_block {
        14502359895342408557 =>
        /* no need to unlock on tcb its gone */
        {
            if !upcall_socket.is_null() {
                if (*upcall_socket).so_upcall.is_some()
                    && (*upcall_socket).so_error as libc::c_int != 0i32
                {
                    Some(
                        (*upcall_socket)
                            .so_upcall
                            .expect("non-null function pointer"),
                    )
                    .expect("non-null function pointer")(
                        upcall_socket,
                        (*upcall_socket).so_upcallarg,
                        0x1i32,
                    );
                }
                pthread_mutex_lock(&mut accept_mtx);
                pthread_mutex_lock(&mut (*upcall_socket).so_rcv.sb_mtx);
                (*upcall_socket).so_count -= 1;
                if (*upcall_socket).so_count == 0i32 {
                    sofree(upcall_socket);
                } else {
                    pthread_mutex_unlock(&mut (*upcall_socket).so_rcv.sb_mtx);
                    pthread_mutex_unlock(&mut accept_mtx);
                }
            }
            if !inp.is_null() {
                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
            }
        }
        _ => {}
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Timer now complete (type = %d)\n\x00" as *const u8 as *const libc::c_char,
                type_0,
            );
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_timer_start(
    mut t_type: libc::c_int,
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    let mut to_ticks = 0;
    let mut tmr = 0 as *mut sctp_timer;
    if t_type != 17i32 && inp.is_null() {
        return;
    }
    tmr = 0 as *mut sctp_timer;
    !stcb.is_null();
    match t_type {
        17 => {
            /* Only 1 tick away :-) */
            tmr = &mut system_base_info.sctppcbinfo.addr_wq_timer;
            to_ticks = 2u32
        }
        1 => {
            let mut rto_val = 0;
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).rxt_timer;
            if (*net).RTO == 0u32 {
                rto_val = (*stcb).asoc.initial_rto as libc::c_int
            } else {
                rto_val = (*net).RTO as libc::c_int
            }
            to_ticks = if hz == 1000i32 {
                rto_val
            } else {
                (rto_val * hz + 999i32) / 1000i32
            } as uint32_t
        }
        2 => {
            /*
             * Here we use the INIT timer default usually about 1
             * minute.
             */
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).rxt_timer;
            if (*net).RTO == 0u32 {
                to_ticks = if hz == 1000i32 {
                    (*stcb).asoc.initial_rto
                } else {
                    (*stcb)
                        .asoc
                        .initial_rto
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            } else {
                to_ticks = if hz == 1000i32 {
                    (*net).RTO
                } else {
                    (*net)
                        .RTO
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            }
        }
        3 => {
            /*
             * Here we use the Delayed-Ack timer value from the inp
             * ususually about 200ms.
             */
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.dack_timer;
            to_ticks = if hz == 1000i32 {
                (*stcb).asoc.delayed_ack
            } else {
                (*stcb)
                    .asoc
                    .delayed_ack
                    .wrapping_mul(hz as libc::c_uint)
                    .wrapping_add(999u32)
                    .wrapping_div(1000u32)
            }
        }
        4 => {
            /* Here we use the RTO of the destination. */
            if stcb.is_null() || net.is_null() {
                return;
            }
            if (*net).RTO == 0u32 {
                to_ticks = if hz == 1000i32 {
                    (*stcb).asoc.initial_rto
                } else {
                    (*stcb)
                        .asoc
                        .initial_rto
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            } else {
                to_ticks = if hz == 1000i32 {
                    (*net).RTO
                } else {
                    (*net)
                        .RTO
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            }
            tmr = &mut (*net).rxt_timer
        }
        5 => {
            /*
             * the net is used here so that we can add in the RTO. Even
             * though we use a different timer. We also add the HB timer
             * PLUS a random jitter.
             */
            if stcb.is_null() || net.is_null() {
                return;
            } else {
                let mut rndval = 0;
                let mut jitter = 0;
                if (*net).dest_state as libc::c_int & 0x4i32 != 0
                    && (*net).dest_state as libc::c_int & 0x200i32 == 0
                {
                    return;
                }
                if (*net).RTO == 0u32 {
                    to_ticks = (*stcb).asoc.initial_rto
                } else {
                    to_ticks = (*net).RTO
                }
                rndval = sctp_select_initial_TSN(&mut (*inp).sctp_ep);
                jitter = rndval.wrapping_rem(to_ticks);
                if jitter >= to_ticks >> 1i32 {
                    to_ticks = to_ticks.wrapping_add(jitter.wrapping_sub(to_ticks >> 1i32))
                } else {
                    to_ticks = to_ticks.wrapping_sub(jitter)
                }
                if (*net).dest_state as libc::c_int & 0x200i32 == 0
                    && (*net).dest_state as libc::c_int & 0x800i32 == 0
                {
                    to_ticks = (to_ticks).wrapping_add((*net).heart_beat_delay)
                }
                /*
                 * Now we must convert the to_ticks that are now in
                 * ms to ticks.
                 */
                to_ticks = if hz == 1000i32 {
                    to_ticks
                } else {
                    to_ticks
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                };
                tmr = &mut (*net).hb_timer
            }
        }
        6 => {
            /*
             * Here we can use the RTO timer from the network since one
             * RTT was compelete. If a retran happened then we will be
             * using the RTO initial value.
             */
            if stcb.is_null() || net.is_null() {
                return;
            }
            if (*net).RTO == 0u32 {
                to_ticks = if hz == 1000i32 {
                    (*stcb).asoc.initial_rto
                } else {
                    (*stcb)
                        .asoc
                        .initial_rto
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            } else {
                to_ticks = if hz == 1000i32 {
                    (*net).RTO
                } else {
                    (*net)
                        .RTO
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            }
            tmr = &mut (*net).rxt_timer
        }
        7 => {
            /*
             * nothing needed but the endpoint here ususually about 60
             * minutes.
             */
            tmr = &mut (*inp).sctp_ep.signature_change;
            to_ticks = (*inp).sctp_ep.sctp_timeoutticks[6usize]
        }
        16 => {
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.strreset_timer;
            to_ticks = if hz == 1000i32 {
                10i32
            } else {
                (10i32 * hz + 999i32) / 1000i32
            } as uint32_t
        }
        15 => {
            /*
             * The inp is setup to die. We re-use the signature_chage
             * timer since that has stopped and we are in the GONE
             * state.
             */
            tmr = &mut (*inp).sctp_ep.signature_change;
            to_ticks = if hz == 1000i32 {
                20i32
            } else {
                (20i32 * hz + 999i32) / 1000i32
            } as uint32_t
        }
        8 => {
            /*
             * Here we use the value found in the EP for PMTU ususually
             * about 10 minutes.
             */
            if stcb.is_null() || net.is_null() {
                return;
            }
            if (*net).dest_state as libc::c_int & 0x2i32 != 0 {
                return;
            }
            to_ticks = (*inp).sctp_ep.sctp_timeoutticks[4usize];
            tmr = &mut (*net).pmtu_timer
        }
        9 => {
            /* Here we use the RTO of the destination */
            if stcb.is_null() || net.is_null() {
                return;
            }
            if (*net).RTO == 0u32 {
                to_ticks = if hz == 1000i32 {
                    (*stcb).asoc.initial_rto
                } else {
                    (*stcb)
                        .asoc
                        .initial_rto
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            } else {
                to_ticks = if hz == 1000i32 {
                    (*net).RTO
                } else {
                    (*net)
                        .RTO
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            }
            tmr = &mut (*net).rxt_timer
        }
        11 => {
            /*
             * Here we use the endpoints shutdown guard timer usually
             * about 3 minutes.
             */
            if stcb.is_null() {
                return;
            }
            if (*inp).sctp_ep.sctp_timeoutticks[5usize] == 0u32 {
                to_ticks = (5u32).wrapping_mul(
                    (if hz == 1000i32 {
                        (*stcb).asoc.maxrto
                    } else {
                        (*stcb)
                            .asoc
                            .maxrto
                            .wrapping_mul(hz as libc::c_uint)
                            .wrapping_add(999u32)
                            .wrapping_div(1000u32)
                    }),
                )
            } else {
                to_ticks = (*inp).sctp_ep.sctp_timeoutticks[5usize]
            }
            tmr = &mut (*stcb).asoc.shut_guard_timer
        }
        14 => {
            /*
             * Here the timer comes from the stcb but its value is from
             * the net's RTO.
             */
            if stcb.is_null() || net.is_null() {
                return;
            }
            if (*net).RTO == 0u32 {
                to_ticks = if hz == 1000i32 {
                    (*stcb).asoc.initial_rto
                } else {
                    (*stcb)
                        .asoc
                        .initial_rto
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            } else {
                to_ticks = if hz == 1000i32 {
                    (*net).RTO
                } else {
                    (*net)
                        .RTO
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            }
            tmr = &mut (*stcb).asoc.strreset_timer
        }
        10 => {
            /*
             * Here the timer comes from the stcb but its value is from
             * the net's RTO.
             */
            if stcb.is_null() || net.is_null() {
                return;
            }
            if (*net).RTO == 0u32 {
                to_ticks = if hz == 1000i32 {
                    (*stcb).asoc.initial_rto
                } else {
                    (*stcb)
                        .asoc
                        .initial_rto
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            } else {
                to_ticks = if hz == 1000i32 {
                    (*net).RTO
                } else {
                    (*net)
                        .RTO
                        .wrapping_mul(hz as libc::c_uint)
                        .wrapping_add(999u32)
                        .wrapping_div(1000u32)
                }
            }
            tmr = &mut (*stcb).asoc.asconf_timer
        }
        18 => {
            if stcb.is_null() || !net.is_null() {
                return;
            }
            to_ticks = if hz == 1000i32 {
                (*stcb).asoc.initial_rto
            } else {
                (*stcb)
                    .asoc
                    .initial_rto
                    .wrapping_mul(hz as libc::c_uint)
                    .wrapping_add(999u32)
                    .wrapping_div(1000u32)
            };
            tmr = &mut (*stcb).asoc.delete_prim_timer
        }
        12 => {
            if stcb.is_null() {
                return;
            }
            if (*stcb).asoc.sctp_autoclose_ticks == 0u32 {
                /*
                 * Really an error since stcb is NOT set to
                 * autoclose
                 */
                return;
            }
            to_ticks = (*stcb).asoc.sctp_autoclose_ticks;
            tmr = &mut (*stcb).asoc.autoclose_timer
        }
        _ => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"%s: Unknown timer type %d\n\x00" as *const u8 as *const libc::c_char,
                        (*::std::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"sctp_timer_start\x00",
                        ))
                        .as_ptr(),
                        t_type,
                    );
                }
            }
            return;
        }
    }
    if to_ticks <= 0u32 || tmr.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%s: %d:software error to_ticks:%d tmr:%p not set ??\n\x00" as *const u8
                        as *const libc::c_char,
                    (*::std::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"sctp_timer_start\x00",
                    ))
                    .as_ptr(),
                    t_type,
                    to_ticks,
                    tmr as *mut libc::c_void,
                );
            }
        }
        return;
    }
    if (*tmr).timer.c_flags & 0x4i32 != 0 {
        /*
         * we do NOT allow you to have it already running. if it is
         * we leave the current one up unchanged
         */
        return;
    }
    /* At this point we can proceed */
    if t_type == 1i32 {
        (*stcb).asoc.num_send_timers_up += 1
    }
    (*tmr).stopped_from = 0u32;
    (*tmr).type_0 = t_type;
    (*tmr).ep = inp as *mut libc::c_void;
    (*tmr).tcb = stcb as *mut libc::c_void;
    (*tmr).net = net as *mut libc::c_void;
    (*tmr).self_0 = tmr as *mut libc::c_void;
    (*tmr).ticks = sctp_get_tick_count();
    sctp_os_timer_start(
        &mut (*tmr).timer,
        to_ticks,
        Some(sctp_timeout_handler as unsafe extern "C" fn(_: *mut libc::c_void) -> ()),
        tmr as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn sctp_timer_stop(
    mut t_type: libc::c_int,
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut from: uint32_t,
) {
    let mut tmr = 0 as *mut sctp_timer;
    if t_type != 17i32 && inp.is_null() {
        return;
    }
    tmr = 0 as *mut sctp_timer;
    !stcb.is_null();
    match t_type {
        17 => tmr = &mut system_base_info.sctppcbinfo.addr_wq_timer,
        1 => {
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).rxt_timer
        }
        2 => {
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).rxt_timer
        }
        3 => {
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.dack_timer
        }
        4 => {
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).rxt_timer
        }
        5 => {
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).hb_timer
        }
        6 => {
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).rxt_timer
        }
        7 => {
            /* nothing needed but the endpoint here */
            tmr = &mut (*inp).sctp_ep.signature_change
        }
        16 => {
            /*
             * Stop the asoc kill timer.
             */
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.strreset_timer
        }
        15 => {
            /*
             * The inp is setup to die. We re-use the signature_chage
             * timer since that has stopped and we are in the GONE
             * state.
             */
            tmr = &mut (*inp).sctp_ep.signature_change
        }
        8 => {
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).pmtu_timer
        }
        9 => {
            if stcb.is_null() || net.is_null() {
                return;
            }
            tmr = &mut (*net).rxt_timer
        }
        11 => {
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.shut_guard_timer
        }
        14 => {
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.strreset_timer
        }
        10 => {
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.asconf_timer
        }
        18 => {
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.delete_prim_timer
        }
        12 => {
            if stcb.is_null() {
                return;
            }
            tmr = &mut (*stcb).asoc.autoclose_timer
        }
        _ => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x1u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"%s: Unknown timer type %d\n\x00" as *const u8 as *const libc::c_char,
                        (*::std::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"sctp_timer_stop\x00",
                        ))
                        .as_ptr(),
                        t_type,
                    );
                }
            }
        }
    }
    if tmr.is_null() {
        return;
    }
    if (*tmr).type_0 != t_type && (*tmr).type_0 != 0 {
        /*
         * Ok we have a timer that is under joint use. Cookie timer
         * per chance with the SEND timer. We therefore are NOT
         * running the timer that the caller wants stopped.  So just
         * return.
         */
        return;
    }
    if t_type == 1i32 && !stcb.is_null() {
        (*stcb).asoc.num_send_timers_up -= 1;
        if ((*stcb).asoc.num_send_timers_up as libc::c_int) < 0i32 {
            (*stcb).asoc.num_send_timers_up = 0i16
        }
    }
    (*tmr).self_0 = 0 as *mut libc::c_void;
    (*tmr).stopped_from = from;
    sctp_os_timer_stop(&mut (*tmr).timer);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_calculate_len(mut m: *mut mbuf) -> uint32_t {
    let mut tlen = 0u32;
    let mut at = 0 as *mut mbuf;
    at = m;
    while !at.is_null() {
        tlen = (tlen).wrapping_add((*at).m_hdr.mh_len as libc::c_uint);
        at = (*at).m_hdr.mh_next
    }
    return tlen;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_mtu_size_reset(
    mut inp: *mut sctp_inpcb,
    mut asoc: *mut sctp_association,
    mut mtu: uint32_t,
) {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut eff_mtu = 0;
    let mut ovh = 0;
    (*asoc).smallest_mtu = mtu;
    if (*inp).sctp_flags & 0x4000000u32 != 0 {
        ovh = (::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
            as libc::c_uint
    } else {
        ovh = (::std::mem::size_of::<ip>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
            as libc::c_uint
    }
    eff_mtu = mtu.wrapping_sub(ovh);
    chk = (*asoc).send_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).send_size as libc::c_uint > eff_mtu {
            (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t
        }
        chk = (*chk).sctp_next.tqe_next
    }
    chk = (*asoc).sent_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).send_size as libc::c_uint > eff_mtu {
            (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t
        }
        chk = (*chk).sctp_next.tqe_next
    }
}
/*
 * Given an association and starting time of the current RTT period, update
 * RTO in number of msecs. net should point to the current network.
 * Return 1, if an RTO update was performed, return 0 if no update was
 * performed due to invalid starting point.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_calculate_rto(
    mut stcb: *mut sctp_tcb,
    mut asoc: *mut sctp_association,
    mut net: *mut sctp_nets,
    mut old: *mut timeval,
    mut rtt_from_sack: libc::c_int,
) -> libc::c_int {
    let mut now = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut rtt_us = 0;
    let mut rtt = 0;
    let mut new_rto = 0;
    let mut first_measure = 0i32;
    /* ***********************/
    /* 1. calculate new RTT */
    /* ***********************/
    /* get the current time */
    if (*stcb).asoc.use_precise_time != 0 {
        gettimeofday(&mut now, 0 as *mut timezone);
    } else {
        gettimeofday(&mut now, 0 as *mut timezone);
    }
    if (*old).tv_sec > now.tv_sec || (*old).tv_sec == now.tv_sec && (*old).tv_sec > now.tv_sec {
        /* The starting point is in the future. */
        return 0i32;
    }
    now.tv_sec -= (*old).tv_sec;
    now.tv_usec -= (*old).tv_usec;
    if now.tv_usec < 0i64 {
        now.tv_sec -= 1;
        now.tv_usec += 1000000i64
    }
    rtt_us = (1000000u64)
        .wrapping_mul(now.tv_sec as uint64_t)
        .wrapping_add(now.tv_usec as uint64_t);
    if rtt_us > (60000i32 * 1000i32) as libc::c_ulong {
        /* The RTT is larger than a sane value. */
        return 0i32;
    }
    /* store the current RTT in us */
    (*net).rtt = rtt_us;
    /* compute rtt in ms */
    rtt = (*net).rtt.wrapping_div(1000u64) as int32_t;
    if (*asoc).cc_functions.sctp_rtt_calculated.is_some() && rtt_from_sack == 1i32 {
        /* Tell the CC module that a new update has just occurred from a sack */
        Some(
            (*asoc)
                .cc_functions
                .sctp_rtt_calculated
                .expect("non-null function pointer"),
        )
        .expect("non-null function pointer")(stcb, net, &mut now);
    }
    /* Do we need to determine the lan? We do this only
     * on sacks i.e. RTT being determined from data not
     * non-data (HB/INIT->INITACK).
     */
    if rtt_from_sack == 1i32 && (*net).lan_type as libc::c_int == 0i32 {
        if (*net).rtt > 900u64 {
            (*net).lan_type = 2u8
        } else {
            (*net).lan_type = 1u8
        }
    }
    /* **************************/
    /* 2. update RTTVAR & SRTT */
    /* **************************/
    /*-
     * Compute the scaled average lastsa and the
     * scaled variance lastsv as described in van Jacobson
     * Paper "Congestion Avoidance and Control", Annex A.
     *
     * (net->lastsa >> SCTP_RTT_SHIFT) is the srtt
     * (net->lastsv >> SCTP_RTT_VAR_SHIFT) is the rttvar
     */
    if (*net).RTO_measured != 0 {
        rtt -= (*net).lastsa >> 3i32;
        (*net).lastsa += rtt;
        if rtt < 0i32 {
            rtt = -rtt
        }
        rtt -= (*net).lastsv >> 2i32;
        (*net).lastsv += rtt;
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2000u32 != 0 {
            rto_logging(net, 52i32);
        }
    } else {
        /* First RTO measurment */
        (*net).RTO_measured = 1u8;
        first_measure = 1i32;
        (*net).lastsa = rtt << 3i32;
        (*net).lastsv = (rtt / 2i32) << 2i32;
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2000u32 != 0 {
            rto_logging(net, 51i32);
        }
    }
    if (*net).lastsv == 0i32 {
        (*net).lastsv = 10i32
    }
    new_rto = (((*net).lastsa >> 3i32) + (*net).lastsv) as uint32_t;
    if new_rto > 400u32 && (*stcb).asoc.sat_network_lockout as libc::c_int == 0i32 {
        (*stcb).asoc.sat_network = 1u8
    } else if first_measure == 0 && (*stcb).asoc.sat_network as libc::c_int != 0 {
        (*stcb).asoc.sat_network = 0u8;
        (*stcb).asoc.sat_network_lockout = 1u8
    }
    /* bound it, per C6/C7 in Section 5.3.1 */
    if new_rto < (*stcb).asoc.minrto {
        new_rto = (*stcb).asoc.minrto
    }
    if new_rto > (*stcb).asoc.maxrto {
        new_rto = (*stcb).asoc.maxrto
    }
    (*net).RTO = new_rto;
    return 1i32;
}
/*
 * return a pointer to a contiguous piece of data from the given mbuf chain
 * starting at 'off' for 'len' bytes.  If the desired piece spans more than
 * one mbuf, a copy is made at 'ptr'. caller must ensure that the buffer size
 * is >= 'len' returns NULL if there there isn't 'len' bytes in the chain.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_m_getptr(
    mut m: *mut mbuf,
    mut off: libc::c_int,
    mut len: libc::c_int,
    mut in_ptr: *mut uint8_t,
) -> caddr_t {
    let mut ptr = 0 as *mut uint8_t;
    ptr = in_ptr;
    if off < 0i32 || len <= 0i32 {
        return 0 as caddr_t;
    }
    /* find the desired start location */
    while !m.is_null() && off > 0i32 {
        if off < (*m).m_hdr.mh_len {
            break;
        }
        off -= (*m).m_hdr.mh_len;
        m = (*m).m_hdr.mh_next
    }
    if m.is_null() {
        return 0 as caddr_t;
    }
    /* is the current mbuf large enough (eg. contiguous)? */
    if (*m).m_hdr.mh_len - off >= len {
        return (*m).m_hdr.mh_data.offset(off as isize);
    } else {
        /* else, it spans more than one mbuf, so save a temp copy... */
        while !m.is_null() && len > 0i32 {
            let mut count = 0;
            count = if (*m).m_hdr.mh_len - off > len {
                len
            } else {
                ((*m).m_hdr.mh_len) - off
            } as uint32_t;
            memcpy(
                ptr as *mut libc::c_void,
                (*m).m_hdr.mh_data.offset(off as isize) as *const libc::c_void,
                count as libc::c_ulong,
            );
            len = (len as libc::c_uint).wrapping_sub(count) as libc::c_int;
            ptr = ptr.offset(count as isize);
            off = 0i32;
            m = (*m).m_hdr.mh_next
        }
        if m.is_null() && len > 0i32 {
            return 0 as caddr_t;
        } else {
            return in_ptr as caddr_t;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_get_next_param(
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut pull: *mut sctp_paramhdr,
    mut pull_limit: libc::c_int,
) -> *mut sctp_paramhdr {
    /* This just provides a typed signature to Peter's Pull routine */
    return sctp_m_getptr(m, offset, pull_limit, pull as *mut uint8_t) as *mut sctp_paramhdr;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_add_pad_tombuf(
    mut m: *mut mbuf,
    mut padlen: libc::c_int,
) -> *mut mbuf {
    let mut m_last = 0 as *mut mbuf;
    let mut dp = 0 as *mut libc::c_char;
    if padlen > 3i32 {
        return 0 as *mut mbuf;
    }
    if padlen as libc::c_long
        <= (if (*m).m_hdr.mh_flags & 0x1i32 != 0 {
            (if (*m).m_hdr.mh_flags & 0x8i32 == 0
                && ((*m).m_hdr.mh_flags & 0x1i32 == 0
                    || *(*m).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32)
            {
                (*m).M_dat
                    .MH
                    .MH_dat
                    .MH_ext
                    .ext_buf
                    .offset((*m).M_dat.MH.MH_dat.MH_ext.ext_size as isize)
                    .wrapping_offset_from((*m).m_hdr.mh_data.offset((*m).m_hdr.mh_len as isize))
                    as libc::c_long
            } else {
                0i64
            })
        } else {
            (&mut *(*m).M_dat.M_databuf.as_mut_ptr().offset(
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_char)
                .wrapping_offset_from((*m).m_hdr.mh_data.offset((*m).m_hdr.mh_len as isize))
                as libc::c_long
        })
    {
        /*
         * The easy way. We hope the majority of the time we hit
         * here :)
         */
        m_last = m
    } else {
        /* Hard way we must grow the mbuf chain */
        m_last = sctp_get_mbuf_for_msg(padlen as libc::c_uint, 0i32, 0x1i32, 1i32, 1i32);
        if m_last.is_null() {
            return 0 as *mut mbuf;
        }
        (*m_last).m_hdr.mh_len = 0i32;
        (*m_last).m_hdr.mh_next = 0 as *mut mbuf;
        (*m).m_hdr.mh_next = m_last
    }
    dp = (*m_last)
        .m_hdr
        .mh_data
        .offset((*m_last).m_hdr.mh_len as isize);
    (*m_last).m_hdr.mh_len += padlen;
    memset(dp as *mut libc::c_void, 0i32, padlen as libc::c_ulong);
    return m_last;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_pad_lastmbuf(
    mut m: *mut mbuf,
    mut padval: libc::c_int,
    mut last_mbuf: *mut mbuf,
) -> *mut mbuf {
    if !last_mbuf.is_null() {
        return sctp_add_pad_tombuf(last_mbuf, padval);
    } else {
        let mut m_at = 0 as *mut mbuf;
        m_at = m;
        while !m_at.is_null() {
            if (*m_at).m_hdr.mh_next.is_null() {
                return sctp_add_pad_tombuf(m_at, padval);
            }
            m_at = (*m_at).m_hdr.mh_next
        }
    }
    return 0 as *mut mbuf;
}
unsafe extern "C" fn sctp_notify_assoc_change(
    mut state: uint16_t,
    mut stcb: *mut sctp_tcb,
    mut error: uint16_t,
    mut abort: *mut sctp_abort_chunk,
    mut from_peer: uint8_t,
    mut so_locked: libc::c_int,
) {
    if stcb.is_null() {
        return;
    }
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x800u64 == 0x800u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x800u64 == 0x800u64
    {
        let mut current_block: u64;
        let mut m_notify = 0 as *mut mbuf;
        let mut notif_len = 0;
        let mut abort_len = 0;
        notif_len = ::std::mem::size_of::<sctp_assoc_change>() as libc::c_uint;
        if !abort.is_null() {
            abort_len = ntohs((*abort).ch.chunk_length);
            /*
             * Only SCTP_CHUNK_BUFFER_SIZE are guaranteed to be
             * contiguous.
             */
            if abort_len as libc::c_int > 512i32 {
                abort_len = 512u16
            }
        } else {
            abort_len = 0u16
        }
        if state as libc::c_int == 0x1i32 || state as libc::c_int == 0x3i32 {
            notif_len = notif_len.wrapping_add(0x6u32)
        } else if state as libc::c_int == 0x2i32 || state as libc::c_int == 0x5i32 {
            notif_len = notif_len.wrapping_add(abort_len as libc::c_uint)
        }
        m_notify = sctp_get_mbuf_for_msg(notif_len, 0i32, 0x1i32, 1i32, 1i32);
        if m_notify.is_null() {
            /* Retry with smaller value. */
            notif_len = ::std::mem::size_of::<sctp_assoc_change>() as libc::c_uint;
            m_notify = sctp_get_mbuf_for_msg(notif_len, 0i32, 0x1i32, 1i32, 1i32);
            if m_notify.is_null() {
                current_block = 345005610389269546;
            } else {
                current_block = 2232869372362427478;
            }
        } else {
            current_block = 2232869372362427478;
        }
        match current_block {
            345005610389269546 => {}
            _ => {
                let mut sac = 0 as *mut sctp_assoc_change;
                let mut control = 0 as *mut sctp_queued_to_read;
                (*m_notify).m_hdr.mh_next = 0 as *mut mbuf;
                sac = (*m_notify).m_hdr.mh_data as *mut sctp_assoc_change;
                memset(sac as *mut libc::c_void, 0i32, notif_len as libc::c_ulong);
                (*sac).sac_type = 0x1u16;
                (*sac).sac_flags = 0u16;
                (*sac).sac_length = ::std::mem::size_of::<sctp_assoc_change>() as uint32_t;
                (*sac).sac_state = state;
                (*sac).sac_error = error;
                /* XXX verify these stream counts */
                (*sac).sac_outbound_streams = (*stcb).asoc.streamoutcnt;
                (*sac).sac_inbound_streams = (*stcb).asoc.streamincnt;
                (*sac).sac_assoc_id = (*stcb).asoc.assoc_id;
                if notif_len as libc::c_ulong
                    > ::std::mem::size_of::<sctp_assoc_change>() as libc::c_ulong
                {
                    if state as libc::c_int == 0x1i32 || state as libc::c_int == 0x3i32 {
                        let mut i = 0;
                        i = 0u32;
                        if (*stcb).asoc.prsctp_supported as libc::c_int == 1i32 {
                            let fresh2 = i;
                            i = i.wrapping_add(1);
                            *(*sac).sac_info.as_mut_ptr().offset(fresh2 as isize) = 0x1u8
                        }
                        if (*stcb).asoc.auth_supported as libc::c_int == 1i32 {
                            let fresh3 = i;
                            i = i.wrapping_add(1);
                            *(*sac).sac_info.as_mut_ptr().offset(fresh3 as isize) = 0x2u8
                        }
                        if (*stcb).asoc.asconf_supported as libc::c_int == 1i32 {
                            let fresh4 = i;
                            i = i.wrapping_add(1);
                            *(*sac).sac_info.as_mut_ptr().offset(fresh4 as isize) = 0x3u8
                        }
                        if (*stcb).asoc.idata_supported as libc::c_int == 1i32 {
                            let fresh5 = i;
                            i = i.wrapping_add(1);
                            *(*sac).sac_info.as_mut_ptr().offset(fresh5 as isize) = 0x6u8
                        }
                        let fresh6 = i;
                        i = i.wrapping_add(1);
                        *(*sac).sac_info.as_mut_ptr().offset(fresh6 as isize) = 0x4u8;
                        if (*stcb).asoc.reconfig_supported as libc::c_int == 1i32 {
                            let fresh7 = i;
                            i = i.wrapping_add(1);
                            *(*sac).sac_info.as_mut_ptr().offset(fresh7 as isize) = 0x5u8
                        }
                        (*sac).sac_length = ((*sac).sac_length).wrapping_add(i)
                    } else if state as libc::c_int == 0x2i32 || state as libc::c_int == 0x5i32 {
                        memcpy(
                            (*sac).sac_info.as_mut_ptr() as *mut libc::c_void,
                            abort as *const libc::c_void,
                            abort_len as libc::c_ulong,
                        );
                        (*sac).sac_length =
                            ((*sac).sac_length).wrapping_add(abort_len as libc::c_uint)
                    }
                }
                (*m_notify).m_hdr.mh_len = (*sac).sac_length as libc::c_int;
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
                if !control.is_null() {
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
                } else {
                    m_freem(m_notify);
                }
            }
        }
    }
    /*
     * For 1-to-1 style sockets, we send up and error when an ABORT
     * comes in.
     */
    if ((*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0)
        && (state as libc::c_int == 0x2i32 || state as libc::c_int == 0x5i32)
    {
        pthread_mutex_lock(&mut (*(*stcb).sctp_socket).so_rcv.sb_mtx);
        if from_peer != 0 {
            if (*stcb).asoc.state & 0x7fi32 == 0x2i32 {
                (*(*stcb).sctp_socket).so_error = 111u16
            } else {
                (*(*stcb).sctp_socket).so_error = 104u16
            }
        } else if (*stcb).asoc.state & 0x7fi32 == 0x2i32 || (*stcb).asoc.state & 0x7fi32 == 0x4i32 {
            (*(*stcb).sctp_socket).so_error = 110u16
        } else {
            (*(*stcb).sctp_socket).so_error = 103u16
        }
        pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_rcv.sb_mtx);
    }
    /* Wake ANY sleepers */
    if ((*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0)
        && (state as libc::c_int == 0x2i32 || state as libc::c_int == 0x5i32)
    {
        socantrcvmore((*stcb).sctp_socket);
    }
    pthread_mutex_lock(&mut (*(*stcb).sctp_socket).so_rcv.sb_mtx);
    if (*(*stcb).sctp_socket).so_rcv.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup((*stcb).sctp_socket, &mut (*(*stcb).sctp_socket).so_rcv);
    } else {
        pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_rcv.sb_mtx);
    }
    pthread_mutex_lock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
    if (*(*stcb).sctp_socket).so_snd.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup((*stcb).sctp_socket, &mut (*(*stcb).sctp_socket).so_snd);
    } else {
        pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
    };
}
unsafe extern "C" fn sctp_notify_peer_addr_change(
    mut stcb: *mut sctp_tcb,
    mut state: uint32_t,
    mut sa: *mut sockaddr,
    mut error: uint32_t,
    mut so_locked: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut spc = 0 as *mut sctp_paddr_change;
    let mut control = 0 as *mut sctp_queued_to_read;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x1000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x1000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_paddr_change>() as libc::c_uint,
        0i32,
        0x1i32,
        1i32,
        1i32,
    );
    if m_notify.is_null() {
        return;
    }
    (*m_notify).m_hdr.mh_len = 0i32;
    spc = (*m_notify).m_hdr.mh_data as *mut sctp_paddr_change;
    memset(
        spc as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_paddr_change>() as libc::c_ulong,
    );
    (*spc).spc_type = 0x2u16;
    (*spc).spc_flags = 0u16;
    (*spc).spc_length = ::std::mem::size_of::<sctp_paddr_change>() as uint32_t;
    match (*sa).sa_family as libc::c_int {
        2 => {
            if (*(*stcb).sctp_ep).sctp_features & 0x800000u64 == 0x800000u64 {
                in6_sin_2_v4mapsin6(
                    sa as *mut sockaddr_in,
                    &mut (*spc).spc_aaddr as *mut sockaddr_storage as *mut sockaddr_in6,
                );
            } else {
                memcpy(
                    &mut (*spc).spc_aaddr as *mut sockaddr_storage as *mut libc::c_void,
                    sa as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                );
            }
        }
        10 => {
            /* SCTP_EMBEDDED_V6_SCOPE */
            memcpy(
                &mut (*spc).spc_aaddr as *mut sockaddr_storage as *mut libc::c_void,
                sa as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            );
        }
        123 => {
            memcpy(
                &mut (*spc).spc_aaddr as *mut sockaddr_storage as *mut libc::c_void,
                sa as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
            );
        }
        _ => {}
    }
    (*spc).spc_state = state;
    (*spc).spc_error = error;
    (*spc).spc_assoc_id = (*stcb).asoc.assoc_id;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_paddr_change>() as libc::c_int;
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
unsafe extern "C" fn sctp_notify_send_failed(
    mut stcb: *mut sctp_tcb,
    mut sent: uint8_t,
    mut error: uint32_t,
    mut chk: *mut sctp_tmit_chunk,
    mut so_locked: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut notifhdr_len = 0;
    let mut chkhdr_len = 0;
    let mut padding_len = 0;
    let mut payload_len = 0;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x4000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x4000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
            && (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x80000000u64 == 0u64
                || stcb.is_null()
                    && !(*stcb).sctp_ep.is_null()
                    && (*(*stcb).sctp_ep).sctp_features & 0x80000000u64 == 0u64
                || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x80000000u64 == 0x80000000u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x80000000u64 == 0x80000000u64
    {
        notifhdr_len = ::std::mem::size_of::<sctp_send_failed_event>() as libc::c_int
    } else {
        notifhdr_len = ::std::mem::size_of::<sctp_send_failed>() as libc::c_int
    }
    m_notify = sctp_get_mbuf_for_msg(notifhdr_len as libc::c_uint, 0i32, 0x1i32, 1i32, 1i32);
    if m_notify.is_null() {
        /* no space left */
        return;
    }
    (*m_notify).m_hdr.mh_len = notifhdr_len;
    if (*stcb).asoc.idata_supported != 0 {
        chkhdr_len = ::std::mem::size_of::<sctp_idata_chunk>() as libc::c_int
    } else {
        chkhdr_len = ::std::mem::size_of::<sctp_data_chunk>() as libc::c_int
    }
    /* Use some defaults in case we can't access the chunk header */
    if (*chk).send_size as libc::c_int >= chkhdr_len {
        payload_len = (*chk).send_size as libc::c_int - chkhdr_len
    } else {
        payload_len = 0i32
    }
    padding_len = 0i32;
    if !(*chk).data.is_null() {
        let mut chkhdr = 0 as *mut sctp_chunkhdr;
        chkhdr = (*(*chk).data).m_hdr.mh_data as *mut sctp_chunkhdr;
        if !chkhdr.is_null() {
            let mut chk_len = 0;
            chk_len = ntohs((*chkhdr).chunk_length) as libc::c_int;
            if chk_len >= chkhdr_len
                && (*chk).send_size as libc::c_int >= chk_len
                && (*chk).send_size as libc::c_int - chk_len < 4i32
            {
                padding_len = (*chk).send_size as libc::c_int - chk_len;
                payload_len = (*chk).send_size as libc::c_int - chkhdr_len - padding_len
            }
        }
    }
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x80000000u64 == 0x80000000u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x80000000u64 == 0x80000000u64
    {
        let mut ssfe = 0 as *mut sctp_send_failed_event;
        ssfe = (*m_notify).m_hdr.mh_data as *mut sctp_send_failed_event;
        memset(
            ssfe as *mut libc::c_void,
            0i32,
            notifhdr_len as libc::c_ulong,
        );
        (*ssfe).ssfe_type = 0xeu16;
        if sent != 0 {
            (*ssfe).ssfe_flags = 0x2u16
        } else {
            (*ssfe).ssfe_flags = 0x1u16
        }
        (*ssfe).ssfe_length = (notifhdr_len + payload_len) as uint32_t;
        (*ssfe).ssfe_error = error;
        /* not exactly what the user sent in, but should be close :) */
        (*ssfe).ssfe_info.snd_sid = (*chk).rec.data.sid;
        (*ssfe).ssfe_info.snd_flags = (*chk).rec.data.rcv_flags as uint16_t;
        (*ssfe).ssfe_info.snd_ppid = (*chk).rec.data.ppid;
        (*ssfe).ssfe_info.snd_context = (*chk).rec.data.context;
        (*ssfe).ssfe_info.snd_assoc_id = (*stcb).asoc.assoc_id;
        (*ssfe).ssfe_assoc_id = (*stcb).asoc.assoc_id
    } else {
        let mut ssf = 0 as *mut sctp_send_failed;
        ssf = (*m_notify).m_hdr.mh_data as *mut sctp_send_failed;
        memset(
            ssf as *mut libc::c_void,
            0i32,
            notifhdr_len as libc::c_ulong,
        );
        (*ssf).ssf_type = 0x4u16;
        if sent != 0 {
            (*ssf).ssf_flags = 0x2u16
        } else {
            (*ssf).ssf_flags = 0x1u16
        }
        (*ssf).ssf_length = (notifhdr_len + payload_len) as uint32_t;
        (*ssf).ssf_error = error;
        /* not exactly what the user sent in, but should be close :) */
        (*ssf).ssf_info.sinfo_stream = (*chk).rec.data.sid;
        (*ssf).ssf_info.sinfo_ssn = (*chk).rec.data.mid as uint16_t;
        (*ssf).ssf_info.sinfo_flags = (*chk).rec.data.rcv_flags as uint16_t;
        (*ssf).ssf_info.sinfo_ppid = (*chk).rec.data.ppid;
        (*ssf).ssf_info.sinfo_context = (*chk).rec.data.context;
        (*ssf).ssf_info.sinfo_assoc_id = (*stcb).asoc.assoc_id;
        (*ssf).ssf_assoc_id = (*stcb).asoc.assoc_id
    }
    if !(*chk).data.is_null() {
        /* Trim off the sctp chunk header (it should be there) */
        if (*chk).send_size as libc::c_int == chkhdr_len + payload_len + padding_len {
            let mut _m = 0 as *mut mbuf;
            m_adj((*chk).data, chkhdr_len);
            m_adj((*chk).data, -padding_len);

            _m = (*chk).data;
            while !_m.is_null() && (*_m).m_hdr.mh_len == 0i32 {
                (*chk).data = (*_m).m_hdr.mh_next;
                (*_m).m_hdr.mh_next = 0 as *mut mbuf;
                m_free(_m);
                _m = (*chk).data
            }
            (*chk).send_size =
                ((*chk).send_size as libc::c_int - (chkhdr_len + padding_len)) as uint16_t
        }
    }
    (*m_notify).m_hdr.mh_next = (*chk).data;
    /* Steal off the mbuf */
    (*chk).data = 0 as *mut mbuf;
    /*
     * For this case, we check the actual socket buffer, since the assoc
     * is going away we don't want to overfill the socket buffer for a
     * non-reader
     */
    if ((if (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
        (*(*stcb).sctp_socket).so_rcv.sb_hiwat
    } else {
        4096u32
    }) > (*(*stcb).sctp_socket).so_rcv.sb_cc
    {
        (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
            (*(*stcb).sctp_socket).so_rcv.sb_hiwat
        } else {
            4096u32
        })
        .wrapping_sub((*(*stcb).sctp_socket).so_rcv.sb_cc)
    } else {
        0u32
    }) as libc::c_long)
        < (*m_notify).m_hdr.mh_len as libc::c_long
    {
        m_freem(m_notify);
        return;
    }
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
unsafe extern "C" fn sctp_notify_send_failed2(
    mut stcb: *mut sctp_tcb,
    mut error: uint32_t,
    mut sp: *mut sctp_stream_queue_pending,
    mut so_locked: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut notifhdr_len = 0;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x4000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x4000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
            && (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x80000000u64 == 0u64
                || stcb.is_null()
                    && !(*stcb).sctp_ep.is_null()
                    && (*(*stcb).sctp_ep).sctp_features & 0x80000000u64 == 0u64
                || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x80000000u64 == 0x80000000u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x80000000u64 == 0x80000000u64
    {
        notifhdr_len = ::std::mem::size_of::<sctp_send_failed_event>() as libc::c_int
    } else {
        notifhdr_len = ::std::mem::size_of::<sctp_send_failed>() as libc::c_int
    }
    m_notify = sctp_get_mbuf_for_msg(notifhdr_len as libc::c_uint, 0i32, 0x1i32, 1i32, 1i32);
    if m_notify.is_null() {
        /* no space left */
        return;
    }
    (*m_notify).m_hdr.mh_len = notifhdr_len;
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x80000000u64 == 0x80000000u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x80000000u64 == 0x80000000u64
    {
        let mut ssfe = 0 as *mut sctp_send_failed_event;
        ssfe = (*m_notify).m_hdr.mh_data as *mut sctp_send_failed_event;
        memset(
            ssfe as *mut libc::c_void,
            0i32,
            notifhdr_len as libc::c_ulong,
        );
        (*ssfe).ssfe_type = 0xeu16;
        (*ssfe).ssfe_flags = 0x1u16;
        (*ssfe).ssfe_length = (notifhdr_len as libc::c_uint).wrapping_add((*sp).length);
        (*ssfe).ssfe_error = error;
        /* not exactly what the user sent in, but should be close :) */
        (*ssfe).ssfe_info.snd_sid = (*sp).sid;
        if (*sp).some_taken != 0 {
            (*ssfe).ssfe_info.snd_flags = 0x1u16
        } else {
            (*ssfe).ssfe_info.snd_flags = 0x3u16
        }
        (*ssfe).ssfe_info.snd_ppid = (*sp).ppid;
        (*ssfe).ssfe_info.snd_context = (*sp).context;
        (*ssfe).ssfe_info.snd_assoc_id = (*stcb).asoc.assoc_id;
        (*ssfe).ssfe_assoc_id = (*stcb).asoc.assoc_id
    } else {
        let mut ssf = 0 as *mut sctp_send_failed;
        ssf = (*m_notify).m_hdr.mh_data as *mut sctp_send_failed;
        memset(
            ssf as *mut libc::c_void,
            0i32,
            notifhdr_len as libc::c_ulong,
        );
        (*ssf).ssf_type = 0x4u16;
        (*ssf).ssf_flags = 0x1u16;
        (*ssf).ssf_length = (notifhdr_len as libc::c_uint).wrapping_add((*sp).length);
        (*ssf).ssf_error = error;
        /* not exactly what the user sent in, but should be close :) */
        (*ssf).ssf_info.sinfo_stream = (*sp).sid;
        (*ssf).ssf_info.sinfo_ssn = 0u16;
        if (*sp).some_taken != 0 {
            (*ssf).ssf_info.sinfo_flags = 0x1u16
        } else {
            (*ssf).ssf_info.sinfo_flags = 0x3u16
        }
        (*ssf).ssf_info.sinfo_ppid = (*sp).ppid;
        (*ssf).ssf_info.sinfo_context = (*sp).context;
        (*ssf).ssf_info.sinfo_assoc_id = (*stcb).asoc.assoc_id;
        (*ssf).ssf_assoc_id = (*stcb).asoc.assoc_id
    }
    (*m_notify).m_hdr.mh_next = (*sp).data;
    /* Steal off the mbuf */
    (*sp).data = 0 as *mut mbuf;
    /*
     * For this case, we check the actual socket buffer, since the assoc
     * is going away we don't want to overfill the socket buffer for a
     * non-reader
     */
    if ((if (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
        (*(*stcb).sctp_socket).so_rcv.sb_hiwat
    } else {
        4096u32
    }) > (*(*stcb).sctp_socket).so_rcv.sb_cc
    {
        (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
            (*(*stcb).sctp_socket).so_rcv.sb_hiwat
        } else {
            4096u32
        })
        .wrapping_sub((*(*stcb).sctp_socket).so_rcv.sb_cc)
    } else {
        0u32
    }) as libc::c_long)
        < (*m_notify).m_hdr.mh_len as libc::c_long
    {
        m_freem(m_notify);
        return;
    }
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
unsafe extern "C" fn sctp_notify_adaptation_layer(mut stcb: *mut sctp_tcb) {
    let mut m_notify = 0 as *mut mbuf;
    let mut sai = 0 as *mut sctp_adaptation_event;
    let mut control = 0 as *mut sctp_queued_to_read;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x10000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x10000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_adaption_event>() as libc::c_uint,
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
    sai = (*m_notify).m_hdr.mh_data as *mut sctp_adaptation_event;
    memset(
        sai as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_adaptation_event>() as libc::c_ulong,
    );
    (*sai).sai_type = 0x6u16;
    (*sai).sai_flags = 0u16;
    (*sai).sai_length = ::std::mem::size_of::<sctp_adaptation_event>() as uint32_t;
    (*sai).sai_adaptation_ind = (*stcb).asoc.peers_adaptation;
    (*sai).sai_assoc_id = (*stcb).asoc.assoc_id;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_adaptation_event>() as libc::c_int;
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
        0i32,
    );
}
/* This always must be called with the read-queue LOCKED in the INP */
unsafe extern "C" fn sctp_notify_partial_delivery_indication(
    mut stcb: *mut sctp_tcb,
    mut error: uint32_t,
    mut val: uint32_t,
    mut so_locked: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut pdapi = 0 as *mut sctp_pdapi_event;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut sb = 0 as *mut sockbuf;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x20000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x20000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    if (*(*stcb).sctp_ep).sctp_flags & 0x40000000u32 != 0 {
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_pdapi_event>() as libc::c_uint,
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
    pdapi = (*m_notify).m_hdr.mh_data as *mut sctp_pdapi_event;
    memset(
        pdapi as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_pdapi_event>() as libc::c_ulong,
    );
    (*pdapi).pdapi_type = 0x7u16;
    (*pdapi).pdapi_flags = 0u16;
    (*pdapi).pdapi_length = ::std::mem::size_of::<sctp_pdapi_event>() as uint32_t;
    (*pdapi).pdapi_indication = error;
    (*pdapi).pdapi_stream = (val >> 16i32) as uint16_t;
    (*pdapi).pdapi_seq = (val & 0xffffu32) as uint16_t;
    (*pdapi).pdapi_assoc_id = (*stcb).asoc.assoc_id;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_pdapi_event>() as libc::c_int;
    (*m_notify).m_hdr.mh_next = 0 as *mut mbuf;
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
    sb = &mut (*(*stcb).sctp_socket).so_rcv;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
        sctp_sblog(
            sb,
            if (*control).do_not_ref_stcb as libc::c_int != 0 {
                0 as *mut sctp_tcb
            } else {
                stcb
            },
            53i32,
            (*m_notify).m_hdr.mh_len,
        );
    }
    ::std::intrinsics::atomic_xadd(&mut (*sb).sb_cc, (*m_notify).m_hdr.mh_len as u_int);
    ::std::intrinsics::atomic_xadd(&mut (*sb).sb_mbcnt, 256u32);
    if !stcb.is_null() {
        ::std::intrinsics::atomic_xadd(
            &mut (*stcb).asoc.sb_cc,
            (*m_notify).m_hdr.mh_len as uint32_t,
        );
        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.my_rwnd_control_len, 256u32);
    }
    if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
        sctp_sblog(
            sb,
            if (*control).do_not_ref_stcb as libc::c_int != 0 {
                0 as *mut sctp_tcb
            } else {
                stcb
            },
            55i32,
            0i32,
        );
    }
    (*control).end_added = 1u8;
    if !(*stcb).asoc.control_pdapi.is_null() {
        (*control).next.tqe_next = (*(*stcb).asoc.control_pdapi).next.tqe_next;
        if !(*control).next.tqe_next.is_null() {
            (*(*control).next.tqe_next).next.tqe_prev = &mut (*control).next.tqe_next
        } else {
            (*(*stcb).sctp_ep).read_queue.tqh_last = &mut (*control).next.tqe_next
        }
        (*(*stcb).asoc.control_pdapi).next.tqe_next = control;
        (*control).next.tqe_prev = &mut (*(*stcb).asoc.control_pdapi).next.tqe_next
    } else {
        /* we really should not see this case */
        (*control).next.tqe_next = 0 as *mut sctp_queued_to_read;
        (*control).next.tqe_prev = (*(*stcb).sctp_ep).read_queue.tqh_last;
        *(*(*stcb).sctp_ep).read_queue.tqh_last = control;
        (*(*stcb).sctp_ep).read_queue.tqh_last = &mut (*control).next.tqe_next
    }
    if !(*stcb).sctp_ep.is_null() && !(*stcb).sctp_socket.is_null() {
        /* This should always be the case */
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
    };
}
unsafe extern "C" fn sctp_notify_shutdown_event(mut stcb: *mut sctp_tcb) {
    let mut m_notify = 0 as *mut mbuf;
    let mut sse = 0 as *mut sctp_shutdown_event;
    let mut control = 0 as *mut sctp_queued_to_read;
    /*
     * For TCP model AND UDP connected sockets we will send an error up
     * when an SHUTDOWN completes
     */
    if (*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0
    {
        /* mark socket closed for read/write and wakeup! */
        socantsendmore((*stcb).sctp_socket);
    }
    if !stcb.is_null() && (*stcb).asoc.sctp_features & 0x8000u64 == 0u64
        || stcb.is_null()
            && !(*stcb).sctp_ep.is_null()
            && (*(*stcb).sctp_ep).sctp_features & 0x8000u64 == 0u64
        || stcb.is_null() && (*stcb).sctp_ep.is_null()
    {
        /* event not enabled */
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_shutdown_event>() as libc::c_uint,
        0i32,
        0x1i32,
        1i32,
        1i32,
    );
    if m_notify.is_null() {
        /* no space left */
        return;
    }
    sse = (*m_notify).m_hdr.mh_data as *mut sctp_shutdown_event;
    memset(
        sse as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_shutdown_event>() as libc::c_ulong,
    );
    (*sse).sse_type = 0x5u16;
    (*sse).sse_flags = 0u16;
    (*sse).sse_length = ::std::mem::size_of::<sctp_shutdown_event>() as uint32_t;
    (*sse).sse_assoc_id = (*stcb).asoc.assoc_id;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_shutdown_event>() as libc::c_int;
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
        0i32,
    );
}
unsafe extern "C" fn sctp_notify_sender_dry_event(
    mut stcb: *mut sctp_tcb,
    mut so_locked: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut event = 0 as *mut sctp_sender_dry_event;
    let mut control = 0 as *mut sctp_queued_to_read;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x4000000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x4000000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_sender_dry_event>() as libc::c_uint,
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
    event = (*m_notify).m_hdr.mh_data as *mut sctp_sender_dry_event;
    memset(
        event as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_sender_dry_event>() as libc::c_ulong,
    );
    (*event).sender_dry_type = 0xau16;
    (*event).sender_dry_flags = 0u16;
    (*event).sender_dry_length = ::std::mem::size_of::<sctp_sender_dry_event>() as uint32_t;
    (*event).sender_dry_assoc_id = (*stcb).asoc.assoc_id;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_sender_dry_event>() as libc::c_int;
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
#[no_mangle]
pub unsafe extern "C" fn sctp_notify_stream_reset_add(
    mut stcb: *mut sctp_tcb,
    mut numberin: uint16_t,
    mut numberout: uint16_t,
    mut flag: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut stradd = 0 as *mut sctp_stream_change_event;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x40000000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x40000000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    if (*stcb).asoc.peer_req_out as libc::c_int != 0 && flag != 0 {
        /* Peer made the request, don't tell the local user */
        (*stcb).asoc.peer_req_out = 0u8;
        return;
    }
    (*stcb).asoc.peer_req_out = 0u8;
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_stream_change_event>() as libc::c_uint,
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
    stradd = (*m_notify).m_hdr.mh_data as *mut sctp_stream_change_event;
    memset(
        stradd as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_stream_change_event>() as libc::c_ulong,
    );
    (*stradd).strchange_type = 0xdu16;
    (*stradd).strchange_flags = flag as uint16_t;
    (*stradd).strchange_length = ::std::mem::size_of::<sctp_stream_change_event>() as uint32_t;
    (*stradd).strchange_assoc_id = (*stcb).asoc.assoc_id;
    (*stradd).strchange_instrms = numberin;
    (*stradd).strchange_outstrms = numberout;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_stream_change_event>() as libc::c_int;
    (*m_notify).m_hdr.mh_next = 0 as *mut mbuf;
    if ((if (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
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
    }) as libc::c_long)
        < (*m_notify).m_hdr.mh_len as libc::c_long
    {
        /* no space */
        m_freem(m_notify);
        return;
    }
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
        0i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn sctp_notify_stream_reset_tsn(
    mut stcb: *mut sctp_tcb,
    mut sending_tsn: uint32_t,
    mut recv_tsn: uint32_t,
    mut flag: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut strasoc = 0 as *mut sctp_assoc_reset_event;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x20000000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x20000000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_assoc_reset_event>() as libc::c_uint,
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
    strasoc = (*m_notify).m_hdr.mh_data as *mut sctp_assoc_reset_event;
    memset(
        strasoc as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_assoc_reset_event>() as libc::c_ulong,
    );
    (*strasoc).assocreset_type = 0xcu16;
    (*strasoc).assocreset_flags = flag as uint16_t;
    (*strasoc).assocreset_length = ::std::mem::size_of::<sctp_assoc_reset_event>() as uint32_t;
    (*strasoc).assocreset_assoc_id = (*stcb).asoc.assoc_id;
    (*strasoc).assocreset_local_tsn = sending_tsn;
    (*strasoc).assocreset_remote_tsn = recv_tsn;
    (*m_notify).m_hdr.mh_len = ::std::mem::size_of::<sctp_assoc_reset_event>() as libc::c_int;
    (*m_notify).m_hdr.mh_next = 0 as *mut mbuf;
    if ((if (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
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
    }) as libc::c_long)
        < (*m_notify).m_hdr.mh_len as libc::c_long
    {
        /* no space */
        m_freem(m_notify);
        return;
    }
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
        0i32,
    );
}
unsafe extern "C" fn sctp_notify_stream_reset(
    mut stcb: *mut sctp_tcb,
    mut number_entries: libc::c_int,
    mut list: *mut uint16_t,
    mut flag: libc::c_int,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut strreset = 0 as *mut sctp_stream_reset_event;
    let mut len = 0;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x80000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x80000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        /* event not enabled */
        return;
    }
    m_notify = sctp_get_mbuf_for_msg(2048u32, 0i32, 0x1i32, 1i32, 1i32);
    if m_notify.is_null() {
        /* no space left */
        return;
    }
    (*m_notify).m_hdr.mh_len = 0i32;
    len = (::std::mem::size_of::<sctp_stream_reset_event>() as libc::c_ulong).wrapping_add(
        (number_entries as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong),
    ) as libc::c_int;
    if len as libc::c_long
        > (if (*m_notify).m_hdr.mh_flags & 0x1i32 != 0 {
            (if (*m_notify).m_hdr.mh_flags & 0x8i32 == 0
                && ((*m_notify).m_hdr.mh_flags & 0x1i32 == 0
                    || *(*m_notify).M_dat.MH.MH_dat.MH_ext.ref_cnt == 1u32)
            {
                (*m_notify)
                    .M_dat
                    .MH
                    .MH_dat
                    .MH_ext
                    .ext_buf
                    .offset((*m_notify).M_dat.MH.MH_dat.MH_ext.ext_size as isize)
                    .wrapping_offset_from(
                        (*m_notify)
                            .m_hdr
                            .mh_data
                            .offset((*m_notify).m_hdr.mh_len as isize),
                    ) as libc::c_long
            } else {
                0i64
            })
        } else {
            (&mut *(*m_notify).M_dat.M_databuf.as_mut_ptr().offset(
                (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong)
                    as libc::c_int as isize,
            ) as *mut libc::c_char)
                .wrapping_offset_from(
                    (*m_notify)
                        .m_hdr
                        .mh_data
                        .offset((*m_notify).m_hdr.mh_len as isize),
                ) as libc::c_long
        })
    {
        /* never enough room */
        m_freem(m_notify);
        return;
    }
    strreset = (*m_notify).m_hdr.mh_data as *mut sctp_stream_reset_event;
    memset(strreset as *mut libc::c_void, 0i32, len as libc::c_ulong);
    (*strreset).strreset_type = 0x9u16;
    (*strreset).strreset_flags = flag as uint16_t;
    (*strreset).strreset_length = len as uint32_t;
    (*strreset).strreset_assoc_id = (*stcb).asoc.assoc_id;
    if number_entries != 0 {
        for i in 0i32..number_entries {
            *(*strreset)
                .strreset_stream_list
                .as_mut_ptr()
                .offset(i as isize) = ntohs(*list.offset(i as isize));
        }
    }
    (*m_notify).m_hdr.mh_len = len;
    (*m_notify).m_hdr.mh_next = 0 as *mut mbuf;
    if ((if (if (*(*stcb).sctp_socket).so_rcv.sb_hiwat > 4096u32 {
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
    }) as libc::c_long)
        < (*m_notify).m_hdr.mh_len as libc::c_long
    {
        /* no space */
        m_freem(m_notify);
        return;
    }
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
        0i32,
    );
}
unsafe extern "C" fn sctp_notify_remote_error(
    mut stcb: *mut sctp_tcb,
    mut error: uint16_t,
    mut chunk: *mut sctp_error_chunk,
) {
    let mut m_notify = 0 as *mut mbuf;
    let mut sre = 0 as *mut sctp_remote_error;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut notif_len = 0;
    let mut chunk_len = 0;
    if stcb.is_null()
        || (!stcb.is_null() && (*stcb).asoc.sctp_features & 0x2000u64 == 0u64
            || stcb.is_null()
                && !(*stcb).sctp_ep.is_null()
                && (*(*stcb).sctp_ep).sctp_features & 0x2000u64 == 0u64
            || stcb.is_null() && (*stcb).sctp_ep.is_null())
    {
        return;
    }
    if !chunk.is_null() {
        chunk_len = ntohs((*chunk).ch.chunk_length);
        /*
         * Only SCTP_CHUNK_BUFFER_SIZE are guaranteed to be
         * contiguous.
         */
        if chunk_len as libc::c_int > 512i32 {
            chunk_len = 512u16
        }
    } else {
        chunk_len = 0u16
    }
    notif_len = (::std::mem::size_of::<sctp_remote_error>() as libc::c_ulong)
        .wrapping_add(chunk_len as libc::c_ulong) as libc::c_uint;
    m_notify = sctp_get_mbuf_for_msg(notif_len, 0i32, 0x1i32, 1i32, 1i32);
    if m_notify.is_null() {
        /* Retry with smaller value. */
        notif_len = ::std::mem::size_of::<sctp_remote_error>() as libc::c_uint;
        m_notify = sctp_get_mbuf_for_msg(notif_len, 0i32, 0x1i32, 1i32, 1i32);
        if m_notify.is_null() {
            return;
        }
    }
    (*m_notify).m_hdr.mh_next = 0 as *mut mbuf;
    sre = (*m_notify).m_hdr.mh_data as *mut sctp_remote_error;
    memset(sre as *mut libc::c_void, 0i32, notif_len as libc::c_ulong);
    (*sre).sre_type = 0x3u16;
    (*sre).sre_flags = 0u16;
    (*sre).sre_length = ::std::mem::size_of::<sctp_remote_error>() as uint32_t;
    (*sre).sre_error = error;
    (*sre).sre_assoc_id = (*stcb).asoc.assoc_id;
    if notif_len as libc::c_ulong > ::std::mem::size_of::<sctp_remote_error>() as libc::c_ulong {
        memcpy(
            (*sre).sre_data.as_mut_ptr() as *mut libc::c_void,
            chunk as *const libc::c_void,
            chunk_len as libc::c_ulong,
        );
        (*sre).sre_length = ((*sre).sre_length).wrapping_add(chunk_len as libc::c_uint)
    }
    (*m_notify).m_hdr.mh_len = (*sre).sre_length as libc::c_int;
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
    if !control.is_null() {
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
            0i32,
        );
    } else {
        m_freem(m_notify);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_ulp_notify(
    mut notification: uint32_t,
    mut stcb: *mut sctp_tcb,
    mut error: uint32_t,
    mut data: *mut libc::c_void,
    mut so_locked: libc::c_int,
) {
    if stcb.is_null()
        || (*(*stcb).sctp_ep).sctp_flags & 0x10000000u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0
        || (*stcb).asoc.state & 0x100i32 != 0
    {
        /* If the socket is gone we are out of here */
        return;
    }
    if (*(*stcb).sctp_socket).so_state as libc::c_int & 0x20i32 != 0 {
        return;
    }
    if (*stcb).asoc.state & 0x7fi32 == 0x2i32 || (*stcb).asoc.state & 0x7fi32 == 0x4i32 {
        if notification == 3u32 || notification == 4u32 || notification == 16u32 {
            /* Don't report these in front states */
            return;
        }
    }
    match notification {
        1 => {
            if (*stcb).asoc.assoc_up_sent as libc::c_int == 0i32 {
                sctp_notify_assoc_change(
                    0x1u16,
                    stcb,
                    error as uint16_t,
                    0 as *mut sctp_abort_chunk,
                    0u8,
                    so_locked,
                );
                (*stcb).asoc.assoc_up_sent = 1u8
            }
            if (*stcb).asoc.adaptation_needed as libc::c_int != 0
                && (*stcb).asoc.adaptation_sent as libc::c_int == 0i32
            {
                sctp_notify_adaptation_layer(stcb);
            }
            if (*stcb).asoc.auth_supported as libc::c_int == 0i32 {
                sctp_ulp_notify(25u32, stcb, 0u32, 0 as *mut libc::c_void, so_locked);
            }
        }
        2 => {
            sctp_notify_assoc_change(
                0x4u16,
                stcb,
                error as uint16_t,
                0 as *mut sctp_abort_chunk,
                0u8,
                so_locked,
            );
            if (*(*stcb).sctp_ep).recv_callback.is_some() {
                if !(*stcb).sctp_socket.is_null() {
                    let mut addr = sctp_sockstore {
                        sin: sockaddr_in {
                            sin_family: 0,
                            sin_port: 0,
                            sin_addr: in_addr { s_addr: 0 },
                            sin_zero: [0; 8],
                        },
                    };
                    let mut rcv = sctp_rcvinfo {
                        rcv_sid: 0,
                        rcv_ssn: 0,
                        rcv_flags: 0,
                        rcv_ppid: 0,
                        rcv_tsn: 0,
                        rcv_cumtsn: 0,
                        rcv_context: 0,
                        rcv_assoc_id: 0,
                    };
                    memset(
                        &mut addr as *mut sctp_sockstore as *mut libc::c_void,
                        0i32,
                        ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
                    );
                    memset(
                        &mut rcv as *mut sctp_rcvinfo as *mut libc::c_void,
                        0i32,
                        ::std::mem::size_of::<sctp_rcvinfo>() as libc::c_ulong,
                    );
                    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    (*(*stcb).sctp_ep)
                        .recv_callback
                        .expect("non-null function pointer")(
                        (*stcb).sctp_socket,
                        addr,
                        0 as *mut libc::c_void,
                        0u64,
                        rcv,
                        0i32,
                        (*(*stcb).sctp_ep).ulp_info,
                    );
                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.refcnt, 1u32);
                }
            }
        }
        3 => {
            let mut net = 0 as *mut sctp_nets;
            net = data as *mut sctp_nets;
            sctp_notify_peer_addr_change(
                stcb,
                0x2u32,
                &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr,
                error,
                so_locked,
            );
        }
        4 => {
            let mut net_0 = 0 as *mut sctp_nets;
            net_0 = data as *mut sctp_nets;
            sctp_notify_peer_addr_change(
                stcb,
                0x1u32,
                &mut (*net_0).ro._l_addr as *mut sctp_sockstore as *mut sockaddr,
                error,
                so_locked,
            );
        }
        16 => {
            let mut net_1 = 0 as *mut sctp_nets;
            net_1 = data as *mut sctp_nets;
            sctp_notify_peer_addr_change(
                stcb,
                0x6u32,
                &mut (*net_1).ro._l_addr as *mut sctp_sockstore as *mut sockaddr,
                error,
                so_locked,
            );
        }
        7 => {
            sctp_notify_send_failed2(
                stcb,
                error,
                data as *mut sctp_stream_queue_pending,
                so_locked,
            );
        }
        5 => {
            sctp_notify_send_failed(stcb, 1u8, error, data as *mut sctp_tmit_chunk, so_locked);
        }
        6 => {
            sctp_notify_send_failed(stcb, 0u8, error, data as *mut sctp_tmit_chunk, so_locked);
        }
        15 => {
            let mut val = 0;
            val = *(data as *mut uint32_t);
            sctp_notify_partial_delivery_indication(stcb, error, val, so_locked);
        }
        8 => {
            if (*stcb).asoc.state & 0x7fi32 == 0x2i32 || (*stcb).asoc.state & 0x7fi32 == 0x4i32 {
                sctp_notify_assoc_change(
                    0x5u16,
                    stcb,
                    error as uint16_t,
                    data as *mut sctp_abort_chunk,
                    0u8,
                    so_locked,
                );
            } else {
                sctp_notify_assoc_change(
                    0x2u16,
                    stcb,
                    error as uint16_t,
                    data as *mut sctp_abort_chunk,
                    0u8,
                    so_locked,
                );
            }
        }
        9 => {
            if (*stcb).asoc.state & 0x7fi32 == 0x2i32 || (*stcb).asoc.state & 0x7fi32 == 0x4i32 {
                sctp_notify_assoc_change(
                    0x5u16,
                    stcb,
                    error as uint16_t,
                    data as *mut sctp_abort_chunk,
                    1u8,
                    so_locked,
                );
            } else {
                sctp_notify_assoc_change(
                    0x2u16,
                    stcb,
                    error as uint16_t,
                    data as *mut sctp_abort_chunk,
                    1u8,
                    so_locked,
                );
            }
        }
        10 => {
            sctp_notify_assoc_change(
                0x3u16,
                stcb,
                error as uint16_t,
                0 as *mut sctp_abort_chunk,
                0u8,
                so_locked,
            );
            if (*stcb).asoc.auth_supported as libc::c_int == 0i32 {
                sctp_ulp_notify(25u32, stcb, 0u32, 0 as *mut libc::c_void, so_locked);
            }
        }
        18 => {
            sctp_notify_stream_reset(stcb, error as libc::c_int, data as *mut uint16_t, 0x2i32);
        }
        17 => {
            sctp_notify_stream_reset(stcb, error as libc::c_int, data as *mut uint16_t, 0x1i32);
        }
        19 => {
            sctp_notify_stream_reset(
                stcb,
                error as libc::c_int,
                data as *mut uint16_t,
                0x2i32 | 0x8i32,
            );
        }
        21 => {
            sctp_notify_stream_reset(
                stcb,
                error as libc::c_int,
                data as *mut uint16_t,
                0x2i32 | 0x4i32,
            );
        }
        20 => {
            sctp_notify_stream_reset(
                stcb,
                error as libc::c_int,
                data as *mut uint16_t,
                0x1i32 | 0x8i32,
            );
        }
        22 => {
            sctp_notify_stream_reset(
                stcb,
                error as libc::c_int,
                data as *mut uint16_t,
                0x1i32 | 0x4i32,
            );
        }
        12 => {
            sctp_notify_peer_addr_change(stcb, 0x4u32, data as *mut sockaddr, error, so_locked);
        }
        13 => {
            sctp_notify_peer_addr_change(stcb, 0x3u32, data as *mut sockaddr, error, so_locked);
        }
        14 => {
            sctp_notify_peer_addr_change(stcb, 0x5u32, data as *mut sockaddr, error, so_locked);
        }
        11 => {
            sctp_notify_shutdown_event(stcb);
        }
        23 => {
            sctp_notify_authentication(
                stcb,
                0x1u32,
                error as uint16_t,
                data as uint16_t,
                so_locked,
            );
        }
        24 => {
            sctp_notify_authentication(
                stcb,
                0x3u32,
                error as uint16_t,
                data as uint16_t,
                so_locked,
            );
        }
        25 => {
            sctp_notify_authentication(
                stcb,
                0x2u32,
                error as uint16_t,
                data as uint16_t,
                so_locked,
            );
        }
        26 => {
            sctp_notify_sender_dry_event(stcb, so_locked);
        }
        27 => {
            sctp_notify_remote_error(stcb, error as uint16_t, data as *mut sctp_error_chunk);
        }
        _ => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x100u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"%s: unknown notification %xh (%u)\n\x00" as *const u8
                            as *const libc::c_char,
                        (*::std::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"sctp_ulp_notify\x00",
                        ))
                        .as_ptr(),
                        notification,
                        notification,
                    );
                }
            }
        }
    };
    /* end switch */
}
#[no_mangle]
pub unsafe extern "C" fn sctp_report_all_outbound(
    mut stcb: *mut sctp_tcb,
    mut error: uint16_t,
    mut holds_lock: libc::c_int,
    mut so_locked: libc::c_int,
) {
    let mut asoc = 0 as *mut sctp_association;
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut nchk = 0 as *mut sctp_tmit_chunk;
    if stcb.is_null() {
        return;
    }
    asoc = &mut (*stcb).asoc;
    if (*asoc).state & 0x200i32 != 0 {
        /* already being freed */
        return;
    }
    if (*(*stcb).sctp_ep).sctp_flags & 0x10000000u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0
        || (*asoc).state & 0x100i32 != 0
    {
        return;
    }
    /* now through all the gunk freeing chunks */
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
    }
    /* sent queue SHOULD be empty */
    chk = (*asoc).sent_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*asoc).sent_queue.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        (*asoc).sent_queue_cnt = (*asoc).sent_queue_cnt.wrapping_sub(1);
        if (*chk).sent != 40010i32 {
            if (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues > 0u32 {
                let ref mut fresh8 =
                    (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues;
                *fresh8 = (*fresh8).wrapping_sub(1)
            }
        }
        if !(*chk).data.is_null() {
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
            sctp_ulp_notify(
                5u32,
                stcb,
                error as uint32_t,
                chk as *mut libc::c_void,
                so_locked,
            );
            if !(*chk).data.is_null() {
                m_freem((*chk).data);
                (*chk).data = 0 as *mut mbuf
            }
        }
        if (*chk).holds_key_ref != 0 {
            sctp_auth_key_release(stcb, (*chk).auth_keyid, so_locked);
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
        /*sa_ignore FREED_MEMORY*/
    }
    /* pending send queue SHOULD be empty */
    chk = (*asoc).send_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if !(*chk).sctp_next.tqe_next.is_null() {
            (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
        } else {
            (*asoc).send_queue.tqh_last = (*chk).sctp_next.tqe_prev
        }
        *(*chk).sctp_next.tqe_prev = (*chk).sctp_next.tqe_next;
        (*asoc).send_queue_cnt = (*asoc).send_queue_cnt.wrapping_sub(1);
        if (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues > 0u32 {
            let ref mut fresh9 =
                (*(*asoc).strmout.offset((*chk).rec.data.sid as isize)).chunks_on_queues;
            *fresh9 = (*fresh9).wrapping_sub(1)
        }
        if !(*chk).data.is_null() {
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
            sctp_ulp_notify(
                6u32,
                stcb,
                error as uint32_t,
                chk as *mut libc::c_void,
                so_locked,
            );
            if !(*chk).data.is_null() {
                m_freem((*chk).data);
                (*chk).data = 0 as *mut mbuf
            }
        }
        if (*chk).holds_key_ref != 0 {
            sctp_auth_key_release(stcb, (*chk).auth_keyid, so_locked);
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
        /*sa_ignore FREED_MEMORY*/
    }

    for i in 0i32..(*asoc).streamoutcnt as libc::c_int {
        let mut outs = 0 as *mut sctp_stream_out;
        let mut sp = 0 as *mut sctp_stream_queue_pending;
        let mut nsp = 0 as *mut sctp_stream_queue_pending;
        outs = &mut *(*asoc).strmout.offset(i as isize) as *mut sctp_stream_out;
        /* clean up any sends there */
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
                sctp_ulp_notify(
                    7u32,
                    stcb,
                    error as uint32_t,
                    sp as *mut libc::c_void,
                    so_locked,
                );
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
            /*sa_ignore FREED_MEMORY*/
            if (*sp).holds_key_ref != 0 {
                sctp_auth_key_release(stcb, (*sp).auth_keyid, so_locked);
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
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_abort_notification(
    mut stcb: *mut sctp_tcb,
    mut from_peer: uint8_t,
    mut error: uint16_t,
    mut abort: *mut sctp_abort_chunk,
    mut so_locked: libc::c_int,
) {
    if stcb.is_null() {
        return;
    }
    if (*(*stcb).sctp_ep).sctp_flags & 0x400000u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0
            && (*(*stcb).sctp_ep).sctp_flags & 0x200000u32 != 0
    {
        (*(*stcb).sctp_ep).sctp_flags |= 0x100000u32
    }
    if (*(*stcb).sctp_ep).sctp_flags & 0x10000000u32 != 0
        || (*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0
        || (*stcb).asoc.state & 0x100i32 != 0
    {
        return;
    }
    /* Free the chunk */
    /* Tell them we lost the asoc */
    sctp_report_all_outbound(stcb, error, 0i32, so_locked);
    if from_peer != 0 {
        sctp_ulp_notify(
            9u32,
            stcb,
            error as uint32_t,
            abort as *mut libc::c_void,
            so_locked,
        );
    } else {
        sctp_ulp_notify(
            8u32,
            stcb,
            error as uint32_t,
            abort as *mut libc::c_void,
            so_locked,
        );
    };
}
/* We abort responding to an IP packet for some reason */
#[no_mangle]
pub unsafe extern "C" fn sctp_abort_association(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut m: *mut mbuf,
    mut iphlen: libc::c_int,
    mut src: *mut sockaddr,
    mut dst: *mut sockaddr,
    mut sh: *mut sctphdr,
    mut op_err: *mut mbuf,
    mut vrf_id: uint32_t,
    mut port: uint16_t,
) {
    let mut vtag = 0;
    vtag = 0u32;
    if !stcb.is_null() {
        vtag = (*stcb).asoc.peer_vtag;
        vrf_id = (*stcb).asoc.vrf_id
    }
    sctp_send_abort(m, iphlen, src, dst, sh, vtag, op_err, vrf_id, port);
    if !stcb.is_null() {
        /* We have a TCB to abort, send notification too */
        sctp_abort_notification(stcb, 0u8, 0u16, 0 as *mut sctp_abort_chunk, 0i32);
        sctp_add_substate(stcb, 0x800i32);
        /* Ok, now lets free it */
        ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_aborted, 1u32);
        if (*stcb).asoc.state & 0x7fi32 == 0x8i32 || (*stcb).asoc.state & 0x7fi32 == 0x20i32 {
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctpstat.sctps_currestab, 1u32);
        }
        sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0x4i32);
    };
}
/* We choose to abort via user input */
#[no_mangle]
pub unsafe extern "C" fn sctp_abort_an_association(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut op_err: *mut mbuf,
    mut so_locked: libc::c_int,
) {
    if stcb.is_null() {
        /* Got to have a TCB */
        if (*inp).sctp_flags & 0x10000000u32 != 0 {
            if (*inp).sctp_asoc_list.lh_first.is_null() {
                sctp_inpcb_free(inp, 1i32, 0i32);
            }
        }
        return;
    } else {
        sctp_add_substate(stcb, 0x800i32);
    }
    /* notify the peer */
    sctp_send_abort_tcb(stcb, op_err, so_locked);
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_aborted, 1u32);
    if (*stcb).asoc.state & 0x7fi32 == 0x8i32 || (*stcb).asoc.state & 0x7fi32 == 0x20i32 {
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctpstat.sctps_currestab, 1u32);
    }
    /* notify the ulp */
    if (*inp).sctp_flags & 0x10000000u32 == 0u32 {
        sctp_abort_notification(stcb, 0u8, 0u16, 0 as *mut sctp_abort_chunk, so_locked);
    }
    /* now free the asoc */
    sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0x5i32);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_handle_ootb(
    mut m: *mut mbuf,
    mut iphlen: libc::c_int,
    mut offset: libc::c_int,
    mut src: *mut sockaddr,
    mut dst: *mut sockaddr,
    mut sh: *mut sctphdr,
    mut inp: *mut sctp_inpcb,
    mut cause: *mut mbuf,
    mut vrf_id: uint32_t,
    mut port: uint16_t,
) {
    let mut ch = 0 as *mut sctp_chunkhdr;
    let mut chunk_buf = sctp_chunkhdr {
        chunk_type: 0,
        chunk_flags: 0,
        chunk_length: 0,
    };
    let mut contains_init_chunk = 0;
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_outoftheblue, 1u32);
    /* Generate a TO address for future reference */
    if !inp.is_null() && (*inp).sctp_flags & 0x10000000u32 != 0 {
        if (*inp).sctp_asoc_list.lh_first.is_null() {
            sctp_inpcb_free(inp, 1i32, 0i32);
        }
    }
    contains_init_chunk = 0i32;
    ch = sctp_m_getptr(
        m,
        offset,
        ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_int,
        &mut chunk_buf as *mut sctp_chunkhdr as *mut uint8_t,
    ) as *mut sctp_chunkhdr;
    while !ch.is_null() {
        let mut chk_length = 0;
        chk_length = ntohs((*ch).chunk_length) as libc::c_uint;
        if (chk_length as libc::c_ulong) < ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_ulong {
            break;
        }
        match (*ch).chunk_type as libc::c_int {
            1 => contains_init_chunk = 1i32,
            129 => {
                /* we don't respond to pkt-dropped */
                return;
            }
            6 => {
                /* we don't respond with an ABORT to an ABORT */
                return;
            }
            14 => {
                /*
                 * we ignore it since we are not waiting for it and
                 * peer is gone
                 */
                return;
            }
            8 => {
                sctp_send_shutdown_complete2(src, dst, sh, vrf_id, port);
                return;
            }
            _ => {}
        }
        offset = (offset as libc::c_uint)
            .wrapping_add((chk_length.wrapping_add(3u32) >> 2i32) << 2i32)
            as libc::c_int;
        ch = sctp_m_getptr(
            m,
            offset,
            ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_int,
            &mut chunk_buf as *mut sctp_chunkhdr as *mut uint8_t,
        ) as *mut sctp_chunkhdr
    }
    if system_base_info.sctpsysctl.sctp_blackhole == 0u32
        || system_base_info.sctpsysctl.sctp_blackhole == 1u32 && contains_init_chunk == 0i32
    {
        sctp_send_abort(m, iphlen, src, dst, sh, 0u32, cause, vrf_id, port);
    };
}
/*
 * check the inbound datagram to make sure there is not an abort inside it,
 * if there is return 1, else return 0.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_is_there_an_abort_here(
    mut m: *mut mbuf,
    mut iphlen: libc::c_int,
    mut vtagfill: *mut uint32_t,
) -> libc::c_int {
    let mut ch = 0 as *mut sctp_chunkhdr;
    let mut chunk_buf = sctp_init_chunk {
        ch: sctp_chunkhdr {
            chunk_type: 0,
            chunk_flags: 0,
            chunk_length: 0,
        },
        init: sctp_init {
            initiate_tag: 0,
            a_rwnd: 0,
            num_outbound_streams: 0,
            num_inbound_streams: 0,
            initial_tsn: 0,
        },
    };
    let mut offset = 0;
    offset = (iphlen as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
        as libc::c_int;
    ch = sctp_m_getptr(
        m,
        offset,
        ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_int,
        &mut chunk_buf as *mut sctp_init_chunk as *mut uint8_t,
    ) as *mut sctp_chunkhdr;
    while !ch.is_null() {
        let mut chk_length = 0;
        chk_length = ntohs((*ch).chunk_length) as libc::c_uint;
        if (chk_length as libc::c_ulong) < ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_ulong {
            break;
        }
        /* we seem to be ok, is it an abort? */
        if (*ch).chunk_type as libc::c_int == 0x6i32 {
            /* yep, tell them */
            return 1i32;
        }
        if (*ch).chunk_type as libc::c_int == 0x1i32 {
            let mut init_chk = 0 as *mut sctp_init_chunk;
            init_chk = sctp_m_getptr(
                m,
                offset,
                ::std::mem::size_of::<sctp_init_chunk>() as libc::c_int,
                &mut chunk_buf as *mut sctp_init_chunk as *mut uint8_t,
            ) as *mut sctp_init_chunk;
            if !init_chk.is_null() {
                *vtagfill = ntohl((*init_chk).init.initiate_tag)
            }
        }
        /* Nope, move to the next chunk */
        offset = (offset as libc::c_uint)
            .wrapping_add((chk_length.wrapping_add(3u32) >> 2i32) << 2i32)
            as libc::c_int;
        ch = sctp_m_getptr(
            m,
            offset,
            ::std::mem::size_of::<sctp_chunkhdr>() as libc::c_int,
            &mut chunk_buf as *mut sctp_init_chunk as *mut uint8_t,
        ) as *mut sctp_chunkhdr
    }
    return 0i32;
}
/*
 * currently (2/02), ifa_addr embeds scope_id's and don't have sin6_scope_id
 * set (i.e. it's 0) so, create this function to compare link local scopes
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_is_same_scope(
    mut addr1: *mut sockaddr_in6,
    mut addr2: *mut sockaddr_in6,
) -> uint32_t {
    /*__Userspace__ Returning 1 here always */
    if (*addr1).sin6_scope_id != (*addr2).sin6_scope_id {
        return 0u32;
    }
    /* SCTP_EMBEDDED_V6_SCOPE */
    return 1u32;
}
/* SCTP_EMBEDDED_V6_SCOPE */
/*
 * are the two addresses the same?  currently a "scopeless" check returns: 1
 * if same, 0 if not
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_cmpaddr(
    mut sa1: *mut sockaddr,
    mut sa2: *mut sockaddr,
) -> libc::c_int {
    /* must be valid */
    if sa1.is_null() || sa2.is_null() {
        return 0i32;
    }
    /* must be the same family */
    if (*sa1).sa_family as libc::c_int != (*sa2).sa_family as libc::c_int {
        return 0i32;
    }
    match (*sa1).sa_family as libc::c_int {
        10 => {
            let mut sin6_1 = 0 as *mut sockaddr_in6;
            let mut sin6_2 = 0 as *mut sockaddr_in6;
            sin6_1 = sa1 as *mut sockaddr_in6;
            sin6_2 = sa2 as *mut sockaddr_in6;
            return SCTP6_ARE_ADDR_EQUAL(sin6_1, sin6_2);
        }
        2 => {
            let mut sin_1 = 0 as *mut sockaddr_in;
            let mut sin_2 = 0 as *mut sockaddr_in;
            sin_1 = sa1 as *mut sockaddr_in;
            sin_2 = sa2 as *mut sockaddr_in;
            return ((*sin_1).sin_addr.s_addr == (*sin_2).sin_addr.s_addr) as libc::c_int;
        }
        123 => {
            let mut sconn_1 = 0 as *mut sockaddr_conn;
            let mut sconn_2 = 0 as *mut sockaddr_conn;
            sconn_1 = sa1 as *mut sockaddr_conn;
            sconn_2 = sa2 as *mut sockaddr_conn;
            return ((*sconn_1).sconn_addr == (*sconn_2).sconn_addr) as libc::c_int;
        }
        _ => {
            /* we don't do these... */
            return 0i32;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_print_address(mut sa: *mut sockaddr) {
    match (*sa).sa_family as libc::c_int {
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 = sa as *mut sockaddr_in6;
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"IPv6 address: %x:%x:%x:%x:%x:%x:%x:%x:port:%d scope:%u\n\x00" as *const u8
                        as *const libc::c_char,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[0usize]) as libc::c_int,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[1usize]) as libc::c_int,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[2usize]) as libc::c_int,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[3usize]) as libc::c_int,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[4usize]) as libc::c_int,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[5usize]) as libc::c_int,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[6usize]) as libc::c_int,
                    ntohs((*sin6).sin6_addr.__in6_u.__u6_addr16[7usize]) as libc::c_int,
                    ntohs((*sin6).sin6_port) as libc::c_int,
                    (*sin6).sin6_scope_id,
                );
            }
        }
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            let mut p = 0 as *mut libc::c_uchar;
            sin = sa as *mut sockaddr_in;
            p = &mut (*sin).sin_addr as *mut in_addr as *mut libc::c_uchar;
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"IPv4 address: %u.%u.%u.%u:%d\n\x00" as *const u8 as *const libc::c_char,
                    *p.offset(0isize) as libc::c_int,
                    *p.offset(1isize) as libc::c_int,
                    *p.offset(2isize) as libc::c_int,
                    *p.offset(3isize) as libc::c_int,
                    ntohs((*sin).sin_port) as libc::c_int,
                );
            }
        }
        123 => {
            let mut sconn = 0 as *mut sockaddr_conn;
            sconn = sa as *mut sockaddr_conn;
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"AF_CONN address: %p\n\x00" as *const u8 as *const libc::c_char,
                    (*sconn).sconn_addr,
                );
            }
        }
        _ => {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"?\n\x00" as *const u8 as *const libc::c_char,
                );
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_pull_off_control_to_new_inp(
    mut old_inp: *mut sctp_inpcb,
    mut new_inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut waitflags: libc::c_int,
) {
    let mut old_so = 0 as *mut socket;
    let mut new_so = 0 as *mut socket;
    let mut control = 0 as *mut sctp_queued_to_read;
    let mut nctl = 0 as *mut sctp_queued_to_read;
    let mut tmp_queue = sctp_readhead {
        tqh_first: 0 as *mut sctp_queued_to_read,
        tqh_last: 0 as *mut *mut sctp_queued_to_read,
    };
    let mut m = 0 as *mut mbuf;
    old_so = (*old_inp).sctp_socket;
    new_so = (*new_inp).sctp_socket;
    tmp_queue.tqh_first = 0 as *mut sctp_queued_to_read;
    tmp_queue.tqh_last = &mut tmp_queue.tqh_first;
    /* lock the socket buffers */
    pthread_mutex_lock(&mut (*old_inp).inp_rdata_mtx);
    control = (*old_inp).read_queue.tqh_first;
    while !control.is_null() && {
        nctl = (*control).next.tqe_next;
        (1i32) != 0
    } {
        /* Pull off all for out target stcb */
        if (*control).stcb == stcb {
            /* remove it we want it */
            if !(*control).next.tqe_next.is_null() {
                (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
            } else {
                (*old_inp).read_queue.tqh_last = (*control).next.tqe_prev
            }
            *(*control).next.tqe_prev = (*control).next.tqe_next;
            (*control).next.tqe_next = 0 as *mut sctp_queued_to_read;
            (*control).next.tqe_prev = tmp_queue.tqh_last;
            *tmp_queue.tqh_last = control;
            tmp_queue.tqh_last = &mut (*control).next.tqe_next;
            m = (*control).data;
            while !m.is_null() {
                let mut oldval = 0;
                let mut oldval_0 = 0;
                if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
                    sctp_sblog(
                        &mut (*old_so).so_rcv,
                        if (*control).do_not_ref_stcb as libc::c_int != 0 {
                            0 as *mut sctp_tcb
                        } else {
                            stcb
                        },
                        54i32,
                        (*m).m_hdr.mh_len,
                    );
                }

                oldval = ::std::intrinsics::atomic_xadd(
                    &mut (*old_so).so_rcv.sb_cc,
                    -(*m).m_hdr.mh_len as u_int,
                ) as int32_t;
                if oldval < (*m).m_hdr.mh_len {
                    (*old_so).so_rcv.sb_cc = 0u32
                }

                oldval_0 = ::std::intrinsics::atomic_xadd(
                    &mut (*old_so).so_rcv.sb_mbcnt,
                    -(256i32) as u_int,
                ) as int32_t;
                if oldval_0 < 256i32 {
                    (*old_so).so_rcv.sb_mbcnt = 0u32
                }
                if (*control).do_not_ref_stcb as libc::c_int == 0i32 && !stcb.is_null() {
                    let mut oldval_1 = 0;
                    let mut oldval_2 = 0;
                    oldval_1 = ::std::intrinsics::atomic_xadd(
                        &mut (*stcb).asoc.sb_cc,
                        -(*m).m_hdr.mh_len as uint32_t,
                    ) as int32_t;
                    if oldval_1 < (*m).m_hdr.mh_len {
                        (*stcb).asoc.sb_cc = 0u32
                    }

                    oldval_2 = ::std::intrinsics::atomic_xadd(
                        &mut (*stcb).asoc.my_rwnd_control_len,
                        -(256i32) as uint32_t,
                    ) as int32_t;
                    if oldval_2 < 256i32 {
                        (*stcb).asoc.my_rwnd_control_len = 0u32
                    }
                }
                if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
                    sctp_sblog(
                        &mut (*old_so).so_rcv,
                        if (*control).do_not_ref_stcb as libc::c_int != 0 {
                            0 as *mut sctp_tcb
                        } else {
                            stcb
                        },
                        55i32,
                        0i32,
                    );
                }
                m = (*m).m_hdr.mh_next
            }
        }
        control = nctl
    }
    pthread_mutex_unlock(&mut (*old_inp).inp_rdata_mtx);
    /* Remove the sb-lock on the old socket */
    /* Now we move them over to the new socket buffer */
    pthread_mutex_lock(&mut (*new_inp).inp_rdata_mtx);
    control = tmp_queue.tqh_first;
    while !control.is_null() && {
        nctl = (*control).next.tqe_next;
        (1i32) != 0
    } {
        (*control).next.tqe_next = 0 as *mut sctp_queued_to_read;
        (*control).next.tqe_prev = (*new_inp).read_queue.tqh_last;
        *(*new_inp).read_queue.tqh_last = control;
        (*new_inp).read_queue.tqh_last = &mut (*control).next.tqe_next;
        m = (*control).data;
        while !m.is_null() {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
                sctp_sblog(
                    &mut (*new_so).so_rcv,
                    if (*control).do_not_ref_stcb as libc::c_int != 0 {
                        0 as *mut sctp_tcb
                    } else {
                        stcb
                    },
                    53i32,
                    (*m).m_hdr.mh_len,
                );
            }
            ::std::intrinsics::atomic_xadd(&mut (*new_so).so_rcv.sb_cc, (*m).m_hdr.mh_len as u_int);
            ::std::intrinsics::atomic_xadd(&mut (*new_so).so_rcv.sb_mbcnt, 256u32);
            if !stcb.is_null() {
                ::std::intrinsics::atomic_xadd(
                    &mut (*stcb).asoc.sb_cc,
                    (*m).m_hdr.mh_len as uint32_t,
                );
                ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.my_rwnd_control_len, 256u32);
            }
            if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
                sctp_sblog(
                    &mut (*new_so).so_rcv,
                    if (*control).do_not_ref_stcb as libc::c_int != 0 {
                        0 as *mut sctp_tcb
                    } else {
                        stcb
                    },
                    55i32,
                    0i32,
                );
            }
            m = (*m).m_hdr.mh_next
        }
        control = nctl
    }
    pthread_mutex_unlock(&mut (*new_inp).inp_rdata_mtx);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_wakeup_the_read_socket(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut so_locked: libc::c_int,
) {
    if !inp.is_null() && !(*inp).sctp_socket.is_null() {
        if (*inp).sctp_flags & 0x800000u32 != 0 {
            (*inp).sctp_flags |= 0x2000000u32
        } else {
            pthread_mutex_lock(&mut (*(*inp).sctp_socket).so_rcv.sb_mtx);
            if (*(*inp).sctp_socket).so_rcv.sb_flags as libc::c_int
                & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                != 0i32
            {
                sowakeup((*inp).sctp_socket, &mut (*(*inp).sctp_socket).so_rcv);
            } else {
                pthread_mutex_unlock(&mut (*(*inp).sctp_socket).so_rcv.sb_mtx);
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_invoke_recv_callback(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut control: *mut sctp_queued_to_read,
    mut inp_read_lock_held: libc::c_int,
) {
    let mut pd_point = 0;
    let mut length = 0;
    if (*inp).recv_callback.is_none() || stcb.is_null() || (*stcb).sctp_socket.is_null() {
        return;
    }
    length = (*control).length;
    if !stcb.is_null() && !(*stcb).sctp_socket.is_null() {
        pd_point = if (*(*stcb).sctp_socket).so_rcv.sb_hiwat >> 1i32
            > (*(*stcb).sctp_ep).partial_delivery_point
        {
            (*(*stcb).sctp_ep).partial_delivery_point
        } else {
            ((*(*stcb).sctp_socket).so_rcv.sb_hiwat) >> 1i32
        }
    } else {
        pd_point = (*inp).partial_delivery_point
    }
    if (*control).end_added as libc::c_int == 1i32 || length >= pd_point {
        let mut so = 0 as *mut socket;
        let mut m = 0 as *mut mbuf;
        let mut buffer = 0 as *mut libc::c_char;
        let mut rcv = sctp_rcvinfo {
            rcv_sid: 0,
            rcv_ssn: 0,
            rcv_flags: 0,
            rcv_ppid: 0,
            rcv_tsn: 0,
            rcv_cumtsn: 0,
            rcv_context: 0,
            rcv_assoc_id: 0,
        };
        let mut addr = sctp_sockstore {
            sin: sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            },
        };
        let mut flags = 0;
        buffer = malloc(length as libc::c_ulong) as *mut libc::c_char;
        if buffer.is_null() {
            return;
        }
        if inp_read_lock_held == 0i32 {
            pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
        }
        so = (*stcb).sctp_socket;
        m = (*control).data;
        while !m.is_null() {
            let mut oldval = 0;
            let mut oldval_0 = 0;
            oldval = ::std::intrinsics::atomic_xadd(
                &mut (*so).so_rcv.sb_cc,
                -(*m).m_hdr.mh_len as u_int,
            ) as int32_t;
            if oldval < (*m).m_hdr.mh_len {
                (*so).so_rcv.sb_cc = 0u32
            }

            oldval_0 =
                ::std::intrinsics::atomic_xadd(&mut (*so).so_rcv.sb_mbcnt, -(256i32) as u_int)
                    as int32_t;
            if oldval_0 < 256i32 {
                (*so).so_rcv.sb_mbcnt = 0u32
            }
            if (*control).do_not_ref_stcb as libc::c_int == 0i32 && !(*control).stcb.is_null() {
                let mut oldval_1 = 0;
                let mut oldval_2 = 0;
                oldval_1 = ::std::intrinsics::atomic_xadd(
                    &mut (*(*control).stcb).asoc.sb_cc,
                    -(*m).m_hdr.mh_len as uint32_t,
                ) as int32_t;
                if oldval_1 < (*m).m_hdr.mh_len {
                    (*(*control).stcb).asoc.sb_cc = 0u32
                }

                oldval_2 = ::std::intrinsics::atomic_xadd(
                    &mut (*(*control).stcb).asoc.my_rwnd_control_len,
                    -(256i32) as uint32_t,
                ) as int32_t;
                if oldval_2 < 256i32 {
                    (*(*control).stcb).asoc.my_rwnd_control_len = 0u32
                }
            }
            m = (*m).m_hdr.mh_next
        }
        m_copydata((*control).data, 0i32, length as libc::c_int, buffer);
        memset(
            &mut rcv as *mut sctp_rcvinfo as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_rcvinfo>() as libc::c_ulong,
        );
        rcv.rcv_sid = (*control).sinfo_stream;
        rcv.rcv_ssn = (*control).mid as uint16_t;
        rcv.rcv_flags = (*control).sinfo_flags;
        rcv.rcv_ppid = (*control).sinfo_ppid;
        rcv.rcv_tsn = (*control).sinfo_tsn;
        rcv.rcv_cumtsn = (*control).sinfo_cumtsn;
        rcv.rcv_context = (*control).sinfo_context;
        rcv.rcv_assoc_id = (*control).sinfo_assoc_id;
        memset(
            &mut addr as *mut sctp_sockstore as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
        );
        match (*(*control).whoFrom).ro._l_addr.sa.sa_family as libc::c_int {
            2 => addr.sin = (*(*control).whoFrom).ro._l_addr.sin,
            10 => addr.sin6 = (*(*control).whoFrom).ro._l_addr.sin6,
            123 => addr.sconn = (*(*control).whoFrom).ro._l_addr.sconn,
            _ => addr.sa = (*(*control).whoFrom).ro._l_addr.sa,
        }
        flags = 0i32;
        if (*control).end_added as libc::c_int == 1i32 {
            flags |= MSG_EOR as libc::c_int
        }
        if (*control).spec_flags as libc::c_int & 0x100i32 != 0 {
            flags |= 0x2000i32
        }
        m_freem((*control).data);
        (*control).data = 0 as *mut mbuf;
        (*control).tail_mbuf = 0 as *mut mbuf;
        (*control).length = 0u32;
        if (*control).end_added != 0 {
            if !(*control).next.tqe_next.is_null() {
                (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
            } else {
                (*(*stcb).sctp_ep).read_queue.tqh_last = (*control).next.tqe_prev
            }
            *(*control).next.tqe_prev = (*control).next.tqe_next;
            (*control).on_read_q = 0u8;
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
            (*control).whoFrom = 0 as *mut sctp_nets;
            free(control as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
        }
        ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        if inp_read_lock_held == 0i32 {
            pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
        }
        (*inp).recv_callback.expect("non-null function pointer")(
            so,
            addr,
            buffer as *mut libc::c_void,
            length as size_t,
            rcv,
            flags,
            (*inp).ulp_info,
        );
        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
        ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.refcnt, 1u32);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_add_to_readq(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut control: *mut sctp_queued_to_read,
    mut sb: *mut sockbuf,
    mut end: libc::c_int,
    mut inp_read_lock_held: libc::c_int,
    mut so_locked: libc::c_int,
) {
    let mut m = 0 as *mut mbuf;
    let mut prev = 0 as *mut mbuf;
    if inp.is_null() {
        /* Gak, TSNH!! */
        return;
    }
    if inp_read_lock_held == 0i32 {
        pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
    }
    if (*inp).sctp_flags & 0x40000000u32 != 0 {
        if (*control).on_strm_q == 0 {
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
        }
        if inp_read_lock_held == 0i32 {
            pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
        }
        return;
    }
    if (*control).spec_flags as libc::c_int & 0x100i32 == 0 {
        ::std::intrinsics::atomic_xadd(&mut (*inp).total_recvs, 1u32);
        if (*control).do_not_ref_stcb == 0 {
            ::std::intrinsics::atomic_xadd(&mut (*stcb).total_recvs, 1u32);
        }
    }
    m = (*control).data;
    (*control).held_length = 0u32;
    (*control).length = 0u32;
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
            if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
                sctp_sblog(
                    sb,
                    if (*control).do_not_ref_stcb as libc::c_int != 0 {
                        0 as *mut sctp_tcb
                    } else {
                        stcb
                    },
                    53i32,
                    (*m).m_hdr.mh_len,
                );
            }
            ::std::intrinsics::atomic_xadd(&mut (*sb).sb_cc, (*m).m_hdr.mh_len as u_int);
            ::std::intrinsics::atomic_xadd(&mut (*sb).sb_mbcnt, 256u32);
            if !stcb.is_null() {
                ::std::intrinsics::atomic_xadd(
                    &mut (*stcb).asoc.sb_cc,
                    (*m).m_hdr.mh_len as uint32_t,
                );
                ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.my_rwnd_control_len, 256u32);
            }
            if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32 != 0 {
                sctp_sblog(
                    sb,
                    if (*control).do_not_ref_stcb as libc::c_int != 0 {
                        0 as *mut sctp_tcb
                    } else {
                        stcb
                    },
                    55i32,
                    0i32,
                );
            }
            ::std::intrinsics::atomic_xadd(&mut (*control).length, (*m).m_hdr.mh_len as uint32_t);
            m = (*m).m_hdr.mh_next
        }
    }
    if !prev.is_null() {
        (*control).tail_mbuf = prev
    } else {
        /* Everything got collapsed out?? */
        if (*control).on_strm_q == 0 {
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
            free(control as *mut libc::c_void);
            ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_readq, 1u32);
        }
        if inp_read_lock_held == 0i32 {
            pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
        }
        return;
    }
    if end != 0 {
        (*control).end_added = 1u8
    }
    (*control).next.tqe_next = 0 as *mut sctp_queued_to_read;
    (*control).next.tqe_prev = (*inp).read_queue.tqh_last;
    *(*inp).read_queue.tqh_last = control;
    (*inp).read_queue.tqh_last = &mut (*control).next.tqe_next;
    (*control).on_read_q = 1u8;
    if inp_read_lock_held == 0i32 {
        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
    }
    sctp_invoke_recv_callback(inp, stcb, control, inp_read_lock_held);
    if !inp.is_null() && !(*inp).sctp_socket.is_null() {
        sctp_wakeup_the_read_socket(inp, stcb, so_locked);
    };
}
/* ************HOLD THIS COMMENT FOR PATCH FILE OF
 *************ALTERNATE ROUTING CODE
 */
/* ************HOLD THIS COMMENT FOR END OF PATCH FILE OF
 *************ALTERNATE ROUTING CODE
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_generate_cause(
    mut code: uint16_t,
    mut info: *mut libc::c_char,
) -> *mut mbuf {
    let mut m = 0 as *mut mbuf;
    let mut info_len = 0;
    let mut len = 0;
    if code as libc::c_int == 0i32 || info.is_null() {
        return 0 as *mut mbuf;
    }
    info_len = strlen(info);
    if info_len > (0xffffu64).wrapping_sub(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
    {
        return 0 as *mut mbuf;
    }
    len = (::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong).wrapping_add(info_len)
        as uint16_t;
    m = sctp_get_mbuf_for_msg(len as libc::c_uint, 0i32, 0x1i32, 1i32, 1i32);
    if !m.is_null() {
        let mut cause = 0 as *mut sctp_gen_error_cause;
        (*m).m_hdr.mh_len = len as libc::c_int;
        cause = (*m).m_hdr.mh_data as *mut sctp_gen_error_cause;
        (*cause).code = htons(code);
        (*cause).length = htons(len);
        memcpy(
            (*cause).info.as_mut_ptr() as *mut libc::c_void,
            info as *const libc::c_void,
            info_len,
        );
    }
    return m;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_generate_no_user_data_cause(mut tsn: uint32_t) -> *mut mbuf {
    let mut m = 0 as *mut mbuf;
    let mut len = 0;
    len = ::std::mem::size_of::<sctp_error_no_user_data>() as uint16_t;
    m = sctp_get_mbuf_for_msg(len as libc::c_uint, 0i32, 0x1i32, 1i32, 1i32);
    if !m.is_null() {
        let mut no_user_data_cause = 0 as *mut sctp_error_no_user_data;
        (*m).m_hdr.mh_len = len as libc::c_int;
        no_user_data_cause = (*m).m_hdr.mh_data as *mut sctp_error_no_user_data;
        (*no_user_data_cause).cause.code = htons(0x9u16);
        (*no_user_data_cause).cause.length = htons(len);
        (*no_user_data_cause).tsn = htonl(tsn)
    }
    return m;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_release_pr_sctp_chunk(
    mut stcb: *mut sctp_tcb,
    mut tp1: *mut sctp_tmit_chunk,
    mut sent: uint8_t,
    mut so_locked: libc::c_int,
) -> libc::c_int {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut mid = 0;
    let mut sid = 0;
    let mut foundeom = 0u8;
    let mut ret_sz = 0i32;
    let mut do_wakeup_routine = 0i32;
    sid = (*tp1).rec.data.sid;
    mid = (*tp1).rec.data.mid;
    if sent as libc::c_int != 0 || (*tp1).rec.data.rcv_flags as libc::c_int & 0x2i32 == 0 {
        (*stcb).asoc.abandoned_sent[0usize] = (*stcb).asoc.abandoned_sent[0usize].wrapping_add(1);
        (*stcb).asoc.abandoned_sent[((*tp1).flags as libc::c_int & 0xfi32) as usize] =
            (*stcb).asoc.abandoned_sent[((*tp1).flags as libc::c_int & 0xfi32) as usize]
                .wrapping_add(1);
        let ref mut fresh10 = (*(*stcb).asoc.strmout.offset(sid as isize)).abandoned_sent[0usize];
        *fresh10 = (*fresh10).wrapping_add(1)
    } else {
        (*stcb).asoc.abandoned_unsent[0usize] =
            (*stcb).asoc.abandoned_unsent[0usize].wrapping_add(1);
        (*stcb).asoc.abandoned_unsent[((*tp1).flags as libc::c_int & 0xfi32) as usize] =
            (*stcb).asoc.abandoned_unsent[((*tp1).flags as libc::c_int & 0xfi32) as usize]
                .wrapping_add(1);
        let ref mut fresh11 = (*(*stcb).asoc.strmout.offset(sid as isize)).abandoned_unsent[0usize];
        *fresh11 = (*fresh11).wrapping_add(1)
    }
    loop {
        let mut notdone = 0;
        ret_sz += (*tp1).book_size as libc::c_int;
        if !(*tp1).data.is_null() {
            if (*tp1).sent < 4i32 {
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
                        (*stcb).asoc.total_flight_count =
                            (*stcb).asoc.total_flight_count.wrapping_sub(1)
                    }
                } else {
                    (*stcb).asoc.total_flight = 0u32;
                    (*stcb).asoc.total_flight_count = 0u32
                }
            }
            if !(*tp1).data.is_null() {
                ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.chunks_on_out_queue, 1u32);
                if (*stcb).asoc.total_output_queue_size >= (*tp1).book_size as libc::c_uint {
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
                    if (*(*stcb).sctp_socket).so_snd.sb_cc >= (*tp1).book_size as libc::c_uint {
                        ::std::intrinsics::atomic_xsub(
                            &mut (*(*stcb).sctp_socket).so_snd.sb_cc,
                            (*tp1).book_size as u_int,
                        );
                    } else {
                        (*(*stcb).sctp_socket).so_snd.sb_cc = 0u32
                    }
                }
            }
            (*stcb).asoc.peers_rwnd =
                ((*stcb).asoc.peers_rwnd).wrapping_add((*tp1).send_size as libc::c_uint);
            (*stcb).asoc.peers_rwnd = ((*stcb).asoc.peers_rwnd)
                .wrapping_add(system_base_info.sctpsysctl.sctp_peer_chunk_oh);
            if sent != 0 {
                sctp_ulp_notify(5u32, stcb, 0u32, tp1 as *mut libc::c_void, so_locked);
            } else {
                sctp_ulp_notify(6u32, stcb, 0u32, tp1 as *mut libc::c_void, so_locked);
            }
            if !(*tp1).data.is_null() {
                m_freem((*tp1).data);
                (*tp1).data = 0 as *mut mbuf
            }
            do_wakeup_routine = 1i32;
            if (*tp1).flags as libc::c_int & 0xfi32 == 0x2i32 {
                (*stcb).asoc.sent_queue_cnt_removeable =
                    (*stcb).asoc.sent_queue_cnt_removeable.wrapping_sub(1)
            }
        }
        (*tp1).sent = 30010i32;
        if (*tp1).rec.data.rcv_flags as libc::c_int & 0x3i32 == 0x3i32 {
            /* not frag'ed we ae done   */
            notdone = 0i32;
            foundeom = 1u8
        } else if (*tp1).rec.data.rcv_flags as libc::c_int & 0x1i32 != 0 {
            /* end of frag, we are done */
            notdone = 0i32;
            foundeom = 1u8
        } else {
            /*
             * Its a begin or middle piece, we must mark all of
             * it
             */
            notdone = 1i32;
            tp1 = (*tp1).sctp_next.tqe_next
        }
        if !(!tp1.is_null() && notdone != 0) {
            break;
        }
    }
    if foundeom as libc::c_int == 0i32 {
        let mut tp2 = 0 as *mut sctp_tmit_chunk;
        tp1 = (*stcb).asoc.send_queue.tqh_first;
        while !tp1.is_null() && {
            tp2 = (*tp1).sctp_next.tqe_next;
            (1i32) != 0
        } {
            if (*tp1).rec.data.sid as libc::c_int != sid as libc::c_int
                || (if (*stcb).asoc.idata_supported as libc::c_int == 1i32 {
                    ((*tp1).rec.data.mid == mid) as libc::c_int
                } else {
                    ((*tp1).rec.data.mid as uint16_t as libc::c_int
                        == mid as uint16_t as libc::c_int) as libc::c_int
                }) == 0
            {
                break;
            }
            /* save to chk in case we have some on stream out
             * queue. If so and we have an un-transmitted one
             * we don't have to fudge the TSN.
             */
            chk = tp1;
            ret_sz += (*tp1).book_size as libc::c_int;
            if !(*tp1).data.is_null() {
                ::std::intrinsics::atomic_xsub(&mut (*stcb).asoc.chunks_on_out_queue, 1u32);
                if (*stcb).asoc.total_output_queue_size >= (*tp1).book_size as libc::c_uint {
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
                    if (*(*stcb).sctp_socket).so_snd.sb_cc >= (*tp1).book_size as libc::c_uint {
                        ::std::intrinsics::atomic_xsub(
                            &mut (*(*stcb).sctp_socket).so_snd.sb_cc,
                            (*tp1).book_size as u_int,
                        );
                    } else {
                        (*(*stcb).sctp_socket).so_snd.sb_cc = 0u32
                    }
                }
            }
            if sent != 0 {
                sctp_ulp_notify(5u32, stcb, 0u32, tp1 as *mut libc::c_void, so_locked);
            } else {
                sctp_ulp_notify(6u32, stcb, 0u32, tp1 as *mut libc::c_void, so_locked);
            }
            if !(*tp1).data.is_null() {
                m_freem((*tp1).data);
                (*tp1).data = 0 as *mut mbuf
            }
            /* No flight involved here book the size to 0 */
            (*tp1).book_size = 0u16;
            if (*tp1).rec.data.rcv_flags as libc::c_int & 0x1i32 != 0 {
                foundeom = 1u8
            }
            do_wakeup_routine = 1i32;
            (*tp1).sent = 30010i32;
            if !(*tp1).sctp_next.tqe_next.is_null() {
                (*(*tp1).sctp_next.tqe_next).sctp_next.tqe_prev = (*tp1).sctp_next.tqe_prev
            } else {
                (*stcb).asoc.send_queue.tqh_last = (*tp1).sctp_next.tqe_prev
            }
            *(*tp1).sctp_next.tqe_prev = (*tp1).sctp_next.tqe_next;
            /* on to the sent queue so we can wait for it to be passed by. */
            (*tp1).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
            (*tp1).sctp_next.tqe_prev = (*stcb).asoc.sent_queue.tqh_last;
            *(*stcb).asoc.sent_queue.tqh_last = tp1;
            (*stcb).asoc.sent_queue.tqh_last = &mut (*tp1).sctp_next.tqe_next;
            (*stcb).asoc.send_queue_cnt = (*stcb).asoc.send_queue_cnt.wrapping_sub(1);
            (*stcb).asoc.sent_queue_cnt = (*stcb).asoc.sent_queue_cnt.wrapping_add(1);
            tp1 = tp2
        }
    }
    if foundeom as libc::c_int == 0i32 {
        let mut strq = 0 as *mut sctp_stream_out;
        let mut sp = 0 as *mut sctp_stream_queue_pending;
        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
        strq = &mut *(*stcb).asoc.strmout.offset(sid as isize) as *mut sctp_stream_out;
        sp = (*strq).outqueue.tqh_first;
        if !sp.is_null() {
            let mut current_block_228: u64;
            (*sp).discard_rest = 1u8;
            /*
             * We may need to put a chunk on the
             * queue that holds the TSN that
             * would have been sent with the LAST
             * bit.
             */
            if chk.is_null() {
                /* Yep, we have to */
                if (*stcb).asoc.free_chunks.tqh_first.is_null() {
                    chk =
                        malloc(system_base_info.sctppcbinfo.ipi_zone_chunk) as *mut sctp_tmit_chunk;
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
                        (*(*chk).sctp_next.tqe_next).sctp_next.tqe_prev = (*chk).sctp_next.tqe_prev
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
                    (*stcb).asoc.free_chunk_cnt = (*stcb).asoc.free_chunk_cnt.wrapping_sub(1)
                }
                if chk.is_null() {
                    current_block_228 = 1255046934928975260;
                } else {
                    memset(
                        chk as *mut libc::c_void,
                        0i32,
                        ::std::mem::size_of::<sctp_tmit_chunk>() as libc::c_ulong,
                    );
                    (*chk).rec.data.rcv_flags = 0u8;
                    (*chk).sent = 30010i32;
                    (*chk).asoc = &mut (*stcb).asoc;
                    if (*stcb).asoc.idata_supported as libc::c_int == 0i32 {
                        if (*sp).sinfo_flags as libc::c_int & 0x400i32 != 0 {
                            (*chk).rec.data.mid = 0u32
                        } else {
                            (*chk).rec.data.mid = (*strq).next_mid_ordered
                        }
                    } else if (*sp).sinfo_flags as libc::c_int & 0x400i32 != 0 {
                        (*chk).rec.data.mid = (*strq).next_mid_unordered
                    } else {
                        (*chk).rec.data.mid = (*strq).next_mid_ordered
                    }
                    (*chk).rec.data.sid = (*sp).sid;
                    (*chk).rec.data.ppid = (*sp).ppid;
                    (*chk).rec.data.context = (*sp).context;
                    (*chk).flags = (*sp).act_flags;
                    (*chk).whoTo = 0 as *mut sctp_nets;
                    let fresh12 = (*stcb).asoc.sending_seq;
                    (*stcb).asoc.sending_seq = (*stcb).asoc.sending_seq.wrapping_add(1);
                    (*chk).rec.data.tsn = fresh12;
                    (*strq).chunks_on_queues = (*strq).chunks_on_queues.wrapping_add(1);
                    (*chk).sctp_next.tqe_next = 0 as *mut sctp_tmit_chunk;
                    (*chk).sctp_next.tqe_prev = (*stcb).asoc.sent_queue.tqh_last;
                    *(*stcb).asoc.sent_queue.tqh_last = chk;
                    (*stcb).asoc.sent_queue.tqh_last = &mut (*chk).sctp_next.tqe_next;
                    (*stcb).asoc.sent_queue_cnt = (*stcb).asoc.sent_queue_cnt.wrapping_add(1);
                    (*stcb).asoc.pr_sctp_cnt = (*stcb).asoc.pr_sctp_cnt.wrapping_add(1);
                    current_block_228 = 5153559628248805366;
                }
            } else {
                current_block_228 = 5153559628248805366;
            }
            match current_block_228 {
                5153559628248805366 => {
                    (*chk).rec.data.rcv_flags =
                        ((*chk).rec.data.rcv_flags as libc::c_int | 0x1i32) as uint8_t;
                    if (*sp).sinfo_flags as libc::c_int & 0x400i32 != 0 {
                        (*chk).rec.data.rcv_flags =
                            ((*chk).rec.data.rcv_flags as libc::c_int | 0x4i32) as uint8_t
                    }
                    if (*stcb).asoc.idata_supported as libc::c_int == 0i32 {
                        if (*sp).sinfo_flags as libc::c_int & 0x400i32 == 0i32 {
                            (*strq).next_mid_ordered = (*strq).next_mid_ordered.wrapping_add(1)
                        }
                    } else if (*sp).sinfo_flags as libc::c_int & 0x400i32 != 0 {
                        (*strq).next_mid_unordered = (*strq).next_mid_unordered.wrapping_add(1)
                    } else {
                        (*strq).next_mid_ordered = (*strq).next_mid_ordered.wrapping_add(1)
                    }
                }
                _ => {}
            }
            /* we are hosed. All we can
             * do is nothing.. which will
             * cause an abort if the peer is
             * paying attention.
             */
            if !(*sp).data.is_null() {
                /* Pull any data to free up the SB and
                 * allow sender to "add more" while we
                 * will throw away :-)
                 */
                if !(*sp).data.is_null() {
                    if (*stcb).asoc.total_output_queue_size >= (*sp).length {
                        ::std::intrinsics::atomic_xsub(
                            &mut (*stcb).asoc.total_output_queue_size,
                            (*sp).length,
                        );
                    } else {
                        (*stcb).asoc.total_output_queue_size = 0u32
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
                ret_sz = (ret_sz as libc::c_uint).wrapping_add((*sp).length) as libc::c_int;
                do_wakeup_routine = 1i32;
                (*sp).some_taken = 1u8;
                m_freem((*sp).data);
                (*sp).data = 0 as *mut mbuf;
                (*sp).tail_mbuf = 0 as *mut mbuf;
                (*sp).length = 0u32
            }
        }
        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
    }
    if do_wakeup_routine != 0 {
        if (*(*stcb).sctp_ep).sctp_flags & 0x800000u32 != 0 {
            (*(*stcb).sctp_ep).sctp_flags |= 0x1000000u32
        } else {
            pthread_mutex_lock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
            if (*(*stcb).sctp_socket).so_snd.sb_flags as libc::c_int
                & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                != 0i32
            {
                sowakeup((*stcb).sctp_socket, &mut (*(*stcb).sctp_socket).so_snd);
            } else {
                pthread_mutex_unlock(&mut (*(*stcb).sctp_socket).so_snd.sb_mtx);
            }
        }
    }
    return ret_sz;
}
/*
 * checks to see if the given address, sa, is one that is currently known by
 * the kernel note: can't distinguish the same address on multiple interfaces
 * and doesn't handle multiple addresses with different zone/scope id's note:
 * ifa_ifwithaddr() compares the entire sockaddr struct
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_find_ifa_in_ep(
    mut inp: *mut sctp_inpcb,
    mut addr: *mut sockaddr,
    mut holds_lock: libc::c_int,
) -> *mut sctp_ifa {
    let mut laddr = 0 as *mut sctp_laddr;
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut (*inp).inp_mtx);
    }
    laddr = (*inp).sctp_addr_list.lh_first;
    while !laddr.is_null() {
        if !(*laddr).ifa.is_null() {
            if !((*addr).sa_family as libc::c_int
                != (*(*laddr).ifa).address.sa.sa_family as libc::c_int)
            {
                if (*addr).sa_family as libc::c_int == 2i32 {
                    if (*(addr as *mut sockaddr_in)).sin_addr.s_addr
                        == (*(*laddr).ifa).address.sin.sin_addr.s_addr
                    {
                        /* found him. */
                        if holds_lock == 0i32 {
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        }
                        return (*laddr).ifa;
                    }
                }
                if (*addr).sa_family as libc::c_int == 10i32 {
                    if SCTP6_ARE_ADDR_EQUAL(
                        addr as *mut sockaddr_in6,
                        &mut (*(*laddr).ifa).address.sin6,
                    ) != 0
                    {
                        /* found him. */
                        if holds_lock == 0i32 {
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        }
                        return (*laddr).ifa;
                    }
                }
                if (*addr).sa_family as libc::c_int == 123i32 {
                    if (*(addr as *mut sockaddr_conn)).sconn_addr
                        == (*(*laddr).ifa).address.sconn.sconn_addr
                    {
                        /* found him. */
                        if holds_lock == 0i32 {
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        }
                        return (*laddr).ifa;
                    }
                }
            }
        }
        laddr = (*laddr).sctp_nxt_addr.le_next
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
    }
    return 0 as *mut sctp_ifa;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_get_ifa_hash_val(mut addr: *mut sockaddr) -> uint32_t {
    match (*addr).sa_family as libc::c_int {
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            sin = addr as *mut sockaddr_in;
            return (*sin).sin_addr.s_addr ^ (*sin).sin_addr.s_addr >> 16i32;
        }
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            let mut hash_of_addr = 0;
            sin6 = addr as *mut sockaddr_in6;
            hash_of_addr = (*sin6).sin6_addr.__in6_u.__u6_addr32[0usize]
                .wrapping_add((*sin6).sin6_addr.__in6_u.__u6_addr32[1usize])
                .wrapping_add((*sin6).sin6_addr.__in6_u.__u6_addr32[2usize])
                .wrapping_add((*sin6).sin6_addr.__in6_u.__u6_addr32[3usize]);
            hash_of_addr = hash_of_addr ^ hash_of_addr >> 16i32;
            return hash_of_addr;
        }
        123 => {
            let mut sconn = 0 as *mut sockaddr_conn;
            let mut temp = 0;
            sconn = addr as *mut sockaddr_conn;
            temp = (*sconn).sconn_addr as uintptr_t;
            return (temp ^ temp >> 16i32) as uint32_t;
        }
        _ => {}
    }
    return 0u32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_find_ifa_by_addr(
    mut addr: *mut sockaddr,
    mut vrf_id: uint32_t,
    mut holds_lock: libc::c_int,
) -> *mut sctp_ifa {
    let mut sctp_ifap = 0 as *mut sctp_ifa;
    let mut vrf = 0 as *mut sctp_vrf;
    let mut hash_head = 0 as *mut sctp_ifalist;
    let mut hash_of_addr = 0;
    if holds_lock == 0i32 {
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    }
    vrf = sctp_find_vrf(vrf_id);
    if vrf.is_null() {
        if holds_lock == 0i32 {
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        }
        return 0 as *mut sctp_ifa;
    }
    hash_of_addr = sctp_get_ifa_hash_val(addr);
    hash_head = &mut *(*vrf)
        .vrf_addr_hash
        .offset((hash_of_addr as libc::c_ulong & (*vrf).vrf_addr_hashmark) as isize)
        as *mut sctp_ifalist;
    if hash_head.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"hash_of_addr:%x mask:%x table:%x - \x00" as *const u8 as *const libc::c_char,
                hash_of_addr,
                (*vrf).vrf_addr_hashmark as uint32_t,
                (hash_of_addr as libc::c_ulong & (*vrf).vrf_addr_hashmark) as uint32_t,
            );
        }
        sctp_print_address(addr);
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"No such bucket for address\n\x00" as *const u8 as *const libc::c_char,
            );
        }
        if holds_lock == 0i32 {
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        }
        return 0 as *mut sctp_ifa;
    }
    sctp_ifap = (*hash_head).lh_first;
    while !sctp_ifap.is_null() {
        if !((*addr).sa_family as libc::c_int != (*sctp_ifap).address.sa.sa_family as libc::c_int) {
            if (*addr).sa_family as libc::c_int == 2i32 {
                if (*(addr as *mut sockaddr_in)).sin_addr.s_addr
                    == (*sctp_ifap).address.sin.sin_addr.s_addr
                {
                    /* found him. */
                    if holds_lock == 0i32 {
                        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
                    }
                    return sctp_ifap;
                }
            }
            if (*addr).sa_family as libc::c_int == 10i32 {
                if SCTP6_ARE_ADDR_EQUAL(addr as *mut sockaddr_in6, &mut (*sctp_ifap).address.sin6)
                    != 0
                {
                    /* found him. */
                    if holds_lock == 0i32 {
                        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
                    }
                    return sctp_ifap;
                }
            }
            if (*addr).sa_family as libc::c_int == 123i32 {
                if (*(addr as *mut sockaddr_conn)).sconn_addr
                    == (*sctp_ifap).address.sconn.sconn_addr
                {
                    /* found him. */
                    if holds_lock == 0i32 {
                        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
                    }
                    return sctp_ifap;
                }
            }
        }
        sctp_ifap = (*sctp_ifap).next_bucket.le_next
    }
    if holds_lock == 0i32 {
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    }
    return 0 as *mut sctp_ifa;
}
unsafe extern "C" fn sctp_user_rcvd(
    mut stcb: *mut sctp_tcb,
    mut freed_so_far: *mut uint32_t,
    mut hold_rlock: libc::c_int,
    mut rwnd_req: uint32_t,
) {
    if stcb.is_null() {
        return;
    }
    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, 1u32);
    if !((*stcb).asoc.state & 0x7fi32 == 0x40i32 || (*stcb).asoc.state & (0x200i32 | 0x20i32) != 0)
    {
        let mut r_unlocked = 0i32;
        let mut so = 0 as *mut socket;
        ::std::intrinsics::atomic_xadd(&mut (*(*stcb).sctp_ep).refcount, 1i32);
        if !((*(*stcb).sctp_ep).sctp_flags & 0x10000000u32 != 0
            || (*(*stcb).sctp_ep).sctp_flags & 0x20000000u32 != 0)
        {
            so = (*stcb).sctp_socket;
            if !so.is_null() {
                let mut dif = 0;
                let mut rwnd = 0;
                ::std::intrinsics::atomic_xadd(
                    &mut (*stcb).freed_by_sorcv_sincelast,
                    *freed_so_far,
                );
                /* Have you have freed enough to look */
                *freed_so_far = 0u32;
                /* Yep, its worth a look and the lock overhead */
                /* Figure out what the rwnd would be */
                rwnd = sctp_calc_rwnd(stcb, &mut (*stcb).asoc);
                if rwnd >= (*stcb).asoc.my_last_reported_rwnd {
                    dif = rwnd.wrapping_sub((*stcb).asoc.my_last_reported_rwnd)
                } else {
                    dif = 0u32
                }
                if dif >= rwnd_req {
                    if hold_rlock != 0 {
                        pthread_mutex_unlock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
                        r_unlocked = 1i32
                    }
                    if !((*stcb).asoc.state & 0x200i32 != 0) {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                        if (*stcb).asoc.state & 0x200i32 != 0 {
                            /* No reports here */
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            ::std::intrinsics::atomic_xadd(
                                &mut system_base_info.sctpstat.sctps_wu_sacks_sent,
                                1u32,
                            );
                            sctp_send_sack(stcb, 1i32);
                            sctp_chunk_output((*stcb).sctp_ep, stcb, 13i32, 1i32);
                            /* make sure no timer is running */
                            sctp_timer_stop(
                                3i32,
                                (*stcb).sctp_ep,
                                stcb,
                                0 as *mut sctp_nets,
                                (0x60000000i32 + 0x6i32) as uint32_t,
                            );
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                } else {
                    /* Update how much we have pending */
                    (*stcb).freed_by_sorcv_sincelast = dif
                }
            }
        }
        /*
         * One last check before we allow the guy possibly
         * to get in. There is a race, where the guy has not
         * reached the gate. In that case
         */
        if !so.is_null() && r_unlocked != 0 && hold_rlock != 0 {
            pthread_mutex_lock(&mut (*(*stcb).sctp_ep).inp_rdata_mtx);
        }
        ::std::intrinsics::atomic_xadd(&mut (*(*stcb).sctp_ep).refcount, -(1i32));
    }
    /* Pre-check If we are freeing no update */
    ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, -(1i32) as uint32_t);
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
/* **********************************/
/* And something for us old timers */
/* **********************************/
/* **********************************/
/* future */
/* sctpAssocEntry 5/6 */
/* sctpAssocEntry 7   */
/* sctpAssocEntry 8   */
/* sctpAssocEntry 9   */
/* sctpAssocEntry 10  */
/* sctpAssocEntry 11  */
/* sctpAssocEntry 12  */
/* sctpAssocEntry 13  */
/* sctpAssocEntry 14  */
/* sctpAssocEntry 15  */
/* sctpAssocEntry 3   */
/* sctpAssocEntry 4   */
/* sctpAssocEntry 16  */
/* sctpAssocEntry 17  */
/* sctpAssocEntry 1   */
/* future */
/* sctpAssocLocalAddrEntry 1/2 */
/* sctpAssocLocalAddrEntry 3   */
/* future */
/* sctpAssocLocalRemEntry 1/2 */
/* sctpAssocLocalRemEntry 5   */
/* sctpAssocLocalRemEntry 6   */
/* sctpAssocLocalRemEntry 7   */
/*                            */
/*                            */
/*                            */
/*                            */
/* sctpAssocLocalRemEntry 3   */
/*                            */
/* sctpAssocLocalRemEntry 4   */
/* sctpAssocLocalRemEntry 8   */
/* future */
/* This number MUST be even   */
/*
 * Kernel defined for sctp_send
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_sorecvmsg(
    mut so: *mut socket,
    mut uio: *mut uio,
    mut mp: *mut *mut mbuf,
    mut from: *mut sockaddr,
    mut fromlen: libc::c_int,
    mut msg_flags: *mut libc::c_int,
    mut sinfo: *mut sctp_sndrcvinfo,
    mut filling_sinfo: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut error = 0i32;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut wakeup_read_socket = 0i32;
    let mut freecnt_applied = 0i32;
    let mut out_flags = 0i32;
    let mut in_flags = 0i32;
    let mut block_allowed = 1i32;
    let mut freed_so_far = 0u32;
    let mut in_eeor_mode = 0i32;
    let mut rwnd_req = 0u32;
    let mut hold_sblock = 0i32;
    let mut hold_rlock = 0i32;
    let mut slen = 0i64;
    if uio.is_null() {
        return 22i32;
    }
    if !msg_flags.is_null() {
        in_flags = *msg_flags;
        if in_flags & MSG_PEEK as libc::c_int != 0 {
            ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_read_peeks, 1u32);
        }
    } else {
        in_flags = 0i32
    }
    slen = (*uio).uio_resid;
    /* Pull in and set up our int flags */
    if in_flags & MSG_OOB as libc::c_int != 0 {
        /* Out of band's NOT supported */
        return 95i32;
    }
    if in_flags & MSG_PEEK as libc::c_int != 0 && !mp.is_null() {
        return 22i32;
    }
    if in_flags & MSG_DONTWAIT as libc::c_int != 0 || (*so).so_state as libc::c_int & 0x100i32 != 0
    {
        block_allowed = 0i32
    }
    /* setup the endpoint */
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 14i32;
    }
    rwnd_req = (*so).so_rcv.sb_hiwat >> 3i32;
    /* Must be at least a MTU's worth */
    if rwnd_req < 1500u32 {
        rwnd_req = 1500u32
    }
    in_eeor_mode = ((*inp).sctp_features & 0x400000u64 == 0x400000u64) as libc::c_int;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x1000u32 != 0 {
        sctp_misc_ints(
            88u8,
            rwnd_req,
            in_eeor_mode as uint32_t,
            (*so).so_rcv.sb_cc,
            (*uio).uio_resid as uint32_t,
        );
    }
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    hold_sblock = 1i32;
    if system_base_info.sctpsysctl.sctp_logging_level & 0x1000u32 != 0 {
        sctp_misc_ints(
            89u8,
            rwnd_req,
            block_allowed as uint32_t,
            (*so).so_rcv.sb_cc,
            (*uio).uio_resid as uint32_t,
        );
    }
    if error != 0 {
        current_block = 3874686694575430777;
    } else {
        current_block = 9906378635038024695;
    }
    'c_10360: loop {
        let mut control = 0 as *mut sctp_queued_to_read;
        let mut no_rcv_needed = 0i32;
        match current_block {
            3874686694575430777 => {
                if hold_sblock != 0 {
                    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
                    hold_sblock = 0i32
                }
                if !stcb.is_null() && in_flags & MSG_PEEK as libc::c_int == 0i32 {
                    if freed_so_far >= rwnd_req
                        && (!control.is_null() && (*control).do_not_ref_stcb as libc::c_int == 0i32)
                        && no_rcv_needed == 0i32
                    {
                        sctp_user_rcvd(stcb, &mut freed_so_far, hold_rlock, rwnd_req);
                    }
                }
                break;
            }
            _ => {
                let mut held_length = 0u32;
                if hold_sblock == 0i32 {
                    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
                    hold_sblock = 1i32
                }
                loop {
                    if hold_sblock == 0i32 {
                        pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
                        hold_sblock = 1i32
                    }
                    if (*inp).sctp_flags & 0x10000000u32 != 0
                        || (*inp).sctp_flags & 0x20000000u32 != 0
                    {
                        break 'c_10360;
                    }
                    if (*so).so_state as libc::c_int & 0x20i32 != 0 && (*so).so_rcv.sb_cc == 0u32 {
                        if (*so).so_error != 0 {
                            error = (*so).so_error as libc::c_int;
                            if in_flags & MSG_PEEK as libc::c_int == 0i32 {
                                (*so).so_error = 0u16
                            }
                            break 'c_10360;
                        } else if (*so).so_rcv.sb_cc == 0u32 {
                            /* indicate EOF */
                            error = 0i32;
                            break 'c_10360;
                        }
                    }
                    if (*so).so_rcv.sb_cc <= held_length {
                        if (*so).so_error != 0 {
                            error = (*so).so_error as libc::c_int;
                            if in_flags & MSG_PEEK as libc::c_int == 0i32 {
                                (*so).so_error = 0u16
                            }
                            break 'c_10360;
                        } else {
                            if (*so).so_rcv.sb_cc == 0u32
                                && ((*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0)
                            {
                                if (*inp).sctp_flags & 0x200000u32 == 0u32 {
                                    /* For active open side clear flags for re-use
                                     * passive open is blocked by connect.
                                     */
                                    if (*inp).sctp_flags & 0x100000u32 != 0 {
                                        /* You were aborted, passive side always hits here */
                                        error = 104i32
                                    }
                                    (*so).so_state = ((*so).so_state as libc::c_int
                                        & !(0x4i32 | 0x8i32 | 0x400i32 | 0x2i32))
                                        as libc::c_short;
                                    if error == 0i32 {
                                        if (*inp).sctp_flags & 0x80000u32 == 0u32 {
                                            error = 107i32
                                        }
                                    }
                                    break 'c_10360;
                                }
                            }
                            if block_allowed != 0 {
                                error = sbwait(&mut (*so).so_rcv);
                                if error != 0 {
                                    break 'c_10360;
                                }
                                held_length = 0u32
                            } else {
                                error = 11i32;
                                break 'c_10360;
                            }
                        }
                    } else {
                        if hold_sblock == 1i32 {
                            pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
                            hold_sblock = 0i32
                        }
                        /* we possibly have data we can read */
                        /*sa_ignore FREED_MEMORY*/
                        control = (*inp).read_queue.tqh_first;
                        if control.is_null() {
                            current_block = 2945622622075328793;
                            break;
                        } else {
                            current_block = 16593409533420678784;
                            break;
                        }
                    }
                }
                match current_block {
                    2945622622075328793 => {
                        /* This could be happening since
                         * the appender did the increment but as not
                         * yet did the tailq insert onto the read_queue
                         */
                        if hold_rlock == 0i32 {
                            pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                        }
                        control = (*inp).read_queue.tqh_first;
                        if control.is_null() && (*so).so_rcv.sb_cc != 0u32 {
                            (*so).so_rcv.sb_cc = 0u32
                        }
                        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                        hold_rlock = 0i32;
                        current_block = 9906378635038024695;
                    }
                    _ => {
                        if (*control).length == 0u32
                            && (*control).do_not_ref_stcb as libc::c_int != 0
                        {
                            /* Clean up code for freeing assoc that left behind a pdapi..
                             * maybe a peer in EEOR that just closed after sending and
                             * never indicated a EOR.
                             */
                            if hold_rlock == 0i32 {
                                hold_rlock = 1i32;
                                pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                            }
                            (*control).held_length = 0u32;
                            if !(*control).data.is_null() {
                                let mut m_tmp = 0 as *mut mbuf;
                                let mut cnt = 0i32;
                                m_tmp = (*control).data;
                                while !m_tmp.is_null() {
                                    cnt += (*m_tmp).m_hdr.mh_len;
                                    if (*m_tmp).m_hdr.mh_next.is_null() {
                                        (*control).tail_mbuf = m_tmp;
                                        (*control).end_added = 1u8
                                    }
                                    m_tmp = (*m_tmp).m_hdr.mh_next
                                }
                                (*control).length = cnt as uint32_t
                            } else {
                                /* remove it */
                                if !(*control).next.tqe_next.is_null() {
                                    (*(*control).next.tqe_next).next.tqe_prev =
                                        (*control).next.tqe_prev
                                } else {
                                    (*inp).read_queue.tqh_last = (*control).next.tqe_prev
                                }
                                *(*control).next.tqe_prev = (*control).next.tqe_next;
                                /* Add back any hiddend data */
                                if !(*control).whoFrom.is_null() {
                                    if ::std::intrinsics::atomic_xadd(
                                        &mut (*(*control).whoFrom).ref_count as *mut libc::c_int,
                                        -(1i32),
                                    ) == 1i32
                                    {
                                        sctp_os_timer_stop(
                                            &mut (*(*control).whoFrom).rxt_timer.timer,
                                        );
                                        sctp_os_timer_stop(
                                            &mut (*(*control).whoFrom).pmtu_timer.timer,
                                        );
                                        sctp_os_timer_stop(
                                            &mut (*(*control).whoFrom).hb_timer.timer,
                                        );
                                        if !(*(*control).whoFrom).ro.ro_rt.is_null() {
                                            if (*(*(*control).whoFrom).ro.ro_rt).rt_refcnt <= 1i64 {
                                                sctp_userspace_rtfree(
                                                    (*(*control).whoFrom).ro.ro_rt,
                                                );
                                            } else {
                                                (*(*(*control).whoFrom).ro.ro_rt).rt_refcnt -= 1
                                            }
                                            (*(*control).whoFrom).ro.ro_rt =
                                                0 as *mut sctp_rtentry_t;
                                            (*(*control).whoFrom).ro.ro_rt =
                                                0 as *mut sctp_rtentry_t
                                        }
                                        if (*(*control).whoFrom).src_addr_selected != 0 {
                                            sctp_free_ifa((*(*control).whoFrom).ro._s_addr);
                                            (*(*control).whoFrom).ro._s_addr = 0 as *mut sctp_ifa
                                        }
                                        (*(*control).whoFrom).src_addr_selected = 0u8;
                                        (*(*control).whoFrom).dest_state =
                                            ((*(*control).whoFrom).dest_state as libc::c_int
                                                & !(0x1i32))
                                                as uint16_t;
                                        free((*control).whoFrom as *mut libc::c_void);
                                        ::std::intrinsics::atomic_xsub(
                                            &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                            1u32,
                                        );
                                    }
                                }
                                free(control as *mut libc::c_void);
                                ::std::intrinsics::atomic_xsub(
                                    &mut system_base_info.sctppcbinfo.ipi_count_readq,
                                    1u32,
                                );
                            }
                            if hold_rlock != 0 {
                                hold_rlock = 0i32;
                                pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                            }
                            current_block = 9906378635038024695;
                        } else if (*control).length == 0u32
                            && (*control).end_added as libc::c_int == 1i32
                        {
                            /* Do we also need to check for (control->pdapi_aborted == 1)? */
                            if hold_rlock == 0i32 {
                                hold_rlock = 1i32;
                                pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                            }
                            if !(*control).next.tqe_next.is_null() {
                                (*(*control).next.tqe_next).next.tqe_prev = (*control).next.tqe_prev
                            } else {
                                (*inp).read_queue.tqh_last = (*control).next.tqe_prev
                            }
                            *(*control).next.tqe_prev = (*control).next.tqe_next;
                            if !(*control).data.is_null() {
                                if system_base_info.debug_printf.is_some() {
                                    system_base_info.debug_printf.expect("non-null function pointer")(b"Strange, data left in the control buffer. Cleaning up.\n\x00"
                                                                                                              as
                                                                                                              *const u8
                                                                                                              as
                                                                                                              *const libc::c_char);
                                }
                                m_freem((*control).data);
                                (*control).data = 0 as *mut mbuf
                            }
                            if !(*control).aux_data.is_null() {
                                m_free((*control).aux_data);
                                (*control).aux_data = 0 as *mut mbuf
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
                                        ((*(*control).whoFrom).dest_state as libc::c_int
                                            & !(0x1i32))
                                            as uint16_t;
                                    free((*control).whoFrom as *mut libc::c_void);
                                    ::std::intrinsics::atomic_xsub(
                                        &mut system_base_info.sctppcbinfo.ipi_count_raddr,
                                        1u32,
                                    );
                                }
                            }
                            free(control as *mut libc::c_void);
                            ::std::intrinsics::atomic_xsub(
                                &mut system_base_info.sctppcbinfo.ipi_count_readq,
                                1u32,
                            );
                            if hold_rlock != 0 {
                                hold_rlock = 0i32;
                                pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                            }
                            current_block = 9906378635038024695;
                        } else {
                            let mut m = 0 as *mut mbuf;
                            if (*control).length == 0u32 {
                                if (*inp).sctp_features & 0x8u64 == 0x8u64 && filling_sinfo != 0 {
                                    let mut ctl = 0 as *mut sctp_queued_to_read;
                                    ctl = (*control).next.tqe_next;
                                    loop {
                                        if ctl.is_null() {
                                            current_block = 10995941774957397090;
                                            break;
                                        }
                                        if (*ctl).stcb != (*control).stcb
                                            && (*ctl).length != 0
                                            && ((*ctl).some_taken as libc::c_int != 0
                                                || (*ctl).spec_flags as libc::c_int & 0x100i32 != 0
                                                || (*ctl).do_not_ref_stcb as libc::c_int == 0i32
                                                    && (*(*(*ctl).stcb)
                                                        .asoc
                                                        .strmin
                                                        .offset((*ctl).sinfo_stream as isize))
                                                    .delivery_started
                                                        as libc::c_int
                                                        == 0i32)
                                        {
                                            /*-
                                             * If we have a different TCB next, and there is data
                                             * present. If we have already taken some (pdapi), OR we can
                                             * ref the tcb and no delivery as started on this stream, we
                                             * take it. Note we allow a notification on a different
                                             * assoc to be delivered..
                                             */
                                            control = ctl;
                                            current_block = 1694039017486245274;
                                            break;
                                        } else if (*inp).sctp_features & 0x10u64 == 0x10u64
                                            && (*ctl).length != 0
                                            && ((*ctl).some_taken as libc::c_int != 0
                                                || (*ctl).do_not_ref_stcb as libc::c_int == 0i32
                                                    && (*ctl).spec_flags as libc::c_int & 0x100i32
                                                        == 0i32
                                                    && (*(*(*ctl).stcb)
                                                        .asoc
                                                        .strmin
                                                        .offset((*ctl).sinfo_stream as isize))
                                                    .delivery_started
                                                        as libc::c_int
                                                        == 0i32)
                                        {
                                            /*-
                                             * If we have the same tcb, and there is data present, and we
                                             * have the strm interleave feature present. Then if we have
                                             * taken some (pdapi) or we can refer to tht tcb AND we have
                                             * not started a delivery for this stream, we can take it.
                                             * Note we do NOT allow a notificaiton on the same assoc to
                                             * be delivered.
                                             */
                                            control = ctl;
                                            current_block = 1694039017486245274;
                                            break;
                                        } else {
                                            ctl = (*ctl).next.tqe_next
                                        }
                                    }
                                } else {
                                    current_block = 10995941774957397090;
                                }
                                match current_block {
                                    1694039017486245274 => {}
                                    _ => {
                                        /*
                                         * if we reach here, not suitable replacement is available
                                         * <or> fragment interleave is NOT on. So stuff the sb_cc
                                         * into the our held count, and its time to sleep again.
                                         */
                                        held_length = (*so).so_rcv.sb_cc;
                                        (*control).held_length = (*so).so_rcv.sb_cc;
                                        current_block = 9906378635038024695;
                                        continue;
                                    }
                                }
                            } else {
                                /* Clear the held length since there is something to read */
                                (*control).held_length = 0u32
                            }
                            /*
                             * If we reach here, control has a some data for us to read off.
                             * Note that stcb COULD be NULL.
                             */
                            if hold_rlock == 0i32 {
                                hold_rlock = 1i32;
                                pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                            }
                            (*control).some_taken = (*control).some_taken.wrapping_add(1);
                            stcb = (*control).stcb;
                            if !stcb.is_null() {
                                if (*control).do_not_ref_stcb as libc::c_int == 0i32
                                    && (*stcb).asoc.state & 0x200i32 != 0
                                {
                                    if freecnt_applied == 0i32 {
                                        stcb = 0 as *mut sctp_tcb
                                    }
                                } else if (*control).do_not_ref_stcb as libc::c_int == 0i32 {
                                    /* you can't free it on me please */
                                    /*
                                     * The lock on the socket buffer protects us so the
                                     * free code will stop. But since we used the socketbuf
                                     * lock and the sender uses the tcb_lock to increment,
                                     * we need to use the atomic add to the refcnt
                                     */
                                    if freecnt_applied != 0 {
                                        if system_base_info.debug_printf.is_some() {
                                            system_base_info
                                                .debug_printf
                                                .expect("non-null function pointer")(
                                                b"refcnt already incremented?\n\x00" as *const u8
                                                    as *const libc::c_char,
                                            );
                                        }
                                    } else {
                                        ::std::intrinsics::atomic_xadd(
                                            &mut (*stcb).asoc.refcnt,
                                            1u32,
                                        );
                                        freecnt_applied = 1i32
                                    }
                                    /*
                                     * Setup to remember how much we have not yet told
                                     * the peer our rwnd has opened up. Note we grab
                                     * the value from the tcb from last time.
                                     * Note too that sack sending clears this when a sack
                                     * is sent, which is fine. Once we hit the rwnd_req,
                                     * we then will go to the sctp_user_rcvd() that will
                                     * not lock until it KNOWs it MUST send a WUP-SACK.
                                     */
                                    freed_so_far = (*stcb).freed_by_sorcv_sincelast;
                                    (*stcb).freed_by_sorcv_sincelast = 0u32
                                }
                            }
                            if !stcb.is_null()
                                && (*control).spec_flags as libc::c_int & 0x100i32 == 0i32
                                && (*control).do_not_ref_stcb as libc::c_int == 0i32
                            {
                                (*(*stcb).asoc.strmin.offset((*control).sinfo_stream as isize))
                                    .delivery_started = 1u8
                            }
                            /* First lets get off the sinfo and sockaddr info */
                            if !sinfo.is_null() && filling_sinfo != 0i32 {
                                let mut nxt = 0 as *mut sctp_queued_to_read;
                                (*sinfo).sinfo_stream = (*control).sinfo_stream;
                                (*sinfo).sinfo_ssn = (*control).mid as uint16_t;
                                (*sinfo).sinfo_flags = (*control).sinfo_flags;
                                (*sinfo).sinfo_ppid = (*control).sinfo_ppid;
                                (*sinfo).sinfo_context = (*control).sinfo_context;
                                (*sinfo).sinfo_timetolive = (*control).sinfo_timetolive;
                                (*sinfo).sinfo_tsn = (*control).sinfo_tsn;
                                (*sinfo).sinfo_cumtsn = (*control).sinfo_cumtsn;
                                (*sinfo).sinfo_assoc_id = (*control).sinfo_assoc_id;
                                nxt = (*control).next.tqe_next;
                                if (*inp).sctp_features & 0x2u64 == 0x2u64
                                    || (*inp).sctp_features & 0x10000000u64 == 0x10000000u64
                                {
                                    let mut s_extra = 0 as *mut sctp_extrcvinfo;
                                    s_extra = sinfo as *mut sctp_extrcvinfo;
                                    if !nxt.is_null() && (*nxt).length != 0 {
                                        (*s_extra).serinfo_next_flags = 0x1u16;
                                        if (*nxt).sinfo_flags as libc::c_int & 0x400i32 != 0 {
                                            (*s_extra).serinfo_next_flags =
                                                ((*s_extra).serinfo_next_flags as libc::c_int
                                                    | 0x4i32)
                                                    as uint16_t
                                        }
                                        if (*nxt).spec_flags as libc::c_int & 0x100i32 != 0 {
                                            (*s_extra).serinfo_next_flags =
                                                ((*s_extra).serinfo_next_flags as libc::c_int
                                                    | 0x8i32)
                                                    as uint16_t
                                        }
                                        (*s_extra).serinfo_next_aid = (*nxt).sinfo_assoc_id;
                                        (*s_extra).serinfo_next_length = (*nxt).length;
                                        (*s_extra).serinfo_next_ppid = (*nxt).sinfo_ppid;
                                        (*s_extra).serinfo_next_stream = (*nxt).sinfo_stream;
                                        if !(*nxt).tail_mbuf.is_null() {
                                            if (*nxt).end_added != 0 {
                                                (*s_extra).serinfo_next_flags =
                                                    ((*s_extra).serinfo_next_flags as libc::c_int
                                                        | 0x2i32)
                                                        as uint16_t
                                            }
                                        }
                                    } else {
                                        /* we explicitly 0 this, since the memcpy got
                                         * some other things beyond the older sinfo_
                                         * that is on the control's structure :-D
                                         */
                                        nxt = 0 as *mut sctp_queued_to_read;
                                        (*s_extra).serinfo_next_flags = 0u16;
                                        (*s_extra).serinfo_next_aid = 0u32;
                                        (*s_extra).serinfo_next_length = 0u32;
                                        (*s_extra).serinfo_next_ppid = 0u32;
                                        (*s_extra).serinfo_next_stream = 0u16
                                    }
                                }
                                /*
                                 * update off the real current cum-ack, if we have an stcb.
                                 */
                                if (*control).do_not_ref_stcb as libc::c_int == 0i32
                                    && !stcb.is_null()
                                {
                                    (*sinfo).sinfo_cumtsn = (*stcb).asoc.cumulative_tsn
                                }
                                /*
                                 * mask off the high bits, we keep the actual chunk bits in
                                 * there.
                                 */
                                (*sinfo).sinfo_flags =
                                    ((*sinfo).sinfo_flags as libc::c_int & 0xffi32) as uint16_t;
                                if (*control).sinfo_flags as libc::c_int >> 8i32 & 0x4i32 != 0 {
                                    (*sinfo).sinfo_flags =
                                        ((*sinfo).sinfo_flags as libc::c_int | 0x400i32) as uint16_t
                                }
                            }
                            if fromlen > 0i32 && !from.is_null() {
                                let mut store = sctp_sockstore {
                                    sin: sockaddr_in {
                                        sin_family: 0,
                                        sin_port: 0,
                                        sin_addr: in_addr { s_addr: 0 },
                                        sin_zero: [0; 8],
                                    },
                                };
                                let mut len = 0;
                                match (*(*control).whoFrom).ro._l_addr.sa.sa_family as libc::c_int {
                                    10 => {
                                        len =
                                            ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong;
                                        store.sin6 = (*(*control).whoFrom).ro._l_addr.sin6;
                                        store.sin6.sin6_port = (*control).port_from
                                    }
                                    2 => {
                                        if (*inp).sctp_features & 0x800000u64 == 0x800000u64 {
                                            len = ::std::mem::size_of::<sockaddr_in6>()
                                                as libc::c_ulong;
                                            in6_sin_2_v4mapsin6(
                                                &mut (*(*control).whoFrom).ro._l_addr.sin,
                                                &mut store.sin6,
                                            );
                                            store.sin6.sin6_port = (*control).port_from
                                        } else {
                                            len = ::std::mem::size_of::<sockaddr_in>()
                                                as libc::c_ulong;
                                            store.sin = (*(*control).whoFrom).ro._l_addr.sin;
                                            store.sin.sin_port = (*control).port_from
                                        }
                                    }
                                    123 => {
                                        len =
                                            ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong;
                                        store.sconn = (*(*control).whoFrom).ro._l_addr.sconn;
                                        store.sconn.sconn_port = (*control).port_from
                                    }
                                    _ => len = 0u64,
                                }
                                memcpy(
                                    from as *mut libc::c_void,
                                    &mut store as *mut sctp_sockstore as *const libc::c_void,
                                    if fromlen as size_t > len {
                                        len
                                    } else {
                                        fromlen as size_t
                                    },
                                );
                            }
                            if hold_rlock != 0 {
                                pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                                hold_rlock = 0i32
                            }
                            if hold_sblock != 0 {
                                pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
                                hold_sblock = 0i32
                            }
                            /* now copy out what data we can */
                            if mp.is_null() {
                                current_block = 12101113700462072058;
                            } else {
                                /*-
                                 * Give caller back the mbuf chain,
                                 * store in uio_resid the length
                                 */
                                wakeup_read_socket = 0i32;
                                if (*control).end_added as libc::c_int == 0i32
                                    || (*control).next.tqe_next.is_null()
                                {
                                    /* Need to get rlock */
                                    if hold_rlock == 0i32 {
                                        pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                                        hold_rlock = 1i32
                                    }
                                }
                                if (*control).end_added != 0 {
                                    out_flags |= MSG_EOR as libc::c_int;
                                    if (*control).do_not_ref_stcb as libc::c_int == 0i32
                                        && !(*control).stcb.is_null()
                                        && (*control).spec_flags as libc::c_int & 0x100i32 == 0i32
                                    {
                                        (*(*(*control).stcb)
                                            .asoc
                                            .strmin
                                            .offset((*control).sinfo_stream as isize))
                                        .delivery_started = 0u8
                                    }
                                }
                                if (*control).spec_flags as libc::c_int & 0x100i32 != 0 {
                                    out_flags |= 0x2000i32
                                }
                                (*uio).uio_resid = (*control).length as ssize_t;
                                *mp = (*control).data;
                                m = (*control).data;
                                while !m.is_null() {
                                    let mut oldval_3 = 0;
                                    let mut oldval_4 = 0;
                                    if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32
                                        != 0
                                    {
                                        sctp_sblog(
                                            &mut (*so).so_rcv,
                                            if (*control).do_not_ref_stcb as libc::c_int != 0 {
                                                0 as *mut sctp_tcb
                                            } else {
                                                stcb
                                            },
                                            54i32,
                                            (*m).m_hdr.mh_len,
                                        );
                                    }

                                    oldval_3 = ::std::intrinsics::atomic_xadd(
                                        &mut (*so).so_rcv.sb_cc,
                                        -(*m).m_hdr.mh_len as u_int,
                                    ) as int32_t;
                                    if oldval_3 < (*m).m_hdr.mh_len {
                                        (*so).so_rcv.sb_cc = 0u32
                                    }

                                    oldval_4 = ::std::intrinsics::atomic_xadd(
                                        &mut (*so).so_rcv.sb_mbcnt,
                                        -(256i32) as u_int,
                                    ) as int32_t;
                                    if oldval_4 < 256i32 {
                                        (*so).so_rcv.sb_mbcnt = 0u32
                                    }
                                    if (*control).do_not_ref_stcb as libc::c_int == 0i32
                                        && !stcb.is_null()
                                    {
                                        let mut oldval_5 = 0;
                                        let mut oldval_6 = 0;
                                        oldval_5 = ::std::intrinsics::atomic_xadd(
                                            &mut (*stcb).asoc.sb_cc,
                                            -(*m).m_hdr.mh_len as uint32_t,
                                        )
                                            as int32_t;
                                        if oldval_5 < (*m).m_hdr.mh_len {
                                            (*stcb).asoc.sb_cc = 0u32
                                        }

                                        oldval_6 = ::std::intrinsics::atomic_xadd(
                                            &mut (*stcb).asoc.my_rwnd_control_len,
                                            -(256i32) as uint32_t,
                                        )
                                            as int32_t;
                                        if oldval_6 < 256i32 {
                                            (*stcb).asoc.my_rwnd_control_len = 0u32
                                        }
                                    }
                                    freed_so_far =
                                        (freed_so_far).wrapping_add((*m).m_hdr.mh_len as uint32_t);
                                    freed_so_far = (freed_so_far).wrapping_add(256u32);
                                    if system_base_info.sctpsysctl.sctp_logging_level & 0x10000u32
                                        != 0
                                    {
                                        sctp_sblog(
                                            &mut (*so).so_rcv,
                                            if (*control).do_not_ref_stcb as libc::c_int != 0 {
                                                0 as *mut sctp_tcb
                                            } else {
                                                stcb
                                            },
                                            55i32,
                                            0i32,
                                        );
                                    }
                                    m = (*m).m_hdr.mh_next
                                }
                                (*control).tail_mbuf = 0 as *mut mbuf;
                                (*control).data = (*control).tail_mbuf;
                                (*control).length = 0u32;
                                if out_flags & MSG_EOR as libc::c_int != 0 {
                                    current_block = 5364280785746004627;
                                } else {
                                    current_block = 17161112121298601216;
                                }
                            }
                            'c_12523: loop {
                                let mut copied_so_far = 0i64;
                                match current_block {
                                    17161112121298601216 =>
                                    /* error we are out of here */
                                    {
                                        if hold_rlock == 1i32 {
                                            pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                                            hold_rlock = 0i32
                                        }
                                        break;
                                    }
                                    12101113700462072058 =>
                                    /* copy out each mbuf in the chain up to length */
                                    {
                                        m = (*control).data; /* end while(m) */
                                        while !m.is_null() {
                                            let mut my_len = 0i64;
                                            let mut cp_len = 0i64;
                                            cp_len = (*uio).uio_resid;
                                            my_len = (*m).m_hdr.mh_len as ssize_t;
                                            if cp_len > my_len {
                                                /* not enough in this buf */
                                                cp_len = my_len
                                            }
                                            if hold_rlock != 0 {
                                                pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                                                hold_rlock = 0i32
                                            }
                                            if cp_len > 0i64 {
                                                error = uiomove(
                                                    (*m).m_hdr.mh_data as *mut libc::c_void,
                                                    cp_len as libc::c_int,
                                                    uio,
                                                )
                                            }
                                            /* re-read */
                                            if (*inp).sctp_flags & 0x10000000u32 != 0 {
                                                current_block = 17161112121298601216;
                                                continue 'c_12523;
                                            }
                                            if (*control).do_not_ref_stcb as libc::c_int == 0i32
                                                && !stcb.is_null()
                                                && (*stcb).asoc.state & 0x200i32 != 0
                                            {
                                                no_rcv_needed = 1i32
                                            }
                                            if error != 0 {
                                                current_block = 17161112121298601216;
                                                continue 'c_12523;
                                            }
                                            pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                                            hold_rlock = 1i32;
                                            if cp_len == (*m).m_hdr.mh_len as libc::c_long {
                                                if (*m).m_hdr.mh_next.is_null()
                                                    && (*control).end_added as libc::c_int != 0
                                                {
                                                    out_flags |= MSG_EOR as libc::c_int;
                                                    if (*control).do_not_ref_stcb as libc::c_int
                                                        == 0i32
                                                        && !(*control).stcb.is_null()
                                                        && (*control).spec_flags as libc::c_int
                                                            & 0x100i32
                                                            == 0i32
                                                    {
                                                        (*(*(*control).stcb).asoc.strmin.offset(
                                                            (*control).sinfo_stream as isize,
                                                        ))
                                                        .delivery_started = 0u8
                                                    }
                                                }
                                                if (*control).spec_flags as libc::c_int & 0x100i32
                                                    != 0
                                                {
                                                    out_flags |= 0x2000i32
                                                }
                                                /* we ate up the mbuf */
                                                if in_flags & MSG_PEEK as libc::c_int != 0 {
                                                    /* just looking */
                                                    m = (*m).m_hdr.mh_next;
                                                    copied_so_far += cp_len
                                                } else {
                                                    let mut oldval = 0;
                                                    let mut oldval_0 = 0;
                                                    if system_base_info
                                                        .sctpsysctl
                                                        .sctp_logging_level
                                                        & 0x10000u32
                                                        != 0
                                                    {
                                                        sctp_sblog(
                                                            &mut (*so).so_rcv,
                                                            if (*control).do_not_ref_stcb
                                                                as libc::c_int
                                                                != 0
                                                            {
                                                                0 as *mut sctp_tcb
                                                            } else {
                                                                stcb
                                                            },
                                                            54i32,
                                                            (*m).m_hdr.mh_len,
                                                        );
                                                    }

                                                    oldval = ::std::intrinsics::atomic_xadd(
                                                        &mut (*so).so_rcv.sb_cc,
                                                        -(*m).m_hdr.mh_len as u_int,
                                                    )
                                                        as int32_t;
                                                    if oldval < (*m).m_hdr.mh_len {
                                                        (*so).so_rcv.sb_cc = 0u32
                                                    }

                                                    oldval_0 = ::std::intrinsics::atomic_xadd(
                                                        &mut (*so).so_rcv.sb_mbcnt,
                                                        -(256i32) as u_int,
                                                    )
                                                        as int32_t;
                                                    if oldval_0 < 256i32 {
                                                        (*so).so_rcv.sb_mbcnt = 0u32
                                                    }
                                                    if (*control).do_not_ref_stcb as libc::c_int
                                                        == 0i32
                                                        && !stcb.is_null()
                                                    {
                                                        let mut oldval_1 = 0;
                                                        let mut oldval_2 = 0;
                                                        oldval_1 = ::std::intrinsics::atomic_xadd(
                                                            &mut (*stcb).asoc.sb_cc,
                                                            -(*m).m_hdr.mh_len as uint32_t,
                                                        )
                                                            as int32_t;
                                                        if oldval_1 < (*m).m_hdr.mh_len {
                                                            (*stcb).asoc.sb_cc = 0u32
                                                        }

                                                        oldval_2 = ::std::intrinsics::atomic_xadd(
                                                            &mut (*stcb).asoc.my_rwnd_control_len,
                                                            -(256i32) as uint32_t,
                                                        )
                                                            as int32_t;
                                                        if oldval_2 < 256i32 {
                                                            (*stcb).asoc.my_rwnd_control_len = 0u32
                                                        }
                                                    }
                                                    if system_base_info
                                                        .sctpsysctl
                                                        .sctp_logging_level
                                                        & 0x10000u32
                                                        != 0
                                                    {
                                                        sctp_sblog(
                                                            &mut (*so).so_rcv,
                                                            if (*control).do_not_ref_stcb
                                                                as libc::c_int
                                                                != 0
                                                            {
                                                                0 as *mut sctp_tcb
                                                            } else {
                                                                stcb
                                                            },
                                                            55i32,
                                                            0i32,
                                                        );
                                                    }
                                                    copied_so_far += cp_len;
                                                    freed_so_far = (freed_so_far)
                                                        .wrapping_add(cp_len as uint32_t);
                                                    freed_so_far =
                                                        (freed_so_far).wrapping_add(256u32);
                                                    ::std::intrinsics::atomic_xsub(
                                                        &mut (*control).length,
                                                        cp_len as uint32_t,
                                                    );
                                                    (*control).data = m_free(m);
                                                    m = (*control).data;
                                                    /* been through it all, must hold sb lock ok to null tail */
                                                    if (*control).data.is_null() {
                                                        (*control).tail_mbuf = 0 as *mut mbuf
                                                    }
                                                }
                                            } else {
                                                /* Do we need to trim the mbuf? */
                                                if (*control).spec_flags as libc::c_int & 0x100i32
                                                    != 0
                                                {
                                                    out_flags |= 0x2000i32
                                                }
                                                if in_flags & MSG_PEEK as libc::c_int == 0i32 {
                                                    (*m).m_hdr.mh_data =
                                                        (*m).m_hdr.mh_data.offset(cp_len as isize);
                                                    (*m).m_hdr.mh_len -= cp_len as libc::c_int;
                                                    if system_base_info
                                                        .sctpsysctl
                                                        .sctp_logging_level
                                                        & 0x10000u32
                                                        != 0
                                                    {
                                                        sctp_sblog(
                                                            &mut (*so).so_rcv,
                                                            if (*control).do_not_ref_stcb
                                                                as libc::c_int
                                                                != 0
                                                            {
                                                                0 as *mut sctp_tcb
                                                            } else {
                                                                stcb
                                                            },
                                                            54i32,
                                                            cp_len as libc::c_int,
                                                        );
                                                    }
                                                    ::std::intrinsics::atomic_xsub(
                                                        &mut (*so).so_rcv.sb_cc,
                                                        cp_len as u_int,
                                                    );
                                                    if (*control).do_not_ref_stcb as libc::c_int
                                                        == 0i32
                                                        && !stcb.is_null()
                                                    {
                                                        ::std::intrinsics::atomic_xsub(
                                                            &mut (*stcb).asoc.sb_cc,
                                                            cp_len as uint32_t,
                                                        );
                                                    }
                                                    copied_so_far += cp_len;
                                                    freed_so_far = (freed_so_far)
                                                        .wrapping_add(cp_len as uint32_t);
                                                    freed_so_far =
                                                        (freed_so_far).wrapping_add(256u32);
                                                    if system_base_info
                                                        .sctpsysctl
                                                        .sctp_logging_level
                                                        & 0x10000u32
                                                        != 0
                                                    {
                                                        sctp_sblog(
                                                            &mut (*so).so_rcv,
                                                            if (*control).do_not_ref_stcb
                                                                as libc::c_int
                                                                != 0
                                                            {
                                                                0 as *mut sctp_tcb
                                                            } else {
                                                                stcb
                                                            },
                                                            55i32,
                                                            0i32,
                                                        );
                                                    }
                                                    ::std::intrinsics::atomic_xsub(
                                                        &mut (*control).length,
                                                        cp_len as uint32_t,
                                                    );
                                                } else {
                                                    copied_so_far += cp_len
                                                }
                                            }
                                            if out_flags & MSG_EOR as libc::c_int != 0
                                                || (*uio).uio_resid == 0i64
                                            {
                                                break;
                                            }
                                            if !stcb.is_null()
                                                && in_flags & MSG_PEEK as libc::c_int == 0i32
                                                && (*control).do_not_ref_stcb as libc::c_int == 0i32
                                                && freed_so_far >= rwnd_req
                                            {
                                                sctp_user_rcvd(
                                                    stcb,
                                                    &mut freed_so_far,
                                                    hold_rlock,
                                                    rwnd_req,
                                                );
                                            }
                                        }
                                        /*
                                         * At this point we have looked at it all and we either have
                                         * a MSG_EOR/or read all the user wants... <OR>
                                         * control->length == 0.
                                         */
                                        if out_flags & MSG_EOR as libc::c_int != 0
                                            && in_flags & MSG_PEEK as libc::c_int == 0i32
                                        {
                                            /* we are done with this control */
                                            if (*control).length == 0u32 {
                                                if !(*control).data.is_null() {
                                                    if system_base_info.debug_printf.is_some() {
                                                        system_base_info.debug_printf.expect("non-null function pointer")(b"Strange, data left in the control buffer .. invarients would panic?\n\x00"
                                                                                                                                      as
                                                                                                                                      *const u8
                                                                                                                                      as
                                                                                                                                      *const libc::c_char);
                                                    }
                                                    m_freem((*control).data);
                                                    (*control).data = 0 as *mut mbuf
                                                }
                                                current_block = 5364280785746004627;
                                                continue;
                                            } else {
                                                /*
                                                 * The user did not read all of this
                                                 * message, turn off the returned MSG_EOR
                                                 * since we are leaving more behind on the
                                                 * control to read.
                                                 */
                                                no_rcv_needed =
                                                    (*control).do_not_ref_stcb as libc::c_int;
                                                out_flags &= !(MSG_EOR as libc::c_int)
                                            }
                                        }
                                    }
                                    _ =>
                                    /* Done with this control */
                                    {
                                        if hold_rlock == 0i32 {
                                            pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                                            hold_rlock = 1i32
                                        }
                                        if !(*control).next.tqe_next.is_null() {
                                            (*(*control).next.tqe_next).next.tqe_prev =
                                                (*control).next.tqe_prev
                                        } else {
                                            (*inp).read_queue.tqh_last = (*control).next.tqe_prev
                                        }
                                        *(*control).next.tqe_prev = (*control).next.tqe_next;
                                        /* Add back any hiddend data */
                                        if (*control).held_length != 0 {
                                            held_length = 0u32;
                                            (*control).held_length = 0u32;
                                            wakeup_read_socket = 1i32
                                        }
                                        if !(*control).aux_data.is_null() {
                                            m_free((*control).aux_data);
                                            (*control).aux_data = 0 as *mut mbuf
                                        }
                                        no_rcv_needed = (*control).do_not_ref_stcb as libc::c_int;
                                        if !(*control).whoFrom.is_null() {
                                            if ::std::intrinsics::atomic_xadd(
                                                &mut (*(*control).whoFrom).ref_count
                                                    as *mut libc::c_int,
                                                -(1i32),
                                            ) == 1i32
                                            {
                                                sctp_os_timer_stop(
                                                    &mut (*(*control).whoFrom).rxt_timer.timer,
                                                );
                                                sctp_os_timer_stop(
                                                    &mut (*(*control).whoFrom).pmtu_timer.timer,
                                                );
                                                sctp_os_timer_stop(
                                                    &mut (*(*control).whoFrom).hb_timer.timer,
                                                );
                                                if !(*(*control).whoFrom).ro.ro_rt.is_null() {
                                                    if (*(*(*control).whoFrom).ro.ro_rt).rt_refcnt
                                                        <= 1i64
                                                    {
                                                        sctp_userspace_rtfree(
                                                            (*(*control).whoFrom).ro.ro_rt,
                                                        );
                                                    } else {
                                                        (*(*(*control).whoFrom).ro.ro_rt)
                                                            .rt_refcnt -= 1
                                                    }
                                                    (*(*control).whoFrom).ro.ro_rt =
                                                        0 as *mut sctp_rtentry_t;
                                                    (*(*control).whoFrom).ro.ro_rt =
                                                        0 as *mut sctp_rtentry_t
                                                }
                                                if (*(*control).whoFrom).src_addr_selected != 0 {
                                                    sctp_free_ifa((*(*control).whoFrom).ro._s_addr);
                                                    (*(*control).whoFrom).ro._s_addr =
                                                        0 as *mut sctp_ifa
                                                }
                                                (*(*control).whoFrom).src_addr_selected = 0u8;
                                                (*(*control).whoFrom).dest_state =
                                                    ((*(*control).whoFrom).dest_state
                                                        as libc::c_int
                                                        & !(0x1i32))
                                                        as uint16_t;
                                                free((*control).whoFrom as *mut libc::c_void);
                                                ::std::intrinsics::atomic_xsub(
                                                    &mut system_base_info
                                                        .sctppcbinfo
                                                        .ipi_count_raddr,
                                                    1u32,
                                                );
                                            }
                                        }
                                        (*control).data = 0 as *mut mbuf;
                                        free(control as *mut libc::c_void);
                                        ::std::intrinsics::atomic_xsub(
                                            &mut system_base_info.sctppcbinfo.ipi_count_readq,
                                            1u32,
                                        );
                                        control = 0 as *mut sctp_queued_to_read;
                                        if freed_so_far >= rwnd_req && no_rcv_needed == 0i32 {
                                            sctp_user_rcvd(
                                                stcb,
                                                &mut freed_so_far,
                                                hold_rlock,
                                                rwnd_req,
                                            );
                                        }
                                    }
                                }
                                if out_flags & MSG_EOR as libc::c_int != 0 {
                                    current_block = 17161112121298601216;
                                    continue;
                                }
                                if (*uio).uio_resid == 0i64
                                    || in_eeor_mode != 0
                                        && copied_so_far
                                            >= (if (*so).so_rcv.sb_lowat > 1i32 {
                                                (*so).so_rcv.sb_lowat
                                            } else {
                                                1i32
                                            })
                                                as libc::c_long
                                {
                                    current_block = 17161112121298601216;
                                    continue;
                                }
                                /*
                                 * If I hit here the receiver wants more and this message is
                                 * NOT done (pd-api). So two questions. Can we block? if not
                                 * we are done. Did the user NOT set MSG_WAITALL?
                                 */
                                if block_allowed == 0i32 {
                                    current_block = 17161112121298601216;
                                    continue;
                                }
                                /*
                                 * We need to wait for more data a few things: - We don't
                                 * sbunlock() so we don't get someone else reading. - We
                                 * must be sure to account for the case where what is added
                                 * is NOT to our control when we wakeup.
                                 */
                                /* Do we need to tell the transport a rwnd update might be
                                 * needed before we go to sleep?
                                 */
                                if !stcb.is_null()
                                    && in_flags & MSG_PEEK as libc::c_int == 0i32
                                    && (freed_so_far >= rwnd_req
                                        && (*control).do_not_ref_stcb as libc::c_int == 0i32
                                        && no_rcv_needed == 0i32)
                                {
                                    sctp_user_rcvd(stcb, &mut freed_so_far, hold_rlock, rwnd_req);
                                }
                                loop {
                                    if (*so).so_state as libc::c_int & 0x20i32 != 0 {
                                        current_block = 17161112121298601216;
                                        continue 'c_12523;
                                    }
                                    if (*inp).sctp_flags & 0x10000000u32 != 0 {
                                        current_block = 17161112121298601216;
                                        continue 'c_12523;
                                    }
                                    if hold_rlock == 1i32 {
                                        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                                        hold_rlock = 0i32
                                    }
                                    if hold_sblock == 0i32 {
                                        pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
                                        hold_sblock = 1i32
                                    }
                                    if copied_so_far != 0
                                        && (*control).length == 0u32
                                        && (*inp).sctp_features & 0x8u64 == 0x8u64
                                    {
                                        current_block = 17161112121298601216;
                                        continue 'c_12523;
                                    }
                                    if (*so).so_rcv.sb_cc <= (*control).held_length {
                                        error = sbwait(&mut (*so).so_rcv);
                                        if error != 0 {
                                            current_block = 3874686694575430777;
                                            continue 'c_10360;
                                        }
                                        (*control).held_length = 0u32
                                    }
                                    if hold_sblock != 0 {
                                        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
                                        hold_sblock = 0i32
                                    }
                                    if (*control).length == 0u32 {
                                        /* still nothing here */
                                        if (*control).end_added as libc::c_int == 1i32 {
                                            /* he aborted, or is done i.e.did a shutdown */
                                            out_flags |= MSG_EOR as libc::c_int;
                                            if (*control).pdapi_aborted != 0 {
                                                if (*control).do_not_ref_stcb as libc::c_int == 0i32
                                                    && (*control).spec_flags as libc::c_int
                                                        & 0x100i32
                                                        == 0i32
                                                {
                                                    (*(*(*control).stcb)
                                                        .asoc
                                                        .strmin
                                                        .offset((*control).sinfo_stream as isize))
                                                    .delivery_started = 0u8
                                                }
                                                out_flags |= MSG_TRUNC as libc::c_int
                                            } else if (*control).do_not_ref_stcb as libc::c_int
                                                == 0i32
                                                && (*control).spec_flags as libc::c_int & 0x100i32
                                                    == 0i32
                                            {
                                                (*(*(*control).stcb)
                                                    .asoc
                                                    .strmin
                                                    .offset((*control).sinfo_stream as isize))
                                                .delivery_started = 0u8
                                            }
                                            current_block = 5364280785746004627;
                                            continue 'c_12523;
                                        } else if (*so).so_rcv.sb_cc > held_length {
                                            (*control).held_length = (*so).so_rcv.sb_cc;
                                            held_length = 0u32
                                        }
                                    } else {
                                        if !(*control).data.is_null() {
                                            current_block = 12101113700462072058;
                                            continue 'c_12523;
                                        }
                                        /* we must re-sync since data
                                         * is probably being added
                                         */
                                        pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
                                        if (*control).length > 0u32 && (*control).data.is_null() {
                                            current_block = 9822782070371558002;
                                            break;
                                        } else {
                                            current_block = 14190623614922940378;
                                            break;
                                        }
                                        /* We will fall around to get more data */
                                    }
                                }
                                match current_block {
                                    14190623614922940378 => {
                                        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                                        current_block = 12101113700462072058;
                                    }
                                    _ => {
                                        /* big trouble.. we have the lock and its corrupt? */
                                        out_flags |= MSG_EOR as libc::c_int;
                                        out_flags |= MSG_TRUNC as libc::c_int;
                                        (*control).length = 0u32;
                                        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
                                        current_block = 5364280785746004627;
                                    }
                                }
                            }
                            if hold_sblock == 0i32 {
                                pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
                                hold_sblock = 1i32
                            }
                            current_block = 3874686694575430777;
                        }
                    }
                }
            }
        }
    }
    if !msg_flags.is_null() {
        *msg_flags = out_flags
    }
    if out_flags & MSG_EOR as libc::c_int == 0i32
        && in_flags & MSG_PEEK as libc::c_int == 0i32
        && !sinfo.is_null()
        && ((*inp).sctp_features & 0x2u64 == 0x2u64
            || (*inp).sctp_features & 0x10000000u64 == 0x10000000u64)
    {
        let mut s_extra_0 = 0 as *mut sctp_extrcvinfo;
        s_extra_0 = sinfo as *mut sctp_extrcvinfo;
        (*s_extra_0).serinfo_next_flags = 0u16
    }
    if hold_rlock == 1i32 {
        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
    }
    if hold_sblock != 0 {
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    }
    if freecnt_applied != 0 {
        /*
         * The lock on the socket buffer protects us so the free
         * code will stop. But since we used the socketbuf lock and
         * the sender uses the tcb_lock to increment, we need to use
         * the atomic add to the refcnt.
         */
        if stcb.is_null() {
            current_block = 16896850163988546332;
        } else {
            /* Save the value back for next time */
            (*stcb).freed_by_sorcv_sincelast = freed_so_far;
            ::std::intrinsics::atomic_xadd(&mut (*stcb).asoc.refcnt, -(1i32) as uint32_t);
            current_block = 4719814514880867531;
        }
    } else {
        current_block = 4719814514880867531;
    }
    match current_block {
        4719814514880867531 => {
            if system_base_info.sctpsysctl.sctp_logging_level & 0x1000u32 != 0 {
                if !stcb.is_null() {
                    sctp_misc_ints(
                        86u8,
                        freed_so_far,
                        if !uio.is_null() {
                            (slen) - (*uio).uio_resid
                        } else {
                            slen
                        } as uint32_t,
                        (*stcb).asoc.my_rwnd,
                        (*so).so_rcv.sb_cc,
                    );
                } else {
                    sctp_misc_ints(
                        86u8,
                        freed_so_far,
                        if !uio.is_null() {
                            (slen) - (*uio).uio_resid
                        } else {
                            slen
                        } as uint32_t,
                        0u32,
                        (*so).so_rcv.sb_cc,
                    );
                }
            }
        }
        _ => {}
    }
    if wakeup_read_socket != 0 {
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
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_dynamic_set_primary(
    mut sa: *mut sockaddr,
    mut vrf_id: uint32_t,
) -> libc::c_int {
    let mut ifa = 0 as *mut sctp_ifa;
    let mut wi = 0 as *mut sctp_laddr;
    ifa = sctp_find_ifa_by_addr(sa, vrf_id, 0i32);
    if ifa.is_null() {
        return 99i32;
    }
    /* Now that we have the ifa we must awaken the
     * iterator with this message.
     */
    wi = malloc(system_base_info.sctppcbinfo.ipi_zone_laddr) as *mut sctp_laddr;
    if wi.is_null() {
        return 12i32;
    }
    /* Now incr the count and int wi structure */
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
    memset(
        wi as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_laddr>() as libc::c_ulong,
    );
    gettimeofday(&mut (*wi).start_time, 0 as *mut timezone);
    (*wi).ifa = ifa;
    (*wi).action = 0xc004u32;
    ::std::intrinsics::atomic_xadd(&mut (*ifa).refcount, 1u32);
    /* Now add it to the work queue */
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
    return 0i32;
}
/* no sctp_soreceive for __Userspace__ now */
/*  __Userspace__ ifdef above sctp_soreceive */
/*
 * __Userspace__ Defining sctp_hashinit_flags() and sctp_hashdestroy() for userland.
 * NOTE: We don't want multiple definitions here. So sctp_hashinit_flags() above for
 *__FreeBSD__ must be excluded.
 *
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_hashinit_flags(
    mut elements: libc::c_int,
    mut type_0: *mut malloc_type,
    mut hashmask: *mut u_long,
    mut flags: libc::c_int,
) -> *mut libc::c_void {
    let mut hashsize = 0;
    let mut hashtbl = 0 as *mut generic;
    let mut i = 0;
    if elements <= 0i32 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"hashinit: bad elements?\x00" as *const u8 as *const libc::c_char,
            );
        }
        elements = 1i32
    }
    hashsize = 1i64;
    while hashsize <= elements as libc::c_long {
        hashsize <<= 1i32
    }
    hashsize >>= 1i32;
    /*cannot use MALLOC here because it has to be declared or defined
    using MALLOC_DECLARE or MALLOC_DEFINE first. */
    if flags & 0x2i32 != 0 {
        hashtbl = malloc(
            (hashsize as u_long).wrapping_mul(::std::mem::size_of::<generic>() as libc::c_ulong),
        ) as *mut generic
    } else if flags & 0x1i32 != 0 {
        hashtbl = malloc(
            (hashsize as u_long).wrapping_mul(::std::mem::size_of::<generic>() as libc::c_ulong),
        ) as *mut generic
    } else {
        return 0 as *mut libc::c_void;
    }
    /* no memory? */
    if hashtbl.is_null() {
        return 0 as *mut libc::c_void;
    }
    i = 0i32;
    while (i as libc::c_long) < hashsize {
        let ref mut fresh13 = (*hashtbl.offset(i as isize)).lh_first;
        *fresh13 = 0 as *mut generic;
        i += 1
    }
    *hashmask = (hashsize - 1i64) as u_long;
    return hashtbl as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_hashdestroy(
    mut vhashtbl: *mut libc::c_void,
    mut type_0: *mut malloc_type,
    mut hashmask: u_long,
) {
    let mut hashtbl = 0 as *mut generic_0;
    let mut hp = 0 as *mut generic_0;
    hashtbl = vhashtbl as *mut generic_0;
    hp = hashtbl;
    while hp <= &mut *hashtbl.offset(hashmask as isize) as *mut generic_0 {
        if !(*hp).lh_first.is_null() {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"hashdestroy: hash not empty.\n\x00" as *const u8 as *const libc::c_char,
                );
            }
            return;
        }
        hp = hp.offset(1)
    }
    free(hashtbl as *mut libc::c_void);
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
#[no_mangle]
pub unsafe extern "C" fn sctp_hashfreedestroy(
    mut vhashtbl: *mut libc::c_void,
    mut type_0: *mut malloc_type,
    mut hashmask: u_long,
) {
    let mut hashtbl = 0 as *mut generic_1;
    /*, *hp*/
    /*
    LIST_ENTRY(type) *start, *temp;
     */
    hashtbl = vhashtbl as *mut generic_1;
    /* Apparently temp is not dynamically allocated, so attempts to
       free it results in error.
    for (hp = hashtbl; hp <= &hashtbl[hashmask]; hp++)
        if (!LIST_EMPTY(hp)) {
            start = LIST_FIRST(hp);
            while (start != NULL) {
                temp = start;
                start = start->le_next;
                SCTP_PRINTF("%s: %p \n", __func__, (void *)temp);
                FREE(temp, type);
            }
        }
     */
    free(hashtbl as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_connectx_helper_add(
    mut stcb: *mut sctp_tcb,
    mut addr: *mut sockaddr,
    mut totaddr: libc::c_int,
    mut error: *mut libc::c_int,
) -> libc::c_int {
    let mut added = 0i32;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut sa = 0 as *mut sockaddr;
    sa = addr;
    inp = (*stcb).sctp_ep;
    *error = 0i32;

    for i in 0i32..totaddr {
        let mut incr = 0u64;
        match (*sa).sa_family as libc::c_int {
            2 => {
                let mut sin = 0 as *mut sockaddr_in;
                incr = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong;
                sin = sa as *mut sockaddr_in;
                if (*sin).sin_addr.s_addr == 0u32
                    || (*sin).sin_addr.s_addr == 0xffffffffu32
                    || ntohl((*sin).sin_addr.s_addr) & 0xf0000000u32 == 0xe0000000u32
                {
                    sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0x7i32);
                    *error = 22i32;
                    break;
                } else if sctp_add_remote_addr(
                    stcb,
                    sa,
                    0 as *mut *mut sctp_nets,
                    (*stcb).asoc.port,
                    0i32,
                    8i32,
                ) != 0
                {
                    /* assoc gone no un-lock */
                    sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0x8i32);
                    *error = 105i32;
                    break;
                } else {
                    added += 1
                }
            }
            10 => {
                let mut sin6 = 0 as *mut sockaddr_in6;
                incr = ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong;
                sin6 = sa as *mut sockaddr_in6;
                if ({
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
                    sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0x9i32);
                    *error = 22i32;
                    break;
                } else if sctp_add_remote_addr(
                    stcb,
                    sa,
                    0 as *mut *mut sctp_nets,
                    (*stcb).asoc.port,
                    0i32,
                    8i32,
                ) != 0
                {
                    /* assoc gone no un-lock */
                    sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0xai32);
                    *error = 105i32;
                    break;
                } else {
                    added += 1
                }
            }
            123 => {
                incr = ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong;
                if sctp_add_remote_addr(
                    stcb,
                    sa,
                    0 as *mut *mut sctp_nets,
                    (*stcb).asoc.port,
                    0i32,
                    8i32,
                ) != 0
                {
                    /* assoc gone no un-lock */
                    sctp_free_assoc(inp, stcb, 0i32, 0x60000000i32 + 0xbi32);
                    *error = 105i32;
                    break;
                } else {
                    added += 1
                }
            }
            _ => {}
        }

        sa = (sa as caddr_t).offset(incr as isize) as *mut sockaddr;
    }
    return added;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_connectx_helper_find(
    mut inp: *mut sctp_inpcb,
    mut addr: *mut sockaddr,
    mut totaddr: libc::c_uint,
    mut num_v4: *mut libc::c_uint,
    mut num_v6: *mut libc::c_uint,
    mut limit: libc::c_uint,
) -> libc::c_int {
    let mut sa = 0 as *mut sockaddr;
    let mut at = 0;
    let mut i = 0;
    at = 0u32;
    sa = addr;
    *num_v4 = 0u32;
    *num_v6 = *num_v4;
    /* account and validate addresses */
    if totaddr == 0u32 {
        return 22i32;
    }
    i = 0u32;
    while i < totaddr {
        let mut stcb = 0 as *mut sctp_tcb;
        let mut incr = 0;
        if (at as libc::c_ulong).wrapping_add(::std::mem::size_of::<sockaddr>() as libc::c_ulong)
            > limit as libc::c_ulong
        {
            return 22i32;
        }
        match (*sa).sa_family as libc::c_int {
            2 => {
                incr = ::std::mem::size_of::<sockaddr_in>() as libc::c_uint;
                *num_v4 = (*num_v4).wrapping_add(1u32)
            }
            10 => {
                let mut sin6 = 0 as *mut sockaddr_in6;
                sin6 = sa as *mut sockaddr_in6;
                if ({
                    let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                        as libc::c_int
                }) != 0
                {
                    /* Must be non-mapped for connectx */
                    return 22i32;
                }
                incr = ::std::mem::size_of::<sockaddr_in6>() as libc::c_uint;
                *num_v6 = (*num_v6).wrapping_add(1u32)
            }
            _ => return 22i32,
        }
        if at.wrapping_add(incr) > limit {
            return 22i32;
        }
        ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
        stcb = sctp_findassociation_ep_addr(
            &mut inp,
            sa,
            0 as *mut *mut sctp_nets,
            0 as *mut sockaddr,
            0 as *mut sctp_tcb,
        );
        if !stcb.is_null() {
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            return 114i32;
        } else {
            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
        }
        at = at.wrapping_add(incr);
        sa = (sa as caddr_t).offset(incr as isize) as *mut sockaddr;
        i = i.wrapping_add(1)
    }
    return 0i32;
}
/*
 * sctp_bindx(ADD) for one address.
 * assumes all arguments are valid/checked by caller.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_bindx_add_address(
    mut so: *mut socket,
    mut inp: *mut sctp_inpcb,
    mut sa: *mut sockaddr,
    mut assoc_id: sctp_assoc_t,
    mut vrf_id: uint32_t,
    mut error: *mut libc::c_int,
    mut p: *mut libc::c_void,
) {
    let mut addr_touse = 0 as *mut sockaddr;
    /* see if we're bound all already! */
    if (*inp).sctp_flags & 0x4u32 != 0 {
        *error = 22i32;
        return;
    }
    addr_touse = sa;
    if (*sa).sa_family as libc::c_int == 10i32 {
        let mut sin6 = 0 as *mut sockaddr_in6;
        if (*inp).sctp_flags & 0x4000000u32 == 0u32 {
            /* can only bind v6 on PF_INET6 sockets */
            *error = 22i32;
            return;
        }
        sin6 = addr_touse as *mut sockaddr_in6;
        if ({
            let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
            ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                as libc::c_int
        }) != 0
        {
            let mut sin = sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            if (*inp).sctp_flags & 0x4000000u32 != 0 && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
            {
                /* can't bind v4-mapped on PF_INET sockets */
                *error = 22i32;
                return;
            }
            in6_sin6_2_sin(&mut sin, sin6);
            addr_touse = &mut sin as *mut sockaddr_in as *mut sockaddr
        }
    }
    if (*sa).sa_family as libc::c_int == 2i32 {
        if (*inp).sctp_flags & 0x4000000u32 != 0 && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0 {
            /* can't bind v4 on PF_INET sockets */
            *error = 22i32;
            return;
        }
    }
    if (*inp).sctp_flags & 0x10u32 != 0 {
        *error = sctp_inpcb_bind(so, addr_touse, 0 as *mut sctp_ifa, p as *mut proc_0);
        return;
    }
    /*
     * No locks required here since bind and mgmt_ep_sa
     * all do their own locking. If we do something for
     * the FIX: below we may need to lock in that case.
     */
    if assoc_id == 0u32 {
        let mut lep = 0 as *mut sctp_inpcb;
        let mut lsin = addr_touse as *mut sockaddr_in;
        /* validate the incoming port */
        if (*lsin).sin_port as libc::c_int != 0i32
            && (*lsin).sin_port as libc::c_int
                != (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport as libc::c_int
        {
            *error = 22i32;
            return;
        } else {
            /* user specified 0 port, set it to existing port */
            (*lsin).sin_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport
        }
        lep = sctp_pcb_findep(addr_touse, 1i32, 0i32, vrf_id);
        if !lep.is_null() {
            /*
             * We must decrement the refcount
             * since we have the ep already and
             * are binding. No remove going on
             * here.
             */
            ::std::intrinsics::atomic_xadd(&mut (*lep).refcount, -(1i32));
        }
        if lep == inp {
            /* already bound to it.. ok */
            return;
        } else {
            if lep.is_null() {
                (*(addr_touse as *mut sockaddr_in)).sin_port = 0u16;
                *error =
                    sctp_addr_mgmt_ep_sa(inp, addr_touse, 0xc001u32, vrf_id, 0 as *mut sctp_ifa)
                        as libc::c_int
            } else {
                *error = 98i32
            }
        }
        if *error != 0 {
            return;
        }
    };
}
/*
 * sctp_bindx(DELETE) for one address.
 * assumes all arguments are valid/checked by caller.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_bindx_delete_address(
    mut inp: *mut sctp_inpcb,
    mut sa: *mut sockaddr,
    mut assoc_id: sctp_assoc_t,
    mut vrf_id: uint32_t,
    mut error: *mut libc::c_int,
) {
    let mut addr_touse = 0 as *mut sockaddr;
    /* see if we're bound all already! */
    if (*inp).sctp_flags & 0x4u32 != 0 {
        *error = 22i32;
        return;
    }
    addr_touse = sa;
    if (*sa).sa_family as libc::c_int == 10i32 {
        let mut sin6 = 0 as *mut sockaddr_in6;
        if (*inp).sctp_flags & 0x4000000u32 == 0u32 {
            /* can only bind v6 on PF_INET6 sockets */
            *error = 22i32;
            return;
        }
        sin6 = addr_touse as *mut sockaddr_in6;
        if ({
            let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
            ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                as libc::c_int
        }) != 0
        {
            let mut sin = sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            if (*inp).sctp_flags & 0x4000000u32 != 0 && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
            {
                /* can't bind mapped-v4 on PF_INET sockets */
                *error = 22i32;
                return;
            }
            in6_sin6_2_sin(&mut sin, sin6);
            addr_touse = &mut sin as *mut sockaddr_in as *mut sockaddr
        }
    }
    if (*sa).sa_family as libc::c_int == 2i32 {
        if (*inp).sctp_flags & 0x4000000u32 != 0 && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0 {
            /* can't bind v4 on PF_INET sockets */
            *error = 22i32;
            return;
        }
    }
    /*
     * No lock required mgmt_ep_sa does its own locking.
     * If the FIX: below is ever changed we may need to
     * lock before calling association level binding.
     */
    if assoc_id == 0u32 {
        /* delete the address */
        *error = sctp_addr_mgmt_ep_sa(inp, addr_touse, 0xc002u32, vrf_id, 0 as *mut sctp_ifa)
            as libc::c_int
    };
}
/*
 * returns the valid local address count for an assoc, taking into account
 * all scoping rules
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_local_addr_count(mut stcb: *mut sctp_tcb) -> libc::c_int {
    let mut loopback_scope = 0;
    let mut ipv4_local_scope = 0;
    let mut ipv4_addr_legal = 0;
    let mut local_scope = 0;
    let mut site_scope = 0;
    let mut ipv6_addr_legal = 0;
    let mut conn_addr_legal = 0;
    let mut vrf = 0 as *mut sctp_vrf;
    let mut count = 0i32;
    /* Turn on all the appropriate scopes */
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
                    if !(sctp_is_addr_restricted(stcb, sctp_ifa) != 0) {
                        let mut current_block_21: u64;
                        match (*sctp_ifa).address.sa.sa_family as libc::c_int {
                            2 => {
                                current_block_21 = 15096969486213676147;
                                match current_block_21 {
                                    17170645623528868489 => {
                                        if conn_addr_legal != 0 {
                                            count += 1
                                        }
                                    }
                                    15096969486213676147 => {
                                        if ipv4_addr_legal != 0 {
                                            let mut sin = 0 as *mut sockaddr_in;
                                            sin = &mut (*sctp_ifa).address.sin;
                                            if !((*sin).sin_addr.s_addr == 0u32) {
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
                                                    /* count this one */
                                                    count += 1
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        if ipv6_addr_legal != 0 {
                                            let mut sin6 = 0 as *mut sockaddr_in6;
                                            sin6 = &mut (*sctp_ifa).address.sin6;
                                            if !(({
                                                let mut __a = &mut (*sin6).sin6_addr
                                                    as *mut in6_addr
                                                    as *const in6_addr;
                                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                                    as libc::c_int
                                            }) != 0)
                                            {
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
                                                        current_block_21 = 12147880666119273379;
                                                    } else {
                                                        current_block_21 = 11743904203796629665;
                                                    }
                                                /* SCTP_EMBEDDED_V6_SCOPE */
                                                } else {
                                                    current_block_21 = 11743904203796629665;
                                                }
                                                match current_block_21 {
                                                    12147880666119273379 => {}
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
                                                            /* count this one */
                                                            count += 1
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            10 => {
                                current_block_21 = 2818805719966761415;
                                match current_block_21 {
                                    17170645623528868489 => {
                                        if conn_addr_legal != 0 {
                                            count += 1
                                        }
                                    }
                                    15096969486213676147 => {
                                        if ipv4_addr_legal != 0 {
                                            let mut sin = 0 as *mut sockaddr_in;
                                            sin = &mut (*sctp_ifa).address.sin;
                                            if !((*sin).sin_addr.s_addr == 0u32) {
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
                                                    count += 1
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        if ipv6_addr_legal != 0 {
                                            let mut sin6 = 0 as *mut sockaddr_in6;
                                            sin6 = &mut (*sctp_ifa).address.sin6;
                                            if !(({
                                                let mut __a = &mut (*sin6).sin6_addr
                                                    as *mut in6_addr
                                                    as *const in6_addr;
                                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                                    as libc::c_int
                                            }) != 0)
                                            {
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
                                                        current_block_21 = 12147880666119273379;
                                                    } else {
                                                        current_block_21 = 11743904203796629665;
                                                    }
                                                } else {
                                                    current_block_21 = 11743904203796629665;
                                                }
                                                match current_block_21 {
                                                    12147880666119273379 => {}
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
                                                            count += 1
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            123 => {
                                current_block_21 = 17170645623528868489;
                                match current_block_21 {
                                    17170645623528868489 => {
                                        if conn_addr_legal != 0 {
                                            count += 1
                                        }
                                    }
                                    15096969486213676147 => {
                                        if ipv4_addr_legal != 0 {
                                            let mut sin = 0 as *mut sockaddr_in;
                                            sin = &mut (*sctp_ifa).address.sin;
                                            if !((*sin).sin_addr.s_addr == 0u32) {
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
                                                    count += 1
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        if ipv6_addr_legal != 0 {
                                            let mut sin6 = 0 as *mut sockaddr_in6;
                                            sin6 = &mut (*sctp_ifa).address.sin6;
                                            if !(({
                                                let mut __a = &mut (*sin6).sin6_addr
                                                    as *mut in6_addr
                                                    as *const in6_addr;
                                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                                    && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                                    as libc::c_int
                                            }) != 0)
                                            {
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
                                                        current_block_21 = 12147880666119273379;
                                                    } else {
                                                        current_block_21 = 11743904203796629665;
                                                    }
                                                } else {
                                                    current_block_21 = 11743904203796629665;
                                                }
                                                match current_block_21 {
                                                    12147880666119273379 => {}
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
                                                            count += 1
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
            if !(sctp_is_addr_restricted(stcb, (*laddr).ifa) != 0) {
                /* count this one */
                count += 1
            }
            laddr = (*laddr).sctp_nxt_addr.le_next
        }
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    return count;
}
/*
 * sctp_min_mtu ()returns the minimum of all non-zero arguments.
 * If all arguments are zero, zero is returned.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_min_mtu(
    mut mtu1: uint32_t,
    mut mtu2: uint32_t,
    mut mtu3: uint32_t,
) -> uint32_t {
    if mtu1 > 0u32 {
        if mtu2 > 0u32 {
            if mtu3 > 0u32 {
                return if mtu1 > (if mtu2 > mtu3 { mtu3 } else { mtu2 }) {
                    if mtu2 > mtu3 {
                        mtu3
                    } else {
                        mtu2
                    }
                } else {
                    mtu1
                };
            } else {
                return if mtu1 > mtu2 { mtu2 } else { mtu1 };
            }
        } else if mtu3 > 0u32 {
            return if mtu1 > mtu3 { mtu3 } else { mtu1 };
        } else {
            return mtu1;
        }
    } else if mtu2 > 0u32 {
        if mtu3 > 0u32 {
            return if mtu2 > mtu3 { mtu3 } else { mtu2 };
        } else {
            return mtu2;
        }
    } else {
        return mtu3;
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_set_state(mut stcb: *mut sctp_tcb, mut new_state: libc::c_int) {
    (*stcb).asoc.state = (*stcb).asoc.state & !(0x7fi32) | new_state;
    if new_state == 0x20i32 || new_state == 0x10i32 || new_state == 0x40i32 {
        (*stcb).asoc.state &= !(0x80i32)
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_add_substate(mut stcb: *mut sctp_tcb, mut substate: libc::c_int) {
    (*stcb).asoc.state |= substate;
}
