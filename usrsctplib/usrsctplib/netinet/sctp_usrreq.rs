use ::c2rust_bitfields;
use ::libc;
extern "C" {
    pub type accept_filter;
    pub type label;
    pub type ifnet;
    pub type aiocblist;
    pub type sigio;
    pub type iface;
    pub type icmp6_filter;
    pub type ip6_pktopts;
    pub type ip_moptions;
    pub type inpcbpolicy;
    pub type uma_zone;
    #[no_mangle]
    fn srandom(__seed: libc::c_uint);
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn pthread_join(__th: pthread_t, __thread_return: *mut *mut libc::c_void) -> libc::c_int;
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
    fn soisconnecting(so: *mut socket);
    #[no_mangle]
    fn soisdisconnecting(so: *mut socket);
    #[no_mangle]
    fn socantsendmore(so: *mut socket);
    #[no_mangle]
    fn solisten_proto(so: *mut socket, backlog: libc::c_int);
    #[no_mangle]
    fn solisten_proto_check(so: *mut socket) -> libc::c_int;
    #[no_mangle]
    fn sowakeup(so: *mut socket, sb: *mut sockbuf);
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
    /* __Userspace__ */
    /* maxsockets is used in SCTP_ZONE_INIT call. It refers to
     * kern.ipc.maxsockets kernel environment variable.
     */
    /* int hz; is declared in sys/kern/subr_param.c and refers to kernel timer frequency.
     * See http://ivoras.sharanet.org/freebsd/vmware.html for additional info about kern.hz
     * hz is initialized in void init_param1(void) in that file.
     */
    /* The following two ints define a range of available ephemeral ports. */
    /* nmbclusters is used in sctp_usrreq.c (e.g., sctp_init). In the FreeBSD kernel,
     *  this is 1024 + maxusers * 64.
     */
    /* errno's may differ per OS.  errno.h now included in sctp_os_userspace.h */
    /* Source: /usr/src/sys/sys/errno.h */
    /* #define	ENOSPC		28 */
    /* No space left on device */
    /* #define	ENOBUFS		55 */
    /* No buffer space available */
    /* #define	ENOMEM		12 */
    /* Cannot allocate memory */
    /* #define	EACCES		13 */
    /* Permission denied */
    /* #define	EFAULT		14 */
    /* Bad address */
    /* #define	EHOSTDOWN	64 */
    /* Host is down */
    /* #define	EHOSTUNREACH	65 */
    /* No route to host */
    /* Source ip_output.c. extern'd in ip_var.h */
    /* necessary for sctp_pcb.c */
    #[no_mangle]
    static mut ip_defttl: libc::c_int;
    #[no_mangle]
    fn soreserve(so: *mut socket, sndcc: u_long, rcvcc: u_long) -> libc::c_int;
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
    fn recv_thread_destroy();
    #[no_mangle]
    static mut hz: libc::c_int;
    #[no_mangle]
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn getpid() -> __pid_t;
    #[no_mangle]
    fn sctp_os_timer_stop(_: *mut sctp_os_timer_t) -> libc::c_int;
    /* MT FIXME: Is the following correct? */
    #[no_mangle]
    fn sctp_start_timer();
    #[no_mangle]
    fn sctp_auth_add_chunk(chunk: uint8_t, list: *mut sctp_auth_chklist_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_auth_delete_chunk(chunk: uint8_t, list: *mut sctp_auth_chklist_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_auth_get_chklist_size(list: *const sctp_auth_chklist_t) -> size_t;
    #[no_mangle]
    fn sctp_serialize_auth_chunks(
        list: *const sctp_auth_chklist_t,
        ptr: *mut uint8_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_fill_pcbinfo(_: *mut sctp_pcbinfo);
    #[no_mangle]
    fn sctp_find_vrf(vrfid: uint32_t) -> *mut sctp_vrf;
    #[no_mangle]
    fn sctp_free_ifa(sctp_ifap: *mut sctp_ifa);
    #[no_mangle]
    fn sctp_findnet(_: *mut sctp_tcb, _: *mut sockaddr) -> *mut sctp_nets;
    #[no_mangle]
    fn sctp_findassociation_ep_asocid(
        _: *mut sctp_inpcb,
        _: sctp_assoc_t,
        _: libc::c_int,
    ) -> *mut sctp_tcb;
    #[no_mangle]
    fn sctp_pcb_init(_: libc::c_int);
    #[no_mangle]
    fn sctp_set_primary_addr(_: *mut sctp_tcb, _: *mut sockaddr, _: *mut sctp_nets) -> libc::c_int;
    #[no_mangle]
    fn sctp_inpcb_bind(
        _: *mut socket,
        _: *mut sockaddr,
        _: *mut sctp_ifa,
        _: *mut proc_0,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_swap_inpcb_for_listen(inp: *mut sctp_inpcb) -> libc::c_int;
    #[no_mangle]
    fn sctp_pcb_findep(
        _: *mut sockaddr,
        _: libc::c_int,
        _: libc::c_int,
        _: uint32_t,
    ) -> *mut sctp_inpcb;
    #[no_mangle]
    fn sctp_free_assoc(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_inpcb_free(_: *mut sctp_inpcb, _: libc::c_int, _: libc::c_int);
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_aloc_assoc(
        _: *mut sctp_inpcb,
        _: *mut sockaddr,
        _: *mut libc::c_int,
        _: uint32_t,
        _: uint32_t,
        _: uint16_t,
        _: uint16_t,
        _: *mut proc_0,
        _: libc::c_int,
    ) -> *mut sctp_tcb;
    #[no_mangle]
    fn sctp_findassociation_ep_addr(
        _: *mut *mut sctp_inpcb,
        _: *mut sockaddr,
        _: *mut *mut sctp_nets,
        _: *mut sockaddr,
        _: *mut sctp_tcb,
    ) -> *mut sctp_tcb;
    #[no_mangle]
    fn sctp_pcb_finish();
    #[no_mangle]
    fn sctp_inpcb_alloc(so: *mut socket, vrf_id: uint32_t) -> libc::c_int;
    /*
     * limits for the sysctl variables
     */
    /* maxdgram: Maximum outgoing SCTP buffer size */
    /* recvspace: Maximum incoming SCTP buffer size */
    /* autoasconf: Enable SCTP Auto-ASCONF */
    /* autoasconf: Enable SCTP Auto-ASCONF */
    /* ecn_enable: Enable SCTP ECN */
    /* pr_enable: Enable PR-SCTP */
    /* auth_enable: Enable SCTP AUTH function */
    /* asconf_enable: Enable SCTP ASCONF */
    /* reconfig_enable: Enable SCTP RE-CONFIG */
    /* nrsack_enable: Enable NR_SACK */
    /* pktdrop_enable: Enable SCTP Packet Drop Reports */
    /* loopback_nocsum: Enable NO Csum on packets sent on loopback */
    /* peer_chkoh: Amount to debit peers rwnd per chunk sent */
    /* maxburst: Default max burst for sctp endpoints */
    /* fr_maxburst: Default max burst for sctp endpoints when fast retransmitting */
    /* maxchunks: Default max chunks on queue per asoc */
    /* tcbhashsize: Tunable for Hash table sizes */
    /* pcbhashsize: Tunable for PCB Hash table sizes */
    /* min_split_point: Minimum size when splitting a chunk */
    /* chunkscale: Tunable for Scaling of number of chunks and messages */
    /* delayed_sack_time: Default delayed SACK timer in ms */
    /* sack_freq: Default SACK frequency */
    /* sys_resource: Max number of cached resources in the system */
    /* asoc_resource: Max number of cached resources in an asoc */
    /* heartbeat_interval: Default heartbeat interval in ms */
    /* pmtu_raise_time: Default PMTU raise timer in seconds */
    /* shutdown_guard_time: Default shutdown guard timer in seconds */
    /* secret_lifetime: Default secret lifetime in seconds */
    /* rto_max: Default maximum retransmission timeout in ms */
    /* rto_min: Default minimum retransmission timeout in ms */
    /* rto_initial: Default initial retransmission timeout in ms */
    /* init_rto_max: Default maximum retransmission timeout during association setup in ms */
    /* valid_cookie_life: Default cookie lifetime in sec */
    /* init_rtx_max: Default maximum number of retransmission for INIT chunks */
    /* assoc_rtx_max: Default maximum number of retransmissions per association */
    /* path_rtx_max: Default maximum of retransmissions per path */
    /* path_pf_threshold: threshold for considering the path potentially failed */
    /* add_more_on_output: When space-wise is it worthwhile to try to add more to a socket send buffer */
    /* incoming_streams: Default number of incoming streams */
    /* outgoing_streams: Default number of outgoing streams */
    /* cmt_on_off: CMT on/off flag */
    /* cmt_use_dac: CMT DAC on/off flag */
    /* cwnd_maxburst: Use a CWND adjusting to implement maxburst */
    /* nat_friendly: SCTP NAT friendly operation */
    /* abc_l_var: SCTP ABC max increase per SACK (L) */
    /* max_chained_mbufs: Default max number of small mbufs on a chain */
    /* do_sctp_drain: Should SCTP respond to the drain calls */
    /* hb_max_burst: Confirmation Heartbeat max burst? */
    /* abort_at_limit: When one-2-one hits qlimit abort */
    /* min_residual: min residual in a data fragment leftover */
    /* max_retran_chunk: max chunk retransmissions */
    /* sctp_logging: This gives us logging when the options are enabled */
    /* JRS - default congestion control module sysctl */
    /* RS - default stream scheduling module sysctl */
    /* RRS - default fragment interleave */
    /* mobility_base: Enable SCTP mobility support */
    /* mobility_fasthandoff: Enable SCTP fast handoff support */
    /* Enable SCTP/UDP tunneling port */
    /* Enable sending of the SACK-IMMEDIATELY bit */
    /* Enable sending of the NAT-FRIENDLY message */
    /* Vtag time wait in seconds */
    /* Enable Send/Receive buffer splitting */
    /* Initial congestion window in MTUs */
    /* rttvar smooth avg for bw calc  */
    /* rttvar smooth avg for bw calc  */
    /* 0 means disable feature */
    /* 0 means disable feature */
    /* sendall_limit: Maximum message with SCTP_SENDALL */
    /* debug: Configure debug output */
    #[no_mangle]
    fn sctp_init_sysctls();
    #[no_mangle]
    fn sctp_free_key(key: *mut sctp_key_t);
    #[no_mangle]
    fn sctp_set_key(key: *mut uint8_t, keylen: uint32_t) -> *mut sctp_key_t;
    /* shared key handling */
    #[no_mangle]
    fn sctp_alloc_sharedkey() -> *mut sctp_sharedkey_t;
    #[no_mangle]
    fn sctp_insert_sharedkey(
        shared_keys: *mut sctp_keyhead,
        new_skey: *mut sctp_sharedkey_t,
    ) -> libc::c_int;
    /* hmac list handling */
    #[no_mangle]
    fn sctp_alloc_hmaclist(num_hmacs: uint16_t) -> *mut sctp_hmaclist_t;
    #[no_mangle]
    fn sctp_free_hmaclist(list: *mut sctp_hmaclist_t);
    #[no_mangle]
    fn sctp_auth_add_hmacid(list: *mut sctp_hmaclist_t, hmac_id: uint16_t) -> libc::c_int;
    /* keyed-HMAC functions */
    #[no_mangle]
    fn sctp_get_auth_chunk_len(hmac_algo: uint16_t) -> uint32_t;
    /*
     * authentication routines
     */
    #[no_mangle]
    fn sctp_clear_cachedkeys(stcb: *mut sctp_tcb, keyid: uint16_t);
    #[no_mangle]
    fn sctp_clear_cachedkeys_ep(inp: *mut sctp_inpcb, keyid: uint16_t);
    #[no_mangle]
    fn sctp_delete_sharedkey(stcb: *mut sctp_tcb, keyid: uint16_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_delete_sharedkey_ep(inp: *mut sctp_inpcb, keyid: uint16_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_auth_setactivekey(stcb: *mut sctp_tcb, keyid: uint16_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_auth_setactivekey_ep(inp: *mut sctp_inpcb, keyid: uint16_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_deact_sharedkey(stcb: *mut sctp_tcb, keyid: uint16_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_deact_sharedkey_ep(inp: *mut sctp_inpcb, keyid: uint16_t) -> libc::c_int;
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
    fn sctp_get_frag_point(_: *mut sctp_tcb, _: *mut sctp_association) -> libc::c_int;
    /* sctp_output is called bu sctp_sendm. Not using sctp_sendm for __Userspace__ */
    #[no_mangle]
    fn sctp_output(
        _: *mut sctp_inpcb,
        _: *mut mbuf,
        _: *mut sockaddr,
        _: *mut mbuf,
        _: *mut proc_0,
        _: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_chunk_output(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: libc::c_int, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_abort_tcb(_: *mut sctp_tcb, _: *mut mbuf, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_hb(_: *mut sctp_tcb, _: *mut sctp_nets, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_stream_reset_out_if_possible(_: *mut sctp_tcb, _: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn sctp_send_str_reset_req(
        _: *mut sctp_tcb,
        _: uint16_t,
        _: *mut uint16_t,
        _: uint8_t,
        _: uint8_t,
        _: uint8_t,
        _: uint16_t,
        _: uint16_t,
        _: uint8_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_set_primary_ip_address_sa(_: *mut sctp_tcb, _: *mut sockaddr) -> int32_t;
    #[no_mangle]
    fn sctp_is_addr_pending(_: *mut sctp_tcb, _: *mut sctp_ifa) -> libc::c_int;
    /*
     * Function prototypes
     */
    #[no_mangle]
    fn sctp_map_assoc_state(_: libc::c_int) -> int32_t;
    #[no_mangle]
    fn sctp_find_ifa_by_addr(
        addr: *mut sockaddr,
        vrf_id: uint32_t,
        holds_lock: libc::c_int,
    ) -> *mut sctp_ifa;
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
    fn sctp_dynamic_set_primary(sa: *mut sockaddr, vrf_id: uint32_t) -> libc::c_int;
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
    fn sctp_connectx_helper_add(
        stcb: *mut sctp_tcb,
        addr: *mut sockaddr,
        totaddr: libc::c_int,
        error: *mut libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_connectx_helper_find(
        _: *mut sctp_inpcb,
        _: *mut sockaddr,
        _: libc::c_uint,
        _: *mut libc::c_uint,
        _: *mut libc::c_uint,
        _: libc::c_uint,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_generate_cause(_: uint16_t, _: *mut libc::c_char) -> *mut mbuf;
    #[no_mangle]
    fn sctp_bindx_add_address(
        so: *mut socket,
        inp: *mut sctp_inpcb,
        sa: *mut sockaddr,
        assoc_id: sctp_assoc_t,
        vrf_id: uint32_t,
        error: *mut libc::c_int,
        p: *mut libc::c_void,
    );
    #[no_mangle]
    fn sctp_bindx_delete_address(
        inp: *mut sctp_inpcb,
        sa: *mut sockaddr,
        assoc_id: sctp_assoc_t,
        vrf_id: uint32_t,
        error: *mut libc::c_int,
    );
    #[no_mangle]
    fn sctp_misc_ints(from: uint8_t, a: uint32_t, b: uint32_t, c: uint32_t, d: uint32_t);
    #[no_mangle]
    fn sctp_fill_stat_log(_: *mut libc::c_void, _: *mut size_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_set_state(_: *mut sctp_tcb, _: libc::c_int);
    #[no_mangle]
    fn sctp_add_substate(_: *mut sctp_tcb, _: libc::c_int);
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
    /* HAVE_SCTP_PEELOFF_SOCKOPT */
    #[no_mangle]
    static sctp_cc_functions: [sctp_cc_functions; 0];
    #[no_mangle]
    static sctp_ss_functions: [sctp_ss_functions; 0];
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
    pub c2rust_unnamed: C2RustUnnamed_719,
    pub c2rust_unnamed_0: C2RustUnnamed_717,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_717 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_718,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_718 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_719 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_720,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_720 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ucred {
    pub pid: pid_t,
    pub uid: uid_t,
    pub gid: gid_t,
}
pub type C2RustUnnamed_721 = libc::c_uint;
pub const SHUT_RDWR: C2RustUnnamed_721 = 2;
pub const SHUT_WR: C2RustUnnamed_721 = 1;
pub const SHUT_RD: C2RustUnnamed_721 = 0;

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
    pub __in6_u: C2RustUnnamed_722,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_722 {
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
pub type userland_mutex_t = pthread_mutex_t;
pub type userland_cond_t = pthread_cond_t;
pub type userland_thread_t = pthread_t;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mtx {
    pub dummy: libc::c_int,
}
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;

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
    pub so_incomp: C2RustUnnamed_730,
    pub so_comp: C2RustUnnamed_729,
    pub so_list: C2RustUnnamed_728,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_727,
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
    pub M_dat: C2RustUnnamed_723,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_723 {
    pub MH: C2RustUnnamed_724,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_724 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_725,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_725 {
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
    pub m_tag_link: C2RustUnnamed_726,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_726 {
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
pub struct C2RustUnnamed_727 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_728 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_729 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_730 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}
/* we choose the number to make a pcb a page */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_761,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_760,
    pub sctp_hash: C2RustUnnamed_759,
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
    pub sctp_tcbhash: C2RustUnnamed_758,
    pub sctp_tcblist: C2RustUnnamed_757,
    pub sctp_tcbasocidhash: C2RustUnnamed_756,
    pub sctp_asocs: C2RustUnnamed_755,
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
    pub next: C2RustUnnamed_731,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_731 {
    pub le_next: *mut sctp_shared_key,
    pub le_prev: *mut *mut sctp_shared_key,
}
/* local random key (concatenated) */
/* local random number length for param */
/* peer's random key (concatenated) */
/* cached concatenated send key */
/* cached concatenated recv key */
/* active send keyid */
/* current send keyid (cached) */
/* last recv keyid (cached) */
/* hmac algos supported list */
pub type sctp_hmaclist_t = sctp_hmaclist;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_hmaclist {
    pub max_algo: uint16_t,
    pub num_algo: uint16_t,
    pub hmac: [uint16_t; 0],
}
/* max algorithms allocated */
/* num algorithms used */
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
    pub next: C2RustUnnamed_743,
    pub next_instrm: C2RustUnnamed_742,
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
    pub rec: C2RustUnnamed_741,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_732,
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
pub struct C2RustUnnamed_732 {
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
    pub sctp_next: C2RustUnnamed_740,
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
    pub tqe: C2RustUnnamed_733,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_733 {
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
    pub next_ifa: C2RustUnnamed_738,
    pub next_bucket: C2RustUnnamed_737,
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
    pub next_ifn: C2RustUnnamed_735,
    pub next_bucket: C2RustUnnamed_734,
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
pub struct C2RustUnnamed_734 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_735 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
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
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_736,
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
pub struct C2RustUnnamed_736 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_737 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_738 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}
pub type sctp_rtentry_t = sctp_rtentry;
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
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_739,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_739 {
    pub ifu_broadaddr: sockaddr,
    pub ifu_dstaddr: sockaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_740 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_741 {
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
pub struct C2RustUnnamed_742 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_743 {
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
    pub next_spoke: C2RustUnnamed_744,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_744 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_745,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_745 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_746,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_746 {
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
    pub next: C2RustUnnamed_748,
    pub ss_next: C2RustUnnamed_747,
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
pub struct C2RustUnnamed_747 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_748 {
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
    pub next_resp: C2RustUnnamed_749,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_749 {
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
    pub sctp_nxt_addr: C2RustUnnamed_750,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_750 {
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
    pub next: C2RustUnnamed_751,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_751 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_752,
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
pub struct C2RustUnnamed_752 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_753,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_753 {
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
    pub next: C2RustUnnamed_754,
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
pub struct C2RustUnnamed_754 {
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
pub struct C2RustUnnamed_755 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_756 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_757 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_758 {
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
pub struct C2RustUnnamed_759 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_760 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_761 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcb {
    pub inp_hash: C2RustUnnamed_769,
    pub inp_list: C2RustUnnamed_768,
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
    pub inp_depend4: C2RustUnnamed_765,
    pub inp_depend6: C2RustUnnamed_764,
    pub inp_portlist: C2RustUnnamed_763,
    pub inp_phd: *mut inpcbport,
    pub inp_mtx: mtx,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbport {
    pub phd_hash: C2RustUnnamed_762,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbhead {
    pub lh_first: *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_762 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_763 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_764 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_765 {
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
    pub ie_dependfaddr: C2RustUnnamed_767,
    pub ie_dependladdr: C2RustUnnamed_766,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_766 {
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
pub union C2RustUnnamed_767 {
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
pub struct C2RustUnnamed_768 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_769 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}
pub type sctp_sharedkey_t = sctp_shared_key;
/* key text */
/* reference count */
/* shared key ID */
/* key is deactivated */
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
/* time when this address was created */
/* the seconds from boot to expire */
/* the vtag that can not be reused */
/* the local port used in vtag */
/* the remote port used in vtag */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tagblock {
    pub sctp_nxt_tagblock: C2RustUnnamed_770,
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
pub struct C2RustUnnamed_770 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}
pub type sctp_zone_t = size_t;

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
pub type __timezone_ptr_t = *mut timezone;

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_route {
    pub ro_rt: *mut sctp_rtentry,
    pub ro_dst: sockaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ip6_hdr {
    pub ip6_ctlun: C2RustUnnamed_771,
    pub ip6_src: in6_addr,
    pub ip6_dst: in6_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_771 {
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
pub type sctp_route_t = sctp_route;

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
pub struct sctp_event {
    pub se_assoc_id: sctp_assoc_t,
    pub se_type: uint16_t,
    pub se_on: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_event_subscribe {
    pub sctp_data_io_event: uint8_t,
    pub sctp_association_event: uint8_t,
    pub sctp_address_event: uint8_t,
    pub sctp_send_failure_event: uint8_t,
    pub sctp_peer_error_event: uint8_t,
    pub sctp_shutdown_event: uint8_t,
    pub sctp_partial_delivery_event: uint8_t,
    pub sctp_adaptation_layer_event: uint8_t,
    pub sctp_authentication_event: uint8_t,
    pub sctp_sender_dry_event: uint8_t,
    pub sctp_stream_reset_event: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_initmsg {
    pub sinit_num_ostreams: uint16_t,
    pub sinit_max_instreams: uint16_t,
    pub sinit_max_attempts: uint16_t,
    pub sinit_max_init_timeo: uint16_t,
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
pub struct sctp_sndinfo {
    pub snd_sid: uint16_t,
    pub snd_flags: uint16_t,
    pub snd_ppid: uint32_t,
    pub snd_context: uint32_t,
    pub snd_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_default_prinfo {
    pub pr_policy: uint16_t,
    pub pr_value: uint32_t,
    pub pr_assoc_id: sctp_assoc_t,
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
pub struct sctp_sockstat {
    pub ss_assoc_id: sctp_assoc_t,
    pub ss_total_sndbuf: uint32_t,
    pub ss_total_recv_buf: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_setadaptation {
    pub ssb_adaptation_ind: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_paddrparams {
    pub spp_address: sockaddr_storage,
    pub spp_assoc_id: sctp_assoc_t,
    pub spp_hbinterval: uint32_t,
    pub spp_pathmtu: uint32_t,
    pub spp_flags: uint32_t,
    pub spp_ipv6_flowlabel: uint32_t,
    pub spp_pathmaxrxt: uint16_t,
    pub spp_dscp: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_paddrthlds {
    pub spt_address: sockaddr_storage,
    pub spt_assoc_id: sctp_assoc_t,
    pub spt_pathmaxrxt: uint16_t,
    pub spt_pathpfthld: uint16_t,
    pub spt_pathcpthld: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_paddrinfo {
    pub spinfo_address: sockaddr_storage,
    pub spinfo_assoc_id: sctp_assoc_t,
    pub spinfo_state: int32_t,
    pub spinfo_cwnd: uint32_t,
    pub spinfo_srtt: uint32_t,
    pub spinfo_rto: uint32_t,
    pub spinfo_mtu: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_rtoinfo {
    pub srto_assoc_id: sctp_assoc_t,
    pub srto_initial: uint32_t,
    pub srto_max: uint32_t,
    pub srto_min: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_assocparams {
    pub sasoc_assoc_id: sctp_assoc_t,
    pub sasoc_peer_rwnd: uint32_t,
    pub sasoc_local_rwnd: uint32_t,
    pub sasoc_cookie_life: uint32_t,
    pub sasoc_asocmaxrxt: uint16_t,
    pub sasoc_number_peer_destinations: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_setprim {
    pub ssp_addr: sockaddr_storage,
    pub ssp_assoc_id: sctp_assoc_t,
    pub ssp_padding: [uint8_t; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_setpeerprim {
    pub sspp_addr: sockaddr_storage,
    pub sspp_assoc_id: sctp_assoc_t,
    pub sspp_padding: [uint8_t; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_getaddresses {
    pub sget_assoc_id: sctp_assoc_t,
    pub addr: [sockaddr; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_status {
    pub sstat_assoc_id: sctp_assoc_t,
    pub sstat_state: int32_t,
    pub sstat_rwnd: uint32_t,
    pub sstat_unackdata: uint16_t,
    pub sstat_penddata: uint16_t,
    pub sstat_instrms: uint16_t,
    pub sstat_outstrms: uint16_t,
    pub sstat_fragmentation_point: uint32_t,
    pub sstat_primary: sctp_paddrinfo,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_authchunk {
    pub sauth_chunk: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_authkey {
    pub sca_assoc_id: sctp_assoc_t,
    pub sca_keynumber: uint16_t,
    pub sca_keylength: uint16_t,
    pub sca_key: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_hmacalgo {
    pub shmac_number_of_idents: uint32_t,
    pub shmac_idents: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_authkeyid {
    pub scact_assoc_id: sctp_assoc_t,
    pub scact_keynumber: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_authchunks {
    pub gauth_assoc_id: sctp_assoc_t,
    pub gauth_number_of_chunks: uint32_t,
    pub gauth_chunks: [uint8_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_stream_value {
    pub assoc_id: sctp_assoc_t,
    pub stream_id: uint16_t,
    pub stream_value: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_assoc_ids {
    pub gaids_number_of_ids: uint32_t,
    pub gaids_assoc_id: [sctp_assoc_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_sack_info {
    pub sack_assoc_id: sctp_assoc_t,
    pub sack_delay: uint32_t,
    pub sack_freq: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_timeouts {
    pub stimo_assoc_id: sctp_assoc_t,
    pub stimo_init: uint32_t,
    pub stimo_data: uint32_t,
    pub stimo_sack: uint32_t,
    pub stimo_shutdown: uint32_t,
    pub stimo_heartbeat: uint32_t,
    pub stimo_cookie: uint32_t,
    pub stimo_shutdownack: uint32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_udpencaps {
    pub sue_address: sockaddr_storage,
    pub sue_assoc_id: sctp_assoc_t,
    pub sue_port: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_prstatus {
    pub sprstat_assoc_id: sctp_assoc_t,
    pub sprstat_sid: uint16_t,
    pub sprstat_policy: uint16_t,
    pub sprstat_abandoned_unsent: uint64_t,
    pub sprstat_abandoned_sent: uint64_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_reset_streams {
    pub srs_assoc_id: sctp_assoc_t,
    pub srs_flags: uint16_t,
    pub srs_number_streams: uint16_t,
    pub srs_stream_list: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_add_streams {
    pub sas_assoc_id: sctp_assoc_t,
    pub sas_instrms: uint16_t,
    pub sas_outstrms: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_get_nonce_values {
    pub gn_assoc_id: sctp_assoc_t,
    pub gn_peers_tag: uint32_t,
    pub gn_local_tag: uint32_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_data {
    pub tsn: uint32_t,
    pub sid: uint16_t,
    pub ssn: uint16_t,
    pub ppid: uint32_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_data_chunk {
    pub ch: sctp_chunkhdr,
    pub dp: sctp_data,
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
pub unsafe extern "C" fn sctp_init(
    mut port: uint16_t,
    mut conn_output: Option<
        unsafe extern "C" fn(
            _: *mut libc::c_void,
            _: *mut libc::c_void,
            _: size_t,
            _: uint8_t,
            _: uint8_t,
        ) -> libc::c_int,
    >,
    mut debug_printf: Option<unsafe extern "C" fn(_: *const libc::c_char, _: ...) -> ()>,
    mut start_threads: libc::c_int,
) {
    /* Initialize and modify the sysctled variables */
    sctp_init_sysctls(); /* so inp->sctp_ep.random_numbers are truly random... */
    srandom(getpid() as libc::c_uint);
    system_base_info.sctpsysctl.sctp_udp_tunneling_port = port as uint32_t;
    system_base_info.first_time = 0u8;
    system_base_info.sctp_pcb_initialized = 0i8;
    system_base_info.userspace_route = -(1i32);
    system_base_info.userspace_rawsctp = -(1i32);
    system_base_info.userspace_udpsctp = -(1i32);
    system_base_info.userspace_rawsctp6 = -(1i32);
    system_base_info.userspace_udpsctp6 = -(1i32);
    system_base_info.timer_thread_should_exit = 0i32;
    system_base_info.conn_output = conn_output;
    system_base_info.debug_printf = debug_printf;
    system_base_info.crc32c_offloaded = 0i32;
    sctp_pcb_init(start_threads);
    if start_threads != 0 {
        sctp_start_timer();
    };
}
/* in process of disconnecting */
/* non-blocking ops */
/* async i/o notify */
/* deciding to accept connection req */
/* socket disconnected from peer */
/*
 * Protocols can mark a socket as SS_PROTOREF to indicate that, following
 * pru_detach, they still want the socket to persist, and will free it
 * themselves when they are done.  Protocols should only ever call sofree()
 * following setting this flag in pru_detach(), and never otherwise, as
 * sofree() bypasses socket reference counting.
 */
/* strong protocol reference */
/*
 * Socket state bits now stored in the socket buffer state field.
 */
/* can't send more data to peer */
/* can't receive more data from peer */
/* at mark on input */
/*
 * Socket state bits stored in so_qstate.
 */
/* unaccepted, incomplete connection */
/* unaccepted, complete connection */
/*
 * Socket event flags
 */
/* socket is readable */
/* socket is writeable */
/* socket has an error state */
/*
 * Externalized form of struct socket used by the sysctl(3) interface.
 */
/* length of this structure */
/* makes a convenient handle sometimes */
/* another convenient handle */
/* XXX */
/* _KERNEL */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------------*/
/*                   __Userspace__                             */
/*-------------------------------------------------------------*/
/*-------------------------------------------------------------*/
/* this new __Userspace__ section is to copy portions of the _KERNEL block
 *  above into, avoiding having to port the entire thing at once...
 *  For function prototypes, the full bodies are in user_socket.c .
 */
/* ---------------------------------------------------------- */
/* --- function prototypes (implemented in user_socket.c) --- */
/* ---------------------------------------------------------- */
/* -------------- */
/* --- macros --- */
/* -------------- */
/* replacing imin with min (user_environment.h) */
/* do we have to send all at once on a socket? */
/* can we read something from so? */
/*  original */
/* line with PR_CONNREQUIRED removed */
/* can we write something to so? */
/*__Userspace__ */
#[no_mangle]
pub unsafe extern "C" fn sctp_finish() {
    recv_thread_destroy();
    if system_base_info.userspace_route != -(1i32) {
        pthread_join(
            system_base_info.recvthreadroute,
            0 as *mut *mut libc::c_void,
        );
    }
    if system_base_info.userspace_rawsctp != -(1i32) {
        pthread_join(system_base_info.recvthreadraw, 0 as *mut *mut libc::c_void);
    }
    if system_base_info.userspace_udpsctp != -(1i32) {
        pthread_join(system_base_info.recvthreadudp, 0 as *mut *mut libc::c_void);
    }
    if system_base_info.userspace_rawsctp6 != -(1i32) {
        pthread_join(system_base_info.recvthreadraw6, 0 as *mut *mut libc::c_void);
    }
    if system_base_info.userspace_udpsctp6 != -(1i32) {
        pthread_join(system_base_info.recvthreadudp6, 0 as *mut *mut libc::c_void);
    }
    ::std::intrinsics::atomic_cxchg(&mut system_base_info.timer_thread_should_exit, 0i32, 1i32).1;
    pthread_join(system_base_info.timer_thread, 0 as *mut *mut libc::c_void);
    sctp_pcb_finish();
}
#[no_mangle]
pub unsafe extern "C" fn sctp_pathmtu_adjustment(mut stcb: *mut sctp_tcb, mut nxtsz: uint16_t) {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut overhead = 0;
    /* Adjust that too */
    (*stcb).asoc.smallest_mtu = nxtsz as uint32_t;
    /* now off to subtract IP_DF flag if needed */
    overhead = (40u64).wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong) as uint16_t;
    if if (*stcb).asoc.peer_auth_chunks.is_null() {
        0i32
    } else {
        ((*(*stcb).asoc.peer_auth_chunks).chunks[0usize] as libc::c_int != 0i32) as libc::c_int
    } != 0
    {
        overhead = (overhead as libc::c_uint)
            .wrapping_add(sctp_get_auth_chunk_len((*stcb).asoc.peer_hmac_id))
            as uint16_t
    }
    chk = (*stcb).asoc.send_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).send_size as libc::c_int + overhead as libc::c_int > nxtsz as libc::c_int {
            (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t
        }
        chk = (*chk).sctp_next.tqe_next
    }
    chk = (*stcb).asoc.sent_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).send_size as libc::c_int + overhead as libc::c_int > nxtsz as libc::c_int {
            /*
             * For this guy we also mark for immediate resend
             * since we sent to big of chunk
             */
            (*chk).flags = ((*chk).flags as libc::c_int | 0x100i32) as uint16_t;
            if (*chk).sent < 4i32 {
                if (*(*chk).whoTo).flight_size >= (*chk).book_size as libc::c_uint {
                    (*(*chk).whoTo).flight_size =
                        ((*(*chk).whoTo).flight_size).wrapping_sub((*chk).book_size as libc::c_uint)
                } else {
                    (*(*chk).whoTo).flight_size = 0u32
                }
                (*chk).window_probe = 0u8;
                if (*stcb).asoc.total_flight >= (*chk).book_size as libc::c_uint {
                    (*stcb).asoc.total_flight = (*stcb)
                        .asoc
                        .total_flight
                        .wrapping_sub((*chk).book_size as libc::c_uint);
                    if (*stcb).asoc.total_flight_count > 0u32 {
                        (*stcb).asoc.total_flight_count =
                            (*stcb).asoc.total_flight_count.wrapping_sub(1)
                    }
                } else {
                    (*stcb).asoc.total_flight = 0u32;
                    (*stcb).asoc.total_flight_count = 0u32
                }
                (*chk).sent = 4i32;
                (*stcb).asoc.sent_queue_retran_cnt =
                    (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1);
                (*chk).rec.data.doing_fast_retransmit = 0u8;
                if system_base_info.sctpsysctl.sctp_logging_level & 0x20u32 != 0 {
                    sctp_misc_ints(
                        116u8,
                        (*(*chk).whoTo).flight_size,
                        (*chk).book_size as uint32_t,
                        (*chk).whoTo as uint32_t,
                        (*chk).rec.data.tsn,
                    );
                }
                /* Clear any time so NO RTT is being done */
                if (*chk).do_rtt as libc::c_int == 1i32 {
                    (*chk).do_rtt = 0u8;
                    (*(*chk).whoTo).rto_needed = 1u8
                }
            }
        }
        chk = (*chk).sctp_next.tqe_next
    }
}
/* #if defined(__FreeBSD__) */
#[no_mangle]
pub unsafe extern "C" fn sctp_abort(mut so: *mut socket) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 22i32;
    }
    loop {
        let mut flags = 0;
        flags = (*inp).sctp_flags;
        if flags & 0x10000000u32 == 0u32
            && ::std::intrinsics::atomic_cxchg(
                &mut (*inp).sctp_flags as *mut uint32_t,
                flags,
                flags | 0x10000000u32 | 0x40000u32,
            )
            .1 as libc::c_int
                != 0
        {
            sctp_inpcb_free(inp, 1i32, 1i32);
            pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
            (*so).so_snd.sb_cc = 0u32;
            (*so).so_snd.sb_mb = 0 as *mut mbuf;
            (*so).so_snd.sb_mbcnt = 0u32;
            /* same for the rcv ones, they are only
             * here for the accounting/select.
             */
            (*so).so_rcv.sb_cc = 0u32;
            (*so).so_rcv.sb_mb = 0 as *mut mbuf;
            (*so).so_rcv.sb_mbcnt = 0u32;
            /* Now null out the reference, we are completely detached. */
            (*so).so_pcb = 0 as *mut libc::c_void; /* I'm not v6! */
            pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
            break;
        } else {
            flags = (*inp).sctp_flags;
            if !(flags & 0x10000000u32 == 0u32) {
                break;
            }
        }
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_attach(
    mut so: *mut socket,
    mut proto: libc::c_int,
    mut vrf_id: uint32_t,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut ip_inp = 0 as *mut inpcb;
    let mut error = 0;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if !inp.is_null() {
        return 22i32;
    }
    if (*so).so_snd.sb_hiwat == 0u32 || (*so).so_rcv.sb_hiwat == 0u32 {
        error = soreserve(
            so,
            system_base_info.sctpsysctl.sctp_sendspace as u_long,
            system_base_info.sctpsysctl.sctp_recvspace as u_long,
        );
        if error != 0 {
            return error;
        }
    }
    error = sctp_inpcb_alloc(so, vrf_id);
    if error != 0 {
        return error;
    }
    inp = (*so).so_pcb as *mut sctp_inpcb;
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    (*inp).sctp_flags &= !(0x4000000i32) as libc::c_uint;
    ip_inp = &mut (*inp).ip_inp.inp;
    (*ip_inp).inp_vflag = ((*ip_inp).inp_vflag as libc::c_int | 0x1i32) as u_char;
    (*ip_inp).inp_ip_ttl = ip_defttl as u_char;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_bind(mut so: *mut socket, mut addr: *mut sockaddr) -> libc::c_int {
    let mut p = 0 as *mut libc::c_void;
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 22i32;
    }
    if !addr.is_null() {
        if (*addr).sa_family as libc::c_int != 2i32 {
            return 22i32;
        }
    }
    return sctp_inpcb_bind(so, addr, 0 as *mut sctp_ifa, p as *mut proc_0);
}
#[no_mangle]
pub unsafe extern "C" fn sctpconn_attach(
    mut so: *mut socket,
    mut proto: libc::c_int,
    mut vrf_id: uint32_t,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut ip_inp = 0 as *mut inpcb;
    let mut error = 0;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if !inp.is_null() {
        return 22i32;
    }
    if (*so).so_snd.sb_hiwat == 0u32 || (*so).so_rcv.sb_hiwat == 0u32 {
        error = soreserve(
            so,
            system_base_info.sctpsysctl.sctp_sendspace as u_long,
            system_base_info.sctpsysctl.sctp_recvspace as u_long,
        );
        if error != 0 {
            return error;
        }
    }
    error = sctp_inpcb_alloc(so, vrf_id);
    if error != 0 {
        return error;
    }
    inp = (*so).so_pcb as *mut sctp_inpcb;
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    (*inp).sctp_flags &= !(0x4000000i32) as libc::c_uint;
    (*inp).sctp_flags |= 0x80000000u32;
    ip_inp = &mut (*inp).ip_inp.inp;
    (*ip_inp).inp_vflag = ((*ip_inp).inp_vflag as libc::c_int | 0x80i32) as u_char;
    (*ip_inp).inp_ip_ttl = ip_defttl as u_char;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctpconn_bind(
    mut so: *mut socket,
    mut addr: *mut sockaddr,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 22i32;
    }
    if !addr.is_null() {
        if (*addr).sa_family as libc::c_int != 123i32 {
            return 22i32;
        }
    }
    return sctp_inpcb_bind(so, addr, 0 as *mut sctp_ifa, 0 as *mut proc_0);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_close(mut so: *mut socket) {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return;
    }
    loop
    /* Inform all the lower layer assoc that we
     * are done.
     */
    {
        let mut flags = 0;
        flags = (*inp).sctp_flags;
        if flags & 0x10000000u32 == 0u32
            && ::std::intrinsics::atomic_cxchg(
                &mut (*inp).sctp_flags as *mut uint32_t,
                flags,
                flags | 0x10000000u32 | 0x40000u32,
            )
            .1 as libc::c_int
                != 0
        {
            if (*so).so_options as libc::c_int & 0x1i32 != 0
                && (*so).so_linger as libc::c_int == 0i32
                || (*so).so_rcv.sb_cc > 0u32
            {
                sctp_inpcb_free(inp, 1i32, 1i32);
            } else {
                sctp_inpcb_free(inp, 0i32, 1i32);
            }
            /* The socket is now detached, no matter what
             * the state of the SCTP association.
             */
            pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
            (*so).so_snd.sb_cc = 0u32;
            (*so).so_snd.sb_mb = 0 as *mut mbuf;
            (*so).so_snd.sb_mbcnt = 0u32;
            /* same for the rcv ones, they are only
             * here for the accounting/select.
             */
            (*so).so_rcv.sb_cc = 0u32;
            (*so).so_rcv.sb_mb = 0 as *mut mbuf;
            (*so).so_rcv.sb_mbcnt = 0u32;
            /* Now null out the reference, we are completely detached. */
            (*so).so_pcb = 0 as *mut libc::c_void;
            pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
            break;
        } else {
            flags = (*inp).sctp_flags;
            if !(flags & 0x10000000u32 == 0u32) {
                break;
            }
        }
    }
}
/* __Userspace__ is not calling sctp_sendm */
#[no_mangle]
pub unsafe extern "C" fn sctp_sendm(
    mut so: *mut socket,
    mut flags: libc::c_int,
    mut m: *mut mbuf,
    mut addr: *mut sockaddr,
    mut control: *mut mbuf,
    mut p: *mut proc_0,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut ret = 0;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        if !control.is_null() {
            m_freem(control);
            control = 0 as *mut mbuf
        }
        m_freem(m);
        return 22i32;
    }
    /* Got to have an to address if we are NOT a connected socket */
    if !(addr.is_null()
        && ((*inp).sctp_flags & 0x200000u32 != 0 || (*inp).sctp_flags & 0x2u32 != 0))
    {
        let mut error = 0;
        if addr.is_null() {
            error = 89i32;
            m_freem(m);
            if !control.is_null() {
                m_freem(control);
                control = 0 as *mut mbuf
            }
            return error;
        }
        if (*addr).sa_family as libc::c_int != 2i32 {
            /* must be a v4 address! */
            m_freem(m);
            if !control.is_null() {
                m_freem(control);
                control = 0 as *mut mbuf
            }
            error = 89i32;
            return error;
        }
    }
    /* INET6 */
    /* now what about control */
    if !control.is_null() {
        if !(*inp).control.is_null() {
            m_freem((*inp).control);
            (*inp).control = 0 as *mut mbuf
        }
        (*inp).control = control
    }
    /* Place the data */
    if !(*inp).pkt.is_null() {
        (*(*inp).pkt_last).m_hdr.mh_next = m;
        (*inp).pkt_last = m
    } else {
        (*inp).pkt = m;
        (*inp).pkt_last = (*inp).pkt
    }
    /* Open BSD does not have any "more to come"
     * indication */

    ret = sctp_output(inp, (*inp).pkt, addr, (*inp).control, p, flags);
    (*inp).pkt = 0 as *mut mbuf;
    (*inp).control = 0 as *mut mbuf;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_disconnect(mut so: *mut socket) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 107i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
        if (*inp).sctp_asoc_list.lh_first.is_null() {
            /* No connection */
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 0i32;
        } else {
            let mut asoc = 0 as *mut sctp_association;
            let mut stcb = 0 as *mut sctp_tcb;
            let mut op_err_0 = 0 as *mut mbuf;
            let mut current_block_72: u64;
            stcb = (*inp).sctp_asoc_list.lh_first;
            if stcb.is_null() {
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                return 22i32;
            }
            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
            asoc = &mut (*stcb).asoc;
            if (*stcb).asoc.state & 0x200i32 != 0 {
                /* We are about to be freed, out of here */
                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                return 0i32;
            }
            if (*so).so_options as libc::c_int & 0x1i32 != 0
                && (*so).so_linger as libc::c_int == 0i32
                || (*so).so_rcv.sb_cc > 0u32
            {
                if (*stcb).asoc.state & 0x7fi32 != 0x2i32 {
                    let mut op_err = 0 as *mut mbuf;
                    op_err = sctp_generate_cause(0xcu16, b"\x00" as *const u8 as *mut libc::c_char);
                    sctp_send_abort_tcb(stcb, op_err, 1i32);
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_aborted,
                        1u32,
                    );
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                if (*stcb).asoc.state & 0x7fi32 == 0x8i32 || (*stcb).asoc.state & 0x7fi32 == 0x20i32
                {
                    ::std::intrinsics::atomic_xsub(
                        &mut system_base_info.sctpstat.sctps_currestab,
                        1u32,
                    );
                }
                sctp_free_assoc(inp, stcb, 0i32, 0x50000000i32 + 0x3i32);
                /* No unlock tcb assoc is gone */
                return 0i32;
            }

            if (*asoc).send_queue.tqh_first.is_null()
                && (*asoc).sent_queue.tqh_first.is_null()
                && (*asoc).stream_queue_cnt == 0u32
            {
                /* there is nothing queued to send, so done */
                if Some(
                    (*asoc)
                        .ss_functions
                        .sctp_ss_is_user_msgs_incomplete
                        .expect("non-null function pointer"),
                )
                .expect("non-null function pointer")(stcb, asoc)
                    != 0
                {
                    current_block_72 = 17392462595312404741;
                } else {
                    if (*stcb).asoc.state & 0x7fi32 != 0x10i32
                        && (*stcb).asoc.state & 0x7fi32 != 0x40i32
                    {
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
                        sctp_chunk_output((*stcb).sctp_ep, stcb, 1i32, 1i32);
                    }
                    current_block_72 = 2723324002591448311;
                }
            } else {
                /*
                 * we still got (or just got) data to send,
                 * so set SHUTDOWN_PENDING
                 */
                /*
                 * XXX sockets draft says that SCTP_EOF
                 * should be sent with no data. currently,
                 * we will allow user data to be sent first
                 * and move to SHUTDOWN-PENDING
                 */
                let mut netp_0 = 0 as *mut sctp_nets;
                netp_0 = 0 as *mut sctp_nets;
                if !(*stcb).asoc.alternate.is_null() {
                    netp_0 = (*stcb).asoc.alternate
                } else {
                    netp_0 = (*stcb).asoc.primary_destination
                }
                sctp_add_substate(stcb, 0x80i32);
                sctp_timer_start(11i32, (*stcb).sctp_ep, stcb, netp_0);
                if Some(
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
                if (*asoc).send_queue.tqh_first.is_null()
                    && (*asoc).sent_queue.tqh_first.is_null()
                    && (*asoc).state & 0x400i32 != 0
                {
                    op_err_0 = 0 as *mut mbuf;
                    current_block_72 = 17392462595312404741;
                } else {
                    sctp_chunk_output(inp, stcb, 16i32, 1i32);
                    current_block_72 = 2723324002591448311;
                }
            }
            match current_block_72 {
                2723324002591448311 => {}
                _ => {
                    op_err_0 =
                        sctp_generate_cause(0xcu16, b"\x00" as *const u8 as *mut libc::c_char);
                    (*(*stcb).sctp_ep).last_abort_code = (0x50000000i32 + 0x4i32) as uint32_t;
                    sctp_send_abort_tcb(stcb, op_err_0, 1i32);
                    ::std::intrinsics::atomic_xadd(
                        &mut system_base_info.sctpstat.sctps_aborted,
                        1u32,
                    );
                    if (*stcb).asoc.state & 0x7fi32 == 0x8i32
                        || (*stcb).asoc.state & 0x7fi32 == 0x20i32
                    {
                        ::std::intrinsics::atomic_xsub(
                            &mut system_base_info.sctpstat.sctps_currestab,
                            1u32,
                        );
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    sctp_free_assoc(inp, stcb, 0i32, 0x50000000i32 + 0x5i32);
                    return 0i32;
                }
            }
            soisdisconnecting(so);
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 0i32;
        }
    /* not reached */
    } else {
        /* UDP model does not support this */
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 95i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_flush(mut so: *mut socket, mut how: libc::c_int) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 22i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    /* For the 1 to many model this does nothing */
    if (*inp).sctp_flags & 0x1u32 != 0 {
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 0i32;
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    if how == SHUT_RD as libc::c_int || how == SHUT_RDWR as libc::c_int {
        /* First make sure the sb will be happy, we don't
         * use these except maybe the count
         */
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        pthread_mutex_lock(&mut (*inp).inp_rdata_mtx);
        (*inp).sctp_flags |= 0x40000000u32;
        pthread_mutex_unlock(&mut (*inp).inp_rdata_mtx);
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        (*so).so_rcv.sb_cc = 0u32;
        (*so).so_rcv.sb_mbcnt = 0u32;
        (*so).so_rcv.sb_mb = 0 as *mut mbuf
    }
    if how == SHUT_WR as libc::c_int || how == SHUT_RDWR as libc::c_int {
        /* First make sure the sb will be happy, we don't
         * use these except maybe the count
         */
        (*so).so_snd.sb_cc = 0u32;
        (*so).so_snd.sb_mbcnt = 0u32;
        (*so).so_snd.sb_mb = 0 as *mut mbuf
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_shutdown(mut so: *mut socket) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 22i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    /* For UDP model this is a invalid call */
    if !((*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0) {
        /* Restore the flags that the soshutdown took away. */
        pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
        (*so).so_state = ((*so).so_state as libc::c_int & !(0x20i32)) as libc::c_short;
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
        /* This proc will wakeup for read and do nothing (I hope) */
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 95i32;
    } else {
        let mut stcb = 0 as *mut sctp_tcb;
        let mut asoc = 0 as *mut sctp_association;
        let mut netp = 0 as *mut sctp_nets;
        let mut op_err = 0 as *mut mbuf;
        let mut current_block_53: u64;
        if (*so).so_state as libc::c_int & (0x2i32 | 0x4i32 | 0x8i32) == 0i32 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 107i32;
        }
        socantsendmore(so);
        stcb = (*inp).sctp_asoc_list.lh_first;
        if stcb.is_null() {
            /*
             * Ok, we hit the case that the shutdown call was
             * made after an abort or something. Nothing to do
             * now.
             */
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 0i32;
        }
        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
        asoc = &mut (*stcb).asoc;
        if (*asoc).state & 0x200i32 != 0 {
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 0i32;
        }
        if (*stcb).asoc.state & 0x7fi32 != 0x2i32
            && (*stcb).asoc.state & 0x7fi32 != 0x4i32
            && (*stcb).asoc.state & 0x7fi32 != 0x8i32
        {
            /* If we are not in or before ESTABLISHED, there is
             * no protocol action required.
             */
            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 0i32;
        }
        if !(*stcb).asoc.alternate.is_null() {
            netp = (*stcb).asoc.alternate
        } else {
            netp = (*stcb).asoc.primary_destination
        }

        if (*stcb).asoc.state & 0x7fi32 == 0x8i32
            && (*asoc).send_queue.tqh_first.is_null()
            && (*asoc).sent_queue.tqh_first.is_null()
            && (*asoc).stream_queue_cnt == 0u32
        {
            if Some(
                (*asoc)
                    .ss_functions
                    .sctp_ss_is_user_msgs_incomplete
                    .expect("non-null function pointer"),
            )
            .expect("non-null function pointer")(stcb, asoc)
                != 0
            {
                current_block_53 = 15285238788721499647;
            } else {
                /* there is nothing queued to send, so I'm done... */
                ::std::intrinsics::atomic_xsub(
                    &mut system_base_info.sctpstat.sctps_currestab,
                    1u32,
                );
                sctp_set_state(stcb, 0x10i32);
                sctp_stop_timers_for_shutdown(stcb);
                sctp_send_shutdown(stcb, netp);
                sctp_timer_start(4i32, (*stcb).sctp_ep, stcb, netp);
                current_block_53 = 17747245473264231573;
            }
        } else {
            /*
             * We still got (or just got) data to send, so set
             * SHUTDOWN_PENDING.
             */
            sctp_add_substate(stcb, 0x80i32);
            if Some(
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
            if (*asoc).send_queue.tqh_first.is_null()
                && (*asoc).sent_queue.tqh_first.is_null()
                && (*asoc).state & 0x400i32 != 0
            {
                op_err = 0 as *mut mbuf;
                current_block_53 = 15285238788721499647;
            } else {
                current_block_53 = 17747245473264231573;
            }
        }
        match current_block_53 {
            17747245473264231573 => {}
            _ => {
                op_err = sctp_generate_cause(0xcu16, b"\x00" as *const u8 as *mut libc::c_char);
                (*(*stcb).sctp_ep).last_abort_code = (0x50000000i32 + 0x6i32) as uint32_t;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 1i32);
                return 0i32;
            }
        }
        sctp_timer_start(11i32, (*stcb).sctp_ep, stcb, netp);
        /* XXX: Why do this in the case where we have still data queued? */
        sctp_chunk_output(inp, stcb, 16i32, 1i32);
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 0i32;
    };
}
/*
 * copies a "user" presentable address and removes embedded scope, etc.
 * returns 0 on success, 1 on error
 */
unsafe extern "C" fn sctp_fill_user_address(
    mut ss: *mut sockaddr_storage,
    mut sa: *mut sockaddr,
) -> uint32_t {
    match (*sa).sa_family as libc::c_int {
        2 => {
            memcpy(
                ss as *mut libc::c_void,
                sa as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
            );
        }
        10 => {
            memcpy(
                ss as *mut libc::c_void,
                sa as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            );
        }
        123 => {
            memcpy(
                ss as *mut libc::c_void,
                sa as *const libc::c_void,
                ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
            );
        }
        _ => {}
    }
    return 0u32;
}
/*
 * NOTE: assumes addr lock is held
 */
unsafe extern "C" fn sctp_fill_up_addresses_vrf(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut limit: size_t,
    mut sas: *mut sockaddr_storage,
    mut vrf_id: uint32_t,
) -> size_t {
    let mut actual = 0;
    let mut loopback_scope = 0;
    let mut ipv4_local_scope = 0;
    let mut ipv4_addr_legal = 0;
    let mut local_scope = 0;
    let mut site_scope = 0;
    let mut ipv6_addr_legal = 0;
    let mut conn_addr_legal = 0;
    let mut vrf = 0 as *mut sctp_vrf;
    actual = 0u64;
    if limit <= 0u64 {
        return actual;
    }
    if !stcb.is_null() {
        /* Turn on all the appropriate scope */
        loopback_scope = (*stcb).asoc.scope.loopback_scope as libc::c_int;
        ipv4_local_scope = (*stcb).asoc.scope.ipv4_local_scope as libc::c_int;
        ipv4_addr_legal = (*stcb).asoc.scope.ipv4_addr_legal as libc::c_int;
        local_scope = (*stcb).asoc.scope.local_scope as libc::c_int;
        site_scope = (*stcb).asoc.scope.site_scope as libc::c_int;
        ipv6_addr_legal = (*stcb).asoc.scope.ipv6_addr_legal as libc::c_int;
        conn_addr_legal = (*stcb).asoc.scope.conn_addr_legal as libc::c_int
    } else {
        /* Use generic values for endpoints. */
        loopback_scope = 1i32;
        ipv4_local_scope = 1i32;
        local_scope = 1i32;
        site_scope = 1i32;
        if (*inp).sctp_flags & 0x4000000u32 != 0 {
            ipv6_addr_legal = 1i32;
            if (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0 {
                ipv4_addr_legal = 0i32
            } else {
                ipv4_addr_legal = 1i32
            }
            conn_addr_legal = 0i32
        } else {
            ipv6_addr_legal = 0i32;
            if (*inp).sctp_flags & 0x80000000u32 != 0 {
                conn_addr_legal = 1i32;
                ipv4_addr_legal = 0i32
            } else {
                conn_addr_legal = 0i32;
                ipv4_addr_legal = 1i32
            }
        }
    }
    vrf = sctp_find_vrf(vrf_id);
    if vrf.is_null() {
        return 0u64;
    }
    if (*inp).sctp_flags & 0x4u32 != 0 {
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
                    let mut current_block_74: u64;
                    if !stcb.is_null() {
                        /*
                         * For the BOUND-ALL case, the list
                         * associated with a TCB is Always
                         * considered a reverse list.. i.e.
                         * it lists addresses that are NOT
                         * part of the association. If this
                         * is one of those we must skip it.
                         */
                        if sctp_is_addr_restricted(stcb, sctp_ifa) != 0 {
                            current_block_74 = 1847472278776910194;
                        } else {
                            current_block_74 = 2989495919056355252;
                        }
                    } else {
                        current_block_74 = 2989495919056355252;
                    }
                    match current_block_74 {
                        2989495919056355252 => {
                            match (*sctp_ifa).address.sa.sa_family as libc::c_int {
                                2 => {
                                    current_block_74 = 12666208562138404485;
                                    match current_block_74 {
                                        4196477696038023414 => {
                                            if conn_addr_legal != 0 {
                                                if actual.wrapping_add(::std::mem::size_of::<
                                                    sockaddr_conn,
                                                >(
                                                )
                                                    as libc::c_ulong)
                                                    > limit
                                                {
                                                    return actual;
                                                }
                                                memcpy(
                                                    sas as *mut libc::c_void,
                                                    &mut (*sctp_ifa).address.sconn
                                                        as *mut sockaddr_conn
                                                        as *const libc::c_void,
                                                    ::std::mem::size_of::<sockaddr_conn>()
                                                        as libc::c_ulong,
                                                );
                                                (*(sas as *mut sockaddr_conn)).sconn_port =
                                                    (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport;
                                                sas = (sas as caddr_t)
                                                    .offset(::std::mem::size_of::<sockaddr_conn>()
                                                        as isize)
                                                    as *mut sockaddr_storage;
                                                actual =
                                                    (actual).wrapping_add(::std::mem::size_of::<
                                                        sockaddr_conn,
                                                    >(
                                                    )
                                                        as libc::c_ulong)
                                            }
                                        }
                                        12666208562138404485 => {
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
                                                        if (*inp).sctp_features & 0x800000u64
                                                            == 0x800000u64
                                                        {
                                                            if actual.wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as libc::c_ulong,
                                                            ) > limit
                                                            {
                                                                return actual;
                                                            }
                                                            in6_sin_2_v4mapsin6(
                                                                sin,
                                                                sas as *mut sockaddr_in6,
                                                            );
                                                            (*(sas as *mut sockaddr_in6))
                                                                .sin6_port = (*inp)
                                                                .ip_inp
                                                                .inp
                                                                .inp_inc
                                                                .inc_ie
                                                                .ie_lport;
                                                            sas = (sas as caddr_t).offset(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as isize,
                                                            )
                                                                as *mut sockaddr_storage;
                                                            actual = (actual).wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as libc::c_ulong,
                                                            )
                                                        } else {
                                                            if actual.wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            ) > limit
                                                            {
                                                                return actual;
                                                            }
                                                            memcpy(
                                                                sas as *mut libc::c_void,
                                                                sin as *const libc::c_void,
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            );
                                                            (*(sas as *mut sockaddr_in)).sin_port =
                                                                (*inp)
                                                                    .ip_inp
                                                                    .inp
                                                                    .inp_inc
                                                                    .inc_ie
                                                                    .ie_lport;
                                                            sas = (sas as caddr_t).offset(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as isize,
                                                            )
                                                                as *mut sockaddr_storage;
                                                            actual = (actual).wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            )
                                                        }
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
                                                        && (*__a).__in6_u.__u6_addr32[1usize]
                                                            == 0u32
                                                        && (*__a).__in6_u.__u6_addr32[2usize]
                                                            == 0u32
                                                        && (*__a).__in6_u.__u6_addr32[3usize]
                                                            == 0u32)
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
                                                            current_block_74 = 1847472278776910194;
                                                        } else {
                                                            current_block_74 = 10778260831612459202;
                                                        }
                                                    /* SCTP_EMBEDDED_V6_SCOPE */
                                                    } else {
                                                        current_block_74 = 10778260831612459202;
                                                    }
                                                    match current_block_74 {
                                                        1847472278776910194 => {}
                                                        _ => {
                                                            if !(site_scope == 0i32
                                                                && ({
                                                                    let mut __a = &mut (*sin6)
                                                                        .sin6_addr
                                                                        as *mut in6_addr
                                                                        as *const in6_addr;
                                                                    ((*__a).__in6_u.__u6_addr32
                                                                        [0usize]
                                                                        & htonl(0xffc00000u32)
                                                                        == htonl(0xfec00000u32))
                                                                        as libc::c_int
                                                                }) != 0)
                                                            {
                                                                if actual.wrapping_add(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                ) > limit
                                                                {
                                                                    return actual;
                                                                }
                                                                memcpy(
                                                                    sas as *mut libc::c_void,
                                                                    sin6 as *const libc::c_void,
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                );
                                                                (*(sas as *mut sockaddr_in6))
                                                                    .sin6_port = (*inp)
                                                                    .ip_inp
                                                                    .inp
                                                                    .inp_inc
                                                                    .inc_ie
                                                                    .ie_lport;
                                                                sas = (sas as caddr_t).offset(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as isize,
                                                                )
                                                                    as *mut sockaddr_storage;
                                                                actual = (actual).wrapping_add(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                )
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                10 => {
                                    current_block_74 = 9477695138712184283;
                                    match current_block_74 {
                                        4196477696038023414 => {
                                            if conn_addr_legal != 0 {
                                                if actual.wrapping_add(::std::mem::size_of::<
                                                    sockaddr_conn,
                                                >(
                                                )
                                                    as libc::c_ulong)
                                                    > limit
                                                {
                                                    return actual;
                                                }
                                                memcpy(
                                                    sas as *mut libc::c_void,
                                                    &mut (*sctp_ifa).address.sconn
                                                        as *mut sockaddr_conn
                                                        as *const libc::c_void,
                                                    ::std::mem::size_of::<sockaddr_conn>()
                                                        as libc::c_ulong,
                                                );
                                                (*(sas as *mut sockaddr_conn)).sconn_port =
                                                    (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport;
                                                sas = (sas as caddr_t)
                                                    .offset(::std::mem::size_of::<sockaddr_conn>()
                                                        as isize)
                                                    as *mut sockaddr_storage;
                                                actual =
                                                    (actual).wrapping_add(::std::mem::size_of::<
                                                        sockaddr_conn,
                                                    >(
                                                    )
                                                        as libc::c_ulong)
                                            }
                                        }
                                        12666208562138404485 => {
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
                                                        if (*inp).sctp_features & 0x800000u64
                                                            == 0x800000u64
                                                        {
                                                            if actual.wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as libc::c_ulong,
                                                            ) > limit
                                                            {
                                                                return actual;
                                                            }
                                                            in6_sin_2_v4mapsin6(
                                                                sin,
                                                                sas as *mut sockaddr_in6,
                                                            );
                                                            (*(sas as *mut sockaddr_in6))
                                                                .sin6_port = (*inp)
                                                                .ip_inp
                                                                .inp
                                                                .inp_inc
                                                                .inc_ie
                                                                .ie_lport;
                                                            sas = (sas as caddr_t).offset(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as isize,
                                                            )
                                                                as *mut sockaddr_storage;
                                                            actual = (actual).wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as libc::c_ulong,
                                                            )
                                                        } else {
                                                            if actual.wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            ) > limit
                                                            {
                                                                return actual;
                                                            }
                                                            memcpy(
                                                                sas as *mut libc::c_void,
                                                                sin as *const libc::c_void,
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            );
                                                            (*(sas as *mut sockaddr_in)).sin_port =
                                                                (*inp)
                                                                    .ip_inp
                                                                    .inp
                                                                    .inp_inc
                                                                    .inc_ie
                                                                    .ie_lport;
                                                            sas = (sas as caddr_t).offset(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as isize,
                                                            )
                                                                as *mut sockaddr_storage;
                                                            actual = (actual).wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            )
                                                        }
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
                                                        && (*__a).__in6_u.__u6_addr32[1usize]
                                                            == 0u32
                                                        && (*__a).__in6_u.__u6_addr32[2usize]
                                                            == 0u32
                                                        && (*__a).__in6_u.__u6_addr32[3usize]
                                                            == 0u32)
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
                                                            current_block_74 = 1847472278776910194;
                                                        } else {
                                                            current_block_74 = 10778260831612459202;
                                                        }
                                                    } else {
                                                        current_block_74 = 10778260831612459202;
                                                    }
                                                    match current_block_74 {
                                                        1847472278776910194 => {}
                                                        _ => {
                                                            if !(site_scope == 0i32
                                                                && ({
                                                                    let mut __a = &mut (*sin6)
                                                                        .sin6_addr
                                                                        as *mut in6_addr
                                                                        as *const in6_addr;
                                                                    ((*__a).__in6_u.__u6_addr32
                                                                        [0usize]
                                                                        & htonl(0xffc00000u32)
                                                                        == htonl(0xfec00000u32))
                                                                        as libc::c_int
                                                                }) != 0)
                                                            {
                                                                if actual.wrapping_add(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                ) > limit
                                                                {
                                                                    return actual;
                                                                }
                                                                memcpy(
                                                                    sas as *mut libc::c_void,
                                                                    sin6 as *const libc::c_void,
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                );
                                                                (*(sas as *mut sockaddr_in6))
                                                                    .sin6_port = (*inp)
                                                                    .ip_inp
                                                                    .inp
                                                                    .inp_inc
                                                                    .inc_ie
                                                                    .ie_lport;
                                                                sas = (sas as caddr_t).offset(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as isize,
                                                                )
                                                                    as *mut sockaddr_storage;
                                                                actual = (actual).wrapping_add(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                )
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                123 => {
                                    current_block_74 = 4196477696038023414;
                                    match current_block_74 {
                                        4196477696038023414 => {
                                            if conn_addr_legal != 0 {
                                                if actual.wrapping_add(::std::mem::size_of::<
                                                    sockaddr_conn,
                                                >(
                                                )
                                                    as libc::c_ulong)
                                                    > limit
                                                {
                                                    return actual;
                                                }
                                                memcpy(
                                                    sas as *mut libc::c_void,
                                                    &mut (*sctp_ifa).address.sconn
                                                        as *mut sockaddr_conn
                                                        as *const libc::c_void,
                                                    ::std::mem::size_of::<sockaddr_conn>()
                                                        as libc::c_ulong,
                                                );
                                                (*(sas as *mut sockaddr_conn)).sconn_port =
                                                    (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport;
                                                sas = (sas as caddr_t)
                                                    .offset(::std::mem::size_of::<sockaddr_conn>()
                                                        as isize)
                                                    as *mut sockaddr_storage;
                                                actual =
                                                    (actual).wrapping_add(::std::mem::size_of::<
                                                        sockaddr_conn,
                                                    >(
                                                    )
                                                        as libc::c_ulong)
                                            }
                                        }
                                        12666208562138404485 => {
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
                                                        if (*inp).sctp_features & 0x800000u64
                                                            == 0x800000u64
                                                        {
                                                            if actual.wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as libc::c_ulong,
                                                            ) > limit
                                                            {
                                                                return actual;
                                                            }
                                                            in6_sin_2_v4mapsin6(
                                                                sin,
                                                                sas as *mut sockaddr_in6,
                                                            );
                                                            (*(sas as *mut sockaddr_in6))
                                                                .sin6_port = (*inp)
                                                                .ip_inp
                                                                .inp
                                                                .inp_inc
                                                                .inc_ie
                                                                .ie_lport;
                                                            sas = (sas as caddr_t).offset(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as isize,
                                                            )
                                                                as *mut sockaddr_storage;
                                                            actual = (actual).wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in6>(
                                                                )
                                                                    as libc::c_ulong,
                                                            )
                                                        } else {
                                                            if actual.wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            ) > limit
                                                            {
                                                                return actual;
                                                            }
                                                            memcpy(
                                                                sas as *mut libc::c_void,
                                                                sin as *const libc::c_void,
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            );
                                                            (*(sas as *mut sockaddr_in)).sin_port =
                                                                (*inp)
                                                                    .ip_inp
                                                                    .inp
                                                                    .inp_inc
                                                                    .inc_ie
                                                                    .ie_lport;
                                                            sas = (sas as caddr_t).offset(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as isize,
                                                            )
                                                                as *mut sockaddr_storage;
                                                            actual = (actual).wrapping_add(
                                                                ::std::mem::size_of::<sockaddr_in>()
                                                                    as libc::c_ulong,
                                                            )
                                                        }
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
                                                        && (*__a).__in6_u.__u6_addr32[1usize]
                                                            == 0u32
                                                        && (*__a).__in6_u.__u6_addr32[2usize]
                                                            == 0u32
                                                        && (*__a).__in6_u.__u6_addr32[3usize]
                                                            == 0u32)
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
                                                            current_block_74 = 1847472278776910194;
                                                        } else {
                                                            current_block_74 = 10778260831612459202;
                                                        }
                                                    } else {
                                                        current_block_74 = 10778260831612459202;
                                                    }
                                                    match current_block_74 {
                                                        1847472278776910194 => {}
                                                        _ => {
                                                            if !(site_scope == 0i32
                                                                && ({
                                                                    let mut __a = &mut (*sin6)
                                                                        .sin6_addr
                                                                        as *mut in6_addr
                                                                        as *const in6_addr;
                                                                    ((*__a).__in6_u.__u6_addr32
                                                                        [0usize]
                                                                        & htonl(0xffc00000u32)
                                                                        == htonl(0xfec00000u32))
                                                                        as libc::c_int
                                                                }) != 0)
                                                            {
                                                                if actual.wrapping_add(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                ) > limit
                                                                {
                                                                    return actual;
                                                                }
                                                                memcpy(
                                                                    sas as *mut libc::c_void,
                                                                    sin6 as *const libc::c_void,
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                );
                                                                (*(sas as *mut sockaddr_in6))
                                                                    .sin6_port = (*inp)
                                                                    .ip_inp
                                                                    .inp
                                                                    .inp_inc
                                                                    .inc_ie
                                                                    .ie_lport;
                                                                sas = (sas as caddr_t).offset(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as isize,
                                                                )
                                                                    as *mut sockaddr_storage;
                                                                actual = (actual).wrapping_add(
                                                                    ::std::mem::size_of::<
                                                                        sockaddr_in6,
                                                                    >(
                                                                    )
                                                                        as libc::c_ulong,
                                                                )
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
                        _ => {}
                    }
                    /* TSNH */
                    sctp_ifa = (*sctp_ifa).next_ifa.le_next
                }
            }
            /* Skip loopback if loopback_scope not set */
            sctp_ifn = (*sctp_ifn).next_ifn.le_next
        }
    } else {
        let mut laddr = 0 as *mut sctp_laddr;
        laddr = (*inp).sctp_addr_list.lh_first;
        while !laddr.is_null() {
            let mut current_block_92: u64;
            if !stcb.is_null() {
                if sctp_is_addr_restricted(stcb, (*laddr).ifa) != 0 {
                    current_block_92 = 562309032768341766;
                } else {
                    current_block_92 = 5697748000427295508;
                }
            } else {
                current_block_92 = 5697748000427295508;
            }
            match current_block_92 {
                5697748000427295508 => {
                    let mut sa_len = 0;
                    match (*(*laddr).ifa).address.sa.sa_family as libc::c_int {
                        2 => sa_len = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                        10 => sa_len = ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                        123 => sa_len = ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
                        _ => {
                            /* TSNH */
                            sa_len = 0u64
                        }
                    }
                    if actual.wrapping_add(sa_len) > limit {
                        return actual;
                    }
                    if !(sctp_fill_user_address(sas, &mut (*(*laddr).ifa).address.sa) != 0) {
                        match (*(*laddr).ifa).address.sa.sa_family as libc::c_int {
                            2 => {
                                (*(sas as *mut sockaddr_in)).sin_port =
                                    (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport
                            }
                            10 => {
                                (*(sas as *mut sockaddr_in6)).sin6_port =
                                    (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport
                            }
                            123 => {
                                (*(sas as *mut sockaddr_conn)).sconn_port =
                                    (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport
                            }
                            _ => {}
                        }
                        sas = (sas as caddr_t).offset(sa_len as isize) as *mut sockaddr_storage;
                        actual = (actual).wrapping_add(sa_len)
                    }
                }
                _ => {}
            }
            laddr = (*laddr).sctp_nxt_addr.le_next
        }
    }
    return actual;
}
unsafe extern "C" fn sctp_fill_up_addresses(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut limit: size_t,
    mut sas: *mut sockaddr_storage,
) -> size_t {
    let mut size = 0u64;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    /* fill up addresses for the endpoint's default vrf */
    size = sctp_fill_up_addresses_vrf(inp, stcb, limit, sas, (*inp).def_vrf_id);
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    return size;
}
/*
 * NOTE: assumes addr lock is held
 */
unsafe extern "C" fn sctp_count_max_addresses_vrf(
    mut inp: *mut sctp_inpcb,
    mut vrf_id: uint32_t,
) -> libc::c_int {
    let mut cnt = 0i32;
    let mut vrf = 0 as *mut sctp_vrf;
    /*
     * In both sub-set bound an bound_all cases we return the MAXIMUM
     * number of addresses that you COULD get. In reality the sub-set
     * bound may have an exclusion list for a given TCB OR in the
     * bound-all case a TCB may NOT include the loopback or other
     * addresses as well.
     */
    vrf = sctp_find_vrf(vrf_id);
    if vrf.is_null() {
        return 0i32;
    }
    if (*inp).sctp_flags & 0x4u32 != 0 {
        let mut sctp_ifn = 0 as *mut sctp_ifn;
        sctp_ifn = (*vrf).ifnlist.lh_first;
        while !sctp_ifn.is_null() {
            let mut sctp_ifa = 0 as *mut sctp_ifa;
            sctp_ifa = (*sctp_ifn).ifalist.lh_first;
            while !sctp_ifa.is_null() {
                /* Count them if they are the right type */
                match (*sctp_ifa).address.sa.sa_family as libc::c_int {
                    2 => {
                        if (*inp).sctp_features & 0x800000u64 == 0x800000u64 {
                            cnt = (cnt as libc::c_ulong).wrapping_add(::std::mem::size_of::<
                                sockaddr_in6,
                            >(
                            )
                                as libc::c_ulong) as libc::c_int
                        } else {
                            cnt =
                                (cnt as libc::c_ulong).wrapping_add(
                                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                                ) as libc::c_int
                        }
                    }
                    10 => {
                        cnt = (cnt as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong)
                            as libc::c_int
                    }
                    123 => {
                        cnt = (cnt as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong)
                            as libc::c_int
                    }
                    _ => {}
                }
                sctp_ifa = (*sctp_ifa).next_ifa.le_next
            }
            sctp_ifn = (*sctp_ifn).next_ifn.le_next
        }
    } else {
        let mut laddr = 0 as *mut sctp_laddr;
        laddr = (*inp).sctp_addr_list.lh_first;
        while !laddr.is_null() {
            match (*(*laddr).ifa).address.sa.sa_family as libc::c_int {
                2 => {
                    if (*inp).sctp_features & 0x800000u64 == 0x800000u64 {
                        cnt = (cnt as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong)
                            as libc::c_int
                    } else {
                        cnt = (cnt as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong)
                            as libc::c_int
                    }
                }
                10 => {
                    cnt = (cnt as libc::c_ulong)
                        .wrapping_add(::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong)
                        as libc::c_int
                }
                123 => {
                    cnt = (cnt as libc::c_ulong)
                        .wrapping_add(::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong)
                        as libc::c_int
                }
                _ => {}
            }
            laddr = (*laddr).sctp_nxt_addr.le_next
        }
    }
    return cnt;
}
unsafe extern "C" fn sctp_count_max_addresses(mut inp: *mut sctp_inpcb) -> libc::c_int {
    let mut cnt = 0i32;
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    /* count addresses for the endpoint's default VRF */
    cnt = sctp_count_max_addresses_vrf(inp, (*inp).def_vrf_id);
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    return cnt;
}
unsafe extern "C" fn sctp_do_connect_x(
    mut so: *mut socket,
    mut inp: *mut sctp_inpcb,
    mut optval: *mut libc::c_void,
    mut optsize: size_t,
    mut p: *mut libc::c_void,
    mut delay: libc::c_int,
) -> libc::c_int {
    let mut error = 0;
    let mut creat_lock_on = 0i32;
    let mut stcb = 0 as *mut sctp_tcb;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x100000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"Connectx called\n\x00" as *const u8 as *const libc::c_char,
            );
        }
    }
    if (*inp).sctp_flags & 0x2u32 != 0 && (*inp).sctp_flags & 0x200000u32 != 0 {
        /* We are already connected AND the TCP model */
        return 98i32;
    }
    if (*inp).sctp_flags & 0x400000u32 != 0 && (*inp).sctp_features & 0x2000000u64 == 0u64 {
        return 22i32;
    }
    if (*inp).sctp_flags & 0x200000u32 != 0 {
        pthread_mutex_lock(&mut (*inp).inp_mtx);
        stcb = (*inp).sctp_asoc_list.lh_first;
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
    }
    if !stcb.is_null() {
        return 114i32;
    }
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
    pthread_mutex_lock(&mut (*inp).inp_create_mtx);
    creat_lock_on = 1i32;
    if (*inp).sctp_flags & 0x20000000u32 != 0 || (*inp).sctp_flags & 0x10000000u32 != 0 {
        error = 14i32
    } else {
        let mut sa = 0 as *mut sockaddr;
        let mut num_v6 = 0u32;
        let mut num_v4 = 0u32;
        let mut totaddrp = 0 as *mut libc::c_uint;
        let mut totaddr = 0;
        totaddrp = optval as *mut libc::c_uint;
        totaddr = *totaddrp;
        sa = totaddrp.offset(1isize) as *mut sockaddr;
        error = sctp_connectx_helper_find(
            inp,
            sa,
            totaddr,
            &mut num_v4,
            &mut num_v6,
            optsize.wrapping_sub(::std::mem::size_of::<libc::c_int>() as libc::c_ulong)
                as libc::c_uint,
        );
        if error != 0i32 {
            /* Already have or am bring up an association */
            pthread_mutex_unlock(&mut (*inp).inp_create_mtx);
            creat_lock_on = 0i32
        } else if (*inp).sctp_flags & 0x4000000u32 == 0u32 && num_v6 > 0u32 {
            error = 22i32
        } else {
            let mut current_block: u64;
            if (*inp).sctp_flags & 0x4000000u32 != 0 && num_v4 > 0u32 {
                if (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0 {
                    /*
                     * if IPV6_V6ONLY flag, ignore connections destined
                     * to a v4 addr or v4-mapped addr
                     */
                    error = 22i32;
                    current_block = 2427635823446356100;
                } else {
                    current_block = 2989495919056355252;
                }
            } else {
                current_block = 2989495919056355252;
            }
            match current_block {
                2427635823446356100 => {}
                _ =>
                /* INET6 */
                {
                    if (*inp).sctp_flags & 0x10u32 == 0x10u32 {
                        /* Bind a ephemeral port */
                        error = sctp_inpcb_bind(
                            so,
                            0 as *mut sockaddr,
                            0 as *mut sctp_ifa,
                            p as *mut proc_0,
                        );
                        if error != 0 {
                            current_block = 2427635823446356100;
                        } else {
                            current_block = 5892776923941496671;
                        }
                    } else {
                        current_block = 5892776923941496671;
                    }
                    match current_block {
                        2427635823446356100 => {}
                        _ => {
                            let mut vrf_id = 0;
                            vrf_id = (*inp).def_vrf_id;
                            /* We are GOOD to go */
                            stcb = sctp_aloc_assoc(
                                inp,
                                sa,
                                &mut error,
                                0u32,
                                vrf_id,
                                (*inp).sctp_ep.pre_open_stream_count,
                                (*inp).sctp_ep.port,
                                p as *mut proc_0,
                                1i32,
                            );
                            if !stcb.is_null() {
                                if (*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0 {
                                    (*(*stcb).sctp_ep).sctp_flags |= 0x200000u32;
                                    /* Set the connected flag so we can queue data */
                                    soisconnecting(so);
                                }
                                sctp_set_state(stcb, 0x2i32);
                                /* move to second address */
                                match (*sa).sa_family as libc::c_int {
                                    2 => {
                                        sa = (sa as caddr_t)
                                            .offset(::std::mem::size_of::<sockaddr_in>() as isize)
                                            as *mut sockaddr
                                    }
                                    10 => {
                                        sa =
                                            (sa as caddr_t).offset(
                                                ::std::mem::size_of::<sockaddr_in6>() as isize,
                                            )
                                                as *mut sockaddr
                                    }
                                    _ => {}
                                }
                                error = 0i32;
                                sctp_connectx_helper_add(
                                    stcb,
                                    sa,
                                    totaddr.wrapping_sub(1u32) as libc::c_int,
                                    &mut error,
                                );
                                /* Fill in the return id */
                                if !(error != 0) {
                                    let mut a_id = 0 as *mut sctp_assoc_t;
                                    a_id = optval as *mut sctp_assoc_t;
                                    *a_id = (*stcb).asoc.assoc_id;
                                    if delay != 0 {
                                        /* doing delayed connection */
                                        (*stcb).asoc.delayed_connection = 1u8;
                                        sctp_timer_start(
                                            2i32,
                                            inp,
                                            stcb,
                                            (*stcb).asoc.primary_destination,
                                        );
                                    } else {
                                        gettimeofday(
                                            &mut (*stcb).asoc.time_entered,
                                            0 as *mut timezone,
                                        );
                                        sctp_send_initiate(inp, stcb, 1i32);
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    /* Gak! no memory */
    if creat_lock_on != 0 {
        pthread_mutex_unlock(&mut (*inp).inp_create_mtx); /* end switch (sopt->sopt_name) */
    } /* end switch (sopt->sopt_name) */
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_getopt(
    mut so: *mut socket,
    mut optname: libc::c_int,
    mut optval: *mut libc::c_void,
    mut optsize: *mut size_t,
    mut p: *mut libc::c_void,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut error = 0;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut current_block_2022: u64;
    if optval.is_null() {
        return 22i32;
    }
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 22i32;
    }
    error = 0i32;

    match optname {
        4 | 5 | 27 | 24 | 9 | 13 | 23 => {
            let mut val = 0i32;
            pthread_mutex_lock(&mut (*inp).inp_mtx);
            match optname {
                9 => {
                    val = ((*inp).sctp_features & 0x100000u64 == 0x100000u64) as libc::c_int;
                    current_block_2022 = 7333393191927787629;
                }
                13 => {
                    val = ((*inp).sctp_features & 0x800000u64 == 0x800000u64) as libc::c_int;
                    current_block_2022 = 7333393191927787629;
                }
                24 => {
                    if (*inp).sctp_flags & 0x4u32 != 0 {
                        /* only valid for bound all sockets */
                        val = ((*inp).sctp_features & 0x40u64 == 0x40u64) as libc::c_int;
                        current_block_2022 = 7333393191927787629;
                    } else {
                        error = 22i32;
                        current_block_2022 = 1398496724659307859;
                    }
                }
                27 => {
                    val = ((*inp).sctp_features & 0x400000u64 == 0x400000u64) as libc::c_int;
                    current_block_2022 = 7333393191927787629;
                }
                4 => {
                    val = ((*inp).sctp_features & 0x100u64 == 0x100u64) as libc::c_int;
                    current_block_2022 = 7333393191927787629;
                }
                23 => {
                    val = ((*inp).sctp_features & 0x2u64 == 0x2u64) as libc::c_int;
                    current_block_2022 = 7333393191927787629;
                }
                5 => {
                    if (*inp).sctp_features & 0x200u64 == 0x200u64 {
                        val = ((*inp).sctp_ep.auto_close_time + (hz - 1i32)) / hz
                    } else {
                        val = 0i32
                    }
                    current_block_2022 = 7333393191927787629;
                }
                _ => {
                    error = 92i32;
                    current_block_2022 = 7333393191927787629;
                }
            }
            match current_block_2022 {
                7333393191927787629 => {
                    if *optsize < ::std::mem::size_of::<libc::c_int>() as libc::c_ulong {
                        error = 22i32
                    }
                }
                _ => {}
            }
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            if error == 0i32 {
                /* return the option value */
                *(optval as *mut libc::c_int) = val;
                *optsize = ::std::mem::size_of::<libc::c_int>() as libc::c_ulong
            }
        }
        16385 => error = 95i32,
        28 => {
            if (*inp).sctp_flags & 0x1u32 != 0 {
                /* Can't do this for a 1-m socket */
                error = 22i32
            } else if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value = 0 as *mut uint32_t;
                value = optval as *mut uint32_t;
                *value = ((*inp).sctp_features & 0x2000000u64 == 0x2000000u64) as uint32_t;
                *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
            }
        }
        17 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_0 = 0 as *mut uint32_t;
                value_0 = optval as *mut uint32_t;
                *value_0 = (*inp).partial_delivery_point;
                *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
            }
        }
        16 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_1 = 0 as *mut uint32_t;
                value_1 = optval as *mut uint32_t;
                if (*inp).sctp_features & 0x8u64 == 0x8u64 {
                    if (*inp).sctp_features & 0x10u64 == 0x10u64 {
                        *value_1 = 0x2u32
                    } else {
                        *value_1 = 0x1u32
                    }
                } else {
                    *value_1 = 0u32
                }
                *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
            }
        }
        4614 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av = 0 as *mut sctp_assoc_value;
                av = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 6528931666172833996;
                } else if (*av).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 6528931666172833996;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 6528931666172833996;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av).assoc_value = (*stcb).asoc.idata_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*inp).idata_supported != 0 {
                                (*av).assoc_value = 1u32
                            } else {
                                (*av).assoc_value = 0u32
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        4608 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_0 = 0 as *mut sctp_assoc_value;
                av_0 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 1745632252074978848;
                } else if (*av_0).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_0).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 1745632252074978848;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 1745632252074978848;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_0).assoc_value = (*stcb).asoc.sctp_cmt_on_off as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_0).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_0).assoc_value = (*inp).sctp_cmt_on_off;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        4610 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_1 = 0 as *mut sctp_assoc_value;
                av_1 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 4877859826192283278;
                } else if (*av_1).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_1).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 4877859826192283278;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 4877859826192283278;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_1).assoc_value = (*stcb).asoc.congestion_control_module;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_1).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_1).assoc_value = (*inp).sctp_ep.sctp_default_cc_module;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        4613 => {
            if *optsize < ::std::mem::size_of::<sctp_cc_option>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut cc_opt = 0 as *mut sctp_cc_option;
                cc_opt = optval as *mut sctp_cc_option;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 6160215453157368027;
                } else if (*cc_opt).aid_value.assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*cc_opt).aid_value.assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 6160215453157368027;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 6160215453157368027;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if stcb.is_null() {
                            error = 22i32
                        } else {
                            if (*stcb).asoc.cc_functions.sctp_cwnd_socket_option.is_none() {
                                error = 95i32
                            } else {
                                error = Some(
                                    (*stcb)
                                        .asoc
                                        .cc_functions
                                        .sctp_cwnd_socket_option
                                        .expect("non-null function pointer"),
                                )
                                .expect("non-null function pointer")(
                                    stcb, 0i32, cc_opt
                                );
                                *optsize = ::std::mem::size_of::<sctp_cc_option>() as libc::c_ulong
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
            }
        }
        4611 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_2 = 0 as *mut sctp_assoc_value;
                av_2 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 9190931632177426379;
                } else if (*av_2).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_2).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 9190931632177426379;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 9190931632177426379;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_2).assoc_value = (*stcb).asoc.stream_scheduling_module;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_2).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_2).assoc_value = (*inp).sctp_ep.sctp_default_ss_module;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        4612 => {
            if *optsize < ::std::mem::size_of::<sctp_stream_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_3 = 0 as *mut sctp_stream_value;
                av_3 = optval as *mut sctp_stream_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 5333604943833105405;
                } else if (*av_3).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_3).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 5333604943833105405;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 5333604943833105405;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            if (*av_3).stream_id as libc::c_int
                                >= (*stcb).asoc.streamoutcnt as libc::c_int
                                || (*stcb)
                                    .asoc
                                    .ss_functions
                                    .sctp_ss_get_value
                                    .expect("non-null function pointer")(
                                    stcb,
                                    &mut (*stcb).asoc,
                                    &mut *(*stcb).asoc.strmout.offset((*av_3).stream_id as isize),
                                    &mut (*av_3).stream_value,
                                ) < 0i32
                            {
                                error = 22i32
                            } else {
                                *optsize =
                                    ::std::mem::size_of::<sctp_stream_value>() as libc::c_ulong
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            /* Can't get stream value without association */
                            error = 22i32
                        }
                    }
                }
            }
        }
        32779 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_4 = 0 as *mut sctp_assoc_value;
                av_4 = optval as *mut sctp_assoc_value;
                error = 22i32;
                if (*av_4).assoc_value == 2u32 {
                    (*av_4).assoc_value = ::std::mem::size_of::<sockaddr_in>() as uint32_t;
                    error = 0i32
                }
                if (*av_4).assoc_value == 10u32 {
                    (*av_4).assoc_value = ::std::mem::size_of::<sockaddr_in6>() as uint32_t;
                    error = 0i32
                }
                if (*av_4).assoc_value == 123u32 {
                    (*av_4).assoc_value = ::std::mem::size_of::<sockaddr_conn>() as uint32_t;
                    error = 0i32
                }
                if !(error != 0) {
                    *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                }
            }
        }
        260 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_2 = 0 as *mut uint32_t;
                value_2 = optval as *mut uint32_t;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    /* Can't do this for a 1-1 socket */
                    error = 22i32;
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                } else {
                    let mut cnt = 0;
                    cnt = 0u32;
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    while !stcb.is_null() {
                        cnt = cnt.wrapping_add(1);
                        stcb = (*stcb).sctp_tcblist.le_next
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    *value_2 = cnt;
                    *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
                }
            }
        }
        261 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_ids>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut ids = 0 as *mut sctp_assoc_ids;
                ids = optval as *mut sctp_assoc_ids;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    /* Can't do this for a 1-1 socket */
                    error = 22i32;
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                } else {
                    let mut at = 0;
                    let mut limit = 0;
                    at = 0u32;
                    limit = (*optsize)
                        .wrapping_sub(::std::mem::size_of::<uint32_t>() as libc::c_ulong)
                        .wrapping_div(::std::mem::size_of::<sctp_assoc_t>() as libc::c_ulong);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    while !stcb.is_null() {
                        if (at as libc::c_ulong) < limit {
                            let fresh0 = at;
                            at = at.wrapping_add(1);
                            *(*ids).gaids_assoc_id.as_mut_ptr().offset(fresh0 as isize) =
                                (*stcb).asoc.assoc_id;
                            if at == 0u32 {
                                error = 22i32;
                                break;
                            } else {
                                stcb = (*stcb).sctp_tcblist.le_next
                            }
                        } else {
                            error = 22i32;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    if error == 0i32 {
                        (*ids).gaids_number_of_ids = at;
                        *optsize = (at as libc::c_ulong)
                            .wrapping_mul(::std::mem::size_of::<sctp_assoc_t>() as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<uint32_t>() as libc::c_ulong)
                    }
                }
            }
        }
        26 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_5 = 0 as *mut sctp_assoc_value;
                av_5 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 3271669279804889922;
                } else if (*av_5).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_5).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 3271669279804889922;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 3271669279804889922;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_5).assoc_value = (*stcb).asoc.context;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_5).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_5).assoc_value = (*inp).sctp_context;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        12289 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut default_vrfid = 0 as *mut uint32_t;
                default_vrfid = optval as *mut uint32_t;
                *default_vrfid = (*inp).def_vrf_id;
                *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
            }
        }
        12292 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut id = 0 as *mut sctp_assoc_value;
                id = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 4692175290644916;
                } else if (*id).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*id).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 4692175290644916;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 4692175290644916;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if stcb.is_null() {
                            error = 22i32
                        } else {
                            (*id).assoc_value = (*stcb).asoc.vrf_id;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        12291 => error = 95i32,
        4357 => {
            if *optsize < ::std::mem::size_of::<sctp_get_nonce_values>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut gnv = 0 as *mut sctp_get_nonce_values;
                gnv = optval as *mut sctp_get_nonce_values;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 6452958575495017105;
                } else if (*gnv).gn_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*gnv).gn_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 6452958575495017105;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 6452958575495017105;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*gnv).gn_peers_tag = (*stcb).asoc.peer_vtag;
                            (*gnv).gn_local_tag = (*stcb).asoc.my_vtag;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *optsize =
                                ::std::mem::size_of::<sctp_get_nonce_values>() as libc::c_ulong
                        } else {
                            error = 107i32
                        }
                    }
                }
            }
        }
        15 => {
            if *optsize < ::std::mem::size_of::<sctp_sack_info>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sack = 0 as *mut sctp_sack_info;
                sack = optval as *mut sctp_sack_info;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 16765645543215489601;
                } else if (*sack).sack_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sack).sack_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 16765645543215489601;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 16765645543215489601;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*sack).sack_delay = (*stcb).asoc.delayed_ack;
                            (*sack).sack_freq = (*stcb).asoc.sack_freq;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*sack).sack_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*sack).sack_delay = if hz == 1000i32 {
                                (*inp).sctp_ep.sctp_timeoutticks[1usize]
                            } else {
                                (*inp).sctp_ep.sctp_timeoutticks[1usize]
                                    .wrapping_mul(1000u32)
                                    .wrapping_add((hz - 1i32) as libc::c_uint)
                                    .wrapping_div(hz as libc::c_uint)
                            };
                            (*sack).sack_freq = (*inp).sctp_ep.sctp_sack_freq;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_sack_info>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        4353 => {
            if *optsize < ::std::mem::size_of::<sctp_sockstat>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut ss = 0 as *mut sctp_sockstat;
                ss = optval as *mut sctp_sockstat;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 7157832835667413340;
                } else if (*ss).ss_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*ss).ss_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 7157832835667413340;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 7157832835667413340;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*ss).ss_total_sndbuf = (*stcb).asoc.total_output_queue_size;
                            (*ss).ss_total_recv_buf = (*stcb)
                                .asoc
                                .size_on_reasm_queue
                                .wrapping_add((*stcb).asoc.size_on_all_streams);
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *optsize = ::std::mem::size_of::<sctp_sockstat>() as libc::c_ulong
                        } else {
                            error = 107i32
                        }
                    }
                }
            }
        }
        25 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_6 = 0 as *mut sctp_assoc_value;
                av_6 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 10734601898397913838;
                } else if (*av_6).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_6).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 10734601898397913838;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 10734601898397913838;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_6).assoc_value = (*stcb).asoc.max_burst;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_6).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_6).assoc_value = (*inp).sctp_ep.max_burst;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        14 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_7 = 0 as *mut sctp_assoc_value;
                av_7 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 88367834180715325;
                } else if (*av_7).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_7).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 88367834180715325;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 88367834180715325;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_7).assoc_value =
                                sctp_get_frag_point(stcb, &mut (*stcb).asoc) as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_7).assoc_id == 0u32
                        {
                            let mut ovh = 0;
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*inp).sctp_flags & 0x4000000u32 != 0 {
                                ovh = (::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong)
                                    .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                                    .wrapping_add(::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
                                    as libc::c_int
                            } else {
                                ovh = (::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong)
                                    .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                                    .wrapping_add(::std::mem::size_of::<ip>() as libc::c_ulong)
                                    as libc::c_int
                            }
                            if (*inp).sctp_frag_point >= 65535u32 {
                                (*av_7).assoc_value = 0u32
                            } else {
                                (*av_7).assoc_value =
                                    (*inp).sctp_frag_point.wrapping_sub(ovh as libc::c_uint)
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        4355 => error = sctp_fill_stat_log(optval, optsize),
        12 => {
            if *optsize < ::std::mem::size_of::<sctp_event_subscribe>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut events = 0 as *mut sctp_event_subscribe;
                events = optval as *mut sctp_event_subscribe;
                memset(
                    events as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<sctp_event_subscribe>() as libc::c_ulong,
                );
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if (*inp).sctp_features & 0x400u64 == 0x400u64 {
                    (*events).sctp_data_io_event = 1u8
                }
                if (*inp).sctp_features & 0x800u64 == 0x800u64 {
                    (*events).sctp_association_event = 1u8
                }
                if (*inp).sctp_features & 0x1000u64 == 0x1000u64 {
                    (*events).sctp_address_event = 1u8
                }
                if (*inp).sctp_features & 0x4000u64 == 0x4000u64 {
                    (*events).sctp_send_failure_event = 1u8
                }
                if (*inp).sctp_features & 0x2000u64 == 0x2000u64 {
                    (*events).sctp_peer_error_event = 1u8
                }
                if (*inp).sctp_features & 0x8000u64 == 0x8000u64 {
                    (*events).sctp_shutdown_event = 1u8
                }
                if (*inp).sctp_features & 0x20000u64 == 0x20000u64 {
                    (*events).sctp_partial_delivery_event = 1u8
                }
                if (*inp).sctp_features & 0x10000u64 == 0x10000u64 {
                    (*events).sctp_adaptation_layer_event = 1u8
                }
                if (*inp).sctp_features & 0x40000u64 == 0x40000u64 {
                    (*events).sctp_authentication_event = 1u8
                }
                if (*inp).sctp_features & 0x4000000u64 == 0x4000000u64 {
                    (*events).sctp_sender_dry_event = 1u8
                }
                if (*inp).sctp_features & 0x80000u64 == 0x80000u64 {
                    (*events).sctp_stream_reset_event = 1u8
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *optsize = ::std::mem::size_of::<sctp_event_subscribe>() as libc::c_ulong
            }
        }
        8 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_3 = 0 as *mut uint32_t;
                value_3 = optval as *mut uint32_t;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                *value_3 = (*inp).sctp_ep.adaptation_layer_indicator;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
            }
        }
        40704 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_4 = 0 as *mut uint32_t;
                value_4 = optval as *mut uint32_t;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                *value_4 = (*inp).sctp_ep.initial_sequence_debug;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
            }
        }
        32773 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_5 = 0 as *mut uint32_t;
                value_5 = optval as *mut uint32_t;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                *value_5 = sctp_count_max_addresses(inp) as uint32_t;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
            }
        }
        32774 => {
            if *optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_6 = 0 as *mut uint32_t;
                value_6 = optval as *mut uint32_t;
                /* FIXME MT: change to sctp_assoc_value? */
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 9162433269210840852;
                } else if *value_6 > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, *value_6, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 9162433269210840852;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 9162433269210840852;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            let mut size = 0;
                            let mut net = 0 as *mut sctp_nets;
                            size = 0u64;
                            /* Count the sizes */
                            net = (*stcb).asoc.nets.tqh_first;
                            while !net.is_null() {
                                match (*net).ro._l_addr.sa.sa_family as libc::c_int {
                                    2 => {
                                        if (*inp).sctp_features & 0x800000u64 == 0x800000u64 {
                                            size = (size).wrapping_add(::std::mem::size_of::<
                                                sockaddr_in6,
                                            >(
                                            )
                                                as libc::c_ulong)
                                        } else {
                                            size = (size).wrapping_add(::std::mem::size_of::<
                                                sockaddr_in,
                                            >(
                                            )
                                                as libc::c_ulong)
                                        }
                                    }
                                    10 => {
                                        size = (size)
                                            .wrapping_add(::std::mem::size_of::<sockaddr_in6>()
                                                as libc::c_ulong)
                                    }
                                    123 => {
                                        size = (size).wrapping_add(::std::mem::size_of::<
                                            sockaddr_conn,
                                        >(
                                        )
                                            as libc::c_ulong)
                                    }
                                    _ => {}
                                }
                                net = (*net).sctp_next.tqe_next
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *value_6 = size as uint32_t;
                            *optsize = ::std::mem::size_of::<uint32_t>() as libc::c_ulong
                        } else {
                            error = 107i32
                        }
                    }
                }
            }
        }
        32771 => {
            if *optsize < ::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut saddr = 0 as *mut sctp_getaddresses;
                saddr = optval as *mut sctp_getaddresses;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 5221102643273385055;
                } else if (*saddr).sget_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*saddr).sget_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 5221102643273385055;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 5221102643273385055;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            let mut left = 0;
                            let mut sas = 0 as *mut sockaddr_storage;
                            let mut net_0 = 0 as *mut sctp_nets;
                            left = (*optsize).wrapping_sub(
                                ::std::mem::size_of::<sctp_assoc_t>() as libc::c_ulong
                            );
                            *optsize = ::std::mem::size_of::<sctp_assoc_t>() as libc::c_ulong;
                            sas = &mut *(*saddr).addr.as_mut_ptr().offset(0isize) as *mut sockaddr
                                as *mut sockaddr_storage;
                            net_0 = (*stcb).asoc.nets.tqh_first;
                            while !net_0.is_null() {
                                let mut cpsz = 0;
                                match (*net_0).ro._l_addr.sa.sa_family as libc::c_int {
                                    2 => {
                                        if (*inp).sctp_features & 0x800000u64 == 0x800000u64 {
                                            cpsz = ::std::mem::size_of::<sockaddr_in6>()
                                                as libc::c_ulong
                                        } else {
                                            cpsz = ::std::mem::size_of::<sockaddr_in>()
                                                as libc::c_ulong
                                        }
                                    }
                                    10 => {
                                        cpsz =
                                            ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong
                                    }
                                    123 => {
                                        cpsz =
                                            ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong
                                    }
                                    _ => cpsz = 0u64,
                                }
                                if cpsz == 0u64 {
                                    break;
                                }
                                if left < cpsz {
                                    break;
                                }
                                if (*inp).sctp_features & 0x800000u64 == 0x800000u64
                                    && (*net_0).ro._l_addr.sa.sa_family as libc::c_int == 2i32
                                {
                                    /* Must map the address */
                                    in6_sin_2_v4mapsin6(
                                        &mut (*net_0).ro._l_addr.sin,
                                        sas as *mut sockaddr_in6,
                                    );
                                } else {
                                    memcpy(
                                        sas as *mut libc::c_void,
                                        &mut (*net_0).ro._l_addr as *mut sctp_sockstore
                                            as *const libc::c_void,
                                        cpsz,
                                    );
                                }
                                (*(sas as *mut sockaddr_in)).sin_port = (*stcb).rport;
                                sas =
                                    (sas as caddr_t).offset(cpsz as isize) as *mut sockaddr_storage;
                                left = (left).wrapping_sub(cpsz);
                                *optsize = (*optsize).wrapping_add(cpsz);
                                net_0 = (*net_0).sctp_next.tqe_next
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            error = 2i32
                        }
                    }
                }
            }
        }
        32772 => {
            if *optsize < ::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut saddr_0 = 0 as *mut sctp_getaddresses;
                saddr_0 = optval as *mut sctp_getaddresses;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 4485404170685685882;
                } else if (*saddr_0).sget_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*saddr_0).sget_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 4485404170685685882;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 4485404170685685882;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut limit_0 = 0;
                        let mut actual = 0;
                        let mut sas_0 = 0 as *mut sockaddr_storage;
                        sas_0 = &mut *(*saddr_0).addr.as_mut_ptr().offset(0isize) as *mut sockaddr
                            as *mut sockaddr_storage;
                        limit_0 = (*optsize)
                            .wrapping_sub(::std::mem::size_of::<sctp_assoc_t>() as libc::c_ulong);
                        actual = sctp_fill_up_addresses(inp, stcb, limit_0, sas_0);
                        if !stcb.is_null() {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                        *optsize = (::std::mem::size_of::<sctp_assoc_t>() as libc::c_ulong)
                            .wrapping_add(actual)
                    }
                }
            }
        }
        10 => {
            if *optsize < ::std::mem::size_of::<sctp_paddrparams>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut paddrp = 0 as *mut sctp_paddrparams;
                paddrp = optval as *mut sctp_paddrparams;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 7609407440601820123;
                } else if (*paddrp).spp_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*paddrp).spp_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 7609407440601820123;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 7609407440601820123;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut net_1 = 0 as *mut sctp_nets;
                        let mut addr = 0 as *mut sockaddr;
                        if (*paddrp).spp_address.ss_family as libc::c_int == 10i32 {
                            let mut sin6 = 0 as *mut sockaddr_in6;
                            sin6 = &mut (*paddrp).spp_address as *mut sockaddr_storage
                                as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store, sin6);
                                addr = &mut sin_store as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr = &mut (*paddrp).spp_address as *mut sockaddr_storage
                                    as *mut sockaddr
                            }
                        } else {
                            addr =
                                &mut (*paddrp).spp_address as *mut sockaddr_storage as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_1 = sctp_findnet(stcb, addr)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_1 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr,
                                &mut net_1,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && net_1.is_null() {
                            if (*addr).sa_family as libc::c_int == 2i32 {
                                let mut sin = 0 as *mut sockaddr_in;
                                sin = addr as *mut sockaddr_in;
                                if (*sin).sin_addr.s_addr != 0u32 {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 4796264792789571185;
                                }
                            } else if (*addr).sa_family as libc::c_int == 10i32 {
                                let mut sin6_0 = 0 as *mut sockaddr_in6;
                                sin6_0 = addr as *mut sockaddr_in6;
                                if ({
                                    let mut __a = &mut (*sin6_0).sin6_addr as *mut in6_addr
                                        as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                        as libc::c_int
                                }) == 0
                                {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 4796264792789571185;
                                }
                            } else if (*addr).sa_family as libc::c_int == 123i32 {
                                let mut sconn = 0 as *mut sockaddr_conn;
                                sconn = addr as *mut sockaddr_conn;
                                if !(*sconn).sconn_addr.is_null() {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 4796264792789571185;
                                }
                            } else {
                                error = 97i32;
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                current_block_2022 = 7666136661722410625;
                            }
                        } else {
                            current_block_2022 = 4796264792789571185;
                        }
                        match current_block_2022 {
                            7666136661722410625 => {}
                            _ => {
                                if !stcb.is_null() {
                                    /* Applies to the specific association */
                                    (*paddrp).spp_flags = 0u32;
                                    if !net_1.is_null() {
                                        (*paddrp).spp_hbinterval = (*net_1).heart_beat_delay;
                                        (*paddrp).spp_pathmaxrxt = (*net_1).failure_threshold;
                                        (*paddrp).spp_pathmtu = (*net_1).mtu;
                                        match (*net_1).ro._l_addr.sa.sa_family as libc::c_int {
                                            2 => {
                                                (*paddrp).spp_pathmtu =
                                                    ((*paddrp).spp_pathmtu as libc::c_ulong)
                                                        .wrapping_sub(
                                                            (::std::mem::size_of::<ip>()
                                                                as libc::c_ulong)
                                                                .wrapping_add(
                                                                    ::std::mem::size_of::<sctphdr>()
                                                                        as libc::c_ulong,
                                                                ),
                                                        )
                                                        as uint32_t
                                            }
                                            10 => {
                                                (*paddrp).spp_pathmtu =
                                                    ((*paddrp).spp_pathmtu as libc::c_ulong)
                                                        .wrapping_sub(
                                                            (::std::mem::size_of::<ip6_hdr>()
                                                                as libc::c_ulong)
                                                                .wrapping_add(
                                                                    ::std::mem::size_of::<sctphdr>()
                                                                        as libc::c_ulong,
                                                                ),
                                                        )
                                                        as uint32_t
                                            }
                                            123 => {
                                                (*paddrp).spp_pathmtu = ((*paddrp).spp_pathmtu
                                                    as libc::c_ulong)
                                                    .wrapping_sub(::std::mem::size_of::<sctphdr>()
                                                        as libc::c_ulong)
                                                    as uint32_t
                                            }
                                            _ => {}
                                        }
                                        /* get flags for HB */
                                        if (*net_1).dest_state as libc::c_int & 0x4i32 != 0 {
                                            (*paddrp).spp_flags |= 0x2u32
                                        } else {
                                            (*paddrp).spp_flags |= 0x1u32
                                        }
                                        /* get flags for PMTU */
                                        if (*net_1).dest_state as libc::c_int & 0x2i32 != 0 {
                                            (*paddrp).spp_flags |= 0x10u32
                                        } else {
                                            (*paddrp).spp_flags |= 0x8u32
                                        }
                                        if (*net_1).dscp as libc::c_int & 0x1i32 != 0 {
                                            (*paddrp).spp_dscp =
                                                ((*net_1).dscp as libc::c_int & 0xfci32) as uint8_t;
                                            (*paddrp).spp_flags |= 0x200u32
                                        }
                                        if (*net_1).ro._l_addr.sa.sa_family as libc::c_int == 10i32
                                            && (*net_1).flowlabel & 0x80000000u32 != 0
                                        {
                                            (*paddrp).spp_ipv6_flowlabel =
                                                (*net_1).flowlabel & 0xfffffu32;
                                            (*paddrp).spp_flags |= 0x100u32
                                        }
                                    } else {
                                        /*
                                         * No destination so return default
                                         * value
                                         */
                                        (*paddrp).spp_pathmaxrxt = (*stcb).asoc.def_net_failure;
                                        (*paddrp).spp_pathmtu = (*stcb).asoc.default_mtu;
                                        if (*stcb).asoc.default_dscp as libc::c_int & 0x1i32 != 0 {
                                            (*paddrp).spp_dscp = ((*stcb).asoc.default_dscp
                                                as libc::c_int
                                                & 0xfci32)
                                                as uint8_t;
                                            (*paddrp).spp_flags |= 0x200u32
                                        }
                                        if (*stcb).asoc.default_flowlabel & 0x80000000u32 != 0 {
                                            (*paddrp).spp_ipv6_flowlabel =
                                                (*stcb).asoc.default_flowlabel & 0xfffffu32;
                                            (*paddrp).spp_flags |= 0x100u32
                                        }
                                        /* default settings should be these */
                                        if !stcb.is_null()
                                            && (*stcb).asoc.sctp_features & 0x4u64 == 0x4u64
                                            || stcb.is_null()
                                                && !inp.is_null()
                                                && (*inp).sctp_features & 0x4u64 == 0x4u64
                                        {
                                            (*paddrp).spp_flags |= 0x2u32
                                        } else {
                                            (*paddrp).spp_flags |= 0x1u32
                                        }
                                        if !stcb.is_null()
                                            && (*stcb).asoc.sctp_features & 0x1u64 == 0x1u64
                                            || stcb.is_null()
                                                && !inp.is_null()
                                                && (*inp).sctp_features & 0x1u64 == 0x1u64
                                        {
                                            (*paddrp).spp_flags |= 0x10u32
                                        } else {
                                            (*paddrp).spp_flags |= 0x8u32
                                        }
                                        (*paddrp).spp_hbinterval = (*stcb).asoc.heart_beat_delay
                                    }
                                    (*paddrp).spp_assoc_id = (*stcb).asoc.assoc_id;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                } else if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && (*paddrp).spp_assoc_id == 0u32
                                {
                                    /* Use endpoint defaults */
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*paddrp).spp_pathmaxrxt = (*inp).sctp_ep.def_net_failure;
                                    (*paddrp).spp_hbinterval = if hz == 1000i32 {
                                        (*inp).sctp_ep.sctp_timeoutticks[3usize]
                                    } else {
                                        (*inp).sctp_ep.sctp_timeoutticks[3usize]
                                            .wrapping_mul(1000u32)
                                            .wrapping_add((hz - 1i32) as libc::c_uint)
                                            .wrapping_div(hz as libc::c_uint)
                                    };
                                    (*paddrp).spp_assoc_id = 0u32;
                                    /* get inp's default */
                                    if (*inp).sctp_ep.default_dscp as libc::c_int & 0x1i32 != 0 {
                                        (*paddrp).spp_dscp =
                                            ((*inp).sctp_ep.default_dscp as libc::c_int & 0xfci32)
                                                as uint8_t;
                                        (*paddrp).spp_flags |= 0x200u32
                                    }
                                    if (*inp).sctp_flags & 0x4000000u32 != 0
                                        && (*inp).sctp_ep.default_flowlabel & 0x80000000u32 != 0
                                    {
                                        (*paddrp).spp_ipv6_flowlabel =
                                            (*inp).sctp_ep.default_flowlabel & 0xfffffu32;
                                        (*paddrp).spp_flags |= 0x100u32
                                    }
                                    (*paddrp).spp_pathmtu = (*inp).sctp_ep.default_mtu;
                                    if (*inp).sctp_features & 0x4u64 == 0u64 {
                                        (*paddrp).spp_flags |= 0x1u32
                                    } else {
                                        (*paddrp).spp_flags |= 0x2u32
                                    }
                                    if (*inp).sctp_features & 0x1u64 == 0u64 {
                                        (*paddrp).spp_flags |= 0x8u32
                                    } else {
                                        (*paddrp).spp_flags |= 0x10u32
                                    }
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                } else {
                                    error = 22i32
                                }
                                if error == 0i32 {
                                    *optsize =
                                        ::std::mem::size_of::<sctp_paddrparams>() as libc::c_ulong
                                }
                            }
                        }
                    }
                }
            }
        }
        257 => {
            if *optsize < ::std::mem::size_of::<sctp_paddrinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut paddri = 0 as *mut sctp_paddrinfo;
                paddri = optval as *mut sctp_paddrinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 1033529924362675109;
                } else if (*paddri).spinfo_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*paddri).spinfo_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 1033529924362675109;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 1033529924362675109;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut net_2 = 0 as *mut sctp_nets;
                        let mut addr_0 = 0 as *mut sockaddr;
                        if (*paddri).spinfo_address.ss_family as libc::c_int == 10i32 {
                            let mut sin6_1 = 0 as *mut sockaddr_in6;
                            sin6_1 = &mut (*paddri).spinfo_address as *mut sockaddr_storage
                                as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6_1).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store_0 = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store_0, sin6_1);
                                addr_0 = &mut sin_store_0 as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr_0 = &mut (*paddri).spinfo_address as *mut sockaddr_storage
                                    as *mut sockaddr
                            }
                        } else {
                            addr_0 = &mut (*paddri).spinfo_address as *mut sockaddr_storage
                                as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_2 = sctp_findnet(stcb, addr_0)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_2 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr_0,
                                &mut net_2,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && !net_2.is_null() {
                            if (*net_2).dest_state as libc::c_int & 0x200i32 != 0 {
                                /* It's unconfirmed */
                                (*paddri).spinfo_state = 0x200i32
                            } else if (*net_2).dest_state as libc::c_int & 0x1i32 != 0 {
                                /* It's active */
                                (*paddri).spinfo_state = 0x1i32
                            } else {
                                /* It's inactive */
                                (*paddri).spinfo_state = 0x2i32
                            }
                            (*paddri).spinfo_cwnd = (*net_2).cwnd;
                            (*paddri).spinfo_srtt = ((*net_2).lastsa >> 3i32) as uint32_t;
                            (*paddri).spinfo_rto = (*net_2).RTO;
                            (*paddri).spinfo_assoc_id = (*stcb).asoc.assoc_id;
                            (*paddri).spinfo_mtu = (*net_2).mtu;
                            match (*addr_0).sa_family as libc::c_int {
                                2 => {
                                    (*paddri).spinfo_mtu =
                                        ((*paddri).spinfo_mtu as libc::c_ulong).wrapping_sub(
                                            (::std::mem::size_of::<ip>() as libc::c_ulong)
                                                .wrapping_add(::std::mem::size_of::<sctphdr>()
                                                    as libc::c_ulong),
                                        ) as uint32_t
                                }
                                10 => {
                                    (*paddri).spinfo_mtu =
                                        ((*paddri).spinfo_mtu as libc::c_ulong).wrapping_sub(
                                            (::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
                                                .wrapping_add(::std::mem::size_of::<sctphdr>()
                                                    as libc::c_ulong),
                                        ) as uint32_t
                                }
                                123 => {
                                    (*paddri).spinfo_mtu =
                                        ((*paddri).spinfo_mtu as libc::c_ulong).wrapping_sub(
                                            ::std::mem::size_of::<sctphdr>() as libc::c_ulong,
                                        ) as uint32_t
                                }
                                _ => {}
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *optsize = ::std::mem::size_of::<sctp_paddrinfo>() as libc::c_ulong
                        } else {
                            if !stcb.is_null() {
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            }
                            error = 2i32
                        }
                    }
                }
            }
        }
        4356 => {
            if *optsize < ::std::mem::size_of::<sctp_pcbinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut spcb = 0 as *mut sctp_pcbinfo;
                spcb = optval as *mut sctp_pcbinfo;
                sctp_fill_pcbinfo(spcb);
                *optsize = ::std::mem::size_of::<sctp_pcbinfo>() as libc::c_ulong
            }
        }
        256 => {
            if *optsize < ::std::mem::size_of::<sctp_status>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sstat = 0 as *mut sctp_status;
                sstat = optval as *mut sctp_status;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 9752185128335110756;
                } else if (*sstat).sstat_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sstat).sstat_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 9752185128335110756;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 9752185128335110756;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if stcb.is_null() {
                            error = 22i32
                        } else {
                            let mut net_3 = 0 as *mut sctp_nets;
                            (*sstat).sstat_state = sctp_map_assoc_state((*stcb).asoc.state);
                            (*sstat).sstat_assoc_id = (*stcb).asoc.assoc_id;
                            (*sstat).sstat_rwnd = (*stcb).asoc.peers_rwnd;
                            (*sstat).sstat_unackdata = (*stcb).asoc.sent_queue_cnt as uint16_t;
                            /*
                             * We can't include chunks that have been passed to
                             * the socket layer. Only things in queue.
                             */
                            (*sstat).sstat_penddata = (*stcb)
                                .asoc
                                .cnt_on_reasm_queue
                                .wrapping_add((*stcb).asoc.cnt_on_all_streams)
                                as uint16_t;
                            (*sstat).sstat_instrms = (*stcb).asoc.streamincnt;
                            (*sstat).sstat_outstrms = (*stcb).asoc.streamoutcnt;
                            (*sstat).sstat_fragmentation_point =
                                sctp_get_frag_point(stcb, &mut (*stcb).asoc) as uint32_t;
                            net_3 = (*stcb).asoc.primary_destination;
                            if !net_3.is_null() {
                                if (*(*stcb).asoc.primary_destination).ro._l_addr.sa.sa_family
                                    as libc::c_int
                                    == 2i32
                                {
                                    memcpy(
                                        &mut (*sstat).sstat_primary.spinfo_address
                                            as *mut sockaddr_storage
                                            as *mut libc::c_void,
                                        &mut (*(*stcb).asoc.primary_destination).ro._l_addr
                                            as *mut sctp_sockstore
                                            as *const libc::c_void,
                                        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                                    );
                                } else {
                                    memcpy(
                                        &mut (*sstat).sstat_primary.spinfo_address
                                            as *mut sockaddr_storage
                                            as *mut libc::c_void,
                                        &mut (*(*stcb).asoc.primary_destination).ro._l_addr
                                            as *mut sctp_sockstore
                                            as *const libc::c_void,
                                        ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                                    );
                                }
                                (*(&mut (*sstat).sstat_primary.spinfo_address
                                    as *mut sockaddr_storage
                                    as *mut sockaddr_in))
                                    .sin_port = (*stcb).rport;
                                /*
                                 * Again the user can get info from sctp_constants.h
                                 * for what the state of the network is.
                                 */
                                if (*net_3).dest_state as libc::c_int & 0x200i32 != 0 {
                                    /* It's unconfirmed */
                                    (*sstat).sstat_primary.spinfo_state = 0x200i32
                                } else if (*net_3).dest_state as libc::c_int & 0x1i32 != 0 {
                                    /* It's active */
                                    (*sstat).sstat_primary.spinfo_state = 0x1i32
                                } else {
                                    /* It's inactive */
                                    (*sstat).sstat_primary.spinfo_state = 0x2i32
                                }
                                (*sstat).sstat_primary.spinfo_cwnd = (*net_3).cwnd;
                                (*sstat).sstat_primary.spinfo_srtt =
                                    ((*net_3).lastsa >> 3i32) as uint32_t;
                                (*sstat).sstat_primary.spinfo_rto = (*net_3).RTO;
                                (*sstat).sstat_primary.spinfo_mtu = (*net_3).mtu;
                                match (*(*stcb).asoc.primary_destination).ro._l_addr.sa.sa_family
                                    as libc::c_int
                                {
                                    2 => {
                                        (*sstat).sstat_primary.spinfo_mtu = ((*sstat)
                                            .sstat_primary
                                            .spinfo_mtu
                                            as libc::c_ulong)
                                            .wrapping_sub(
                                                (::std::mem::size_of::<ip>() as libc::c_ulong)
                                                    .wrapping_add(::std::mem::size_of::<sctphdr>()
                                                        as libc::c_ulong),
                                            )
                                            as uint32_t
                                    }
                                    10 => {
                                        (*sstat).sstat_primary.spinfo_mtu = ((*sstat)
                                            .sstat_primary
                                            .spinfo_mtu
                                            as libc::c_ulong)
                                            .wrapping_sub(
                                                (::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
                                                    .wrapping_add(::std::mem::size_of::<sctphdr>()
                                                        as libc::c_ulong),
                                            )
                                            as uint32_t
                                    }
                                    123 => {
                                        (*sstat).sstat_primary.spinfo_mtu =
                                            ((*sstat).sstat_primary.spinfo_mtu as libc::c_ulong)
                                                .wrapping_sub(::std::mem::size_of::<sctphdr>()
                                                    as libc::c_ulong)
                                                as uint32_t
                                    }
                                    _ => {}
                                }
                            } else {
                                memset(
                                    &mut (*sstat).sstat_primary as *mut sctp_paddrinfo
                                        as *mut libc::c_void,
                                    0i32,
                                    ::std::mem::size_of::<sctp_paddrinfo>() as libc::c_ulong,
                                );
                            }
                            (*sstat).sstat_primary.spinfo_assoc_id = (*stcb).asoc.assoc_id;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *optsize = ::std::mem::size_of::<sctp_status>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        1 => {
            if *optsize < ::std::mem::size_of::<sctp_rtoinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut srto = 0 as *mut sctp_rtoinfo;
                srto = optval as *mut sctp_rtoinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 12150205307204879056;
                } else if (*srto).srto_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*srto).srto_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 12150205307204879056;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 12150205307204879056;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*srto).srto_initial = (*stcb).asoc.initial_rto;
                            (*srto).srto_max = (*stcb).asoc.maxrto;
                            (*srto).srto_min = (*stcb).asoc.minrto;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*srto).srto_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*srto).srto_initial = (*inp).sctp_ep.initial_rto;
                            (*srto).srto_max = (*inp).sctp_ep.sctp_maxrto;
                            (*srto).srto_min = (*inp).sctp_ep.sctp_minrto;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_rtoinfo>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        262 => {
            if *optsize < ::std::mem::size_of::<sctp_timeouts>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut stimo = 0 as *mut sctp_timeouts;
                stimo = optval as *mut sctp_timeouts;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 14669082715419004533;
                } else if (*stimo).stimo_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*stimo).stimo_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 14669082715419004533;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 14669082715419004533;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*stimo).stimo_init = (*stcb).asoc.timoinit;
                            (*stimo).stimo_data = (*stcb).asoc.timodata;
                            (*stimo).stimo_sack = (*stcb).asoc.timosack;
                            (*stimo).stimo_shutdown = (*stcb).asoc.timoshutdown;
                            (*stimo).stimo_heartbeat = (*stcb).asoc.timoheartbeat;
                            (*stimo).stimo_cookie = (*stcb).asoc.timocookie;
                            (*stimo).stimo_shutdownack = (*stcb).asoc.timoshutdownack;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *optsize = ::std::mem::size_of::<sctp_timeouts>() as libc::c_ulong
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        2 => {
            if *optsize < ::std::mem::size_of::<sctp_assocparams>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sasoc = 0 as *mut sctp_assocparams;
                sasoc = optval as *mut sctp_assocparams;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 11609557072037522120;
                } else if (*sasoc).sasoc_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sasoc).sasoc_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 11609557072037522120;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 11609557072037522120;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*sasoc).sasoc_cookie_life = if hz == 1000i32 {
                                (*stcb).asoc.cookie_life
                            } else {
                                (*stcb)
                                    .asoc
                                    .cookie_life
                                    .wrapping_mul(1000u32)
                                    .wrapping_add((hz - 1i32) as libc::c_uint)
                                    .wrapping_div(hz as libc::c_uint)
                            };
                            (*sasoc).sasoc_asocmaxrxt = (*stcb).asoc.max_send_times;
                            (*sasoc).sasoc_number_peer_destinations =
                                (*stcb).asoc.numnets as uint16_t;
                            (*sasoc).sasoc_peer_rwnd = (*stcb).asoc.peers_rwnd;
                            (*sasoc).sasoc_local_rwnd = (*stcb).asoc.my_rwnd;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*sasoc).sasoc_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*sasoc).sasoc_cookie_life = if hz == 1000i32 {
                                (*inp).sctp_ep.def_cookie_life
                            } else {
                                (*inp)
                                    .sctp_ep
                                    .def_cookie_life
                                    .wrapping_mul(1000u32)
                                    .wrapping_add((hz - 1i32) as libc::c_uint)
                                    .wrapping_div(hz as libc::c_uint)
                            };
                            (*sasoc).sasoc_asocmaxrxt = (*inp).sctp_ep.max_send_times;
                            (*sasoc).sasoc_number_peer_destinations = 0u16;
                            (*sasoc).sasoc_peer_rwnd = 0u32;
                            (*sasoc).sasoc_local_rwnd = if (*(*inp).sctp_socket)
                                .so_rcv
                                .sb_hiwat
                                .wrapping_sub((*(*inp).sctp_socket).so_rcv.sb_cc)
                                as libc::c_int
                                > (*(*inp).sctp_socket)
                                    .so_rcv
                                    .sb_mbmax
                                    .wrapping_sub((*(*inp).sctp_socket).so_rcv.sb_mbcnt)
                                    as libc::c_int
                            {
                                (*(*inp).sctp_socket)
                                    .so_rcv
                                    .sb_mbmax
                                    .wrapping_sub((*(*inp).sctp_socket).so_rcv.sb_mbcnt)
                                    as libc::c_int
                            } else {
                                (*(*inp).sctp_socket)
                                    .so_rcv
                                    .sb_hiwat
                                    .wrapping_sub((*(*inp).sctp_socket).so_rcv.sb_cc)
                                    as libc::c_int
                            } as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assocparams>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        11 => {
            if *optsize < ::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut s_info = 0 as *mut sctp_sndrcvinfo;
                s_info = optval as *mut sctp_sndrcvinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 8509181542506876999;
                } else if (*s_info).sinfo_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*s_info).sinfo_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 8509181542506876999;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 8509181542506876999;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            memcpy(
                                s_info as *mut libc::c_void,
                                &mut (*stcb).asoc.def_send as *mut sctp_nonpad_sndrcvinfo
                                    as *const libc::c_void,
                                ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>() as libc::c_ulong,
                            );
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*s_info).sinfo_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            memcpy(
                                s_info as *mut libc::c_void,
                                &mut (*inp).def_send as *mut sctp_nonpad_sndrcvinfo
                                    as *const libc::c_void,
                                ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>() as libc::c_ulong,
                            );
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        3 => {
            if *optsize < ::std::mem::size_of::<sctp_initmsg>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sinit = 0 as *mut sctp_initmsg;
                sinit = optval as *mut sctp_initmsg;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                (*sinit).sinit_num_ostreams = (*inp).sctp_ep.pre_open_stream_count;
                (*sinit).sinit_max_instreams = (*inp).sctp_ep.max_open_streams_intome;
                (*sinit).sinit_max_attempts = (*inp).sctp_ep.max_init_times;
                (*sinit).sinit_max_init_timeo = (*inp).sctp_ep.initial_init_rto_max as uint16_t;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                *optsize = ::std::mem::size_of::<sctp_initmsg>() as libc::c_ulong
            }
        }
        7 => {
            if *optsize < ::std::mem::size_of::<sctp_setprim>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut ssp = 0 as *mut sctp_setprim;
                ssp = optval as *mut sctp_setprim;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 10614326310622419317;
                } else if (*ssp).ssp_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*ssp).ssp_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 10614326310622419317;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 10614326310622419317;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            let mut addr_1 = 0 as *mut sctp_sockstore;
                            addr_1 = &mut (*(*stcb).asoc.primary_destination).ro._l_addr;
                            match (*addr_1).sa.sa_family as libc::c_int {
                                2 => {
                                    if (*inp).sctp_features & 0x800000u64 == 0x800000u64 {
                                        in6_sin_2_v4mapsin6(
                                            &mut (*addr_1).sin,
                                            &mut (*ssp).ssp_addr as *mut sockaddr_storage
                                                as *mut sockaddr_in6,
                                        );
                                    } else {
                                        memcpy(
                                            &mut (*ssp).ssp_addr as *mut sockaddr_storage
                                                as *mut libc::c_void,
                                            &mut (*addr_1).sin as *mut sockaddr_in
                                                as *const libc::c_void,
                                            ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                                        );
                                    }
                                }
                                10 => {
                                    memcpy(
                                        &mut (*ssp).ssp_addr as *mut sockaddr_storage
                                            as *mut libc::c_void,
                                        &mut (*addr_1).sin6 as *mut sockaddr_in6
                                            as *const libc::c_void,
                                        ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                                    );
                                }
                                123 => {
                                    memcpy(
                                        &mut (*ssp).ssp_addr as *mut sockaddr_storage
                                            as *mut libc::c_void,
                                        &mut (*addr_1).sconn as *mut sockaddr_conn
                                            as *const libc::c_void,
                                        ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
                                    );
                                }
                                _ => {}
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            *optsize = ::std::mem::size_of::<sctp_setprim>() as libc::c_ulong
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        20 => {
            if *optsize < ::std::mem::size_of::<sctp_hmacalgo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut shmac = 0 as *mut sctp_hmacalgo;
                let mut hmaclist = 0 as *mut sctp_hmaclist_t;
                shmac = optval as *mut sctp_hmacalgo;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                hmaclist = (*inp).sctp_ep.local_hmacs;
                if hmaclist.is_null() {
                    /* no HMACs to return */
                    *optsize = ::std::mem::size_of::<sctp_hmacalgo>() as libc::c_ulong;
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                } else {
                    let mut size_0 = 0;
                    size_0 = (::std::mem::size_of::<sctp_hmacalgo>() as libc::c_ulong).wrapping_add(
                        ((*hmaclist).num_algo as libc::c_ulong)
                            .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong),
                    ) as uint32_t;
                    if *optsize < size_0 as libc::c_ulong {
                        error = 22i32;
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    } else {
                        /* copy in the list */
                        (*shmac).shmac_number_of_idents = (*hmaclist).num_algo as uint32_t;

                        for i in 0i32..(*hmaclist).num_algo as libc::c_int {
                            *(*shmac).shmac_idents.as_mut_ptr().offset(i as isize) =
                                *(*hmaclist).hmac.as_mut_ptr().offset(i as isize);
                        }
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        *optsize = size_0 as size_t
                    }
                }
            }
        }
        21 => {
            if *optsize < ::std::mem::size_of::<sctp_authkeyid>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut scact = 0 as *mut sctp_authkeyid;
                scact = optval as *mut sctp_authkeyid;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 8021799272863076509;
                } else if (*scact).scact_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*scact).scact_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 8021799272863076509;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 8021799272863076509;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            /* get the active key on the assoc */
                            (*scact).scact_keynumber = (*stcb).asoc.authinfo.active_keyid;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*scact).scact_assoc_id == 0u32
                        {
                            /* get the endpoint active key */
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*scact).scact_keynumber = (*inp).sctp_ep.default_keyid;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_authkeyid>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        259 => {
            if *optsize < ::std::mem::size_of::<sctp_authchunks>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sac = 0 as *mut sctp_authchunks;
                sac = optval as *mut sctp_authchunks;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 8745593045889728090;
                } else if (*sac).gauth_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sac).gauth_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 8745593045889728090;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 8745593045889728090;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut chklist = 0 as *mut sctp_auth_chklist_t;
                        let mut size_1 = 0u64;
                        if !stcb.is_null() {
                            /* get off the assoc */
                            chklist = (*stcb).asoc.local_auth_chunks;
                            /* is there enough space? */
                            size_1 = sctp_auth_get_chklist_size(chklist);
                            if *optsize
                                < (::std::mem::size_of::<sctp_authchunks>() as libc::c_ulong)
                                    .wrapping_add(size_1)
                            {
                                error = 22i32
                            } else {
                                /* copy in the chunks */
                                sctp_serialize_auth_chunks(
                                    chklist,
                                    (*sac).gauth_chunks.as_mut_ptr(),
                                );
                                (*sac).gauth_number_of_chunks = size_1 as uint32_t;
                                *optsize = (::std::mem::size_of::<sctp_authchunks>()
                                    as libc::c_ulong)
                                    .wrapping_add(size_1)
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*sac).gauth_assoc_id == 0u32
                        {
                            /* get off the endpoint */
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            chklist = (*inp).sctp_ep.local_auth_chunks;
                            /* is there enough space? */
                            size_1 = sctp_auth_get_chklist_size(chklist);
                            if *optsize
                                < (::std::mem::size_of::<sctp_authchunks>() as libc::c_ulong)
                                    .wrapping_add(size_1)
                            {
                                error = 22i32
                            } else {
                                /* copy in the chunks */
                                sctp_serialize_auth_chunks(
                                    chklist,
                                    (*sac).gauth_chunks.as_mut_ptr(),
                                );
                                (*sac).gauth_number_of_chunks = size_1 as uint32_t;
                                *optsize = (::std::mem::size_of::<sctp_authchunks>()
                                    as libc::c_ulong)
                                    .wrapping_add(size_1)
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        258 => {
            if *optsize < ::std::mem::size_of::<sctp_authchunks>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sac_0 = 0 as *mut sctp_authchunks;
                sac_0 = optval as *mut sctp_authchunks;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 1558244004301936126;
                } else if (*sac_0).gauth_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sac_0).gauth_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 1558244004301936126;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 1558244004301936126;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            let mut chklist_0 = 0 as *mut sctp_auth_chklist_t;
                            let mut size_2 = 0u64;
                            chklist_0 = (*stcb).asoc.peer_auth_chunks;
                            /* is there enough space? */
                            size_2 = sctp_auth_get_chklist_size(chklist_0);
                            if *optsize
                                < (::std::mem::size_of::<sctp_authchunks>() as libc::c_ulong)
                                    .wrapping_add(size_2)
                            {
                                error = 22i32
                            } else {
                                /* copy in the chunks */
                                sctp_serialize_auth_chunks(
                                    chklist_0,
                                    (*sac_0).gauth_chunks.as_mut_ptr(),
                                );
                                (*sac_0).gauth_number_of_chunks = size_2 as uint32_t;
                                *optsize = (::std::mem::size_of::<sctp_authchunks>()
                                    as libc::c_ulong)
                                    .wrapping_add(size_2)
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            error = 2i32
                        }
                    }
                }
            }
        }
        30 => {
            if *optsize < ::std::mem::size_of::<sctp_event>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut event = 0 as *mut sctp_event;
                event = optval as *mut sctp_event;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 17858784396931120117;
                } else if (*event).se_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*event).se_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 17858784396931120117;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 17858784396931120117;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut event_type = 0;
                        match (*event).se_type as libc::c_int {
                            1 => event_type = 0x800u32,
                            2 => event_type = 0x1000u32,
                            3 => event_type = 0x2000u32,
                            4 => event_type = 0x4000u32,
                            5 => event_type = 0x8000u32,
                            6 => event_type = 0x10000u32,
                            7 => event_type = 0x20000u32,
                            8 => event_type = 0x40000u32,
                            9 => event_type = 0x80000u32,
                            10 => event_type = 0x4000000u32,
                            11 => {
                                event_type = 0u32;
                                error = 95i32
                            }
                            12 => event_type = 0x20000000u32,
                            13 => event_type = 0x40000000u32,
                            14 => event_type = 0x80000000u32,
                            _ => {
                                event_type = 0u32;
                                error = 22i32
                            }
                        }
                        if event_type > 0u32 {
                            if !stcb.is_null() {
                                (*event).se_on = (!stcb.is_null()
                                    && (*stcb).asoc.sctp_features & event_type as libc::c_ulong
                                        == event_type as libc::c_ulong
                                    || stcb.is_null()
                                        && !inp.is_null()
                                        && (*inp).sctp_features & event_type as libc::c_ulong
                                            == event_type as libc::c_ulong)
                                    as uint8_t
                            } else if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0 && (*event).se_assoc_id == 0u32
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                (*event).se_on = ((*inp).sctp_features
                                    & event_type as libc::c_ulong
                                    == event_type as libc::c_ulong)
                                    as uint8_t;
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            } else {
                                error = 22i32
                            }
                        }
                        if !stcb.is_null() {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_event>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        31 => {
            let mut onoff = 0;
            if *optsize < ::std::mem::size_of::<libc::c_int>() as libc::c_ulong {
                error = 22i32
            } else {
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                onoff = ((*inp).sctp_features & 0x8000000u64 == 0x8000000u64) as libc::c_int;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
            if error == 0i32 {
                /* return the option value */
                *(optval as *mut libc::c_int) = onoff;
                *optsize = ::std::mem::size_of::<libc::c_int>() as libc::c_ulong
            }
        }
        32 => {
            let mut onoff_0 = 0;
            if *optsize < ::std::mem::size_of::<libc::c_int>() as libc::c_ulong {
                error = 22i32
            } else {
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                onoff_0 = ((*inp).sctp_features & 0x10000000u64 == 0x10000000u64) as libc::c_int;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
            if error == 0i32 {
                /* return the option value */
                *(optval as *mut libc::c_int) = onoff_0;
                *optsize = ::std::mem::size_of::<libc::c_int>() as libc::c_ulong
            }
        }
        33 => {
            if *optsize < ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut info = 0 as *mut sctp_sndinfo;
                info = optval as *mut sctp_sndinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 17447619022132457282;
                } else if (*info).snd_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*info).snd_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 17447619022132457282;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 17447619022132457282;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*info).snd_sid = (*stcb).asoc.def_send.sinfo_stream;
                            (*info).snd_flags = (*stcb).asoc.def_send.sinfo_flags;
                            (*info).snd_flags =
                                ((*info).snd_flags as libc::c_int & 0xfff0i32) as uint16_t;
                            (*info).snd_ppid = (*stcb).asoc.def_send.sinfo_ppid;
                            (*info).snd_context = (*stcb).asoc.def_send.sinfo_context;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*info).snd_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*info).snd_sid = (*inp).def_send.sinfo_stream;
                            (*info).snd_flags = (*inp).def_send.sinfo_flags;
                            (*info).snd_flags =
                                ((*info).snd_flags as libc::c_int & 0xfff0i32) as uint16_t;
                            (*info).snd_ppid = (*inp).def_send.sinfo_ppid;
                            (*info).snd_context = (*inp).def_send.sinfo_context;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        34 => {
            if *optsize < ::std::mem::size_of::<sctp_default_prinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut info_0 = 0 as *mut sctp_default_prinfo;
                info_0 = optval as *mut sctp_default_prinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 17742170664137915125;
                } else if (*info_0).pr_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*info_0).pr_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 17742170664137915125;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 17742170664137915125;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*info_0).pr_policy = ((*stcb).asoc.def_send.sinfo_flags as libc::c_int
                                & 0xfi32)
                                as uint16_t;
                            (*info_0).pr_value = (*stcb).asoc.def_send.sinfo_timetolive;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*info_0).pr_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*info_0).pr_policy =
                                ((*inp).def_send.sinfo_flags as libc::c_int & 0xfi32) as uint16_t;
                            (*info_0).pr_value = (*inp).def_send.sinfo_timetolive;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_default_prinfo>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        35 => {
            if *optsize < ::std::mem::size_of::<sctp_paddrthlds>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut thlds = 0 as *mut sctp_paddrthlds;
                thlds = optval as *mut sctp_paddrthlds;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 18070632272863103188;
                } else if (*thlds).spt_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*thlds).spt_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 18070632272863103188;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 18070632272863103188;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut net_4 = 0 as *mut sctp_nets;
                        let mut addr_2 = 0 as *mut sockaddr;
                        if (*thlds).spt_address.ss_family as libc::c_int == 10i32 {
                            let mut sin6_2 = 0 as *mut sockaddr_in6;
                            sin6_2 = &mut (*thlds).spt_address as *mut sockaddr_storage
                                as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6_2).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store_1 = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store_1, sin6_2);
                                addr_2 = &mut sin_store_1 as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr_2 = &mut (*thlds).spt_address as *mut sockaddr_storage
                                    as *mut sockaddr
                            }
                        } else {
                            addr_2 =
                                &mut (*thlds).spt_address as *mut sockaddr_storage as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_4 = sctp_findnet(stcb, addr_2)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_4 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr_2,
                                &mut net_4,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && net_4.is_null() {
                            if (*addr_2).sa_family as libc::c_int == 2i32 {
                                let mut sin_0 = 0 as *mut sockaddr_in;
                                sin_0 = addr_2 as *mut sockaddr_in;
                                if (*sin_0).sin_addr.s_addr != 0u32 {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 16347177639504923624;
                                }
                            } else if (*addr_2).sa_family as libc::c_int == 10i32 {
                                let mut sin6_3 = 0 as *mut sockaddr_in6;
                                sin6_3 = addr_2 as *mut sockaddr_in6;
                                if ({
                                    let mut __a = &mut (*sin6_3).sin6_addr as *mut in6_addr
                                        as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                        as libc::c_int
                                }) == 0
                                {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 16347177639504923624;
                                }
                            } else if (*addr_2).sa_family as libc::c_int == 123i32 {
                                let mut sconn_0 = 0 as *mut sockaddr_conn;
                                sconn_0 = addr_2 as *mut sockaddr_conn;
                                if !(*sconn_0).sconn_addr.is_null() {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 16347177639504923624;
                                }
                            } else {
                                error = 97i32;
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                current_block_2022 = 7666136661722410625;
                            }
                        } else {
                            current_block_2022 = 16347177639504923624;
                        }
                        match current_block_2022 {
                            7666136661722410625 => {}
                            _ => {
                                if !stcb.is_null() {
                                    if !net_4.is_null() {
                                        (*thlds).spt_pathmaxrxt = (*net_4).failure_threshold;
                                        (*thlds).spt_pathpfthld = (*net_4).pf_threshold;
                                        (*thlds).spt_pathcpthld = 0xffffu16
                                    } else {
                                        (*thlds).spt_pathmaxrxt = (*stcb).asoc.def_net_failure;
                                        (*thlds).spt_pathpfthld = (*stcb).asoc.def_net_pf_threshold;
                                        (*thlds).spt_pathcpthld = 0xffffu16
                                    }
                                    (*thlds).spt_assoc_id = (*stcb).asoc.assoc_id;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                } else if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && (*thlds).spt_assoc_id == 0u32
                                {
                                    /* Use endpoint defaults */
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*thlds).spt_pathmaxrxt = (*inp).sctp_ep.def_net_failure;
                                    (*thlds).spt_pathpfthld = (*inp).sctp_ep.def_net_pf_threshold;
                                    (*thlds).spt_pathcpthld = 0xffffu16;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                } else {
                                    error = 22i32
                                }
                                if error == 0i32 {
                                    *optsize =
                                        ::std::mem::size_of::<sctp_paddrthlds>() as libc::c_ulong
                                }
                            }
                        }
                    }
                }
            }
        }
        36 => {
            if *optsize < ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut encaps = 0 as *mut sctp_udpencaps;
                encaps = optval as *mut sctp_udpencaps;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 9250857829335639245;
                } else if (*encaps).sue_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*encaps).sue_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 9250857829335639245;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 9250857829335639245;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut net_5 = 0 as *mut sctp_nets;
                        let mut addr_3 = 0 as *mut sockaddr;
                        if (*encaps).sue_address.ss_family as libc::c_int == 10i32 {
                            let mut sin6_4 = 0 as *mut sockaddr_in6;
                            sin6_4 = &mut (*encaps).sue_address as *mut sockaddr_storage
                                as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6_4).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store_2 = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store_2, sin6_4);
                                addr_3 = &mut sin_store_2 as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr_3 = &mut (*encaps).sue_address as *mut sockaddr_storage
                                    as *mut sockaddr
                            }
                        } else {
                            addr_3 =
                                &mut (*encaps).sue_address as *mut sockaddr_storage as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_5 = sctp_findnet(stcb, addr_3)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_5 = 0 as *mut sctp_nets; /* end switch (opt) */
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr_3,
                                &mut net_5,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && net_5.is_null() {
                            if (*addr_3).sa_family as libc::c_int == 2i32 {
                                let mut sin_1 = 0 as *mut sockaddr_in;
                                sin_1 = addr_3 as *mut sockaddr_in;
                                if (*sin_1).sin_addr.s_addr != 0u32 {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 7612262316633937150;
                                }
                            } else if (*addr_3).sa_family as libc::c_int == 10i32 {
                                let mut sin6_5 = 0 as *mut sockaddr_in6;
                                sin6_5 = addr_3 as *mut sockaddr_in6;
                                if ({
                                    let mut __a = &mut (*sin6_5).sin6_addr as *mut in6_addr
                                        as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                        as libc::c_int
                                }) == 0
                                {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 7612262316633937150;
                                }
                            } else if (*addr_3).sa_family as libc::c_int == 123i32 {
                                let mut sconn_1 = 0 as *mut sockaddr_conn;
                                sconn_1 = addr_3 as *mut sockaddr_conn;
                                if !(*sconn_1).sconn_addr.is_null() {
                                    error = 22i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block_2022 = 7666136661722410625;
                                } else {
                                    current_block_2022 = 7612262316633937150;
                                }
                            } else {
                                error = 97i32;
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                current_block_2022 = 7666136661722410625;
                            }
                        } else {
                            current_block_2022 = 7612262316633937150;
                        }
                        match current_block_2022 {
                            7666136661722410625 => {}
                            _ => {
                                if !stcb.is_null() {
                                    if !net_5.is_null() {
                                        (*encaps).sue_port = (*net_5).port
                                    } else {
                                        (*encaps).sue_port = (*stcb).asoc.port
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                } else if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && (*encaps).sue_assoc_id == 0u32
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*encaps).sue_port = (*inp).sctp_ep.port;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                } else {
                                    error = 22i32
                                }
                                if error == 0i32 {
                                    *optsize =
                                        ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong
                                }
                            }
                        }
                    }
                }
            }
        }
        37 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_8 = 0 as *mut sctp_assoc_value;
                av_8 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 6316812268695542941;
                } else if (*av_8).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_8).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 6316812268695542941;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 6316812268695542941;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_8).assoc_value = (*stcb).asoc.ecn_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_8).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_8).assoc_value = (*inp).ecn_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        38 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_9 = 0 as *mut sctp_assoc_value;
                av_9 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 14368460663895810593;
                } else if (*av_9).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_9).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 14368460663895810593;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 14368460663895810593;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_9).assoc_value = (*stcb).asoc.prsctp_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_9).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_9).assoc_value = (*inp).prsctp_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        39 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_10 = 0 as *mut sctp_assoc_value;
                av_10 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 10593729028429063849;
                } else if (*av_10).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_10).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 10593729028429063849;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 10593729028429063849;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_10).assoc_value = (*stcb).asoc.auth_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_10).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_10).assoc_value = (*inp).auth_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        40 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_11 = 0 as *mut sctp_assoc_value;
                av_11 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 749057208233739588;
                } else if (*av_11).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_11).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 749057208233739588;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 749057208233739588;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_11).assoc_value = (*stcb).asoc.asconf_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_11).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_11).assoc_value = (*inp).asconf_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        41 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_12 = 0 as *mut sctp_assoc_value;
                av_12 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 2635347592719866193;
                } else if (*av_12).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_12).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 2635347592719866193;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 2635347592719866193;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_12).assoc_value = (*stcb).asoc.reconfig_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_12).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_12).assoc_value = (*inp).reconfig_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        48 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_13 = 0 as *mut sctp_assoc_value;
                av_13 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 9037595613548586190;
                } else if (*av_13).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_13).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 9037595613548586190;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 9037595613548586190;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_13).assoc_value = (*stcb).asoc.nrsack_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_13).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_13).assoc_value = (*inp).nrsack_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        49 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_14 = 0 as *mut sctp_assoc_value;
                av_14 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 2776854999332320833;
                } else if (*av_14).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_14).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 2776854999332320833;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 2776854999332320833;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_14).assoc_value = (*stcb).asoc.pktdrop_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_14).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_14).assoc_value = (*inp).pktdrop_supported as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        2304 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_15 = 0 as *mut sctp_assoc_value;
                av_15 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 7483072579061746144;
                } else if (*av_15).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_15).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 7483072579061746144;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 7483072579061746144;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_15).assoc_value = (*stcb).asoc.local_strreset_support as uint32_t;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_15).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_15).assoc_value = (*inp).local_strreset_support as uint32_t;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        263 => {
            if *optsize < ::std::mem::size_of::<sctp_prstatus>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sprstat = 0 as *mut sctp_prstatus;
                sprstat = optval as *mut sctp_prstatus;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 6140744515306670682;
                } else if (*sprstat).sprstat_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sprstat).sprstat_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 6140744515306670682;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 6140744515306670682;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut sid = 0;
                        let mut policy = 0;
                        sid = (*sprstat).sprstat_sid;
                        policy = (*sprstat).sprstat_policy;
                        if !stcb.is_null()
                            && (sid as libc::c_int) < (*stcb).asoc.streamoutcnt as libc::c_int
                            && policy as libc::c_int == 0xfi32
                        {
                            (*sprstat).sprstat_abandoned_unsent =
                                (*(*stcb).asoc.strmout.offset(sid as isize)).abandoned_unsent
                                    [0usize] as uint64_t;
                            (*sprstat).sprstat_abandoned_sent =
                                (*(*stcb).asoc.strmout.offset(sid as isize)).abandoned_sent[0usize]
                                    as uint64_t
                        } else {
                            error = 22i32
                        }
                        if !stcb.is_null() {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_prstatus>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        264 => {
            if *optsize < ::std::mem::size_of::<sctp_prstatus>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sprstat_0 = 0 as *mut sctp_prstatus;
                sprstat_0 = optval as *mut sctp_prstatus;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 10297688268733444570;
                } else if (*sprstat_0).sprstat_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sprstat_0).sprstat_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 10297688268733444570;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 10297688268733444570;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        let mut policy_0 = 0;
                        policy_0 = (*sprstat_0).sprstat_policy;
                        if !stcb.is_null()
                            && policy_0 as libc::c_int != 0i32
                            && (policy_0 as libc::c_int <= 0x3i32
                                || policy_0 as libc::c_int == 0xfi32)
                        {
                            if policy_0 as libc::c_int == 0xfi32 {
                                (*sprstat_0).sprstat_abandoned_unsent =
                                    (*stcb).asoc.abandoned_unsent[0usize];
                                (*sprstat_0).sprstat_abandoned_sent =
                                    (*stcb).asoc.abandoned_sent[0usize]
                            } else {
                                (*sprstat_0).sprstat_abandoned_unsent =
                                    (*stcb).asoc.abandoned_unsent[policy_0 as usize];
                                (*sprstat_0).sprstat_abandoned_sent =
                                    (*stcb).asoc.abandoned_sent[policy_0 as usize]
                            }
                        } else {
                            error = 22i32
                        }
                        if !stcb.is_null() {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_prstatus>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        50 => {
            if *optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_16 = 0 as *mut sctp_assoc_value;
                av_16 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block_2022 = 6710180381371027342;
                } else if (*av_16).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_16).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block_2022 = 7666136661722410625;
                    } else {
                        current_block_2022 = 6710180381371027342;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block_2022 = 6710180381371027342;
                }
                match current_block_2022 {
                    7666136661722410625 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*av_16).assoc_value = (*stcb).asoc.max_cwnd;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_16).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*av_16).assoc_value = (*inp).max_cwnd;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                        if error == 0i32 {
                            *optsize = ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong
                        }
                    }
                }
            }
        }
        _ => error = 92i32,
    }
    if error != 0 {
        *optsize = 0u64
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_setopt(
    mut so: *mut socket,
    mut optname: libc::c_int,
    mut optval: *mut libc::c_void,
    mut optsize: size_t,
    mut p: *mut libc::c_void,
) -> libc::c_int {
    let mut current_block: u64;
    let mut error = 0;
    let mut mopt = 0 as *mut uint32_t;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut vrf_id = 0;
    if optval.is_null() {
        return 22i32;
    }
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 22i32;
    }
    vrf_id = (*inp).def_vrf_id;
    error = 0i32;
    match optname {
        4 | 5 | 24 | 27 | 9 | 23 | 13 => {
            /* copy in the option value */
            if optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut set_opt = 0;
                mopt = optval as *mut uint32_t;
                set_opt = 0i32;
                if !(error != 0) {
                    match optname {
                        9 => set_opt = 0x100000i32,
                        24 => {
                            /*
                             * NOTE: we don't really support this flag
                             */
                            if (*inp).sctp_flags & 0x4u32 != 0 {
                                /* only valid for bound all sockets */
                                if system_base_info.sctpsysctl.sctp_auto_asconf == 0u32
                                    && *mopt != 0u32
                                {
                                    /* forbidden by admin */
                                    return 1i32;
                                }
                                set_opt = 0x40i32
                            } else {
                                return 22i32;
                            }
                        }
                        27 => set_opt = 0x400000i32,
                        23 => set_opt = 0x2i32,
                        13 => {
                            if (*inp).sctp_flags & 0x4000000u32 != 0 {
                                set_opt = 0x800000i32
                            } else {
                                return 22i32;
                            }
                        }
                        4 => set_opt = 0x100i32,
                        5 => {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                            {
                                return 22i32;
                            }
                            set_opt = 0x200i32;
                            /*
                             * The value is in ticks. Note this does not effect
                             * old associations, only new ones.
                             */
                            (*inp).sctp_ep.auto_close_time =
                                (*mopt).wrapping_mul(hz as libc::c_uint) as libc::c_int
                        }
                        _ => {}
                    }
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    if *mopt != 0u32 {
                        (*inp).sctp_features |= set_opt as libc::c_ulong
                    } else {
                        (*inp).sctp_features &= !set_opt as libc::c_ulong
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                }
            }
        }
        28 => {
            if optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                mopt = optval as *mut uint32_t;
                if (*inp).sctp_flags & 0x10u32 == 0u32 {
                    /* Can't set it after we are bound */
                    error = 22i32
                } else if (*inp).sctp_flags & 0x1u32 != 0 {
                    /* Can't do this for a 1-m socket */
                    error = 22i32
                } else if !optval.is_null() {
                    (*inp).sctp_features |= 0x2000000u64
                } else {
                    (*inp).sctp_features &= !(0x2000000i32) as libc::c_ulong
                }
            }
        }
        17 => {
            if optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value = 0 as *mut uint32_t;
                value = optval as *mut uint32_t;
                if *value > (*so).so_rcv.sb_hiwat {
                    error = 22i32
                } else {
                    (*inp).partial_delivery_point = *value
                }
            }
        }
        16 => {
            if optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut level = 0 as *mut uint32_t;
                level = optval as *mut uint32_t;
                if *level == 0x2u32 {
                    (*inp).sctp_features |= 0x8u64;
                    (*inp).sctp_features |= 0x10u64
                } else if *level == 0x1u32 {
                    (*inp).sctp_features |= 0x8u64;
                    (*inp).sctp_features &= !(0x10i32) as libc::c_ulong
                } else if *level == 0u32 {
                    (*inp).sctp_features &= !(0x8i32) as libc::c_ulong;
                    (*inp).sctp_features &= !(0x10i32) as libc::c_ulong
                } else {
                    error = 22i32
                }
            }
        }
        4614 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av = 0 as *mut sctp_assoc_value;
                av = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 15460309861373144675;
                } else if (*av).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 15460309861373144675;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 15460309861373144675;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*av).assoc_value == 0u32 {
                                (*inp).idata_supported = 0u8
                            } else if (*inp).sctp_features & 0x8u64 == 0x8u64
                                && (*inp).sctp_features & 0x10u64 == 0x10u64
                            {
                                (*inp).idata_supported = 1u8
                            } else {
                                /* Must have Frag interleave and stream interleave on */
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        4608 => {
            if system_base_info.sctpsysctl.sctp_cmt_on_off != 0 {
                if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                    error = 22i32
                } else {
                    let mut av_0 = 0 as *mut sctp_assoc_value;
                    av_0 = optval as *mut sctp_assoc_value;
                    if (*av_0).assoc_value > 4u32 {
                        error = 22i32
                    } else {
                        if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            stcb = (*inp).sctp_asoc_list.lh_first;
                            if !stcb.is_null() {
                                pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            current_block = 16512738885216853798;
                        } else if (*av_0).assoc_id > 2u32 {
                            stcb = sctp_findassociation_ep_asocid(inp, (*av_0).assoc_id, 1i32);
                            if stcb.is_null() {
                                error = 2i32;
                                current_block = 13515130358667707052;
                            } else {
                                current_block = 16512738885216853798;
                            }
                        } else {
                            stcb = 0 as *mut sctp_tcb;
                            current_block = 16512738885216853798;
                        }
                        match current_block {
                            13515130358667707052 => {}
                            _ => {
                                if !stcb.is_null() {
                                    (*stcb).asoc.sctp_cmt_on_off = (*av_0).assoc_value as uint8_t;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                } else {
                                    if (*inp).sctp_flags & 0x2u32 != 0
                                        || (*inp).sctp_flags & 0x400000u32 != 0
                                        || (*inp).sctp_flags & 0x1u32 != 0
                                            && ((*av_0).assoc_id == 0u32
                                                || (*av_0).assoc_id == 2u32)
                                    {
                                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                                        (*inp).sctp_cmt_on_off = (*av_0).assoc_value;
                                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                    }
                                    if (*inp).sctp_flags & 0x1u32 != 0
                                        && ((*av_0).assoc_id == 1u32 || (*av_0).assoc_id == 2u32)
                                    {
                                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                                        stcb = (*inp).sctp_asoc_list.lh_first;
                                        while !stcb.is_null() {
                                            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                            (*stcb).asoc.sctp_cmt_on_off =
                                                (*av_0).assoc_value as uint8_t;
                                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                            stcb = (*stcb).sctp_tcblist.le_next
                                        }
                                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                error = 92i32
            }
        }
        4610 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_1 = 0 as *mut sctp_assoc_value;
                av_1 = optval as *mut sctp_assoc_value;
                if (*av_1).assoc_value != 0u32
                    && (*av_1).assoc_value != 0x1u32
                    && (*av_1).assoc_value != 0x2u32
                    && (*av_1).assoc_value != 0x3u32
                {
                    error = 22i32
                } else {
                    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                        stcb = (*inp).sctp_asoc_list.lh_first;
                        if !stcb.is_null() {
                            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                        }
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        current_block = 14800950693471784367;
                    } else if (*av_1).assoc_id > 2u32 {
                        stcb = sctp_findassociation_ep_asocid(inp, (*av_1).assoc_id, 1i32);
                        if stcb.is_null() {
                            error = 2i32;
                            current_block = 13515130358667707052;
                        } else {
                            current_block = 14800950693471784367;
                        }
                    } else {
                        stcb = 0 as *mut sctp_tcb;
                        current_block = 14800950693471784367;
                    }
                    match current_block {
                        13515130358667707052 => {}
                        _ => {
                            let mut net = 0 as *mut sctp_nets;
                            if !stcb.is_null() {
                                (*stcb).asoc.cc_functions = *sctp_cc_functions
                                    .as_ptr()
                                    .offset((*av_1).assoc_value as isize);
                                (*stcb).asoc.congestion_control_module = (*av_1).assoc_value;
                                if (*stcb)
                                    .asoc
                                    .cc_functions
                                    .sctp_set_initial_cc_param
                                    .is_some()
                                {
                                    net = (*stcb).asoc.nets.tqh_first;
                                    while !net.is_null() {
                                        (*stcb)
                                            .asoc
                                            .cc_functions
                                            .sctp_set_initial_cc_param
                                            .expect("non-null function pointer")(
                                            stcb, net
                                        );
                                        net = (*net).sctp_next.tqe_next
                                    }
                                }
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            } else {
                                if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && ((*av_1).assoc_id == 0u32 || (*av_1).assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*inp).sctp_ep.sctp_default_cc_module = (*av_1).assoc_value;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                                if (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*av_1).assoc_id == 1u32 || (*av_1).assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    stcb = (*inp).sctp_asoc_list.lh_first;
                                    while !stcb.is_null() {
                                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                        (*stcb).asoc.cc_functions = *sctp_cc_functions
                                            .as_ptr()
                                            .offset((*av_1).assoc_value as isize);
                                        (*stcb).asoc.congestion_control_module =
                                            (*av_1).assoc_value;
                                        if (*stcb)
                                            .asoc
                                            .cc_functions
                                            .sctp_set_initial_cc_param
                                            .is_some()
                                        {
                                            net = (*stcb).asoc.nets.tqh_first;
                                            while !net.is_null() {
                                                (*stcb)
                                                    .asoc
                                                    .cc_functions
                                                    .sctp_set_initial_cc_param
                                                    .expect("non-null function pointer")(
                                                    stcb, net
                                                );
                                                net = (*net).sctp_next.tqe_next
                                            }
                                        }
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                        stcb = (*stcb).sctp_tcblist.le_next
                                    }
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                            }
                        }
                    }
                }
            }
        }
        4613 => {
            if optsize < ::std::mem::size_of::<sctp_cc_option>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut cc_opt = 0 as *mut sctp_cc_option;
                cc_opt = optval as *mut sctp_cc_option;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 2277243988550674409;
                } else if (*cc_opt).aid_value.assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*cc_opt).aid_value.assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 2277243988550674409;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 2277243988550674409;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if stcb.is_null() {
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && (*cc_opt).aid_value.assoc_id == 1u32
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    if (*stcb).asoc.cc_functions.sctp_cwnd_socket_option.is_some() {
                                        Some(
                                            (*stcb)
                                                .asoc
                                                .cc_functions
                                                .sctp_cwnd_socket_option
                                                .expect("non-null function pointer"),
                                        )
                                        .expect("non-null function pointer")(
                                            stcb, 1i32, cc_opt
                                        );
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            } else {
                                error = 22i32
                            }
                        } else {
                            if (*stcb).asoc.cc_functions.sctp_cwnd_socket_option.is_none() {
                                error = 95i32
                            } else {
                                error = Some(
                                    (*stcb)
                                        .asoc
                                        .cc_functions
                                        .sctp_cwnd_socket_option
                                        .expect("non-null function pointer"),
                                )
                                .expect("non-null function pointer")(
                                    stcb, 1i32, cc_opt
                                )
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
            }
        }
        4611 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_2 = 0 as *mut sctp_assoc_value;
                av_2 = optval as *mut sctp_assoc_value;
                if (*av_2).assoc_value != 0u32
                    && (*av_2).assoc_value != 0x1u32
                    && (*av_2).assoc_value != 0x2u32
                    && (*av_2).assoc_value != 0x3u32
                    && (*av_2).assoc_value != 0x4u32
                    && (*av_2).assoc_value != 0x5u32
                {
                    error = 22i32
                } else {
                    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                        stcb = (*inp).sctp_asoc_list.lh_first;
                        if !stcb.is_null() {
                            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                        }
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        current_block = 8967406177575768232;
                    } else if (*av_2).assoc_id > 2u32 {
                        stcb = sctp_findassociation_ep_asocid(inp, (*av_2).assoc_id, 1i32);
                        if stcb.is_null() {
                            error = 2i32;
                            current_block = 13515130358667707052;
                        } else {
                            current_block = 8967406177575768232;
                        }
                    } else {
                        stcb = 0 as *mut sctp_tcb;
                        current_block = 8967406177575768232;
                    }
                    match current_block {
                        13515130358667707052 => {}
                        _ => {
                            if !stcb.is_null() {
                                pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
                                (*stcb)
                                    .asoc
                                    .ss_functions
                                    .sctp_ss_clear
                                    .expect("non-null function pointer")(
                                    stcb,
                                    &mut (*stcb).asoc,
                                    1i32,
                                    1i32,
                                );
                                (*stcb).asoc.ss_functions = *sctp_ss_functions
                                    .as_ptr()
                                    .offset((*av_2).assoc_value as isize);
                                (*stcb).asoc.stream_scheduling_module = (*av_2).assoc_value;
                                (*stcb)
                                    .asoc
                                    .ss_functions
                                    .sctp_ss_init
                                    .expect("non-null function pointer")(
                                    stcb,
                                    &mut (*stcb).asoc,
                                    1i32,
                                );
                                pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            } else {
                                if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && ((*av_2).assoc_id == 0u32 || (*av_2).assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*inp).sctp_ep.sctp_default_ss_module = (*av_2).assoc_value;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                                if (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*av_2).assoc_id == 1u32 || (*av_2).assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    stcb = (*inp).sctp_asoc_list.lh_first;
                                    while !stcb.is_null() {
                                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                        pthread_mutex_lock(&mut (*stcb).tcb_send_mtx);
                                        (*stcb)
                                            .asoc
                                            .ss_functions
                                            .sctp_ss_clear
                                            .expect("non-null function pointer")(
                                            stcb,
                                            &mut (*stcb).asoc,
                                            1i32,
                                            1i32,
                                        );
                                        (*stcb).asoc.ss_functions = *sctp_ss_functions
                                            .as_ptr()
                                            .offset((*av_2).assoc_value as isize);
                                        (*stcb).asoc.stream_scheduling_module = (*av_2).assoc_value;
                                        (*stcb)
                                            .asoc
                                            .ss_functions
                                            .sctp_ss_init
                                            .expect("non-null function pointer")(
                                            stcb,
                                            &mut (*stcb).asoc,
                                            1i32,
                                        );
                                        pthread_mutex_unlock(&mut (*stcb).tcb_send_mtx);
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                        stcb = (*stcb).sctp_tcblist.le_next
                                    }
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                            }
                        }
                    }
                }
            }
        }
        4612 => {
            if optsize < ::std::mem::size_of::<sctp_stream_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_3 = 0 as *mut sctp_stream_value;
                av_3 = optval as *mut sctp_stream_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 10162005052971631276;
                } else if (*av_3).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_3).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 10162005052971631276;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 10162005052971631276;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            if (*av_3).stream_id as libc::c_int
                                >= (*stcb).asoc.streamoutcnt as libc::c_int
                                || (*stcb)
                                    .asoc
                                    .ss_functions
                                    .sctp_ss_set_value
                                    .expect("non-null function pointer")(
                                    stcb,
                                    &mut (*stcb).asoc,
                                    &mut *(*stcb).asoc.strmout.offset((*av_3).stream_id as isize),
                                    (*av_3).stream_value,
                                ) < 0i32
                            {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x1u32 != 0 && (*av_3).assoc_id == 1u32 {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            stcb = (*inp).sctp_asoc_list.lh_first;
                            while !stcb.is_null() {
                                pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                if ((*av_3).stream_id as libc::c_int)
                                    < (*stcb).asoc.streamoutcnt as libc::c_int
                                {
                                    (*stcb)
                                        .asoc
                                        .ss_functions
                                        .sctp_ss_set_value
                                        .expect("non-null function pointer")(
                                        stcb,
                                        &mut (*stcb).asoc,
                                        &mut *(*stcb)
                                            .asoc
                                            .strmout
                                            .offset((*av_3).stream_id as isize),
                                        (*av_3).stream_value,
                                    );
                                }
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                stcb = (*stcb).sctp_tcblist.le_next
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            /* Can't set stream value without association */
                            error = 22i32
                        }
                    }
                }
            }
        }
        4103 => error = 95i32,
        26 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_4 = 0 as *mut sctp_assoc_value;
                av_4 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 10634324963949432367;
                } else if (*av_4).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_4).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 10634324963949432367;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 10634324963949432367;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*stcb).asoc.context = (*av_4).assoc_value;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*av_4).assoc_id == 0u32 || (*av_4).assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                (*inp).sctp_context = (*av_4).assoc_value;
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*av_4).assoc_id == 1u32 || (*av_4).assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    (*stcb).asoc.context = (*av_4).assoc_value;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        12289 => {
            if optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut default_vrfid = 0 as *mut uint32_t;
                default_vrfid = optval as *mut uint32_t;
                if *default_vrfid > 0u32 {
                    error = 22i32
                } else {
                    (*inp).def_vrf_id = *default_vrfid
                }
            }
        }
        12293 => error = 95i32,
        12290 => error = 95i32,
        15 => {
            if optsize < ::std::mem::size_of::<sctp_sack_info>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sack = 0 as *mut sctp_sack_info;
                sack = optval as *mut sctp_sack_info;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 8603633071738804762;
                } else if (*sack).sack_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sack).sack_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 8603633071738804762;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 8603633071738804762;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if (*sack).sack_delay != 0 {
                            if (*sack).sack_delay > 500u32 {
                                (*sack).sack_delay = 500u32
                            }
                            if (if hz == 1000i32 {
                                (*sack).sack_delay
                            } else {
                                (*sack)
                                    .sack_delay
                                    .wrapping_mul(hz as libc::c_uint)
                                    .wrapping_add(999u32)
                                    .wrapping_div(1000u32)
                            }) < 1u32
                            {
                                (*sack).sack_delay = if hz == 1000i32 {
                                    1i32
                                } else {
                                    (1i32 * 1000i32 + (hz - 1i32)) / hz
                                } as uint32_t
                            }
                        }
                        if !stcb.is_null() {
                            if (*sack).sack_delay != 0 {
                                (*stcb).asoc.delayed_ack = (*sack).sack_delay
                            }
                            if (*sack).sack_freq != 0 {
                                (*stcb).asoc.sack_freq = (*sack).sack_freq
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*sack).sack_assoc_id == 0u32
                                        || (*sack).sack_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                if (*sack).sack_delay != 0 {
                                    (*inp).sctp_ep.sctp_timeoutticks[1usize] = if hz == 1000i32 {
                                        (*sack).sack_delay
                                    } else {
                                        (*sack)
                                            .sack_delay
                                            .wrapping_mul(hz as libc::c_uint)
                                            .wrapping_add(999u32)
                                            .wrapping_div(1000u32)
                                    }
                                }
                                if (*sack).sack_freq != 0 {
                                    (*inp).sctp_ep.sctp_sack_freq = (*sack).sack_freq
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*sack).sack_assoc_id == 1u32 || (*sack).sack_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    if (*sack).sack_delay != 0 {
                                        (*stcb).asoc.delayed_ack = (*sack).sack_delay
                                    }
                                    if (*sack).sack_freq != 0 {
                                        (*stcb).asoc.sack_freq = (*sack).sack_freq
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        18 => {
            if optsize < ::std::mem::size_of::<sctp_authchunk>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sauth = 0 as *mut sctp_authchunk;
                sauth = optval as *mut sctp_authchunk;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if sctp_auth_add_chunk((*sauth).sauth_chunk, (*inp).sctp_ep.local_auth_chunks) != 0
                {
                    error = 22i32
                } else {
                    (*inp).auth_supported = 1u8
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        19 => {
            if optsize < ::std::mem::size_of::<sctp_authkey>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sca = 0 as *mut sctp_authkey;
                let mut size = 0;
                sca = optval as *mut sctp_authkey;
                if (*sca).sca_keylength as libc::c_int == 0i32 {
                    size = optsize
                        .wrapping_sub(::std::mem::size_of::<sctp_authkey>() as libc::c_ulong);
                    current_block = 17987166386953563438;
                } else if ((*sca).sca_keylength as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<sctp_authkey>() as libc::c_ulong)
                    <= optsize
                {
                    size = (*sca).sca_keylength as size_t;
                    current_block = 17987166386953563438;
                } else {
                    error = 22i32;
                    current_block = 13515130358667707052;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            stcb = (*inp).sctp_asoc_list.lh_first;
                            if !stcb.is_null() {
                                pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            current_block = 18415419099355257153;
                        } else if (*sca).sca_assoc_id > 2u32 {
                            stcb = sctp_findassociation_ep_asocid(inp, (*sca).sca_assoc_id, 1i32);
                            if stcb.is_null() {
                                error = 2i32;
                                current_block = 13515130358667707052;
                            } else {
                                current_block = 18415419099355257153;
                            }
                        } else {
                            stcb = 0 as *mut sctp_tcb;
                            current_block = 18415419099355257153;
                        }
                        match current_block {
                            13515130358667707052 => {}
                            _ => {
                                let mut shared_keys = 0 as *mut sctp_keyhead;
                                let mut shared_key = 0 as *mut sctp_sharedkey_t;
                                let mut key = 0 as *mut sctp_key_t;
                                if !stcb.is_null() {
                                    shared_keys = &mut (*stcb).asoc.shared_keys;
                                    /* clear the cached keys for this key id */
                                    sctp_clear_cachedkeys(stcb, (*sca).sca_keynumber);
                                    /*
                                     * create the new shared key and
                                     * insert/replace it
                                     */
                                    if size > 0u64 {
                                        key = sctp_set_key(
                                            (*sca).sca_key.as_mut_ptr(),
                                            size as uint32_t,
                                        );
                                        if key.is_null() {
                                            error = 12i32;
                                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                            current_block = 13515130358667707052;
                                        } else {
                                            current_block = 9809875485161521081;
                                        }
                                    } else {
                                        current_block = 9809875485161521081;
                                    }
                                    match current_block {
                                        13515130358667707052 => {}
                                        _ => {
                                            shared_key = sctp_alloc_sharedkey();
                                            if shared_key.is_null() {
                                                sctp_free_key(key);
                                                error = 12i32;
                                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                            } else {
                                                (*shared_key).key = key;
                                                (*shared_key).keyid = (*sca).sca_keynumber;
                                                error =
                                                    sctp_insert_sharedkey(shared_keys, shared_key);
                                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                            }
                                        }
                                    }
                                } else {
                                    if (*inp).sctp_flags & 0x2u32 != 0
                                        || (*inp).sctp_flags & 0x400000u32 != 0
                                        || (*inp).sctp_flags & 0x1u32 != 0
                                            && ((*sca).sca_assoc_id == 0u32
                                                || (*sca).sca_assoc_id == 2u32)
                                    {
                                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                                        shared_keys = &mut (*inp).sctp_ep.shared_keys;
                                        /*
                                         * clear the cached keys on all assocs for
                                         * this key id
                                         */
                                        sctp_clear_cachedkeys_ep(inp, (*sca).sca_keynumber);
                                        /*
                                         * create the new shared key and
                                         * insert/replace it
                                         */
                                        if size > 0u64 {
                                            key = sctp_set_key(
                                                (*sca).sca_key.as_mut_ptr(),
                                                size as uint32_t,
                                            );
                                            if key.is_null() {
                                                error = 12i32;
                                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                                current_block = 13515130358667707052;
                                            } else {
                                                current_block = 6708766400982322261;
                                            }
                                        } else {
                                            current_block = 6708766400982322261;
                                        }
                                        match current_block {
                                            13515130358667707052 => {}
                                            _ => {
                                                shared_key = sctp_alloc_sharedkey();
                                                if shared_key.is_null() {
                                                    sctp_free_key(key);
                                                    error = 12i32;
                                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                                    current_block = 13515130358667707052;
                                                } else {
                                                    (*shared_key).key = key;
                                                    (*shared_key).keyid = (*sca).sca_keynumber;
                                                    error = sctp_insert_sharedkey(
                                                        shared_keys,
                                                        shared_key,
                                                    );
                                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                                    current_block = 7296667520727038133;
                                                }
                                            }
                                        }
                                    } else {
                                        current_block = 7296667520727038133;
                                    }
                                    match current_block {
                                        13515130358667707052 => {}
                                        _ => {
                                            if (*inp).sctp_flags & 0x1u32 != 0
                                                && ((*sca).sca_assoc_id == 1u32
                                                    || (*sca).sca_assoc_id == 2u32)
                                            {
                                                pthread_mutex_lock(&mut (*inp).inp_mtx);

                                                stcb = (*inp).sctp_asoc_list.lh_first;
                                                while !stcb.is_null() {
                                                    let mut current_block_552: u64;
                                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                                    shared_keys = &mut (*stcb).asoc.shared_keys;
                                                    /* clear the cached keys for this key id */
                                                    sctp_clear_cachedkeys(
                                                        stcb,
                                                        (*sca).sca_keynumber,
                                                    );
                                                    /*
                                                     * create the new shared key and
                                                     * insert/replace it
                                                     */
                                                    if size > 0u64 {
                                                        key = sctp_set_key(
                                                            (*sca).sca_key.as_mut_ptr(),
                                                            size as uint32_t,
                                                        );
                                                        if key.is_null() {
                                                            pthread_mutex_unlock(
                                                                &mut (*stcb).tcb_mtx,
                                                            );
                                                            current_block_552 =
                                                                10244038056695365035;
                                                        } else {
                                                            current_block_552 =
                                                                14912882087301211396;
                                                        }
                                                    } else {
                                                        current_block_552 = 14912882087301211396;
                                                    }
                                                    match current_block_552 {
                                                        14912882087301211396 => {
                                                            shared_key = sctp_alloc_sharedkey();
                                                            if shared_key.is_null() {
                                                                sctp_free_key(key);
                                                                pthread_mutex_unlock(
                                                                    &mut (*stcb).tcb_mtx,
                                                                );
                                                            } else {
                                                                (*shared_key).key = key;
                                                                (*shared_key).keyid =
                                                                    (*sca).sca_keynumber;
                                                                error = sctp_insert_sharedkey(
                                                                    shared_keys,
                                                                    shared_key,
                                                                );
                                                                pthread_mutex_unlock(
                                                                    &mut (*stcb).tcb_mtx,
                                                                );
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                    stcb = (*stcb).sctp_tcblist.le_next
                                                }
                                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
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
        20 => {
            if optsize < ::std::mem::size_of::<sctp_hmacalgo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut shmac = 0 as *mut sctp_hmacalgo;
                shmac = optval as *mut sctp_hmacalgo;
                if optsize
                    < (::std::mem::size_of::<sctp_hmacalgo>() as libc::c_ulong).wrapping_add(
                        ((*shmac).shmac_number_of_idents as libc::c_ulong)
                            .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong),
                    )
                    || (*shmac).shmac_number_of_idents > 0xffffu32
                {
                    error = 22i32
                } else {
                    let mut hmaclist = 0 as *mut sctp_hmaclist_t;
                    hmaclist = sctp_alloc_hmaclist((*shmac).shmac_number_of_idents as uint16_t);
                    if hmaclist.is_null() {
                        error = 12i32
                    } else {
                        let mut i = 0;
                        i = 0u32;
                        loop {
                            let mut hmacid = 0;
                            if !(i < (*shmac).shmac_number_of_idents) {
                                current_block = 4363117845869414711;
                                break;
                            }
                            hmacid = *(*shmac).shmac_idents.as_mut_ptr().offset(i as isize);
                            if sctp_auth_add_hmacid(hmaclist, hmacid) != 0 {
                                /* invalid HMACs were found */
                                error = 22i32;
                                sctp_free_hmaclist(hmaclist);
                                current_block = 13515130358667707052;
                                break;
                            } else {
                                i = i.wrapping_add(1)
                            }
                        }
                        match current_block {
                            13515130358667707052 => {}
                            _ => {
                                i = 0u32;
                                while i < (*hmaclist).num_algo as libc::c_uint {
                                    if *(*hmaclist).hmac.as_mut_ptr().offset(i as isize)
                                        as libc::c_int
                                        == 0x1i32
                                    {
                                        break;
                                    }
                                    i = i.wrapping_add(1)
                                }
                                if i == (*hmaclist).num_algo as libc::c_uint {
                                    /* not found in list */
                                    sctp_free_hmaclist(hmaclist);
                                    error = 22i32
                                } else {
                                    /* set it on the endpoint */
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    if !(*inp).sctp_ep.local_hmacs.is_null() {
                                        sctp_free_hmaclist((*inp).sctp_ep.local_hmacs);
                                    }
                                    (*inp).sctp_ep.local_hmacs = hmaclist;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                            }
                        }
                    }
                }
            }
        }
        21 => {
            if optsize < ::std::mem::size_of::<sctp_authkeyid>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut scact = 0 as *mut sctp_authkeyid;
                scact = optval as *mut sctp_authkeyid;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 9267933025378065668;
                } else if (*scact).scact_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*scact).scact_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 9267933025378065668;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 9267933025378065668;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        /* set the active key on the right place */
                        if !stcb.is_null() {
                            /* set the active key on the assoc */
                            if sctp_auth_setactivekey(stcb, (*scact).scact_keynumber) != 0 {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*scact).scact_assoc_id == 0u32
                                        || (*scact).scact_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                if sctp_auth_setactivekey_ep(inp, (*scact).scact_keynumber) != 0 {
                                    error = 22i32
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*scact).scact_assoc_id == 1u32
                                    || (*scact).scact_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    sctp_auth_setactivekey(stcb, (*scact).scact_keynumber);
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        22 => {
            if optsize < ::std::mem::size_of::<sctp_authkeyid>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut scdel = 0 as *mut sctp_authkeyid;
                scdel = optval as *mut sctp_authkeyid;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 12252114572146488012;
                } else if (*scdel).scact_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*scdel).scact_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 12252114572146488012;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 12252114572146488012;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        /* delete the key from the right place */
                        if !stcb.is_null() {
                            if sctp_delete_sharedkey(stcb, (*scdel).scact_keynumber) != 0 {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*scdel).scact_assoc_id == 0u32
                                        || (*scdel).scact_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                if sctp_delete_sharedkey_ep(inp, (*scdel).scact_keynumber) != 0 {
                                    error = 22i32
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*scdel).scact_assoc_id == 1u32
                                    || (*scdel).scact_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    sctp_delete_sharedkey(stcb, (*scdel).scact_keynumber);
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        29 => {
            if optsize < ::std::mem::size_of::<sctp_authkeyid>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut keyid = 0 as *mut sctp_authkeyid;
                keyid = optval as *mut sctp_authkeyid;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 6452473995766335310;
                } else if (*keyid).scact_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*keyid).scact_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 6452473995766335310;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 6452473995766335310;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        /* deactivate the key from the right place */
                        if !stcb.is_null() {
                            if sctp_deact_sharedkey(stcb, (*keyid).scact_keynumber) != 0 {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*keyid).scact_assoc_id == 0u32
                                        || (*keyid).scact_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                if sctp_deact_sharedkey_ep(inp, (*keyid).scact_keynumber) != 0 {
                                    error = 22i32
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*keyid).scact_assoc_id == 1u32
                                    || (*keyid).scact_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    sctp_deact_sharedkey(stcb, (*keyid).scact_keynumber);
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        2304 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_5 = 0 as *mut sctp_assoc_value;
                av_5 = optval as *mut sctp_assoc_value;
                if (*av_5).assoc_value & !(0x7i32) as libc::c_uint != 0 {
                    error = 22i32
                } else {
                    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                        stcb = (*inp).sctp_asoc_list.lh_first;
                        if !stcb.is_null() {
                            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                        }
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        current_block = 6291110978680950373;
                    } else if (*av_5).assoc_id > 2u32 {
                        stcb = sctp_findassociation_ep_asocid(inp, (*av_5).assoc_id, 1i32);
                        if stcb.is_null() {
                            error = 2i32;
                            current_block = 13515130358667707052;
                        } else {
                            current_block = 6291110978680950373;
                        }
                    } else {
                        stcb = 0 as *mut sctp_tcb;
                        current_block = 6291110978680950373;
                    }
                    match current_block {
                        13515130358667707052 => {}
                        _ => {
                            if !stcb.is_null() {
                                (*stcb).asoc.local_strreset_support =
                                    (*av_5).assoc_value as uint8_t;
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            } else {
                                if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && ((*av_5).assoc_id == 0u32 || (*av_5).assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*inp).local_strreset_support = (*av_5).assoc_value as uint8_t;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                                if (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*av_5).assoc_id == 1u32 || (*av_5).assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    stcb = (*inp).sctp_asoc_list.lh_first;
                                    while !stcb.is_null() {
                                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                        (*stcb).asoc.local_strreset_support =
                                            (*av_5).assoc_value as uint8_t;
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                        stcb = (*stcb).sctp_tcblist.le_next
                                    }
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                            }
                        }
                    }
                }
            }
        }
        2305 => {
            if optsize < ::std::mem::size_of::<sctp_reset_streams>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut strrst = 0 as *mut sctp_reset_streams;
                strrst = optval as *mut sctp_reset_streams;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 14036967227385098324;
                } else if (*strrst).srs_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*strrst).srs_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 14036967227385098324;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 14036967227385098324;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if stcb.is_null() {
                            error = 2i32
                        } else if (*stcb).asoc.reconfig_supported as libc::c_int == 0i32 {
                            /*
                             * Peer does not support the chunk type.
                             */
                            error = 95i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*stcb).asoc.state & 0x7fi32 != 0x8i32 {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (::std::mem::size_of::<sctp_reset_streams>() as libc::c_ulong)
                            .wrapping_add(
                                ((*strrst).srs_number_streams as libc::c_ulong).wrapping_mul(
                                    ::std::mem::size_of::<uint16_t>() as libc::c_ulong,
                                ),
                            )
                            > optsize
                        {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            let mut send_in = 0i32;
                            if (*strrst).srs_flags as libc::c_int & 0x1i32 != 0 {
                                send_in = 1i32;
                                if (*stcb).asoc.stream_reset_outstanding != 0 {
                                    error = 114i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 16057415118720189607;
                                }
                            } else {
                                current_block = 16057415118720189607;
                            }
                            match current_block {
                                13515130358667707052 => {}
                                _ => {
                                    let mut send_out = 0i32;
                                    if (*strrst).srs_flags as libc::c_int & 0x2i32 != 0 {
                                        send_out = 1i32
                                    }
                                    if (*strrst).srs_number_streams as libc::c_int > 200i32
                                        && send_in != 0
                                    {
                                        error = 12i32;
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    } else if send_in == 0i32 && send_out == 0i32 {
                                        error = 22i32;
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    } else {
                                        let mut i_0 = 0;
                                        i_0 = 0i32;
                                        while i_0 < (*strrst).srs_number_streams as libc::c_int {
                                            if send_in != 0
                                                && *(*strrst)
                                                    .srs_stream_list
                                                    .as_mut_ptr()
                                                    .offset(i_0 as isize)
                                                    as libc::c_int
                                                    >= (*stcb).asoc.streamincnt as libc::c_int
                                            {
                                                error = 22i32;
                                                break;
                                            } else if send_out != 0
                                                && *(*strrst)
                                                    .srs_stream_list
                                                    .as_mut_ptr()
                                                    .offset(i_0 as isize)
                                                    as libc::c_int
                                                    >= (*stcb).asoc.streamoutcnt as libc::c_int
                                            {
                                                error = 22i32;
                                                break;
                                            } else {
                                                i_0 += 1
                                            }
                                        }
                                        if error != 0 {
                                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                        } else {
                                            if send_out != 0 {
                                                let mut cnt = 0;
                                                if (*strrst).srs_number_streams != 0 {
                                                    i_0 = 0i32;
                                                    cnt = 0i32;
                                                    while i_0
                                                        < (*strrst).srs_number_streams
                                                            as libc::c_int
                                                    {
                                                        let mut strm = 0;
                                                        strm = *(*strrst)
                                                            .srs_stream_list
                                                            .as_mut_ptr()
                                                            .offset(i_0 as isize);
                                                        if (*(*stcb)
                                                            .asoc
                                                            .strmout
                                                            .offset(strm as isize))
                                                        .state
                                                            as libc::c_int
                                                            == 0x2i32
                                                        {
                                                            (*(*stcb)
                                                                .asoc
                                                                .strmout
                                                                .offset(strm as isize))
                                                            .state = 0x3u8;
                                                            cnt += 1
                                                        }
                                                        i_0 += 1
                                                    }
                                                } else {
                                                    /* Its all */
                                                    i_0 = 0i32;
                                                    cnt = 0i32;
                                                    while i_0
                                                        < (*stcb).asoc.streamoutcnt as libc::c_int
                                                    {
                                                        if (*(*stcb)
                                                            .asoc
                                                            .strmout
                                                            .offset(i_0 as isize))
                                                        .state
                                                            as libc::c_int
                                                            == 0x2i32
                                                        {
                                                            (*(*stcb)
                                                                .asoc
                                                                .strmout
                                                                .offset(i_0 as isize))
                                                            .state = 0x3u8;
                                                            cnt += 1
                                                        }
                                                        i_0 += 1
                                                    }
                                                }
                                            }
                                            if send_in != 0 {
                                                error = sctp_send_str_reset_req(
                                                    stcb,
                                                    (*strrst).srs_number_streams,
                                                    (*strrst).srs_stream_list.as_mut_ptr(),
                                                    send_in as uint8_t,
                                                    0u8,
                                                    0u8,
                                                    0u16,
                                                    0u16,
                                                    0u8,
                                                )
                                            } else {
                                                error = sctp_send_stream_reset_out_if_possible(
                                                    stcb, 1i32,
                                                )
                                            }
                                            if error == 0i32 {
                                                sctp_chunk_output(inp, stcb, 12i32, 1i32);
                                            } else {
                                                /*
                                                 * For outgoing streams don't report any problems in
                                                 * sending the request to the application.
                                                 * XXX: Double check resetting incoming streams.
                                                 */
                                                error = 0i32
                                            }
                                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        2307 => {
            if optsize < ::std::mem::size_of::<sctp_add_streams>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut stradd = 0 as *mut sctp_add_streams;
                stradd = optval as *mut sctp_add_streams;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 9807289104302690431;
                } else if (*stradd).sas_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*stradd).sas_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 9807289104302690431;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 9807289104302690431;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if stcb.is_null() {
                            error = 2i32
                        } else if (*stcb).asoc.reconfig_supported as libc::c_int == 0i32 {
                            /*
                             * Peer does not support the chunk type.
                             */
                            error = 95i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*stcb).asoc.state & 0x7fi32 != 0x8i32 {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*stcb).asoc.stream_reset_outstanding != 0 {
                            error = 114i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*stradd).sas_outstrms as libc::c_int == 0i32
                                && (*stradd).sas_instrms as libc::c_int == 0i32
                            {
                                error = 22i32
                            } else {
                                let mut addstream = 0u8;
                                let mut add_o_strmcnt = 0u16;
                                if (*stradd).sas_outstrms != 0 {
                                    addstream = 1u8;
                                    /* We allocate here */
                                    add_o_strmcnt = (*stradd).sas_outstrms;
                                    if add_o_strmcnt as libc::c_int
                                        + (*stcb).asoc.streamoutcnt as libc::c_int
                                        > 0xffffi32
                                    {
                                        /* You can't have more than 64k */
                                        error = 22i32;
                                        current_block = 15523506527172296258;
                                    } else {
                                        current_block = 2572519802022678944;
                                    }
                                } else {
                                    current_block = 2572519802022678944;
                                }
                                match current_block {
                                    15523506527172296258 => {}
                                    _ => {
                                        let mut add_i_strmcnt = 0u16;
                                        if (*stradd).sas_instrms != 0 {
                                            let mut cnt_0 = 0;
                                            addstream =
                                                (addstream as libc::c_int | 2i32) as uint8_t;
                                            /* We allocate inside sctp_send_str_reset_req() */
                                            add_i_strmcnt = (*stradd).sas_instrms;
                                            cnt_0 = add_i_strmcnt as libc::c_int;
                                            cnt_0 += (*stcb).asoc.streamincnt as libc::c_int;
                                            if cnt_0 > 0xffffi32 {
                                                /* You can't have more than 64k */
                                                error = 22i32;
                                                current_block = 15523506527172296258;
                                            } else if cnt_0
                                                > (*stcb).asoc.max_inbound_streams as libc::c_int
                                            {
                                                /* More than you are allowed */
                                                error = 22i32;
                                                current_block = 15523506527172296258;
                                            } else {
                                                current_block = 9270461330285003124;
                                            }
                                        } else {
                                            current_block = 9270461330285003124;
                                        }
                                        match current_block {
                                            15523506527172296258 => {}
                                            _ => {
                                                error = sctp_send_str_reset_req(
                                                    stcb,
                                                    0u16,
                                                    0 as *mut uint16_t,
                                                    0u8,
                                                    0u8,
                                                    addstream,
                                                    add_o_strmcnt,
                                                    add_i_strmcnt,
                                                    0u8,
                                                );
                                                sctp_chunk_output(inp, stcb, 12i32, 1i32);
                                            }
                                        }
                                    }
                                }
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
            }
        }
        2306 => {
            if optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut value_0 = 0 as *mut uint32_t;
                value_0 = optval as *mut uint32_t;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 8866555332191072766;
                } else if *value_0 > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, *value_0, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 8866555332191072766;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 8866555332191072766;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if stcb.is_null() {
                            error = 2i32
                        } else if (*stcb).asoc.reconfig_supported as libc::c_int == 0i32 {
                            /*
                             * Peer does not support the chunk type.
                             */
                            error = 95i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*stcb).asoc.state & 0x7fi32 != 0x8i32 {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*stcb).asoc.stream_reset_outstanding != 0 {
                            error = 114i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            /* Is there any data pending in the send or sent queues? */
                            if !(*stcb).asoc.send_queue.tqh_first.is_null()
                                || !(*stcb).asoc.sent_queue.tqh_first.is_null()
                            {
                                current_block = 9603911636750623490;
                            } else {
                                let mut i_1 = 0;
                                i_1 = 0i32;
                                loop {
                                    if !(i_1 < (*stcb).asoc.streamoutcnt as libc::c_int) {
                                        current_block = 14213571897897081603;
                                        break;
                                    }
                                    if !(*(*stcb).asoc.strmout.offset(i_1 as isize))
                                        .outqueue
                                        .tqh_first
                                        .is_null()
                                    {
                                        current_block = 9603911636750623490;
                                        break;
                                    }
                                    i_1 += 1
                                }
                                match current_block {
                                    9603911636750623490 => {}
                                    _ => {
                                        error = sctp_send_str_reset_req(
                                            stcb,
                                            0u16,
                                            0 as *mut uint16_t,
                                            0u8,
                                            1u8,
                                            0u8,
                                            0u16,
                                            0u16,
                                            0u8,
                                        );
                                        sctp_chunk_output(inp, stcb, 12i32, 1i32);
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                        current_block = 13515130358667707052;
                                    }
                                }
                            }
                            match current_block {
                                13515130358667707052 => {}
                                _ => {
                                    error = 16i32;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                }
                            }
                        }
                    }
                }
            }
        }
        32775 => {
            if optsize
                < (::std::mem::size_of::<libc::c_int>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong)
            {
                error = 22i32
            } else {
                error = sctp_do_connect_x(so, inp, optval, optsize, p, 0i32)
            }
        }
        32776 => {
            if optsize
                < (::std::mem::size_of::<libc::c_int>() as libc::c_ulong)
                    .wrapping_add(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong)
            {
                error = 22i32
            } else {
                error = sctp_do_connect_x(so, inp, optval, optsize, p, 1i32)
            }
        }
        32777 => {
            /* FIXME MT: check correct? */
            if optsize < ::std::mem::size_of::<sockaddr>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sa = 0 as *mut sockaddr;
                sa = optval as *mut sockaddr;
                /* find tcb */
                if (*inp).sctp_flags & 0x200000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                } else {
                    /* We increment here since sctp_findassociation_ep_addr() wil
                     * do a decrement if it finds the stcb as long as the locked
                     * tcb (last argument) is NOT a TCB.. aka NULL.
                     */
                    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                    stcb = sctp_findassociation_ep_addr(
                        &mut inp,
                        sa,
                        0 as *mut *mut sctp_nets,
                        0 as *mut sockaddr,
                        0 as *mut sctp_tcb,
                    );
                    if stcb.is_null() {
                        ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                    }
                }
                if stcb.is_null() {
                    error = 2i32
                } else {
                    if (*stcb).asoc.delayed_connection as libc::c_int == 1i32 {
                        (*stcb).asoc.delayed_connection = 0u8;
                        gettimeofday(&mut (*stcb).asoc.time_entered, 0 as *mut timezone);
                        sctp_timer_stop(
                            2i32,
                            inp,
                            stcb,
                            (*stcb).asoc.primary_destination,
                            (0x50000000i32 + 0x8i32) as uint32_t,
                        );
                        sctp_send_initiate(inp, stcb, 1i32);
                    } else {
                        /*
                         * already expired or did not use delayed
                         * connectx
                         */
                        error = 114i32
                    }
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                }
            }
        }
        25 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_6 = 0 as *mut sctp_assoc_value;
                av_6 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 9121943670071928338;
                } else if (*av_6).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_6).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 9121943670071928338;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 9121943670071928338;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*stcb).asoc.max_burst = (*av_6).assoc_value;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*av_6).assoc_id == 0u32 || (*av_6).assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                (*inp).sctp_ep.max_burst = (*av_6).assoc_value;
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*av_6).assoc_id == 1u32 || (*av_6).assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    (*stcb).asoc.max_burst = (*av_6).assoc_value;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        14 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_7 = 0 as *mut sctp_assoc_value;
                av_7 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 6867135362890989784;
                } else if (*av_7).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_7).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 6867135362890989784;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 6867135362890989784;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut ovh = 0;
                        if (*inp).sctp_flags & 0x4000000u32 != 0 {
                            ovh = (::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong)
                                .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                                .wrapping_add(::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
                                as libc::c_int
                        } else {
                            ovh = (::std::mem::size_of::<sctp_data_chunk>() as libc::c_ulong)
                                .wrapping_add(::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                                .wrapping_add(::std::mem::size_of::<ip>() as libc::c_ulong)
                                as libc::c_int
                        }
                        if !stcb.is_null() {
                            if (*av_7).assoc_value != 0 {
                                (*stcb).asoc.sctp_frag_point =
                                    (*av_7).assoc_value.wrapping_add(ovh as libc::c_uint)
                            } else {
                                (*stcb).asoc.sctp_frag_point = 65535u32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_7).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            /* FIXME MT: I think this is not in tune with the API ID */
                            if (*av_7).assoc_value != 0 {
                                (*inp).sctp_frag_point =
                                    (*av_7).assoc_value.wrapping_add(ovh as libc::c_uint)
                            } else {
                                (*inp).sctp_frag_point = 65535u32
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        12 => {
            if optsize < ::std::mem::size_of::<sctp_event_subscribe>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut events = 0 as *mut sctp_event_subscribe;
                events = optval as *mut sctp_event_subscribe;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if (*events).sctp_data_io_event != 0 {
                    (*inp).sctp_features |= 0x400u64
                } else {
                    (*inp).sctp_features &= !(0x400i32) as libc::c_ulong
                }
                if (*events).sctp_association_event != 0 {
                    (*inp).sctp_features |= 0x800u64
                } else {
                    (*inp).sctp_features &= !(0x800i32) as libc::c_ulong
                }
                if (*events).sctp_address_event != 0 {
                    (*inp).sctp_features |= 0x1000u64
                } else {
                    (*inp).sctp_features &= !(0x1000i32) as libc::c_ulong
                }
                if (*events).sctp_send_failure_event != 0 {
                    (*inp).sctp_features |= 0x4000u64
                } else {
                    (*inp).sctp_features &= !(0x4000i32) as libc::c_ulong
                }
                if (*events).sctp_peer_error_event != 0 {
                    (*inp).sctp_features |= 0x2000u64
                } else {
                    (*inp).sctp_features &= !(0x2000i32) as libc::c_ulong
                }
                if (*events).sctp_shutdown_event != 0 {
                    (*inp).sctp_features |= 0x8000u64
                } else {
                    (*inp).sctp_features &= !(0x8000i32) as libc::c_ulong
                }
                if (*events).sctp_partial_delivery_event != 0 {
                    (*inp).sctp_features |= 0x20000u64
                } else {
                    (*inp).sctp_features &= !(0x20000i32) as libc::c_ulong
                }
                if (*events).sctp_adaptation_layer_event != 0 {
                    (*inp).sctp_features |= 0x10000u64
                } else {
                    (*inp).sctp_features &= !(0x10000i32) as libc::c_ulong
                }
                if (*events).sctp_authentication_event != 0 {
                    (*inp).sctp_features |= 0x40000u64
                } else {
                    (*inp).sctp_features &= !(0x40000i32) as libc::c_ulong
                }
                if (*events).sctp_sender_dry_event != 0 {
                    (*inp).sctp_features |= 0x4000000u64
                } else {
                    (*inp).sctp_features &= !(0x4000000i32) as libc::c_ulong
                }
                if (*events).sctp_stream_reset_event != 0 {
                    (*inp).sctp_features |= 0x80000u64
                } else {
                    (*inp).sctp_features &= !(0x80000i32) as libc::c_ulong
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                stcb = (*inp).sctp_asoc_list.lh_first;
                while !stcb.is_null() {
                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    if (*events).sctp_association_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x800u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x800u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x800i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x800i32) as libc::c_ulong
                    }
                    if (*events).sctp_address_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x1000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x1000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x1000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x1000i32) as libc::c_ulong
                    }
                    if (*events).sctp_send_failure_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x4000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x4000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x4000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x4000i32) as libc::c_ulong
                    }
                    if (*events).sctp_peer_error_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x2000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x2000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x2000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x2000i32) as libc::c_ulong
                    }
                    if (*events).sctp_shutdown_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x8000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x8000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x8000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x8000i32) as libc::c_ulong
                    }
                    if (*events).sctp_partial_delivery_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x20000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x20000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x20000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x20000i32) as libc::c_ulong
                    }
                    if (*events).sctp_adaptation_layer_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x10000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x10000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x10000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x10000i32) as libc::c_ulong
                    }
                    if (*events).sctp_authentication_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x40000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x40000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x40000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x40000i32) as libc::c_ulong
                    }
                    if (*events).sctp_sender_dry_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x4000000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x4000000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x4000000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x4000000i32) as libc::c_ulong
                    }
                    if (*events).sctp_stream_reset_event != 0 {
                        if !stcb.is_null() {
                            (*stcb).asoc.sctp_features |= 0x80000u64
                        } else if !inp.is_null() {
                            (*inp).sctp_features |= 0x80000u64
                        }
                    } else if !stcb.is_null() {
                        (*stcb).asoc.sctp_features &= !(0x80000i32) as libc::c_ulong
                    } else if !inp.is_null() {
                        (*inp).sctp_features &= !(0x80000i32) as libc::c_ulong
                    }
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    stcb = (*stcb).sctp_tcblist.le_next
                }
                /* Send up the sender dry event only for 1-to-1 style sockets. */
                if (*events).sctp_sender_dry_event != 0 {
                    if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                        stcb = (*inp).sctp_asoc_list.lh_first;
                        if !stcb.is_null() {
                            pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                            if (*stcb).asoc.send_queue.tqh_first.is_null()
                                && (*stcb).asoc.sent_queue.tqh_first.is_null()
                                && (*stcb).asoc.stream_queue_cnt == 0u32
                            {
                                sctp_ulp_notify(26u32, stcb, 0u32, 0 as *mut libc::c_void, 1i32);
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        8 => {
            if optsize < ::std::mem::size_of::<sctp_setadaptation>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut adap_bits = 0 as *mut sctp_setadaptation;
                adap_bits = optval as *mut sctp_setadaptation;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                (*inp).sctp_ep.adaptation_layer_indicator = (*adap_bits).ssb_adaptation_ind;
                (*inp).sctp_ep.adaptation_layer_indicator_provided = 1u8;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        40704 => {
            if optsize < ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut vvv = 0 as *mut uint32_t;
                vvv = optval as *mut uint32_t;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                (*inp).sctp_ep.initial_sequence_debug = *vvv;
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        11 => {
            if optsize < ::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut s_info = 0 as *mut sctp_sndrcvinfo;
                s_info = optval as *mut sctp_sndrcvinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 1170867150189720048;
                } else if (*s_info).sinfo_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*s_info).sinfo_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 1170867150189720048;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 1170867150189720048;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            if ((*s_info).sinfo_stream as libc::c_int)
                                < (*stcb).asoc.streamoutcnt as libc::c_int
                            {
                                memcpy(
                                    &mut (*stcb).asoc.def_send as *mut sctp_nonpad_sndrcvinfo
                                        as *mut libc::c_void,
                                    s_info as *const libc::c_void,
                                    if optsize
                                        > ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>()
                                            as libc::c_ulong
                                    {
                                        ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>()
                                            as libc::c_ulong
                                    } else {
                                        optsize
                                    },
                                );
                            } else {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*s_info).sinfo_assoc_id == 0u32
                                        || (*s_info).sinfo_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                memcpy(
                                    &mut (*inp).def_send as *mut sctp_nonpad_sndrcvinfo
                                        as *mut libc::c_void,
                                    s_info as *const libc::c_void,
                                    if optsize
                                        > ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>()
                                            as libc::c_ulong
                                    {
                                        ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>()
                                            as libc::c_ulong
                                    } else {
                                        optsize
                                    },
                                );
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*s_info).sinfo_assoc_id == 1u32
                                    || (*s_info).sinfo_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    if ((*s_info).sinfo_stream as libc::c_int)
                                        < (*stcb).asoc.streamoutcnt as libc::c_int
                                    {
                                        memcpy(
                                            &mut (*stcb).asoc.def_send
                                                as *mut sctp_nonpad_sndrcvinfo
                                                as *mut libc::c_void,
                                            s_info as *const libc::c_void,
                                            if optsize
                                                > ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>()
                                                    as libc::c_ulong
                                            {
                                                ::std::mem::size_of::<sctp_nonpad_sndrcvinfo>()
                                                    as libc::c_ulong
                                            } else {
                                                optsize
                                            },
                                        );
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        10 => {
            if optsize < ::std::mem::size_of::<sctp_paddrparams>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut paddrp = 0 as *mut sctp_paddrparams;
                paddrp = optval as *mut sctp_paddrparams;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 17414622797861935605;
                } else if (*paddrp).spp_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*paddrp).spp_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 17414622797861935605;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 17414622797861935605;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut net_0 = 0 as *mut sctp_nets;
                        let mut addr = 0 as *mut sockaddr;
                        if (*paddrp).spp_address.ss_family as libc::c_int == 10i32 {
                            let mut sin6 = 0 as *mut sockaddr_in6;
                            sin6 = &mut (*paddrp).spp_address as *mut sockaddr_storage
                                as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store, sin6);
                                addr = &mut sin_store as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr = &mut (*paddrp).spp_address as *mut sockaddr_storage
                                    as *mut sockaddr
                            }
                        } else {
                            addr =
                                &mut (*paddrp).spp_address as *mut sockaddr_storage as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_0 = sctp_findnet(stcb, addr)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_0 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr,
                                &mut net_0,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && net_0.is_null() {
                            if (*addr).sa_family as libc::c_int == 2i32 {
                                let mut sin = 0 as *mut sockaddr_in;
                                sin = addr as *mut sockaddr_in;
                                if (*sin).sin_addr.s_addr != 0u32 {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 9460097188959224148;
                                }
                            } else if (*addr).sa_family as libc::c_int == 10i32 {
                                let mut sin6_0 = 0 as *mut sockaddr_in6;
                                sin6_0 = addr as *mut sockaddr_in6;
                                if ({
                                    let mut __a = &mut (*sin6_0).sin6_addr as *mut in6_addr
                                        as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                        as libc::c_int
                                }) == 0
                                {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 9460097188959224148;
                                }
                            } else if (*addr).sa_family as libc::c_int == 123i32 {
                                let mut sconn = 0 as *mut sockaddr_conn;
                                sconn = addr as *mut sockaddr_conn;
                                if !(*sconn).sconn_addr.is_null() {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 9460097188959224148;
                                }
                            } else {
                                error = 97i32;
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                current_block = 13515130358667707052;
                            }
                        } else {
                            current_block = 9460097188959224148;
                        }
                        match current_block {
                            13515130358667707052 => {}
                            _ => {
                                /* sanity checks */
                                if (*paddrp).spp_flags & 0x1u32 != 0
                                    && (*paddrp).spp_flags & 0x2u32 != 0
                                {
                                    if !stcb.is_null() {
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    }
                                    return 22i32;
                                }
                                if (*paddrp).spp_flags & 0x8u32 != 0
                                    && (*paddrp).spp_flags & 0x10u32 != 0
                                {
                                    if !stcb.is_null() {
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    }
                                    return 22i32;
                                }
                                if (*paddrp).spp_flags & 0x10u32 != 0
                                    && ((*paddrp).spp_pathmtu < 512u32
                                        || (*paddrp).spp_pathmtu > 65536u32)
                                {
                                    if !stcb.is_null() {
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    }
                                    return 22i32;
                                }
                                if !stcb.is_null() {
                                    /* ***********************TCB SPECIFIC SET ******************/
                                    if !net_0.is_null() {
                                        /* ***********************NET SPECIFIC SET ******************/
                                        if (*paddrp).spp_flags & 0x2u32 != 0 {
                                            if (*net_0).dest_state as libc::c_int & 0x200i32 == 0
                                                && (*net_0).dest_state as libc::c_int & 0x4i32 == 0
                                            {
                                                sctp_timer_stop(
                                                    5i32,
                                                    inp,
                                                    stcb,
                                                    net_0,
                                                    (0x50000000i32 + 0x9i32) as uint32_t,
                                                );
                                            }
                                            (*net_0).dest_state =
                                                ((*net_0).dest_state as libc::c_int | 0x4i32)
                                                    as uint16_t
                                        }
                                        if (*paddrp).spp_flags & 0x1u32 != 0 {
                                            if (*paddrp).spp_hbinterval != 0 {
                                                (*net_0).heart_beat_delay = (*paddrp).spp_hbinterval
                                            } else if (*paddrp).spp_flags & 0x80u32 != 0 {
                                                (*net_0).heart_beat_delay = 0u32
                                            }
                                            sctp_timer_stop(
                                                5i32,
                                                inp,
                                                stcb,
                                                net_0,
                                                (0x50000000i32 + 0xai32) as uint32_t,
                                            );
                                            sctp_timer_start(5i32, inp, stcb, net_0);
                                            (*net_0).dest_state =
                                                ((*net_0).dest_state as libc::c_int & !(0x4i32))
                                                    as uint16_t
                                        }
                                        if (*paddrp).spp_flags & 0x4u32 != 0 {
                                            if (*stcb).asoc.state & 0x7fi32 == 0x8i32 {
                                                sctp_send_hb(stcb, net_0, 1i32);
                                                sctp_chunk_output(inp, stcb, 17i32, 1i32);
                                                sctp_timer_start(5i32, inp, stcb, net_0);
                                            }
                                        }
                                        if (*paddrp).spp_flags & 0x10u32 != 0 {
                                            if (*net_0).pmtu_timer.timer.c_flags & 0x4i32 != 0 {
                                                sctp_timer_stop(
                                                    8i32,
                                                    inp,
                                                    stcb,
                                                    net_0,
                                                    (0x50000000i32 + 0xbi32) as uint32_t,
                                                );
                                            }
                                            (*net_0).dest_state =
                                                ((*net_0).dest_state as libc::c_int | 0x2i32)
                                                    as uint16_t;
                                            (*net_0).mtu = (*paddrp).spp_pathmtu;
                                            match (*net_0).ro._l_addr.sa.sa_family as libc::c_int {
                                                2 => {
                                                    (*net_0).mtu = ((*net_0).mtu as libc::c_ulong)
                                                        .wrapping_add(
                                                            (::std::mem::size_of::<ip>()
                                                                as libc::c_ulong)
                                                                .wrapping_add(
                                                                    ::std::mem::size_of::<sctphdr>()
                                                                        as libc::c_ulong,
                                                                ),
                                                        )
                                                        as uint32_t
                                                }
                                                10 => {
                                                    (*net_0).mtu = ((*net_0).mtu as libc::c_ulong)
                                                        .wrapping_add(
                                                            (::std::mem::size_of::<ip6_hdr>()
                                                                as libc::c_ulong)
                                                                .wrapping_add(
                                                                    ::std::mem::size_of::<sctphdr>()
                                                                        as libc::c_ulong,
                                                                ),
                                                        )
                                                        as uint32_t
                                                }
                                                123 => {
                                                    (*net_0).mtu = ((*net_0).mtu as libc::c_ulong)
                                                        .wrapping_add(
                                                            ::std::mem::size_of::<sctphdr>()
                                                                as libc::c_ulong,
                                                        )
                                                        as uint32_t
                                                }
                                                _ => {}
                                            }
                                            if (*net_0).mtu < (*stcb).asoc.smallest_mtu {
                                                sctp_pathmtu_adjustment(
                                                    stcb,
                                                    (*net_0).mtu as uint16_t,
                                                );
                                            }
                                        }
                                        if (*paddrp).spp_flags & 0x8u32 != 0 {
                                            if (*net_0).pmtu_timer.timer.c_flags & 0x4i32 == 0 {
                                                sctp_timer_start(8i32, inp, stcb, net_0);
                                            }
                                            (*net_0).dest_state =
                                                ((*net_0).dest_state as libc::c_int & !(0x2i32))
                                                    as uint16_t
                                        }
                                        if (*paddrp).spp_pathmaxrxt != 0 {
                                            if (*net_0).dest_state as libc::c_int & 0x800i32 != 0 {
                                                if (*net_0).error_count as libc::c_int
                                                    > (*paddrp).spp_pathmaxrxt as libc::c_int
                                                {
                                                    (*net_0).dest_state = ((*net_0).dest_state
                                                        as libc::c_int
                                                        & !(0x800i32))
                                                        as uint16_t
                                                }
                                            } else if (*net_0).error_count as libc::c_int
                                                <= (*paddrp).spp_pathmaxrxt as libc::c_int
                                                && (*net_0).error_count as libc::c_int
                                                    > (*net_0).pf_threshold as libc::c_int
                                            {
                                                (*net_0).dest_state =
                                                    ((*net_0).dest_state as libc::c_int | 0x800i32)
                                                        as uint16_t;
                                                sctp_send_hb(stcb, net_0, 1i32);
                                                sctp_timer_stop(
                                                    5i32,
                                                    (*stcb).sctp_ep,
                                                    stcb,
                                                    net_0,
                                                    (0x50000000i32 + 0xci32) as uint32_t,
                                                );
                                                sctp_timer_start(
                                                    5i32,
                                                    (*stcb).sctp_ep,
                                                    stcb,
                                                    net_0,
                                                );
                                            }
                                            if (*net_0).dest_state as libc::c_int & 0x1i32 != 0 {
                                                if (*net_0).error_count as libc::c_int
                                                    > (*paddrp).spp_pathmaxrxt as libc::c_int
                                                {
                                                    (*net_0).dest_state = ((*net_0).dest_state
                                                        as libc::c_int
                                                        & !(0x1i32))
                                                        as uint16_t;
                                                    sctp_ulp_notify(
                                                        3u32,
                                                        stcb,
                                                        0u32,
                                                        net_0 as *mut libc::c_void,
                                                        1i32,
                                                    );
                                                }
                                            } else if (*net_0).error_count as libc::c_int
                                                <= (*paddrp).spp_pathmaxrxt as libc::c_int
                                            {
                                                (*net_0).dest_state =
                                                    ((*net_0).dest_state as libc::c_int | 0x1i32)
                                                        as uint16_t;
                                                sctp_ulp_notify(
                                                    4u32,
                                                    stcb,
                                                    0u32,
                                                    net_0 as *mut libc::c_void,
                                                    1i32,
                                                );
                                            }
                                            (*net_0).failure_threshold = (*paddrp).spp_pathmaxrxt
                                        }
                                        if (*paddrp).spp_flags & 0x200u32 != 0 {
                                            (*net_0).dscp = ((*paddrp).spp_dscp as libc::c_int
                                                & 0xfci32)
                                                as uint8_t;
                                            (*net_0).dscp =
                                                ((*net_0).dscp as libc::c_int | 0x1i32) as uint8_t
                                        }
                                        if (*paddrp).spp_flags & 0x100u32 != 0 {
                                            if (*net_0).ro._l_addr.sa.sa_family as libc::c_int
                                                == 10i32
                                            {
                                                (*net_0).flowlabel =
                                                    (*paddrp).spp_ipv6_flowlabel & 0xfffffu32;
                                                (*net_0).flowlabel |= 0x80000000u32
                                            }
                                        }
                                    } else {
                                        /* ***********************ASSOC ONLY -- NO NET SPECIFIC SET ******************/
                                        if (*paddrp).spp_pathmaxrxt as libc::c_int != 0i32 {
                                            (*stcb).asoc.def_net_failure = (*paddrp).spp_pathmaxrxt;
                                            net_0 = (*stcb).asoc.nets.tqh_first;
                                            while !net_0.is_null() {
                                                if (*net_0).dest_state as libc::c_int & 0x800i32
                                                    != 0
                                                {
                                                    if (*net_0).error_count as libc::c_int
                                                        > (*paddrp).spp_pathmaxrxt as libc::c_int
                                                    {
                                                        (*net_0).dest_state = ((*net_0).dest_state
                                                            as libc::c_int
                                                            & !(0x800i32))
                                                            as uint16_t
                                                    }
                                                } else if (*net_0).error_count as libc::c_int
                                                    <= (*paddrp).spp_pathmaxrxt as libc::c_int
                                                    && (*net_0).error_count as libc::c_int
                                                        > (*net_0).pf_threshold as libc::c_int
                                                {
                                                    (*net_0).dest_state = ((*net_0).dest_state
                                                        as libc::c_int
                                                        | 0x800i32)
                                                        as uint16_t;
                                                    sctp_send_hb(stcb, net_0, 1i32);
                                                    sctp_timer_stop(
                                                        5i32,
                                                        (*stcb).sctp_ep,
                                                        stcb,
                                                        net_0,
                                                        (0x50000000i32 + 0xdi32) as uint32_t,
                                                    );
                                                    sctp_timer_start(
                                                        5i32,
                                                        (*stcb).sctp_ep,
                                                        stcb,
                                                        net_0,
                                                    );
                                                }
                                                if (*net_0).dest_state as libc::c_int & 0x1i32 != 0
                                                {
                                                    if (*net_0).error_count as libc::c_int
                                                        > (*paddrp).spp_pathmaxrxt as libc::c_int
                                                    {
                                                        (*net_0).dest_state = ((*net_0).dest_state
                                                            as libc::c_int
                                                            & !(0x1i32))
                                                            as uint16_t;
                                                        sctp_ulp_notify(
                                                            3u32,
                                                            stcb,
                                                            0u32,
                                                            net_0 as *mut libc::c_void,
                                                            1i32,
                                                        );
                                                    }
                                                } else if (*net_0).error_count as libc::c_int
                                                    <= (*paddrp).spp_pathmaxrxt as libc::c_int
                                                {
                                                    (*net_0).dest_state = ((*net_0).dest_state
                                                        as libc::c_int
                                                        | 0x1i32)
                                                        as uint16_t;
                                                    sctp_ulp_notify(
                                                        4u32,
                                                        stcb,
                                                        0u32,
                                                        net_0 as *mut libc::c_void,
                                                        1i32,
                                                    );
                                                }
                                                (*net_0).failure_threshold =
                                                    (*paddrp).spp_pathmaxrxt;
                                                net_0 = (*net_0).sctp_next.tqe_next
                                            }
                                        }
                                        if (*paddrp).spp_flags & 0x1u32 != 0 {
                                            if (*paddrp).spp_hbinterval != 0u32 {
                                                (*stcb).asoc.heart_beat_delay =
                                                    (*paddrp).spp_hbinterval
                                            } else if (*paddrp).spp_flags & 0x80u32 != 0 {
                                                (*stcb).asoc.heart_beat_delay = 0u32
                                            }
                                            /* Turn back on the timer */
                                            net_0 = (*stcb).asoc.nets.tqh_first;
                                            while !net_0.is_null() {
                                                if (*paddrp).spp_hbinterval != 0u32 {
                                                    (*net_0).heart_beat_delay =
                                                        (*paddrp).spp_hbinterval
                                                } else if (*paddrp).spp_flags & 0x80u32 != 0 {
                                                    (*net_0).heart_beat_delay = 0u32
                                                }
                                                if (*net_0).dest_state as libc::c_int & 0x4i32 != 0
                                                {
                                                    (*net_0).dest_state = ((*net_0).dest_state
                                                        as libc::c_int
                                                        & !(0x4i32))
                                                        as uint16_t
                                                }
                                                sctp_timer_stop(
                                                    5i32,
                                                    inp,
                                                    stcb,
                                                    net_0,
                                                    (0x50000000i32 + 0xei32) as uint32_t,
                                                );
                                                sctp_timer_start(5i32, inp, stcb, net_0);
                                                net_0 = (*net_0).sctp_next.tqe_next
                                            }
                                            if !stcb.is_null() {
                                                (*stcb).asoc.sctp_features &=
                                                    !(0x4i32) as libc::c_ulong
                                            } else if !inp.is_null() {
                                                (*inp).sctp_features &= !(0x4i32) as libc::c_ulong
                                            }
                                        }
                                        if (*paddrp).spp_flags & 0x2u32 != 0 {
                                            net_0 = (*stcb).asoc.nets.tqh_first;
                                            while !net_0.is_null() {
                                                if (*net_0).dest_state as libc::c_int & 0x4i32 == 0
                                                {
                                                    (*net_0).dest_state = ((*net_0).dest_state
                                                        as libc::c_int
                                                        | 0x4i32)
                                                        as uint16_t;
                                                    if (*net_0).dest_state as libc::c_int & 0x200i32
                                                        == 0
                                                    {
                                                        sctp_timer_stop(
                                                            5i32,
                                                            inp,
                                                            stcb,
                                                            net_0,
                                                            (0x50000000i32 + 0xfi32) as uint32_t,
                                                        );
                                                    }
                                                }
                                                net_0 = (*net_0).sctp_next.tqe_next
                                            }
                                            if !stcb.is_null() {
                                                (*stcb).asoc.sctp_features |= 0x4u64
                                            } else if !inp.is_null() {
                                                (*inp).sctp_features |= 0x4u64
                                            }
                                        }
                                        if (*paddrp).spp_flags & 0x10u32 != 0 {
                                            net_0 = (*stcb).asoc.nets.tqh_first;
                                            while !net_0.is_null() {
                                                if (*net_0).pmtu_timer.timer.c_flags & 0x4i32 != 0 {
                                                    sctp_timer_stop(
                                                        8i32,
                                                        inp,
                                                        stcb,
                                                        net_0,
                                                        (0x50000000i32 + 0x10i32) as uint32_t,
                                                    );
                                                }
                                                (*net_0).dest_state =
                                                    ((*net_0).dest_state as libc::c_int | 0x2i32)
                                                        as uint16_t;
                                                (*net_0).mtu = (*paddrp).spp_pathmtu;
                                                match (*net_0).ro._l_addr.sa.sa_family
                                                    as libc::c_int
                                                {
                                                    2 => (*net_0).mtu = ((*net_0).mtu
                                                        as libc::c_ulong)
                                                        .wrapping_add(
                                                            (::std::mem::size_of::<ip>()
                                                                as libc::c_ulong)
                                                                .wrapping_add(
                                                                    ::std::mem::size_of::<sctphdr>()
                                                                        as libc::c_ulong,
                                                                ),
                                                        )
                                                        as uint32_t,
                                                    10 => (*net_0).mtu = ((*net_0).mtu
                                                        as libc::c_ulong)
                                                        .wrapping_add(
                                                            (::std::mem::size_of::<ip6_hdr>()
                                                                as libc::c_ulong)
                                                                .wrapping_add(
                                                                    ::std::mem::size_of::<sctphdr>()
                                                                        as libc::c_ulong,
                                                                ),
                                                        )
                                                        as uint32_t,
                                                    123 => {
                                                        (*net_0).mtu =
                                                            ((*net_0).mtu as libc::c_ulong)
                                                                .wrapping_add(
                                                                    ::std::mem::size_of::<sctphdr>()
                                                                        as libc::c_ulong,
                                                                )
                                                                as uint32_t
                                                    }
                                                    _ => {}
                                                }
                                                if (*net_0).mtu < (*stcb).asoc.smallest_mtu {
                                                    sctp_pathmtu_adjustment(
                                                        stcb,
                                                        (*net_0).mtu as uint16_t,
                                                    );
                                                }
                                                net_0 = (*net_0).sctp_next.tqe_next
                                            }
                                            (*stcb).asoc.default_mtu = (*paddrp).spp_pathmtu;
                                            if !stcb.is_null() {
                                                (*stcb).asoc.sctp_features |= 0x1u64
                                            } else if !inp.is_null() {
                                                (*inp).sctp_features |= 0x1u64
                                            }
                                        }
                                        if (*paddrp).spp_flags & 0x8u32 != 0 {
                                            net_0 = (*stcb).asoc.nets.tqh_first;
                                            while !net_0.is_null() {
                                                if (*net_0).pmtu_timer.timer.c_flags & 0x4i32 == 0 {
                                                    sctp_timer_start(8i32, inp, stcb, net_0);
                                                }
                                                (*net_0).dest_state = ((*net_0).dest_state
                                                    as libc::c_int
                                                    & !(0x2i32))
                                                    as uint16_t;
                                                net_0 = (*net_0).sctp_next.tqe_next
                                            }
                                            (*stcb).asoc.default_mtu = 0u32;
                                            if !stcb.is_null() {
                                                (*stcb).asoc.sctp_features &=
                                                    !(0x1i32) as libc::c_ulong
                                            } else if !inp.is_null() {
                                                (*inp).sctp_features &= !(0x1i32) as libc::c_ulong
                                            }
                                        }
                                        if (*paddrp).spp_flags & 0x200u32 != 0 {
                                            net_0 = (*stcb).asoc.nets.tqh_first;
                                            while !net_0.is_null() {
                                                (*net_0).dscp = ((*paddrp).spp_dscp as libc::c_int
                                                    & 0xfci32)
                                                    as uint8_t;
                                                (*net_0).dscp = ((*net_0).dscp as libc::c_int
                                                    | 0x1i32)
                                                    as uint8_t;
                                                net_0 = (*net_0).sctp_next.tqe_next
                                            }
                                            (*stcb).asoc.default_dscp =
                                                ((*paddrp).spp_dscp as libc::c_int & 0xfci32)
                                                    as uint8_t;
                                            (*stcb).asoc.default_dscp =
                                                ((*stcb).asoc.default_dscp as libc::c_int | 0x1i32)
                                                    as uint8_t
                                        }
                                        if (*paddrp).spp_flags & 0x100u32 != 0 {
                                            net_0 = (*stcb).asoc.nets.tqh_first;
                                            while !net_0.is_null() {
                                                if (*net_0).ro._l_addr.sa.sa_family as libc::c_int
                                                    == 10i32
                                                {
                                                    (*net_0).flowlabel =
                                                        (*paddrp).spp_ipv6_flowlabel & 0xfffffu32;
                                                    (*net_0).flowlabel |= 0x80000000u32
                                                }
                                                net_0 = (*net_0).sctp_next.tqe_next
                                            }
                                            (*stcb).asoc.default_flowlabel =
                                                (*paddrp).spp_ipv6_flowlabel & 0xfffffu32;
                                            (*stcb).asoc.default_flowlabel |= 0x80000000u32
                                        }
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                } else if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && (*paddrp).spp_assoc_id == 0u32
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    /* ***********************NO TCB, SET TO default stuff ******************/
                                    /*
                                     * For the TOS/FLOWLABEL stuff you set it
                                     * with the options on the socket
                                     */
                                    if (*paddrp).spp_pathmaxrxt as libc::c_int != 0i32 {
                                        (*inp).sctp_ep.def_net_failure = (*paddrp).spp_pathmaxrxt
                                    }
                                    if (*paddrp).spp_flags & 0x80u32 != 0 {
                                        (*inp).sctp_ep.sctp_timeoutticks[3usize] = 0u32
                                    } else if (*paddrp).spp_hbinterval != 0u32 {
                                        if (*paddrp).spp_hbinterval > 14400000u32 {
                                            (*paddrp).spp_hbinterval = 14400000u32
                                        }
                                        (*inp).sctp_ep.sctp_timeoutticks[3usize] = if hz == 1000i32
                                        {
                                            (*paddrp).spp_hbinterval
                                        } else {
                                            (*paddrp)
                                                .spp_hbinterval
                                                .wrapping_mul(hz as libc::c_uint)
                                                .wrapping_add(999u32)
                                                .wrapping_div(1000u32)
                                        }
                                    }
                                    if (*paddrp).spp_flags & 0x1u32 != 0 {
                                        if (*paddrp).spp_flags & 0x80u32 != 0 {
                                            (*inp).sctp_ep.sctp_timeoutticks[3usize] = 0u32
                                        } else if (*paddrp).spp_hbinterval != 0 {
                                            (*inp).sctp_ep.sctp_timeoutticks[3usize] =
                                                if hz == 1000i32 {
                                                    (*paddrp).spp_hbinterval
                                                } else {
                                                    (*paddrp)
                                                        .spp_hbinterval
                                                        .wrapping_mul(hz as libc::c_uint)
                                                        .wrapping_add(999u32)
                                                        .wrapping_div(1000u32)
                                                }
                                        }
                                        (*inp).sctp_features &= !(0x4i32) as libc::c_ulong
                                    } else if (*paddrp).spp_flags & 0x2u32 != 0 {
                                        (*inp).sctp_features |= 0x4u64
                                    }
                                    if (*paddrp).spp_flags & 0x8u32 != 0 {
                                        (*inp).sctp_ep.default_mtu = 0u32;
                                        (*inp).sctp_features &= !(0x1i32) as libc::c_ulong
                                    } else if (*paddrp).spp_flags & 0x10u32 != 0 {
                                        (*inp).sctp_ep.default_mtu = (*paddrp).spp_pathmtu;
                                        (*inp).sctp_features |= 0x1u64
                                    }
                                    if (*paddrp).spp_flags & 0x200u32 != 0 {
                                        (*inp).sctp_ep.default_dscp =
                                            ((*paddrp).spp_dscp as libc::c_int & 0xfci32)
                                                as uint8_t;
                                        (*inp).sctp_ep.default_dscp =
                                            ((*inp).sctp_ep.default_dscp as libc::c_int | 0x1i32)
                                                as uint8_t
                                    }
                                    if (*paddrp).spp_flags & 0x100u32 != 0 {
                                        if (*inp).sctp_flags & 0x4000000u32 != 0 {
                                            (*inp).sctp_ep.default_flowlabel =
                                                (*paddrp).spp_ipv6_flowlabel & 0xfffffu32;
                                            (*inp).sctp_ep.default_flowlabel |= 0x80000000u32
                                        }
                                    }
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                } else {
                                    error = 22i32
                                }
                            }
                        }
                    }
                }
            }
        }
        1 => {
            if optsize < ::std::mem::size_of::<sctp_rtoinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut srto = 0 as *mut sctp_rtoinfo;
                srto = optval as *mut sctp_rtoinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 1106491687089200498;
                } else if (*srto).srto_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*srto).srto_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 1106491687089200498;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 1106491687089200498;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut new_init = 0;
                        let mut new_min = 0;
                        let mut new_max = 0;
                        if !stcb.is_null() {
                            if (*srto).srto_initial != 0 {
                                new_init = (*srto).srto_initial
                            } else {
                                new_init = (*stcb).asoc.initial_rto
                            }
                            if (*srto).srto_max != 0 {
                                new_max = (*srto).srto_max
                            } else {
                                new_max = (*stcb).asoc.maxrto
                            }
                            if (*srto).srto_min != 0 {
                                new_min = (*srto).srto_min
                            } else {
                                new_min = (*stcb).asoc.minrto
                            }
                            if new_min <= new_init && new_init <= new_max {
                                (*stcb).asoc.initial_rto = new_init;
                                (*stcb).asoc.maxrto = new_max;
                                (*stcb).asoc.minrto = new_min
                            } else {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*srto).srto_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*srto).srto_initial != 0 {
                                new_init = (*srto).srto_initial
                            } else {
                                new_init = (*inp).sctp_ep.initial_rto
                            }
                            if (*srto).srto_max != 0 {
                                new_max = (*srto).srto_max
                            } else {
                                new_max = (*inp).sctp_ep.sctp_maxrto
                            }
                            if (*srto).srto_min != 0 {
                                new_min = (*srto).srto_min
                            } else {
                                new_min = (*inp).sctp_ep.sctp_minrto
                            }
                            if new_min <= new_init && new_init <= new_max {
                                (*inp).sctp_ep.initial_rto = new_init;
                                (*inp).sctp_ep.sctp_maxrto = new_max;
                                (*inp).sctp_ep.sctp_minrto = new_min
                            } else {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        2 => {
            if optsize < ::std::mem::size_of::<sctp_assocparams>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sasoc = 0 as *mut sctp_assocparams;
                sasoc = optval as *mut sctp_assocparams;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 10022840432029039528;
                } else if (*sasoc).sasoc_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sasoc).sasoc_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 10022840432029039528;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 10022840432029039528;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if (*sasoc).sasoc_cookie_life != 0 {
                            /* boundary check the cookie life */
                            if (*sasoc).sasoc_cookie_life < 1000u32 {
                                (*sasoc).sasoc_cookie_life = 1000u32
                            }
                            if (*sasoc).sasoc_cookie_life > 3600000u32 {
                                (*sasoc).sasoc_cookie_life = 3600000u32
                            }
                        }
                        if !stcb.is_null() {
                            if (*sasoc).sasoc_asocmaxrxt != 0 {
                                (*stcb).asoc.max_send_times = (*sasoc).sasoc_asocmaxrxt
                            }
                            if (*sasoc).sasoc_cookie_life != 0 {
                                (*stcb).asoc.cookie_life = if hz == 1000i32 {
                                    (*sasoc).sasoc_cookie_life
                                } else {
                                    (*sasoc)
                                        .sasoc_cookie_life
                                        .wrapping_mul(hz as libc::c_uint)
                                        .wrapping_add(999u32)
                                        .wrapping_div(1000u32)
                                }
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*sasoc).sasoc_assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*sasoc).sasoc_asocmaxrxt != 0 {
                                (*inp).sctp_ep.max_send_times = (*sasoc).sasoc_asocmaxrxt
                            }
                            if (*sasoc).sasoc_cookie_life != 0 {
                                (*inp).sctp_ep.def_cookie_life = if hz == 1000i32 {
                                    (*sasoc).sasoc_cookie_life
                                } else {
                                    (*sasoc)
                                        .sasoc_cookie_life
                                        .wrapping_mul(hz as libc::c_uint)
                                        .wrapping_add(999u32)
                                        .wrapping_div(1000u32)
                                }
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        3 => {
            if optsize < ::std::mem::size_of::<sctp_initmsg>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sinit = 0 as *mut sctp_initmsg;
                sinit = optval as *mut sctp_initmsg;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if (*sinit).sinit_num_ostreams != 0 {
                    (*inp).sctp_ep.pre_open_stream_count = (*sinit).sinit_num_ostreams
                }
                if (*sinit).sinit_max_instreams != 0 {
                    (*inp).sctp_ep.max_open_streams_intome = (*sinit).sinit_max_instreams
                }
                if (*sinit).sinit_max_attempts != 0 {
                    (*inp).sctp_ep.max_init_times = (*sinit).sinit_max_attempts
                }
                if (*sinit).sinit_max_init_timeo != 0 {
                    (*inp).sctp_ep.initial_init_rto_max =
                        (*sinit).sinit_max_init_timeo as libc::c_int
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        7 => {
            if optsize < ::std::mem::size_of::<sctp_setprim>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut spa = 0 as *mut sctp_setprim;
                spa = optval as *mut sctp_setprim;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 17448300121533256200;
                } else if (*spa).ssp_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*spa).ssp_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 17448300121533256200;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 17448300121533256200;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut net_1 = 0 as *mut sctp_nets;
                        let mut addr_0 = 0 as *mut sockaddr;
                        if (*spa).ssp_addr.ss_family as libc::c_int == 10i32 {
                            let mut sin6_1 = 0 as *mut sockaddr_in6;
                            sin6_1 =
                                &mut (*spa).ssp_addr as *mut sockaddr_storage as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6_1).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store_0 = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store_0, sin6_1);
                                addr_0 = &mut sin_store_0 as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr_0 =
                                    &mut (*spa).ssp_addr as *mut sockaddr_storage as *mut sockaddr
                            }
                        } else {
                            addr_0 = &mut (*spa).ssp_addr as *mut sockaddr_storage as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_1 = sctp_findnet(stcb, addr_0)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_1 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr_0,
                                &mut net_1,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && !net_1.is_null() {
                            if net_1 != (*stcb).asoc.primary_destination {
                                if (*net_1).dest_state as libc::c_int & 0x200i32 == 0 {
                                    /* Ok we need to set it */
                                    if sctp_set_primary_addr(stcb, 0 as *mut sockaddr, net_1)
                                        == 0i32
                                    {
                                        if !(*stcb).asoc.alternate.is_null()
                                            && (*net_1).dest_state as libc::c_int & 0x800i32 == 0
                                            && (*net_1).dest_state as libc::c_int & 0x1i32 != 0
                                        {
                                            if !(*stcb).asoc.alternate.is_null() {
                                                if ::std::intrinsics::atomic_xadd(
                                                    &mut (*(*stcb).asoc.alternate).ref_count
                                                        as *mut libc::c_int,
                                                    -(1i32),
                                                ) == 1i32
                                                {
                                                    sctp_os_timer_stop(
                                                        &mut (*(*stcb).asoc.alternate)
                                                            .rxt_timer
                                                            .timer,
                                                    );
                                                    sctp_os_timer_stop(
                                                        &mut (*(*stcb).asoc.alternate)
                                                            .pmtu_timer
                                                            .timer,
                                                    );
                                                    sctp_os_timer_stop(
                                                        &mut (*(*stcb).asoc.alternate)
                                                            .hb_timer
                                                            .timer,
                                                    );
                                                    if !(*(*stcb).asoc.alternate).ro.ro_rt.is_null()
                                                    {
                                                        if (*(*(*stcb).asoc.alternate).ro.ro_rt)
                                                            .rt_refcnt
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
                                                    if (*(*stcb).asoc.alternate).src_addr_selected
                                                        != 0
                                                    {
                                                        sctp_free_ifa(
                                                            (*(*stcb).asoc.alternate).ro._s_addr,
                                                        );
                                                        (*(*stcb).asoc.alternate).ro._s_addr =
                                                            0 as *mut sctp_ifa
                                                    }
                                                    (*(*stcb).asoc.alternate).src_addr_selected =
                                                        0u8;
                                                    (*(*stcb).asoc.alternate).dest_state =
                                                        ((*(*stcb).asoc.alternate).dest_state
                                                            as libc::c_int
                                                            & !(0x1i32))
                                                            as uint16_t;
                                                    free(
                                                        (*stcb).asoc.alternate as *mut libc::c_void,
                                                    );
                                                    ::std::intrinsics::atomic_xsub(
                                                        &mut system_base_info
                                                            .sctppcbinfo
                                                            .ipi_count_raddr,
                                                        1u32,
                                                    );
                                                }
                                            }
                                            (*stcb).asoc.alternate = 0 as *mut sctp_nets
                                        }
                                    } else {
                                        error = 22i32
                                    }
                                } else {
                                    error = 22i32
                                }
                            }
                        } else {
                            error = 22i32
                        }
                        if !stcb.is_null() {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
            }
        }
        8193 => {
            if optsize < ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut ss = 0 as *mut sctp_sockstore;
                ss = optval as *mut sctp_sockstore;
                /* SUPER USER CHECK? */
                error = sctp_dynamic_set_primary(&mut (*ss).sa, vrf_id)
            }
        }
        6 => {
            if optsize < ::std::mem::size_of::<sctp_setpeerprim>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut sspp = 0 as *mut sctp_setpeerprim;
                sspp = optval as *mut sctp_setpeerprim;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 4443026054951337226;
                } else if (*sspp).sspp_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*sspp).sspp_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 4443026054951337226;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 4443026054951337226;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            let mut addr_1 = 0 as *mut sockaddr;
                            let mut ifa = 0 as *mut sctp_ifa;
                            if (*sspp).sspp_addr.ss_family as libc::c_int == 10i32 {
                                let mut sin6_2 = 0 as *mut sockaddr_in6;
                                sin6_2 = &mut (*sspp).sspp_addr as *mut sockaddr_storage
                                    as *mut sockaddr_in6;
                                if ({
                                    let mut __a = &mut (*sin6_2).sin6_addr as *mut in6_addr
                                        as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                        as libc::c_int
                                }) != 0
                                {
                                    let mut sin_store_1 = sockaddr_in {
                                        sin_family: 0,
                                        sin_port: 0,
                                        sin_addr: in_addr { s_addr: 0 },
                                        sin_zero: [0; 8],
                                    };
                                    in6_sin6_2_sin(&mut sin_store_1, sin6_2);
                                    addr_1 = &mut sin_store_1 as *mut sockaddr_in as *mut sockaddr
                                } else {
                                    addr_1 = &mut (*sspp).sspp_addr as *mut sockaddr_storage
                                        as *mut sockaddr
                                }
                            } else {
                                addr_1 =
                                    &mut (*sspp).sspp_addr as *mut sockaddr_storage as *mut sockaddr
                            }
                            ifa = sctp_find_ifa_by_addr(addr_1, (*stcb).asoc.vrf_id, 0i32);
                            if ifa.is_null() {
                                error = 22i32
                            } else {
                                if (*inp).sctp_flags & 0x4u32 == 0u32 {
                                    let mut laddr = 0 as *mut sctp_laddr;
                                    let mut found = 0i32;
                                    laddr = (*inp).sctp_addr_list.lh_first;
                                    while !laddr.is_null() {
                                        if (*laddr).ifa.is_null() {
                                            if system_base_info.sctpsysctl.sctp_debug_on & 0x10u32
                                                != 0
                                            {
                                                if system_base_info.debug_printf.is_some() {
                                                    system_base_info
                                                        .debug_printf
                                                        .expect("non-null function pointer")(
                                                        b"%s: NULL ifa\n\x00" as *const u8
                                                            as *const libc::c_char,
                                                        (*::std::mem::transmute::<
                                                            &[u8; 12],
                                                            &[libc::c_char; 12],
                                                        >(
                                                            b"sctp_setopt\x00"
                                                        ))
                                                        .as_ptr(),
                                                    );
                                                }
                                            }
                                        } else if !(sctp_is_addr_restricted(stcb, (*laddr).ifa)
                                            != 0
                                            && sctp_is_addr_pending(stcb, (*laddr).ifa) == 0)
                                        {
                                            if (*laddr).ifa == ifa {
                                                found = 1i32;
                                                break;
                                            }
                                        }
                                        laddr = (*laddr).sctp_nxt_addr.le_next
                                    }
                                    if found == 0 {
                                        error = 22i32;
                                        current_block = 455258607574059780;
                                    } else {
                                        current_block = 13433739829890827173;
                                    }
                                } else {
                                    current_block = 13433739829890827173;
                                }
                                match current_block {
                                    455258607574059780 => {}
                                    _ => {
                                        if sctp_set_primary_ip_address_sa(stcb, addr_1) != 0i32 {
                                            error = 22i32
                                        }
                                        sctp_chunk_output(inp, stcb, 17i32, 1i32);
                                    }
                                }
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        32769 => {
            if optsize < ::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut addrs = 0 as *mut sctp_getaddresses;
                addrs = optval as *mut sctp_getaddresses;
                if (*(*addrs).addr.as_mut_ptr()).sa_family as libc::c_int == 2i32 {
                    if optsize
                        < (::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong)
                            .wrapping_sub(::std::mem::size_of::<sockaddr>() as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong)
                    {
                        error = 22i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 12299674041094913965;
                    }
                } else if (*(*addrs).addr.as_mut_ptr()).sa_family as libc::c_int == 10i32 {
                    if optsize
                        < (::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong)
                            .wrapping_sub(::std::mem::size_of::<sockaddr>() as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong)
                    {
                        error = 22i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 12299674041094913965;
                    }
                } else {
                    error = 97i32;
                    current_block = 13515130358667707052;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        sctp_bindx_add_address(
                            so,
                            inp,
                            (*addrs).addr.as_mut_ptr(),
                            (*addrs).sget_assoc_id,
                            vrf_id,
                            &mut error,
                            p,
                        );
                    }
                }
            }
        }
        32770 => {
            if optsize < ::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut addrs_0 = 0 as *mut sctp_getaddresses;
                addrs_0 = optval as *mut sctp_getaddresses;
                if (*(*addrs_0).addr.as_mut_ptr()).sa_family as libc::c_int == 2i32 {
                    if optsize
                        < (::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong)
                            .wrapping_sub(::std::mem::size_of::<sockaddr>() as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong)
                    {
                        error = 22i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 13934127387459307610;
                    }
                } else if (*(*addrs_0).addr.as_mut_ptr()).sa_family as libc::c_int == 10i32 {
                    if optsize
                        < (::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong)
                            .wrapping_sub(::std::mem::size_of::<sockaddr>() as libc::c_ulong)
                            .wrapping_add(::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong)
                    {
                        error = 22i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 13934127387459307610;
                    }
                } else {
                    error = 97i32;
                    current_block = 13515130358667707052;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        sctp_bindx_delete_address(
                            inp,
                            (*addrs_0).addr.as_mut_ptr(),
                            (*addrs_0).sget_assoc_id,
                            vrf_id,
                            &mut error,
                        );
                    }
                }
            }
        }
        30 => {
            if optsize < ::std::mem::size_of::<sctp_event>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut event = 0 as *mut sctp_event;
                event = optval as *mut sctp_event;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 388090809815178464;
                } else if (*event).se_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*event).se_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 388090809815178464;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 388090809815178464;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut event_type = 0;
                        match (*event).se_type as libc::c_int {
                            1 => event_type = 0x800u32,
                            2 => event_type = 0x1000u32,
                            3 => event_type = 0x2000u32,
                            4 => event_type = 0x4000u32,
                            5 => event_type = 0x8000u32,
                            6 => event_type = 0x10000u32,
                            7 => event_type = 0x20000u32,
                            8 => event_type = 0x40000u32,
                            9 => event_type = 0x80000u32,
                            10 => event_type = 0x4000000u32,
                            11 => {
                                event_type = 0u32;
                                error = 95i32
                            }
                            12 => event_type = 0x20000000u32,
                            13 => event_type = 0x40000000u32,
                            14 => event_type = 0x80000000u32,
                            _ => {
                                event_type = 0u32;
                                error = 22i32
                            }
                        }
                        if event_type > 0u32 {
                            if !stcb.is_null() {
                                if (*event).se_on != 0 {
                                    if !stcb.is_null() {
                                        (*stcb).asoc.sctp_features |= event_type as libc::c_ulong
                                    } else if !inp.is_null() {
                                        (*inp).sctp_features |= event_type as libc::c_ulong
                                    }
                                    if event_type == 0x4000000u32 {
                                        if (*stcb).asoc.send_queue.tqh_first.is_null()
                                            && (*stcb).asoc.sent_queue.tqh_first.is_null()
                                            && (*stcb).asoc.stream_queue_cnt == 0u32
                                        {
                                            sctp_ulp_notify(
                                                26u32,
                                                stcb,
                                                0u32,
                                                0 as *mut libc::c_void,
                                                1i32,
                                            );
                                        }
                                    }
                                } else if !stcb.is_null() {
                                    (*stcb).asoc.sctp_features &= !event_type as libc::c_ulong
                                } else if !inp.is_null() {
                                    (*inp).sctp_features &= !event_type as libc::c_ulong
                                }
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            } else if event_type == 0x4000000u32
                                && (*inp).sctp_flags & 0x1u32 != 0
                                && ((*event).se_assoc_id == 2u32 || (*event).se_assoc_id == 1u32)
                            {
                                error = 95i32
                            } else {
                                if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && ((*event).se_assoc_id == 0u32
                                            || (*event).se_assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    if (*event).se_on != 0 {
                                        (*inp).sctp_features |= event_type as libc::c_ulong
                                    } else {
                                        (*inp).sctp_features &= !event_type as libc::c_ulong
                                    }
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                                if (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*event).se_assoc_id == 1u32
                                        || (*event).se_assoc_id == 2u32)
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    stcb = (*inp).sctp_asoc_list.lh_first;
                                    while !stcb.is_null() {
                                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                        if (*event).se_on != 0 {
                                            if !stcb.is_null() {
                                                (*stcb).asoc.sctp_features |=
                                                    event_type as libc::c_ulong
                                            } else if !inp.is_null() {
                                                (*inp).sctp_features |= event_type as libc::c_ulong
                                            }
                                        } else if !stcb.is_null() {
                                            (*stcb).asoc.sctp_features &=
                                                !event_type as libc::c_ulong
                                        } else if !inp.is_null() {
                                            (*inp).sctp_features &= !event_type as libc::c_ulong
                                        }
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                        stcb = (*stcb).sctp_tcblist.le_next
                                    }
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                }
                            }
                        } else if !stcb.is_null() {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
            }
        }
        31 => {
            if optsize < ::std::mem::size_of::<libc::c_int>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut onoff = 0 as *mut libc::c_int;
                onoff = optval as *mut libc::c_int;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if *onoff != 0i32 {
                    (*inp).sctp_features |= 0x8000000u64
                } else {
                    (*inp).sctp_features &= !(0x8000000i32) as libc::c_ulong
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        32 => {
            if optsize < ::std::mem::size_of::<libc::c_int>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut onoff_0 = 0 as *mut libc::c_int;
                onoff_0 = optval as *mut libc::c_int;
                pthread_mutex_lock(&mut (*inp).inp_mtx);
                if *onoff_0 != 0i32 {
                    (*inp).sctp_features |= 0x10000000u64
                } else {
                    (*inp).sctp_features &= !(0x10000000i32) as libc::c_ulong
                }
                pthread_mutex_unlock(&mut (*inp).inp_mtx);
            }
        }
        33 => {
            if optsize < ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut info = 0 as *mut sctp_sndinfo;
                info = optval as *mut sctp_sndinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 1223176510024453262;
                } else if (*info).snd_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*info).snd_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 1223176510024453262;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 1223176510024453262;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut policy = 0;
                        if !stcb.is_null() {
                            if ((*info).snd_sid as libc::c_int)
                                < (*stcb).asoc.streamoutcnt as libc::c_int
                            {
                                (*stcb).asoc.def_send.sinfo_stream = (*info).snd_sid;
                                policy = ((*stcb).asoc.def_send.sinfo_flags as libc::c_int & 0xfi32)
                                    as uint16_t;
                                (*stcb).asoc.def_send.sinfo_flags = (*info).snd_flags;
                                (*stcb).asoc.def_send.sinfo_flags =
                                    ((*stcb).asoc.def_send.sinfo_flags as libc::c_int
                                        | policy as libc::c_int)
                                        as uint16_t;
                                (*stcb).asoc.def_send.sinfo_ppid = (*info).snd_ppid;
                                (*stcb).asoc.def_send.sinfo_context = (*info).snd_context
                            } else {
                                error = 22i32
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*info).snd_assoc_id == 0u32
                                        || (*info).snd_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                (*inp).def_send.sinfo_stream = (*info).snd_sid;
                                policy = ((*inp).def_send.sinfo_flags as libc::c_int & 0xfi32)
                                    as uint16_t;
                                (*inp).def_send.sinfo_flags = (*info).snd_flags;
                                (*inp).def_send.sinfo_flags = ((*inp).def_send.sinfo_flags
                                    as libc::c_int
                                    | policy as libc::c_int)
                                    as uint16_t;
                                (*inp).def_send.sinfo_ppid = (*info).snd_ppid;
                                (*inp).def_send.sinfo_context = (*info).snd_context;
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*info).snd_assoc_id == 1u32 || (*info).snd_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    if ((*info).snd_sid as libc::c_int)
                                        < (*stcb).asoc.streamoutcnt as libc::c_int
                                    {
                                        (*stcb).asoc.def_send.sinfo_stream = (*info).snd_sid;
                                        policy = ((*stcb).asoc.def_send.sinfo_flags as libc::c_int
                                            & 0xfi32)
                                            as uint16_t;
                                        (*stcb).asoc.def_send.sinfo_flags = (*info).snd_flags;
                                        (*stcb).asoc.def_send.sinfo_flags =
                                            ((*stcb).asoc.def_send.sinfo_flags as libc::c_int
                                                | policy as libc::c_int)
                                                as uint16_t;
                                        (*stcb).asoc.def_send.sinfo_ppid = (*info).snd_ppid;
                                        (*stcb).asoc.def_send.sinfo_context = (*info).snd_context
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        34 => {
            if optsize < ::std::mem::size_of::<sctp_default_prinfo>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut info_0 = 0 as *mut sctp_default_prinfo;
                info_0 = optval as *mut sctp_default_prinfo;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 8618027029035688756;
                } else if (*info_0).pr_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*info_0).pr_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 8618027029035688756;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 8618027029035688756;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if (*info_0).pr_policy as libc::c_int > 0x3i32 {
                            if !stcb.is_null() {
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                            }
                            error = 22i32
                        } else if !stcb.is_null() {
                            (*stcb).asoc.def_send.sinfo_flags =
                                ((*stcb).asoc.def_send.sinfo_flags as libc::c_int & 0xfff0i32)
                                    as uint16_t;
                            (*stcb).asoc.def_send.sinfo_flags = ((*stcb).asoc.def_send.sinfo_flags
                                as libc::c_int
                                | (*info_0).pr_policy as libc::c_int)
                                as uint16_t;
                            (*stcb).asoc.def_send.sinfo_timetolive = (*info_0).pr_value;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else {
                            if (*inp).sctp_flags & 0x2u32 != 0
                                || (*inp).sctp_flags & 0x400000u32 != 0
                                || (*inp).sctp_flags & 0x1u32 != 0
                                    && ((*info_0).pr_assoc_id == 0u32
                                        || (*info_0).pr_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                (*inp).def_send.sinfo_flags =
                                    ((*inp).def_send.sinfo_flags as libc::c_int & 0xfff0i32)
                                        as uint16_t;
                                (*inp).def_send.sinfo_flags = ((*inp).def_send.sinfo_flags
                                    as libc::c_int
                                    | (*info_0).pr_policy as libc::c_int)
                                    as uint16_t;
                                (*inp).def_send.sinfo_timetolive = (*info_0).pr_value;
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                            if (*inp).sctp_flags & 0x1u32 != 0
                                && ((*info_0).pr_assoc_id == 1u32 || (*info_0).pr_assoc_id == 2u32)
                            {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                stcb = (*inp).sctp_asoc_list.lh_first;
                                while !stcb.is_null() {
                                    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                                    (*stcb).asoc.def_send.sinfo_flags =
                                        ((*stcb).asoc.def_send.sinfo_flags as libc::c_int
                                            & 0xfff0i32)
                                            as uint16_t;
                                    (*stcb).asoc.def_send.sinfo_flags =
                                        ((*stcb).asoc.def_send.sinfo_flags as libc::c_int
                                            | (*info_0).pr_policy as libc::c_int)
                                            as uint16_t;
                                    (*stcb).asoc.def_send.sinfo_timetolive = (*info_0).pr_value;
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    stcb = (*stcb).sctp_tcblist.le_next
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        }
                    }
                }
            }
        }
        35 => {
            if optsize < ::std::mem::size_of::<sctp_paddrthlds>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut thlds = 0 as *mut sctp_paddrthlds;
                thlds = optval as *mut sctp_paddrthlds;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 2226390490110544944;
                } else if (*thlds).spt_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*thlds).spt_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 2226390490110544944;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 2226390490110544944;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut net_2 = 0 as *mut sctp_nets;
                        let mut addr_2 = 0 as *mut sockaddr;
                        if (*thlds).spt_address.ss_family as libc::c_int == 10i32 {
                            let mut sin6_3 = 0 as *mut sockaddr_in6;
                            sin6_3 = &mut (*thlds).spt_address as *mut sockaddr_storage
                                as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6_3).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store_2 = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store_2, sin6_3);
                                addr_2 = &mut sin_store_2 as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr_2 = &mut (*thlds).spt_address as *mut sockaddr_storage
                                    as *mut sockaddr
                            }
                        } else {
                            addr_2 =
                                &mut (*thlds).spt_address as *mut sockaddr_storage as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_2 = sctp_findnet(stcb, addr_2)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_2 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr_2,
                                &mut net_2,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && net_2.is_null() {
                            if (*addr_2).sa_family as libc::c_int == 2i32 {
                                let mut sin_0 = 0 as *mut sockaddr_in;
                                sin_0 = addr_2 as *mut sockaddr_in;
                                if (*sin_0).sin_addr.s_addr != 0u32 {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 13452221320129491419;
                                }
                            } else if (*addr_2).sa_family as libc::c_int == 10i32 {
                                let mut sin6_4 = 0 as *mut sockaddr_in6;
                                sin6_4 = addr_2 as *mut sockaddr_in6;
                                if ({
                                    let mut __a = &mut (*sin6_4).sin6_addr as *mut in6_addr
                                        as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                        as libc::c_int
                                }) == 0
                                {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 13452221320129491419;
                                }
                            } else if (*addr_2).sa_family as libc::c_int == 123i32 {
                                let mut sconn_0 = 0 as *mut sockaddr_conn;
                                sconn_0 = addr_2 as *mut sockaddr_conn;
                                if !(*sconn_0).sconn_addr.is_null() {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 13452221320129491419;
                                }
                            } else {
                                error = 97i32;
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                current_block = 13515130358667707052;
                            }
                        } else {
                            current_block = 13452221320129491419;
                        }
                        match current_block {
                            13515130358667707052 => {}
                            _ => {
                                if (*thlds).spt_pathcpthld as libc::c_int != 0xffffi32 {
                                    if !stcb.is_null() {
                                        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    }
                                    error = 22i32
                                } else if !stcb.is_null() {
                                    if !net_2.is_null() {
                                        (*net_2).failure_threshold = (*thlds).spt_pathmaxrxt;
                                        (*net_2).pf_threshold = (*thlds).spt_pathpfthld;
                                        if (*net_2).dest_state as libc::c_int & 0x800i32 != 0 {
                                            if (*net_2).error_count as libc::c_int
                                                > (*net_2).failure_threshold as libc::c_int
                                                || (*net_2).error_count as libc::c_int
                                                    <= (*net_2).pf_threshold as libc::c_int
                                            {
                                                (*net_2).dest_state = ((*net_2).dest_state
                                                    as libc::c_int
                                                    & !(0x800i32))
                                                    as uint16_t
                                            }
                                        } else if (*net_2).error_count as libc::c_int
                                            > (*net_2).pf_threshold as libc::c_int
                                            && (*net_2).error_count as libc::c_int
                                                <= (*net_2).failure_threshold as libc::c_int
                                        {
                                            (*net_2).dest_state =
                                                ((*net_2).dest_state as libc::c_int | 0x800i32)
                                                    as uint16_t;
                                            sctp_send_hb(stcb, net_2, 1i32);
                                            sctp_timer_stop(
                                                5i32,
                                                (*stcb).sctp_ep,
                                                stcb,
                                                net_2,
                                                (0x50000000i32 + 0x11i32) as uint32_t,
                                            );
                                            sctp_timer_start(5i32, (*stcb).sctp_ep, stcb, net_2);
                                        }
                                        if (*net_2).dest_state as libc::c_int & 0x1i32 != 0 {
                                            if (*net_2).error_count as libc::c_int
                                                > (*net_2).failure_threshold as libc::c_int
                                            {
                                                (*net_2).dest_state = ((*net_2).dest_state
                                                    as libc::c_int
                                                    & !(0x1i32))
                                                    as uint16_t;
                                                sctp_ulp_notify(
                                                    3u32,
                                                    stcb,
                                                    0u32,
                                                    net_2 as *mut libc::c_void,
                                                    1i32,
                                                );
                                            }
                                        } else if (*net_2).error_count as libc::c_int
                                            <= (*net_2).failure_threshold as libc::c_int
                                        {
                                            (*net_2).dest_state =
                                                ((*net_2).dest_state as libc::c_int | 0x1i32)
                                                    as uint16_t;
                                            sctp_ulp_notify(
                                                4u32,
                                                stcb,
                                                0u32,
                                                net_2 as *mut libc::c_void,
                                                1i32,
                                            );
                                        }
                                    } else {
                                        net_2 = (*stcb).asoc.nets.tqh_first;
                                        while !net_2.is_null() {
                                            (*net_2).failure_threshold = (*thlds).spt_pathmaxrxt;
                                            (*net_2).pf_threshold = (*thlds).spt_pathpfthld;
                                            if (*net_2).dest_state as libc::c_int & 0x800i32 != 0 {
                                                if (*net_2).error_count as libc::c_int
                                                    > (*net_2).failure_threshold as libc::c_int
                                                    || (*net_2).error_count as libc::c_int
                                                        <= (*net_2).pf_threshold as libc::c_int
                                                {
                                                    (*net_2).dest_state = ((*net_2).dest_state
                                                        as libc::c_int
                                                        & !(0x800i32))
                                                        as uint16_t
                                                }
                                            } else if (*net_2).error_count as libc::c_int
                                                > (*net_2).pf_threshold as libc::c_int
                                                && (*net_2).error_count as libc::c_int
                                                    <= (*net_2).failure_threshold as libc::c_int
                                            {
                                                (*net_2).dest_state =
                                                    ((*net_2).dest_state as libc::c_int | 0x800i32)
                                                        as uint16_t;
                                                sctp_send_hb(stcb, net_2, 1i32);
                                                sctp_timer_stop(
                                                    5i32,
                                                    (*stcb).sctp_ep,
                                                    stcb,
                                                    net_2,
                                                    (0x50000000i32 + 0x12i32) as uint32_t,
                                                );
                                                sctp_timer_start(
                                                    5i32,
                                                    (*stcb).sctp_ep,
                                                    stcb,
                                                    net_2,
                                                );
                                            }
                                            if (*net_2).dest_state as libc::c_int & 0x1i32 != 0 {
                                                if (*net_2).error_count as libc::c_int
                                                    > (*net_2).failure_threshold as libc::c_int
                                                {
                                                    (*net_2).dest_state = ((*net_2).dest_state
                                                        as libc::c_int
                                                        & !(0x1i32))
                                                        as uint16_t;
                                                    sctp_ulp_notify(
                                                        3u32,
                                                        stcb,
                                                        0u32,
                                                        net_2 as *mut libc::c_void,
                                                        1i32,
                                                    );
                                                }
                                            } else if (*net_2).error_count as libc::c_int
                                                <= (*net_2).failure_threshold as libc::c_int
                                            {
                                                (*net_2).dest_state =
                                                    ((*net_2).dest_state as libc::c_int | 0x1i32)
                                                        as uint16_t;
                                                sctp_ulp_notify(
                                                    4u32,
                                                    stcb,
                                                    0u32,
                                                    net_2 as *mut libc::c_void,
                                                    1i32,
                                                );
                                            }
                                            net_2 = (*net_2).sctp_next.tqe_next
                                        }
                                        (*stcb).asoc.def_net_failure = (*thlds).spt_pathmaxrxt;
                                        (*stcb).asoc.def_net_pf_threshold = (*thlds).spt_pathpfthld
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                } else if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && (*thlds).spt_assoc_id == 0u32
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*inp).sctp_ep.def_net_failure = (*thlds).spt_pathmaxrxt;
                                    (*inp).sctp_ep.def_net_pf_threshold = (*thlds).spt_pathpfthld;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                } else {
                                    error = 22i32
                                }
                            }
                        }
                    }
                }
            }
        }
        36 => {
            if optsize < ::std::mem::size_of::<sctp_udpencaps>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut encaps = 0 as *mut sctp_udpencaps;
                encaps = optval as *mut sctp_udpencaps;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 16501492364408416809;
                } else if (*encaps).sue_assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*encaps).sue_assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 16501492364408416809;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 16501492364408416809;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        let mut net_3 = 0 as *mut sctp_nets;
                        let mut addr_3 = 0 as *mut sockaddr;
                        if (*encaps).sue_address.ss_family as libc::c_int == 10i32 {
                            let mut sin6_5 = 0 as *mut sockaddr_in6;
                            sin6_5 = &mut (*encaps).sue_address as *mut sockaddr_storage
                                as *mut sockaddr_in6;
                            if ({
                                let mut __a =
                                    &mut (*sin6_5).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                                    as libc::c_int
                            }) != 0
                            {
                                let mut sin_store_3 = sockaddr_in {
                                    sin_family: 0,
                                    sin_port: 0,
                                    sin_addr: in_addr { s_addr: 0 },
                                    sin_zero: [0; 8],
                                };
                                in6_sin6_2_sin(&mut sin_store_3, sin6_5);
                                addr_3 = &mut sin_store_3 as *mut sockaddr_in as *mut sockaddr
                            } else {
                                addr_3 = &mut (*encaps).sue_address as *mut sockaddr_storage
                                    as *mut sockaddr
                            }
                        } else {
                            addr_3 =
                                &mut (*encaps).sue_address as *mut sockaddr_storage as *mut sockaddr
                        }
                        if !stcb.is_null() {
                            net_3 = sctp_findnet(stcb, addr_3)
                        } else {
                            /* We increment here since sctp_findassociation_ep_addr() wil
                             * do a decrement if it finds the stcb as long as the locked
                             * tcb (last argument) is NOT a TCB.. aka NULL.
                             */
                            net_3 = 0 as *mut sctp_nets;
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                            stcb = sctp_findassociation_ep_addr(
                                &mut inp,
                                addr_3,
                                &mut net_3,
                                0 as *mut sockaddr,
                                0 as *mut sctp_tcb,
                            );
                            if stcb.is_null() {
                                ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                            }
                        }
                        if !stcb.is_null() && net_3.is_null() {
                            if (*addr_3).sa_family as libc::c_int == 2i32 {
                                let mut sin_1 = 0 as *mut sockaddr_in;
                                sin_1 = addr_3 as *mut sockaddr_in;
                                if (*sin_1).sin_addr.s_addr != 0u32 {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 17780002210375695354;
                                }
                            } else if (*addr_3).sa_family as libc::c_int == 10i32 {
                                let mut sin6_6 = 0 as *mut sockaddr_in6;
                                sin6_6 = addr_3 as *mut sockaddr_in6;
                                if ({
                                    let mut __a = &mut (*sin6_6).sin6_addr as *mut in6_addr
                                        as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                        as libc::c_int
                                }) == 0
                                {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 17780002210375695354;
                                }
                            } else if (*addr_3).sa_family as libc::c_int == 123i32 {
                                let mut sconn_1 = 0 as *mut sockaddr_conn;
                                sconn_1 = addr_3 as *mut sockaddr_conn;
                                if !(*sconn_1).sconn_addr.is_null() {
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                    error = 22i32;
                                    current_block = 13515130358667707052;
                                } else {
                                    current_block = 17780002210375695354;
                                }
                            } else {
                                error = 97i32;
                                pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                current_block = 13515130358667707052;
                            }
                        } else {
                            current_block = 17780002210375695354;
                        }
                        match current_block {
                            13515130358667707052 => {}
                            _ => {
                                if !stcb.is_null() {
                                    if !net_3.is_null() {
                                        (*net_3).port = (*encaps).sue_port
                                    } else {
                                        (*stcb).asoc.port = (*encaps).sue_port
                                    }
                                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                                } else if (*inp).sctp_flags & 0x2u32 != 0
                                    || (*inp).sctp_flags & 0x400000u32 != 0
                                    || (*inp).sctp_flags & 0x1u32 != 0
                                        && (*encaps).sue_assoc_id == 0u32
                                {
                                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                                    (*inp).sctp_ep.port = (*encaps).sue_port;
                                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                                } else {
                                    error = 22i32
                                }
                            }
                        }
                    }
                }
            }
        }
        37 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_8 = 0 as *mut sctp_assoc_value;
                av_8 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 4571827802364727487;
                } else if (*av_8).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_8).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 4571827802364727487;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 4571827802364727487;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_8).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*av_8).assoc_value == 0u32 {
                                (*inp).ecn_supported = 0u8
                            } else {
                                (*inp).ecn_supported = 1u8
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        38 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_9 = 0 as *mut sctp_assoc_value;
                av_9 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 3112552795622546566;
                } else if (*av_9).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_9).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 3112552795622546566;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 3112552795622546566;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_9).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*av_9).assoc_value == 0u32 {
                                (*inp).prsctp_supported = 0u8
                            } else {
                                (*inp).prsctp_supported = 1u8
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        39 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_10 = 0 as *mut sctp_assoc_value;
                av_10 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 8378483116964698641;
                } else if (*av_10).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_10).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 8378483116964698641;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 8378483116964698641;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_10).assoc_id == 0u32
                        {
                            if (*av_10).assoc_value == 0u32
                                && (*inp).asconf_supported as libc::c_int == 1i32
                            {
                                /* AUTH is required for ASCONF */
                                error = 22i32
                            } else {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                if (*av_10).assoc_value == 0u32 {
                                    (*inp).auth_supported = 0u8
                                } else {
                                    (*inp).auth_supported = 1u8
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        40 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_11 = 0 as *mut sctp_assoc_value;
                av_11 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 14942586808607309138;
                } else if (*av_11).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_11).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 14942586808607309138;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 14942586808607309138;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_11).assoc_id == 0u32
                        {
                            if (*av_11).assoc_value != 0u32
                                && (*inp).auth_supported as libc::c_int == 0i32
                            {
                                /* AUTH is required for ASCONF */
                                error = 22i32
                            } else {
                                pthread_mutex_lock(&mut (*inp).inp_mtx);
                                if (*av_11).assoc_value == 0u32 {
                                    (*inp).asconf_supported = 0u8;
                                    sctp_auth_delete_chunk(
                                        0xc1u8,
                                        (*inp).sctp_ep.local_auth_chunks,
                                    );
                                    sctp_auth_delete_chunk(
                                        0x80u8,
                                        (*inp).sctp_ep.local_auth_chunks,
                                    );
                                } else {
                                    (*inp).asconf_supported = 1u8;
                                    sctp_auth_add_chunk(0xc1u8, (*inp).sctp_ep.local_auth_chunks);
                                    sctp_auth_add_chunk(0x80u8, (*inp).sctp_ep.local_auth_chunks);
                                }
                                pthread_mutex_unlock(&mut (*inp).inp_mtx);
                            }
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        41 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_12 = 0 as *mut sctp_assoc_value;
                av_12 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 5643088064438158648;
                } else if (*av_12).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_12).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 5643088064438158648;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 5643088064438158648;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_12).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*av_12).assoc_value == 0u32 {
                                (*inp).reconfig_supported = 0u8
                            } else {
                                (*inp).reconfig_supported = 1u8
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        48 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_13 = 0 as *mut sctp_assoc_value;
                av_13 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 11391902387524471726;
                } else if (*av_13).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_13).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 11391902387524471726;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 11391902387524471726;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_13).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*av_13).assoc_value == 0u32 {
                                (*inp).nrsack_supported = 0u8
                            } else {
                                (*inp).nrsack_supported = 1u8
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        49 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_14 = 0 as *mut sctp_assoc_value;
                av_14 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 3784252282131597499;
                } else if (*av_14).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_14).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 3784252282131597499;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 3784252282131597499;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            error = 22i32;
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_14).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            if (*av_14).assoc_value == 0u32 {
                                (*inp).pktdrop_supported = 0u8
                            } else {
                                (*inp).pktdrop_supported = 1u8
                            }
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        50 => {
            if optsize < ::std::mem::size_of::<sctp_assoc_value>() as libc::c_ulong {
                error = 22i32
            } else {
                let mut av_15 = 0 as *mut sctp_assoc_value;
                av_15 = optval as *mut sctp_assoc_value;
                if (*inp).sctp_flags & 0x2u32 != 0 || (*inp).sctp_flags & 0x400000u32 != 0 {
                    pthread_mutex_lock(&mut (*inp).inp_mtx);
                    stcb = (*inp).sctp_asoc_list.lh_first;
                    if !stcb.is_null() {
                        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                    }
                    pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    current_block = 15972725674387295449;
                } else if (*av_15).assoc_id > 2u32 {
                    stcb = sctp_findassociation_ep_asocid(inp, (*av_15).assoc_id, 1i32);
                    if stcb.is_null() {
                        error = 2i32;
                        current_block = 13515130358667707052;
                    } else {
                        current_block = 15972725674387295449;
                    }
                } else {
                    stcb = 0 as *mut sctp_tcb;
                    current_block = 15972725674387295449;
                }
                match current_block {
                    13515130358667707052 => {}
                    _ => {
                        if !stcb.is_null() {
                            (*stcb).asoc.max_cwnd = (*av_15).assoc_value;
                            if (*stcb).asoc.max_cwnd > 0u32 {
                                let mut net_4 = 0 as *mut sctp_nets;
                                net_4 = (*stcb).asoc.nets.tqh_first;
                                while !net_4.is_null() {
                                    if (*net_4).cwnd > (*stcb).asoc.max_cwnd
                                        && (*net_4).cwnd as libc::c_ulong
                                            > ((*net_4).mtu as libc::c_ulong)
                                                .wrapping_sub(::std::mem::size_of::<sctphdr>()
                                                    as libc::c_ulong)
                                    {
                                        (*net_4).cwnd = (*stcb).asoc.max_cwnd;
                                        if ((*net_4).cwnd as libc::c_ulong)
                                            < ((*net_4).mtu as libc::c_ulong)
                                                .wrapping_sub(::std::mem::size_of::<sctphdr>()
                                                    as libc::c_ulong)
                                        {
                                            (*net_4).cwnd = ((*net_4).mtu as libc::c_ulong)
                                                .wrapping_sub(::std::mem::size_of::<sctphdr>()
                                                    as libc::c_ulong)
                                                as uint32_t
                                        }
                                    }
                                    net_4 = (*net_4).sctp_next.tqe_next
                                }
                            }
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        } else if (*inp).sctp_flags & 0x2u32 != 0
                            || (*inp).sctp_flags & 0x400000u32 != 0
                            || (*inp).sctp_flags & 0x1u32 != 0 && (*av_15).assoc_id == 0u32
                        {
                            pthread_mutex_lock(&mut (*inp).inp_mtx);
                            (*inp).max_cwnd = (*av_15).assoc_value;
                            pthread_mutex_unlock(&mut (*inp).inp_mtx);
                        } else {
                            error = 22i32
                        }
                    }
                }
            }
        }
        _ => error = 92i32,
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_connect(mut so: *mut socket, mut addr: *mut sockaddr) -> libc::c_int {
    let mut error = 0i32;
    let mut create_lock_on = 0i32;
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        /* I made the same as TCP since we are not setup? */
        return 104i32;
    }
    if addr.is_null() {
        return 22i32;
    }
    /* TODO __Userspace__ falls into this code for IPv6 stuff at the moment... */
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
    pthread_mutex_lock(&mut (*inp).inp_create_mtx);
    create_lock_on = 1i32;
    if (*inp).sctp_flags & 0x20000000u32 != 0 || (*inp).sctp_flags & 0x10000000u32 != 0 {
        /* Should I really unlock ? */
        error = 14i32
    } else if (*inp).sctp_flags & 0x4000000u32 == 0u32 && (*addr).sa_family as libc::c_int == 10i32
    {
        error = 22i32
    } else if (*inp).sctp_flags & 0x80000000u32 != 0 && (*addr).sa_family as libc::c_int != 123i32 {
        error = 22i32
    } else {
        let mut current_block: u64;
        let mut p = 0 as *mut libc::c_void;
        if (*inp).sctp_flags & 0x10u32 == 0x10u32 {
            /* Bind a ephemeral port */
            error = sctp_inpcb_bind(so, 0 as *mut sockaddr, 0 as *mut sctp_ifa, p as *mut proc_0);
            if error != 0 {
                current_block = 14749961112982339958;
            } else {
                current_block = 14763689060501151050;
            }
        } else {
            current_block = 14763689060501151050;
        }
        match current_block {
            14749961112982339958 => {}
            _ =>
            /* Now do we connect? */
            {
                if (*inp).sctp_flags & 0x400000u32 != 0
                    && (*inp).sctp_features & 0x2000000u64 == 0u64
                {
                    error = 22i32
                } else if (*inp).sctp_flags & 0x2u32 != 0 && (*inp).sctp_flags & 0x200000u32 != 0 {
                    /* We are already connected AND the TCP model */
                    error = 98i32
                } else {
                    let mut stcb = 0 as *mut sctp_tcb;
                    if (*inp).sctp_flags & 0x200000u32 != 0 {
                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                        stcb = (*inp).sctp_asoc_list.lh_first;
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    } else {
                        /* We increment here since sctp_findassociation_ep_addr() will
                         * do a decrement if it finds the stcb as long as the locked
                         * tcb (last argument) is NOT a TCB.. aka NULL.
                         */
                        ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                        stcb = sctp_findassociation_ep_addr(
                            &mut inp,
                            addr,
                            0 as *mut *mut sctp_nets,
                            0 as *mut sockaddr,
                            0 as *mut sctp_tcb,
                        );
                        if stcb.is_null() {
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                        } else {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                    if !stcb.is_null() {
                        /* Already have or am bring up an association */
                        error = 114i32
                    } else {
                        let mut vrf_id = 0;
                        vrf_id = (*inp).def_vrf_id;
                        /* We are GOOD to go */
                        stcb = sctp_aloc_assoc(
                            inp,
                            addr,
                            &mut error,
                            0u32,
                            vrf_id,
                            (*inp).sctp_ep.pre_open_stream_count,
                            (*inp).sctp_ep.port,
                            p as *mut proc_0,
                            1i32,
                        );
                        if !stcb.is_null() {
                            if (*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0 {
                                (*(*stcb).sctp_ep).sctp_flags |= 0x200000u32;
                                /* Set the connected flag so we can queue data */
                                soisconnecting(so);
                            }
                            sctp_set_state(stcb, 0x2i32);
                            gettimeofday(&mut (*stcb).asoc.time_entered, 0 as *mut timezone);
                            sctp_send_initiate(inp, stcb, 1i32);
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
            }
        }
    }
    /* Gak! no memory */
    if create_lock_on != 0 {
        pthread_mutex_unlock(&mut (*inp).inp_create_mtx);
    }
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn sctpconn_connect(
    mut so: *mut socket,
    mut addr: *mut sockaddr,
) -> libc::c_int {
    let mut error = 0i32;
    let mut create_lock_on = 0i32;
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        /* I made the same as TCP since we are not setup? */
        return 104i32;
    }
    if addr.is_null() {
        return 22i32;
    }
    match (*addr).sa_family as libc::c_int {
        2 | 10 | 123 => {}
        _ => return 97i32,
    }
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
    pthread_mutex_lock(&mut (*inp).inp_create_mtx);
    create_lock_on = 1i32;
    if (*inp).sctp_flags & 0x20000000u32 != 0 || (*inp).sctp_flags & 0x10000000u32 != 0 {
        /* Should I really unlock ? */
        error = 14i32
    } else if (*inp).sctp_flags & 0x4000000u32 == 0u32 && (*addr).sa_family as libc::c_int == 10i32
    {
        error = 22i32
    } else {
        let mut current_block: u64;
        let mut p = 0 as *mut libc::c_void;
        if (*inp).sctp_flags & 0x10u32 == 0x10u32 {
            /* Bind a ephemeral port */
            error = sctp_inpcb_bind(so, 0 as *mut sockaddr, 0 as *mut sctp_ifa, p as *mut proc_0);
            if error != 0 {
                current_block = 3563299137679231916;
            } else {
                current_block = 4775909272756257391;
            }
        } else {
            current_block = 4775909272756257391;
        }
        match current_block {
            3563299137679231916 => {}
            _ =>
            /* Now do we connect? */
            {
                if (*inp).sctp_flags & 0x400000u32 != 0
                    && (*inp).sctp_features & 0x2000000u64 == 0u64
                {
                    error = 22i32
                } else if (*inp).sctp_flags & 0x2u32 != 0 && (*inp).sctp_flags & 0x200000u32 != 0 {
                    /* We are already connected AND the TCP model */
                    error = 98i32
                } else {
                    let mut stcb = 0 as *mut sctp_tcb;
                    if (*inp).sctp_flags & 0x200000u32 != 0 {
                        pthread_mutex_lock(&mut (*inp).inp_mtx);
                        stcb = (*inp).sctp_asoc_list.lh_first;
                        pthread_mutex_unlock(&mut (*inp).inp_mtx);
                    } else {
                        /* We increment here since sctp_findassociation_ep_addr() will
                         * do a decrement if it finds the stcb as long as the locked
                         * tcb (last argument) is NOT a TCB.. aka NULL.
                         */
                        ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, 1i32);
                        stcb = sctp_findassociation_ep_addr(
                            &mut inp,
                            addr,
                            0 as *mut *mut sctp_nets,
                            0 as *mut sockaddr,
                            0 as *mut sctp_tcb,
                        );
                        if stcb.is_null() {
                            ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
                        } else {
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                    if !stcb.is_null() {
                        /* Already have or am bring up an association */
                        error = 114i32
                    } else {
                        let mut vrf_id = 0;
                        vrf_id = (*inp).def_vrf_id;
                        /* We are GOOD to go */
                        stcb = sctp_aloc_assoc(
                            inp,
                            addr,
                            &mut error,
                            0u32,
                            vrf_id,
                            (*inp).sctp_ep.pre_open_stream_count,
                            (*inp).sctp_ep.port,
                            p as *mut proc_0,
                            1i32,
                        );
                        if !stcb.is_null() {
                            if (*(*stcb).sctp_ep).sctp_flags & 0x2u32 != 0 {
                                (*(*stcb).sctp_ep).sctp_flags |= 0x200000u32;
                                /* Set the connected flag so we can queue data */
                                soisconnecting(so);
                            }
                            sctp_set_state(stcb, 0x2i32);
                            gettimeofday(&mut (*stcb).asoc.time_entered, 0 as *mut timezone);
                            sctp_send_initiate(inp, stcb, 1i32);
                            pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                        }
                    }
                }
            }
        }
    }
    /* Gak! no memory */
    if create_lock_on != 0 {
        pthread_mutex_unlock(&mut (*inp).inp_create_mtx);
    }
    ::std::intrinsics::atomic_xadd(&mut (*inp).refcount, -(1i32));
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_listen(
    mut so: *mut socket,
    mut backlog: libc::c_int,
    mut p: *mut proc_0,
) -> libc::c_int {
    let mut error = 0i32;
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        /* I made the same as TCP since we are not setup? */
        return 104i32;
    }
    if (*inp).sctp_features & 0x2000000u64 == 0x2000000u64 {
        let mut tinp = 0 as *mut sctp_inpcb;
        let mut store = sctp_sockstore {
            sin: sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            },
        };
        if (*inp).sctp_flags & 0x4u32 == 0u32 {
            let mut laddr = 0 as *mut sctp_laddr;
            laddr = (*inp).sctp_addr_list.lh_first;
            while !laddr.is_null() {
                memcpy(
                    &mut store as *mut sctp_sockstore as *mut libc::c_void,
                    &mut (*(*laddr).ifa).address as *mut sctp_sockstore as *const libc::c_void,
                    ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
                );
                match store.sa.sa_family as libc::c_int {
                    2 => store.sin.sin_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport,
                    10 => store.sin6.sin6_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport,
                    123 => store.sconn.sconn_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport,
                    _ => {}
                }
                tinp = sctp_pcb_findep(&mut store.sa, 0i32, 0i32, (*inp).def_vrf_id);
                if !tinp.is_null()
                    && tinp != inp
                    && (*tinp).sctp_flags & 0x20000000u32 == 0u32
                    && (*tinp).sctp_flags & 0x10000000u32 == 0u32
                    && (*tinp).sctp_flags & 0x8u32 != 0u32
                {
                    /* we have a listener already and its not this inp. */
                    ::std::intrinsics::atomic_xadd(&mut (*tinp).refcount, -(1i32));
                    return 98i32;
                } else {
                    if !tinp.is_null() {
                        ::std::intrinsics::atomic_xadd(&mut (*tinp).refcount, -(1i32));
                    }
                }
                laddr = (*laddr).sctp_nxt_addr.le_next
            }
        } else {
            /* Setup a local addr bound all */
            memset(
                &mut store as *mut sctp_sockstore as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
            );
            if (*inp).sctp_flags & 0x4000000u32 != 0 {
                store.sa.sa_family = 10u16
            }
            if (*inp).sctp_flags & 0x80000000u32 != 0 {
                store.sa.sa_family = 123u16
            }
            if (*inp).sctp_flags & 0x4000000u32 == 0u32 && (*inp).sctp_flags & 0x80000000u32 == 0u32
            {
                store.sa.sa_family = 2u16
            }
            match store.sa.sa_family as libc::c_int {
                2 => store.sin.sin_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport,
                10 => store.sin6.sin6_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport,
                123 => store.sconn.sconn_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport,
                _ => {}
            }
            tinp = sctp_pcb_findep(&mut store.sa, 0i32, 0i32, (*inp).def_vrf_id);
            if !tinp.is_null()
                && tinp != inp
                && (*tinp).sctp_flags & 0x20000000u32 == 0u32
                && (*tinp).sctp_flags & 0x10000000u32 == 0u32
                && (*tinp).sctp_flags & 0x8u32 != 0u32
            {
                /* we have a listener already and its not this inp. */
                ::std::intrinsics::atomic_xadd(&mut (*tinp).refcount, -(1i32));
                return 98i32;
            } else {
                if !tinp.is_null() {
                    ::std::intrinsics::atomic_xadd(&mut (*tinp).refcount, -(1i32));
                }
            }
        }
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    error = solisten_proto_check(so);
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    if error != 0 {
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return error;
    }
    if (*inp).sctp_features & 0x2000000u64 == 0x2000000u64 && (*inp).sctp_flags & 0x400000u32 != 0 {
        /* The unlucky case
         * - We are in the tcp pool with this guy.
         * - Someone else is in the main inp slot.
         * - We must move this guy (the listener) to the main slot
         * - We must then move the guy that was listener to the TCP Pool.
         */
        if sctp_swap_inpcb_for_listen(inp) != 0 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 98i32;
        }
    }
    if (*inp).sctp_flags & 0x2u32 != 0 && (*inp).sctp_flags & 0x200000u32 != 0 {
        /* We are already connected AND the TCP model */
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 98i32;
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    if (*inp).sctp_flags & 0x10u32 != 0 {
        /* We must do a bind. */
        error = sctp_inpcb_bind(so, 0 as *mut sockaddr, 0 as *mut sctp_ifa, p);
        if error != 0 {
            /* bind error, probably perm */
            return error;
        }
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    /* It appears for 7.0 and on, we must always call this. */
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    solisten_proto(so, backlog);
    if (*inp).sctp_flags & 0x1u32 != 0 {
        /* remove the ACCEPTCONN flag for one-to-many sockets */
        (*so).so_options = ((*so).so_options as libc::c_int & !(0x2i32)) as libc::c_short
    }
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    if backlog > 0i32 {
        (*inp).sctp_flags |= 0x8u32
    } else {
        (*inp).sctp_flags &= !(0x8i32) as libc::c_uint
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return error;
}
static mut sctp_defered_wakeup_cnt: libc::c_int = 0i32;
#[no_mangle]
pub unsafe extern "C" fn sctp_accept(
    mut so: *mut socket,
    mut addr: *mut *mut sockaddr,
) -> libc::c_int {
    let mut stcb = 0 as *mut sctp_tcb;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut store = sctp_sockstore {
        sin: sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        },
    };
    /* SCTP_KAME */
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 104i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    if (*inp).sctp_flags & 0x1u32 != 0 {
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 95i32;
    }
    if (*so).so_state as libc::c_int & 0x2000i32 != 0 {
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 103i32;
    }
    stcb = (*inp).sctp_asoc_list.lh_first;
    if stcb.is_null() {
        pthread_mutex_unlock(&mut (*inp).inp_mtx);
        return 104i32;
    }
    pthread_mutex_lock(&mut (*stcb).tcb_mtx);
    store = (*(*stcb).asoc.primary_destination).ro._l_addr;
    (*stcb).asoc.state &= !(0x1000i32);
    /* Wake any delayed sleep action */
    if (*inp).sctp_flags & 0x800000u32 != 0 {
        (*inp).sctp_flags &= !(0x800000i32) as libc::c_uint;
        if (*inp).sctp_flags & 0x1000000u32 != 0 {
            (*inp).sctp_flags &= !(0x1000000i32) as libc::c_uint;
            pthread_mutex_lock(&mut (*(*inp).sctp_socket).so_snd.sb_mtx);
            if (if (*(*inp).sctp_socket)
                .so_snd
                .sb_hiwat
                .wrapping_sub((*(*inp).sctp_socket).so_snd.sb_cc) as libc::c_int
                > (*(*inp).sctp_socket)
                    .so_snd
                    .sb_mbmax
                    .wrapping_sub((*(*inp).sctp_socket).so_snd.sb_mbcnt)
                    as libc::c_int
            {
                (*(*inp).sctp_socket)
                    .so_snd
                    .sb_mbmax
                    .wrapping_sub((*(*inp).sctp_socket).so_snd.sb_mbcnt)
                    as libc::c_int
            } else {
                (*(*inp).sctp_socket)
                    .so_snd
                    .sb_hiwat
                    .wrapping_sub((*(*inp).sctp_socket).so_snd.sb_cc) as libc::c_int
            }) as libc::c_long
                >= (*(*inp).sctp_socket).so_snd.sb_lowat as libc::c_long
                && (*(*inp).sctp_socket).so_state as libc::c_int & 0x2i32 != 0
                || (*(*inp).sctp_socket).so_snd.sb_state as libc::c_int & 0x10i32 != 0
                || (*(*inp).sctp_socket).so_error as libc::c_int != 0
            {
                /*__Userspace__ calling sowwakup_locked because of SOCKBUF_LOCK above. */
                if (*(*inp).sctp_socket).so_snd.sb_flags as libc::c_int
                    & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                    != 0i32
                {
                    sowakeup((*inp).sctp_socket, &mut (*(*inp).sctp_socket).so_snd);
                } else {
                    pthread_mutex_unlock(&mut (*(*inp).sctp_socket).so_snd.sb_mtx);
                }
            } else {
                pthread_mutex_unlock(&mut (*(*inp).sctp_socket).so_snd.sb_mtx);
            }
        }
        if (*inp).sctp_flags & 0x2000000u32 != 0 {
            (*inp).sctp_flags &= !(0x2000000i32) as libc::c_uint;
            pthread_mutex_lock(&mut (*(*inp).sctp_socket).so_rcv.sb_mtx);
            if (*(*inp).sctp_socket).so_rcv.sb_cc as libc::c_int
                >= (*(*inp).sctp_socket).so_rcv.sb_lowat
                || (*(*inp).sctp_socket).so_rcv.sb_state as libc::c_int & 0x20i32 != 0
                || !(*(*inp).sctp_socket).so_comp.tqh_first.is_null()
                || (*(*inp).sctp_socket).so_error as libc::c_int != 0
            {
                sctp_defered_wakeup_cnt += 1;
                /*__Userspace__ calling sorwakup_locked because of SOCKBUF_LOCK above */
                if (*(*inp).sctp_socket).so_rcv.sb_flags as libc::c_int
                    & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
                    != 0i32
                {
                    sowakeup((*inp).sctp_socket, &mut (*(*inp).sctp_socket).so_rcv);
                } else {
                    pthread_mutex_unlock(&mut (*(*inp).sctp_socket).so_rcv.sb_mtx);
                }
            } else {
                pthread_mutex_unlock(&mut (*(*inp).sctp_socket).so_rcv.sb_mtx);
            }
        }
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    if (*stcb).asoc.state & 0x200i32 != 0 {
        sctp_free_assoc(inp, stcb, 0i32, 0x50000000i32 + 0x13i32);
    } else {
        pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
    }
    match store.sa.sa_family as libc::c_int {
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            sin = malloc(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong) as *mut sockaddr_in;
            if (0x2i32 | 0x100i32) & 0x100i32 != 0 {
                memset(
                    sin as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                );
            }
            if sin.is_null() {
                return 12i32;
            }
            (*sin).sin_family = 2u16;
            (*sin).sin_port = store.sin.sin_port;
            (*sin).sin_addr = store.sin.sin_addr;
            *addr = sin as *mut sockaddr
        }
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 =
                malloc(::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong) as *mut sockaddr_in6;
            if (0x2i32 | 0x100i32) & 0x100i32 != 0 {
                memset(
                    sin6 as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                );
            }
            if sin6.is_null() {
                return 12i32;
            }
            (*sin6).sin6_family = 10u16;
            (*sin6).sin6_port = store.sin6.sin6_port;
            (*sin6).sin6_addr = store.sin6.sin6_addr;
            /* SCTP_EMBEDDED_V6_SCOPE */
            *addr = sin6 as *mut sockaddr
        }
        123 => {
            let mut sconn = 0 as *mut sockaddr_conn;
            sconn = malloc(::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong)
                as *mut sockaddr_conn;
            if (0x2i32 | 0x100i32) & 0x100i32 != 0 {
                memset(
                    sconn as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
                );
            }
            if sconn.is_null() {
                return 12i32;
            }
            (*sconn).sconn_family = 123u16;
            (*sconn).sconn_port = store.sconn.sconn_port;
            (*sconn).sconn_addr = store.sconn.sconn_addr;
            *addr = sconn as *mut sockaddr
        }
        _ => {}
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_ingetaddr(mut so: *mut socket, mut nam: *mut mbuf) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    let mut sin = (*nam).m_hdr.mh_data as *mut sockaddr_in;

    /*
     * Do the malloc first in case it blocks.
     */
    (*nam).m_hdr.mh_len = ::std::mem::size_of::<sockaddr_in>() as libc::c_int;
    memset(
        sin as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
    );
    (*sin).sin_family = 2u16;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 104i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    (*sin).sin_port = (*inp).ip_inp.inp.inp_inc.inc_ie.ie_lport;
    if (*inp).sctp_flags & 0x4u32 != 0 {
        let mut current_block: u64;
        if (*inp).sctp_flags & 0x200000u32 != 0 {
            let mut stcb = 0 as *mut sctp_tcb;
            stcb = (*inp).sctp_asoc_list.lh_first;
            if stcb.is_null() {
                current_block = 9902795564051184236;
            } else {
                let mut sin_a = 0 as *mut sockaddr_in;
                let mut net = 0 as *mut sctp_nets;
                let mut fnd = 0;
                fnd = 0i32;
                sin_a = 0 as *mut sockaddr_in;
                pthread_mutex_lock(&mut (*stcb).tcb_mtx);
                net = (*stcb).asoc.nets.tqh_first;
                while !net.is_null() {
                    sin_a = &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr_in;
                    if !sin_a.is_null() {
                        if (*sin_a).sin_family as libc::c_int == 2i32 {
                            fnd = 1i32;
                            break;
                        }
                    }
                    /* this will make coverity happy */
                    net = (*net).sctp_next.tqe_next
                }
                if fnd == 0 || sin_a.is_null() {
                    /* punt */
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    current_block = 9902795564051184236;
                } else {
                    let mut vrf_id = 0;
                    let mut sctp_ifa = 0 as *mut sctp_ifa;
                    vrf_id = (*inp).def_vrf_id;
                    sctp_ifa = sctp_source_address_selection(
                        inp,
                        stcb,
                        &mut (*net).ro as *mut sctp_net_route as *mut sctp_route_t,
                        net,
                        0i32,
                        vrf_id,
                    );
                    if !sctp_ifa.is_null() {
                        (*sin).sin_addr = (*sctp_ifa).address.sin.sin_addr;
                        sctp_free_ifa(sctp_ifa);
                    }
                    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
                    current_block = 13826291924415791078;
                }
            }
        } else {
            current_block = 9902795564051184236;
        }
        match current_block {
            13826291924415791078 => {}
            _ =>
            /* For the bound all case you get back 0 */
            {
                (*sin).sin_addr.s_addr = 0u32
            }
        }
    } else {
        let mut laddr = 0 as *mut sctp_laddr;
        let mut fnd_0 = 0i32;
        laddr = (*inp).sctp_addr_list.lh_first;
        while !laddr.is_null() {
            if (*(*laddr).ifa).address.sa.sa_family as libc::c_int == 2i32 {
                let mut sin_a_0 = 0 as *mut sockaddr_in;
                sin_a_0 = &mut (*(*laddr).ifa).address.sin;
                (*sin).sin_addr = (*sin_a_0).sin_addr;
                fnd_0 = 1i32;
                break;
            } else {
                laddr = (*laddr).sctp_nxt_addr.le_next
            }
        }
        if fnd_0 == 0 {
            pthread_mutex_unlock(&mut (*inp).inp_mtx);
            return 2i32;
        }
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_peeraddr(mut so: *mut socket, mut nam: *mut mbuf) -> libc::c_int {
    let mut fnd = 0;
    let mut inp = 0 as *mut sctp_inpcb;
    let mut stcb = 0 as *mut sctp_tcb;
    let mut net = 0 as *mut sctp_nets;
    let mut sin = (*nam).m_hdr.mh_data as *mut sockaddr_in;

    /* Do the malloc first in case it blocks. */
    (*nam).m_hdr.mh_len = ::std::mem::size_of::<sockaddr_in>() as libc::c_int;
    memset(
        sin as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
    );
    (*sin).sin_family = 2u16;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() || (*inp).sctp_flags & 0x200000u32 == 0u32 {
        /* UDP type and listeners will drop out here */
        return 107i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    stcb = (*inp).sctp_asoc_list.lh_first;
    if !stcb.is_null() {
        pthread_mutex_lock(&mut (*stcb).tcb_mtx);
    }
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    if stcb.is_null() {
        return 104i32;
    }
    fnd = 0i32;
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        let mut sin_a = 0 as *mut sockaddr_in;
        sin_a = &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr_in;
        if (*sin_a).sin_family as libc::c_int == 2i32 {
            fnd = 1i32;
            (*sin).sin_port = (*stcb).rport;
            (*sin).sin_addr = (*sin_a).sin_addr;
            break;
        } else {
            net = (*net).sctp_next.tqe_next
        }
    }
    pthread_mutex_unlock(&mut (*stcb).tcb_mtx);
    if fnd == 0 {
        /* No IPv4 address */
        return 2i32;
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn register_recv_cb(
    mut so: *mut socket,
    mut receive_cb: Option<
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
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 0i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    (*inp).recv_callback = receive_cb;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return 1i32;
}
#[no_mangle]
pub unsafe extern "C" fn register_send_cb(
    mut so: *mut socket,
    mut sb_threshold: uint32_t,
    mut send_cb: Option<unsafe extern "C" fn(_: *mut socket, _: uint32_t) -> libc::c_int>,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 0i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    (*inp).send_callback = send_cb;
    (*inp).send_sb_threshold = sb_threshold;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    /* FIXME change to current amount free. This will be the full buffer
     * the first time this is registered but it could be only a portion
     * of the send buffer if this is called a second time e.g. if the
     * threshold changes.
     */
    return 1i32;
}
#[no_mangle]
pub unsafe extern "C" fn register_ulp_info(
    mut so: *mut socket,
    mut ulp_info: *mut libc::c_void,
) -> libc::c_int {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if inp.is_null() {
        return 0i32;
    }
    pthread_mutex_lock(&mut (*inp).inp_mtx);
    (*inp).ulp_info = ulp_info;
    pthread_mutex_unlock(&mut (*inp).inp_mtx);
    return 1i32;
}
