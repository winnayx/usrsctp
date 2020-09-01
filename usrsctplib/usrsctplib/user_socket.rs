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
    pub type icmp6_filter;
    pub type ip6_pktopts;
    pub type ip_moptions;
    pub type inpcbpolicy;
    pub type uma_zone;
    pub type llentry;
    pub type rtentry;
    #[no_mangle]
    static in6addr_any: in6_addr;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn sendmsg(__fd: libc::c_int, __message: *const msghdr, __flags: libc::c_int) -> ssize_t;
    #[no_mangle]
    fn localtime_r(__timer: *const time_t, __tp: *mut tm) -> *mut tm;
    #[no_mangle]
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_trylock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
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
    fn pthread_cond_broadcast(__cond: *mut pthread_cond_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_cond_wait(__cond: *mut pthread_cond_t, __mutex: *mut pthread_mutex_t)
        -> libc::c_int;
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
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn sctp_close(so: *mut socket);
    #[no_mangle]
    fn sctp_abort(so: *mut socket) -> libc::c_int;
    #[no_mangle]
    fn sctp6_abort(so: *mut socket) -> libc::c_int;
    #[no_mangle]
    fn sctp6_attach(so: *mut socket, proto: libc::c_int, vrf_id: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_attach(so: *mut socket, proto: libc::c_int, vrf_id: uint32_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_listen(so: *mut socket, backlog: libc::c_int, p: *mut proc_0) -> libc::c_int;
    #[no_mangle]
    fn sctp_bind(so: *mut socket, addr: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp6_bind(so: *mut socket, addr: *mut sockaddr, proc_0: *mut libc::c_void) -> libc::c_int;
    #[no_mangle]
    fn sctpconn_bind(so: *mut socket, addr: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp_accept(so: *mut socket, addr: *mut *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp_disconnect(so: *mut socket) -> libc::c_int;
    #[no_mangle]
    fn sctpconn_connect(so: *mut socket, addr: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp6_connect(so: *mut socket, addr: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp_connect(so: *mut socket, addr: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp_finish();
    #[no_mangle]
    fn m_adj(_: *mut mbuf, _: libc::c_int);
    #[no_mangle]
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn m_copyback(_: *mut mbuf, _: libc::c_int, _: libc::c_int, _: caddr_t);
    #[no_mangle]
    fn m_pullup(_: *mut mbuf, _: libc::c_int) -> *mut mbuf;
    #[no_mangle]
    fn sctp_handle_tick(_: uint32_t);
    /*
     * Kernel defined for sctp_send
     */
    #[no_mangle]
    fn sctp_lower_sosend(
        so: *mut socket,
        addr: *mut sockaddr,
        uio: *mut uio,
        i_pak: *mut mbuf,
        control: *mut mbuf,
        flags: libc::c_int,
        srcv: *mut sctp_sndrcvinfo,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_sorecvmsg(
        so: *mut socket,
        uio: *mut uio,
        mp: *mut *mut mbuf,
        from: *mut sockaddr,
        fromlen: libc::c_int,
        msg_flags: *mut libc::c_int,
        sinfo: *mut sctp_sndrcvinfo,
        filling_sinfo: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn sctp_get_mbuf_for_msg(
        space_needed: libc::c_uint,
        want_header: libc::c_int,
        how: libc::c_int,
        allonebuf: libc::c_int,
        type_0: libc::c_int,
    ) -> *mut mbuf;
    #[no_mangle]
    fn register_recv_cb(
        _: *mut socket,
        _: Option<
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
    ) -> libc::c_int;
    #[no_mangle]
    fn register_send_cb(
        _: *mut socket,
        _: uint32_t,
        _: Option<unsafe extern "C" fn(_: *mut socket, _: uint32_t) -> libc::c_int>,
    ) -> libc::c_int;
    #[no_mangle]
    fn register_ulp_info(_: *mut socket, _: *mut libc::c_void) -> libc::c_int;
    #[no_mangle]
    fn sctp_add_addr_to_vrf(
        vrfid: uint32_t,
        ifn: *mut libc::c_void,
        ifn_index: uint32_t,
        ifn_type: uint32_t,
        if_name: *const libc::c_char,
        ifa: *mut libc::c_void,
        addr: *mut sockaddr,
        ifa_flags: uint32_t,
        dynamic_add: libc::c_int,
    ) -> *mut sctp_ifa;
    #[no_mangle]
    fn sctp_del_addr_from_vrf(
        vrfid: uint32_t,
        addr: *mut sockaddr,
        ifn_index: uint32_t,
        if_name: *const libc::c_char,
    );
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t) -> libc::c_int;
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_init(
        _: uint16_t,
        _: Option<
            unsafe extern "C" fn(
                _: *mut libc::c_void,
                _: *mut libc::c_void,
                _: size_t,
                _: uint8_t,
                _: uint8_t,
            ) -> libc::c_int,
        >,
        _: Option<unsafe extern "C" fn(_: *const libc::c_char, _: ...) -> ()>,
        start_threads: libc::c_int,
    );
    #[no_mangle]
    fn sctp_flush(_: *mut socket, _: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn sctp_shutdown(_: *mut socket) -> libc::c_int;
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
    fn sctp_common_input_processing(
        _: *mut *mut mbuf,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: *mut sockaddr,
        _: *mut sockaddr,
        _: *mut sctphdr,
        _: *mut sctp_chunkhdr,
        _: uint8_t,
        _: uint8_t,
        _: uint32_t,
        _: uint16_t,
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
    /* HAVE_SCTP_PEELOFF_SOCKOPT */
    /* _KERNEL */
    #[no_mangle]
    fn sctp_can_peel_off(_: *mut socket, _: sctp_assoc_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_do_peeloff(_: *mut socket, _: *mut socket, _: sctp_assoc_t) -> libc::c_int;
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
    /* _KERNEL */
    #[no_mangle]
    fn calculate_crc32c(_: uint32_t, _: *const libc::c_uchar, _: libc::c_uint) -> uint32_t;
    #[no_mangle]
    fn sctp_finalize_crc32c(_: uint32_t) -> uint32_t;
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
    fn sctpconn_attach(so: *mut socket, proto: libc::c_int, vrf_id: uint32_t) -> libc::c_int;
    /* needed from sctp_usrreq.c */
    #[no_mangle]
    fn sctp_setopt(
        so: *mut socket,
        optname: libc::c_int,
        optval: *mut libc::c_void,
        optsize: size_t,
        p: *mut libc::c_void,
    ) -> libc::c_int;
    /* needed from sctp_usrreq.c */
    #[no_mangle]
    fn sctp_getopt(
        so: *mut socket,
        optname: libc::c_int,
        optval: *mut libc::c_void,
        optsize: *mut size_t,
        p: *mut libc::c_void,
    ) -> libc::c_int;
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
pub type __socklen_t = libc::c_uint;
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
pub type time_t = __time_t;
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
    pub c2rust_unnamed: C2RustUnnamed_990,
    pub c2rust_unnamed_0: C2RustUnnamed_988,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_988 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_989,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_989 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_990 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_991,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_991 {
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
pub type socklen_t = __socklen_t;
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
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
pub type C2RustUnnamed_992 = libc::c_uint;
pub const MSG_CMSG_CLOEXEC: C2RustUnnamed_992 = 1073741824;
pub const MSG_FASTOPEN: C2RustUnnamed_992 = 536870912;
pub const MSG_ZEROCOPY: C2RustUnnamed_992 = 67108864;
pub const MSG_BATCH: C2RustUnnamed_992 = 262144;
pub const MSG_WAITFORONE: C2RustUnnamed_992 = 65536;
pub const MSG_MORE: C2RustUnnamed_992 = 32768;
pub const MSG_NOSIGNAL: C2RustUnnamed_992 = 16384;
pub const MSG_ERRQUEUE: C2RustUnnamed_992 = 8192;
pub const MSG_RST: C2RustUnnamed_992 = 4096;
pub const MSG_CONFIRM: C2RustUnnamed_992 = 2048;
pub const MSG_SYN: C2RustUnnamed_992 = 1024;
pub const MSG_FIN: C2RustUnnamed_992 = 512;
pub const MSG_WAITALL: C2RustUnnamed_992 = 256;
pub const MSG_EOR: C2RustUnnamed_992 = 128;
pub const MSG_DONTWAIT: C2RustUnnamed_992 = 64;
pub const MSG_TRUNC: C2RustUnnamed_992 = 32;
pub const MSG_PROXY: C2RustUnnamed_992 = 16;
pub const MSG_CTRUNC: C2RustUnnamed_992 = 8;
pub const MSG_TRYHARD: C2RustUnnamed_992 = 4;
pub const MSG_DONTROUTE: C2RustUnnamed_992 = 4;
pub const MSG_PEEK: C2RustUnnamed_992 = 2;
pub const MSG_OOB: C2RustUnnamed_992 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct msghdr {
    pub msg_name: *mut libc::c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: size_t,
    pub msg_control: *mut libc::c_void,
    pub msg_controllen: size_t,
    pub msg_flags: libc::c_int,
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
pub struct linger {
    pub l_onoff: libc::c_int,
    pub l_linger: libc::c_int,
}
pub type C2RustUnnamed_993 = libc::c_uint;
pub const SHUT_RDWR: C2RustUnnamed_993 = 2;
pub const SHUT_WR: C2RustUnnamed_993 = 1;
pub const SHUT_RD: C2RustUnnamed_993 = 0;

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
    pub __in6_u: C2RustUnnamed_994,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_994 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
}
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct udphdr {
    pub c2rust_unnamed: C2RustUnnamed_995,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_995 {
    pub c2rust_unnamed: C2RustUnnamed_997,
    pub c2rust_unnamed_0: C2RustUnnamed_996,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_996 {
    pub source: uint16_t,
    pub dest: uint16_t,
    pub len: uint16_t,
    pub check: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_997 {
    pub uh_sport: uint16_t,
    pub uh_dport: uint16_t,
    pub uh_ulen: uint16_t,
    pub uh_sum: uint16_t,
}
/* __Userspace__ Are these all the fields we need?
 * Removing struct thread *uio_td;    owner field
*/
/* scatter/gather list */
/* length of scatter/gather list */
/* offset in target object */
/* remaining bytes to process */
/* address space */
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
    pub so_incomp: C2RustUnnamed_1005,
    pub so_comp: C2RustUnnamed_1004,
    pub so_list: C2RustUnnamed_1003,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_1002,
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
    pub M_dat: C2RustUnnamed_998,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_998 {
    pub MH: C2RustUnnamed_999,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_999 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_1000,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_1000 {
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
    pub m_tag_link: C2RustUnnamed_1001,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1001 {
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
pub struct C2RustUnnamed_1002 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1003 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1004 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1005 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_1036,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_1035,
    pub sctp_hash: C2RustUnnamed_1034,
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
pub struct sctpasochead {
    pub lh_first: *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_1033,
    pub sctp_tcblist: C2RustUnnamed_1032,
    pub sctp_tcbasocidhash: C2RustUnnamed_1031,
    pub sctp_asocs: C2RustUnnamed_1030,
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
    pub next: C2RustUnnamed_1006,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1006 {
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
    pub next: C2RustUnnamed_1018,
    pub next_instrm: C2RustUnnamed_1017,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tmit_chunk {
    pub rec: C2RustUnnamed_1016,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_1007,
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
pub struct C2RustUnnamed_1007 {
    pub tqe_next: *mut sctp_tmit_chunk,
    pub tqe_prev: *mut *mut sctp_tmit_chunk,
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
    pub sctp_next: C2RustUnnamed_1015,
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
    pub tqe: C2RustUnnamed_1008,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1008 {
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
    pub next_ifa: C2RustUnnamed_1013,
    pub next_bucket: C2RustUnnamed_1012,
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
    pub next_ifn: C2RustUnnamed_1010,
    pub next_bucket: C2RustUnnamed_1009,
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
pub struct C2RustUnnamed_1009 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1010 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_1011,
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
pub struct C2RustUnnamed_1011 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1012 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1013 {
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
    pub ifa_ifu: C2RustUnnamed_1014,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_1014 {
    pub ifu_broadaddr: sockaddr,
    pub ifu_dstaddr: sockaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1015 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_1016 {
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
pub struct C2RustUnnamed_1017 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1018 {
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
    pub next_spoke: C2RustUnnamed_1019,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1019 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_1020,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1020 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_1021,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1021 {
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
    pub next: C2RustUnnamed_1023,
    pub ss_next: C2RustUnnamed_1022,
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
pub struct C2RustUnnamed_1022 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1023 {
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
/* type=SCTP_IPV6_PARAM_TYPE, len=20 */
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
/* an ASCONF "parameter" */
/* a SCTP parameter header */
/* correlation id for this param */
/* an ASCONF address parameter */
/* asconf "parameter" */
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
    pub next_resp: C2RustUnnamed_1024,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1024 {
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
    pub sctp_nxt_addr: C2RustUnnamed_1025,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1025 {
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
    pub next: C2RustUnnamed_1026,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1026 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_1027,
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
pub struct C2RustUnnamed_1027 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_1028,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_1028 {
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
/* used to keep track of the addresses yet to try to add/delete */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_1029,
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
pub struct C2RustUnnamed_1029 {
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
pub struct C2RustUnnamed_1030 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1031 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1032 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1033 {
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
pub struct C2RustUnnamed_1034 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1035 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_1036 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcb {
    pub inp_hash: C2RustUnnamed_1044,
    pub inp_list: C2RustUnnamed_1043,
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
    pub inp_depend4: C2RustUnnamed_1040,
    pub inp_depend6: C2RustUnnamed_1039,
    pub inp_portlist: C2RustUnnamed_1038,
    pub inp_phd: *mut inpcbport,
    pub inp_mtx: mtx,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbport {
    pub phd_hash: C2RustUnnamed_1037,
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
pub struct C2RustUnnamed_1037 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1038 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1039 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1040 {
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
    pub ie_dependfaddr: C2RustUnnamed_1042,
    pub ie_dependladdr: C2RustUnnamed_1041,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_1041 {
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
pub union C2RustUnnamed_1042 {
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
pub struct C2RustUnnamed_1043 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1044 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

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
pub struct sctp_getaddresses {
    pub sget_assoc_id: sctp_assoc_t,
    pub addr: [sockaddr; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}
pub const IPPROTO_SCTP: C2RustUnnamed_1045 = 132;
pub type sctp_zone_t = size_t;
pub type C2RustUnnamed_1045 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_1045 = 256;
pub const IPPROTO_RAW: C2RustUnnamed_1045 = 255;
pub const IPPROTO_MPLS: C2RustUnnamed_1045 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_1045 = 136;
pub const IPPROTO_COMP: C2RustUnnamed_1045 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_1045 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_1045 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_1045 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_1045 = 92;
pub const IPPROTO_AH: C2RustUnnamed_1045 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_1045 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_1045 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_1045 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_1045 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_1045 = 33;
pub const IPPROTO_TP: C2RustUnnamed_1045 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_1045 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_1045 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_1045 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_1045 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_1045 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_1045 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_1045 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_1045 = 1;
pub const IPPROTO_IP: C2RustUnnamed_1045 = 0;

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ip6_hdr {
    pub ip6_ctlun: C2RustUnnamed_1046,
    pub ip6_src: in6_addr,
    pub ip6_dst: in6_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_1046 {
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
/*-
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 *
 */
/*-
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct route_in6 {
    pub ro_rt: *mut rtentry,
    pub ro_lle: *mut llentry,
    pub ro_ia6: *mut in6_addr,
    pub ro_flags: libc::c_int,
    pub ro_dst: sockaddr_in6,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct calloutlist {
    pub tqh_first: *mut sctp_callout,
    pub tqh_last: *mut *mut sctp_callout,
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
pub struct sctp_prinfo {
    pub pr_policy: uint16_t,
    pub pr_value: uint32_t,
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
pub struct sctp_authinfo {
    pub auth_keynumber: uint16_t,
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
pub struct sctp_recvv_rn {
    pub recvv_rcvinfo: sctp_rcvinfo,
    pub recvv_nxtinfo: sctp_nxtinfo,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_sendv_spa {
    pub sendv_flags: uint32_t,
    pub sendv_sndinfo: sctp_sndinfo,
    pub sendv_prinfo: sctp_prinfo,
    pub sendv_authinfo: sctp_authinfo,
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
pub struct sctp_authkey {
    pub sca_assoc_id: sctp_assoc_t,
    pub sca_keynumber: uint16_t,
    pub sca_keylength: uint16_t,
    pub sca_key: [uint8_t; 0],
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
    pub sctp_nxt_tagblock: C2RustUnnamed_1047,
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
pub struct C2RustUnnamed_1047 {
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
pub type __timezone_ptr_t = *mut timezone;
/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
 *      The Regents of the University of California.
 * Copyright (c) 2004 The FreeBSD Foundation
 * Copyright (c) 2004-2008 Robert N. M. Watson
 * Copyright (c) 2009-2010 Brad Penoff
 * Copyright (c) 2009-2010 Humaira Kamal
 * Copyright (c) 2011-2012 Irene Ruengeler
 * Copyright (c) 2011-2012 Michael Tuexen
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
 *
 */
/* (on Ubuntu at least) enables UDP header field names like BSD in RFC 768 */
#[no_mangle]
pub static mut accept_mtx: userland_mutex_t = pthread_mutex_t {
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
};
#[no_mangle]
pub static mut accept_cond: userland_cond_t = pthread_cond_t {
    __data: __pthread_cond_s {
        c2rust_unnamed: C2RustUnnamed_990 { __wseq: 0 },
        c2rust_unnamed_0: C2RustUnnamed_988 { __g1_start: 0 },
        __g_refs: [0; 2],
        __g_size: [0; 2],
        __g1_orig_size: 0,
        __wrefs: 0,
        __g_signals: [0; 2],
    },
};
#[no_mangle]
pub static mut M_PCB: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_pcb\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
#[no_mangle]
pub static mut M_SONAME: [malloc_type; 1] = [{
    let mut init = malloc_type {
        ks_next: 0 as *mut malloc_type,
        _ks_memuse: 0u64,
        _ks_size: 0u64,
        _ks_inuse: 0u64,
        _ks_calls: 0u64,
        _ks_maxused: 0u64,
        ks_magic: 877983977u64,
        ks_shortdesc: b"sctp_soname\x00" as *const u8 as *const libc::c_char,
        ks_handle: 0 as *mut libc::c_void,
        _lo_name: 0 as *const libc::c_char,
        _lo_type: 0 as *const libc::c_char,
        _lo_flags: 0u32,
        _lo_list_next: 0 as *mut libc::c_void,
        _lo_witness: 0 as *mut witness,
        _mtx_lock: 0u64,
        _mtx_recurse: 0u32,
    };
    init
}];
unsafe extern "C" fn init_sync() {
    let mut mutex_attr = pthread_mutexattr_t { __size: [0; 4] };
    pthread_mutexattr_init(&mut mutex_attr);
    pthread_mutex_init(&mut accept_mtx, &mut mutex_attr);
    pthread_mutexattr_destroy(&mut mutex_attr);
    pthread_cond_init(&mut accept_cond, 0 as *const pthread_condattr_t);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_init(
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
) {
    init_sync();
    sctp_init(port, conn_output, debug_printf, 1i32);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_init_nothreads(
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
) {
    init_sync();
    sctp_init(port, conn_output, debug_printf, 0i32);
}
/* Taken from  usr/src/sys/kern/uipc_sockbuf.c and modified for __Userspace__*/
/*
 * Socantsendmore indicates that no more data will be sent on the socket; it
 * would normally be applied to a socket when the user informs the system
 * that no more data is to be sent, by the protocol code (in case
 * PRU_SHUTDOWN).  Socantrcvmore indicates that no more data will be
 * received, and will normally be applied to the socket by a protocol when it
 * detects that the peer will send no more data.  Data queued for reading in
 * the socket may yet be read.
 */
#[no_mangle]
pub unsafe extern "C" fn socantrcvmore_locked(mut so: *mut socket) {
    (*so).so_rcv.sb_state = ((*so).so_rcv.sb_state as libc::c_int | 0x20i32) as libc::c_short;
    if (*so).so_rcv.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup(so, &mut (*so).so_rcv);
    } else {
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    };
}
#[no_mangle]
pub unsafe extern "C" fn socantrcvmore(mut so: *mut socket) {
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    socantrcvmore_locked(so);
}
#[no_mangle]
pub unsafe extern "C" fn socantsendmore_locked(mut so: *mut socket) {
    (*so).so_snd.sb_state = ((*so).so_snd.sb_state as libc::c_int | 0x10i32) as libc::c_short;
    if (*so).so_snd.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup(so, &mut (*so).so_snd);
    } else {
        pthread_mutex_unlock(&mut (*so).so_snd.sb_mtx);
    };
}
#[no_mangle]
pub unsafe extern "C" fn socantsendmore(mut so: *mut socket) {
    pthread_mutex_lock(&mut (*so).so_snd.sb_mtx);
    socantsendmore_locked(so);
}
/* Taken from  usr/src/sys/kern/uipc_sockbuf.c and called within sctp_lower_sosend.
 */
#[no_mangle]
pub unsafe extern "C" fn sbwait(mut sb: *mut sockbuf) -> libc::c_int {
    /* __Userspace__ */
    (*sb).sb_flags = ((*sb).sb_flags as libc::c_int | 0x4i32) as libc::c_short;
    return pthread_cond_wait(&mut (*sb).sb_cond, &mut (*sb).sb_mtx);
}
/* Taken from  /src/sys/kern/uipc_socket.c
 * and modified for __Userspace__
 */
unsafe extern "C" fn soalloc() -> *mut socket {
    let mut so = 0 as *mut socket;
    /*
     * soalloc() sets of socket layer state for a socket,
     * called only by socreate() and sonewconn().
     *
     * sodealloc() tears down socket layer state for a socket,
     * called only by sofree() and sonewconn().
     * __Userspace__ TODO : Make sure so is properly deallocated
     * when tearing down the connection.
     */
    so = malloc(::std::mem::size_of::<socket>() as libc::c_ulong) as *mut socket;
    if so.is_null() {
        return 0 as *mut socket;
    }
    memset(
        so as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<socket>() as libc::c_ulong,
    );
    /* __Userspace__ Initializing the socket locks here */
    pthread_mutex_init(&mut (*so).so_snd.sb_mtx, 0 as *const pthread_mutexattr_t); /* timeo_cond */
    pthread_mutex_init(&mut (*so).so_rcv.sb_mtx, 0 as *const pthread_mutexattr_t);
    pthread_cond_init(&mut (*so).so_snd.sb_cond, 0 as *const pthread_condattr_t);
    pthread_cond_init(&mut (*so).so_rcv.sb_cond, 0 as *const pthread_condattr_t);
    pthread_cond_init(&mut (*so).timeo_cond, 0 as *const pthread_condattr_t);
    /* __Userspace__ Any ref counting required here? Will we have any use for aiojobq?
    What about gencnt and numopensockets?*/
    (*so).so_aiojobq.tqh_first = 0 as *mut aiocblist;
    (*so).so_aiojobq.tqh_last = &mut (*so).so_aiojobq.tqh_first;
    return so;
}
unsafe extern "C" fn sodealloc(mut so: *mut socket) {
    pthread_cond_destroy(&mut (*so).so_snd.sb_cond);
    pthread_cond_destroy(&mut (*so).so_rcv.sb_cond);
    pthread_cond_destroy(&mut (*so).timeo_cond);
    pthread_mutex_destroy(&mut (*so).so_snd.sb_mtx);
    pthread_mutex_destroy(&mut (*so).so_rcv.sb_mtx);
    free(so as *mut libc::c_void);
}
/* Taken from  /src/sys/kern/uipc_socket.c
 * and modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn sofree(mut so: *mut socket) {
    let mut head = 0 as *mut socket;
    /* SS_NOFDREF unset in accept call.  this condition seems irrelevent
     *  for __Userspace__...
     */
    if (*so).so_count != 0i32
        || (*so).so_state as libc::c_int & 0x4000i32 != 0
        || (*so).so_qstate & 0x1000i32 != 0
    {
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx); /* was...    sctp_detach(so); */
        pthread_mutex_unlock(&mut accept_mtx);
        return;
    }
    head = (*so).so_head;
    if !head.is_null() {
        if !(*so).so_list.tqe_next.is_null() {
            (*(*so).so_list.tqe_next).so_list.tqe_prev = (*so).so_list.tqe_prev
        } else {
            (*head).so_incomp.tqh_last = (*so).so_list.tqe_prev
        }
        *(*so).so_list.tqe_prev = (*so).so_list.tqe_next;
        (*head).so_incqlen = (*head).so_incqlen.wrapping_sub(1);
        (*so).so_qstate &= !(0x800i32);
        (*so).so_head = 0 as *mut socket
    }
    ((*so).so_options as libc::c_int & 0x2i32) != 0;
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    pthread_mutex_unlock(&mut accept_mtx);
    sctp_close(so);
    /*
     * From this point on, we assume that no other references to this
     * socket exist anywhere else in the stack.  Therefore, no locks need
     * to be acquired or held.
     *
     * We used to do a lot of socket buffer and socket locking here, as
     * well as invoke sorflush() and perform wakeups.  The direct call to
     * dom_dispose() and sbrelease_internal() are an inlining of what was
     * necessary from sorflush().
     *
     * Notice that the socket buffer and kqueue state are torn down
     * before calling pru_detach.  This means that protocols shold not
     * assume they can perform socket wakeups, etc, in their detach code.
     */
    sodealloc(so);
}
/* Taken from  /src/sys/kern/uipc_socket.c */
#[no_mangle]
pub unsafe extern "C" fn soabort(mut so: *mut socket) {
    let mut inp = 0 as *mut sctp_inpcb;
    inp = (*so).so_pcb as *mut sctp_inpcb;
    if (*inp).sctp_flags & 0x4000000u32 != 0 {
        sctp6_abort(so);
    } else {
        sctp_abort(so);
    }
    pthread_mutex_lock(&mut accept_mtx);
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    sofree(so);
}
/* Taken from  usr/src/sys/kern/uipc_socket.c and called within sctp_connect (sctp_usrreq.c).
 *  We use sctp_connect for send_one_init_real in ms1.
 */
#[no_mangle]
pub unsafe extern "C" fn soisconnecting(mut so: *mut socket) {
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    (*so).so_state = ((*so).so_state as libc::c_int & !(0x2i32 | 0x8i32)) as libc::c_short;
    (*so).so_state = ((*so).so_state as libc::c_int | 0x4i32) as libc::c_short;
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
}
/* Taken from  usr/src/sys/kern/uipc_socket.c and called within sctp_disconnect (sctp_usrreq.c).
 *  TODO Do we use sctp_disconnect?
 */
#[no_mangle]
pub unsafe extern "C" fn soisdisconnecting(mut so: *mut socket) {
    /*
     * Note: This code assumes that SOCK_LOCK(so) and
     * SOCKBUF_LOCK(&so->so_rcv) are the same.
     */
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    (*so).so_state = ((*so).so_state as libc::c_int & !(0x4i32)) as libc::c_short;
    (*so).so_state = ((*so).so_state as libc::c_int | 0x8i32) as libc::c_short;
    (*so).so_rcv.sb_state = ((*so).so_rcv.sb_state as libc::c_int | 0x20i32) as libc::c_short;
    if (*so).so_rcv.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup(so, &mut (*so).so_rcv);
    } else {
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    }
    pthread_mutex_lock(&mut (*so).so_snd.sb_mtx);
    (*so).so_snd.sb_state = ((*so).so_snd.sb_state as libc::c_int | 0x10i32) as libc::c_short;
    if (*so).so_snd.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup(so, &mut (*so).so_snd);
    } else {
        pthread_mutex_unlock(&mut (*so).so_snd.sb_mtx);
    }
    wakeup(b"dummy\x00" as *const u8 as *mut libc::c_void, so);
    /* requires 2 args but this was in orig */
    /* wakeup(&so->so_timeo); */
}
/* Taken from sys/kern/kern_synch.c and
   modified for __Userspace__
*/
/*
 * Make all threads sleeping on the specified identifier runnable.
 * Associating wakeup with so_timeo identifier and timeo_cond
 * condition variable. TODO. If we use iterator thread then we need to
 * modify wakeup so it can distinguish between iterator identifier and
 * timeo identifier.
 */
#[no_mangle]
pub unsafe extern "C" fn wakeup(mut ident: *mut libc::c_void, mut so: *mut socket) {
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    pthread_cond_broadcast(&mut (*so).timeo_cond);
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
}
/*
 * Make a thread sleeping on the specified identifier runnable.
 * May wake more than one thread if a target thread is currently
 * swapped out.
 */
#[no_mangle]
pub unsafe extern "C" fn wakeup_one(mut ident: *mut libc::c_void) {
    /* __Userspace__ Check: We are using accept_cond for wakeup_one.
     It seems that wakeup_one is only called within
     soisconnected() and sonewconn() with ident &head->so_timeo
     head is so->so_head, which is back pointer to listen socket
     This seems to indicate that the use of accept_cond is correct
     since socket where accepts occur is so_head in all
     subsidiary sockets.
    */
    pthread_mutex_lock(&mut accept_mtx);
    pthread_cond_broadcast(&mut accept_cond);
    pthread_mutex_unlock(&mut accept_mtx);
}
/* Called within sctp_process_cookie_[existing/new] */
#[no_mangle]
pub unsafe extern "C" fn soisconnected(mut so: *mut socket) {
    let mut head = 0 as *mut socket;
    pthread_mutex_lock(&mut accept_mtx);
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    (*so).so_state =
        ((*so).so_state as libc::c_int & !(0x4i32 | 0x8i32 | 0x400i32)) as libc::c_short;
    (*so).so_state = ((*so).so_state as libc::c_int | 0x2i32) as libc::c_short;
    head = (*so).so_head;
    if !head.is_null() && (*so).so_qstate & 0x800i32 != 0 {
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
        if !(*so).so_list.tqe_next.is_null() {
            (*(*so).so_list.tqe_next).so_list.tqe_prev = (*so).so_list.tqe_prev
        } else {
            (*head).so_incomp.tqh_last = (*so).so_list.tqe_prev
        }
        *(*so).so_list.tqe_prev = (*so).so_list.tqe_next;
        (*head).so_incqlen = (*head).so_incqlen.wrapping_sub(1);
        (*so).so_qstate &= !(0x800i32);
        (*so).so_list.tqe_next = 0 as *mut socket;
        (*so).so_list.tqe_prev = (*head).so_comp.tqh_last;
        *(*head).so_comp.tqh_last = so;
        (*head).so_comp.tqh_last = &mut (*so).so_list.tqe_next;
        (*head).so_qlen = (*head).so_qlen.wrapping_add(1);
        (*so).so_qstate |= 0x1000i32;
        pthread_mutex_unlock(&mut accept_mtx);
        pthread_mutex_lock(&mut (*head).so_rcv.sb_mtx);
        if (*head).so_rcv.sb_flags as libc::c_int
            & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
            != 0i32
        {
            sowakeup(head, &mut (*head).so_rcv);
        } else {
            pthread_mutex_unlock(&mut (*head).so_rcv.sb_mtx);
        }
        wakeup_one(&mut (*head).so_timeo as *mut libc::c_short as *mut libc::c_void);
        return;
    }
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    pthread_mutex_unlock(&mut accept_mtx);
    wakeup(
        &mut (*so).so_timeo as *mut libc::c_short as *mut libc::c_void,
        so,
    );
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    if (*so).so_rcv.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup(so, &mut (*so).so_rcv);
    } else {
        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    }
    pthread_mutex_lock(&mut (*so).so_snd.sb_mtx);
    if (*so).so_snd.sb_flags as libc::c_int
        & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
        != 0i32
    {
        sowakeup(so, &mut (*so).so_snd);
    } else {
        pthread_mutex_unlock(&mut (*so).so_snd.sb_mtx);
    };
}
/* called within sctp_handle_cookie_echo */
#[no_mangle]
pub unsafe extern "C" fn sonewconn(
    mut head: *mut socket,
    mut connstatus: libc::c_int,
) -> *mut socket {
    let mut so = 0 as *mut socket;
    let mut over = 0;
    pthread_mutex_lock(&mut accept_mtx);
    over = ((*head).so_qlen as libc::c_int > 3i32 * (*head).so_qlimit as libc::c_int / 2i32)
        as libc::c_int;
    pthread_mutex_unlock(&mut accept_mtx);
    if over != 0 {
        return 0 as *mut socket;
    }
    so = soalloc();
    if so.is_null() {
        return 0 as *mut socket;
    }
    (*so).so_head = head;
    (*so).so_type = (*head).so_type;
    (*so).so_options = ((*head).so_options as libc::c_int & !(0x2i32)) as libc::c_short;
    (*so).so_linger = (*head).so_linger;
    (*so).so_state = ((*head).so_state as libc::c_int | 0x1i32) as libc::c_short;
    (*so).so_dom = (*head).so_dom;
    if soreserve(
        so,
        (*head).so_snd.sb_hiwat as u_long,
        (*head).so_rcv.sb_hiwat as u_long,
    ) != 0
    {
        sodealloc(so);
        return 0 as *mut socket;
    }
    match (*head).so_dom {
        2 => {
            if sctp_attach(so, IPPROTO_SCTP as libc::c_int, 0u32) != 0 {
                sodealloc(so);
                return 0 as *mut socket;
            }
        }
        10 => {
            if sctp6_attach(so, IPPROTO_SCTP as libc::c_int, 0u32) != 0 {
                sodealloc(so);
                return 0 as *mut socket;
            }
        }
        123 => {
            if sctpconn_attach(so, IPPROTO_SCTP as libc::c_int, 0u32) != 0 {
                sodealloc(so);
                return 0 as *mut socket;
            }
        }
        _ => {
            sodealloc(so);
            return 0 as *mut socket;
        }
    }
    (*so).so_rcv.sb_lowat = (*head).so_rcv.sb_lowat;
    (*so).so_snd.sb_lowat = (*head).so_snd.sb_lowat;
    (*so).so_rcv.sb_timeo = (*head).so_rcv.sb_timeo;
    (*so).so_snd.sb_timeo = (*head).so_snd.sb_timeo;
    (*so).so_rcv.sb_flags = ((*so).so_rcv.sb_flags as libc::c_int
        | (*head).so_rcv.sb_flags as libc::c_int & 0x800i32)
        as libc::c_short;
    (*so).so_snd.sb_flags = ((*so).so_snd.sb_flags as libc::c_int
        | (*head).so_snd.sb_flags as libc::c_int & 0x800i32)
        as libc::c_short;
    (*so).so_state = ((*so).so_state as libc::c_int | connstatus) as libc::c_short;
    pthread_mutex_lock(&mut accept_mtx);
    if connstatus != 0 {
        (*so).so_list.tqe_next = 0 as *mut socket;
        (*so).so_list.tqe_prev = (*head).so_comp.tqh_last;
        *(*head).so_comp.tqh_last = so;
        (*head).so_comp.tqh_last = &mut (*so).so_list.tqe_next;
        (*so).so_qstate |= 0x1000i32;
        (*head).so_qlen = (*head).so_qlen.wrapping_add(1)
    } else {
        /*
         * Keep removing sockets from the head until there's room for
         * us to insert on the tail.  In pre-locking revisions, this
         * was a simple if (), but as we could be racing with other
         * threads and soabort() requires dropping locks, we must
         * loop waiting for the condition to be true.
         */
        while (*head).so_incqlen as libc::c_int > (*head).so_qlimit as libc::c_int {
            let mut sp = 0 as *mut socket;
            sp = (*head).so_incomp.tqh_first;
            if !(*sp).so_list.tqe_next.is_null() {
                (*(*sp).so_list.tqe_next).so_list.tqe_prev = (*sp).so_list.tqe_prev
            } else {
                (*head).so_incomp.tqh_last = (*sp).so_list.tqe_prev
            }
            *(*sp).so_list.tqe_prev = (*sp).so_list.tqe_next;
            (*head).so_incqlen = (*head).so_incqlen.wrapping_sub(1);
            (*sp).so_qstate &= !(0x800i32);
            (*sp).so_head = 0 as *mut socket;
            pthread_mutex_unlock(&mut accept_mtx);
            soabort(sp);
            pthread_mutex_lock(&mut accept_mtx);
        }
        (*so).so_list.tqe_next = 0 as *mut socket;
        (*so).so_list.tqe_prev = (*head).so_incomp.tqh_last;
        *(*head).so_incomp.tqh_last = so;
        (*head).so_incomp.tqh_last = &mut (*so).so_list.tqe_next;
        (*so).so_qstate |= 0x800i32;
        (*head).so_incqlen = (*head).so_incqlen.wrapping_add(1)
    }
    pthread_mutex_unlock(&mut accept_mtx);
    if connstatus != 0 {
        pthread_mutex_lock(&mut (*head).so_rcv.sb_mtx);
        if (*head).so_rcv.sb_flags as libc::c_int
            & (0x4i32 | 0x8i32 | 0x10i32 | 0x20i32 | 0x80i32 | 0x100i32)
            != 0i32
        {
            sowakeup(head, &mut (*head).so_rcv);
        } else {
            pthread_mutex_unlock(&mut (*head).so_rcv.sb_mtx);
        }
        wakeup_one(&mut (*head).so_timeo as *mut libc::c_short as *mut libc::c_void);
    }
    return so;
}
/*
  Source: /src/sys/gnu/fs/xfs/FreeBSD/xfs_ioctl.c
*/
#[inline]
unsafe extern "C" fn copy_to_user(
    mut dst: *mut libc::c_void,
    mut src: *mut libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    memcpy(dst, src, len);
    return 0i32;
}
#[inline]
unsafe extern "C" fn copy_from_user(
    mut dst: *mut libc::c_void,
    mut src: *mut libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    memcpy(dst, src, len);
    return 0i32;
}
/*
 References:
 src/sys/dev/lmc/if_lmc.h:
 src/sys/powerpc/powerpc/copyinout.c
 src/sys/sys/systm.h
*/
/* References:
   src/sys/powerpc/powerpc/copyinout.c
   src/sys/sys/systm.h
*/
/* copyiniov definition copied/modified from src/sys/kern/kern_subr.c */
#[no_mangle]
pub unsafe extern "C" fn copyiniov(
    mut iovp: *mut iovec,
    mut iovcnt: u_int,
    mut iov: *mut *mut iovec,
    mut error: libc::c_int,
) -> libc::c_int {
    let mut iovlen = 0; /*, M_IOV, M_WAITOK); */
    *iov = 0 as *mut iovec; /*, M_IOV); */
    if iovcnt > 1024u32 {
        return error;
    }
    iovlen = (iovcnt as libc::c_ulong).wrapping_mul(::std::mem::size_of::<iovec>() as libc::c_ulong)
        as u_int;
    *iov = malloc(iovlen as libc::c_ulong) as *mut iovec;
    error = copy_from_user(
        *iov as *mut libc::c_void,
        iovp as *mut libc::c_void,
        iovlen as size_t,
    );
    if error != 0 {
        free(*iov as *mut libc::c_void);
        *iov = 0 as *mut iovec
    }
    return error;
}
/* (__Userspace__) version of uiomove */
#[no_mangle]
pub unsafe extern "C" fn uiomove(
    mut cp: *mut libc::c_void,
    mut n: libc::c_int,
    mut uio: *mut uio,
) -> libc::c_int {
    let mut error = 0i32;
    if (*uio).uio_rw != UIO_READ && (*uio).uio_rw != UIO_WRITE {
        return 22i32;
    }
    while n > 0i32 && (*uio).uio_resid != 0 {
        let mut iov = 0 as *mut iovec;
        let mut cnt = 0;
        iov = (*uio).uio_iov;
        cnt = (*iov).iov_len;
        if cnt == 0u64 {
            (*uio).uio_iov = (*uio).uio_iov.offset(1);
            (*uio).uio_iovcnt -= 1
        } else {
            if cnt > n as size_t {
                cnt = n as size_t
            }
            match (*uio).uio_segflg {
                0 => {
                    if (*uio).uio_rw == UIO_READ {
                        error = copy_to_user((*iov).iov_base, cp, cnt)
                    } else {
                        error = copy_from_user(cp, (*iov).iov_base, cnt)
                    }
                    if error != 0 {
                        break;
                    }
                }
                1 => {
                    if (*uio).uio_rw == UIO_READ {
                        memcpy((*iov).iov_base, cp, cnt);
                    } else {
                        memcpy(cp, (*iov).iov_base, cnt);
                    }
                }
                _ => {}
            }
            (*iov).iov_base =
                ((*iov).iov_base as *mut libc::c_char).offset(cnt as isize) as *mut libc::c_void;
            (*iov).iov_len = ((*iov).iov_len).wrapping_sub(cnt);
            (*uio).uio_resid = ((*uio).uio_resid as libc::c_ulong).wrapping_sub(cnt) as ssize_t;
            (*uio).uio_offset += cnt as off_t;
            cp = (cp as *mut libc::c_char).offset(cnt as isize) as *mut libc::c_void;
            n -= cnt as libc::c_int
        }
    }
    return error;
}
/* Source: src/sys/kern/uipc_syscalls.c */
#[no_mangle]
pub unsafe extern "C" fn getsockaddr(
    mut namp: *mut *mut sockaddr,
    mut uaddr: caddr_t,
    mut len: size_t,
) -> libc::c_int {
    let mut sa = 0 as *mut sockaddr;
    let mut error = 0;
    if len > 255u64 {
        return 36i32;
    }
    if len < 2u64 {
        return 22i32;
    }
    sa = malloc(len) as *mut sockaddr;
    if 0x2i32 & 0x100i32 != 0 {
        memset(sa as *mut libc::c_void, 0i32, len);
    }
    error = copy_from_user(sa as *mut libc::c_void, uaddr as *mut libc::c_void, len);
    if error != 0 {
        free(sa as *mut libc::c_void);
    } else {
        *namp = sa
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_getassocid(
    mut sock: *mut socket,
    mut sa: *mut sockaddr,
) -> sctp_assoc_t {
    let mut sp = sctp_paddrinfo {
        spinfo_address: sockaddr_storage {
            ss_family: 0,
            __ss_padding: [0; 118],
            __ss_align: 0,
        },
        spinfo_assoc_id: 0,
        spinfo_state: 0,
        spinfo_cwnd: 0,
        spinfo_srtt: 0,
        spinfo_rto: 0,
        spinfo_mtu: 0,
    };
    let mut siz = 0;
    let mut sa_len = 0;
    /* First get the assoc id */
    siz = ::std::mem::size_of::<sctp_paddrinfo>() as socklen_t;
    memset(
        &mut sp as *mut sctp_paddrinfo as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_paddrinfo>() as libc::c_ulong,
    );
    match (*sa).sa_family as libc::c_int {
        2 => sa_len = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
        10 => sa_len = ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
        123 => sa_len = ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
        _ => sa_len = 0u64,
    }
    memcpy(
        &mut sp.spinfo_address as *mut sockaddr_storage as *mut libc::c_void,
        sa as *const libc::c_void,
        sa_len,
    );
    if usrsctp_getsockopt(
        sock,
        IPPROTO_SCTP as libc::c_int,
        0x101i32,
        &mut sp as *mut sctp_paddrinfo as *mut libc::c_void,
        &mut siz,
    ) != 0i32
    {
        /* We depend on the fact that 0 can never be returned */
        return 0u32;
    }
    return sp.spinfo_assoc_id;
}
/* Taken from  /src/lib/libc/net/sctp_sys_calls.c
 * and modified for __Userspace__
 * calling sctp_generic_sendmsg from this function
 */
#[no_mangle]
pub unsafe extern "C" fn userspace_sctp_sendmsg(
    mut so: *mut socket,
    mut data: *const libc::c_void,
    mut len: size_t,
    mut to: *mut sockaddr,
    mut tolen: socklen_t,
    mut ppid: u_int32_t,
    mut flags: u_int32_t,
    mut stream_no: u_int16_t,
    mut timetolive: u_int32_t,
    mut context: u_int32_t,
) -> ssize_t {
    let mut sndrcvinfo = sctp_sndrcvinfo {
        sinfo_stream: 0,
        sinfo_ssn: 0,
        sinfo_flags: 0,
        sinfo_ppid: 0,
        sinfo_context: 0,
        sinfo_timetolive: 0,
        sinfo_tsn: 0,
        sinfo_cumtsn: 0,
        sinfo_assoc_id: 0,
        sinfo_keynumber: 0,
        sinfo_keynumber_valid: 0,
        __reserve_pad: [0; 92],
    };
    let mut iov = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 1];
    let mut sinfo: *mut sctp_sndrcvinfo = &mut sndrcvinfo;
    let mut auio = uio {
        uio_iov: 0 as *mut iovec,
        uio_iovcnt: 0,
        uio_offset: 0,
        uio_resid: 0,
        uio_segflg: UIO_USERSPACE,
        uio_rw: UIO_READ,
    };

    memset(
        sinfo as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong,
    );
    (*sinfo).sinfo_ppid = ppid;
    (*sinfo).sinfo_flags = flags as uint16_t;
    (*sinfo).sinfo_stream = stream_no;
    (*sinfo).sinfo_timetolive = timetolive;
    (*sinfo).sinfo_context = context;
    (*sinfo).sinfo_assoc_id = 0u32;
    /* Perform error checks on destination (to) */
    if tolen > 255u32 {
        *__errno_location() = 36i32;
        return -1i64;
    }
    if tolen > 0u32 && (to.is_null() || tolen < ::std::mem::size_of::<sockaddr>() as socklen_t) {
        *__errno_location() = 22i32;
        return -1i64;
    }
    if data == 0 as *mut libc::c_void {
        *__errno_location() = 14i32;
        return -1i64;
    }
    /* Adding the following as part of defensive programming, in case the application
    does not do it when preparing the destination address.*/
    iov[0usize].iov_base = data as *mut libc::c_void; /* XXX */
    iov[0usize].iov_len = len;
    auio.uio_iov = iov.as_mut_ptr();
    auio.uio_iovcnt = 1i32;
    auio.uio_segflg = UIO_USERSPACE;
    auio.uio_rw = UIO_WRITE;
    auio.uio_offset = 0i64;
    auio.uio_resid = len as ssize_t;
    *__errno_location() = sctp_lower_sosend(
        so,
        to,
        &mut auio,
        0 as *mut mbuf,
        0 as *mut mbuf,
        0i32,
        sinfo,
    );
    if *__errno_location() == 0i32 {
        return len.wrapping_sub(auio.uio_resid as libc::c_ulong) as ssize_t;
    } else {
        return -1i64;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sendv(
    mut so: *mut socket,
    mut data: *const libc::c_void,
    mut len: size_t,
    mut to: *mut sockaddr,
    mut addrcnt: libc::c_int,
    mut info: *mut libc::c_void,
    mut infolen: socklen_t,
    mut infotype: libc::c_uint,
    mut flags: libc::c_int,
) -> ssize_t {
    let mut sinfo = sctp_sndrcvinfo {
        sinfo_stream: 0,
        sinfo_ssn: 0,
        sinfo_flags: 0,
        sinfo_ppid: 0,
        sinfo_context: 0,
        sinfo_timetolive: 0,
        sinfo_tsn: 0,
        sinfo_cumtsn: 0,
        sinfo_assoc_id: 0,
        sinfo_keynumber: 0,
        sinfo_keynumber_valid: 0,
        __reserve_pad: [0; 92],
    };
    let mut iov = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 1];
    let mut use_sinfo = 0;
    let mut assoc_id = 0 as *mut sctp_assoc_t;
    let mut auio = uio {
        uio_iov: 0 as *mut iovec,
        uio_iovcnt: 0,
        uio_offset: 0,
        uio_resid: 0,
        uio_segflg: UIO_USERSPACE,
        uio_rw: UIO_READ,
    };

    if so.is_null() {
        *__errno_location() = 9i32;
        return -1i64;
    }
    if data == 0 as *mut libc::c_void {
        *__errno_location() = 14i32;
        return -1i64;
    }
    memset(
        &mut sinfo as *mut sctp_sndrcvinfo as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_sndrcvinfo>() as libc::c_ulong,
    );
    assoc_id = 0 as *mut sctp_assoc_t;
    use_sinfo = 0i32;
    match infotype {
        0 => {
            if infolen != 0u32 || !info.is_null() {
                *__errno_location() = 22i32;
                return -1i64;
            }
        }
        1 => {
            if info.is_null()
                || infolen as libc::c_ulong
                    != ::std::mem::size_of::<sctp_sndinfo>() as libc::c_ulong
            {
                *__errno_location() = 22i32;
                return -1i64;
            }
            sinfo.sinfo_stream = (*(info as *mut sctp_sndinfo)).snd_sid;
            sinfo.sinfo_flags = (*(info as *mut sctp_sndinfo)).snd_flags;
            sinfo.sinfo_ppid = (*(info as *mut sctp_sndinfo)).snd_ppid;
            sinfo.sinfo_context = (*(info as *mut sctp_sndinfo)).snd_context;
            sinfo.sinfo_assoc_id = (*(info as *mut sctp_sndinfo)).snd_assoc_id;
            assoc_id = &mut (*(info as *mut sctp_sndinfo)).snd_assoc_id;
            use_sinfo = 1i32
        }
        2 => {
            if info.is_null()
                || infolen as libc::c_ulong != ::std::mem::size_of::<sctp_prinfo>() as libc::c_ulong
            {
                *__errno_location() = 22i32;
                return -1i64;
            }
            sinfo.sinfo_stream = 0u16;
            sinfo.sinfo_flags =
                ((*(info as *mut sctp_prinfo)).pr_policy as libc::c_int & 0xfi32) as uint16_t;
            sinfo.sinfo_timetolive = (*(info as *mut sctp_prinfo)).pr_value;
            use_sinfo = 1i32
        }
        3 => {
            *__errno_location() = 22i32;
            return -1i64;
        }
        4 => {
            if info.is_null()
                || infolen as libc::c_ulong
                    != ::std::mem::size_of::<sctp_sendv_spa>() as libc::c_ulong
            {
                *__errno_location() = 22i32;
                return -1i64;
            }
            if (*(info as *mut sctp_sendv_spa)).sendv_flags & 0x1u32 != 0 {
                sinfo.sinfo_stream = (*(info as *mut sctp_sendv_spa)).sendv_sndinfo.snd_sid;
                sinfo.sinfo_flags = (*(info as *mut sctp_sendv_spa)).sendv_sndinfo.snd_flags;
                sinfo.sinfo_ppid = (*(info as *mut sctp_sendv_spa)).sendv_sndinfo.snd_ppid;
                sinfo.sinfo_context = (*(info as *mut sctp_sendv_spa)).sendv_sndinfo.snd_context;
                sinfo.sinfo_assoc_id = (*(info as *mut sctp_sendv_spa)).sendv_sndinfo.snd_assoc_id;
                assoc_id = &mut (*(info as *mut sctp_sendv_spa)).sendv_sndinfo.snd_assoc_id
            } else {
                sinfo.sinfo_flags = 0u16;
                sinfo.sinfo_stream = 0u16
            }
            if (*(info as *mut sctp_sendv_spa)).sendv_flags & 0x2u32 != 0 {
                sinfo.sinfo_flags = (sinfo.sinfo_flags as libc::c_int
                    | (*(info as *mut sctp_sendv_spa)).sendv_prinfo.pr_policy as libc::c_int
                        & 0xfi32) as uint16_t;
                sinfo.sinfo_timetolive = (*(info as *mut sctp_sendv_spa)).sendv_prinfo.pr_value
            }
            if (*(info as *mut sctp_sendv_spa)).sendv_flags & 0x4u32 != 0 {
                *__errno_location() = 22i32;
                return -1i64;
            }
            use_sinfo = 1i32
        }
        _ => {
            *__errno_location() = 22i32;
            return -1i64;
        }
    }
    /* Perform error checks on destination (to) */
    if addrcnt > 1i32 {
        *__errno_location() = 22i32; /* XXX */
        return -1i64;
    }
    iov[0usize].iov_base = data as *mut libc::c_void;
    iov[0usize].iov_len = len;
    auio.uio_iov = iov.as_mut_ptr();
    auio.uio_iovcnt = 1i32;
    auio.uio_segflg = UIO_USERSPACE;
    auio.uio_rw = UIO_WRITE;
    auio.uio_offset = 0i64;
    auio.uio_resid = len as ssize_t;
    *__errno_location() = sctp_lower_sosend(
        so,
        to,
        &mut auio,
        0 as *mut mbuf,
        0 as *mut mbuf,
        flags,
        if use_sinfo != 0 {
            &mut sinfo
        } else {
            0 as *mut sctp_sndrcvinfo
        },
    );
    if *__errno_location() == 0i32 {
        if !to.is_null() && !assoc_id.is_null() {
            *assoc_id = usrsctp_getassocid(so, to)
        }
        return len.wrapping_sub(auio.uio_resid as libc::c_ulong) as ssize_t;
    } else {
        return -1i64;
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_sctp_sendmbuf(
    mut so: *mut socket,
    mut mbufdata: *mut mbuf,
    mut len: size_t,
    mut to: *mut sockaddr,
    mut tolen: socklen_t,
    mut ppid: u_int32_t,
    mut flags: u_int32_t,
    mut stream_no: u_int16_t,
    mut timetolive: u_int32_t,
    mut context: u_int32_t,
) -> ssize_t {
    let mut sndrcvinfo = sctp_sndrcvinfo {
        sinfo_stream: 0,
        sinfo_ssn: 0,
        sinfo_flags: 0,
        sinfo_ppid: 0,
        sinfo_context: 0,
        sinfo_timetolive: 0,
        sinfo_tsn: 0,
        sinfo_cumtsn: 0,
        sinfo_assoc_id: 0,
        sinfo_keynumber: 0,
        sinfo_keynumber_valid: 0,
        __reserve_pad: [0; 92],
    };
    let mut error = 0i32;
    let mut retval = 0;
    let mut sinfo = &mut sndrcvinfo;
    /*    struct uio auio;
    struct iovec iov[1]; */

    (*sinfo).sinfo_ppid = ppid;
    (*sinfo).sinfo_flags = flags as uint16_t;
    (*sinfo).sinfo_stream = stream_no;
    (*sinfo).sinfo_timetolive = timetolive;
    (*sinfo).sinfo_context = context;
    (*sinfo).sinfo_assoc_id = 0u32;
    /* Perform error checks on destination (to) */
    if tolen > 255u32 {
        error = 36i32
    } else if tolen < 2u32 {
        error = 22i32
    } else {
        /* Adding the following as part of defensive programming, in case the application
        does not do it when preparing the destination address.*/
        let mut uflags = 0i32;
        error = sctp_lower_sosend(
            so,
            to,
            0 as *mut uio,
            mbufdata,
            0 as *mut mbuf,
            uflags,
            sinfo,
        )
    }
    /* TODO: Needs a condition for non-blocking when error is EWOULDBLOCK */
    if 0i32 == error {
        retval = len as ssize_t
    } else if error == 11i32 {
        *__errno_location() = 11i32;
        retval = -1i64
    } else {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%s: error = %d\n\x00" as *const u8 as *const libc::c_char,
                (*::std::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"userspace_sctp_sendmbuf\x00",
                ))
                .as_ptr(),
                error,
            );
        }
        *__errno_location() = error;
        retval = -1i64
    }
    return retval;
}
/* taken from usr.lib/sctp_sys_calls.c and needed here */
/* Taken from  /src/lib/libc/net/sctp_sys_calls.c
 * and modified for __Userspace__
 * calling sctp_generic_recvmsg from this function
 */
#[no_mangle]
pub unsafe extern "C" fn userspace_sctp_recvmsg(
    mut so: *mut socket,
    mut dbuf: *mut libc::c_void,
    mut len: size_t,
    mut from: *mut sockaddr,
    mut fromlenp: *mut socklen_t,
    mut sinfo: *mut sctp_sndrcvinfo,
    mut msg_flags: *mut libc::c_int,
) -> ssize_t {
    let mut iov = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 2];
    let mut tiov = 0 as *mut iovec;
    let mut iovlen = 1i32;
    let mut error = 0i32;
    let mut ulen = 0;
    let mut i = 0;
    let mut fromlen = 0;
    let mut auio = uio {
        uio_iov: 0 as *mut iovec,
        uio_iovcnt: 0,
        uio_offset: 0,
        uio_resid: 0,
        uio_segflg: UIO_USERSPACE,
        uio_rw: UIO_READ,
    }; /* XXX */

    iov[0usize].iov_base = dbuf;
    iov[0usize].iov_len = len;
    auio.uio_iov = iov.as_mut_ptr();
    auio.uio_iovcnt = iovlen;
    auio.uio_segflg = UIO_USERSPACE;
    auio.uio_rw = UIO_READ;
    auio.uio_offset = 0i64;
    auio.uio_resid = 0i64;
    tiov = iov.as_mut_ptr();
    i = 0i32;
    while i < iovlen {
        auio.uio_resid = (auio.uio_resid as libc::c_ulong).wrapping_add((*tiov).iov_len) as ssize_t;
        if auio.uio_resid < 0i64 {
            error = 22i32;
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"%s: error = %d\n\x00" as *const u8 as *const libc::c_char,
                    (*::std::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"userspace_sctp_recvmsg\x00",
                    ))
                    .as_ptr(),
                    error,
                );
            }
            return -1i64;
        }
        i += 1;
        tiov = tiov.offset(1)
    }
    ulen = auio.uio_resid;
    if !fromlenp.is_null() {
        fromlen = *fromlenp
    } else {
        fromlen = 0u32
    }
    error = sctp_sorecvmsg(
        so,
        &mut auio,
        0 as *mut *mut mbuf,
        from,
        fromlen as libc::c_int,
        msg_flags,
        sinfo,
        1i32,
    );
    if error != 0 {
        if auio.uio_resid != ulen && (error == 4i32 || error == 85i32 || error == 11i32) {
            error = 0i32
        }
    }
    if !fromlenp.is_null() && fromlen > 0u32 && !from.is_null() {
        match (*from).sa_family as libc::c_int {
            2 => *fromlenp = ::std::mem::size_of::<sockaddr_in>() as socklen_t,
            10 => *fromlenp = ::std::mem::size_of::<sockaddr_in6>() as socklen_t,
            123 => *fromlenp = ::std::mem::size_of::<sockaddr_conn>() as socklen_t,
            _ => *fromlenp = 0u32,
        }
        if *fromlenp > fromlen {
            *fromlenp = fromlen
        }
    }
    if error == 0i32 {
        /* ready return value */
        return ulen - auio.uio_resid;
    } else {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"%s: error = %d\n\x00" as *const u8 as *const libc::c_char,
                (*::std::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"userspace_sctp_recvmsg\x00",
                ))
                .as_ptr(),
                error,
            ); /* XXX */
        }
        return -1i64;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_recvv(
    mut so: *mut socket,
    mut dbuf: *mut libc::c_void,
    mut len: size_t,
    mut from: *mut sockaddr,
    mut fromlenp: *mut socklen_t,
    mut info: *mut libc::c_void,
    mut infolen: *mut socklen_t,
    mut infotype: *mut libc::c_uint,
    mut msg_flags: *mut libc::c_int,
) -> ssize_t {
    let mut iov = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 2];
    let mut tiov = 0 as *mut iovec;
    let mut iovlen = 1i32;
    let mut ulen = 0;
    let mut i = 0;
    let mut fromlen = 0;
    let mut seinfo = sctp_extrcvinfo {
        sinfo_stream: 0,
        sinfo_ssn: 0,
        sinfo_flags: 0,
        sinfo_ppid: 0,
        sinfo_context: 0,
        sinfo_timetolive: 0,
        sinfo_tsn: 0,
        sinfo_cumtsn: 0,
        sinfo_assoc_id: 0,
        serinfo_next_flags: 0,
        serinfo_next_stream: 0,
        serinfo_next_aid: 0,
        serinfo_next_length: 0,
        serinfo_next_ppid: 0,
        sinfo_keynumber: 0,
        sinfo_keynumber_valid: 0,
        __reserve_pad: [0; 76],
    };
    let mut auio = uio {
        uio_iov: 0 as *mut iovec,
        uio_iovcnt: 0,
        uio_offset: 0,
        uio_resid: 0,
        uio_segflg: UIO_USERSPACE,
        uio_rw: UIO_READ,
    };

    if so.is_null() {
        *__errno_location() = 9i32;
        return -1i64;
    }
    iov[0usize].iov_base = dbuf;
    iov[0usize].iov_len = len;
    auio.uio_iov = iov.as_mut_ptr();
    auio.uio_iovcnt = iovlen;
    auio.uio_segflg = UIO_USERSPACE;
    auio.uio_rw = UIO_READ;
    auio.uio_offset = 0i64;
    auio.uio_resid = 0i64;
    tiov = iov.as_mut_ptr();
    i = 0i32;
    while i < iovlen {
        auio.uio_resid = (auio.uio_resid as libc::c_ulong).wrapping_add((*tiov).iov_len) as ssize_t;
        if auio.uio_resid < 0i64 {
            *__errno_location() = 22i32;
            return -1i64;
        }
        i += 1;
        tiov = tiov.offset(1)
    }
    ulen = auio.uio_resid;
    if !fromlenp.is_null() {
        fromlen = *fromlenp
    } else {
        fromlen = 0u32
    }
    *__errno_location() = sctp_sorecvmsg(
        so,
        &mut auio,
        0 as *mut *mut mbuf,
        from,
        fromlen as libc::c_int,
        msg_flags,
        &mut seinfo as *mut sctp_extrcvinfo as *mut sctp_sndrcvinfo,
        1i32,
    );
    if *__errno_location() != 0 {
        if auio.uio_resid != ulen
            && (*__errno_location() == 4i32
                || *__errno_location() == 85i32
                || *__errno_location() == 11i32)
        {
            *__errno_location() = 0i32
        }
    }
    if !(*__errno_location() != 0i32) {
        if *msg_flags & 0x2000i32 == 0i32 {
            let mut inp = 0 as *mut sctp_inpcb;
            inp = (*so).so_pcb as *mut sctp_inpcb;
            if (*inp).sctp_features & 0x10000000u64 == 0x10000000u64
                && (*inp).sctp_features & 0x8000000u64 == 0x8000000u64
                && *infolen >= ::std::mem::size_of::<sctp_recvv_rn>() as socklen_t
                && seinfo.serinfo_next_flags as libc::c_int & 0x1i32 != 0
            {
                let mut rn = 0 as *mut sctp_recvv_rn;
                rn = info as *mut sctp_recvv_rn;
                (*rn).recvv_rcvinfo.rcv_sid = seinfo.sinfo_stream;
                (*rn).recvv_rcvinfo.rcv_ssn = seinfo.sinfo_ssn;
                (*rn).recvv_rcvinfo.rcv_flags = seinfo.sinfo_flags;
                (*rn).recvv_rcvinfo.rcv_ppid = seinfo.sinfo_ppid;
                (*rn).recvv_rcvinfo.rcv_context = seinfo.sinfo_context;
                (*rn).recvv_rcvinfo.rcv_tsn = seinfo.sinfo_tsn;
                (*rn).recvv_rcvinfo.rcv_cumtsn = seinfo.sinfo_cumtsn;
                (*rn).recvv_rcvinfo.rcv_assoc_id = seinfo.sinfo_assoc_id;
                (*rn).recvv_nxtinfo.nxt_sid = seinfo.serinfo_next_stream;
                (*rn).recvv_nxtinfo.nxt_flags = 0u16;
                if seinfo.serinfo_next_flags as libc::c_int & 0x4i32 != 0 {
                    (*rn).recvv_nxtinfo.nxt_flags =
                        ((*rn).recvv_nxtinfo.nxt_flags as libc::c_int | 0x400i32) as uint16_t
                }
                if seinfo.serinfo_next_flags as libc::c_int & 0x8i32 != 0 {
                    (*rn).recvv_nxtinfo.nxt_flags =
                        ((*rn).recvv_nxtinfo.nxt_flags as libc::c_int | 0x10i32) as uint16_t
                }
                if seinfo.serinfo_next_flags as libc::c_int & 0x2i32 != 0 {
                    (*rn).recvv_nxtinfo.nxt_flags =
                        ((*rn).recvv_nxtinfo.nxt_flags as libc::c_int | 0x20i32) as uint16_t
                }
                (*rn).recvv_nxtinfo.nxt_ppid = seinfo.serinfo_next_ppid;
                (*rn).recvv_nxtinfo.nxt_length = seinfo.serinfo_next_length;
                (*rn).recvv_nxtinfo.nxt_assoc_id = seinfo.serinfo_next_aid;
                *infolen = ::std::mem::size_of::<sctp_recvv_rn>() as socklen_t;
                *infotype = 3u32
            } else if (*inp).sctp_features & 0x8000000u64 == 0x8000000u64
                && *infolen >= ::std::mem::size_of::<sctp_rcvinfo>() as socklen_t
            {
                let mut rcv = 0 as *mut sctp_rcvinfo;
                rcv = info as *mut sctp_rcvinfo;
                (*rcv).rcv_sid = seinfo.sinfo_stream;
                (*rcv).rcv_ssn = seinfo.sinfo_ssn;
                (*rcv).rcv_flags = seinfo.sinfo_flags;
                (*rcv).rcv_ppid = seinfo.sinfo_ppid;
                (*rcv).rcv_context = seinfo.sinfo_context;
                (*rcv).rcv_tsn = seinfo.sinfo_tsn;
                (*rcv).rcv_cumtsn = seinfo.sinfo_cumtsn;
                (*rcv).rcv_assoc_id = seinfo.sinfo_assoc_id;
                *infolen = ::std::mem::size_of::<sctp_rcvinfo>() as socklen_t;
                *infotype = 1u32
            } else {
                *infotype = 0u32;
                *infolen = 0u32
            }
        }
        if !fromlenp.is_null() && fromlen > 0u32 && !from.is_null() && ulen > auio.uio_resid {
            match (*from).sa_family as libc::c_int {
                2 => *fromlenp = ::std::mem::size_of::<sockaddr_in>() as socklen_t,
                10 => *fromlenp = ::std::mem::size_of::<sockaddr_in6>() as socklen_t,
                123 => *fromlenp = ::std::mem::size_of::<sockaddr_conn>() as socklen_t,
                _ => *fromlenp = 0u32,
            }
            if *fromlenp > fromlen {
                *fromlenp = fromlen
            }
        }
    }
    if *__errno_location() == 0i32 {
        /* ready return value */
        return ulen - auio.uio_resid;
    } else {
        return -1i64;
    };
}
/* Taken from  /src/sys/kern/uipc_socket.c
 * and modified for __Userspace__
 * socreate returns a socket.  The socket should be
 * closed with soclose().
 */
#[no_mangle]
pub unsafe extern "C" fn socreate(
    mut dom: libc::c_int,
    mut aso: *mut *mut socket,
    mut type_0: libc::c_int,
    mut proto: libc::c_int,
) -> libc::c_int {
    let mut so = 0 as *mut socket;
    let mut error = 0;
    if dom != 123i32 && dom != 2i32 && dom != 10i32 {
        return 22i32;
    }
    if type_0 != SOCK_STREAM as libc::c_int && type_0 != SOCK_SEQPACKET as libc::c_int {
        return 22i32;
    }
    if proto != IPPROTO_SCTP as libc::c_int {
        return 22i32;
    }
    so = soalloc();
    if so.is_null() {
        return 105i32;
    }
    /*
     * so_incomp represents a queue of connections that
     * must be completed at protocol level before being
     * returned. so_comp field heads a list of sockets
     * that are ready to be returned to the listening process
     *__Userspace__ These queues are being used at a number of places like accept etc.
     */
    (*so).so_incomp.tqh_first = 0 as *mut socket;
    (*so).so_incomp.tqh_last = &mut (*so).so_incomp.tqh_first;
    (*so).so_comp.tqh_first = 0 as *mut socket;
    (*so).so_comp.tqh_last = &mut (*so).so_comp.tqh_first;
    (*so).so_type = type_0 as libc::c_short;
    (*so).so_count = 1i32;
    (*so).so_dom = dom;
    /*
     * Auto-sizing of socket buffers is managed by the protocols and
     * the appropriate flags must be set in the pru_attach function.
     * For __Userspace__ The pru_attach function in this case is sctp_attach.
     */
    match dom {
        2 => error = sctp_attach(so, proto, 0u32),
        10 => error = sctp6_attach(so, proto, 0u32),
        123 => error = sctpconn_attach(so, proto, 0u32),
        _ => error = 97i32,
    }
    if error != 0 {
        (*so).so_count = 0i32;
        sodealloc(so);
        return error;
    }
    *aso = so;
    return 0i32;
}
/* Taken from  /src/sys/kern/uipc_syscalls.c
 * and modified for __Userspace__
 * Removing struct thread td.
 */
#[no_mangle]
pub unsafe extern "C" fn userspace_socket(
    mut domain: libc::c_int,
    mut type_0: libc::c_int,
    mut protocol: libc::c_int,
) -> *mut socket {
    let mut so = 0 as *mut socket;
    *__errno_location() = socreate(domain, &mut so, type_0, protocol);
    if *__errno_location() != 0 {
        return 0 as *mut socket;
    }
    /*
     * The original socket call returns the file descriptor fd.
     * td->td_retval[0] = fd.
     * We are returning struct socket *so.
     */
    return so;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_socket(
    mut domain: libc::c_int,
    mut type_0: libc::c_int,
    mut protocol: libc::c_int,
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
    mut send_cb: Option<unsafe extern "C" fn(_: *mut socket, _: uint32_t) -> libc::c_int>,
    mut sb_threshold: uint32_t,
    mut ulp_info: *mut libc::c_void,
) -> *mut socket {
    let mut so = 0 as *mut socket;
    if protocol == IPPROTO_SCTP as libc::c_int
        && system_base_info.sctp_pcb_initialized as libc::c_int == 0i32
    {
        *__errno_location() = 93i32;
        return 0 as *mut socket;
    }
    if receive_cb.is_none() && (send_cb.is_some() || sb_threshold != 0u32 || !ulp_info.is_null()) {
        *__errno_location() = 22i32;
        return 0 as *mut socket;
    }
    if domain == 123i32 && system_base_info.conn_output.is_none() {
        *__errno_location() = 97i32;
        return 0 as *mut socket;
    }
    *__errno_location() = socreate(domain, &mut so, type_0, protocol);
    if *__errno_location() != 0 {
        return 0 as *mut socket;
    }
    /*
     * The original socket call returns the file descriptor fd.
     * td->td_retval[0] = fd.
     * We are returning struct socket *so.
     */
    register_recv_cb(so, receive_cb);
    register_send_cb(so, sb_threshold, send_cb);
    register_ulp_info(so, ulp_info);
    return so;
}
#[no_mangle]
pub static mut sb_max: u_long = (256i32 * 1024i32) as u_long;
#[no_mangle]
pub static mut sb_max_adj: u_long = (256i32 * 1024i32 * 2048i32 / (256i32 + 2048i32)) as u_long;
/* adjusted sb_max */
static mut sb_efficiency: u_long = 8u64;
/* parameter for sbreserve() */
/*
 * Allot mbufs to a sockbuf.  Attempt to scale mbmax so that mbcnt doesn't
 * become limiting if buffering efficiency is near the normal case.
 */
#[no_mangle]
pub unsafe extern "C" fn sbreserve_locked(
    mut sb: *mut sockbuf,
    mut cc: u_long,
    mut so: *mut socket,
) -> libc::c_int {
    (*sb).sb_mbmax = if cc.wrapping_mul(sb_efficiency) > sb_max {
        sb_max
    } else {
        cc.wrapping_mul(sb_efficiency)
    } as u_int;
    (*sb).sb_hiwat = cc as u_int;
    if (*sb).sb_lowat > (*sb).sb_hiwat as libc::c_int {
        (*sb).sb_lowat = (*sb).sb_hiwat as libc::c_int
    }
    return 1i32;
}
unsafe extern "C" fn sbreserve(
    mut sb: *mut sockbuf,
    mut cc: u_long,
    mut so: *mut socket,
) -> libc::c_int {
    let mut error = 0;
    pthread_mutex_lock(&mut (*sb).sb_mtx);
    error = sbreserve_locked(sb, cc, so);
    pthread_mutex_unlock(&mut (*sb).sb_mtx);
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn soreserve(
    mut so: *mut socket,
    mut sndcc: u_long,
    mut rcvcc: u_long,
) -> libc::c_int {
    pthread_mutex_lock(&mut (*so).so_snd.sb_mtx);
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    (*so).so_snd.sb_hiwat = sndcc as uint32_t;
    (*so).so_rcv.sb_hiwat = rcvcc as uint32_t;
    if !(sbreserve_locked(&mut (*so).so_snd, sndcc, so) == 0i32) {
        if !(sbreserve_locked(&mut (*so).so_rcv, rcvcc, so) == 0i32) {
            if (*so).so_rcv.sb_lowat == 0i32 {
                (*so).so_rcv.sb_lowat = 1i32
            }
            if (*so).so_snd.sb_lowat == 0i32 {
                (*so).so_snd.sb_lowat = 2048i32
            }
            if (*so).so_snd.sb_lowat > (*so).so_snd.sb_hiwat as libc::c_int {
                (*so).so_snd.sb_lowat = (*so).so_snd.sb_hiwat as libc::c_int
            }
            pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
            pthread_mutex_unlock(&mut (*so).so_snd.sb_mtx);
            return 0i32;
        }
    }
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    pthread_mutex_unlock(&mut (*so).so_snd.sb_mtx);
    return 105i32;
}
/* kernel version for reference */
/* Taken from  /src/sys/kern/uipc_sockbuf.c
 * and modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn sowakeup(mut so: *mut socket, mut sb: *mut sockbuf) {
    (*sb).sb_flags = ((*sb).sb_flags as libc::c_int & !(0x8i32)) as libc::c_short;
    if (*sb).sb_flags as libc::c_int & 0x4i32 != 0 {
        (*sb).sb_flags = ((*sb).sb_flags as libc::c_int & !(0x4i32)) as libc::c_short;
        pthread_cond_broadcast(&mut (*sb).sb_cond);
    }
    pthread_mutex_unlock(&mut (*sb).sb_mtx);
}
/* kernel version for reference */
/* Taken from  /src/sys/kern/uipc_socket.c
 * and modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn sobind(mut so: *mut socket, mut nam: *mut sockaddr) -> libc::c_int {
    match (*nam).sa_family as libc::c_int {
        2 => return sctp_bind(so, nam),
        10 => return sctp6_bind(so, nam, 0 as *mut libc::c_void),
        123 => return sctpconn_bind(so, nam),
        _ => return 97i32,
    };
}
/* Taken from  /src/sys/kern/uipc_syscalls.c
 * and modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn usrsctp_bind(
    mut so: *mut socket,
    mut name: *mut sockaddr,
    mut namelen: libc::c_int,
) -> libc::c_int {
    let mut sa = 0 as *mut sockaddr;
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    let ref mut fresh0 = *__errno_location();
    *fresh0 = getsockaddr(&mut sa, name as caddr_t, namelen as size_t);
    if *fresh0 != 0i32 {
        return -(1i32);
    }
    *__errno_location() = sobind(so, sa);
    free(sa as *mut libc::c_void);
    if *__errno_location() != 0 {
        return -(1i32);
    } else {
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_bind(
    mut so: *mut socket,
    mut name: *mut sockaddr,
    mut namelen: libc::c_int,
) -> libc::c_int {
    return usrsctp_bind(so, name, namelen);
}
/* Taken from  /src/sys/kern/uipc_socket.c
 * and modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn solisten(mut so: *mut socket, mut backlog: libc::c_int) -> libc::c_int {
    if so.is_null() {
        return 9i32;
    } else {
        return sctp_listen(so, backlog, 0 as *mut proc_0);
    };
}
#[no_mangle]
pub unsafe extern "C" fn solisten_proto_check(mut so: *mut socket) -> libc::c_int {
    if (*so).so_state as libc::c_int & (0x2i32 | 0x4i32 | 0x8i32) != 0 {
        return 22i32;
    }
    return 0i32;
}
static mut somaxconn: libc::c_int = 128i32;
#[no_mangle]
pub unsafe extern "C" fn solisten_proto(mut so: *mut socket, mut backlog: libc::c_int) {
    if backlog < 0i32 || backlog > somaxconn {
        backlog = somaxconn
    }
    (*so).so_qlimit = backlog as u_short;
    (*so).so_options = ((*so).so_options as libc::c_int | 0x2i32) as libc::c_short;
}
/* Taken from  /src/sys/kern/uipc_syscalls.c
 * and modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn usrsctp_listen(
    mut so: *mut socket,
    mut backlog: libc::c_int,
) -> libc::c_int {
    *__errno_location() = solisten(so, backlog);
    if *__errno_location() != 0 {
        return -(1i32);
    } else {
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_listen(
    mut so: *mut socket,
    mut backlog: libc::c_int,
) -> libc::c_int {
    return usrsctp_listen(so, backlog);
}
/* Taken from  /src/sys/kern/uipc_socket.c
 * and modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn soaccept(mut so: *mut socket, mut nam: *mut *mut sockaddr) -> libc::c_int {
    let mut error = 0;
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    (*so).so_state = ((*so).so_state as libc::c_int & !(0x1i32)) as libc::c_short;
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    error = sctp_accept(so, nam);
    return error;
}
/* Taken from  /src/sys/kern/uipc_syscalls.c
 * kern_accept modified for __Userspace__
 */
#[no_mangle]
pub unsafe extern "C" fn user_accept(
    mut head: *mut socket,
    mut name: *mut *mut sockaddr,
    mut namelen: *mut socklen_t,
    mut ptr_accept_ret_sock: *mut *mut socket,
) -> libc::c_int {
    let mut error = 0;
    let mut so = 0 as *mut socket;
    if !name.is_null() {
        *name = 0 as *mut sockaddr
    }
    if (*head).so_options as libc::c_int & 0x2i32 == 0i32 {
        error = 22i32
    } else {
        let mut current_block: u64;
        let mut sa = 0 as *mut sockaddr;
        pthread_mutex_lock(&mut accept_mtx);
        if (*head).so_state as libc::c_int & 0x100i32 != 0 && (*head).so_comp.tqh_first.is_null() {
            pthread_mutex_unlock(&mut accept_mtx);
            error = 11i32;
            current_block = 17120429816060008152;
        } else {
            loop {
                if !((*head).so_comp.tqh_first.is_null() && (*head).so_error as libc::c_int == 0i32)
                {
                    current_block = 2370887241019905314;
                    break;
                }
                if (*head).so_rcv.sb_state as libc::c_int & 0x20i32 != 0 {
                    (*head).so_error = 103u16;
                    current_block = 2370887241019905314;
                    break;
                } else {
                    error = pthread_cond_wait(&mut accept_cond, &mut accept_mtx);
                    if !(error != 0) {
                        continue;
                    }
                    pthread_mutex_unlock(&mut accept_mtx);
                    current_block = 17120429816060008152;
                    break;
                }
            }
            match current_block {
                17120429816060008152 => {}
                _ => {
                    if (*head).so_error != 0 {
                        error = (*head).so_error as libc::c_int;
                        (*head).so_error = 0u16;
                        pthread_mutex_unlock(&mut accept_mtx);
                        current_block = 17120429816060008152;
                    } else {
                        so = (*head).so_comp.tqh_first;
                        /*
                         * Before changing the flags on the socket, we have to bump the
                         * reference count.  Otherwise, if the protocol calls sofree(),
                         * the socket will be released due to a zero refcount.
                         */
                        pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx); /* soref() and so_state update */
                        (*so).so_count += 1; /* file descriptor reference */
                        if !(*so).so_list.tqe_next.is_null() {
                            (*(*so).so_list.tqe_next).so_list.tqe_prev = (*so).so_list.tqe_prev
                        } else {
                            (*head).so_comp.tqh_last = (*so).so_list.tqe_prev
                        }
                        *(*so).so_list.tqe_prev = (*so).so_list.tqe_next;
                        (*head).so_qlen = (*head).so_qlen.wrapping_sub(1);
                        (*so).so_state = ((*so).so_state as libc::c_int
                            | (*head).so_state as libc::c_int & 0x100i32)
                            as libc::c_short;
                        (*so).so_qstate &= !(0x1000i32);
                        (*so).so_head = 0 as *mut socket;
                        pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
                        pthread_mutex_unlock(&mut accept_mtx);
                        /*
                         * The original accept returns fd value via td->td_retval[0] = fd;
                         * we will return the socket for accepted connection.
                         */
                        error = soaccept(so, &mut sa);
                        if error != 0 {
                            /*
                             * return a namelen of zero for older code which might
                             * ignore the return value from accept.
                             */
                            if !name.is_null() {
                                *namelen = 0u32
                            }
                            current_block = 17120429816060008152;
                        } else if sa.is_null() {
                            if !name.is_null() {
                                *namelen = 0u32
                            }
                            current_block = 14695010454872034025;
                        } else {
                            if !name.is_null() {
                                let mut sa_len = 0;
                                match (*sa).sa_family as libc::c_int {
                                    2 => sa_len = ::std::mem::size_of::<sockaddr_in>() as socklen_t,
                                    10 => {
                                        sa_len = ::std::mem::size_of::<sockaddr_in6>() as socklen_t
                                    }
                                    123 => {
                                        sa_len = ::std::mem::size_of::<sockaddr_conn>() as socklen_t
                                    }
                                    _ => sa_len = 0u32,
                                }
                                if *namelen > sa_len {
                                    *namelen = sa_len
                                }
                                *name = sa;
                                sa = 0 as *mut sockaddr
                            }
                            current_block = 17120429816060008152;
                        }
                    }
                }
            }
        }
        match current_block {
            14695010454872034025 => {}
            _ => {
                if !sa.is_null() {
                    free(sa as *mut libc::c_void);
                }
            }
        }
    }
    *ptr_accept_ret_sock = so;
    return error;
}
/* Taken from  /src/sys/kern/uipc_syscalls.c
 * and modified for __Userspace__
 */
/*
 * accept1()
 */
unsafe extern "C" fn accept1(
    mut so: *mut socket,
    mut aname: *mut sockaddr,
    mut anamelen: *mut socklen_t,
    mut ptr_accept_ret_sock: *mut *mut socket,
) -> libc::c_int {
    let mut name = 0 as *mut sockaddr;
    let mut namelen = 0;
    let mut error = 0;
    if so.is_null() {
        return 9i32;
    }
    if aname.is_null() {
        return user_accept(
            so,
            0 as *mut *mut sockaddr,
            0 as *mut socklen_t,
            ptr_accept_ret_sock,
        );
    }
    error = copy_from_user(
        &mut namelen as *mut socklen_t as *mut libc::c_void,
        anamelen as *mut libc::c_void,
        ::std::mem::size_of::<socklen_t>() as libc::c_ulong,
    );
    if error != 0 {
        return error;
    }
    error = user_accept(so, &mut name, &mut namelen, ptr_accept_ret_sock);
    /*
     * return a namelen of zero for older code which might
     * ignore the return value from accept.
     */
    if error != 0 {
        copy_to_user(
            anamelen as *mut libc::c_void,
            &mut namelen as *mut socklen_t as *mut libc::c_void,
            ::std::mem::size_of::<socklen_t>() as libc::c_ulong,
        );
        return error;
    }
    if error == 0i32 && !name.is_null() {
        error = copy_to_user(
            aname as *mut libc::c_void,
            name as *mut libc::c_void,
            namelen as size_t,
        )
    }
    if error == 0i32 {
        error = copy_to_user(
            anamelen as *mut libc::c_void,
            &mut namelen as *mut socklen_t as *mut libc::c_void,
            ::std::mem::size_of::<socklen_t>() as libc::c_ulong,
        )
    }
    if !name.is_null() {
        free(name as *mut libc::c_void);
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_accept(
    mut so: *mut socket,
    mut aname: *mut sockaddr,
    mut anamelen: *mut socklen_t,
) -> *mut socket {
    let mut accept_return_sock = 0 as *mut socket;
    *__errno_location() = accept1(so, aname, anamelen, &mut accept_return_sock);
    if *__errno_location() != 0 {
        return 0 as *mut socket;
    } else {
        return accept_return_sock;
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_accept(
    mut so: *mut socket,
    mut aname: *mut sockaddr,
    mut anamelen: *mut socklen_t,
) -> *mut socket {
    return usrsctp_accept(so, aname, anamelen);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_peeloff(
    mut head: *mut socket,
    mut id: sctp_assoc_t,
) -> *mut socket {
    let mut so = 0 as *mut socket;
    let ref mut fresh1 = *__errno_location();
    *fresh1 = sctp_can_peel_off(head, id);
    if *fresh1 != 0i32 {
        return 0 as *mut socket;
    }
    so = sonewconn(head, 0x2i32);
    if so.is_null() {
        return 0 as *mut socket;
    }
    pthread_mutex_lock(&mut accept_mtx);
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    (*so).so_count += 1;
    if !(*so).so_list.tqe_next.is_null() {
        (*(*so).so_list.tqe_next).so_list.tqe_prev = (*so).so_list.tqe_prev
    } else {
        (*head).so_comp.tqh_last = (*so).so_list.tqe_prev
    }
    *(*so).so_list.tqe_prev = (*so).so_list.tqe_next;
    (*head).so_qlen = (*head).so_qlen.wrapping_sub(1);
    (*so).so_state = ((*so).so_state as libc::c_int | (*head).so_state as libc::c_int & 0x100i32)
        as libc::c_short;
    (*so).so_qstate &= !(0x1000i32);
    (*so).so_head = 0 as *mut socket;
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    pthread_mutex_unlock(&mut accept_mtx);
    let ref mut fresh2 = *__errno_location();
    *fresh2 = sctp_do_peeloff(head, so, id);
    if *fresh2 != 0i32 {
        (*so).so_count = 0i32;
        sodealloc(so);
        return 0 as *mut socket;
    }
    return so;
}
#[no_mangle]
pub unsafe extern "C" fn sodisconnect(mut so: *mut socket) -> libc::c_int {
    let mut error = 0;
    if (*so).so_state as libc::c_int & 0x2i32 == 0i32 {
        return 107i32;
    }
    if (*so).so_state as libc::c_int & 0x8i32 != 0 {
        return 114i32;
    }
    error = sctp_disconnect(so);
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_set_non_blocking(
    mut so: *mut socket,
    mut onoff: libc::c_int,
) -> libc::c_int {
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    if onoff != 0i32 {
        (*so).so_state = ((*so).so_state as libc::c_int | 0x100i32) as libc::c_short
    } else {
        (*so).so_state = ((*so).so_state as libc::c_int & !(0x100i32)) as libc::c_short
    }
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_get_non_blocking(mut so: *mut socket) -> libc::c_int {
    let mut result = 0;
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    if (*so).so_state as libc::c_int & 0x100i32 != 0 {
        result = 1i32
    } else {
        result = 0i32
    }
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    return result;
}
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
pub unsafe extern "C" fn soconnect(mut so: *mut socket, mut nam: *mut sockaddr) -> libc::c_int {
    let mut error = 0;
    if (*so).so_options as libc::c_int & 0x2i32 != 0 {
        return 95i32;
    }
    /*
     * If protocol is connection-based, can only connect once.
     * Otherwise, if connected, try to disconnect first.  This allows
     * user to disconnect by connecting to, e.g., a null address.
     */
    if (*so).so_state as libc::c_int & (0x2i32 | 0x4i32) != 0 && {
        error = sodisconnect(so);
        (error) != 0
    } {
        error = 106i32
    } else {
        /*
         * Prevent accumulated error from previous connection from
         * biting us.
         */
        (*so).so_error = 0u16;
        match (*nam).sa_family as libc::c_int {
            2 => error = sctp_connect(so, nam),
            10 => error = sctp6_connect(so, nam),
            123 => error = sctpconn_connect(so, nam),
            _ => error = 97i32,
        }
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn user_connect(mut so: *mut socket, mut sa: *mut sockaddr) -> libc::c_int {
    let mut error = 0;
    if so.is_null() {
        error = 9i32
    } else if (*so).so_state as libc::c_int & 0x4i32 != 0 {
        error = 114i32
    } else {
        let mut current_block: u64;
        let mut interrupted = 0i32;
        error = soconnect(so, sa);
        if error != 0 {
            current_block = 13737779130977851289;
        } else if (*so).so_state as libc::c_int & 0x100i32 != 0
            && (*so).so_state as libc::c_int & 0x4i32 != 0
        {
            error = 115i32;
            current_block = 8197461698413576138;
        } else {
            pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
            while (*so).so_state as libc::c_int & 0x4i32 != 0
                && (*so).so_error as libc::c_int == 0i32
            {
                error = pthread_cond_wait(&mut (*so).timeo_cond, &mut (*so).so_rcv.sb_mtx);
                if !(error != 0) {
                    continue;
                }
                if error == 4i32 || error == 85i32 {
                    interrupted = 1i32
                }
                break;
            }
            if error == 0i32 {
                error = (*so).so_error as libc::c_int;
                (*so).so_error = 0u16
            }
            pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
            current_block = 13737779130977851289;
        }
        match current_block {
            8197461698413576138 => {}
            _ => {
                if interrupted == 0 {
                    (*so).so_state = ((*so).so_state as libc::c_int & !(0x4i32)) as libc::c_short
                }
                if error == 85i32 {
                    error = 4i32
                }
            }
        }
    }
    return error;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_connect(
    mut so: *mut socket,
    mut name: *mut sockaddr,
    mut namelen: libc::c_int,
) -> libc::c_int {
    let mut sa = 0 as *mut sockaddr;
    *__errno_location() = getsockaddr(&mut sa, name as caddr_t, namelen as size_t);
    if *__errno_location() != 0 {
        return -(1i32);
    }
    *__errno_location() = user_connect(so, sa);
    free(sa as *mut libc::c_void);
    if *__errno_location() != 0 {
        return -(1i32);
    } else {
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_connect(
    mut so: *mut socket,
    mut name: *mut sockaddr,
    mut namelen: libc::c_int,
) -> libc::c_int {
    return usrsctp_connect(so, name, namelen);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_close(mut so: *mut socket) {
    if !so.is_null() {
        if (*so).so_options as libc::c_int & 0x2i32 != 0 {
            pthread_mutex_lock(&mut accept_mtx);
            loop {
                let mut sp = 0 as *mut socket;
                sp = (*so).so_comp.tqh_first;
                if sp.is_null() {
                    break;
                }
                if !(*sp).so_list.tqe_next.is_null() {
                    (*(*sp).so_list.tqe_next).so_list.tqe_prev = (*sp).so_list.tqe_prev
                } else {
                    (*so).so_comp.tqh_last = (*sp).so_list.tqe_prev
                }
                *(*sp).so_list.tqe_prev = (*sp).so_list.tqe_next;
                (*so).so_qlen = (*so).so_qlen.wrapping_sub(1);
                (*sp).so_qstate &= !(0x1000i32);
                (*sp).so_head = 0 as *mut socket;
                pthread_mutex_unlock(&mut accept_mtx);
                soabort(sp);
                pthread_mutex_lock(&mut accept_mtx);
            }
            pthread_mutex_unlock(&mut accept_mtx);
        }
        pthread_mutex_lock(&mut accept_mtx);
        pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
        (*so).so_count -= 1;
        if (*so).so_count == 0i32 {
            sofree(so);
        } else {
            pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
            pthread_mutex_unlock(&mut accept_mtx);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_close(mut so: *mut socket) {
    usrsctp_close(so);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_shutdown(
    mut so: *mut socket,
    mut how: libc::c_int,
) -> libc::c_int {
    if !(how == SHUT_RD as libc::c_int
        || how == SHUT_WR as libc::c_int
        || how == SHUT_RDWR as libc::c_int)
    {
        *__errno_location() = 22i32;
        return -(1i32);
    }
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    sctp_flush(so, how);
    if how != SHUT_WR as libc::c_int {
        socantrcvmore(so);
    }
    if how != SHUT_RD as libc::c_int {
        *__errno_location() = sctp_shutdown(so);
        if *__errno_location() != 0 {
            return -(1i32);
        } else {
            return 0i32;
        }
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn userspace_shutdown(
    mut so: *mut socket,
    mut how: libc::c_int,
) -> libc::c_int {
    return usrsctp_shutdown(so, how);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_finish() -> libc::c_int {
    if system_base_info.sctp_pcb_initialized as libc::c_int == 0i32 {
        return 0i32;
    }
    if pthread_mutex_trylock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx) == 0 {
        if !system_base_info.sctppcbinfo.listhead.lh_first.is_null() {
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
            return -(1i32);
        }
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_ep_mtx);
    } else {
        return -(1i32);
    }
    sctp_finish();
    pthread_cond_destroy(&mut accept_cond);
    pthread_mutex_destroy(&mut accept_mtx);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn userspace_finish() -> libc::c_int {
    return usrsctp_finish();
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_setsockopt(
    mut so: *mut socket,
    mut level: libc::c_int,
    mut option_name: libc::c_int,
    mut option_value: *const libc::c_void,
    mut option_len: socklen_t,
) -> libc::c_int {
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    match level {
        1 => match option_name {
            8 => {
                if option_len < ::std::mem::size_of::<libc::c_int>() as socklen_t {
                    *__errno_location() = 22i32;
                    return -(1i32);
                } else {
                    let mut buf_size = 0 as *mut libc::c_int;
                    buf_size = option_value as *mut libc::c_int;
                    if *buf_size < 1i32 {
                        *__errno_location() = 22i32;
                        return -(1i32);
                    }
                    sbreserve(&mut (*so).so_rcv, *buf_size as u_long, so);
                    return 0i32;
                }
            }
            7 => {
                if option_len < ::std::mem::size_of::<libc::c_int>() as socklen_t {
                    *__errno_location() = 22i32;
                    return -(1i32);
                } else {
                    let mut buf_size_0 = 0 as *mut libc::c_int;
                    buf_size_0 = option_value as *mut libc::c_int;
                    if *buf_size_0 < 1i32 {
                        *__errno_location() = 22i32;
                        return -(1i32);
                    }
                    sbreserve(&mut (*so).so_snd, *buf_size_0 as u_long, so);
                    return 0i32;
                }
            }
            13 => {
                if option_len < ::std::mem::size_of::<linger>() as socklen_t {
                    *__errno_location() = 22i32;
                    return -(1i32);
                } else {
                    let mut l = 0 as *mut linger;
                    l = option_value as *mut linger;
                    (*so).so_linger = (*l).l_linger as libc::c_short;
                    if (*l).l_onoff != 0 {
                        (*so).so_options =
                            ((*so).so_options as libc::c_int | 0x1i32) as libc::c_short
                    } else {
                        (*so).so_options =
                            ((*so).so_options as libc::c_int & !(0x1i32)) as libc::c_short
                    }
                    return 0i32;
                }
            }
            _ => {
                *__errno_location() = 22i32;
                return -(1i32);
            }
        },
        132 => {
            *__errno_location() = sctp_setopt(
                so,
                option_name,
                option_value as *mut libc::c_void,
                option_len as size_t,
                0 as *mut libc::c_void,
            );
            if *__errno_location() != 0 {
                return -(1i32);
            } else {
                return 0i32;
            }
        }
        _ => {
            *__errno_location() = 92i32;
            return -(1i32);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_setsockopt(
    mut so: *mut socket,
    mut level: libc::c_int,
    mut option_name: libc::c_int,
    mut option_value: *const libc::c_void,
    mut option_len: socklen_t,
) -> libc::c_int {
    return usrsctp_setsockopt(so, level, option_name, option_value, option_len);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_getsockopt(
    mut so: *mut socket,
    mut level: libc::c_int,
    mut option_name: libc::c_int,
    mut option_value: *mut libc::c_void,
    mut option_len: *mut socklen_t,
) -> libc::c_int {
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    if option_len.is_null() {
        *__errno_location() = 14i32;
        return -(1i32);
    }
    match level {
        1 => match option_name {
            8 => {
                if *option_len < ::std::mem::size_of::<libc::c_int>() as socklen_t {
                    *__errno_location() = 22i32;
                    return -(1i32);
                } else {
                    let mut buf_size = 0 as *mut libc::c_int;
                    buf_size = option_value as *mut libc::c_int;
                    *buf_size = (*so).so_rcv.sb_hiwat as libc::c_int;
                    *option_len = ::std::mem::size_of::<libc::c_int>() as socklen_t;
                    return 0i32;
                }
            }
            7 => {
                if *option_len < ::std::mem::size_of::<libc::c_int>() as socklen_t {
                    *__errno_location() = 22i32;
                    return -(1i32);
                } else {
                    let mut buf_size_0 = 0 as *mut libc::c_int;
                    buf_size_0 = option_value as *mut libc::c_int;
                    *buf_size_0 = (*so).so_snd.sb_hiwat as libc::c_int;
                    *option_len = ::std::mem::size_of::<libc::c_int>() as socklen_t;
                    return 0i32;
                }
            }
            13 => {
                if *option_len < ::std::mem::size_of::<linger>() as socklen_t {
                    *__errno_location() = 22i32;
                    return -(1i32);
                } else {
                    let mut l = 0 as *mut linger;
                    l = option_value as *mut linger;
                    (*l).l_linger = (*so).so_linger as libc::c_int;
                    if (*so).so_options as libc::c_int & 0x1i32 != 0 {
                        (*l).l_onoff = 1i32
                    } else {
                        (*l).l_onoff = 0i32
                    }
                    *option_len = ::std::mem::size_of::<linger>() as socklen_t;
                    return 0i32;
                }
            }
            4 => {
                if *option_len < ::std::mem::size_of::<libc::c_int>() as socklen_t {
                    *__errno_location() = 22i32;
                    return -(1i32);
                } else {
                    let mut intval = 0 as *mut libc::c_int;
                    intval = option_value as *mut libc::c_int;
                    *intval = (*so).so_error as libc::c_int;
                    *option_len = ::std::mem::size_of::<libc::c_int>() as socklen_t;
                    return 0i32;
                }
            }
            _ => {
                *__errno_location() = 22i32;
                return -(1i32);
            }
        },
        132 => {
            let mut len = 0;
            len = *option_len as size_t;
            *__errno_location() = sctp_getopt(
                so,
                option_name,
                option_value,
                &mut len,
                0 as *mut libc::c_void,
            );
            *option_len = len as socklen_t;
            if *__errno_location() != 0 {
                return -(1i32);
            } else {
                return 0i32;
            }
        }
        _ => {
            *__errno_location() = 92i32;
            return -(1i32);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn userspace_getsockopt(
    mut so: *mut socket,
    mut level: libc::c_int,
    mut option_name: libc::c_int,
    mut option_value: *mut libc::c_void,
    mut option_len: *mut socklen_t,
) -> libc::c_int {
    return usrsctp_getsockopt(so, level, option_name, option_value, option_len);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_opt_info(
    mut so: *mut socket,
    mut id: sctp_assoc_t,
    mut opt: libc::c_int,
    mut arg: *mut libc::c_void,
    mut size: *mut socklen_t,
) -> libc::c_int {
    if arg.is_null() {
        *__errno_location() = 22i32;
        return -(1i32);
    }
    if id == 1u32 || id == 2u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    }
    match opt {
        1 => (*(arg as *mut sctp_rtoinfo)).srto_assoc_id = id,
        2 => (*(arg as *mut sctp_assocparams)).sasoc_assoc_id = id,
        11 => (*(arg as *mut sctp_assocparams)).sasoc_assoc_id = id,
        7 => (*(arg as *mut sctp_setprim)).ssp_assoc_id = id,
        10 => (*(arg as *mut sctp_paddrparams)).spp_assoc_id = id,
        14 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        19 => (*(arg as *mut sctp_authkey)).sca_assoc_id = id,
        21 => (*(arg as *mut sctp_authkeyid)).scact_assoc_id = id,
        15 => (*(arg as *mut sctp_sack_info)).sack_assoc_id = id,
        26 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        256 => (*(arg as *mut sctp_status)).sstat_assoc_id = id,
        257 => (*(arg as *mut sctp_paddrinfo)).spinfo_assoc_id = id,
        258 => (*(arg as *mut sctp_authchunks)).gauth_assoc_id = id,
        259 => (*(arg as *mut sctp_authchunks)).gauth_assoc_id = id,
        262 => (*(arg as *mut sctp_timeouts)).stimo_assoc_id = id,
        30 => (*(arg as *mut sctp_event)).se_assoc_id = id,
        33 => (*(arg as *mut sctp_sndinfo)).snd_assoc_id = id,
        34 => (*(arg as *mut sctp_default_prinfo)).pr_assoc_id = id,
        35 => (*(arg as *mut sctp_paddrthlds)).spt_assoc_id = id,
        36 => (*(arg as *mut sctp_udpencaps)).sue_assoc_id = id,
        37 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        38 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        39 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        40 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        41 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        48 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        49 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        25 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        2304 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        263 => (*(arg as *mut sctp_prstatus)).sprstat_assoc_id = id,
        264 => (*(arg as *mut sctp_prstatus)).sprstat_assoc_id = id,
        50 => (*(arg as *mut sctp_assoc_value)).assoc_id = id,
        _ => {}
    }
    return usrsctp_getsockopt(so, IPPROTO_SCTP as libc::c_int, opt, arg, size);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_set_ulpinfo(
    mut so: *mut socket,
    mut ulp_info: *mut libc::c_void,
) -> libc::c_int {
    return register_ulp_info(so, ulp_info);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_bindx(
    mut so: *mut socket,
    mut addrs: *mut sockaddr,
    mut addrcnt: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut gaddrs = 0 as *mut sctp_getaddresses;
    let mut sa = 0 as *mut sockaddr;
    let mut sin = 0 as *mut sockaddr_in;
    let mut sin6 = 0 as *mut sockaddr_in6;
    let mut argsz = 0;
    let mut sport = 0u16;
    /* validate the flags */
    if flags != 0x8001i32 && flags != 0x8002i32 {
        *__errno_location() = 14i32;
        return -(1i32);
    }
    /* validate the address count and list */
    if addrcnt <= 0i32 || addrs.is_null() {
        *__errno_location() = 22i32;
        return -(1i32);
    }
    /* First pre-screen the addresses */
    sa = addrs;

    for i in 0i32..addrcnt {
        match (*sa).sa_family as libc::c_int {
            2 => {
                sin = sa as *mut sockaddr_in;
                if (*sin).sin_port != 0 {
                    /* non-zero port, check or save */
                    if sport != 0 {
                        /* Check against our port */
                        if sport as libc::c_int != (*sin).sin_port as libc::c_int {
                            *__errno_location() = 22i32;
                            return -(1i32);
                        }
                    } else {
                        /* save off the port */
                        sport = (*sin).sin_port
                    }
                }
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_in>() as isize)
                    as *mut sockaddr
            }
            10 => {
                sin6 = sa as *mut sockaddr_in6;
                if (*sin6).sin6_port != 0 {
                    /* non-zero port, check or save */
                    if sport != 0 {
                        /* Check against our port */
                        if sport as libc::c_int != (*sin6).sin6_port as libc::c_int {
                            *__errno_location() = 22i32;
                            return -(1i32);
                        }
                    } else {
                        /* save off the port */
                        sport = (*sin6).sin6_port
                    }
                }
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_in6>() as isize)
                    as *mut sockaddr
            }
            _ => {
                /* Invalid address family specified. */
                *__errno_location() = 97i32;
                return -(1i32);
            }
        }
    }
    argsz = (::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sockaddr_storage>() as libc::c_ulong);
    gaddrs = malloc(argsz) as *mut sctp_getaddresses;
    if gaddrs.is_null() {
        *__errno_location() = 12i32;
        return -(1i32);
    }
    sa = addrs;

    for i in 0i32..addrcnt {
        let mut sa_len = 0;

        memset(gaddrs as *mut libc::c_void, 0i32, argsz);

        (*gaddrs).sget_assoc_id = 0u32;

        match (*sa).sa_family as libc::c_int {
            2 => sa_len = ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
            10 => sa_len = ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            _ => sa_len = 0u64,
        }

        memcpy(
            (*gaddrs).addr.as_mut_ptr() as *mut libc::c_void,
            sa as *const libc::c_void,
            sa_len,
        );

        if i == 0i32 && sport as libc::c_int != 0i32 {
            match (*(*gaddrs).addr.as_mut_ptr()).sa_family as libc::c_int {
                2 => {
                    sin = (*gaddrs).addr.as_mut_ptr() as *mut sockaddr_in;
                    (*sin).sin_port = sport
                }
                10 => {
                    sin6 = (*gaddrs).addr.as_mut_ptr() as *mut sockaddr_in6;
                    (*sin6).sin6_port = sport
                }
                _ => {}
            }
        }

        if usrsctp_setsockopt(
            so,
            IPPROTO_SCTP as libc::c_int,
            flags,
            gaddrs as *const libc::c_void,
            argsz as socklen_t,
        ) != 0i32
        {
            free(gaddrs as *mut libc::c_void);
            return -(1i32);
        }

        sa = (sa as caddr_t).offset(sa_len as isize) as *mut sockaddr;
    }
    free(gaddrs as *mut libc::c_void);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_connectx(
    mut so: *mut socket,
    mut addrs: *const sockaddr,
    mut addrcnt: libc::c_int,
    mut id: *mut sctp_assoc_t,
) -> libc::c_int {
    let mut buf = [0; 2048];
    let mut ret = 0;
    let mut cnt = 0;
    let mut aa = 0 as *mut libc::c_int;
    let mut cpto = 0 as *mut libc::c_char;
    let mut at = 0 as *const sockaddr;
    let mut len = ::std::mem::size_of::<libc::c_int>() as libc::c_ulong;
    /* validate the address count and list */
    if addrs.is_null() || addrcnt <= 0i32 {
        *__errno_location() = 22i32;
        return -(1i32);
    }
    at = addrs;
    cnt = 0i32;
    cpto = buf
        .as_mut_ptr()
        .offset(::std::mem::size_of::<libc::c_int>() as isize);
    /* validate all the addresses and get the size */

    for i in 0i32..addrcnt {
        match (*at).sa_family as libc::c_int {
            2 => {
                len = (len).wrapping_add(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
                if len > 2048u64 {
                    *__errno_location() = 12i32;
                    return -(1i32);
                }
                memcpy(
                    cpto as *mut libc::c_void,
                    at as *const libc::c_void,
                    ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
                );
                cpto = cpto.offset(::std::mem::size_of::<sockaddr_in>() as isize);
                at = (at as caddr_t).offset(::std::mem::size_of::<sockaddr_in>() as isize)
                    as *mut sockaddr
            }
            10 => {
                if ({
                    let mut __a = &mut (*(at as *mut sockaddr_in6)).sin6_addr as *mut in6_addr
                        as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                        && (*__a).__in6_u.__u6_addr32[2usize] == htonl(0xffffu32))
                        as libc::c_int
                }) != 0
                {
                    len = (len).wrapping_add(::std::mem::size_of::<sockaddr_in>() as libc::c_ulong);
                    if len > 2048u64 {
                        *__errno_location() = 12i32;
                        return -(1i32);
                    }
                    in6_sin6_2_sin(cpto as *mut sockaddr_in, at as *mut sockaddr_in6);
                    cpto = cpto.offset(::std::mem::size_of::<sockaddr_in>() as isize)
                } else {
                    len =
                        (len).wrapping_add(::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong);
                    if len > 2048u64 {
                        *__errno_location() = 12i32;
                        return -(1i32);
                    }
                    memcpy(
                        cpto as *mut libc::c_void,
                        at as *const libc::c_void,
                        ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                    );
                    cpto = cpto.offset(::std::mem::size_of::<sockaddr_in6>() as isize)
                }
                at = (at as caddr_t).offset(::std::mem::size_of::<sockaddr_in6>() as isize)
                    as *mut sockaddr
            }
            _ => {
                *__errno_location() = 22i32;
                return -(1i32);
            }
        }

        cnt += 1;
    }
    aa = buf.as_mut_ptr() as *mut libc::c_int;
    *aa = cnt;
    ret = usrsctp_setsockopt(
        so,
        IPPROTO_SCTP as libc::c_int,
        0x8007i32,
        buf.as_mut_ptr() as *mut libc::c_void,
        len as socklen_t,
    );
    if ret == 0i32 && !id.is_null() {
        let mut p_id = 0 as *mut sctp_assoc_t;
        p_id = buf.as_mut_ptr() as *mut sctp_assoc_t;
        *id = *p_id
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_getpaddrs(
    mut so: *mut socket,
    mut id: sctp_assoc_t,
    mut raddrs: *mut *mut sockaddr,
) -> libc::c_int {
    let mut addrs = 0 as *mut sctp_getaddresses;
    let mut sa = 0 as *mut sockaddr;
    let mut asoc = 0;
    let mut lim = 0 as *mut libc::c_char;
    let mut opt_len = 0;
    let mut cnt = 0;
    if raddrs.is_null() {
        *__errno_location() = 14i32;
        return -(1i32);
    }
    asoc = id;
    opt_len = ::std::mem::size_of::<sctp_assoc_t>() as socklen_t;
    if usrsctp_getsockopt(
        so,
        IPPROTO_SCTP as libc::c_int,
        0x8006i32,
        &mut asoc as *mut sctp_assoc_t as *mut libc::c_void,
        &mut opt_len,
    ) != 0i32
    {
        return -(1i32);
    }
    /* size required is returned in 'asoc' */
    opt_len = (asoc as size_t)
        .wrapping_add(::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong)
        as socklen_t;
    addrs = calloc(1u64, opt_len as size_t) as *mut sctp_getaddresses;
    if addrs.is_null() {
        *__errno_location() = 12i32;
        return -(1i32);
    }
    (*addrs).sget_assoc_id = id;
    /* Now lets get the array of addresses */
    if usrsctp_getsockopt(
        so,
        IPPROTO_SCTP as libc::c_int,
        0x8003i32,
        addrs as *mut libc::c_void,
        &mut opt_len,
    ) != 0i32
    {
        free(addrs as *mut libc::c_void);
        return -(1i32);
    }
    *raddrs = &mut *(*addrs).addr.as_mut_ptr().offset(0isize) as *mut sockaddr;
    cnt = 0i32;
    sa = &mut *(*addrs).addr.as_mut_ptr().offset(0isize) as *mut sockaddr;
    lim = (addrs as caddr_t).offset(opt_len as isize);
    while (sa as caddr_t) < lim {
        match (*sa).sa_family as libc::c_int {
            2 => {
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_in>() as isize)
                    as *mut sockaddr
            }
            10 => {
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_in6>() as isize)
                    as *mut sockaddr
            }
            123 => {
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_conn>() as isize)
                    as *mut sockaddr
            }
            _ => return cnt,
        }
        cnt += 1
    }
    return cnt;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_freepaddrs(mut addrs: *mut sockaddr) {
    /* Take away the hidden association id */
    let mut fr_addr = 0 as *mut libc::c_void;
    fr_addr = (addrs as caddr_t).offset(-(::std::mem::size_of::<sctp_assoc_t>() as isize))
        as *mut libc::c_void;
    /* Now free it */
    free(fr_addr);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_getladdrs(
    mut so: *mut socket,
    mut id: sctp_assoc_t,
    mut raddrs: *mut *mut sockaddr,
) -> libc::c_int {
    let mut addrs = 0 as *mut sctp_getaddresses;
    let mut lim = 0 as *mut libc::c_char;
    let mut sa = 0 as *mut sockaddr;
    let mut size_of_addresses = 0;
    let mut opt_len = 0;
    let mut cnt = 0;
    if raddrs.is_null() {
        *__errno_location() = 14i32;
        return -(1i32);
    }
    size_of_addresses = 0u64;
    opt_len = ::std::mem::size_of::<libc::c_int>() as socklen_t;
    if usrsctp_getsockopt(
        so,
        IPPROTO_SCTP as libc::c_int,
        0x8005i32,
        &mut size_of_addresses as *mut size_t as *mut libc::c_void,
        &mut opt_len,
    ) != 0i32
    {
        *__errno_location() = 12i32;
        return -(1i32);
    }
    if size_of_addresses == 0u64 {
        *__errno_location() = 107i32;
        return -(1i32);
    }
    opt_len = size_of_addresses
        .wrapping_add(::std::mem::size_of::<sockaddr_storage>() as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_getaddresses>() as libc::c_ulong)
        as socklen_t;
    addrs = calloc(1u64, opt_len as size_t) as *mut sctp_getaddresses;
    if addrs.is_null() {
        *__errno_location() = 12i32;
        return -(1i32);
    }
    (*addrs).sget_assoc_id = id;
    /* Now lets get the array of addresses */
    if usrsctp_getsockopt(
        so,
        IPPROTO_SCTP as libc::c_int,
        0x8004i32,
        addrs as *mut libc::c_void,
        &mut opt_len,
    ) != 0i32
    {
        free(addrs as *mut libc::c_void);
        *__errno_location() = 12i32;
        return -(1i32);
    }
    *raddrs = &mut *(*addrs).addr.as_mut_ptr().offset(0isize) as *mut sockaddr;
    cnt = 0i32;
    sa = &mut *(*addrs).addr.as_mut_ptr().offset(0isize) as *mut sockaddr;
    lim = (addrs as caddr_t).offset(opt_len as isize);
    while (sa as caddr_t) < lim {
        match (*sa).sa_family as libc::c_int {
            2 => {
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_in>() as isize)
                    as *mut sockaddr
            }
            10 => {
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_in6>() as isize)
                    as *mut sockaddr
            }
            123 => {
                sa = (sa as caddr_t).offset(::std::mem::size_of::<sockaddr_conn>() as isize)
                    as *mut sockaddr
            }
            _ => return cnt,
        }
        cnt += 1
    }
    return cnt;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_freeladdrs(mut addrs: *mut sockaddr) {
    /* Take away the hidden association id */
    let mut fr_addr = 0 as *mut libc::c_void;
    fr_addr = (addrs as caddr_t).offset(-(::std::mem::size_of::<sctp_assoc_t>() as isize))
        as *mut libc::c_void;
    /* Now free it */
    free(fr_addr);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_userspace_ip_output(
    mut result: *mut libc::c_int,
    mut o_pak: *mut mbuf,
    mut ro: *mut sctp_route_t,
    mut stcb: *mut libc::c_void,
    mut vrf_id: uint32_t,
) {
    let mut m = 0 as *mut mbuf;
    let mut m_orig = 0 as *mut mbuf;
    let mut iovcnt = 0;
    let mut send_len = 0;
    let mut len = 0;
    let mut send_count = 0;
    let mut ip = 0 as *mut ip;
    let mut udp = 0 as *mut udphdr;
    let mut dst = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut send_iovec = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 32];
    let mut use_udp_tunneling = 0;
    *result = 0i32;
    m = o_pak;
    m_orig = m;
    len = ::std::mem::size_of::<ip>() as libc::c_int;
    if (*m).m_hdr.mh_len < len {
        m = m_pullup(m, len);
        if m.is_null() {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Can not get the IP header in the first mbuf.\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
            return;
        }
    }
    ip = (*m).m_hdr.mh_data as *mut ip;
    use_udp_tunneling = ((*ip).ip_p as libc::c_int == IPPROTO_UDP as libc::c_int) as libc::c_int;
    if use_udp_tunneling != 0 {
        len = (::std::mem::size_of::<ip>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<udphdr>() as libc::c_ulong)
            as libc::c_int;
        if (*m).m_hdr.mh_len < len {
            m = m_pullup(m, len);
            if m.is_null() {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Can not get the UDP/IP header in the first mbuf.\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
                return;
            }
            ip = (*m).m_hdr.mh_data as *mut ip
        }
        udp = ip.offset(1isize) as *mut udphdr
    } else {
        udp = 0 as *mut udphdr
    }
    if use_udp_tunneling == 0 {
        if (*ip).ip_src.s_addr == 0u32 {
            /* TODO get addr of outgoing interface */
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Why did the SCTP implementation did not choose a source address?\n\x00"
                        as *const u8 as *const libc::c_char,
                );
            }
        }
        /* TODO need to worry about ro->ro_dst as in ip_output? */
        /* need to put certain fields into network order for Linux */
        (*ip).ip_len = htons((*ip).ip_len)
    }
    memset(
        &mut dst as *mut sockaddr_in as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
    );
    dst.sin_family = 2u16;
    dst.sin_addr.s_addr = (*ip).ip_dst.s_addr;
    if use_udp_tunneling != 0 {
        dst.sin_port = (*udp).c2rust_unnamed.c2rust_unnamed.uh_dport
    } else {
        dst.sin_port = 0u16
    }
    /* tweak the mbuf chain */
    if use_udp_tunneling != 0 {
        m_adj(
            m,
            (::std::mem::size_of::<ip>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<udphdr>() as libc::c_ulong)
                as libc::c_int,
        ); /* length of entire packet */
    }
    send_len = (*m).M_dat.MH.MH_pkthdr.len;
    send_count = 0i32;
    iovcnt = 0i32;
    while !m.is_null() && iovcnt < 32i32 {
        send_iovec[iovcnt as usize].iov_base = (*m).m_hdr.mh_data as *mut libc::c_void;
        send_iovec[iovcnt as usize].iov_len = (*m).m_hdr.mh_len as size_t;
        send_count = (send_count as libc::c_ulong).wrapping_add(send_iovec[iovcnt as usize].iov_len)
            as libc::c_int;
        m = (*m).m_hdr.mh_next;
        iovcnt += 1
    }
    if !m.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"mbuf chain couldn\'t be copied completely\n\x00" as *const u8
                    as *const libc::c_char,
            );
        }
    } else {
        let mut res = 0;
        let mut msg_hdr = msghdr {
            msg_name: 0 as *mut libc::c_void,
            msg_namelen: 0,
            msg_iov: 0 as *mut iovec,
            msg_iovlen: 0,
            msg_control: 0 as *mut libc::c_void,
            msg_controllen: 0,
            msg_flags: 0,
        };
        msg_hdr.msg_name = &mut dst as *mut sockaddr_in as *mut libc::c_void;
        msg_hdr.msg_namelen = ::std::mem::size_of::<sockaddr_in>() as socklen_t;
        msg_hdr.msg_iov = send_iovec.as_mut_ptr();
        msg_hdr.msg_iovlen = iovcnt as size_t;
        msg_hdr.msg_control = 0 as *mut libc::c_void;
        msg_hdr.msg_controllen = 0u64;
        msg_hdr.msg_flags = 0i32;
        if use_udp_tunneling == 0 && system_base_info.userspace_rawsctp != -(1i32) {
            res = sendmsg(
                system_base_info.userspace_rawsctp,
                &mut msg_hdr,
                MSG_DONTWAIT as libc::c_int,
            ) as libc::c_int;
            if res != send_len {
                *result = *__errno_location()
            }
        }
        if use_udp_tunneling != 0 && system_base_info.userspace_udpsctp != -(1i32) {
            res = sendmsg(
                system_base_info.userspace_udpsctp,
                &mut msg_hdr,
                MSG_DONTWAIT as libc::c_int,
            ) as libc::c_int;
            if res != send_len {
                *result = *__errno_location()
            }
        }
    }
    m_freem(m_orig);
}
/*
 * SCTP protocol specific mbuf flags.
 */
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
#[no_mangle]
pub unsafe extern "C" fn sctp_userspace_ip6_output(
    mut result: *mut libc::c_int,
    mut o_pak: *mut mbuf,
    mut ro: *mut route_in6,
    mut stcb: *mut libc::c_void,
    mut vrf_id: uint32_t,
) {
    let mut m = 0 as *mut mbuf;
    let mut m_orig = 0 as *mut mbuf;
    let mut iovcnt = 0;
    let mut send_len = 0;
    let mut len = 0;
    let mut send_count = 0;
    let mut ip6 = 0 as *mut ip6_hdr;
    let mut udp = 0 as *mut udphdr;
    let mut dst = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            __in6_u: C2RustUnnamed_994 {
                __u6_addr8: [0; 16],
            },
        },
        sin6_scope_id: 0,
    };
    let mut send_iovec = [iovec {
        iov_base: 0 as *mut libc::c_void,
        iov_len: 0,
    }; 32];
    let mut use_udp_tunneling = 0;
    *result = 0i32;
    m = o_pak;
    m_orig = m;
    len = ::std::mem::size_of::<ip6_hdr>() as libc::c_int;
    if (*m).m_hdr.mh_len < len {
        m = m_pullup(m, len);
        if m.is_null() {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Can not get the IP header in the first mbuf.\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
            return;
        }
    }
    ip6 = (*m).m_hdr.mh_data as *mut ip6_hdr;
    use_udp_tunneling = ((*ip6).ip6_ctlun.ip6_un1.ip6_un1_nxt as libc::c_int
        == IPPROTO_UDP as libc::c_int) as libc::c_int;
    if use_udp_tunneling != 0 {
        len = (::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<udphdr>() as libc::c_ulong)
            as libc::c_int;
        if (*m).m_hdr.mh_len < len {
            m = m_pullup(m, len);
            if m.is_null() {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Can not get the UDP/IP header in the first mbuf.\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
                return;
            }
            ip6 = (*m).m_hdr.mh_data as *mut ip6_hdr
        }
        udp = ip6.offset(1isize) as *mut udphdr
    } else {
        udp = 0 as *mut udphdr
    }
    if use_udp_tunneling == 0 {
        if (*ip6).ip6_src.__in6_u.__u6_addr8.as_mut_ptr()
            == in6addr_any.__in6_u.__u6_addr8.as_ptr() as *mut uint8_t
        {
            /* TODO get addr of outgoing interface */
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Why did the SCTP implementation did not choose a source address?\n\x00"
                        as *const u8 as *const libc::c_char,
                );
            }
        }
        /* TODO need to worry about ro->ro_dst as in ip_output? */
    }
    memset(
        &mut dst as *mut sockaddr_in6 as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
    );
    dst.sin6_family = 10u16;
    dst.sin6_addr = (*ip6).ip6_dst;
    if use_udp_tunneling != 0 {
        dst.sin6_port = (*udp).c2rust_unnamed.c2rust_unnamed.uh_dport
    } else {
        dst.sin6_port = 0u16
    }
    /* tweak the mbuf chain */
    if use_udp_tunneling != 0 {
        m_adj(
            m,
            (::std::mem::size_of::<ip6_hdr>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<udphdr>() as libc::c_ulong)
                as libc::c_int,
        ); /* length of entire packet */
    } else {
        m_adj(m, ::std::mem::size_of::<ip6_hdr>() as libc::c_int);
    }
    send_len = (*m).M_dat.MH.MH_pkthdr.len;
    send_count = 0i32;
    iovcnt = 0i32;
    while !m.is_null() && iovcnt < 32i32 {
        send_iovec[iovcnt as usize].iov_base = (*m).m_hdr.mh_data as *mut libc::c_void;
        send_iovec[iovcnt as usize].iov_len = (*m).m_hdr.mh_len as size_t;
        send_count = (send_count as libc::c_ulong).wrapping_add(send_iovec[iovcnt as usize].iov_len)
            as libc::c_int;
        m = (*m).m_hdr.mh_next;
        iovcnt += 1
    }
    if !m.is_null() {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"mbuf chain couldn\'t be copied completely\n\x00" as *const u8
                    as *const libc::c_char,
            );
        }
    } else {
        let mut res = 0;
        let mut msg_hdr = msghdr {
            msg_name: 0 as *mut libc::c_void,
            msg_namelen: 0,
            msg_iov: 0 as *mut iovec,
            msg_iovlen: 0,
            msg_control: 0 as *mut libc::c_void,
            msg_controllen: 0,
            msg_flags: 0,
        };
        msg_hdr.msg_name = &mut dst as *mut sockaddr_in6 as *mut libc::c_void;
        msg_hdr.msg_namelen = ::std::mem::size_of::<sockaddr_in6>() as socklen_t;
        msg_hdr.msg_iov = send_iovec.as_mut_ptr();
        msg_hdr.msg_iovlen = iovcnt as size_t;
        msg_hdr.msg_control = 0 as *mut libc::c_void;
        msg_hdr.msg_controllen = 0u64;
        msg_hdr.msg_flags = 0i32;
        if use_udp_tunneling == 0 && system_base_info.userspace_rawsctp6 != -(1i32) {
            res = sendmsg(
                system_base_info.userspace_rawsctp6,
                &mut msg_hdr,
                MSG_DONTWAIT as libc::c_int,
            ) as libc::c_int;
            if res != send_len {
                *result = *__errno_location()
            }
        }
        if use_udp_tunneling != 0 && system_base_info.userspace_udpsctp6 != -(1i32) {
            res = sendmsg(
                system_base_info.userspace_udpsctp6,
                &mut msg_hdr,
                MSG_DONTWAIT as libc::c_int,
            ) as libc::c_int;
            if res != send_len {
                *result = *__errno_location()
            }
        }
    }
    m_freem(m_orig);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_register_address(mut addr: *mut libc::c_void) {
    let mut sconn = sockaddr_conn {
        sconn_family: 0,
        sconn_port: 0,
        sconn_addr: 0 as *mut libc::c_void,
    };
    memset(
        &mut sconn as *mut sockaddr_conn as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
    );
    sconn.sconn_family = 123u16;
    sconn.sconn_port = 0u16;
    sconn.sconn_addr = addr;
    sctp_add_addr_to_vrf(
        0u32,
        0 as *mut libc::c_void,
        0xffffffffu32,
        0u32,
        b"conn\x00" as *const u8 as *const libc::c_char,
        0 as *mut libc::c_void,
        &mut sconn as *mut sockaddr_conn as *mut sockaddr,
        0u32,
        0i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_deregister_address(mut addr: *mut libc::c_void) {
    let mut sconn = sockaddr_conn {
        sconn_family: 0,
        sconn_port: 0,
        sconn_addr: 0 as *mut libc::c_void,
    };
    memset(
        &mut sconn as *mut sockaddr_conn as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
    );
    sconn.sconn_family = 123u16;
    sconn.sconn_port = 0u16;
    sconn.sconn_addr = addr;
    sctp_del_addr_from_vrf(
        0u32,
        &mut sconn as *mut sockaddr_conn as *mut sockaddr,
        0xffffffffu32,
        b"conn\x00" as *const u8 as *const libc::c_char,
    );
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_dumppacket(
    mut buf: *const libc::c_void,
    mut len: size_t,
    mut outbound: libc::c_int,
) -> *mut libc::c_char {
    let mut i = 0;
    let mut pos = 0;
    let mut dump_buf = 0 as *mut libc::c_char;
    let mut packet = 0 as *mut libc::c_char;
    let mut t = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const libc::c_char,
    };
    let mut tv = timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut sec = 0;
    if len == 0u64 || buf == 0 as *mut libc::c_void {
        return 0 as *mut libc::c_char;
    }
    dump_buf = malloc(
        (19u64)
            .wrapping_add(strlen(b"0000 \x00" as *const u8 as *const libc::c_char))
            .wrapping_add((3u64).wrapping_mul(len))
            .wrapping_add(strlen(
                b"# SCTP_PACKET\n\x00" as *const u8 as *const libc::c_char,
            ))
            .wrapping_add(1u64),
    ) as *mut libc::c_char;
    if dump_buf.is_null() {
        return 0 as *mut libc::c_char;
    }
    pos = 0u64;
    gettimeofday(&mut tv, 0 as *mut timezone);
    sec = tv.tv_sec;
    localtime_r(&mut sec as *mut time_t as *const time_t, &mut t);
    snprintf(
        dump_buf,
        (19i32 + 1i32) as libc::c_ulong,
        b"\n%c %02d:%02d:%02d.%06ld \x00" as *const u8 as *const libc::c_char,
        if outbound != 0 {
            'O' as i32
        } else {
            'I' as i32
        },
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
        tv.tv_usec,
    );
    pos = (pos).wrapping_add(19u64);
    strcpy(
        dump_buf.offset(pos as isize),
        b"0000 \x00" as *const u8 as *const libc::c_char,
    );
    pos = (pos).wrapping_add(strlen(b"0000 \x00" as *const u8 as *const libc::c_char));
    packet = buf as *mut libc::c_char;
    i = 0u64;
    while i < len {
        let mut byte = 0;
        let mut low = 0;
        let mut high = 0;
        byte = *packet.offset(i as isize) as uint8_t;
        high = (byte as libc::c_int / 16i32) as uint8_t;
        low = (byte as libc::c_int % 16i32) as uint8_t;
        let fresh3 = pos;
        pos = pos.wrapping_add(1);
        *dump_buf.offset(fresh3 as isize) = if (high as libc::c_int) < 10i32 {
            ('0' as i32) + high as libc::c_int
        } else {
            ('a' as i32) + (high as libc::c_int - 10i32)
        } as libc::c_char;
        let fresh4 = pos;
        pos = pos.wrapping_add(1);
        *dump_buf.offset(fresh4 as isize) = if (low as libc::c_int) < 10i32 {
            ('0' as i32) + low as libc::c_int
        } else {
            ('a' as i32) + (low as libc::c_int - 10i32)
        } as libc::c_char;
        let fresh5 = pos;
        pos = pos.wrapping_add(1);
        *dump_buf.offset(fresh5 as isize) = ' ' as libc::c_char;
        i = i.wrapping_add(1)
    }
    strcpy(
        dump_buf.offset(pos as isize),
        b"# SCTP_PACKET\n\x00" as *const u8 as *const libc::c_char,
    );
    pos = (pos).wrapping_add(strlen(
        b"# SCTP_PACKET\n\x00" as *const u8 as *const libc::c_char,
    ));
    let fresh6 = pos;
    pos = pos.wrapping_add(1);
    *dump_buf.offset(fresh6 as isize) = '\u{0}' as libc::c_char;
    return dump_buf;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_freedumpbuffer(mut buf: *mut libc::c_char) {
    free(buf as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_enable_crc32c_offload() {
    system_base_info.crc32c_offloaded = 1i32;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_disable_crc32c_offload() {
    system_base_info.crc32c_offloaded = 0i32;
}
/* Compute the CRC32C in network byte order */
#[no_mangle]
pub unsafe extern "C" fn usrsctp_crc32c(
    mut buffer: *mut libc::c_void,
    mut length: size_t,
) -> uint32_t {
    let mut base = 0xffffffffu32;
    base = calculate_crc32c(
        0xffffffffu32,
        buffer as *mut libc::c_uchar,
        length as libc::c_uint,
    );
    base = sctp_finalize_crc32c(base);
    return base;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_conninput(
    mut addr: *mut libc::c_void,
    mut buffer: *const libc::c_void,
    mut length: size_t,
    mut ecn_bits: uint8_t,
) {
    let mut src = sockaddr_conn {
        sconn_family: 0,
        sconn_port: 0,
        sconn_addr: 0 as *mut libc::c_void,
    };
    let mut dst = sockaddr_conn {
        sconn_family: 0,
        sconn_port: 0,
        sconn_addr: 0 as *mut libc::c_void,
    };
    let mut m = 0 as *mut mbuf;
    let mut sh = 0 as *mut sctphdr;
    let mut ch = 0 as *mut sctp_chunkhdr;
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_recvpackets, 1u32);
    ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_inpackets, 1u32);
    memset(
        &mut src as *mut sockaddr_conn as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
    );
    src.sconn_family = 123u16;
    src.sconn_addr = addr;
    memset(
        &mut dst as *mut sockaddr_conn as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sockaddr_conn>() as libc::c_ulong,
    );
    dst.sconn_family = 123u16;
    dst.sconn_addr = addr;
    m = sctp_get_mbuf_for_msg(length as libc::c_uint, 1i32, 0x1i32, 0i32, 1i32);
    if m.is_null() {
        return;
    }
    m_copyback(m, 0i32, length as libc::c_int, buffer as caddr_t);
    if (*m).m_hdr.mh_len
        < (::std::mem::size_of::<sctphdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_chunkhdr>() as libc::c_ulong)
            as libc::c_int
    {
        m = m_pullup(
            m,
            (::std::mem::size_of::<sctphdr>() as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<sctp_chunkhdr>() as libc::c_ulong)
                as libc::c_int,
        );
        if m.is_null() {
            ::std::intrinsics::atomic_xadd(&mut system_base_info.sctpstat.sctps_hdrops, 1u32);
            return;
        }
    }
    sh = (*m).m_hdr.mh_data as *mut sctphdr;
    ch = (sh as caddr_t).offset(::std::mem::size_of::<sctphdr>() as isize) as *mut sctp_chunkhdr;
    src.sconn_port = (*sh).src_port;
    dst.sconn_port = (*sh).dest_port;
    sctp_common_input_processing(
        &mut m,
        0i32,
        ::std::mem::size_of::<sctphdr>() as libc::c_int,
        length as libc::c_int,
        &mut src as *mut sockaddr_conn as *mut sockaddr,
        &mut dst as *mut sockaddr_conn as *mut sockaddr,
        sh,
        ch,
        if system_base_info.crc32c_offloaded == 1i32 {
            0i32
        } else {
            1i32
        } as uint8_t,
        ecn_bits,
        0u32,
        0u16,
    );
    if !m.is_null() {
        m_freem(m);
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_handle_timers(mut delta: uint32_t) {
    sctp_handle_tick(delta);
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_get_events(mut so: *mut socket) -> libc::c_int {
    let mut events = 0i32;
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    if (*so).so_rcv.sb_cc as libc::c_int >= (*so).so_rcv.sb_lowat
        || (*so).so_rcv.sb_state as libc::c_int & 0x20i32 != 0
        || !(*so).so_comp.tqh_first.is_null()
        || (*so).so_error as libc::c_int != 0
    {
        events |= 0x1i32
    }
    if (if (*so).so_snd.sb_hiwat.wrapping_sub((*so).so_snd.sb_cc) as libc::c_int
        > (*so).so_snd.sb_mbmax.wrapping_sub((*so).so_snd.sb_mbcnt) as libc::c_int
    {
        (*so).so_snd.sb_mbmax.wrapping_sub((*so).so_snd.sb_mbcnt) as libc::c_int
    } else {
        (*so).so_snd.sb_hiwat.wrapping_sub((*so).so_snd.sb_cc) as libc::c_int
    }) as libc::c_long
        >= (*so).so_snd.sb_lowat as libc::c_long
        && (*so).so_state as libc::c_int & 0x2i32 != 0
        || (*so).so_snd.sb_state as libc::c_int & 0x10i32 != 0
        || (*so).so_error as libc::c_int != 0
    {
        events |= 0x2i32
    }
    if (*so).so_error != 0 {
        events |= 0x4i32
    }
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    return events;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_set_upcall(
    mut so: *mut socket,
    mut upcall: Option<
        unsafe extern "C" fn(_: *mut socket, _: *mut libc::c_void, _: libc::c_int) -> (),
    >,
    mut arg: *mut libc::c_void,
) -> libc::c_int {
    if so.is_null() {
        *__errno_location() = 9i32;
        return -(1i32);
    }
    pthread_mutex_lock(&mut (*so).so_rcv.sb_mtx);
    (*so).so_upcall = upcall;
    (*so).so_upcallarg = arg;
    (*so).so_snd.sb_flags = ((*so).so_snd.sb_flags as libc::c_int | 0x20i32) as libc::c_short;
    (*so).so_rcv.sb_flags = ((*so).so_rcv.sb_flags as libc::c_int | 0x20i32) as libc::c_short;
    pthread_mutex_unlock(&mut (*so).so_rcv.sb_mtx);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_tunable_set_sctp_hashtblsize(mut value: uint32_t) -> libc::c_int {
    if value < 1u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_hashtblsize = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_tunable_set_sctp_pcbtblsize(mut value: uint32_t) -> libc::c_int {
    if value < 1u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_pcbtblsize = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_tunable_set_sctp_chunkscale(mut value: uint32_t) -> libc::c_int {
    if value < 1u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_chunkscale = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_sendspace(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_sendspace = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_recvspace(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_recvspace = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_auto_asconf(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_auto_asconf = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_ecn_enable(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_ecn_enable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_pr_enable(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_pr_enable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_auth_enable(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_auth_enable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_asconf_enable(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_asconf_enable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_reconfig_enable(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_reconfig_enable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_nrsack_enable(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_nrsack_enable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_pktdrop_enable(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_pktdrop_enable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_no_csum_on_loopback(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_no_csum_on_loopback = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_peer_chunk_oh(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_peer_chunk_oh = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_max_burst_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_max_burst_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_max_chunks_on_queue(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_max_chunks_on_queue = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_min_split_point(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_min_split_point = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_delayed_sack_time_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_delayed_sack_time_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_sack_freq_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_sack_freq_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_system_free_resc_limit(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_system_free_resc_limit = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_asoc_free_resc_limit(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_asoc_free_resc_limit = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_heartbeat_interval_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_heartbeat_interval_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_pmtu_raise_time_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_pmtu_raise_time_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_shutdown_guard_time_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_shutdown_guard_time_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_secret_lifetime_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_secret_lifetime_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_rto_max_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_rto_max_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_rto_min_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_rto_min_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_rto_initial_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_rto_initial_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_init_rto_max_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_init_rto_max_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_valid_cookie_life_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_valid_cookie_life_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_init_rtx_max_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_init_rtx_max_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_assoc_rtx_max_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_assoc_rtx_max_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_path_rtx_max_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_path_rtx_max_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_add_more_threshold(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_add_more_threshold = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_nr_incoming_streams_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 1u32 || value > 65535u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_nr_incoming_streams_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 1u32 || value > 65535u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_nr_outgoing_streams_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_cmt_on_off(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 4u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_cmt_on_off = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_cmt_use_dac(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_cmt_use_dac = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_use_cwnd_based_maxburst(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_use_cwnd_based_maxburst = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_nat_friendly(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_nat_friendly = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_L2_abc_variable(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_L2_abc_variable = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_mbuf_threshold_count(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_mbuf_threshold_count = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_do_drain(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_do_drain = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_hb_maxburst(mut value: uint32_t) -> libc::c_int {
    if value < 1u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_hb_maxburst = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_abort_if_one_2_one_hits_limit(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info
            .sctpsysctl
            .sctp_abort_if_one_2_one_hits_limit = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_min_residual(mut value: uint32_t) -> libc::c_int {
    if value < 20u32 || value > 65535u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_min_residual = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_max_retran_chunk(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 65535u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_max_retran_chunk = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_logging_level(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_logging_level = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_default_cc_module(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 2u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_default_cc_module = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_default_frag_interleave(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 2u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_default_frag_interleave = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_mobility_base(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_mobility_base = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_mobility_fasthandoff(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_mobility_fasthandoff = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_inits_include_nat_friendly(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_inits_include_nat_friendly = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_udp_tunneling_port(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 65535u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_udp_tunneling_port = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_enable_sack_immediately(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_enable_sack_immediately = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_vtag_time_wait(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_vtag_time_wait = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_blackhole(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 2u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_blackhole = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_diag_info_code(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 65535u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_diag_info_code = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_fr_max_burst_default(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_fr_max_burst_default = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_path_pf_threshold(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0xffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_path_pf_threshold = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_default_ss_module(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 5u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_default_ss_module = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_rttvar_bw(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 32u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_rttvar_bw = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_rttvar_rtt(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 32u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_rttvar_rtt = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_rttvar_eqret(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_rttvar_eqret = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_steady_step(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 0xffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_steady_step = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_use_dccc_ecn(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 1u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_use_dccc_ecn = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_buffer_splitting(
    mut value: uint32_t,
) -> libc::c_int {
    if value < 0u32 || value > 0x3u32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_buffer_splitting = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_initial_cwnd(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_initial_cwnd = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_set_sctp_debug_on(mut value: uint32_t) -> libc::c_int {
    if value < 0u32 || value > 0xffffffffu32 {
        *__errno_location() = 22i32;
        return -(1i32);
    } else {
        system_base_info.sctpsysctl.sctp_debug_on = value;
        return 0i32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_sendspace() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_sendspace;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_recvspace() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_recvspace;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_auto_asconf() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_auto_asconf;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_multiple_asconfs() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_multiple_asconfs;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_ecn_enable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_ecn_enable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_pr_enable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_pr_enable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_auth_enable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_auth_enable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_asconf_enable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_asconf_enable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_reconfig_enable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_reconfig_enable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_nrsack_enable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_nrsack_enable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_pktdrop_enable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_pktdrop_enable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_no_csum_on_loopback() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_no_csum_on_loopback;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_peer_chunk_oh() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_peer_chunk_oh;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_max_burst_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_max_burst_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_max_chunks_on_queue() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_max_chunks_on_queue;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_hashtblsize() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_hashtblsize;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_pcbtblsize() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_pcbtblsize;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_min_split_point() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_min_split_point;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_chunkscale() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_chunkscale;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_delayed_sack_time_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_delayed_sack_time_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_sack_freq_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_sack_freq_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_system_free_resc_limit() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_system_free_resc_limit;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_asoc_free_resc_limit() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_asoc_free_resc_limit;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_heartbeat_interval_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_heartbeat_interval_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_pmtu_raise_time_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_pmtu_raise_time_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_shutdown_guard_time_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_shutdown_guard_time_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_secret_lifetime_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_secret_lifetime_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_rto_max_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_rto_max_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_rto_min_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_rto_min_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_rto_initial_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_rto_initial_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_init_rto_max_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_init_rto_max_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_valid_cookie_life_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_valid_cookie_life_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_init_rtx_max_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_init_rtx_max_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_assoc_rtx_max_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_assoc_rtx_max_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_path_rtx_max_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_path_rtx_max_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_add_more_threshold() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_add_more_threshold;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_nr_incoming_streams_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_nr_incoming_streams_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_nr_outgoing_streams_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_nr_outgoing_streams_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_cmt_on_off() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_cmt_on_off;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_cmt_use_dac() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_cmt_use_dac;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_use_cwnd_based_maxburst() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_use_cwnd_based_maxburst;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_nat_friendly() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_nat_friendly;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_L2_abc_variable() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_L2_abc_variable;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_mbuf_threshold_count() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_mbuf_threshold_count;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_do_drain() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_do_drain;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_hb_maxburst() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_hb_maxburst;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_abort_if_one_2_one_hits_limit() -> uint32_t {
    return system_base_info
        .sctpsysctl
        .sctp_abort_if_one_2_one_hits_limit;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_min_residual() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_min_residual;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_max_retran_chunk() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_max_retran_chunk;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_logging_level() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_logging_level;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_default_cc_module() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_default_cc_module;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_default_frag_interleave() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_default_frag_interleave;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_mobility_base() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_mobility_base;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_mobility_fasthandoff() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_mobility_fasthandoff;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_inits_include_nat_friendly() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_inits_include_nat_friendly;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_udp_tunneling_port() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_udp_tunneling_port;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_enable_sack_immediately() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_enable_sack_immediately;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_vtag_time_wait() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_vtag_time_wait;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_blackhole() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_blackhole;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_diag_info_code() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_diag_info_code;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_fr_max_burst_default() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_fr_max_burst_default;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_path_pf_threshold() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_path_pf_threshold;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_default_ss_module() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_default_ss_module;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_rttvar_bw() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_rttvar_bw;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_rttvar_rtt() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_rttvar_rtt;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_rttvar_eqret() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_rttvar_eqret;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_steady_step() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_steady_step;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_use_dccc_ecn() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_use_dccc_ecn;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_buffer_splitting() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_buffer_splitting;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_initial_cwnd() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_initial_cwnd;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_sysctl_get_sctp_debug_on() -> uint32_t {
    return system_base_info.sctpsysctl.sctp_debug_on;
}
#[no_mangle]
pub unsafe extern "C" fn usrsctp_get_stat(mut stat: *mut sctpstat) {
    *stat = system_base_info.sctpstat;
}
