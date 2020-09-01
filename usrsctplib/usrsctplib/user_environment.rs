use ::libc;
extern "C" {
    #[no_mangle]
    fn random() -> libc::c_long;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
}
pub type size_t = libc::c_ulong;
pub type __u_short = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type u_short = __u_short;

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
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [libc::c_char; 40],
    pub __align: libc::c_long,
}
pub type uint32_t = __uint32_t;
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
/* See user_include/user_environment.h for comments about these variables */
#[no_mangle]
pub static mut maxsockets: libc::c_int = 25600i32;
#[no_mangle]
pub static mut hz: libc::c_int = 1000i32;
#[no_mangle]
pub static mut ip_defttl: libc::c_int = 64i32;
#[no_mangle]
pub static mut ipport_firstauto: libc::c_int = 49152i32;
#[no_mangle]
pub static mut ipport_lastauto: libc::c_int = 65535i32;
#[no_mangle]
pub static mut nmbclusters: libc::c_int = 65536i32;
/* Source ip_output.c. extern'd in ip_var.h */
#[no_mangle]
pub static mut ip_id: u_short = 0u16;
/*__Userspace__ TODO Should it be initialized to zero? */
/* used in user_include/user_atomic.h in order to make the operations
 * defined there truly atomic
 */
#[no_mangle]
pub static mut atomic_mtx: userland_mutex_t = pthread_mutex_t {
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
/* If the entropy device is not loaded, make a token effort to
 * provide _some_ kind of randomness. This should only be used
 * inside other RNG's, like arc4random(9).
 */
unsafe extern "C" fn read_random_phony(
    mut buf: *mut libc::c_void,
    mut count: libc::c_int,
) -> libc::c_int {
    for i in (0i32..count).step_by(::std::mem::size_of::<uint32_t>() as libc::c_int as usize) {
        let mut randval = 0;
        let mut size = 0;
        randval = random() as uint32_t;

        size = if count - i < ::std::mem::size_of::<uint32_t>() as libc::c_int {
            (count) - i
        } else {
            ::std::mem::size_of::<uint32_t>() as libc::c_int
        };

        memcpy(
            &mut *(buf as *mut libc::c_char).offset(i as isize) as *mut libc::c_char
                as *mut libc::c_void,
            &mut randval as *mut uint32_t as *const libc::c_void,
            size as size_t,
        );
    }
    return count;
}
static mut read_func: Option<
    unsafe extern "C" fn(_: *mut libc::c_void, _: libc::c_int) -> libc::c_int,
> = {
    Some(
        read_random_phony
            as unsafe extern "C" fn(_: *mut libc::c_void, _: libc::c_int) -> libc::c_int,
    )
};
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
/* Userland-visible version of read_random */
#[no_mangle]
pub unsafe extern "C" fn read_random(
    mut buf: *mut libc::c_void,
    mut count: libc::c_int,
) -> libc::c_int {
    return Some(read_func.expect("non-null function pointer")).expect("non-null function pointer")(
        buf, count,
    );
}
