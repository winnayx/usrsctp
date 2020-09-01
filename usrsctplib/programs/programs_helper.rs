use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    #[no_mangle]
    static mut stderr: *mut FILE;
    #[no_mangle]
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn vprintf(_: *const libc::c_char, _: ::std::ffi::VaList) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn gettimeofday(__tv: *mut timeval, __tz: __timezone_ptr_t)
     -> libc::c_int;
    #[no_mangle]
    fn inet_ntop(__af: libc::c_int, __cp: *const libc::c_void,
                 __buf: *mut libc::c_char, __len: socklen_t)
     -> *const libc::c_char;
}
pub type __builtin_va_list = [__va_list_tag; 1];

#[repr(C)]#[derive(Copy, Clone)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type size_t = libc::c_ulong;
pub type va_list = __builtin_va_list;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __socklen_t = libc::c_uint;

#[repr(C)]#[derive(Copy, Clone)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;

#[repr(C)]#[derive(Copy, Clone)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
pub type uint32_t = __uint32_t;

#[repr(C)]#[derive(Copy, Clone)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_3,
}

#[repr(C)]#[derive(Copy, Clone)]
pub union C2RustUnnamed_3 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
pub type in_port_t = uint16_t;

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
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
/* This definition MUST be in sync with usrsctplib/user_socketvar.h */
pub type sctp_assoc_t = uint32_t;
/* The definition of struct sockaddr_conn MUST be in
 * tune with other sockaddr_* structures.
 */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sockaddr_conn {
    pub sconn_family: uint16_t,
    pub sconn_port: uint16_t,
    pub sconn_addr: *mut libc::c_void,
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_sndinfo {
    pub snd_sid: uint16_t,
    pub snd_flags: uint16_t,
    pub snd_ppid: uint32_t,
    pub snd_context: uint32_t,
    pub snd_assoc_id: sctp_assoc_t,
}
/* notification event structures */
/* association change event */

#[repr(C)]#[derive(Copy, Clone)]
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
/* Address event */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_paddr_change {
    pub spc_type: uint16_t,
    pub spc_flags: uint16_t,
    pub spc_length: uint32_t,
    pub spc_aaddr: sockaddr_storage,
    pub spc_state: uint32_t,
    pub spc_error: uint32_t,
    pub spc_assoc_id: sctp_assoc_t,
    pub spc_padding: [uint8_t; 4],
}
/* remote error events */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_remote_error {
    pub sre_type: uint16_t,
    pub sre_flags: uint16_t,
    pub sre_length: uint32_t,
    pub sre_error: uint16_t,
    pub sre_assoc_id: sctp_assoc_t,
    pub sre_data: [uint8_t; 0],
}
/* shutdown event */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_shutdown_event {
    pub sse_type: uint16_t,
    pub sse_flags: uint16_t,
    pub sse_length: uint32_t,
    pub sse_assoc_id: sctp_assoc_t,
}
/* Adaptation layer indication */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_adaptation_event {
    pub sai_type: uint16_t,
    pub sai_flags: uint16_t,
    pub sai_length: uint32_t,
    pub sai_adaptation_ind: uint32_t,
    pub sai_assoc_id: sctp_assoc_t,
}
/* Partial delivery event */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_pdapi_event {
    pub pdapi_type: uint16_t,
    pub pdapi_flags: uint16_t,
    pub pdapi_length: uint32_t,
    pub pdapi_indication: uint32_t,
    pub pdapi_stream: uint32_t,
    pub pdapi_seq: uint32_t,
    pub pdapi_assoc_id: sctp_assoc_t,
}
/* indication values */
/* SCTP authentication event */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_authkey_event {
    pub auth_type: uint16_t,
    pub auth_flags: uint16_t,
    pub auth_length: uint32_t,
    pub auth_keynumber: uint16_t,
    pub auth_indication: uint32_t,
    pub auth_assoc_id: sctp_assoc_t,
}
/* indication values */
/* SCTP sender dry event */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_sender_dry_event {
    pub sender_dry_type: uint16_t,
    pub sender_dry_flags: uint16_t,
    pub sender_dry_length: uint32_t,
    pub sender_dry_assoc_id: sctp_assoc_t,
}
/* Stream reset event - subscribe to SCTP_STREAM_RESET_EVENT */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_stream_reset_event {
    pub strreset_type: uint16_t,
    pub strreset_flags: uint16_t,
    pub strreset_length: uint32_t,
    pub strreset_assoc_id: sctp_assoc_t,
    pub strreset_stream_list: [uint16_t; 0],
}
/* SCTP_STRRESET_FAILED */
/* SCTP_STRRESET_FAILED */
/* Assoc reset event - subscribe to SCTP_ASSOC_RESET_EVENT */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_assoc_reset_event {
    pub assocreset_type: uint16_t,
    pub assocreset_flags: uint16_t,
    pub assocreset_length: uint32_t,
    pub assocreset_assoc_id: sctp_assoc_t,
    pub assocreset_local_tsn: uint32_t,
    pub assocreset_remote_tsn: uint32_t,
}
/* Stream change event - subscribe to SCTP_STREAM_CHANGE_EVENT */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_stream_change_event {
    pub strchange_type: uint16_t,
    pub strchange_flags: uint16_t,
    pub strchange_length: uint32_t,
    pub strchange_assoc_id: sctp_assoc_t,
    pub strchange_instrms: uint16_t,
    pub strchange_outstrms: uint16_t,
}
/* SCTP send failed event */

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_send_failed_event {
    pub ssfe_type: uint16_t,
    pub ssfe_flags: uint16_t,
    pub ssfe_length: uint32_t,
    pub ssfe_error: uint32_t,
    pub ssfe_info: sctp_sndinfo,
    pub ssfe_assoc_id: sctp_assoc_t,
    pub ssfe_data: [uint8_t; 0],
}

#[repr(C)]#[derive(Copy, Clone)]
pub union sctp_notification {
    pub sn_header: sctp_tlv,
    pub sn_assoc_change: sctp_assoc_change,
    pub sn_paddr_change: sctp_paddr_change,
    pub sn_remote_error: sctp_remote_error,
    pub sn_shutdown_event: sctp_shutdown_event,
    pub sn_adaptation_event: sctp_adaptation_event,
    pub sn_pdapi_event: sctp_pdapi_event,
    pub sn_auth_event: sctp_authkey_event,
    pub sn_sender_dry_event: sctp_sender_dry_event,
    pub sn_send_failed_event: sctp_send_failed_event,
    pub sn_strreset_event: sctp_stream_reset_event,
    pub sn_assocreset_event: sctp_assoc_reset_event,
    pub sn_strchange_event: sctp_stream_change_event,
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct sctp_tlv {
    pub sn_type: uint16_t,
    pub sn_flags: uint16_t,
    pub sn_length: uint32_t,
}

#[repr(C)]#[derive(Copy, Clone)]
pub struct timezone {
    pub tz_minuteswest: libc::c_int,
    pub tz_dsttime: libc::c_int,
}
pub type __timezone_ptr_t = *mut timezone;
#[no_mangle]
pub unsafe extern "C" fn debug_printf_runtime() {
           let mut time_now =      timeval{tv_sec: 0, tv_usec: 0,}; let mut time_delta =      timeval{tv_sec: 0, tv_usec: 0,};static mut time_main: timeval = timeval{tv_sec: 0, tv_usec: 0,};
    
      
    if time_main.tv_sec == 0i64 &&
           time_main.tv_usec == 0i64 {
        gettimeofday(&mut time_main, 0 as *mut timezone);
    }
    gettimeofday(&mut time_now, 0 as *mut timezone);
    
    
    
     
     
    time_delta =
    crate::programs_helper::timeval{tv_sec:
                                        
                                        
                                     time_now.tv_sec - time_main.tv_sec,
                                    tv_usec:
                                        
                                        
                                     time_now.tv_usec - time_main.tv_usec, ..
    time_delta};
    if time_delta.tv_usec < 0i64 {
        time_delta.tv_sec -= 1;
        time_delta.tv_usec += 1000000i64
    }
    fprintf(stderr, b"[%u.%03u] \x00" as *const u8 as *const libc::c_char,
            time_delta.tv_sec as libc::c_uint,
            (time_delta.tv_usec as
                 libc::c_uint).wrapping_div(1000u32));
}
#[no_mangle]
pub unsafe extern "C" fn debug_printf_stack(mut format: *const libc::c_char,
                                            mut args: ...) {
    
      let mut ap =   args.clone();
    vprintf(format, ap.as_va_list());
}
unsafe extern "C" fn handle_association_change_event(mut sac:
                                                         *mut sctp_assoc_change) {
    
         let mut i =      0; 
    fprintf(stderr,
            b"Association change \x00" as *const u8 as *const libc::c_char);
    match (*sac).sac_state as libc::c_int {
        1 => {
            fprintf(stderr,
                    b"SCTP_COMM_UP\x00" as *const u8 as *const libc::c_char);
        }
        2 => {
            fprintf(stderr,
                    b"SCTP_COMM_LOST\x00" as *const u8 as
                        *const libc::c_char);
        }
        3 => {
            fprintf(stderr,
                    b"SCTP_RESTART\x00" as *const u8 as *const libc::c_char);
        }
        4 => {
            fprintf(stderr,
                    b"SCTP_SHUTDOWN_COMP\x00" as *const u8 as
                        *const libc::c_char);
        }
        5 => {
            fprintf(stderr,
                    b"SCTP_CANT_STR_ASSOC\x00" as *const u8 as
                        *const libc::c_char);
        }
        _ => {
            fprintf(stderr,
                    b"UNKNOWN\x00" as *const u8 as *const libc::c_char);
        }
    }
    fprintf(stderr,
            b", streams (in/out) = (%u/%u)\x00" as *const u8 as
                *const libc::c_char,
            (*sac).sac_inbound_streams as libc::c_int,
            (*sac).sac_outbound_streams as libc::c_int);
     let mut n =
    
        ((*sac).sac_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_assoc_change>()
                                             as libc::c_ulong) as
            libc::c_uint;
    if ((*sac).sac_state as libc::c_int == 0x1i32 ||
            (*sac).sac_state as libc::c_int == 0x3i32) &&
           n > 0u32 {
        fprintf(stderr,
                b", supports\x00" as *const u8 as *const libc::c_char);
        i = 0u32;
        while i < n {
            match *(*sac).sac_info.as_mut_ptr().offset(i as isize) as
                      libc::c_int {
                1 => {
                    fprintf(stderr,
                            b" PR\x00" as *const u8 as *const libc::c_char);
                }
                2 => {
                    fprintf(stderr,
                            b" AUTH\x00" as *const u8 as *const libc::c_char);
                }
                3 => {
                    fprintf(stderr,
                            b" ASCONF\x00" as *const u8 as
                                *const libc::c_char);
                }
                4 => {
                    fprintf(stderr,
                            b" MULTIBUF\x00" as *const u8 as
                                *const libc::c_char);
                }
                5 => {
                    fprintf(stderr,
                            b" RE-CONFIG\x00" as *const u8 as
                                *const libc::c_char);
                }
                _ => {
                    fprintf(stderr,
                            b" UNKNOWN(0x%02x)\x00" as *const u8 as
                                *const libc::c_char,
                            *(*sac).sac_info.as_mut_ptr().offset(i as isize)
                                as libc::c_int);
                }
            }
            i = i.wrapping_add(1)
        }
    } else if ((*sac).sac_state as libc::c_int == 0x2i32 ||
                   (*sac).sac_state as libc::c_int == 0x5i32) &&
                  n > 0u32 {
        fprintf(stderr, b", ABORT =\x00" as *const u8 as *const libc::c_char);
        i = 0u32;
        while i < n {
            fprintf(stderr,
                    b" 0x%02x\x00" as *const u8 as *const libc::c_char,
                    *(*sac).sac_info.as_mut_ptr().offset(i as isize) as
                        libc::c_int);
            i = i.wrapping_add(1)
        }
    }
    fprintf(stderr, b".\n\x00" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn handle_peer_address_change_event(mut spc:
                                                          *mut sctp_paddr_change) {
    
    
    
    
                let mut addr_buf =      [0; 46]; let mut addr =      0 as *const libc::c_char;
    match (*spc).spc_aaddr.ss_family as libc::c_int {
        2 => {
                let mut sin =      0 as *mut sockaddr_in;sin =
                &mut (*spc).spc_aaddr as *mut sockaddr_storage as
                    *mut sockaddr_in;
            addr =
                inet_ntop(2i32,
                          &mut (*sin).sin_addr as *mut in_addr as
                              *const libc::c_void, addr_buf.as_mut_ptr(),
                          16u32)
        }
        10 => {
                let mut sin6 =      0 as *mut sockaddr_in6;sin6 =
                &mut (*spc).spc_aaddr as *mut sockaddr_storage as
                    *mut sockaddr_in6;
            addr =
                inet_ntop(10i32,
                          &mut (*sin6).sin6_addr as *mut in6_addr as
                              *const libc::c_void, addr_buf.as_mut_ptr(),
                          46u32)
        }
        123 => {
                let mut sconn =      0 as *mut sockaddr_conn;sconn =
                &mut (*spc).spc_aaddr as *mut sockaddr_storage as
                    *mut sockaddr_conn;
            snprintf(addr_buf.as_mut_ptr(),
                     46u64,
                     b"%p\x00" as *const u8 as *const libc::c_char,
                     (*sconn).sconn_addr);
            addr = addr_buf.as_mut_ptr()
        }
        _ => {
            snprintf(addr_buf.as_mut_ptr(),
                     46u64,
                     b"Unknown family %d\x00" as *const u8 as
                         *const libc::c_char,
                     (*spc).spc_aaddr.ss_family as libc::c_int);
            addr = addr_buf.as_mut_ptr()
        }
    }
    fprintf(stderr,
            b"Peer address %s is now \x00" as *const u8 as
                *const libc::c_char, addr);
    match (*spc).spc_state {
        1 => {
            fprintf(stderr,
                    b"SCTP_ADDR_AVAILABLE\x00" as *const u8 as
                        *const libc::c_char);
        }
        2 => {
            fprintf(stderr,
                    b"SCTP_ADDR_UNREACHABLE\x00" as *const u8 as
                        *const libc::c_char);
        }
        3 => {
            fprintf(stderr,
                    b"SCTP_ADDR_REMOVED\x00" as *const u8 as
                        *const libc::c_char);
        }
        4 => {
            fprintf(stderr,
                    b"SCTP_ADDR_ADDED\x00" as *const u8 as
                        *const libc::c_char);
        }
        5 => {
            fprintf(stderr,
                    b"SCTP_ADDR_MADE_PRIM\x00" as *const u8 as
                        *const libc::c_char);
        }
        6 => {
            fprintf(stderr,
                    b"SCTP_ADDR_CONFIRMED\x00" as *const u8 as
                        *const libc::c_char);
        }
        _ => {
            fprintf(stderr,
                    b"UNKNOWN\x00" as *const u8 as *const libc::c_char);
        }
    }
    fprintf(stderr,
            b" (error = 0x%08x).\n\x00" as *const u8 as *const libc::c_char,
            (*spc).spc_error);
}
unsafe extern "C" fn handle_send_failed_event(mut ssfe:
                                                  *mut sctp_send_failed_event) {
    
      
        let mut i =      0u64;if (*ssfe).ssfe_flags as libc::c_int & 0x1i32 != 0 {
        fprintf(stderr, b"Unsent \x00" as *const u8 as *const libc::c_char);
    }
    if (*ssfe).ssfe_flags as libc::c_int & 0x2i32 != 0 {
        fprintf(stderr, b"Sent \x00" as *const u8 as *const libc::c_char);
    }
    if (*ssfe).ssfe_flags as libc::c_int &
           !(0x2i32 | 0x1i32) != 0 {
        fprintf(stderr,
                b"(flags = %x) \x00" as *const u8 as *const libc::c_char,
                (*ssfe).ssfe_flags as libc::c_int);
    }
    fprintf(stderr,
            b"message with PPID = %u, SID = %u, flags: 0x%04x due to error = 0x%08x\x00"
                as *const u8 as *const libc::c_char,
            ntohl((*ssfe).ssfe_info.snd_ppid),
            (*ssfe).ssfe_info.snd_sid as libc::c_int,
            (*ssfe).ssfe_info.snd_flags as libc::c_int, (*ssfe).ssfe_error);
    
     let mut n =
    
        ((*ssfe).ssfe_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_send_failed_event>()
                                             as libc::c_ulong); 
    while i < n {
        fprintf(stderr, b" 0x%02x\x00" as *const u8 as *const libc::c_char,
                *(*ssfe).ssfe_data.as_mut_ptr().offset(i as isize) as
                    libc::c_int);
        i = i.wrapping_add(1)
    }
    fprintf(stderr, b".\n\x00" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn handle_adaptation_indication(mut sai:
                                                      *mut sctp_adaptation_event) {
    fprintf(stderr,
            b"Adaptation indication: %x.\n\x00" as *const u8 as
                *const libc::c_char, (*sai).sai_adaptation_ind);
}
unsafe extern "C" fn handle_shutdown_event(mut sse:
                                               *mut sctp_shutdown_event) {
    fprintf(stderr,
            b"Shutdown event.\n\x00" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn handle_stream_reset_event(mut strrst:
                                                   *mut sctp_stream_reset_event) {
    
      
         let mut i =      0u32;let mut n =
    
        ((*strrst).strreset_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_stream_reset_event>()
                                             as
                                             libc::c_ulong).wrapping_div(::std::mem::size_of::<uint16_t>()
                                                                             as
                                                                             libc::c_ulong)
            as uint32_t;
    fprintf(stderr,
            b"Stream reset event: flags = %x, \x00" as *const u8 as
                *const libc::c_char, (*strrst).strreset_flags as libc::c_int);
    if (*strrst).strreset_flags as libc::c_int & 0x1i32 != 0 {
        if (*strrst).strreset_flags as libc::c_int & 0x2i32 != 0 {
            fprintf(stderr,
                    b"incoming/\x00" as *const u8 as *const libc::c_char);
        }
        fprintf(stderr, b"incoming \x00" as *const u8 as *const libc::c_char);
    }
    if (*strrst).strreset_flags as libc::c_int & 0x2i32 != 0 {
        fprintf(stderr, b"outgoing \x00" as *const u8 as *const libc::c_char);
    }
    fprintf(stderr, b"stream ids = \x00" as *const u8 as *const libc::c_char);
     
    while i < n {
        if i > 0u32 {
            fprintf(stderr, b", \x00" as *const u8 as *const libc::c_char);
        }
        fprintf(stderr, b"%d\x00" as *const u8 as *const libc::c_char,
                *(*strrst).strreset_stream_list.as_mut_ptr().offset(i as
                                                                        isize)
                    as libc::c_int);
        i = i.wrapping_add(1)
    }
    fprintf(stderr, b".\n\x00" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn handle_stream_change_event(mut strchg:
                                                    *mut sctp_stream_change_event) {
    fprintf(stderr,
            b"Stream change event: streams (in/out) = (%u/%u), flags = %x.\n\x00"
                as *const u8 as *const libc::c_char,
            (*strchg).strchange_instrms as libc::c_int,
            (*strchg).strchange_outstrms as libc::c_int,
            (*strchg).strchange_flags as libc::c_int);
}
unsafe extern "C" fn handle_remote_error_event(mut sre:
                                                   *mut sctp_remote_error) {
    
      
         let mut i =      0u64;let mut n =
    
        ((*sre).sre_length as
             libc::c_ulong).wrapping_sub(::std::mem::size_of::<sctp_remote_error>()
                                             as libc::c_ulong);
    fprintf(stderr,
            b"Remote Error (error = 0x%04x): \x00" as *const u8 as
                *const libc::c_char, (*sre).sre_error as libc::c_int);
     
    while i < n {
        fprintf(stderr, b" 0x%02x\x00" as *const u8 as *const libc::c_char,
                *(*sre).sre_data.as_mut_ptr().offset(i as isize) as
                    libc::c_int);
        i = i.wrapping_add(1)
    }
    fprintf(stderr, b".\n\x00" as *const u8 as *const libc::c_char);
}
/* I-TSN */
/* optional param's follow */
#[no_mangle]
pub unsafe extern "C" fn handle_notification(mut notif:
                                                 *mut sctp_notification,
                                             mut n: size_t) {
    if (*notif).sn_header.sn_length != n as uint32_t { return }
    fprintf(stderr,
            b"handle_notification : \x00" as *const u8 as
                *const libc::c_char);
    match (*notif).sn_header.sn_type as libc::c_int {
        1 => {
            fprintf(stderr,
                    b"SCTP_ASSOC_CHANGE\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_association_change_event(&mut (*notif).sn_assoc_change);
        }
        2 => {
            fprintf(stderr,
                    b"SCTP_PEER_ADDR_CHANGE\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_peer_address_change_event(&mut (*notif).sn_paddr_change);
        }
        3 => {
            fprintf(stderr,
                    b"SCTP_REMOTE_ERROR\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_remote_error_event(&mut (*notif).sn_remote_error);
        }
        5 => {
            fprintf(stderr,
                    b"SCTP_SHUTDOWN_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_shutdown_event(&mut (*notif).sn_shutdown_event);
        }
        6 => {
            fprintf(stderr,
                    b"SCTP_ADAPTATION_INDICATION\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_adaptation_indication(&mut (*notif).sn_adaptation_event);
        }
        7 => {
            fprintf(stderr,
                    b"SCTP_PARTIAL_DELIVERY_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
        }
        8 => {
            fprintf(stderr,
                    b"SCTP_AUTHENTICATION_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
        }
        10 => {
            fprintf(stderr,
                    b"SCTP_SENDER_DRY_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
        }
        11 => {
            fprintf(stderr,
                    b"SCTP_NOTIFICATIONS_STOPPED_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
        }
        14 => {
            fprintf(stderr,
                    b"SCTP_SEND_FAILED_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_send_failed_event(&mut (*notif).sn_send_failed_event);
        }
        9 => {
            fprintf(stderr,
                    b"SCTP_STREAM_RESET_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_stream_reset_event(&mut (*notif).sn_strreset_event);
        }
        12 => {
            fprintf(stderr,
                    b"SCTP_ASSOC_RESET_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
        }
        13 => {
            fprintf(stderr,
                    b"SCTP_STREAM_CHANGE_EVENT\n\x00" as *const u8 as
                        *const libc::c_char);
            handle_stream_change_event(&mut (*notif).sn_strchange_event);
        }
        _ => { }
    };
}
