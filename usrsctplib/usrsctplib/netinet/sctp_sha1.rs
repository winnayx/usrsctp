use ::libc;
extern "C" {
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
}
pub type __uint32_t = libc::c_uint;

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
pub type uint32_t = __uint32_t;
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
/* block I am collecting to process */
/* collected so far */
#[no_mangle]
pub unsafe extern "C" fn sctp_sha1_init(mut ctx: *mut sctp_sha1_context) {
    /* Init the SHA-1 context structure */
    (*ctx).A = 0u32;
    (*ctx).B = 0u32;
    (*ctx).C = 0u32;
    (*ctx).D = 0u32;
    (*ctx).E = 0u32;
    (*ctx).H0 = 0x67452301u32;
    (*ctx).H1 = 0xefcdab89u32;
    (*ctx).H2 = 0x98badcfeu32;
    (*ctx).H3 = 0x10325476u32;
    (*ctx).H4 = 0xc3d2e1f0u32;
    (*ctx).TEMP = 0u32;
    memset(
        (*ctx).words.as_mut_ptr() as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<[libc::c_uint; 80]>() as libc::c_ulong,
    );
    (*ctx).how_many_in_block = 0i32;
    (*ctx).running_total = 0u32;
}
unsafe extern "C" fn sctp_sha1_process_a_block(
    mut ctx: *mut sctp_sha1_context,
    mut block: *mut libc::c_uint,
) {
    for i in 0i32..16i32 {
        (*ctx).words[i as usize] = ntohl(*block.offset(i as isize));
    }
    for i in 16i32..80i32 {
        (*ctx).words[i as usize] = ((*ctx).words[(i - 3i32) as usize]
            ^ (*ctx).words[(i - 8i32) as usize]
            ^ (*ctx).words[(i - 14i32) as usize]
            ^ (*ctx).words[(i - 16i32) as usize])
            << 1i32
            | ((*ctx).words[(i - 3i32) as usize]
                ^ (*ctx).words[(i - 8i32) as usize]
                ^ (*ctx).words[(i - 14i32) as usize]
                ^ (*ctx).words[(i - 16i32) as usize])
                >> 32i32 - 1i32;
    }
    /* step c) */
    (*ctx).A = (*ctx).H0;
    (*ctx).B = (*ctx).H1;
    (*ctx).C = (*ctx).H2;
    (*ctx).D = (*ctx).H3;
    (*ctx).E = (*ctx).H4;

    for i in 0i32..80i32 {
        if i < 20i32 {
            (*ctx).TEMP = ((*ctx).A << 5i32 | (*ctx).A >> 32i32 - 5i32)
                .wrapping_add((*ctx).B & (*ctx).C | !(*ctx).B & (*ctx).D)
                .wrapping_add((*ctx).E)
                .wrapping_add((*ctx).words[i as usize])
                .wrapping_add(0x5a827999u32)
        } else if i < 40i32 {
            (*ctx).TEMP = ((*ctx).A << 5i32 | (*ctx).A >> 32i32 - 5i32)
                .wrapping_add((*ctx).B ^ (*ctx).C ^ (*ctx).D)
                .wrapping_add((*ctx).E)
                .wrapping_add((*ctx).words[i as usize])
                .wrapping_add(0x6ed9eba1u32)
        } else if i < 60i32 {
            (*ctx).TEMP = ((*ctx).A << 5i32 | (*ctx).A >> 32i32 - 5i32)
                .wrapping_add((*ctx).B & (*ctx).C | (*ctx).B & (*ctx).D | (*ctx).C & (*ctx).D)
                .wrapping_add((*ctx).E)
                .wrapping_add((*ctx).words[i as usize])
                .wrapping_add(0x8f1bbcdcu32)
        } else {
            (*ctx).TEMP = ((*ctx).A << 5i32 | (*ctx).A >> 32i32 - 5i32)
                .wrapping_add((*ctx).B ^ (*ctx).C ^ (*ctx).D)
                .wrapping_add((*ctx).E)
                .wrapping_add((*ctx).words[i as usize])
                .wrapping_add(0xca62c1d6u32)
        }

        (*ctx).E = (*ctx).D;

        (*ctx).D = (*ctx).C;

        (*ctx).C = (*ctx).B << 30i32 | (*ctx).B >> 32i32 - 30i32;

        (*ctx).B = (*ctx).A;

        (*ctx).A = (*ctx).TEMP;
    }
    /* step e) */
    (*ctx).H0 = (*ctx).H0.wrapping_add((*ctx).A);
    (*ctx).H1 = (*ctx).H1.wrapping_add((*ctx).B);
    (*ctx).H2 = (*ctx).H2.wrapping_add((*ctx).C);
    (*ctx).H3 = (*ctx).H3.wrapping_add((*ctx).D);
    (*ctx).H4 = (*ctx).H4.wrapping_add((*ctx).E);
}
#[no_mangle]
pub unsafe extern "C" fn sctp_sha1_update(
    mut ctx: *mut sctp_sha1_context,
    mut ptr: *const libc::c_uchar,
    mut siz: libc::c_uint,
) {
    let mut number_left = 0;
    number_left = siz;
    while number_left > 0u32 {
        let mut left_to_fill = 0;
        left_to_fill = (::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong)
            .wrapping_sub((*ctx).how_many_in_block as libc::c_ulong)
            as libc::c_uint;
        if left_to_fill > number_left {
            /* can only partially fill up this one */
            memcpy(
                &mut *(*ctx)
                    .sha_block
                    .as_mut_ptr()
                    .offset((*ctx).how_many_in_block as isize) as *mut libc::c_char
                    as *mut libc::c_void,
                ptr as *const libc::c_void,
                number_left as libc::c_ulong,
            );
            (*ctx).how_many_in_block =
                ((*ctx).how_many_in_block as libc::c_uint).wrapping_add(number_left) as libc::c_int;
            (*ctx).running_total = (*ctx).running_total.wrapping_add(number_left);
            break;
        } else {
            /* block is now full, process it */
            memcpy(
                &mut *(*ctx)
                    .sha_block
                    .as_mut_ptr()
                    .offset((*ctx).how_many_in_block as isize) as *mut libc::c_char
                    as *mut libc::c_void,
                ptr as *const libc::c_void,
                left_to_fill as libc::c_ulong,
            );
            sctp_sha1_process_a_block(ctx, (*ctx).sha_block.as_mut_ptr() as *mut libc::c_uint);
            number_left = number_left.wrapping_sub(left_to_fill);
            (*ctx).running_total = (*ctx).running_total.wrapping_add(left_to_fill);
            (*ctx).how_many_in_block = 0i32;
            ptr = ptr.offset(left_to_fill as isize)
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn sctp_sha1_final(
    mut digest: *mut libc::c_uchar,
    mut ctx: *mut sctp_sha1_context,
) {
    let mut i = 0;
    let mut ptr = 0 as *mut libc::c_uint;
    if (*ctx).how_many_in_block > 55i32 {
        let mut left_to_fill = 0;
        left_to_fill = (::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong)
            .wrapping_sub((*ctx).how_many_in_block as libc::c_ulong)
            as libc::c_int;
        if left_to_fill == 0i32 {
            /* Should not really happen but I am paranoid */
            sctp_sha1_process_a_block(ctx, (*ctx).sha_block.as_mut_ptr() as *mut libc::c_uint);
            /* init last block, a bit different than the rest */
            (*ctx).sha_block[0usize] = -128i32 as libc::c_char;
            i = 1u32;
            while (i as libc::c_ulong)
                < ::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong
            {
                (*ctx).sha_block[i as usize] = 0i8;
                i = i.wrapping_add(1)
            }
        } else if left_to_fill == 1i32 {
            (*ctx).sha_block[(*ctx).how_many_in_block as usize] = -128i32 as libc::c_char;
            sctp_sha1_process_a_block(ctx, (*ctx).sha_block.as_mut_ptr() as *mut libc::c_uint);
            /* init last block */
            memset(
                (*ctx).sha_block.as_mut_ptr() as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
            );
        } else {
            (*ctx).sha_block[(*ctx).how_many_in_block as usize] = -128i32 as libc::c_char;
            i = ((*ctx).how_many_in_block + 1i32) as libc::c_uint;
            while (i as libc::c_ulong)
                < ::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong
            {
                (*ctx).sha_block[i as usize] = 0i8;
                i = i.wrapping_add(1)
            }
            sctp_sha1_process_a_block(ctx, (*ctx).sha_block.as_mut_ptr() as *mut libc::c_uint);
            /* init last block */
            memset(
                (*ctx).sha_block.as_mut_ptr() as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
            );
        }
        /* This is in bits so multiply by 8 */
        (*ctx).running_total = (*ctx).running_total.wrapping_mul(8u32);
        ptr = &mut *(*ctx).sha_block.as_mut_ptr().offset(60isize) as *mut libc::c_char
            as *mut libc::c_uint;
        *ptr = htonl((*ctx).running_total);
        sctp_sha1_process_a_block(ctx, (*ctx).sha_block.as_mut_ptr() as *mut libc::c_uint);
    } else {
        /*
         * easy case, we just pad this message to size - end with 0
         * add the magic 0x80 to the next word and then put the
         * network byte order size in the last spot and process the
         * block.
         */
        (*ctx).sha_block[(*ctx).how_many_in_block as usize] = -128i32 as libc::c_char;
        i = ((*ctx).how_many_in_block + 1i32) as libc::c_uint;
        while (i as libc::c_ulong) < ::std::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong {
            (*ctx).sha_block[i as usize] = 0i8;
            i = i.wrapping_add(1)
        }
        /* get last int spot */
        (*ctx).running_total = (*ctx).running_total.wrapping_mul(8u32);
        ptr = &mut *(*ctx).sha_block.as_mut_ptr().offset(60isize) as *mut libc::c_char
            as *mut libc::c_uint;
        *ptr = htonl((*ctx).running_total);
        sctp_sha1_process_a_block(ctx, (*ctx).sha_block.as_mut_ptr() as *mut libc::c_uint);
    }
    /* transfer the digest back to the user */
    *digest.offset(3isize) = ((*ctx).H0 & 0xffu32) as libc::c_uchar;
    *digest.offset(2isize) = ((*ctx).H0 >> 8i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(1isize) = ((*ctx).H0 >> 16i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(0isize) = ((*ctx).H0 >> 24i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(7isize) = ((*ctx).H1 & 0xffu32) as libc::c_uchar;
    *digest.offset(6isize) = ((*ctx).H1 >> 8i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(5isize) = ((*ctx).H1 >> 16i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(4isize) = ((*ctx).H1 >> 24i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(11isize) = ((*ctx).H2 & 0xffu32) as libc::c_uchar;
    *digest.offset(10isize) = ((*ctx).H2 >> 8i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(9isize) = ((*ctx).H2 >> 16i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(8isize) = ((*ctx).H2 >> 24i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(15isize) = ((*ctx).H3 & 0xffu32) as libc::c_uchar;
    *digest.offset(14isize) = ((*ctx).H3 >> 8i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(13isize) = ((*ctx).H3 >> 16i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(12isize) = ((*ctx).H3 >> 24i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(19isize) = ((*ctx).H4 & 0xffu32) as libc::c_uchar;
    *digest.offset(18isize) = ((*ctx).H4 >> 8i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(17isize) = ((*ctx).H4 >> 16i32 & 0xffu32) as libc::c_uchar;
    *digest.offset(16isize) = ((*ctx).H4 >> 24i32 & 0xffu32) as libc::c_uchar;
}
