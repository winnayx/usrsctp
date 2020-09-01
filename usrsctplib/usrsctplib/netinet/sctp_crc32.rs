use ::libc;
extern "C" {
    pub type ifnet;
    pub type iface;
}
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __caddr_t = *mut libc::c_char;
pub type u_int = __u_int;
pub type caddr_t = __caddr_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type sa_family_t = libc::c_ushort;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
/* sys/mutex.h typically on FreeBSD */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mtx {
    pub dummy: libc::c_int,
}
pub type uintptr_t = libc::c_ulong;
/* type of external storage */
/*
 * The core of the mbuf object along with some shortcut defined for practical
 * purposes.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mbuf {
    pub m_hdr: m_hdr,
    pub M_dat: C2RustUnnamed_266,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_266 {
    pub MH: C2RustUnnamed_267,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_267 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_268,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_268 {
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
    pub m_tag_link: C2RustUnnamed_269,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_269 {
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
pub struct ifaddr {
    pub ifa_addr: sockaddr,
    pub ifa_ifu: C2RustUnnamed_270,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_270 {
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
pub type sctp_rtentry_t = sctp_rtentry;
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
/* *
 *
 * Routine Description:
 *
 * Computes the CRC32c checksum for the specified buffer using the slicing by 8
 * algorithm over 64 bit quantities.
 *
 * Arguments:
 *
 *		p_running_crc - pointer to the initial or final remainder value
 *				used in CRC computations. It should be set to
 *				non-NULL if the mode argument is equal to CONT or END
 *		p_buf - the packet buffer where crc computations are being performed
 *		length - the length of p_buf in bytes
 *		init_bytes - the number of initial bytes that need to be procesed before
 *					 aligning p_buf to multiples of 4 bytes
 *		mode - can be any of the following: BEGIN, CONT, END, BODY, ALIGN
 *
 * Return value:
 *
 *		The computed CRC32c value
 */
/*
 * Copyright (c) 2004-2006 Intel Corporation - All Rights Reserved
 *
 *
 * This software program is licensed subject to the BSD License, available at
 * http://www.opensource.org/licenses/bsd-license.html.
 *
 * Abstract:
 *
 * Tables for software CRC generation
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o32: [uint32_t; 256] = [
    0u32,
    0xf26b8303u32,
    0xe13b70f7u32,
    0x1350f3f4u32,
    0xc79a971fu32,
    0x35f1141cu32,
    0x26a1e7e8u32,
    0xd4ca64ebu32,
    0x8ad958cfu32,
    0x78b2dbccu32,
    0x6be22838u32,
    0x9989ab3bu32,
    0x4d43cfd0u32,
    0xbf284cd3u32,
    0xac78bf27u32,
    0x5e133c24u32,
    0x105ec76fu32,
    0xe235446cu32,
    0xf165b798u32,
    0x30e349bu32,
    0xd7c45070u32,
    0x25afd373u32,
    0x36ff2087u32,
    0xc494a384u32,
    0x9a879fa0u32,
    0x68ec1ca3u32,
    0x7bbcef57u32,
    0x89d76c54u32,
    0x5d1d08bfu32,
    0xaf768bbcu32,
    0xbc267848u32,
    0x4e4dfb4bu32,
    0x20bd8edeu32,
    0xd2d60dddu32,
    0xc186fe29u32,
    0x33ed7d2au32,
    0xe72719c1u32,
    0x154c9ac2u32,
    0x61c6936u32,
    0xf477ea35u32,
    0xaa64d611u32,
    0x580f5512u32,
    0x4b5fa6e6u32,
    0xb93425e5u32,
    0x6dfe410eu32,
    0x9f95c20du32,
    0x8cc531f9u32,
    0x7eaeb2fau32,
    0x30e349b1u32,
    0xc288cab2u32,
    0xd1d83946u32,
    0x23b3ba45u32,
    0xf779deaeu32,
    0x5125dadu32,
    0x1642ae59u32,
    0xe4292d5au32,
    0xba3a117eu32,
    0x4851927du32,
    0x5b016189u32,
    0xa96ae28au32,
    0x7da08661u32,
    0x8fcb0562u32,
    0x9c9bf696u32,
    0x6ef07595u32,
    0x417b1dbcu32,
    0xb3109ebfu32,
    0xa0406d4bu32,
    0x522bee48u32,
    0x86e18aa3u32,
    0x748a09a0u32,
    0x67dafa54u32,
    0x95b17957u32,
    0xcba24573u32,
    0x39c9c670u32,
    0x2a993584u32,
    0xd8f2b687u32,
    0xc38d26cu32,
    0xfe53516fu32,
    0xed03a29bu32,
    0x1f682198u32,
    0x5125dad3u32,
    0xa34e59d0u32,
    0xb01eaa24u32,
    0x42752927u32,
    0x96bf4dccu32,
    0x64d4cecfu32,
    0x77843d3bu32,
    0x85efbe38u32,
    0xdbfc821cu32,
    0x2997011fu32,
    0x3ac7f2ebu32,
    0xc8ac71e8u32,
    0x1c661503u32,
    0xee0d9600u32,
    0xfd5d65f4u32,
    0xf36e6f7u32,
    0x61c69362u32,
    0x93ad1061u32,
    0x80fde395u32,
    0x72966096u32,
    0xa65c047du32,
    0x5437877eu32,
    0x4767748au32,
    0xb50cf789u32,
    0xeb1fcbadu32,
    0x197448aeu32,
    0xa24bb5au32,
    0xf84f3859u32,
    0x2c855cb2u32,
    0xdeeedfb1u32,
    0xcdbe2c45u32,
    0x3fd5af46u32,
    0x7198540du32,
    0x83f3d70eu32,
    0x90a324fau32,
    0x62c8a7f9u32,
    0xb602c312u32,
    0x44694011u32,
    0x5739b3e5u32,
    0xa55230e6u32,
    0xfb410cc2u32,
    0x92a8fc1u32,
    0x1a7a7c35u32,
    0xe811ff36u32,
    0x3cdb9bddu32,
    0xceb018deu32,
    0xdde0eb2au32,
    0x2f8b6829u32,
    0x82f63b78u32,
    0x709db87bu32,
    0x63cd4b8fu32,
    0x91a6c88cu32,
    0x456cac67u32,
    0xb7072f64u32,
    0xa457dc90u32,
    0x563c5f93u32,
    0x82f63b7u32,
    0xfa44e0b4u32,
    0xe9141340u32,
    0x1b7f9043u32,
    0xcfb5f4a8u32,
    0x3dde77abu32,
    0x2e8e845fu32,
    0xdce5075cu32,
    0x92a8fc17u32,
    0x60c37f14u32,
    0x73938ce0u32,
    0x81f80fe3u32,
    0x55326b08u32,
    0xa759e80bu32,
    0xb4091bffu32,
    0x466298fcu32,
    0x1871a4d8u32,
    0xea1a27dbu32,
    0xf94ad42fu32,
    0xb21572cu32,
    0xdfeb33c7u32,
    0x2d80b0c4u32,
    0x3ed04330u32,
    0xccbbc033u32,
    0xa24bb5a6u32,
    0x502036a5u32,
    0x4370c551u32,
    0xb11b4652u32,
    0x65d122b9u32,
    0x97baa1bau32,
    0x84ea524eu32,
    0x7681d14du32,
    0x2892ed69u32,
    0xdaf96e6au32,
    0xc9a99d9eu32,
    0x3bc21e9du32,
    0xef087a76u32,
    0x1d63f975u32,
    0xe330a81u32,
    0xfc588982u32,
    0xb21572c9u32,
    0x407ef1cau32,
    0x532e023eu32,
    0xa145813du32,
    0x758fe5d6u32,
    0x87e466d5u32,
    0x94b49521u32,
    0x66df1622u32,
    0x38cc2a06u32,
    0xcaa7a905u32,
    0xd9f75af1u32,
    0x2b9cd9f2u32,
    0xff56bd19u32,
    0xd3d3e1au32,
    0x1e6dcdeeu32,
    0xec064eedu32,
    0xc38d26c4u32,
    0x31e6a5c7u32,
    0x22b65633u32,
    0xd0ddd530u32,
    0x417b1dbu32,
    0xf67c32d8u32,
    0xe52cc12cu32,
    0x1747422fu32,
    0x49547e0bu32,
    0xbb3ffd08u32,
    0xa86f0efcu32,
    0x5a048dffu32,
    0x8ecee914u32,
    0x7ca56a17u32,
    0x6ff599e3u32,
    0x9d9e1ae0u32,
    0xd3d3e1abu32,
    0x21b862a8u32,
    0x32e8915cu32,
    0xc083125fu32,
    0x144976b4u32,
    0xe622f5b7u32,
    0xf5720643u32,
    0x7198540u32,
    0x590ab964u32,
    0xab613a67u32,
    0xb831c993u32,
    0x4a5a4a90u32,
    0x9e902e7bu32,
    0x6cfbad78u32,
    0x7fab5e8cu32,
    0x8dc0dd8fu32,
    0xe330a81au32,
    0x115b2b19u32,
    0x20bd8edu32,
    0xf0605beeu32,
    0x24aa3f05u32,
    0xd6c1bc06u32,
    0xc5914ff2u32,
    0x37faccf1u32,
    0x69e9f0d5u32,
    0x9b8273d6u32,
    0x88d28022u32,
    0x7ab90321u32,
    0xae7367cau32,
    0x5c18e4c9u32,
    0x4f48173du32,
    0xbd23943eu32,
    0xf36e6f75u32,
    0x105ec76u32,
    0x12551f82u32,
    0xe03e9c81u32,
    0x34f4f86au32,
    0xc69f7b69u32,
    0xd5cf889du32,
    0x27a40b9eu32,
    0x79b737bau32,
    0x8bdcb4b9u32,
    0x988c474du32,
    0x6ae7c44eu32,
    0xbe2da0a5u32,
    0x4c4623a6u32,
    0x5f16d052u32,
    0xad7d5351u32,
];
/*
 * end of the CRC lookup table crc_tableil8_o32
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o40: [uint32_t; 256] = [
    0u32,
    0x13a29877u32,
    0x274530eeu32,
    0x34e7a899u32,
    0x4e8a61dcu32,
    0x5d28f9abu32,
    0x69cf5132u32,
    0x7a6dc945u32,
    0x9d14c3b8u32,
    0x8eb65bcfu32,
    0xba51f356u32,
    0xa9f36b21u32,
    0xd39ea264u32,
    0xc03c3a13u32,
    0xf4db928au32,
    0xe7790afdu32,
    0x3fc5f181u32,
    0x2c6769f6u32,
    0x1880c16fu32,
    0xb225918u32,
    0x714f905du32,
    0x62ed082au32,
    0x560aa0b3u32,
    0x45a838c4u32,
    0xa2d13239u32,
    0xb173aa4eu32,
    0x859402d7u32,
    0x96369aa0u32,
    0xec5b53e5u32,
    0xfff9cb92u32,
    0xcb1e630bu32,
    0xd8bcfb7cu32,
    0x7f8be302u32,
    0x6c297b75u32,
    0x58ced3ecu32,
    0x4b6c4b9bu32,
    0x310182deu32,
    0x22a31aa9u32,
    0x1644b230u32,
    0x5e62a47u32,
    0xe29f20bau32,
    0xf13db8cdu32,
    0xc5da1054u32,
    0xd6788823u32,
    0xac154166u32,
    0xbfb7d911u32,
    0x8b507188u32,
    0x98f2e9ffu32,
    0x404e1283u32,
    0x53ec8af4u32,
    0x670b226du32,
    0x74a9ba1au32,
    0xec4735fu32,
    0x1d66eb28u32,
    0x298143b1u32,
    0x3a23dbc6u32,
    0xdd5ad13bu32,
    0xcef8494cu32,
    0xfa1fe1d5u32,
    0xe9bd79a2u32,
    0x93d0b0e7u32,
    0x80722890u32,
    0xb4958009u32,
    0xa737187eu32,
    0xff17c604u32,
    0xecb55e73u32,
    0xd852f6eau32,
    0xcbf06e9du32,
    0xb19da7d8u32,
    0xa23f3fafu32,
    0x96d89736u32,
    0x857a0f41u32,
    0x620305bcu32,
    0x71a19dcbu32,
    0x45463552u32,
    0x56e4ad25u32,
    0x2c896460u32,
    0x3f2bfc17u32,
    0xbcc548eu32,
    0x186eccf9u32,
    0xc0d23785u32,
    0xd370aff2u32,
    0xe797076bu32,
    0xf4359f1cu32,
    0x8e585659u32,
    0x9dface2eu32,
    0xa91d66b7u32,
    0xbabffec0u32,
    0x5dc6f43du32,
    0x4e646c4au32,
    0x7a83c4d3u32,
    0x69215ca4u32,
    0x134c95e1u32,
    0xee0d96u32,
    0x3409a50fu32,
    0x27ab3d78u32,
    0x809c2506u32,
    0x933ebd71u32,
    0xa7d915e8u32,
    0xb47b8d9fu32,
    0xce1644dau32,
    0xddb4dcadu32,
    0xe9537434u32,
    0xfaf1ec43u32,
    0x1d88e6beu32,
    0xe2a7ec9u32,
    0x3acdd650u32,
    0x296f4e27u32,
    0x53028762u32,
    0x40a01f15u32,
    0x7447b78cu32,
    0x67e52ffbu32,
    0xbf59d487u32,
    0xacfb4cf0u32,
    0x981ce469u32,
    0x8bbe7c1eu32,
    0xf1d3b55bu32,
    0xe2712d2cu32,
    0xd69685b5u32,
    0xc5341dc2u32,
    0x224d173fu32,
    0x31ef8f48u32,
    0x50827d1u32,
    0x16aabfa6u32,
    0x6cc776e3u32,
    0x7f65ee94u32,
    0x4b82460du32,
    0x5820de7au32,
    0xfbc3faf9u32,
    0xe861628eu32,
    0xdc86ca17u32,
    0xcf245260u32,
    0xb5499b25u32,
    0xa6eb0352u32,
    0x920cabcbu32,
    0x81ae33bcu32,
    0x66d73941u32,
    0x7575a136u32,
    0x419209afu32,
    0x523091d8u32,
    0x285d589du32,
    0x3bffc0eau32,
    0xf186873u32,
    0x1cbaf004u32,
    0xc4060b78u32,
    0xd7a4930fu32,
    0xe3433b96u32,
    0xf0e1a3e1u32,
    0x8a8c6aa4u32,
    0x992ef2d3u32,
    0xadc95a4au32,
    0xbe6bc23du32,
    0x5912c8c0u32,
    0x4ab050b7u32,
    0x7e57f82eu32,
    0x6df56059u32,
    0x1798a91cu32,
    0x43a316bu32,
    0x30dd99f2u32,
    0x237f0185u32,
    0x844819fbu32,
    0x97ea818cu32,
    0xa30d2915u32,
    0xb0afb162u32,
    0xcac27827u32,
    0xd960e050u32,
    0xed8748c9u32,
    0xfe25d0beu32,
    0x195cda43u32,
    0xafe4234u32,
    0x3e19eaadu32,
    0x2dbb72dau32,
    0x57d6bb9fu32,
    0x447423e8u32,
    0x70938b71u32,
    0x63311306u32,
    0xbb8de87au32,
    0xa82f700du32,
    0x9cc8d894u32,
    0x8f6a40e3u32,
    0xf50789a6u32,
    0xe6a511d1u32,
    0xd242b948u32,
    0xc1e0213fu32,
    0x26992bc2u32,
    0x353bb3b5u32,
    0x1dc1b2cu32,
    0x127e835bu32,
    0x68134a1eu32,
    0x7bb1d269u32,
    0x4f567af0u32,
    0x5cf4e287u32,
    0x4d43cfdu32,
    0x1776a48au32,
    0x23910c13u32,
    0x30339464u32,
    0x4a5e5d21u32,
    0x59fcc556u32,
    0x6d1b6dcfu32,
    0x7eb9f5b8u32,
    0x99c0ff45u32,
    0x8a626732u32,
    0xbe85cfabu32,
    0xad2757dcu32,
    0xd74a9e99u32,
    0xc4e806eeu32,
    0xf00fae77u32,
    0xe3ad3600u32,
    0x3b11cd7cu32,
    0x28b3550bu32,
    0x1c54fd92u32,
    0xff665e5u32,
    0x759baca0u32,
    0x663934d7u32,
    0x52de9c4eu32,
    0x417c0439u32,
    0xa6050ec4u32,
    0xb5a796b3u32,
    0x81403e2au32,
    0x92e2a65du32,
    0xe88f6f18u32,
    0xfb2df76fu32,
    0xcfca5ff6u32,
    0xdc68c781u32,
    0x7b5fdfffu32,
    0x68fd4788u32,
    0x5c1aef11u32,
    0x4fb87766u32,
    0x35d5be23u32,
    0x26772654u32,
    0x12908ecdu32,
    0x13216bau32,
    0xe64b1c47u32,
    0xf5e98430u32,
    0xc10e2ca9u32,
    0xd2acb4deu32,
    0xa8c17d9bu32,
    0xbb63e5ecu32,
    0x8f844d75u32,
    0x9c26d502u32,
    0x449a2e7eu32,
    0x5738b609u32,
    0x63df1e90u32,
    0x707d86e7u32,
    0xa104fa2u32,
    0x19b2d7d5u32,
    0x2d557f4cu32,
    0x3ef7e73bu32,
    0xd98eedc6u32,
    0xca2c75b1u32,
    0xfecbdd28u32,
    0xed69455fu32,
    0x97048c1au32,
    0x84a6146du32,
    0xb041bcf4u32,
    0xa3e32483u32,
];
/*
 * end of the CRC lookup table crc_tableil8_o40
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o48: [uint32_t; 256] = [
    0u32,
    0xa541927eu32,
    0x4f6f520du32,
    0xea2ec073u32,
    0x9edea41au32,
    0x3b9f3664u32,
    0xd1b1f617u32,
    0x74f06469u32,
    0x38513ec5u32,
    0x9d10acbbu32,
    0x773e6cc8u32,
    0xd27ffeb6u32,
    0xa68f9adfu32,
    0x3ce08a1u32,
    0xe9e0c8d2u32,
    0x4ca15aacu32,
    0x70a27d8au32,
    0xd5e3eff4u32,
    0x3fcd2f87u32,
    0x9a8cbdf9u32,
    0xee7cd990u32,
    0x4b3d4beeu32,
    0xa1138b9du32,
    0x45219e3u32,
    0x48f3434fu32,
    0xedb2d131u32,
    0x79c1142u32,
    0xa2dd833cu32,
    0xd62de755u32,
    0x736c752bu32,
    0x9942b558u32,
    0x3c032726u32,
    0xe144fb14u32,
    0x4405696au32,
    0xae2ba919u32,
    0xb6a3b67u32,
    0x7f9a5f0eu32,
    0xdadbcd70u32,
    0x30f50d03u32,
    0x95b49f7du32,
    0xd915c5d1u32,
    0x7c5457afu32,
    0x967a97dcu32,
    0x333b05a2u32,
    0x47cb61cbu32,
    0xe28af3b5u32,
    0x8a433c6u32,
    0xade5a1b8u32,
    0x91e6869eu32,
    0x34a714e0u32,
    0xde89d493u32,
    0x7bc846edu32,
    0xf382284u32,
    0xaa79b0fau32,
    0x40577089u32,
    0xe516e2f7u32,
    0xa9b7b85bu32,
    0xcf62a25u32,
    0xe6d8ea56u32,
    0x43997828u32,
    0x37691c41u32,
    0x92288e3fu32,
    0x78064e4cu32,
    0xdd47dc32u32,
    0xc76580d9u32,
    0x622412a7u32,
    0x880ad2d4u32,
    0x2d4b40aau32,
    0x59bb24c3u32,
    0xfcfab6bdu32,
    0x16d476ceu32,
    0xb395e4b0u32,
    0xff34be1cu32,
    0x5a752c62u32,
    0xb05bec11u32,
    0x151a7e6fu32,
    0x61ea1a06u32,
    0xc4ab8878u32,
    0x2e85480bu32,
    0x8bc4da75u32,
    0xb7c7fd53u32,
    0x12866f2du32,
    0xf8a8af5eu32,
    0x5de93d20u32,
    0x29195949u32,
    0x8c58cb37u32,
    0x66760b44u32,
    0xc337993au32,
    0x8f96c396u32,
    0x2ad751e8u32,
    0xc0f9919bu32,
    0x65b803e5u32,
    0x1148678cu32,
    0xb409f5f2u32,
    0x5e273581u32,
    0xfb66a7ffu32,
    0x26217bcdu32,
    0x8360e9b3u32,
    0x694e29c0u32,
    0xcc0fbbbeu32,
    0xb8ffdfd7u32,
    0x1dbe4da9u32,
    0xf7908ddau32,
    0x52d11fa4u32,
    0x1e704508u32,
    0xbb31d776u32,
    0x511f1705u32,
    0xf45e857bu32,
    0x80aee112u32,
    0x25ef736cu32,
    0xcfc1b31fu32,
    0x6a802161u32,
    0x56830647u32,
    0xf3c29439u32,
    0x19ec544au32,
    0xbcadc634u32,
    0xc85da25du32,
    0x6d1c3023u32,
    0x8732f050u32,
    0x2273622eu32,
    0x6ed23882u32,
    0xcb93aafcu32,
    0x21bd6a8fu32,
    0x84fcf8f1u32,
    0xf00c9c98u32,
    0x554d0ee6u32,
    0xbf63ce95u32,
    0x1a225cebu32,
    0x8b277743u32,
    0x2e66e53du32,
    0xc448254eu32,
    0x6109b730u32,
    0x15f9d359u32,
    0xb0b84127u32,
    0x5a968154u32,
    0xffd7132au32,
    0xb3764986u32,
    0x1637dbf8u32,
    0xfc191b8bu32,
    0x595889f5u32,
    0x2da8ed9cu32,
    0x88e97fe2u32,
    0x62c7bf91u32,
    0xc7862defu32,
    0xfb850ac9u32,
    0x5ec498b7u32,
    0xb4ea58c4u32,
    0x11abcabau32,
    0x655baed3u32,
    0xc01a3cadu32,
    0x2a34fcdeu32,
    0x8f756ea0u32,
    0xc3d4340cu32,
    0x6695a672u32,
    0x8cbb6601u32,
    0x29faf47fu32,
    0x5d0a9016u32,
    0xf84b0268u32,
    0x1265c21bu32,
    0xb7245065u32,
    0x6a638c57u32,
    0xcf221e29u32,
    0x250cde5au32,
    0x804d4c24u32,
    0xf4bd284du32,
    0x51fcba33u32,
    0xbbd27a40u32,
    0x1e93e83eu32,
    0x5232b292u32,
    0xf77320ecu32,
    0x1d5de09fu32,
    0xb81c72e1u32,
    0xccec1688u32,
    0x69ad84f6u32,
    0x83834485u32,
    0x26c2d6fbu32,
    0x1ac1f1ddu32,
    0xbf8063a3u32,
    0x55aea3d0u32,
    0xf0ef31aeu32,
    0x841f55c7u32,
    0x215ec7b9u32,
    0xcb7007cau32,
    0x6e3195b4u32,
    0x2290cf18u32,
    0x87d15d66u32,
    0x6dff9d15u32,
    0xc8be0f6bu32,
    0xbc4e6b02u32,
    0x190ff97cu32,
    0xf321390fu32,
    0x5660ab71u32,
    0x4c42f79au32,
    0xe90365e4u32,
    0x32da597u32,
    0xa66c37e9u32,
    0xd29c5380u32,
    0x77ddc1feu32,
    0x9df3018du32,
    0x38b293f3u32,
    0x7413c95fu32,
    0xd1525b21u32,
    0x3b7c9b52u32,
    0x9e3d092cu32,
    0xeacd6d45u32,
    0x4f8cff3bu32,
    0xa5a23f48u32,
    0xe3ad36u32,
    0x3ce08a10u32,
    0x99a1186eu32,
    0x738fd81du32,
    0xd6ce4a63u32,
    0xa23e2e0au32,
    0x77fbc74u32,
    0xed517c07u32,
    0x4810ee79u32,
    0x4b1b4d5u32,
    0xa1f026abu32,
    0x4bdee6d8u32,
    0xee9f74a6u32,
    0x9a6f10cfu32,
    0x3f2e82b1u32,
    0xd50042c2u32,
    0x7041d0bcu32,
    0xad060c8eu32,
    0x8479ef0u32,
    0xe2695e83u32,
    0x4728ccfdu32,
    0x33d8a894u32,
    0x96993aeau32,
    0x7cb7fa99u32,
    0xd9f668e7u32,
    0x9557324bu32,
    0x3016a035u32,
    0xda386046u32,
    0x7f79f238u32,
    0xb899651u32,
    0xaec8042fu32,
    0x44e6c45cu32,
    0xe1a75622u32,
    0xdda47104u32,
    0x78e5e37au32,
    0x92cb2309u32,
    0x378ab177u32,
    0x437ad51eu32,
    0xe63b4760u32,
    0xc158713u32,
    0xa954156du32,
    0xe5f54fc1u32,
    0x40b4ddbfu32,
    0xaa9a1dccu32,
    0xfdb8fb2u32,
    0x7b2bebdbu32,
    0xde6a79a5u32,
    0x3444b9d6u32,
    0x91052ba8u32,
];
/*
 * end of the CRC lookup table crc_tableil8_o48
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o56: [uint32_t; 256] = [
    0u32,
    0xdd45aab8u32,
    0xbf672381u32,
    0x62228939u32,
    0x7b2231f3u32,
    0xa6679b4bu32,
    0xc4451272u32,
    0x1900b8cau32,
    0xf64463e6u32,
    0x2b01c95eu32,
    0x49234067u32,
    0x9466eadfu32,
    0x8d665215u32,
    0x5023f8adu32,
    0x32017194u32,
    0xef44db2cu32,
    0xe964b13du32,
    0x34211b85u32,
    0x560392bcu32,
    0x8b463804u32,
    0x924680ceu32,
    0x4f032a76u32,
    0x2d21a34fu32,
    0xf06409f7u32,
    0x1f20d2dbu32,
    0xc2657863u32,
    0xa047f15au32,
    0x7d025be2u32,
    0x6402e328u32,
    0xb9474990u32,
    0xdb65c0a9u32,
    0x6206a11u32,
    0xd725148bu32,
    0xa60be33u32,
    0x6842370au32,
    0xb5079db2u32,
    0xac072578u32,
    0x71428fc0u32,
    0x136006f9u32,
    0xce25ac41u32,
    0x2161776du32,
    0xfc24ddd5u32,
    0x9e0654ecu32,
    0x4343fe54u32,
    0x5a43469eu32,
    0x8706ec26u32,
    0xe524651fu32,
    0x3861cfa7u32,
    0x3e41a5b6u32,
    0xe3040f0eu32,
    0x81268637u32,
    0x5c632c8fu32,
    0x45639445u32,
    0x98263efdu32,
    0xfa04b7c4u32,
    0x27411d7cu32,
    0xc805c650u32,
    0x15406ce8u32,
    0x7762e5d1u32,
    0xaa274f69u32,
    0xb327f7a3u32,
    0x6e625d1bu32,
    0xc40d422u32,
    0xd1057e9au32,
    0xaba65fe7u32,
    0x76e3f55fu32,
    0x14c17c66u32,
    0xc984d6deu32,
    0xd0846e14u32,
    0xdc1c4acu32,
    0x6fe34d95u32,
    0xb2a6e72du32,
    0x5de23c01u32,
    0x80a796b9u32,
    0xe2851f80u32,
    0x3fc0b538u32,
    0x26c00df2u32,
    0xfb85a74au32,
    0x99a72e73u32,
    0x44e284cbu32,
    0x42c2eedau32,
    0x9f874462u32,
    0xfda5cd5bu32,
    0x20e067e3u32,
    0x39e0df29u32,
    0xe4a57591u32,
    0x8687fca8u32,
    0x5bc25610u32,
    0xb4868d3cu32,
    0x69c32784u32,
    0xbe1aebdu32,
    0xd6a40405u32,
    0xcfa4bccfu32,
    0x12e11677u32,
    0x70c39f4eu32,
    0xad8635f6u32,
    0x7c834b6cu32,
    0xa1c6e1d4u32,
    0xc3e468edu32,
    0x1ea1c255u32,
    0x7a17a9fu32,
    0xdae4d027u32,
    0xb8c6591eu32,
    0x6583f3a6u32,
    0x8ac7288au32,
    0x57828232u32,
    0x35a00b0bu32,
    0xe8e5a1b3u32,
    0xf1e51979u32,
    0x2ca0b3c1u32,
    0x4e823af8u32,
    0x93c79040u32,
    0x95e7fa51u32,
    0x48a250e9u32,
    0x2a80d9d0u32,
    0xf7c57368u32,
    0xeec5cba2u32,
    0x3380611au32,
    0x51a2e823u32,
    0x8ce7429bu32,
    0x63a399b7u32,
    0xbee6330fu32,
    0xdcc4ba36u32,
    0x181108eu32,
    0x1881a844u32,
    0xc5c402fcu32,
    0xa7e68bc5u32,
    0x7aa3217du32,
    0x52a0c93fu32,
    0x8fe56387u32,
    0xedc7eabeu32,
    0x30824006u32,
    0x2982f8ccu32,
    0xf4c75274u32,
    0x96e5db4du32,
    0x4ba071f5u32,
    0xa4e4aad9u32,
    0x79a10061u32,
    0x1b838958u32,
    0xc6c623e0u32,
    0xdfc69b2au32,
    0x2833192u32,
    0x60a1b8abu32,
    0xbde41213u32,
    0xbbc47802u32,
    0x6681d2bau32,
    0x4a35b83u32,
    0xd9e6f13bu32,
    0xc0e649f1u32,
    0x1da3e349u32,
    0x7f816a70u32,
    0xa2c4c0c8u32,
    0x4d801be4u32,
    0x90c5b15cu32,
    0xf2e73865u32,
    0x2fa292ddu32,
    0x36a22a17u32,
    0xebe780afu32,
    0x89c50996u32,
    0x5480a32eu32,
    0x8585ddb4u32,
    0x58c0770cu32,
    0x3ae2fe35u32,
    0xe7a7548du32,
    0xfea7ec47u32,
    0x23e246ffu32,
    0x41c0cfc6u32,
    0x9c85657eu32,
    0x73c1be52u32,
    0xae8414eau32,
    0xcca69dd3u32,
    0x11e3376bu32,
    0x8e38fa1u32,
    0xd5a62519u32,
    0xb784ac20u32,
    0x6ac10698u32,
    0x6ce16c89u32,
    0xb1a4c631u32,
    0xd3864f08u32,
    0xec3e5b0u32,
    0x17c35d7au32,
    0xca86f7c2u32,
    0xa8a47efbu32,
    0x75e1d443u32,
    0x9aa50f6fu32,
    0x47e0a5d7u32,
    0x25c22ceeu32,
    0xf8878656u32,
    0xe1873e9cu32,
    0x3cc29424u32,
    0x5ee01d1du32,
    0x83a5b7a5u32,
    0xf90696d8u32,
    0x24433c60u32,
    0x4661b559u32,
    0x9b241fe1u32,
    0x8224a72bu32,
    0x5f610d93u32,
    0x3d4384aau32,
    0xe0062e12u32,
    0xf42f53eu32,
    0xd2075f86u32,
    0xb025d6bfu32,
    0x6d607c07u32,
    0x7460c4cdu32,
    0xa9256e75u32,
    0xcb07e74cu32,
    0x16424df4u32,
    0x106227e5u32,
    0xcd278d5du32,
    0xaf050464u32,
    0x7240aedcu32,
    0x6b401616u32,
    0xb605bcaeu32,
    0xd4273597u32,
    0x9629f2fu32,
    0xe6264403u32,
    0x3b63eebbu32,
    0x59416782u32,
    0x8404cd3au32,
    0x9d0475f0u32,
    0x4041df48u32,
    0x22635671u32,
    0xff26fcc9u32,
    0x2e238253u32,
    0xf36628ebu32,
    0x9144a1d2u32,
    0x4c010b6au32,
    0x5501b3a0u32,
    0x88441918u32,
    0xea669021u32,
    0x37233a99u32,
    0xd867e1b5u32,
    0x5224b0du32,
    0x6700c234u32,
    0xba45688cu32,
    0xa345d046u32,
    0x7e007afeu32,
    0x1c22f3c7u32,
    0xc167597fu32,
    0xc747336eu32,
    0x1a0299d6u32,
    0x782010efu32,
    0xa565ba57u32,
    0xbc65029du32,
    0x6120a825u32,
    0x302211cu32,
    0xde478ba4u32,
    0x31035088u32,
    0xec46fa30u32,
    0x8e647309u32,
    0x5321d9b1u32,
    0x4a21617bu32,
    0x9764cbc3u32,
    0xf54642fau32,
    0x2803e842u32,
];
/*
 * end of the CRC lookup table crc_tableil8_o56
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o64: [uint32_t; 256] = [
    0u32,
    0x38116facu32,
    0x7022df58u32,
    0x4833b0f4u32,
    0xe045beb0u32,
    0xd854d11cu32,
    0x906761e8u32,
    0xa8760e44u32,
    0xc5670b91u32,
    0xfd76643du32,
    0xb545d4c9u32,
    0x8d54bb65u32,
    0x2522b521u32,
    0x1d33da8du32,
    0x55006a79u32,
    0x6d1105d5u32,
    0x8f2261d3u32,
    0xb7330e7fu32,
    0xff00be8bu32,
    0xc711d127u32,
    0x6f67df63u32,
    0x5776b0cfu32,
    0x1f45003bu32,
    0x27546f97u32,
    0x4a456a42u32,
    0x725405eeu32,
    0x3a67b51au32,
    0x276dab6u32,
    0xaa00d4f2u32,
    0x9211bb5eu32,
    0xda220baau32,
    0xe2336406u32,
    0x1ba8b557u32,
    0x23b9dafbu32,
    0x6b8a6a0fu32,
    0x539b05a3u32,
    0xfbed0be7u32,
    0xc3fc644bu32,
    0x8bcfd4bfu32,
    0xb3debb13u32,
    0xdecfbec6u32,
    0xe6ded16au32,
    0xaeed619eu32,
    0x96fc0e32u32,
    0x3e8a0076u32,
    0x69b6fdau32,
    0x4ea8df2eu32,
    0x76b9b082u32,
    0x948ad484u32,
    0xac9bbb28u32,
    0xe4a80bdcu32,
    0xdcb96470u32,
    0x74cf6a34u32,
    0x4cde0598u32,
    0x4edb56cu32,
    0x3cfcdac0u32,
    0x51eddf15u32,
    0x69fcb0b9u32,
    0x21cf004du32,
    0x19de6fe1u32,
    0xb1a861a5u32,
    0x89b90e09u32,
    0xc18abefdu32,
    0xf99bd151u32,
    0x37516aaeu32,
    0xf400502u32,
    0x4773b5f6u32,
    0x7f62da5au32,
    0xd714d41eu32,
    0xef05bbb2u32,
    0xa7360b46u32,
    0x9f2764eau32,
    0xf236613fu32,
    0xca270e93u32,
    0x8214be67u32,
    0xba05d1cbu32,
    0x1273df8fu32,
    0x2a62b023u32,
    0x625100d7u32,
    0x5a406f7bu32,
    0xb8730b7du32,
    0x806264d1u32,
    0xc851d425u32,
    0xf040bb89u32,
    0x5836b5cdu32,
    0x6027da61u32,
    0x28146a95u32,
    0x10050539u32,
    0x7d1400ecu32,
    0x45056f40u32,
    0xd36dfb4u32,
    0x3527b018u32,
    0x9d51be5cu32,
    0xa540d1f0u32,
    0xed736104u32,
    0xd5620ea8u32,
    0x2cf9dff9u32,
    0x14e8b055u32,
    0x5cdb00a1u32,
    0x64ca6f0du32,
    0xccbc6149u32,
    0xf4ad0ee5u32,
    0xbc9ebe11u32,
    0x848fd1bdu32,
    0xe99ed468u32,
    0xd18fbbc4u32,
    0x99bc0b30u32,
    0xa1ad649cu32,
    0x9db6ad8u32,
    0x31ca0574u32,
    0x79f9b580u32,
    0x41e8da2cu32,
    0xa3dbbe2au32,
    0x9bcad186u32,
    0xd3f96172u32,
    0xebe80edeu32,
    0x439e009au32,
    0x7b8f6f36u32,
    0x33bcdfc2u32,
    0xbadb06eu32,
    0x66bcb5bbu32,
    0x5eadda17u32,
    0x169e6ae3u32,
    0x2e8f054fu32,
    0x86f90b0bu32,
    0xbee864a7u32,
    0xf6dbd453u32,
    0xcecabbffu32,
    0x6ea2d55cu32,
    0x56b3baf0u32,
    0x1e800a04u32,
    0x269165a8u32,
    0x8ee76becu32,
    0xb6f60440u32,
    0xfec5b4b4u32,
    0xc6d4db18u32,
    0xabc5decdu32,
    0x93d4b161u32,
    0xdbe70195u32,
    0xe3f66e39u32,
    0x4b80607du32,
    0x73910fd1u32,
    0x3ba2bf25u32,
    0x3b3d089u32,
    0xe180b48fu32,
    0xd991db23u32,
    0x91a26bd7u32,
    0xa9b3047bu32,
    0x1c50a3fu32,
    0x39d46593u32,
    0x71e7d567u32,
    0x49f6bacbu32,
    0x24e7bf1eu32,
    0x1cf6d0b2u32,
    0x54c56046u32,
    0x6cd40feau32,
    0xc4a201aeu32,
    0xfcb36e02u32,
    0xb480def6u32,
    0x8c91b15au32,
    0x750a600bu32,
    0x4d1b0fa7u32,
    0x528bf53u32,
    0x3d39d0ffu32,
    0x954fdebbu32,
    0xad5eb117u32,
    0xe56d01e3u32,
    0xdd7c6e4fu32,
    0xb06d6b9au32,
    0x887c0436u32,
    0xc04fb4c2u32,
    0xf85edb6eu32,
    0x5028d52au32,
    0x6839ba86u32,
    0x200a0a72u32,
    0x181b65deu32,
    0xfa2801d8u32,
    0xc2396e74u32,
    0x8a0ade80u32,
    0xb21bb12cu32,
    0x1a6dbf68u32,
    0x227cd0c4u32,
    0x6a4f6030u32,
    0x525e0f9cu32,
    0x3f4f0a49u32,
    0x75e65e5u32,
    0x4f6dd511u32,
    0x777cbabdu32,
    0xdf0ab4f9u32,
    0xe71bdb55u32,
    0xaf286ba1u32,
    0x9739040du32,
    0x59f3bff2u32,
    0x61e2d05eu32,
    0x29d160aau32,
    0x11c00f06u32,
    0xb9b60142u32,
    0x81a76eeeu32,
    0xc994de1au32,
    0xf185b1b6u32,
    0x9c94b463u32,
    0xa485dbcfu32,
    0xecb66b3bu32,
    0xd4a70497u32,
    0x7cd10ad3u32,
    0x44c0657fu32,
    0xcf3d58bu32,
    0x34e2ba27u32,
    0xd6d1de21u32,
    0xeec0b18du32,
    0xa6f30179u32,
    0x9ee26ed5u32,
    0x36946091u32,
    0xe850f3du32,
    0x46b6bfc9u32,
    0x7ea7d065u32,
    0x13b6d5b0u32,
    0x2ba7ba1cu32,
    0x63940ae8u32,
    0x5b856544u32,
    0xf3f36b00u32,
    0xcbe204acu32,
    0x83d1b458u32,
    0xbbc0dbf4u32,
    0x425b0aa5u32,
    0x7a4a6509u32,
    0x3279d5fdu32,
    0xa68ba51u32,
    0xa21eb415u32,
    0x9a0fdbb9u32,
    0xd23c6b4du32,
    0xea2d04e1u32,
    0x873c0134u32,
    0xbf2d6e98u32,
    0xf71ede6cu32,
    0xcf0fb1c0u32,
    0x6779bf84u32,
    0x5f68d028u32,
    0x175b60dcu32,
    0x2f4a0f70u32,
    0xcd796b76u32,
    0xf56804dau32,
    0xbd5bb42eu32,
    0x854adb82u32,
    0x2d3cd5c6u32,
    0x152dba6au32,
    0x5d1e0a9eu32,
    0x650f6532u32,
    0x81e60e7u32,
    0x300f0f4bu32,
    0x783cbfbfu32,
    0x402dd013u32,
    0xe85bde57u32,
    0xd04ab1fbu32,
    0x9879010fu32,
    0xa0686ea3u32,
];
/*
 * end of the CRC lookup table crc_tableil8_o64
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o72: [uint32_t; 256] = [
    0u32,
    0xef306b19u32,
    0xdb8ca0c3u32,
    0x34bccbdau32,
    0xb2f53777u32,
    0x5dc55c6eu32,
    0x697997b4u32,
    0x8649fcadu32,
    0x6006181fu32,
    0x8f367306u32,
    0xbb8ab8dcu32,
    0x54bad3c5u32,
    0xd2f32f68u32,
    0x3dc34471u32,
    0x97f8fabu32,
    0xe64fe4b2u32,
    0xc00c303eu32,
    0x2f3c5b27u32,
    0x1b8090fdu32,
    0xf4b0fbe4u32,
    0x72f90749u32,
    0x9dc96c50u32,
    0xa975a78au32,
    0x4645cc93u32,
    0xa00a2821u32,
    0x4f3a4338u32,
    0x7b8688e2u32,
    0x94b6e3fbu32,
    0x12ff1f56u32,
    0xfdcf744fu32,
    0xc973bf95u32,
    0x2643d48cu32,
    0x85f4168du32,
    0x6ac47d94u32,
    0x5e78b64eu32,
    0xb148dd57u32,
    0x370121fau32,
    0xd8314ae3u32,
    0xec8d8139u32,
    0x3bdea20u32,
    0xe5f20e92u32,
    0xac2658bu32,
    0x3e7eae51u32,
    0xd14ec548u32,
    0x570739e5u32,
    0xb83752fcu32,
    0x8c8b9926u32,
    0x63bbf23fu32,
    0x45f826b3u32,
    0xaac84daau32,
    0x9e748670u32,
    0x7144ed69u32,
    0xf70d11c4u32,
    0x183d7addu32,
    0x2c81b107u32,
    0xc3b1da1eu32,
    0x25fe3eacu32,
    0xcace55b5u32,
    0xfe729e6fu32,
    0x1142f576u32,
    0x970b09dbu32,
    0x783b62c2u32,
    0x4c87a918u32,
    0xa3b7c201u32,
    0xe045bebu32,
    0xe13430f2u32,
    0xd588fb28u32,
    0x3ab89031u32,
    0xbcf16c9cu32,
    0x53c10785u32,
    0x677dcc5fu32,
    0x884da746u32,
    0x6e0243f4u32,
    0x813228edu32,
    0xb58ee337u32,
    0x5abe882eu32,
    0xdcf77483u32,
    0x33c71f9au32,
    0x77bd440u32,
    0xe84bbf59u32,
    0xce086bd5u32,
    0x213800ccu32,
    0x1584cb16u32,
    0xfab4a00fu32,
    0x7cfd5ca2u32,
    0x93cd37bbu32,
    0xa771fc61u32,
    0x48419778u32,
    0xae0e73cau32,
    0x413e18d3u32,
    0x7582d309u32,
    0x9ab2b810u32,
    0x1cfb44bdu32,
    0xf3cb2fa4u32,
    0xc777e47eu32,
    0x28478f67u32,
    0x8bf04d66u32,
    0x64c0267fu32,
    0x507ceda5u32,
    0xbf4c86bcu32,
    0x39057a11u32,
    0xd6351108u32,
    0xe289dad2u32,
    0xdb9b1cbu32,
    0xebf65579u32,
    0x4c63e60u32,
    0x307af5bau32,
    0xdf4a9ea3u32,
    0x5903620eu32,
    0xb6330917u32,
    0x828fc2cdu32,
    0x6dbfa9d4u32,
    0x4bfc7d58u32,
    0xa4cc1641u32,
    0x9070dd9bu32,
    0x7f40b682u32,
    0xf9094a2fu32,
    0x16392136u32,
    0x2285eaecu32,
    0xcdb581f5u32,
    0x2bfa6547u32,
    0xc4ca0e5eu32,
    0xf076c584u32,
    0x1f46ae9du32,
    0x990f5230u32,
    0x763f3929u32,
    0x4283f2f3u32,
    0xadb399eau32,
    0x1c08b7d6u32,
    0xf338dccfu32,
    0xc7841715u32,
    0x28b47c0cu32,
    0xaefd80a1u32,
    0x41cdebb8u32,
    0x75712062u32,
    0x9a414b7bu32,
    0x7c0eafc9u32,
    0x933ec4d0u32,
    0xa7820f0au32,
    0x48b26413u32,
    0xcefb98beu32,
    0x21cbf3a7u32,
    0x1577387du32,
    0xfa475364u32,
    0xdc0487e8u32,
    0x3334ecf1u32,
    0x788272bu32,
    0xe8b84c32u32,
    0x6ef1b09fu32,
    0x81c1db86u32,
    0xb57d105cu32,
    0x5a4d7b45u32,
    0xbc029ff7u32,
    0x5332f4eeu32,
    0x678e3f34u32,
    0x88be542du32,
    0xef7a880u32,
    0xe1c7c399u32,
    0xd57b0843u32,
    0x3a4b635au32,
    0x99fca15bu32,
    0x76ccca42u32,
    0x42700198u32,
    0xad406a81u32,
    0x2b09962cu32,
    0xc439fd35u32,
    0xf08536efu32,
    0x1fb55df6u32,
    0xf9fab944u32,
    0x16cad25du32,
    0x22761987u32,
    0xcd46729eu32,
    0x4b0f8e33u32,
    0xa43fe52au32,
    0x90832ef0u32,
    0x7fb345e9u32,
    0x59f09165u32,
    0xb6c0fa7cu32,
    0x827c31a6u32,
    0x6d4c5abfu32,
    0xeb05a612u32,
    0x435cd0bu32,
    0x308906d1u32,
    0xdfb96dc8u32,
    0x39f6897au32,
    0xd6c6e263u32,
    0xe27a29b9u32,
    0xd4a42a0u32,
    0x8b03be0du32,
    0x6433d514u32,
    0x508f1eceu32,
    0xbfbf75d7u32,
    0x120cec3du32,
    0xfd3c8724u32,
    0xc9804cfeu32,
    0x26b027e7u32,
    0xa0f9db4au32,
    0x4fc9b053u32,
    0x7b757b89u32,
    0x94451090u32,
    0x720af422u32,
    0x9d3a9f3bu32,
    0xa98654e1u32,
    0x46b63ff8u32,
    0xc0ffc355u32,
    0x2fcfa84cu32,
    0x1b736396u32,
    0xf443088fu32,
    0xd200dc03u32,
    0x3d30b71au32,
    0x98c7cc0u32,
    0xe6bc17d9u32,
    0x60f5eb74u32,
    0x8fc5806du32,
    0xbb794bb7u32,
    0x544920aeu32,
    0xb206c41cu32,
    0x5d36af05u32,
    0x698a64dfu32,
    0x86ba0fc6u32,
    0xf3f36bu32,
    0xefc39872u32,
    0xdb7f53a8u32,
    0x344f38b1u32,
    0x97f8fab0u32,
    0x78c891a9u32,
    0x4c745a73u32,
    0xa344316au32,
    0x250dcdc7u32,
    0xca3da6deu32,
    0xfe816d04u32,
    0x11b1061du32,
    0xf7fee2afu32,
    0x18ce89b6u32,
    0x2c72426cu32,
    0xc3422975u32,
    0x450bd5d8u32,
    0xaa3bbec1u32,
    0x9e87751bu32,
    0x71b71e02u32,
    0x57f4ca8eu32,
    0xb8c4a197u32,
    0x8c786a4du32,
    0x63480154u32,
    0xe501fdf9u32,
    0xa3196e0u32,
    0x3e8d5d3au32,
    0xd1bd3623u32,
    0x37f2d291u32,
    0xd8c2b988u32,
    0xec7e7252u32,
    0x34e194bu32,
    0x8507e5e6u32,
    0x6a378effu32,
    0x5e8b4525u32,
    0xb1bb2e3cu32,
];
/*
 * end of the CRC lookup table crc_tableil8_o72
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o80: [uint32_t; 256] = [
    0u32,
    0x68032cc8u32,
    0xd0065990u32,
    0xb8057558u32,
    0xa5e0c5d1u32,
    0xcde3e919u32,
    0x75e69c41u32,
    0x1de5b089u32,
    0x4e2dfd53u32,
    0x262ed19bu32,
    0x9e2ba4c3u32,
    0xf628880bu32,
    0xebcd3882u32,
    0x83ce144au32,
    0x3bcb6112u32,
    0x53c84ddau32,
    0x9c5bfaa6u32,
    0xf458d66eu32,
    0x4c5da336u32,
    0x245e8ffeu32,
    0x39bb3f77u32,
    0x51b813bfu32,
    0xe9bd66e7u32,
    0x81be4a2fu32,
    0xd27607f5u32,
    0xba752b3du32,
    0x2705e65u32,
    0x6a7372adu32,
    0x7796c224u32,
    0x1f95eeecu32,
    0xa7909bb4u32,
    0xcf93b77cu32,
    0x3d5b83bdu32,
    0x5558af75u32,
    0xed5dda2du32,
    0x855ef6e5u32,
    0x98bb466cu32,
    0xf0b86aa4u32,
    0x48bd1ffcu32,
    0x20be3334u32,
    0x73767eeeu32,
    0x1b755226u32,
    0xa370277eu32,
    0xcb730bb6u32,
    0xd696bb3fu32,
    0xbe9597f7u32,
    0x690e2afu32,
    0x6e93ce67u32,
    0xa100791bu32,
    0xc90355d3u32,
    0x7106208bu32,
    0x19050c43u32,
    0x4e0bccau32,
    0x6ce39002u32,
    0xd4e6e55au32,
    0xbce5c992u32,
    0xef2d8448u32,
    0x872ea880u32,
    0x3f2bddd8u32,
    0x5728f110u32,
    0x4acd4199u32,
    0x22ce6d51u32,
    0x9acb1809u32,
    0xf2c834c1u32,
    0x7ab7077au32,
    0x12b42bb2u32,
    0xaab15eeau32,
    0xc2b27222u32,
    0xdf57c2abu32,
    0xb754ee63u32,
    0xf519b3bu32,
    0x6752b7f3u32,
    0x349afa29u32,
    0x5c99d6e1u32,
    0xe49ca3b9u32,
    0x8c9f8f71u32,
    0x917a3ff8u32,
    0xf9791330u32,
    0x417c6668u32,
    0x297f4aa0u32,
    0xe6ecfddcu32,
    0x8eefd114u32,
    0x36eaa44cu32,
    0x5ee98884u32,
    0x430c380du32,
    0x2b0f14c5u32,
    0x930a619du32,
    0xfb094d55u32,
    0xa8c1008fu32,
    0xc0c22c47u32,
    0x78c7591fu32,
    0x10c475d7u32,
    0xd21c55eu32,
    0x6522e996u32,
    0xdd279cceu32,
    0xb524b006u32,
    0x47ec84c7u32,
    0x2fefa80fu32,
    0x97eadd57u32,
    0xffe9f19fu32,
    0xe20c4116u32,
    0x8a0f6ddeu32,
    0x320a1886u32,
    0x5a09344eu32,
    0x9c17994u32,
    0x61c2555cu32,
    0xd9c72004u32,
    0xb1c40cccu32,
    0xac21bc45u32,
    0xc422908du32,
    0x7c27e5d5u32,
    0x1424c91du32,
    0xdbb77e61u32,
    0xb3b452a9u32,
    0xbb127f1u32,
    0x63b20b39u32,
    0x7e57bbb0u32,
    0x16549778u32,
    0xae51e220u32,
    0xc652cee8u32,
    0x959a8332u32,
    0xfd99affau32,
    0x459cdaa2u32,
    0x2d9ff66au32,
    0x307a46e3u32,
    0x58796a2bu32,
    0xe07c1f73u32,
    0x887f33bbu32,
    0xf56e0ef4u32,
    0x9d6d223cu32,
    0x25685764u32,
    0x4d6b7bacu32,
    0x508ecb25u32,
    0x388de7edu32,
    0x808892b5u32,
    0xe88bbe7du32,
    0xbb43f3a7u32,
    0xd340df6fu32,
    0x6b45aa37u32,
    0x34686ffu32,
    0x1ea33676u32,
    0x76a01abeu32,
    0xcea56fe6u32,
    0xa6a6432eu32,
    0x6935f452u32,
    0x136d89au32,
    0xb933adc2u32,
    0xd130810au32,
    0xccd53183u32,
    0xa4d61d4bu32,
    0x1cd36813u32,
    0x74d044dbu32,
    0x27180901u32,
    0x4f1b25c9u32,
    0xf71e5091u32,
    0x9f1d7c59u32,
    0x82f8ccd0u32,
    0xeafbe018u32,
    0x52fe9540u32,
    0x3afdb988u32,
    0xc8358d49u32,
    0xa036a181u32,
    0x1833d4d9u32,
    0x7030f811u32,
    0x6dd54898u32,
    0x5d66450u32,
    0xbdd31108u32,
    0xd5d03dc0u32,
    0x8618701au32,
    0xee1b5cd2u32,
    0x561e298au32,
    0x3e1d0542u32,
    0x23f8b5cbu32,
    0x4bfb9903u32,
    0xf3feec5bu32,
    0x9bfdc093u32,
    0x546e77efu32,
    0x3c6d5b27u32,
    0x84682e7fu32,
    0xec6b02b7u32,
    0xf18eb23eu32,
    0x998d9ef6u32,
    0x2188ebaeu32,
    0x498bc766u32,
    0x1a438abcu32,
    0x7240a674u32,
    0xca45d32cu32,
    0xa246ffe4u32,
    0xbfa34f6du32,
    0xd7a063a5u32,
    0x6fa516fdu32,
    0x7a63a35u32,
    0x8fd9098eu32,
    0xe7da2546u32,
    0x5fdf501eu32,
    0x37dc7cd6u32,
    0x2a39cc5fu32,
    0x423ae097u32,
    0xfa3f95cfu32,
    0x923cb907u32,
    0xc1f4f4ddu32,
    0xa9f7d815u32,
    0x11f2ad4du32,
    0x79f18185u32,
    0x6414310cu32,
    0xc171dc4u32,
    0xb412689cu32,
    0xdc114454u32,
    0x1382f328u32,
    0x7b81dfe0u32,
    0xc384aab8u32,
    0xab878670u32,
    0xb66236f9u32,
    0xde611a31u32,
    0x66646f69u32,
    0xe6743a1u32,
    0x5daf0e7bu32,
    0x35ac22b3u32,
    0x8da957ebu32,
    0xe5aa7b23u32,
    0xf84fcbaau32,
    0x904ce762u32,
    0x2849923au32,
    0x404abef2u32,
    0xb2828a33u32,
    0xda81a6fbu32,
    0x6284d3a3u32,
    0xa87ff6bu32,
    0x17624fe2u32,
    0x7f61632au32,
    0xc7641672u32,
    0xaf673abau32,
    0xfcaf7760u32,
    0x94ac5ba8u32,
    0x2ca92ef0u32,
    0x44aa0238u32,
    0x594fb2b1u32,
    0x314c9e79u32,
    0x8949eb21u32,
    0xe14ac7e9u32,
    0x2ed97095u32,
    0x46da5c5du32,
    0xfedf2905u32,
    0x96dc05cdu32,
    0x8b39b544u32,
    0xe33a998cu32,
    0x5b3fecd4u32,
    0x333cc01cu32,
    0x60f48dc6u32,
    0x8f7a10eu32,
    0xb0f2d456u32,
    0xd8f1f89eu32,
    0xc5144817u32,
    0xad1764dfu32,
    0x15121187u32,
    0x7d113d4fu32,
];
/*
 * end of the CRC lookup table crc_tableil8_o80
 */
/*
 * The following CRC lookup table was generated automagically using the
 * following model parameters:
 *
 * Generator Polynomial = ................. 0x1EDC6F41
 * Generator Polynomial Length = .......... 32 bits
 * Reflected Bits = ....................... TRUE
 * Table Generation Offset = .............. 32 bits
 * Number of Slices = ..................... 8 slices
 * Slice Lengths = ........................ 8 8 8 8 8 8 8 8
 * Directory Name = ....................... .\
 * File Name = ............................ 8x256_tables.c
 */
static mut sctp_crc_tableil8_o88: [uint32_t; 256] = [
    0u32,
    0x493c7d27u32,
    0x9278fa4eu32,
    0xdb448769u32,
    0x211d826du32,
    0x6821ff4au32,
    0xb3657823u32,
    0xfa590504u32,
    0x423b04dau32,
    0xb0779fdu32,
    0xd043fe94u32,
    0x997f83b3u32,
    0x632686b7u32,
    0x2a1afb90u32,
    0xf15e7cf9u32,
    0xb86201deu32,
    0x847609b4u32,
    0xcd4a7493u32,
    0x160ef3fau32,
    0x5f328eddu32,
    0xa56b8bd9u32,
    0xec57f6feu32,
    0x37137197u32,
    0x7e2f0cb0u32,
    0xc64d0d6eu32,
    0x8f717049u32,
    0x5435f720u32,
    0x1d098a07u32,
    0xe7508f03u32,
    0xae6cf224u32,
    0x7528754du32,
    0x3c14086au32,
    0xd006599u32,
    0x443c18beu32,
    0x9f789fd7u32,
    0xd644e2f0u32,
    0x2c1de7f4u32,
    0x65219ad3u32,
    0xbe651dbau32,
    0xf759609du32,
    0x4f3b6143u32,
    0x6071c64u32,
    0xdd439b0du32,
    0x947fe62au32,
    0x6e26e32eu32,
    0x271a9e09u32,
    0xfc5e1960u32,
    0xb5626447u32,
    0x89766c2du32,
    0xc04a110au32,
    0x1b0e9663u32,
    0x5232eb44u32,
    0xa86bee40u32,
    0xe1579367u32,
    0x3a13140eu32,
    0x732f6929u32,
    0xcb4d68f7u32,
    0x827115d0u32,
    0x593592b9u32,
    0x1009ef9eu32,
    0xea50ea9au32,
    0xa36c97bdu32,
    0x782810d4u32,
    0x31146df3u32,
    0x1a00cb32u32,
    0x533cb615u32,
    0x8878317cu32,
    0xc1444c5bu32,
    0x3b1d495fu32,
    0x72213478u32,
    0xa965b311u32,
    0xe059ce36u32,
    0x583bcfe8u32,
    0x1107b2cfu32,
    0xca4335a6u32,
    0x837f4881u32,
    0x79264d85u32,
    0x301a30a2u32,
    0xeb5eb7cbu32,
    0xa262caecu32,
    0x9e76c286u32,
    0xd74abfa1u32,
    0xc0e38c8u32,
    0x453245efu32,
    0xbf6b40ebu32,
    0xf6573dccu32,
    0x2d13baa5u32,
    0x642fc782u32,
    0xdc4dc65cu32,
    0x9571bb7bu32,
    0x4e353c12u32,
    0x7094135u32,
    0xfd504431u32,
    0xb46c3916u32,
    0x6f28be7fu32,
    0x2614c358u32,
    0x1700aeabu32,
    0x5e3cd38cu32,
    0x857854e5u32,
    0xcc4429c2u32,
    0x361d2cc6u32,
    0x7f2151e1u32,
    0xa465d688u32,
    0xed59abafu32,
    0x553baa71u32,
    0x1c07d756u32,
    0xc743503fu32,
    0x8e7f2d18u32,
    0x7426281cu32,
    0x3d1a553bu32,
    0xe65ed252u32,
    0xaf62af75u32,
    0x9376a71fu32,
    0xda4ada38u32,
    0x10e5d51u32,
    0x48322076u32,
    0xb26b2572u32,
    0xfb575855u32,
    0x2013df3cu32,
    0x692fa21bu32,
    0xd14da3c5u32,
    0x9871dee2u32,
    0x4335598bu32,
    0xa0924acu32,
    0xf05021a8u32,
    0xb96c5c8fu32,
    0x6228dbe6u32,
    0x2b14a6c1u32,
    0x34019664u32,
    0x7d3deb43u32,
    0xa6796c2au32,
    0xef45110du32,
    0x151c1409u32,
    0x5c20692eu32,
    0x8764ee47u32,
    0xce589360u32,
    0x763a92beu32,
    0x3f06ef99u32,
    0xe44268f0u32,
    0xad7e15d7u32,
    0x572710d3u32,
    0x1e1b6df4u32,
    0xc55fea9du32,
    0x8c6397bau32,
    0xb0779fd0u32,
    0xf94be2f7u32,
    0x220f659eu32,
    0x6b3318b9u32,
    0x916a1dbdu32,
    0xd856609au32,
    0x312e7f3u32,
    0x4a2e9ad4u32,
    0xf24c9b0au32,
    0xbb70e62du32,
    0x60346144u32,
    0x29081c63u32,
    0xd3511967u32,
    0x9a6d6440u32,
    0x4129e329u32,
    0x8159e0eu32,
    0x3901f3fdu32,
    0x703d8edau32,
    0xab7909b3u32,
    0xe2457494u32,
    0x181c7190u32,
    0x51200cb7u32,
    0x8a648bdeu32,
    0xc358f6f9u32,
    0x7b3af727u32,
    0x32068a00u32,
    0xe9420d69u32,
    0xa07e704eu32,
    0x5a27754au32,
    0x131b086du32,
    0xc85f8f04u32,
    0x8163f223u32,
    0xbd77fa49u32,
    0xf44b876eu32,
    0x2f0f0007u32,
    0x66337d20u32,
    0x9c6a7824u32,
    0xd5560503u32,
    0xe12826au32,
    0x472eff4du32,
    0xff4cfe93u32,
    0xb67083b4u32,
    0x6d3404ddu32,
    0x240879fau32,
    0xde517cfeu32,
    0x976d01d9u32,
    0x4c2986b0u32,
    0x515fb97u32,
    0x2e015d56u32,
    0x673d2071u32,
    0xbc79a718u32,
    0xf545da3fu32,
    0xf1cdf3bu32,
    0x4620a21cu32,
    0x9d642575u32,
    0xd4585852u32,
    0x6c3a598cu32,
    0x250624abu32,
    0xfe42a3c2u32,
    0xb77edee5u32,
    0x4d27dbe1u32,
    0x41ba6c6u32,
    0xdf5f21afu32,
    0x96635c88u32,
    0xaa7754e2u32,
    0xe34b29c5u32,
    0x380faeacu32,
    0x7133d38bu32,
    0x8b6ad68fu32,
    0xc256aba8u32,
    0x19122cc1u32,
    0x502e51e6u32,
    0xe84c5038u32,
    0xa1702d1fu32,
    0x7a34aa76u32,
    0x3308d751u32,
    0xc951d255u32,
    0x806daf72u32,
    0x5b29281bu32,
    0x1215553cu32,
    0x230138cfu32,
    0x6a3d45e8u32,
    0xb179c281u32,
    0xf845bfa6u32,
    0x21cbaa2u32,
    0x4b20c785u32,
    0x906440ecu32,
    0xd9583dcbu32,
    0x613a3c15u32,
    0x28064132u32,
    0xf342c65bu32,
    0xba7ebb7cu32,
    0x4027be78u32,
    0x91bc35fu32,
    0xd25f4436u32,
    0x9b633911u32,
    0xa777317bu32,
    0xee4b4c5cu32,
    0x350fcb35u32,
    0x7c33b612u32,
    0x866ab316u32,
    0xcf56ce31u32,
    0x14124958u32,
    0x5d2e347fu32,
    0xe54c35a1u32,
    0xac704886u32,
    0x7734cfefu32,
    0x3e08b2c8u32,
    0xc451b7ccu32,
    0x8d6dcaebu32,
    0x56294d82u32,
    0x1f1530a5u32,
];
/*
 * end of the CRC lookup table crc_tableil8_o88
 */
unsafe extern "C" fn sctp_crc32c_sb8_64_bit(
    mut crc: uint32_t,
    mut p_buf: *const libc::c_uchar,
    mut length: uint32_t,
    mut init_bytes: uint32_t,
) -> uint32_t {
    let mut li = 0;
    let mut running_length = 0;
    let mut end_bytes = 0;
    running_length = length
        .wrapping_sub(init_bytes)
        .wrapping_div(8u32)
        .wrapping_mul(8u32);
    end_bytes = length.wrapping_sub(init_bytes).wrapping_sub(running_length);
    li = 0u32;
    while li < init_bytes {
        let fresh0 = p_buf;
        p_buf = p_buf.offset(1);
        crc = sctp_crc_tableil8_o32[((crc ^ *fresh0 as libc::c_uint) & 0xffu32) as usize]
            ^ crc >> 8i32;
        li = li.wrapping_add(1)
    }
    li = 0u32;
    while li < running_length.wrapping_div(8u32) {
        let mut term1 = 0;
        let mut term2 = 0;
        crc ^= *(p_buf as *const uint32_t);
        p_buf = p_buf.offset(4isize);
        term1 = sctp_crc_tableil8_o88[(crc & 0xffu32) as usize]
            ^ sctp_crc_tableil8_o80[(crc >> 8i32 & 0xffu32) as usize];
        term2 = crc >> 16i32;
        crc = term1
            ^ sctp_crc_tableil8_o72[(term2 & 0xffu32) as usize]
            ^ sctp_crc_tableil8_o64[(term2 >> 8i32 & 0xffu32) as usize];
        term1 = sctp_crc_tableil8_o56[(*(p_buf as *const uint32_t) & 0xffu32) as usize]
            ^ sctp_crc_tableil8_o48[(*(p_buf as *const uint32_t) >> 8i32 & 0xffu32) as usize];
        term2 = *(p_buf as *const uint32_t) >> 16i32;
        crc = crc
            ^ term1
            ^ sctp_crc_tableil8_o40[(term2 & 0xffu32) as usize]
            ^ sctp_crc_tableil8_o32[(term2 >> 8i32 & 0xffu32) as usize];
        p_buf = p_buf.offset(4isize);
        li = li.wrapping_add(1)
    }
    li = 0u32;
    while li < end_bytes {
        let fresh1 = p_buf;
        p_buf = p_buf.offset(1);
        crc = sctp_crc_tableil8_o32[((crc ^ *fresh1 as libc::c_uint) & 0xffu32) as usize]
            ^ crc >> 8i32;
        li = li.wrapping_add(1)
    }
    return crc;
}
/* *
 *
 * Routine Description:
 *
 * warms the tables
 *
 * Arguments:
 *
 *		none
 *
 * Return value:
 *
 *		none
 */
unsafe extern "C" fn multitable_crc32c(
    mut crc32c: uint32_t,
    mut buffer: *const libc::c_uchar,
    mut length: libc::c_uint,
) -> uint32_t {
    let mut to_even_word = 0;
    if length == 0u32 {
        return crc32c;
    }
    to_even_word = (4u64).wrapping_sub(buffer as uintptr_t & 0x3u64) as uint32_t;
    return sctp_crc32c_sb8_64_bit(crc32c, buffer, length, to_even_word);
}
static mut sctp_crc_c: [uint32_t; 256] = [
    0u32,
    0xf26b8303u32,
    0xe13b70f7u32,
    0x1350f3f4u32,
    0xc79a971fu32,
    0x35f1141cu32,
    0x26a1e7e8u32,
    0xd4ca64ebu32,
    0x8ad958cfu32,
    0x78b2dbccu32,
    0x6be22838u32,
    0x9989ab3bu32,
    0x4d43cfd0u32,
    0xbf284cd3u32,
    0xac78bf27u32,
    0x5e133c24u32,
    0x105ec76fu32,
    0xe235446cu32,
    0xf165b798u32,
    0x30e349bu32,
    0xd7c45070u32,
    0x25afd373u32,
    0x36ff2087u32,
    0xc494a384u32,
    0x9a879fa0u32,
    0x68ec1ca3u32,
    0x7bbcef57u32,
    0x89d76c54u32,
    0x5d1d08bfu32,
    0xaf768bbcu32,
    0xbc267848u32,
    0x4e4dfb4bu32,
    0x20bd8edeu32,
    0xd2d60dddu32,
    0xc186fe29u32,
    0x33ed7d2au32,
    0xe72719c1u32,
    0x154c9ac2u32,
    0x61c6936u32,
    0xf477ea35u32,
    0xaa64d611u32,
    0x580f5512u32,
    0x4b5fa6e6u32,
    0xb93425e5u32,
    0x6dfe410eu32,
    0x9f95c20du32,
    0x8cc531f9u32,
    0x7eaeb2fau32,
    0x30e349b1u32,
    0xc288cab2u32,
    0xd1d83946u32,
    0x23b3ba45u32,
    0xf779deaeu32,
    0x5125dadu32,
    0x1642ae59u32,
    0xe4292d5au32,
    0xba3a117eu32,
    0x4851927du32,
    0x5b016189u32,
    0xa96ae28au32,
    0x7da08661u32,
    0x8fcb0562u32,
    0x9c9bf696u32,
    0x6ef07595u32,
    0x417b1dbcu32,
    0xb3109ebfu32,
    0xa0406d4bu32,
    0x522bee48u32,
    0x86e18aa3u32,
    0x748a09a0u32,
    0x67dafa54u32,
    0x95b17957u32,
    0xcba24573u32,
    0x39c9c670u32,
    0x2a993584u32,
    0xd8f2b687u32,
    0xc38d26cu32,
    0xfe53516fu32,
    0xed03a29bu32,
    0x1f682198u32,
    0x5125dad3u32,
    0xa34e59d0u32,
    0xb01eaa24u32,
    0x42752927u32,
    0x96bf4dccu32,
    0x64d4cecfu32,
    0x77843d3bu32,
    0x85efbe38u32,
    0xdbfc821cu32,
    0x2997011fu32,
    0x3ac7f2ebu32,
    0xc8ac71e8u32,
    0x1c661503u32,
    0xee0d9600u32,
    0xfd5d65f4u32,
    0xf36e6f7u32,
    0x61c69362u32,
    0x93ad1061u32,
    0x80fde395u32,
    0x72966096u32,
    0xa65c047du32,
    0x5437877eu32,
    0x4767748au32,
    0xb50cf789u32,
    0xeb1fcbadu32,
    0x197448aeu32,
    0xa24bb5au32,
    0xf84f3859u32,
    0x2c855cb2u32,
    0xdeeedfb1u32,
    0xcdbe2c45u32,
    0x3fd5af46u32,
    0x7198540du32,
    0x83f3d70eu32,
    0x90a324fau32,
    0x62c8a7f9u32,
    0xb602c312u32,
    0x44694011u32,
    0x5739b3e5u32,
    0xa55230e6u32,
    0xfb410cc2u32,
    0x92a8fc1u32,
    0x1a7a7c35u32,
    0xe811ff36u32,
    0x3cdb9bddu32,
    0xceb018deu32,
    0xdde0eb2au32,
    0x2f8b6829u32,
    0x82f63b78u32,
    0x709db87bu32,
    0x63cd4b8fu32,
    0x91a6c88cu32,
    0x456cac67u32,
    0xb7072f64u32,
    0xa457dc90u32,
    0x563c5f93u32,
    0x82f63b7u32,
    0xfa44e0b4u32,
    0xe9141340u32,
    0x1b7f9043u32,
    0xcfb5f4a8u32,
    0x3dde77abu32,
    0x2e8e845fu32,
    0xdce5075cu32,
    0x92a8fc17u32,
    0x60c37f14u32,
    0x73938ce0u32,
    0x81f80fe3u32,
    0x55326b08u32,
    0xa759e80bu32,
    0xb4091bffu32,
    0x466298fcu32,
    0x1871a4d8u32,
    0xea1a27dbu32,
    0xf94ad42fu32,
    0xb21572cu32,
    0xdfeb33c7u32,
    0x2d80b0c4u32,
    0x3ed04330u32,
    0xccbbc033u32,
    0xa24bb5a6u32,
    0x502036a5u32,
    0x4370c551u32,
    0xb11b4652u32,
    0x65d122b9u32,
    0x97baa1bau32,
    0x84ea524eu32,
    0x7681d14du32,
    0x2892ed69u32,
    0xdaf96e6au32,
    0xc9a99d9eu32,
    0x3bc21e9du32,
    0xef087a76u32,
    0x1d63f975u32,
    0xe330a81u32,
    0xfc588982u32,
    0xb21572c9u32,
    0x407ef1cau32,
    0x532e023eu32,
    0xa145813du32,
    0x758fe5d6u32,
    0x87e466d5u32,
    0x94b49521u32,
    0x66df1622u32,
    0x38cc2a06u32,
    0xcaa7a905u32,
    0xd9f75af1u32,
    0x2b9cd9f2u32,
    0xff56bd19u32,
    0xd3d3e1au32,
    0x1e6dcdeeu32,
    0xec064eedu32,
    0xc38d26c4u32,
    0x31e6a5c7u32,
    0x22b65633u32,
    0xd0ddd530u32,
    0x417b1dbu32,
    0xf67c32d8u32,
    0xe52cc12cu32,
    0x1747422fu32,
    0x49547e0bu32,
    0xbb3ffd08u32,
    0xa86f0efcu32,
    0x5a048dffu32,
    0x8ecee914u32,
    0x7ca56a17u32,
    0x6ff599e3u32,
    0x9d9e1ae0u32,
    0xd3d3e1abu32,
    0x21b862a8u32,
    0x32e8915cu32,
    0xc083125fu32,
    0x144976b4u32,
    0xe622f5b7u32,
    0xf5720643u32,
    0x7198540u32,
    0x590ab964u32,
    0xab613a67u32,
    0xb831c993u32,
    0x4a5a4a90u32,
    0x9e902e7bu32,
    0x6cfbad78u32,
    0x7fab5e8cu32,
    0x8dc0dd8fu32,
    0xe330a81au32,
    0x115b2b19u32,
    0x20bd8edu32,
    0xf0605beeu32,
    0x24aa3f05u32,
    0xd6c1bc06u32,
    0xc5914ff2u32,
    0x37faccf1u32,
    0x69e9f0d5u32,
    0x9b8273d6u32,
    0x88d28022u32,
    0x7ab90321u32,
    0xae7367cau32,
    0x5c18e4c9u32,
    0x4f48173du32,
    0xbd23943eu32,
    0xf36e6f75u32,
    0x105ec76u32,
    0x12551f82u32,
    0xe03e9c81u32,
    0x34f4f86au32,
    0xc69f7b69u32,
    0xd5cf889du32,
    0x27a40b9eu32,
    0x79b737bau32,
    0x8bdcb4b9u32,
    0x988c474du32,
    0x6ae7c44eu32,
    0xbe2da0a5u32,
    0x4c4623a6u32,
    0x5f16d052u32,
    0xad7d5351u32,
];
unsafe extern "C" fn singletable_crc32c(
    mut crc32c: uint32_t,
    mut buffer: *const libc::c_uchar,
    mut length: libc::c_uint,
) -> uint32_t {
    let mut i = 0;
    i = 0u32;
    while i < length {
        crc32c = crc32c >> 8i32
            ^ sctp_crc_c
                [((crc32c ^ *buffer.offset(i as isize) as libc::c_uint) & 0xffu32) as usize];
        i = i.wrapping_add(1)
    }
    return crc32c;
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
/* _KERNEL */
#[no_mangle]
pub unsafe extern "C" fn calculate_crc32c(
    mut crc32c: uint32_t,
    mut buffer: *const libc::c_uchar,
    mut length: libc::c_uint,
) -> uint32_t {
    if length < 4u32 {
        return singletable_crc32c(crc32c, buffer, length);
    } else {
        return multitable_crc32c(crc32c, buffer, length);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_finalize_crc32c(mut crc32c: uint32_t) -> uint32_t {
    let mut result = 0;
    /* Complement the result */
    result = !crc32c;
    /*
     * For LITTLE ENDIAN platforms the result is in already in network
     * byte order.
     */
    crc32c = result;
    return crc32c;
}
/*
 * Compute the SCTP checksum in network byte order for a given mbuf chain m
 * which contains an SCTP packet starting at offset.
 * Since this function is also called by ipfw, don't assume that
 * it is compiled on a kernel with SCTP support.
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_calculate_cksum(mut m: *mut mbuf, mut offset: uint32_t) -> uint32_t {
    let mut base = 0xffffffffu32;
    while offset > 0u32 {
        if offset < (*m).m_hdr.mh_len as uint32_t {
            break;
        }
        offset = (offset).wrapping_sub((*m).m_hdr.mh_len as libc::c_uint);
        m = (*m).m_hdr.mh_next
    }
    if offset > 0u32 {
        base = calculate_crc32c(
            base,
            (*m).m_hdr.mh_data.offset(offset as isize) as *mut libc::c_uchar,
            ((*m).m_hdr.mh_len as libc::c_uint).wrapping_sub(offset),
        );
        m = (*m).m_hdr.mh_next
    }
    while !m.is_null() {
        base = calculate_crc32c(
            base,
            (*m).m_hdr.mh_data as *mut libc::c_uchar,
            (*m).m_hdr.mh_len as libc::c_uint,
        );
        m = (*m).m_hdr.mh_next
    }
    base = sctp_finalize_crc32c(base);
    return base;
}
