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
    fn m_freem(_: *mut mbuf);
    #[no_mangle]
    fn sctp_get_mbuf_for_msg(
        space_needed: libc::c_uint,
        want_header: libc::c_int,
        how: libc::c_int,
        allonebuf: libc::c_int,
        type_0: libc::c_int,
    ) -> *mut mbuf;
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
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    #[no_mangle]
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn ntohl(__netlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn ntohs(__netshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn sctp_os_timer_stop(_: *mut sctp_os_timer_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    #[no_mangle]
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
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
    /*-
     * For this call ep_addr, the to is the destination endpoint address of the
     * peer (relative to outbound). The from field is only used if the TCP model
     * is enabled and helps distingush amongst the subset bound (non-boundall).
     * The TCP model MAY change the actual ep field, this is why it is passed.
     */
    /* proc will be NULL for __Userspace__ */
    #[no_mangle]
    fn sctp_add_local_addr_restricted(_: *mut sctp_tcb, _: *mut sctp_ifa);
    #[no_mangle]
    static mut system_base_info: sctp_base_info;
    #[no_mangle]
    fn sctp_find_vrf(vrfid: uint32_t) -> *mut sctp_vrf;
    #[no_mangle]
    fn sctp_findnet(_: *mut sctp_tcb, _: *mut sockaddr) -> *mut sctp_nets;
    #[no_mangle]
    fn sctp_free_ifa(sctp_ifap: *mut sctp_ifa);
    #[no_mangle]
    fn sctp_add_local_addr_ep(_: *mut sctp_inpcb, _: *mut sctp_ifa, _: uint32_t);
    #[no_mangle]
    fn sctp_del_local_addr_ep(_: *mut sctp_inpcb, _: *mut sctp_ifa);
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
    fn sctp_remove_net(_: *mut sctp_tcb, _: *mut sctp_nets);
    #[no_mangle]
    fn sctp_del_remote_addr(_: *mut sctp_tcb, _: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp_del_local_addr_restricted(_: *mut sctp_tcb, _: *mut sctp_ifa);
    #[no_mangle]
    fn sctp_set_primary_addr(_: *mut sctp_tcb, _: *mut sockaddr, _: *mut sctp_nets) -> libc::c_int;
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
    fn sctp_find_ifa_in_ep(
        inp: *mut sctp_inpcb,
        addr: *mut sockaddr,
        hold_lock: libc::c_int,
    ) -> *mut sctp_ifa;
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
    fn sctp_m_getptr(_: *mut mbuf, _: libc::c_int, _: libc::c_int, _: *mut uint8_t) -> caddr_t;
    #[no_mangle]
    fn sctp_ulp_notify(
        _: uint32_t,
        _: *mut sctp_tcb,
        _: uint32_t,
        _: *mut libc::c_void,
        _: libc::c_int,
    );
    /* We choose to abort via user input */
    #[no_mangle]
    fn sctp_abort_an_association(
        _: *mut sctp_inpcb,
        _: *mut sctp_tcb,
        _: *mut mbuf,
        _: libc::c_int,
    );
    #[no_mangle]
    fn sctp_is_same_scope(_: *mut sockaddr_in6, _: *mut sockaddr_in6) -> uint32_t;
    #[no_mangle]
    fn sctp_cmpaddr(_: *mut sockaddr, _: *mut sockaddr) -> libc::c_int;
    #[no_mangle]
    fn sctp_print_address(_: *mut sockaddr);
    #[no_mangle]
    fn sctp_generate_cause(_: uint16_t, _: *mut libc::c_char) -> *mut mbuf;
    #[no_mangle]
    fn sctp_local_addr_count(stcb: *mut sctp_tcb) -> libc::c_int;
    #[no_mangle]
    fn sctp_misc_ints(from: uint8_t, a: uint32_t, b: uint32_t, c: uint32_t, d: uint32_t);
    #[no_mangle]
    fn sctp_is_addr_restricted(_: *mut sctp_tcb, _: *mut sctp_ifa) -> libc::c_int;
    #[no_mangle]
    fn sctp_is_address_in_scope(
        ifa: *mut sctp_ifa,
        scope: *mut sctp_scoping,
        do_update: libc::c_int,
    ) -> libc::c_int;
    #[no_mangle]
    fn sctp_is_addr_in_ep(inp: *mut sctp_inpcb, ifa: *mut sctp_ifa) -> libc::c_int;
    #[no_mangle]
    fn sctp_v6src_match_nexthop(src6: *mut sockaddr_in6, ro: *mut sctp_route_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_v4src_match_nexthop(sifa: *mut sctp_ifa, ro: *mut sctp_route_t) -> libc::c_int;
    #[no_mangle]
    fn sctp_send_asconf(_: *mut sctp_tcb, _: *mut sctp_nets, addr_locked: libc::c_int);
    #[no_mangle]
    fn sctp_toss_old_asconf(_: *mut sctp_tcb);
    #[no_mangle]
    fn sctp_move_chunks_from_net(stcb: *mut sctp_tcb, net: *mut sctp_nets);
    #[no_mangle]
    fn sctp_chunk_output(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: libc::c_int, _: libc::c_int);
    #[no_mangle]
    fn sctp_send_hb(_: *mut sctp_tcb, _: *mut sctp_nets, _: libc::c_int);
    #[no_mangle]
    fn sctp_t3rxt_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets) -> libc::c_int;
    #[no_mangle]
    fn sctp_delete_prim_timer(_: *mut sctp_inpcb, _: *mut sctp_tcb, _: *mut sctp_nets);
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
    pub c2rust_unnamed: C2RustUnnamed_2,
    pub c2rust_unnamed_0: C2RustUnnamed_0,
    pub __g_refs: [libc::c_uint; 2],
    pub __g_size: [libc::c_uint; 2],
    pub __g1_orig_size: libc::c_uint,
    pub __wrefs: libc::c_uint,
    pub __g_signals: [libc::c_uint; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_0 {
    pub __g1_start: libc::c_ulonglong,
    pub __g1_start32: C2RustUnnamed_1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_1 {
    pub __low: libc::c_uint,
    pub __high: libc::c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_2 {
    pub __wseq: libc::c_ulonglong,
    pub __wseq32: C2RustUnnamed_3,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_3 {
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
    pub __in6_u: C2RustUnnamed_4,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_4 {
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
    pub so_incomp: C2RustUnnamed_12,
    pub so_comp: C2RustUnnamed_11,
    pub so_list: C2RustUnnamed_10,
    pub so_qlen: u_short,
    pub so_incqlen: u_short,
    pub so_qlimit: u_short,
    pub so_timeo: libc::c_short,
    pub timeo_cond: userland_cond_t,
    pub so_error: u_short,
    pub so_sigio: *mut sigio,
    pub so_oobmark: u_long,
    pub so_aiojobq: C2RustUnnamed_9,
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
    pub M_dat: C2RustUnnamed_5,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_5 {
    pub MH: C2RustUnnamed_6,
    pub M_databuf: [libc::c_char; 216],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_6 {
    pub MH_pkthdr: pkthdr,
    pub MH_dat: C2RustUnnamed_7,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_7 {
    pub MH_ext: m_ext,
    pub MH_databuf: [libc::c_char; 176],
}

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
    pub m_tag_link: C2RustUnnamed_8,
    pub m_tag_id: u_int16_t,
    pub m_tag_len: u_int16_t,
    pub m_tag_cookie: u_int32_t,
    pub m_tag_free: Option<unsafe extern "C" fn(_: *mut m_tag) -> ()>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_8 {
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
pub struct C2RustUnnamed_9 {
    pub tqh_first: *mut aiocblist,
    pub tqh_last: *mut *mut aiocblist,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_10 {
    pub tqe_next: *mut socket,
    pub tqe_prev: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_11 {
    pub tqh_first: *mut socket,
    pub tqh_last: *mut *mut socket,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_12 {
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
    pub ifa_ifu: C2RustUnnamed_13,
    pub ifa_ifp: *mut iface,
    pub ifa_next: *mut ifaddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_13 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbhead {
    pub lh_first: *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcb {
    pub inp_hash: C2RustUnnamed_21,
    pub inp_list: C2RustUnnamed_20,
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
    pub inp_depend4: C2RustUnnamed_17,
    pub inp_depend6: C2RustUnnamed_16,
    pub inp_portlist: C2RustUnnamed_15,
    pub inp_phd: *mut inpcbport,
    pub inp_mtx: mtx,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inpcbport {
    pub phd_hash: C2RustUnnamed_14,
    pub phd_pcblist: inpcbhead,
    pub phd_port: u_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_14 {
    pub le_next: *mut inpcbport,
    pub le_prev: *mut *mut inpcbport,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_15 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_16 {
    pub inp6_options: *mut mbuf,
    pub inp6_outputopts: *mut ip6_pktopts,
    pub inp6_icmp6filt: *mut crate::sctp6_usrreq::icmp6_filter,
    pub inp6_cksum: libc::c_int,
    pub inp6_hops: libc::c_short,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_17 {
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
    pub ie_dependfaddr: C2RustUnnamed_19,
    pub ie_dependladdr: C2RustUnnamed_18,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_18 {
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
pub union C2RustUnnamed_19 {
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
pub struct C2RustUnnamed_20 {
    pub le_next: *mut inpcb,
    pub le_prev: *mut *mut inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_21 {
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
    pub tqe: C2RustUnnamed_22,
    pub c_time: uint32_t,
    pub c_arg: *mut libc::c_void,
    pub c_func: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub c_flags: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_22 {
    pub tqe_next: *mut sctp_callout,
    pub tqe_prev: *mut *mut sctp_callout,
}
pub type sctp_os_timer_t = sctp_callout;
pub type sctp_route_t = sctp_route;
pub type sctp_rtentry_t = sctp_rtentry;
/* used to save ASCONF-ACK chunks for retransmission */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ack {
    pub next: C2RustUnnamed_29,
    pub serial_number: uint32_t,
    pub last_sent_to: *mut sctp_nets,
    pub data: *mut mbuf,
    pub len: uint16_t,
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
    pub sctp_next: C2RustUnnamed_28,
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
    pub next_ifa: C2RustUnnamed_27,
    pub next_bucket: C2RustUnnamed_26,
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
    pub next_ifn: C2RustUnnamed_24,
    pub next_bucket: C2RustUnnamed_23,
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
pub struct C2RustUnnamed_23 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_24 {
    pub le_next: *mut sctp_ifn,
    pub le_prev: *mut *mut sctp_ifn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrf {
    pub next_vrf: C2RustUnnamed_25,
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
pub struct C2RustUnnamed_25 {
    pub le_next: *mut sctp_vrf,
    pub le_prev: *mut *mut sctp_vrf,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_26 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_27 {
    pub le_next: *mut sctp_ifa,
    pub le_prev: *mut *mut sctp_ifa,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_28 {
    pub tqe_next: *mut sctp_nets,
    pub tqe_prev: *mut *mut sctp_nets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_29 {
    pub tqe_next: *mut sctp_asconf_ack,
    pub tqe_prev: *mut *mut sctp_asconf_ack,
}
/* used to keep track of the addresses yet to try to add/delete */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addr {
    pub next: C2RustUnnamed_30,
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
pub struct C2RustUnnamed_30 {
    pub tqe_next: *mut sctp_asconf_addr,
    pub tqe_prev: *mut *mut sctp_asconf_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_tcb {
    pub sctp_socket: *mut socket,
    pub sctp_ep: *mut sctp_inpcb,
    pub sctp_tcbhash: C2RustUnnamed_51,
    pub sctp_tcblist: C2RustUnnamed_50,
    pub sctp_tcbasocidhash: C2RustUnnamed_49,
    pub sctp_asocs: C2RustUnnamed_48,
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
    pub next: C2RustUnnamed_31,
    pub key: *mut sctp_key_t,
    pub refcount: uint32_t,
    pub keyid: uint16_t,
    pub deactivated: uint8_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_31 {
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
    pub next: C2RustUnnamed_35,
    pub next_instrm: C2RustUnnamed_34,
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
    pub rec: C2RustUnnamed_33,
    pub asoc: *mut sctp_association,
    pub sent_rcv_time: timeval,
    pub data: *mut mbuf,
    pub last_mbuf: *mut mbuf,
    pub whoTo: *mut sctp_nets,
    pub sctp_next: C2RustUnnamed_32,
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
pub struct C2RustUnnamed_32 {
    pub tqe_next: *mut sctp_tmit_chunk,
    pub tqe_prev: *mut *mut sctp_tmit_chunk,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_33 {
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
pub struct C2RustUnnamed_34 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_35 {
    pub tqe_next: *mut sctp_queued_to_read,
    pub tqe_prev: *mut *mut sctp_queued_to_read,
}
pub type sctp_assoc_t = uint32_t;

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
    pub next_spoke: C2RustUnnamed_36,
    pub rounds: int32_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_36 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_prio {
    pub next_spoke: C2RustUnnamed_37,
    pub priority: uint16_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_37 {
    pub tqe_next: *mut sctp_stream_out,
    pub tqe_prev: *mut *mut sctp_stream_out,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ss_rr {
    pub next_spoke: C2RustUnnamed_38,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_38 {
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
    pub next: C2RustUnnamed_40,
    pub ss_next: C2RustUnnamed_39,
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
pub struct C2RustUnnamed_39 {
    pub tqe_next: *mut sctp_stream_queue_pending,
    pub tqe_prev: *mut *mut sctp_stream_queue_pending,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_40 {
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
    pub next_resp: C2RustUnnamed_41,
    pub seq: uint32_t,
    pub tsn: uint32_t,
    pub number_entries: uint32_t,
    pub list_of_streams: [uint16_t; 0],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_41 {
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
    pub sctp_nxt_addr: C2RustUnnamed_42,
    pub ifa: *mut sctp_ifa,
    pub action: uint32_t,
    pub start_time: timeval,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_42 {
    pub le_next: *mut sctp_laddr,
    pub le_prev: *mut *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ackhead {
    pub tqh_first: *mut sctp_asconf_ack,
    pub tqh_last: *mut *mut sctp_asconf_ack,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_iterator {
    pub sctp_nxt_itr: C2RustUnnamed_46,
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_inpcb {
    pub ip_inp: C2RustUnnamed_45,
    pub read_queue: sctp_readhead,
    pub sctp_list: C2RustUnnamed_44,
    pub sctp_hash: C2RustUnnamed_43,
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
pub struct sctpladdr {
    pub lh_first: *mut sctp_laddr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_43 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_44 {
    pub le_next: *mut sctp_inpcb,
    pub le_prev: *mut *mut sctp_inpcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_45 {
    pub inp: inpcb,
    pub align: [libc::c_char; 256],
}
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
pub struct C2RustUnnamed_46 {
    pub tqe_next: *mut sctp_iterator,
    pub tqe_prev: *mut *mut sctp_iterator,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct scheduling_data {
    pub locked_on_sending: *mut sctp_stream_out,
    pub last_out_stream: *mut sctp_stream_out,
    pub out: C2RustUnnamed_47,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union C2RustUnnamed_47 {
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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_block_entry {
    pub error: libc::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_48 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_49 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_50 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct C2RustUnnamed_51 {
    pub le_next: *mut sctp_tcb,
    pub le_prev: *mut *mut sctp_tcb,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_iterator {
    pub list_of_work: sctpladdr,
    pub cnt: libc::c_int,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_ipv4addr_param {
    pub ph: sctp_paramhdr,
    pub addr: uint32_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_error_cause {
    pub code: uint16_t,
    pub length: uint16_t,
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
    pub sctp_nxt_tagblock: C2RustUnnamed_52,
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
pub struct C2RustUnnamed_52 {
    pub le_next: *mut sctp_tagblock,
    pub le_prev: *mut *mut sctp_tagblock,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sctp_vrflist {
    pub lh_first: *mut sctp_vrf,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_tag_param {
    pub aph: sctp_asconf_paramhdr,
    pub local_vtag: uint32_t,
    pub remote_vtag: uint32_t,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_addrv4_param {
    pub aph: sctp_asconf_paramhdr,
    pub addrp: sctp_ipv4addr_param,
}
/*
 * draft-ietf-tsvwg-addip-sctp
 */
/* Address/Stream Configuration Change (ASCONF) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_chunk {
    pub ch: sctp_chunkhdr,
    pub serial_number: uint32_t,
}
/* lookup address parameter (mandatory) */
/* asconf parameters follow */
/* Address/Stream Configuration Acknowledge (ASCONF ACK) */

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct sctp_asconf_ack_chunk {
    pub ch: sctp_chunkhdr,
    pub serial_number: uint32_t,
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
    memset(
        (*ro).ro_rt as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_rtentry_t>() as libc::c_ulong,
    );
    (*(*ro).ro_rt).rt_refcnt = 1i64;
    (*(*ro).ro_rt).rt_rmx.rmx_mtu = 1500u32;
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
/*
 * debug flags:
 * SCTP_DEBUG_ASCONF1: protocol info, general info and errors
 * SCTP_DEBUG_ASCONF2: detailed info
 */
/*
 * RFC 5061
 *
 * An ASCONF parameter queue exists per asoc which holds the pending address
 * operations.  Lists are updated upon receipt of ASCONF-ACK.
 *
 * A restricted_addrs list exists per assoc to hold local addresses that are
 * not (yet) usable by the assoc as a source address.  These addresses are
 * either pending an ASCONF operation (and exist on the ASCONF parameter
 * queue), or they are permanently restricted (the peer has returned an
 * ERROR indication to an ASCONF(ADD), or the peer does not support ASCONF).
 *
 * Deleted addresses are always immediately removed from the lists as they will
 * (shortly) no longer exist in the kernel.  We send ASCONFs as a courtesy,
 * only if allowed.
 */
/*
 * ASCONF parameter processing.
 * response_required: set if a reply is required (eg. SUCCESS_REPORT).
 * returns a mbuf to an "error" response parameter or NULL/"success" if ok.
 * FIX: allocating this many mbufs on the fly is pretty inefficient...
 */
unsafe extern "C" fn sctp_asconf_success_response(mut id: uint32_t) -> *mut mbuf {
    let mut m_reply = 0 as *mut mbuf;
    let mut aph = 0 as *mut sctp_asconf_paramhdr;
    m_reply = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_uint,
        0i32,
        0x1i32,
        1i32,
        1i32,
    );
    if m_reply.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_success_response: couldn\'t get mbuf!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return 0 as *mut mbuf;
    }
    aph = (*m_reply).m_hdr.mh_data as *mut sctp_asconf_paramhdr;
    (*aph).correlation_id = id;
    (*aph).ph.param_type = htons(0xc005u16);
    (*aph).ph.param_length = ::std::mem::size_of::<sctp_asconf_paramhdr>() as uint16_t;
    (*m_reply).m_hdr.mh_len = (*aph).ph.param_length as libc::c_int;
    (*aph).ph.param_length = htons((*aph).ph.param_length);
    return m_reply;
}
unsafe extern "C" fn sctp_asconf_error_response(
    mut id: uint32_t,
    mut cause: uint16_t,
    mut error_tlv: *mut uint8_t,
    mut tlv_length: uint16_t,
) -> *mut mbuf {
    let mut m_reply = 0 as *mut mbuf;
    let mut aph = 0 as *mut sctp_asconf_paramhdr;
    let mut error = 0 as *mut sctp_error_cause;
    let mut buf_len = 0;
    let mut param_length = 0;
    let mut cause_length = 0;
    let mut padding_length = 0;
    if error_tlv.is_null() {
        tlv_length = 0u16
    }
    cause_length = (::std::mem::size_of::<sctp_error_cause>() as libc::c_ulong)
        .wrapping_add(tlv_length as libc::c_ulong) as uint16_t;
    param_length = (::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong)
        .wrapping_add(cause_length as libc::c_ulong) as uint16_t;
    padding_length = (tlv_length as libc::c_int % 4i32) as uint16_t;
    if padding_length as libc::c_int != 0i32 {
        padding_length = (4i32 - padding_length as libc::c_int) as uint16_t
    }
    buf_len = (param_length as libc::c_int + padding_length as libc::c_int) as uint32_t;
    if buf_len
        > (256u64).wrapping_sub(::std::mem::size_of::<m_hdr>() as libc::c_ulong) as libc::c_uint
    {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_error_response: tlv_length (%xh) too big\n\x00" as *const u8
                        as *const libc::c_char,
                    tlv_length as libc::c_int,
                );
            }
        }
        return 0 as *mut mbuf;
    }
    m_reply = sctp_get_mbuf_for_msg(buf_len, 0i32, 0x1i32, 1i32, 1i32);
    if m_reply.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_error_response: couldn\'t get mbuf!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return 0 as *mut mbuf;
    }
    aph = (*m_reply).m_hdr.mh_data as *mut sctp_asconf_paramhdr;
    (*aph).ph.param_type = htons(0xc003u16);
    (*aph).ph.param_length = htons(param_length);
    (*aph).correlation_id = id;
    error = aph.offset(1isize) as *mut sctp_error_cause;
    (*error).code = htons(cause);
    (*error).length = htons(cause_length);
    if !error_tlv.is_null() {
        let mut i = 0;
        let mut tlv = 0 as *mut uint8_t;
        tlv = error.offset(1isize) as *mut uint8_t;
        memcpy(
            tlv as *mut libc::c_void,
            error_tlv as *const libc::c_void,
            tlv_length as libc::c_ulong,
        );
        i = 0u16;
        while (i as libc::c_int) < padding_length as libc::c_int {
            *tlv.offset((tlv_length as libc::c_int + i as libc::c_int) as isize) = 0u8;
            i = i.wrapping_add(1)
        }
    }
    (*m_reply).m_hdr.mh_len = buf_len as libc::c_int;
    return m_reply;
}
unsafe extern "C" fn sctp_process_asconf_add_ip(
    mut src: *mut sockaddr,
    mut aph: *mut sctp_asconf_paramhdr,
    mut stcb: *mut sctp_tcb,
    mut send_hb: libc::c_int,
    mut response_required: libc::c_int,
) -> *mut mbuf {
    let mut net = 0 as *mut sctp_nets;
    let mut m_reply = 0 as *mut mbuf;
    let mut store = sctp_sockstore {
        sin: sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        },
    };
    let mut ph = 0 as *mut sctp_paramhdr;
    let mut param_type = 0;
    let mut aparam_length = 0;
    let mut param_length = 0;
    let mut sa = 0 as *mut sockaddr;
    let mut zero_address = 0i32;
    let mut bad_address = 0i32;
    aparam_length = ntohs((*aph).ph.param_length);
    if (aparam_length as libc::c_ulong)
        < (::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
    {
        return 0 as *mut mbuf;
    }
    ph = aph.offset(1isize) as *mut sctp_paramhdr;
    param_type = ntohs((*ph).param_type);
    param_length = ntohs((*ph).param_length);
    if (param_length as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong)
        != aparam_length as libc::c_ulong
    {
        return 0 as *mut mbuf;
    }
    sa = &mut store.sa;
    match param_type as libc::c_int {
        5 => {
            let mut sin = 0 as *mut sockaddr_in;
            let mut v4addr = 0 as *mut sctp_ipv4addr_param;
            if param_length as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
            {
                /* invalid param size */
                return 0 as *mut mbuf;
            }
            v4addr = ph as *mut sctp_ipv4addr_param;
            sin = &mut store.sin;
            memset(
                sin as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
            );
            (*sin).sin_family = 2u16;
            (*sin).sin_port = (*stcb).rport;
            (*sin).sin_addr.s_addr = (*v4addr).addr;
            if (*sin).sin_addr.s_addr == 0xffffffffu32
                || ntohl((*sin).sin_addr.s_addr) & 0xf0000000u32 == 0xe0000000u32
            {
                bad_address = 1i32
            }
            if (*sin).sin_addr.s_addr == 0u32 {
                zero_address = 1i32
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_asconf_add_ip: adding \x00" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                sctp_print_address(sa);
            }
        }
        6 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            let mut v6addr = 0 as *mut sctp_ipv6addr_param;
            if param_length as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
            {
                /* invalid param size */
                return 0 as *mut mbuf;
            }
            v6addr = ph as *mut sctp_ipv6addr_param;
            sin6 = &mut store.sin6;
            memset(
                sin6 as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            );
            (*sin6).sin6_family = 10u16;
            (*sin6).sin6_port = (*stcb).rport;
            memcpy(
                &mut (*sin6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                (*v6addr).addr.as_mut_ptr() as *const libc::c_void,
                ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
            );
            if *(&mut (*sin6).sin6_addr as *mut in6_addr as *const uint8_t).offset(0isize)
                as libc::c_int
                == 0xffi32
            {
                bad_address = 1i32
            }
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
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_asconf_add_ip: adding \x00" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                sctp_print_address(sa);
            }
        }
        _ => {
            m_reply = sctp_asconf_error_response(
                (*aph).correlation_id,
                0x7u16,
                aph as *mut uint8_t,
                aparam_length,
            );
            return m_reply;
        }
    }
    /* if 0.0.0.0/::0, add the source address instead */
    if zero_address != 0 && system_base_info.sctpsysctl.sctp_nat_friendly != 0 {
        sa = src;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_asconf_add_ip: using source addr \x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            sctp_print_address(src);
        }
    }
    net = 0 as *mut sctp_nets;
    /* add the address */
    if bad_address != 0 {
        m_reply = sctp_asconf_error_response(
            (*aph).correlation_id,
            0x7u16,
            aph as *mut uint8_t,
            aparam_length,
        )
    } else if sctp_add_remote_addr(stcb, sa, &mut net, (*stcb).asoc.port, 0i32, 6i32) != 0i32 {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_asconf_add_ip: error adding address\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        m_reply = sctp_asconf_error_response(
            (*aph).correlation_id,
            0xa1u16,
            aph as *mut uint8_t,
            aparam_length,
        )
    } else {
        if response_required != 0 {
            m_reply = sctp_asconf_success_response((*aph).correlation_id)
        }
        if !net.is_null() {
            /* notify upper layer */
            sctp_ulp_notify(12u32, stcb, 0u32, sa as *mut libc::c_void, 0i32);
            sctp_timer_start(8i32, (*stcb).sctp_ep, stcb, net);
            sctp_timer_start(5i32, (*stcb).sctp_ep, stcb, net);
            if send_hb != 0 {
                sctp_send_hb(stcb, net, 0i32);
            }
        }
    }
    return m_reply;
}
unsafe extern "C" fn sctp_asconf_del_remote_addrs_except(
    mut stcb: *mut sctp_tcb,
    mut src: *mut sockaddr,
) -> libc::c_int {
    let mut src_net = 0 as *mut sctp_nets;
    let mut net = 0 as *mut sctp_nets;
    let mut nnet = 0 as *mut sctp_nets;
    /* make sure the source address exists as a destination net */
    src_net = sctp_findnet(stcb, src);
    if src_net.is_null() {
        /* not found */
        return -(1i32);
    }
    /* delete all destination addresses except the source */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() && {
        nnet = (*net).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if net != src_net {
            /* delete this address */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"asconf_del_remote_addrs_except: deleting \x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                sctp_print_address(&mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr);
            }
            /* notify upper layer */
            sctp_ulp_notify(
                13u32,
                stcb,
                0u32,
                &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut libc::c_void,
                0i32,
            );
            sctp_remove_net(stcb, net);
        }
        net = nnet
    }
    return 0i32;
}
unsafe extern "C" fn sctp_process_asconf_delete_ip(
    mut src: *mut sockaddr,
    mut aph: *mut sctp_asconf_paramhdr,
    mut stcb: *mut sctp_tcb,
    mut response_required: libc::c_int,
) -> *mut mbuf {
    let mut m_reply = 0 as *mut mbuf;
    let mut store = sctp_sockstore {
        sin: sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        },
    };
    let mut ph = 0 as *mut sctp_paramhdr;
    let mut param_type = 0;
    let mut aparam_length = 0;
    let mut param_length = 0;
    let mut sa = 0 as *mut sockaddr;
    let mut zero_address = 0i32;
    let mut result = 0;
    aparam_length = ntohs((*aph).ph.param_length);
    if (aparam_length as libc::c_ulong)
        < (::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
    {
        return 0 as *mut mbuf;
    }
    ph = aph.offset(1isize) as *mut sctp_paramhdr;
    param_type = ntohs((*ph).param_type);
    param_length = ntohs((*ph).param_length);
    if (param_length as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong)
        != aparam_length as libc::c_ulong
    {
        return 0 as *mut mbuf;
    }
    sa = &mut store.sa;
    match param_type as libc::c_int {
        5 => {
            let mut sin = 0 as *mut sockaddr_in;
            let mut v4addr = 0 as *mut sctp_ipv4addr_param;
            if param_length as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
            {
                /* invalid param size */
                return 0 as *mut mbuf;
            }
            v4addr = ph as *mut sctp_ipv4addr_param;
            sin = &mut store.sin;
            memset(
                sin as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
            );
            (*sin).sin_family = 2u16;
            (*sin).sin_port = (*stcb).rport;
            (*sin).sin_addr.s_addr = (*v4addr).addr;
            if (*sin).sin_addr.s_addr == 0u32 {
                zero_address = 1i32
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_asconf_delete_ip: deleting \x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                sctp_print_address(sa);
            }
        }
        6 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            let mut v6addr = 0 as *mut sctp_ipv6addr_param;
            if param_length as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
            {
                /* invalid param size */
                return 0 as *mut mbuf;
            }
            v6addr = ph as *mut sctp_ipv6addr_param;
            sin6 = &mut store.sin6;
            memset(
                sin6 as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            );
            (*sin6).sin6_family = 10u16;
            (*sin6).sin6_port = (*stcb).rport;
            memcpy(
                &mut (*sin6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                (*v6addr).addr.as_mut_ptr() as *const libc::c_void,
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
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_asconf_delete_ip: deleting \x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                sctp_print_address(sa);
            }
        }
        _ => {
            m_reply = sctp_asconf_error_response(
                (*aph).correlation_id,
                0x5u16,
                aph as *mut uint8_t,
                aparam_length,
            );
            return m_reply;
        }
    }
    /* make sure the source address is not being deleted */
    if sctp_cmpaddr(sa, src) != 0 {
        /* trying to delete the source address! */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_asconf_delete_ip: tried to delete source addr\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        m_reply = sctp_asconf_error_response(
            (*aph).correlation_id,
            0xa2u16,
            aph as *mut uint8_t,
            aparam_length,
        );
        return m_reply;
    }
    /* if deleting 0.0.0.0/::0, delete all addresses except src addr */
    if zero_address != 0 && system_base_info.sctpsysctl.sctp_nat_friendly != 0 {
        result = sctp_asconf_del_remote_addrs_except(stcb, src);
        if result != 0 {
            /* src address did not exist? */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_asconf_delete_ip: src addr does not exist?\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            /* what error to reply with?? */
            m_reply = sctp_asconf_error_response(
                (*aph).correlation_id,
                0xa4u16,
                aph as *mut uint8_t,
                aparam_length,
            )
        } else if response_required != 0 {
            m_reply = sctp_asconf_success_response((*aph).correlation_id)
        }
        return m_reply;
    }
    /* delete the address */
    result = sctp_del_remote_addr(stcb, sa);
    /*
     * note if result == -2, the address doesn't exist in the asoc but
     * since it's being deleted anyways, we just ack the delete -- but
     * this probably means something has already gone awry
     */
    if result == -(1i32) {
        /* only one address in the asoc */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_asconf_delete_ip: tried to delete last IP addr!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        m_reply = sctp_asconf_error_response(
            (*aph).correlation_id,
            0xa0u16,
            aph as *mut uint8_t,
            aparam_length,
        )
    } else {
        if response_required != 0 {
            m_reply = sctp_asconf_success_response((*aph).correlation_id)
        }
        /* notify upper layer */
        sctp_ulp_notify(13u32, stcb, 0u32, sa as *mut libc::c_void, 0i32);
    }
    return m_reply;
}
unsafe extern "C" fn sctp_process_asconf_set_primary(
    mut src: *mut sockaddr,
    mut aph: *mut sctp_asconf_paramhdr,
    mut stcb: *mut sctp_tcb,
    mut response_required: libc::c_int,
) -> *mut mbuf {
    let mut m_reply = 0 as *mut mbuf;
    let mut store = sctp_sockstore {
        sin: sockaddr_in {
            sin_family: 0,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        },
    };
    let mut ph = 0 as *mut sctp_paramhdr;
    let mut param_type = 0;
    let mut aparam_length = 0;
    let mut param_length = 0;
    let mut sa = 0 as *mut sockaddr;
    let mut zero_address = 0i32;
    aparam_length = ntohs((*aph).ph.param_length);
    if (aparam_length as libc::c_ulong)
        < (::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
    {
        return 0 as *mut mbuf;
    }
    ph = aph.offset(1isize) as *mut sctp_paramhdr;
    param_type = ntohs((*ph).param_type);
    param_length = ntohs((*ph).param_length);
    if (param_length as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong)
        != aparam_length as libc::c_ulong
    {
        return 0 as *mut mbuf;
    }
    sa = &mut store.sa;
    match param_type as libc::c_int {
        5 => {
            let mut sin = 0 as *mut sockaddr_in;
            let mut v4addr = 0 as *mut sctp_ipv4addr_param;
            if param_length as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
            {
                /* invalid param size */
                return 0 as *mut mbuf;
            }
            v4addr = ph as *mut sctp_ipv4addr_param;
            sin = &mut store.sin;
            memset(
                sin as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong,
            );
            (*sin).sin_family = 2u16;
            (*sin).sin_addr.s_addr = (*v4addr).addr;
            if (*sin).sin_addr.s_addr == 0u32 {
                zero_address = 1i32
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_asconf_set_primary: \x00" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                sctp_print_address(sa);
            }
        }
        6 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            let mut v6addr = 0 as *mut sctp_ipv6addr_param;
            if param_length as libc::c_ulong
                != ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
            {
                /* invalid param size */
                return 0 as *mut mbuf;
            }
            v6addr = ph as *mut sctp_ipv6addr_param;
            sin6 = &mut store.sin6;
            memset(
                sin6 as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
            );
            (*sin6).sin6_family = 10u16;
            memcpy(
                &mut (*sin6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                (*v6addr).addr.as_mut_ptr() as *const libc::c_void,
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
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_asconf_set_primary: \x00" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                sctp_print_address(sa);
            }
        }
        _ => {
            m_reply = sctp_asconf_error_response(
                (*aph).correlation_id,
                0x5u16,
                aph as *mut uint8_t,
                aparam_length,
            );
            return m_reply;
        }
    }
    /* if 0.0.0.0/::0, use the source address instead */
    if zero_address != 0 && system_base_info.sctpsysctl.sctp_nat_friendly != 0 {
        sa = src;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_asconf_set_primary: using source addr \x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            sctp_print_address(src);
        }
    }
    /* set the primary address */
    if sctp_set_primary_addr(stcb, sa, 0 as *mut sctp_nets) == 0i32 {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_asconf_set_primary: primary address set\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        /* notify upper layer */
        sctp_ulp_notify(14u32, stcb, 0u32, sa as *mut libc::c_void, 0i32);
        if (*(*stcb).asoc.primary_destination).dest_state as libc::c_int & 0x1i32 != 0
            && (*(*stcb).asoc.primary_destination).dest_state as libc::c_int & 0x800i32 == 0
            && !(*stcb).asoc.alternate.is_null()
        {
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
        if response_required != 0 {
            m_reply = sctp_asconf_success_response((*aph).correlation_id)
        }
        /* Mobility adaptation.
          Ideally, when the reception of SET PRIMARY with DELETE IP
          ADDRESS of the previous primary destination, unacknowledged
          DATA are retransmitted immediately to the new primary
          destination for seamless handover.
          If the destination is UNCONFIRMED and marked to REQ_PRIM,
          The retransmission occur when reception of the
          HEARTBEAT-ACK.  (See sctp_handle_heartbeat_ack in
          sctp_input.c)
          Also, when change of the primary destination, it is better
          that all subsequent new DATA containing already queued DATA
          are transmitted to the new primary destination. (by micchie)
        */
        if ((*(*stcb).sctp_ep).sctp_mobility_features & 0x1u32 != 0
            || (*(*stcb).sctp_ep).sctp_mobility_features & 0x2u32 != 0)
            && (*(*stcb).sctp_ep).sctp_mobility_features & 0x4u32 != 0
            && (*(*stcb).asoc.primary_destination).dest_state as libc::c_int & 0x200i32 == 0i32
        {
            sctp_timer_stop(
                18i32,
                (*stcb).sctp_ep,
                stcb,
                0 as *mut sctp_nets,
                (0x80000000u32).wrapping_add(0x1u32),
            );
            if (*(*stcb).sctp_ep).sctp_mobility_features & 0x2u32 != 0 {
                sctp_assoc_immediate_retrans(stcb, (*stcb).asoc.primary_destination);
            }
            if (*(*stcb).sctp_ep).sctp_mobility_features & 0x1u32 != 0 {
                sctp_move_chunks_from_net(stcb, (*stcb).asoc.deleted_primary);
            }
            sctp_delete_prim_timer((*stcb).sctp_ep, stcb, (*stcb).asoc.deleted_primary);
        }
    } else {
        /* couldn't set the requested primary address! */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_asconf_set_primary: set primary failed!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        /* must have been an invalid address, so report */
        m_reply = sctp_asconf_error_response(
            (*aph).correlation_id,
            0x5u16,
            aph as *mut uint8_t,
            aparam_length,
        )
    }
    return m_reply;
}
/*
 * handles an ASCONF chunk.
 * if all parameters are processed ok, send a plain (empty) ASCONF-ACK
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_handle_asconf(
    mut m: *mut mbuf,
    mut offset: libc::c_uint,
    mut src: *mut sockaddr,
    mut cp: *mut sctp_asconf_chunk,
    mut stcb: *mut sctp_tcb,
    mut first: libc::c_int,
) {
    let mut asoc = 0 as *mut sctp_association;
    let mut serial_num = 0;
    let mut n = 0 as *mut mbuf;
    let mut m_ack = 0 as *mut mbuf;
    let mut m_tail = 0 as *mut mbuf;
    let mut ack_cp = 0 as *mut sctp_asconf_ack_chunk;
    let mut aph = 0 as *mut sctp_asconf_paramhdr;
    let mut p_addr = 0 as *mut sctp_ipv6addr_param;
    let mut asconf_limit = 0;
    let mut aparam_buf = [0; 512];
    let mut ack = 0 as *mut sctp_asconf_ack;
    /* verify minimum length */
    if (ntohs((*cp).ch.chunk_length) as libc::c_ulong)
        < ::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_ulong
    {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf: chunk too small = %xh\n\x00" as *const u8
                        as *const libc::c_char,
                    ntohs((*cp).ch.chunk_length) as libc::c_int,
                );
            }
        }
        return;
    }
    asoc = &mut (*stcb).asoc;
    serial_num = ntohl((*cp).serial_number);
    if (*asoc).asconf_seq_in < serial_num
        && serial_num.wrapping_sub((*asoc).asconf_seq_in) > (1u32) << 31i32
        || (*asoc).asconf_seq_in > serial_num
            && (*asoc).asconf_seq_in.wrapping_sub(serial_num) < (1u32) << 31i32
        || (*asoc).asconf_seq_in == serial_num
    {
        /* got a duplicate ASCONF */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf: got duplicate serial number = %xh\n\x00" as *const u8
                        as *const libc::c_char,
                    serial_num,
                );
            }
        }
        return;
    } else {
        if serial_num != (*asoc).asconf_seq_in.wrapping_add(1u32) {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"handle_asconf: incorrect serial number = %xh (expected next = %xh)\n\x00"
                            as *const u8 as *const libc::c_char,
                        serial_num,
                        (*asoc).asconf_seq_in.wrapping_add(1u32),
                    );
                }
            }
            return;
        }
    }
    /* it's the expected "next" sequence number, so process it */
    (*asoc).asconf_seq_in = serial_num; /* update sequence */
    /* get length of all the param's in the ASCONF */
    asconf_limit = offset.wrapping_add(ntohs((*cp).ch.chunk_length) as libc::c_uint);
    if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"handle_asconf: asconf_limit=%u, sequence=%xh\n\x00" as *const u8
                    as *const libc::c_char,
                asconf_limit,
                serial_num,
            );
        }
    }
    if first != 0 {
        let mut ack_next = 0 as *mut sctp_asconf_ack;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf: Now processing first ASCONF. Try to delete old cache\n\x00"
                        as *const u8 as *const libc::c_char,
                ); /* current reply chain's tail */
            }
        }
        ack = (*asoc).asconf_ack_sent.tqh_first;
        while !ack.is_null() && {
            ack_next = (*ack).next.tqe_next;
            (1i32) != 0
        } {
            if (*ack).serial_number == serial_num {
                break;
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"handle_asconf: delete old(%u) < first(%u)\n\x00" as *const u8
                            as *const libc::c_char,
                        (*ack).serial_number,
                        serial_num,
                    );
                }
            }
            if !(*ack).next.tqe_next.is_null() {
                (*(*ack).next.tqe_next).next.tqe_prev = (*ack).next.tqe_prev
            } else {
                (*asoc).asconf_ack_sent.tqh_last = (*ack).next.tqe_prev
            }
            *(*ack).next.tqe_prev = (*ack).next.tqe_next;
            if !(*ack).data.is_null() {
                m_freem((*ack).data);
            }
            free(ack as *mut libc::c_void);
            ack = ack_next
        }
    }
    m_ack = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_asconf_ack_chunk>() as libc::c_uint,
        0i32,
        0x1i32,
        1i32,
        1i32,
    );
    if m_ack.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf: couldn\'t get mbuf!\n\x00" as *const u8 as *const libc::c_char,
                );
            }
        }
        return;
    }
    m_tail = m_ack;
    /* fill in ASCONF-ACK header */
    ack_cp = (*m_ack).m_hdr.mh_data as *mut sctp_asconf_ack_chunk;
    (*ack_cp).ch.chunk_type = 0x80u8;
    (*ack_cp).ch.chunk_flags = 0u8;
    (*ack_cp).serial_number = htonl(serial_num);
    /* set initial lengths (eg. just an ASCONF-ACK), ntohx at the end! */
    (*m_ack).m_hdr.mh_len = ::std::mem::size_of::<sctp_asconf_ack_chunk>() as libc::c_int;
    (*ack_cp).ch.chunk_length = ::std::mem::size_of::<sctp_asconf_ack_chunk>() as uint16_t;
    /* skip the lookup address parameter */
    offset = (offset as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_ulong)
        as libc::c_uint;
    p_addr = sctp_m_getptr(
        m,
        offset as libc::c_int,
        ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
        &mut aparam_buf as *mut [uint8_t; 512] as *mut uint8_t,
    ) as *mut sctp_ipv6addr_param;
    if p_addr.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf: couldn\'t get lookup addr!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        /* respond with a missing/invalid mandatory parameter error */
        m_freem(m_ack);
        return;
    }
    /* skip lookup addr */
    offset = offset.wrapping_add(
        ((ntohs((*p_addr).ph.param_length) as libc::c_int + 3i32 >> 2i32) << 2i32) as libc::c_uint,
    );
    /* get pointer to first asconf param in ASCONF */
    aph = sctp_m_getptr(
        m,
        offset as libc::c_int,
        ::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_int,
        &mut aparam_buf as *mut [uint8_t; 512] as *mut uint8_t,
    ) as *mut sctp_asconf_paramhdr;
    if aph.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Empty ASCONF received?\n\x00" as *const u8 as *const libc::c_char,
                );
            }
        }
    } else {
        let mut cnt = 0;
        cnt = 0u32;
        while !aph.is_null() {
            let mut m_result = 0 as *mut mbuf;
            let mut error = 0i32;
            let mut param_length = 0;
            let mut param_type = 0;
            param_type = ntohs((*aph).ph.param_type) as libc::c_uint;
            param_length = ntohs((*aph).ph.param_length) as libc::c_uint;
            if offset.wrapping_add(param_length) > asconf_limit {
                /* parameter goes beyond end of chunk! */
                m_freem(m_ack);
                return;
            }
            m_result = 0 as *mut mbuf;
            if param_length as libc::c_ulong
                > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong
            {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"handle_asconf: param length (%u) larger than buffer size!\n\x00"
                                as *const u8 as *const libc::c_char,
                            param_length,
                        );
                    }
                }
                m_freem(m_ack);
                return;
            }
            if param_length as libc::c_ulong
                <= ::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong
            {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"handle_asconf: param length (%u) too short\n\x00" as *const u8
                                as *const libc::c_char,
                            param_length,
                        );
                    }
                }
                m_freem(m_ack);
                return;
            }
            /* get the entire parameter */
            aph = sctp_m_getptr(
                m,
                offset as libc::c_int,
                param_length as libc::c_int,
                aparam_buf.as_mut_ptr(),
            ) as *mut sctp_asconf_paramhdr; /* switch */
            if aph.is_null() {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"handle_asconf: couldn\'t get entire param\n\x00" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                m_freem(m_ack);
                return;
            }
            match param_type {
                49153 => {
                    m_result = sctp_process_asconf_add_ip(
                        src,
                        aph,
                        stcb,
                        (cnt < system_base_info.sctpsysctl.sctp_hb_maxburst) as libc::c_int,
                        error,
                    );
                    cnt = cnt.wrapping_add(1)
                }
                49154 => m_result = sctp_process_asconf_delete_ip(src, aph, stcb, error),
                49155 => {}
                49156 => m_result = sctp_process_asconf_set_primary(src, aph, stcb, error),
                49160 => {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"handle_asconf: sees a NAT VTAG state parameter\n\x00" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    }
                }
                49157 => {}
                49158 => {}
                _ => {
                    if param_type & 0x8000u32 == 0u32 {
                        /* Been told to STOP at this param */
                        asconf_limit = offset
                        /*
                         * FIX FIX - We need to call
                         * sctp_arethere_unrecognized_parameters()
                         * to get a operr and send it for any
                         * param's with the 0x4000 bit set OR do it
                         * here ourselves... note we still must STOP
                         * if the 0x8000 bit is clear.
                         */
                    }
                }
            }
            /* add any (error) result to the reply mbuf chain */
            if !m_result.is_null() {
                (*m_tail).m_hdr.mh_next = m_result;
                m_tail = m_result;
                (*ack_cp).ch.chunk_length = ((*ack_cp).ch.chunk_length as libc::c_int
                    + (*m_result).m_hdr.mh_len)
                    as uint16_t;
                /* set flag to force success reports */
                error = 1i32
            }
            offset = offset.wrapping_add((param_length.wrapping_add(3u32) >> 2i32) << 2i32);
            /* update remaining ASCONF message length to process */
            if offset >= asconf_limit {
                break;
            }
            /* get pointer to next asconf param */
            aph = sctp_m_getptr(
                m,
                offset as libc::c_int,
                ::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_int,
                &mut aparam_buf as *mut [uint8_t; 512] as *mut uint8_t,
            ) as *mut sctp_asconf_paramhdr;
            if aph.is_null() {
                /* can't get an asconf paramhdr */
                if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"handle_asconf: can\'t get asconf param hdr!\n\x00" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                /* FIX ME - add error here... */
            }
        }
    }
    (*ack_cp).ch.chunk_length = htons((*ack_cp).ch.chunk_length);
    /* save the ASCONF-ACK reply */
    ack = malloc(system_base_info.sctppcbinfo.ipi_zone_asconf_ack) as *mut sctp_asconf_ack;
    if ack.is_null() {
        m_freem(m_ack);
        return;
    }
    (*ack).serial_number = serial_num;
    (*ack).last_sent_to = 0 as *mut sctp_nets;
    (*ack).data = m_ack;
    (*ack).len = 0u16;
    n = m_ack;
    while !n.is_null() {
        (*ack).len = ((*ack).len as libc::c_int + (*n).m_hdr.mh_len) as uint16_t;
        n = (*n).m_hdr.mh_next
    }
    (*ack).next.tqe_next = 0 as *mut sctp_asconf_ack;
    (*ack).next.tqe_prev = (*stcb).asoc.asconf_ack_sent.tqh_last;
    *(*stcb).asoc.asconf_ack_sent.tqh_last = ack;
    (*stcb).asoc.asconf_ack_sent.tqh_last = &mut (*ack).next.tqe_next;
    /* see if last_control_chunk_from is set properly (use IP src addr) */
    if (*stcb).asoc.last_control_chunk_from.is_null() {
        /*
         * this could happen if the source address was just newly
         * added
         */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf: looking up net for IP source address\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Looking for IP source: \x00" as *const u8 as *const libc::c_char,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            sctp_print_address(src);
        }
        /* look up the from address */
        (*stcb).asoc.last_control_chunk_from = sctp_findnet(stcb, src);
        if (*stcb).asoc.last_control_chunk_from.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"handle_asconf: IP source address not found?!\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        }
    };
}
/*
 * does the address match? returns 0 if not, 1 if so
 */
unsafe extern "C" fn sctp_asconf_addr_match(
    mut aa: *mut sctp_asconf_addr,
    mut sa: *mut sockaddr,
) -> uint32_t {
    match (*sa).sa_family as libc::c_int {
        10 => {
            let mut sin6 = sa as *mut sockaddr_in6;
            if (*aa).ap.addrp.ph.param_type as libc::c_int == 0x6i32
                && memcmp(
                    &mut (*aa).ap.addrp.addr as *mut [uint8_t; 16] as *const libc::c_void,
                    &mut (*sin6).sin6_addr as *mut in6_addr as *const libc::c_void,
                    ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
                ) == 0i32
            {
                return 1u32;
            }
        }
        2 => {
            let mut sin = sa as *mut sockaddr_in;
            if (*aa).ap.addrp.ph.param_type as libc::c_int == 0x5i32
                && memcmp(
                    &mut (*aa).ap.addrp.addr as *mut [uint8_t; 16] as *const libc::c_void,
                    &mut (*sin).sin_addr as *mut in_addr as *const libc::c_void,
                    ::std::mem::size_of::<in_addr>() as libc::c_ulong,
                ) == 0i32
            {
                return 1u32;
            }
        }
        _ => {}
    }
    return 0u32;
}
/*
 * does the address match? returns 0 if not, 1 if so
 */
unsafe extern "C" fn sctp_addr_match(
    mut ph: *mut sctp_paramhdr,
    mut sa: *mut sockaddr,
) -> uint32_t {
    let mut param_type = 0;
    let mut param_length = 0;
    param_type = ntohs((*ph).param_type);
    param_length = ntohs((*ph).param_length);
    match (*sa).sa_family as libc::c_int {
        10 => {
            let mut v6addr = 0 as *mut sctp_ipv6addr_param;
            let mut sin6 = sa as *mut sockaddr_in6;

            v6addr = ph as *mut sctp_ipv6addr_param;
            if param_type as libc::c_int == 0x6i32
                && param_length as libc::c_ulong
                    == ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
                && memcmp(
                    &mut (*v6addr).addr as *mut [uint8_t; 16] as *const libc::c_void,
                    &mut (*sin6).sin6_addr as *mut in6_addr as *const libc::c_void,
                    ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
                ) == 0i32
            {
                return 1u32;
            }
        }
        2 => {
            let mut v4addr = 0 as *mut sctp_ipv4addr_param;
            let mut sin = sa as *mut sockaddr_in;

            v4addr = ph as *mut sctp_ipv4addr_param;
            if param_type as libc::c_int == 0x5i32
                && param_length as libc::c_ulong
                    == ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
                && memcmp(
                    &mut (*v4addr).addr as *mut uint32_t as *const libc::c_void,
                    &mut (*sin).sin_addr as *mut in_addr as *const libc::c_void,
                    ::std::mem::size_of::<in_addr>() as libc::c_ulong,
                ) == 0i32
            {
                return 1u32;
            }
        }
        _ => {}
    }
    return 0u32;
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
 * function prototypes
 */
/*
 * Cleanup for non-responded/OP ERR'd ASCONF
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_asconf_cleanup(mut stcb: *mut sctp_tcb, mut net: *mut sctp_nets) {
    /*
     * clear out any existing asconfs going out
     */
    sctp_timer_stop(
        10i32,
        (*stcb).sctp_ep,
        stcb,
        net,
        (0x80000000u32).wrapping_add(0x2u32),
    );
    (*stcb).asoc.asconf_seq_out_acked = (*stcb).asoc.asconf_seq_out;
    /* remove the old ASCONF on our outbound queue */
    sctp_toss_old_asconf(stcb);
}
/*
 * cleanup any cached source addresses that may be topologically
 * incorrect after a new address has been added to this interface.
 */
unsafe extern "C" fn sctp_asconf_nets_cleanup(mut stcb: *mut sctp_tcb, mut ifn: *mut sctp_ifn) {
    let mut net = 0 as *mut sctp_nets;
    /*
     * Ideally, we want to only clear cached routes and source addresses
     * that are topologically incorrect.  But since there is no easy way
     * to know whether the newly added address on the ifn would cause a
     * routing change (i.e. a new egress interface would be chosen)
     * without doing a new routing lookup and source address selection,
     * we will (for now) just flush any cached route using a different
     * ifn (and cached source addrs) and let output re-choose them during
     * the next send on that net.
     */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        /*
         * clear any cached route (and cached source address) if the
         * route's interface is NOT the same as the address change.
         * If it's the same interface, just clear the cached source
         * address.
         */
        if !(*net).ro.ro_rt.is_null()
            && !(*(*net).ro.ro_rt).rt_ifp.is_null()
            && (ifn.is_null() || 1u32 != (*ifn).ifn_index)
        {
            /* clear any cached route */
            if (*(*net).ro.ro_rt).rt_refcnt <= 1i64 {
                sctp_userspace_rtfree((*net).ro.ro_rt);
            } else {
                (*(*net).ro.ro_rt).rt_refcnt -= 1
            }
            (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t;
            (*net).ro.ro_rt = 0 as *mut sctp_rtentry_t
        }
        /* clear any cached source address */
        if (*net).src_addr_selected != 0 {
            sctp_free_ifa((*net).ro._s_addr);
            (*net).ro._s_addr = 0 as *mut sctp_ifa;
            (*net).src_addr_selected = 0u8
        }
        net = (*net).sctp_next.tqe_next
    }
}
#[no_mangle]
pub unsafe extern "C" fn sctp_assoc_immediate_retrans(
    mut stcb: *mut sctp_tcb,
    mut dstnet: *mut sctp_nets,
) {
    if (*dstnet).dest_state as libc::c_int & 0x200i32 != 0 {
        return;
    }
    if (*stcb).asoc.deleted_primary.is_null() {
        return;
    }
    if !(*stcb).asoc.sent_queue.tqh_first.is_null() {
        let mut error = 0;
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"assoc_immediate_retrans: Deleted primary is \x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            sctp_print_address(&mut (*(*stcb).asoc.deleted_primary).ro._l_addr.sa);
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"Current Primary is \x00" as *const u8 as *const libc::c_char,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            sctp_print_address(&mut (*(*stcb).asoc.primary_destination).ro._l_addr.sa);
        }
        sctp_timer_stop(
            1i32,
            (*stcb).sctp_ep,
            stcb,
            (*stcb).asoc.deleted_primary,
            (0x80000000u32).wrapping_add(0x3u32),
        );
        (*stcb).asoc.num_send_timers_up -= 1;
        if ((*stcb).asoc.num_send_timers_up as libc::c_int) < 0i32 {
            (*stcb).asoc.num_send_timers_up = 0i16
        }
        error = sctp_t3rxt_timer((*stcb).sctp_ep, stcb, (*stcb).asoc.deleted_primary);
        if error != 0 {
            ::std::intrinsics::atomic_xadd(&mut (*(*stcb).sctp_ep).refcount, -(1i32));
            return;
        }
        sctp_chunk_output((*stcb).sctp_ep, stcb, 1i32, 0i32);
        if (*stcb).asoc.num_send_timers_up as libc::c_int == 0i32
            && (*stcb).asoc.sent_queue_cnt > 0u32
        {
            let mut chk = 0 as *mut sctp_tmit_chunk;
            chk = (*stcb).asoc.sent_queue.tqh_first;
            sctp_timer_start(1i32, (*stcb).sctp_ep, stcb, (*chk).whoTo);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_net_immediate_retrans(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"net_immediate_retrans: RTO is %d\n\x00" as *const u8 as *const libc::c_char,
                (*net).RTO,
            );
        }
    }
    sctp_timer_stop(
        1i32,
        (*stcb).sctp_ep,
        stcb,
        net,
        (0x80000000u32).wrapping_add(0x4u32),
    );
    (*stcb)
        .asoc
        .cc_functions
        .sctp_set_initial_cc_param
        .expect("non-null function pointer")(stcb, net);
    (*net).error_count = 0u16;
    chk = (*stcb).asoc.sent_queue.tqh_first;
    while !chk.is_null() {
        if (*chk).whoTo == net {
            if (*chk).sent < 4i32 {
                (*chk).sent = 4i32;
                (*stcb).asoc.sent_queue_retran_cnt =
                    (*stcb).asoc.sent_queue_retran_cnt.wrapping_add(1);
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
                (*net).marked_retrans = (*net).marked_retrans.wrapping_add(1);
                (*stcb).asoc.marked_retrans = (*stcb).asoc.marked_retrans.wrapping_add(1)
            }
        }
        chk = (*chk).sctp_next.tqe_next
    }
    if (*net).marked_retrans != 0 {
        sctp_chunk_output((*stcb).sctp_ep, stcb, 1i32, 0i32);
    };
}
unsafe extern "C" fn sctp_path_check_and_react(mut stcb: *mut sctp_tcb, mut newifa: *mut sctp_ifa) {
    let mut net = 0 as *mut sctp_nets;
    let mut addrnum = 0;
    /*   If number of local valid addresses is 1, the valid address is
        probably newly added address.
        Several valid addresses in this association.  A source address
        may not be changed.  Additionally, they can be configured on a
        same interface as "alias" addresses.  (by micchie)
    */
    addrnum = sctp_local_addr_count(stcb);
    if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"p_check_react(): %d local addresses\n\x00" as *const u8 as *const libc::c_char,
                addrnum,
            );
        }
    }
    if addrnum == 1i32 {
        net = (*stcb).asoc.nets.tqh_first;
        while !net.is_null() {
            /* clear any cached route and source address */
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
                (*net).ro._s_addr = 0 as *mut sctp_ifa;
                (*net).src_addr_selected = 0u8
            }
            /* also, SET PRIMARY is maybe already sent */
            if (*(*stcb).sctp_ep).sctp_mobility_features & 0x2u32 != 0 {
                sctp_net_immediate_retrans(stcb, net);
            }
            net = (*net).sctp_next.tqe_next
        }
        return;
    }
    /* Retransmit unacknowledged DATA chunks immediately */
    /* Multiple local addresses exsist in the association.  */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        /* clear any cached route and source address */
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
            (*net).ro._s_addr = 0 as *mut sctp_ifa;
            (*net).src_addr_selected = 0u8
        }
        /* Check if the nexthop is corresponding to the new address.
          If the new address is corresponding to the current nexthop,
          the path will be changed.
          If the new address is NOT corresponding to the current
          nexthop, the path will not be changed.
        */
        sctp_userspace_rtalloc(&mut (*net).ro as *mut sctp_net_route as *mut sctp_route_t);
        if !(*net).ro.ro_rt.is_null() {
            let mut changed = 0;
            changed = 0i32;
            match (*net).ro._l_addr.sa.sa_family as libc::c_int {
                2 => {
                    if sctp_v4src_match_nexthop(
                        newifa,
                        &mut (*net).ro as *mut sctp_net_route as *mut sctp_route_t,
                    ) != 0
                    {
                        changed = 1i32
                    }
                }
                10 => {
                    if sctp_v6src_match_nexthop(
                        &mut (*newifa).address.sin6,
                        &mut (*net).ro as *mut sctp_net_route as *mut sctp_route_t,
                    ) != 0
                    {
                        changed = 1i32
                    }
                }
                _ => {}
            }
            /* if the newly added address does not relate routing
              information, we skip.
            */
            if !(changed == 0i32) {
                /* Retransmit unacknowledged DATA chunks immediately */
                if (*(*stcb).sctp_ep).sctp_mobility_features & 0x2u32 != 0 {
                    sctp_net_immediate_retrans(stcb, net);
                }
                /* Send SET PRIMARY for this new address */
                if net == (*stcb).asoc.primary_destination {
                    sctp_asconf_queue_mgmt(stcb, newifa, 0xc004u16);
                }
            }
        }
        net = (*net).sctp_next.tqe_next
    }
}
/* __FreeBSD__  __APPLE__  __Userspace__ */
/*
 * process an ADD/DELETE IP ack from peer.
 * addr: corresponding sctp_ifa to the address being added/deleted.
 * type: SCTP_ADD_IP_ADDRESS or SCTP_DEL_IP_ADDRESS.
 * flag: 1=success, 0=failure.
 */
unsafe extern "C" fn sctp_asconf_addr_mgmt_ack(
    mut stcb: *mut sctp_tcb,
    mut addr: *mut sctp_ifa,
    mut flag: uint32_t,
) {
    /*
     * do the necessary asoc list work- if we get a failure indication,
     * leave the address on the assoc's restricted list.  If we get a
     * success indication, remove the address from the restricted list.
     */
    /*
     * Note: this will only occur for ADD_IP_ADDRESS, since
     * DEL_IP_ADDRESS is never actually added to the list...
     */
    if flag != 0 {
        /* success case, so remove from the restricted list */
        sctp_del_local_addr_restricted(stcb, addr);
        if (*(*stcb).sctp_ep).sctp_mobility_features & 0x1u32 != 0
            || (*(*stcb).sctp_ep).sctp_mobility_features & 0x2u32 != 0
        {
            sctp_path_check_and_react(stcb, addr);
            return;
        }
        /* __FreeBSD__ __APPLE__ __Userspace__ */
        /* clear any cached/topologically incorrect source addresses */
        sctp_asconf_nets_cleanup(stcb, (*addr).ifn_p);
    };
    /* else, leave it on the list */
}
/*
 * add an asconf add/delete/set primary IP address parameter to the queue.
 * type = SCTP_ADD_IP_ADDRESS, SCTP_DEL_IP_ADDRESS, SCTP_SET_PRIM_ADDR.
 * returns 0 if queued, -1 if not queued/removed.
 * NOTE: if adding, but a delete for the same address is already scheduled
 * (and not yet sent out), simply remove it from queue.  Same for deleting
 * an address already scheduled for add.  If a duplicate operation is found,
 * ignore the new one.
 */
unsafe extern "C" fn sctp_asconf_queue_mgmt(
    mut stcb: *mut sctp_tcb,
    mut ifa: *mut sctp_ifa,
    mut type_0: uint16_t,
) -> libc::c_int {
    let mut aa = 0 as *mut sctp_asconf_addr;
    let mut aa_next = 0 as *mut sctp_asconf_addr;
    /* make sure the request isn't already in the queue */
    aa = (*stcb).asoc.asconf_queue.tqh_first; /* for each aa */
    while !aa.is_null() && {
        aa_next = (*aa).next.tqe_next;
        (1i32) != 0
    } {
        /* address match? */
        if !(sctp_asconf_addr_match(aa, &mut (*ifa).address.sa) == 0u32) {
            /* is the request already in queue but not sent?
             * pass the request already sent in order to resolve the following case:
             *  1. arrival of ADD, then sent
             *  2. arrival of DEL. we can't remove the ADD request already sent
             *  3. arrival of ADD
             */
            if (*aa).ap.aph.ph.param_type as libc::c_int == type_0 as libc::c_int
                && (*aa).sent as libc::c_int == 0i32
            {
                return -(1i32);
            }
            /* is the negative request already in queue, and not sent */
            if (*aa).sent as libc::c_int == 0i32
                && type_0 as libc::c_int == 0xc001i32
                && (*aa).ap.aph.ph.param_type as libc::c_int == 0xc002i32
            {
                /* add requested, delete already queued */
                if !(*aa).next.tqe_next.is_null() {
                    (*(*aa).next.tqe_next).next.tqe_prev = (*aa).next.tqe_prev
                } else {
                    (*stcb).asoc.asconf_queue.tqh_last = (*aa).next.tqe_prev
                }
                *(*aa).next.tqe_prev = (*aa).next.tqe_next;
                /* remove the ifa from the restricted list */
                sctp_del_local_addr_restricted(stcb, ifa);
                /* free the asconf param */
                free(aa as *mut libc::c_void);
                if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"asconf_queue_mgmt: add removes queued entry\n\x00" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                return -(1i32);
            }
            if (*aa).sent as libc::c_int == 0i32
                && type_0 as libc::c_int == 0xc002i32
                && (*aa).ap.aph.ph.param_type as libc::c_int == 0xc001i32
            {
                /* delete requested, add already queued */
                if !(*aa).next.tqe_next.is_null() {
                    (*(*aa).next.tqe_next).next.tqe_prev = (*aa).next.tqe_prev
                } else {
                    (*stcb).asoc.asconf_queue.tqh_last = (*aa).next.tqe_prev
                }
                *(*aa).next.tqe_prev = (*aa).next.tqe_next;
                /* remove the aa->ifa from the restricted list */
                sctp_del_local_addr_restricted(stcb, (*aa).ifa);
                /* free the asconf param */
                free(aa as *mut libc::c_void);
                if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"asconf_queue_mgmt: delete removes queued entry\n\x00" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
                return -(1i32);
            }
        }
        aa = aa_next
    }
    /* adding new request to the queue */
    aa =
        malloc(::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong) as *mut sctp_asconf_addr;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            aa as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong,
        );
    }
    if aa.is_null() {
        /* didn't get memory */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_queue_mgmt: failed to get memory!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return -(1i32);
    }
    (*aa).special_del = 0u8;
    /* fill in asconf address parameter fields */
    /* top level elements are "networked" during send */
    (*aa).ap.aph.ph.param_type = type_0;
    (*aa).ifa = ifa;
    ::std::intrinsics::atomic_xadd(&mut (*ifa).refcount, 1u32);
    /* correlation_id filled in during send routine later... */
    match (*ifa).address.sa.sa_family as libc::c_int {
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 = &mut (*ifa).address.sin6;
            (*aa).ap.addrp.ph.param_type = 0x6u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv6addr_param>() as uint16_t;
            (*aa).ap.aph.ph.param_length = (::std::mem::size_of::<sctp_asconf_paramhdr>()
                as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong)
                as uint16_t;
            memcpy(
                &mut (*aa).ap.addrp.addr as *mut [uint8_t; 16] as *mut libc::c_void,
                &mut (*sin6).sin6_addr as *mut in6_addr as *const libc::c_void,
                ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
            );
        }
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            sin = &mut (*ifa).address.sin;
            (*aa).ap.addrp.ph.param_type = 0x5u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv4addr_param>() as uint16_t;
            (*aa).ap.aph.ph.param_length = (::std::mem::size_of::<sctp_asconf_paramhdr>()
                as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong)
                as uint16_t;
            memcpy(
                &mut (*aa).ap.addrp.addr as *mut [uint8_t; 16] as *mut libc::c_void,
                &mut (*sin).sin_addr as *mut in_addr as *const libc::c_void,
                ::std::mem::size_of::<in_addr>() as libc::c_ulong,
            );
        }
        _ => {
            /* invalid family! */
            free(aa as *mut libc::c_void); /* clear sent flag */
            sctp_free_ifa(ifa);
            return -(1i32);
        }
    }
    (*aa).sent = 0u8;
    (*aa).next.tqe_next = 0 as *mut sctp_asconf_addr;
    (*aa).next.tqe_prev = (*stcb).asoc.asconf_queue.tqh_last;
    *(*stcb).asoc.asconf_queue.tqh_last = aa;
    (*stcb).asoc.asconf_queue.tqh_last = &mut (*aa).next.tqe_next;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
        if type_0 as libc::c_int == 0xc001i32 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_queue_mgmt: inserted asconf ADD_IP_ADDRESS: \x00" as *const u8
                        as *const libc::c_char,
                );
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
                sctp_print_address(&mut (*ifa).address.sa);
            }
        } else if type_0 as libc::c_int == 0xc002i32 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_queue_mgmt: appended asconf DEL_IP_ADDRESS: \x00" as *const u8
                        as *const libc::c_char,
                );
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
                sctp_print_address(&mut (*ifa).address.sa);
            }
        } else {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_queue_mgmt: appended asconf SET_PRIM_ADDR: \x00" as *const u8
                        as *const libc::c_char,
                );
            }
            if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
                sctp_print_address(&mut (*ifa).address.sa);
            }
        }
    }
    return 0i32;
}
/*
 * add an asconf operation for the given ifa and type.
 * type = SCTP_ADD_IP_ADDRESS, SCTP_DEL_IP_ADDRESS, SCTP_SET_PRIM_ADDR.
 * returns 0 if completed, -1 if not completed, 1 if immediate send is
 * advisable.
 */
unsafe extern "C" fn sctp_asconf_queue_add(
    mut stcb: *mut sctp_tcb,
    mut ifa: *mut sctp_ifa,
    mut type_0: uint16_t,
) -> libc::c_int {
    let mut status = 0;
    let mut pending_delete_queued = 0i32;
    /* see if peer supports ASCONF */
    if (*stcb).asoc.asconf_supported as libc::c_int == 0i32 {
        return -(1i32);
    }
    /*
     * if this is deleting the last address from the assoc, mark it as
     * pending.
     */
    if type_0 as libc::c_int == 0xc002i32 && (*stcb).asoc.asconf_del_pending == 0 {
        let mut last = 0;
        if (*(*stcb).sctp_ep).sctp_flags & 0x4u32 != 0 {
            last = (sctp_local_addr_count(stcb) == 0i32) as libc::c_int
        } else {
            last = (sctp_local_addr_count(stcb) == 1i32) as libc::c_int
        }
        if last != 0 {
            /* set the pending delete info only */
            (*stcb).asoc.asconf_del_pending = 1u8;
            (*stcb).asoc.asconf_addr_del_pending = ifa;
            ::std::intrinsics::atomic_xadd(&mut (*ifa).refcount, 1u32);
            if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"asconf_queue_add: mark delete last address pending\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            return -(1i32);
        }
    }
    /* queue an asconf parameter */
    status = sctp_asconf_queue_mgmt(stcb, ifa, type_0) as uint32_t;
    /*
     * if this is an add, and there is a delete also pending (i.e. the
     * last local address is being changed), queue the pending delete too.
     */
    if type_0 as libc::c_int == 0xc001i32
        && (*stcb).asoc.asconf_del_pending as libc::c_int != 0
        && status == 0u32
    {
        /* queue in the pending delete */
        if sctp_asconf_queue_mgmt(stcb, (*stcb).asoc.asconf_addr_del_pending, 0xc002u16) == 0i32 {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"asconf_queue_add: queuing pending delete\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            pending_delete_queued = 1i32;
            /* clear out the pending delete info */
            (*stcb).asoc.asconf_del_pending = 0u8;
            sctp_free_ifa((*stcb).asoc.asconf_addr_del_pending);
            (*stcb).asoc.asconf_addr_del_pending = 0 as *mut sctp_ifa
        }
    }
    if pending_delete_queued != 0 {
        let mut net = 0 as *mut sctp_nets;
        /*
         * since we know that the only/last address is now being
         * changed in this case, reset the cwnd/rto on all nets to
         * start as a new address and path.  Also clear the error
         * counts to give the assoc the best chance to complete the
         * address change.
         */
        net = (*stcb).asoc.nets.tqh_first;
        while !net.is_null() {
            (*stcb)
                .asoc
                .cc_functions
                .sctp_set_initial_cc_param
                .expect("non-null function pointer")(stcb, net);
            (*net).RTO = 0u32;
            (*net).error_count = 0u16;
            net = (*net).sctp_next.tqe_next
        }
        (*stcb).asoc.overall_error_count = 0u32;
        if system_base_info.sctpsysctl.sctp_logging_level & 0x2000000u32 != 0 {
            sctp_misc_ints(
                120u8,
                (*stcb).asoc.overall_error_count,
                0u32,
                0x80000000u32,
                1439u32,
            );
        }
        /* queue in an advisory set primary too */
        sctp_asconf_queue_mgmt(stcb, ifa, 0xc004u16);
        /* let caller know we should send this out immediately */
        status = 1u32
    }
    return status as libc::c_int;
}
/*-
 * add an asconf delete IP address parameter to the queue by sockaddr and
 * possibly with no sctp_ifa available.  This is only called by the routine
 * that checks the addresses in an INIT-ACK against the current address list.
 * returns 0 if completed, non-zero if not completed.
 * NOTE: if an add is already scheduled (and not yet sent out), simply
 * remove it from queue.  If a duplicate operation is found, ignore the
 * new one.
 */
unsafe extern "C" fn sctp_asconf_queue_sa_delete(
    mut stcb: *mut sctp_tcb,
    mut sa: *mut sockaddr,
) -> libc::c_int {
    let mut ifa = 0 as *mut sctp_ifa;
    let mut aa = 0 as *mut sctp_asconf_addr;
    let mut aa_next = 0 as *mut sctp_asconf_addr;
    if stcb.is_null() {
        return -(1i32);
    }
    /* see if peer supports ASCONF */
    if (*stcb).asoc.asconf_supported as libc::c_int == 0i32 {
        return -(1i32);
    }
    /* make sure the request isn't already in the queue */
    aa = (*stcb).asoc.asconf_queue.tqh_first; /* for each aa */
    while !aa.is_null() && {
        aa_next = (*aa).next.tqe_next;
        (1i32) != 0
    } {
        /* address match? */
        if !(sctp_asconf_addr_match(aa, sa) == 0u32) {
            /* is the request already in queue (sent or not) */
            if (*aa).ap.aph.ph.param_type as libc::c_int == 0xc002i32 {
                return -(1i32);
            }
            /* is the negative request already in queue, and not sent */
            if !((*aa).sent as libc::c_int == 1i32) {
                if (*aa).ap.aph.ph.param_type as libc::c_int == 0xc001i32 {
                    /* add already queued, so remove existing entry */
                    if !(*aa).next.tqe_next.is_null() {
                        (*(*aa).next.tqe_next).next.tqe_prev = (*aa).next.tqe_prev
                    } else {
                        (*stcb).asoc.asconf_queue.tqh_last = (*aa).next.tqe_prev
                    }
                    *(*aa).next.tqe_prev = (*aa).next.tqe_next;
                    sctp_del_local_addr_restricted(stcb, (*aa).ifa);
                    /* free the entry */
                    free(aa as *mut libc::c_void);
                    return -(1i32);
                }
            }
        }
        aa = aa_next
    }
    /* find any existing ifa-- NOTE ifa CAN be allowed to be NULL */
    ifa = sctp_find_ifa_by_addr(sa, (*stcb).asoc.vrf_id, 0i32);
    /* adding new request to the queue */
    aa =
        malloc(::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong) as *mut sctp_asconf_addr;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            aa as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong,
        );
    }
    if aa.is_null() {
        /* didn't get memory */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"sctp_asconf_queue_sa_delete: failed to get memory!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return -(1i32);
    }
    (*aa).special_del = 0u8;
    /* fill in asconf address parameter fields */
    /* top level elements are "networked" during send */
    (*aa).ap.aph.ph.param_type = 0xc002u16;
    (*aa).ifa = ifa;
    if !ifa.is_null() {
        ::std::intrinsics::atomic_xadd(&mut (*ifa).refcount, 1u32);
    }
    /* correlation_id filled in during send routine later... */
    match (*sa).sa_family as libc::c_int {
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 = sa as *mut sockaddr_in6;
            (*aa).ap.addrp.ph.param_type = 0x6u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv6addr_param>() as uint16_t;
            (*aa).ap.aph.ph.param_length = (::std::mem::size_of::<sctp_asconf_paramhdr>()
                as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong)
                as uint16_t;
            memcpy(
                &mut (*aa).ap.addrp.addr as *mut [uint8_t; 16] as *mut libc::c_void,
                &mut (*sin6).sin6_addr as *mut in6_addr as *const libc::c_void,
                ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
            );
        }
        2 => {
            let mut sin = sa as *mut sockaddr_in;
            (*aa).ap.addrp.ph.param_type = 0x5u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv4addr_param>() as uint16_t;
            (*aa).ap.aph.ph.param_length = (::std::mem::size_of::<sctp_asconf_paramhdr>()
                as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong)
                as uint16_t;
            memcpy(
                &mut (*aa).ap.addrp.addr as *mut [uint8_t; 16] as *mut libc::c_void,
                &mut (*sin).sin_addr as *mut in_addr as *const libc::c_void,
                ::std::mem::size_of::<in_addr>() as libc::c_ulong,
            );
        }
        _ => {
            /* invalid family! */
            free(aa as *mut libc::c_void); /* clear sent flag */
            if !ifa.is_null() {
                sctp_free_ifa(ifa);
            }
            return -(1i32);
        }
    }
    (*aa).sent = 0u8;
    /* delete goes to the back of the queue */
    (*aa).next.tqe_next = 0 as *mut sctp_asconf_addr;
    (*aa).next.tqe_prev = (*stcb).asoc.asconf_queue.tqh_last;
    *(*stcb).asoc.asconf_queue.tqh_last = aa;
    (*stcb).asoc.asconf_queue.tqh_last = &mut (*aa).next.tqe_next;
    /* sa_ignore MEMLEAK {memory is put on the tailq} */
    return 0i32;
}
/*
 * find a specific asconf param on our "sent" queue
 */
unsafe extern "C" fn sctp_asconf_find_param(
    mut stcb: *mut sctp_tcb,
    mut correlation_id: uint32_t,
) -> *mut sctp_asconf_addr {
    let mut aa = 0 as *mut sctp_asconf_addr;
    aa = (*stcb).asoc.asconf_queue.tqh_first;
    while !aa.is_null() {
        if (*aa).ap.aph.correlation_id == correlation_id && (*aa).sent as libc::c_int == 1i32 {
            /* found it */
            return aa;
        }
        aa = (*aa).next.tqe_next
    }
    /* didn't find it */
    return 0 as *mut sctp_asconf_addr;
}
/*
 * process an SCTP_ERROR_CAUSE_IND for a ASCONF-ACK parameter and do
 * notifications based on the error response
 */
unsafe extern "C" fn sctp_asconf_process_error(
    mut stcb: *mut sctp_tcb,
    mut aph: *mut sctp_asconf_paramhdr,
) {
    let mut eh = 0 as *mut sctp_error_cause;
    let mut ph = 0 as *mut sctp_paramhdr;
    let mut param_type = 0;
    let mut error_code = 0;
    eh = aph.offset(1isize) as *mut sctp_error_cause;
    ph = eh.offset(1isize) as *mut sctp_paramhdr;
    /* validate lengths */
    if (htons((*eh).length) as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_error_cause>() as libc::c_ulong)
        > htons((*aph).ph.param_length) as libc::c_ulong
    {
        /* invalid error cause length */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_process_error: cause element too long\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return;
    }
    if (htons((*ph).param_length) as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
        > htons((*eh).length) as libc::c_ulong
    {
        /* invalid included TLV length */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"asconf_process_error: included TLV too long\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return;
    }
    /* which error code ? */
    error_code = ntohs((*eh).code);
    param_type = ntohs((*aph).ph.param_type);
    /* FIX: this should go back up the REMOTE_ERROR ULP notify */
    match error_code as libc::c_int {
        161 => {}
        _ => {
            /* peer can't handle it... */
            match param_type as libc::c_int {
                49153 | 49154 | 49156 | _ => {}
            }
        }
    };
}
/*
 * process an asconf queue param.
 * aparam: parameter to process, will be removed from the queue.
 * flag: 1=success case, 0=failure case
 */
unsafe extern "C" fn sctp_asconf_process_param_ack(
    mut stcb: *mut sctp_tcb,
    mut aparam: *mut sctp_asconf_addr,
    mut flag: uint32_t,
) {
    let mut param_type = 0;
    /* process this param */
    param_type = (*aparam).ap.aph.ph.param_type;
    match param_type as libc::c_int {
        49153 => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_param_ack: added IP address\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            sctp_asconf_addr_mgmt_ack(stcb, (*aparam).ifa, flag);
        }
        49154 => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_param_ack: deleted IP address\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        }
        49156 => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"process_param_ack: set primary IP address\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        }
        _ => {}
    }
    /* remove the param and free it */
    if !(*aparam).next.tqe_next.is_null() {
        (*(*aparam).next.tqe_next).next.tqe_prev = (*aparam).next.tqe_prev
    } else {
        (*stcb).asoc.asconf_queue.tqh_last = (*aparam).next.tqe_prev
    }
    *(*aparam).next.tqe_prev = (*aparam).next.tqe_next;
    if !(*aparam).ifa.is_null() {
        sctp_free_ifa((*aparam).ifa);
    }
    free(aparam as *mut libc::c_void);
}
/*
 * cleanup from a bad asconf ack parameter
 */
unsafe extern "C" fn sctp_asconf_ack_clear(mut stcb: *mut sctp_tcb) {
    /* assume peer doesn't really know how to do asconfs */
    /* XXX we could free the pending queue here */
}
#[no_mangle]
pub unsafe extern "C" fn sctp_handle_asconf_ack(
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut cp: *mut sctp_asconf_ack_chunk,
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
    mut abort_no_unlock: *mut libc::c_int,
) {
    let mut asoc = 0 as *mut sctp_association;
    let mut serial_num = 0;
    let mut ack_length = 0;
    let mut aa = 0 as *mut sctp_asconf_addr;
    let mut aa_next = 0 as *mut sctp_asconf_addr;
    let mut last_error_id = 0u32;
    /* verify minimum length */
    if (ntohs((*cp).ch.chunk_length) as libc::c_ulong)
        < ::std::mem::size_of::<sctp_asconf_ack_chunk>() as libc::c_ulong
    {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf_ack: chunk too small = %xh\n\x00" as *const u8
                        as *const libc::c_char,
                    ntohs((*cp).ch.chunk_length) as libc::c_int,
                );
            }
        }
        return;
    }
    asoc = &mut (*stcb).asoc;
    serial_num = ntohl((*cp).serial_number);
    /*
     * NOTE: we may want to handle this differently- currently, we will
     * abort when we get an ack for the expected serial number + 1 (eg.
     * we didn't send it), process an ack normally if it is the expected
     * serial number, and re-send the previous ack for *ALL* other
     * serial numbers
     */
    /*
     * if the serial number is the next expected, but I didn't send it,
     * abort the asoc, since someone probably just hijacked us...
     */
    if serial_num == (*asoc).asconf_seq_out.wrapping_add(1u32) {
        let mut op_err = 0 as *mut mbuf;
        let mut msg = [0; 128];
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"handle_asconf_ack: got unexpected next serial number! Aborting asoc!\n\x00"
                        as *const u8 as *const libc::c_char,
                );
            }
        }
        snprintf(
            msg.as_mut_ptr(),
            ::std::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            b"Never sent serial number %8.8x\x00" as *const u8 as *const libc::c_char,
            serial_num,
        );
        op_err = sctp_generate_cause(0xdu16, msg.as_mut_ptr());
        sctp_abort_an_association((*stcb).sctp_ep, stcb, op_err, 0i32);
        *abort_no_unlock = 1i32;
        return;
    }
    if serial_num != (*asoc).asconf_seq_out_acked.wrapping_add(1u32) {
        /* got a duplicate/unexpected ASCONF-ACK */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info.debug_printf.expect("non-null function pointer")(b"handle_asconf_ack: got duplicate/unexpected serial number = %xh (expected = %xh)\n\x00"
                                                                                      as
                                                                                      *const u8
                                                                                      as
                                                                                      *const libc::c_char,
                                                                                  serial_num,
                                                                                  (*asoc).asconf_seq_out_acked.wrapping_add(1u32));
            }
        }
        return;
    }
    if serial_num == (*asoc).asconf_seq_out.wrapping_sub(1u32) {
        /* stop our timer */
        sctp_timer_stop(
            10i32,
            (*stcb).sctp_ep,
            stcb,
            net,
            (0x80000000u32).wrapping_add(0x5u32),
        );
    }
    /* process the ASCONF-ACK contents */
    ack_length = (ntohs((*cp).ch.chunk_length) as libc::c_ulong)
        .wrapping_sub(::std::mem::size_of::<sctp_asconf_ack_chunk>() as libc::c_ulong)
        as uint16_t;
    offset = (offset as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_asconf_ack_chunk>() as libc::c_ulong)
        as libc::c_int;
    /* process through all parameters */
    while ack_length as libc::c_ulong
        >= ::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_ulong
    {
        let mut aph = 0 as *mut sctp_asconf_paramhdr;
        let mut id = 0;
        let mut ap = 0 as *mut sctp_asconf_addr;
        let mut aparam_buf = [0; 512];
        let mut param_length = 0;
        let mut param_type = 0;
        /* get pointer to next asconf parameter */
        aph = sctp_m_getptr(
            m,
            offset,
            ::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_int,
            aparam_buf.as_mut_ptr(),
        ) as *mut sctp_asconf_paramhdr;
        if aph.is_null() {
            /* can't get an asconf paramhdr */
            sctp_asconf_ack_clear(stcb);
            return;
        }
        param_type = ntohs((*aph).ph.param_type) as libc::c_uint;
        param_length = ntohs((*aph).ph.param_length) as libc::c_uint;
        if param_length > ack_length as libc::c_uint {
            sctp_asconf_ack_clear(stcb);
            return;
        }
        if (param_length as libc::c_ulong) < ::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong
        {
            sctp_asconf_ack_clear(stcb);
            return;
        }
        /* get the complete parameter... */
        if param_length as libc::c_ulong > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong
        {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"param length (%u) larger than buffer size!\n\x00" as *const u8
                            as *const libc::c_char,
                        param_length,
                    );
                }
            }
            sctp_asconf_ack_clear(stcb);
            return;
        }
        aph = sctp_m_getptr(
            m,
            offset,
            param_length as libc::c_int,
            aparam_buf.as_mut_ptr(),
        ) as *mut sctp_asconf_paramhdr;
        if aph.is_null() {
            sctp_asconf_ack_clear(stcb);
            return;
        }
        /* correlation_id is transparent to peer, no ntohl needed */
        id = (*aph).correlation_id; /* switch */
        match param_type {
            49155 => {
                last_error_id = id;
                /* find the corresponding asconf param in our queue */
                ap = sctp_asconf_find_param(stcb, id);
                if !ap.is_null() {
                    /* process the parameter, failed flag */
                    sctp_asconf_process_param_ack(stcb, ap, 0u32);
                    /* process the error response */
                    sctp_asconf_process_error(stcb, aph);
                }
            }
            49157 => {
                /* find the corresponding asconf param in our queue */
                ap = sctp_asconf_find_param(stcb, id);
                if !ap.is_null() {
                    /* process the parameter, success flag */
                    sctp_asconf_process_param_ack(stcb, ap, 1u32);
                }
            }
            _ => {}
        }
        /* update remaining ASCONF-ACK message length to process */
        ack_length = (ack_length as libc::c_uint)
            .wrapping_sub((param_length.wrapping_add(3u32) >> 2i32) << 2i32)
            as uint16_t;
        if ack_length as libc::c_int <= 0i32 {
            break;
        }
        offset = (offset as libc::c_uint)
            .wrapping_add((param_length.wrapping_add(3u32) >> 2i32) << 2i32)
            as libc::c_int
    }
    /*
     * if there are any "sent" params still on the queue, these are
     * implicitly "success", or "failed" (if we got an error back) ...
     * so process these appropriately
     *
     * we assume that the correlation_id's are monotonically increasing
     * beginning from 1 and that we don't have *that* many outstanding
     * at any given time
     */
    if last_error_id == 0u32 {
        last_error_id = last_error_id.wrapping_sub(1)
    } /* set to "max" value */
    aa = (*stcb).asoc.asconf_queue.tqh_first;
    while !aa.is_null() && {
        aa_next = (*aa).next.tqe_next;
        (1i32) != 0
    } {
        if !((*aa).sent as libc::c_int == 1i32) {
            break;
        }
        /*
         * implicitly successful or failed if correlation_id
         * < last_error_id, then success else, failure
         */
        if (*aa).ap.aph.correlation_id < last_error_id {
            sctp_asconf_process_param_ack(stcb, aa, 1u32);
        } else {
            sctp_asconf_process_param_ack(stcb, aa, 0u32);
        }
        aa = aa_next
    }
    /* update the next sequence number to use */
    (*asoc).asconf_seq_out_acked = (*asoc).asconf_seq_out_acked.wrapping_add(1);
    /* remove the old ASCONF on our outbound queue */
    sctp_toss_old_asconf(stcb);
    if !(*stcb).asoc.asconf_queue.tqh_first.is_null() {
        /* we have more params, so send out more */
        sctp_send_asconf(stcb, net, 0i32);
    };
}
unsafe extern "C" fn sctp_is_scopeid_in_nets(
    mut stcb: *mut sctp_tcb,
    mut sa: *mut sockaddr,
) -> uint32_t {
    let mut sin6 = 0 as *mut sockaddr_in6;
    let mut net = 0 as *mut sctp_nets;
    if (*sa).sa_family as libc::c_int != 10i32 {
        /* wrong family */
        return 0u32;
    }
    sin6 = sa as *mut sockaddr_in6;
    if ({
        let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
        ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32) == htonl(0xfe800000u32))
            as libc::c_int
    }) == 0i32
    {
        /* not link local address */
        return 0u32;
    }
    /* hunt through our destination nets list for this scope_id */
    net = (*stcb).asoc.nets.tqh_first;
    while !net.is_null() {
        if !((*(&mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr)).sa_family
            as libc::c_int
            != 10i32)
        {
            let mut net6 = 0 as *mut sockaddr_in6;
            net6 = &mut (*net).ro._l_addr as *mut sctp_sockstore as *mut sockaddr_in6;
            if !(({
                let mut __a = &mut (*net6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32) == htonl(0xfe800000u32))
                    as libc::c_int
            }) == 0i32)
            {
                if sctp_is_same_scope(sin6, net6) != 0 {
                    /* found one */
                    return 1u32;
                }
            }
        }
        net = (*net).sctp_next.tqe_next
    }
    /* didn't find one */
    return 0u32;
}
/*
 * address management functions
 */
unsafe extern "C" fn sctp_addr_mgmt_assoc(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut ifa: *mut sctp_ifa,
    mut type_0: uint16_t,
    mut addr_locked: libc::c_int,
) {
    if (*inp).sctp_flags & 0x4u32 == 0u32 || (*inp).sctp_features & 0x20u64 == 0u64 {
        /* subset bound, no ASCONF allowed case, so ignore */
        return;
    }
    /*
     * note: we know this is not the subset bound, no ASCONF case eg.
     * this is boundall or subset bound w/ASCONF allowed
     */
    /* first, make sure that the address is IPv4 or IPv6 and not jailed */
    match (*ifa).address.sa.sa_family as libc::c_int {
        10 | 2 => {}
        _ => return,
    }
    /* make sure we're "allowed" to add this type of addr */
    if (*ifa).address.sa.sa_family as libc::c_int == 10i32 {
        /* invalid if we're not a v6 endpoint */
        if (*inp).sctp_flags & 0x4000000u32 == 0u32 {
            return;
        }
        /* is the v6 addr really valid ? */
        if (*ifa).localifa_flags & 0x8u32 != 0 {
            return;
        }
    }
    /* put this address on the "pending/do not use yet" list */
    sctp_add_local_addr_restricted(stcb, ifa);
    /*
     * check address scope if address is out of scope, don't queue
     * anything... note: this would leave the address on both inp and
     * asoc lists
     */
    match (*ifa).address.sa.sa_family as libc::c_int {
        10 => {
            let mut sin6 = 0 as *mut sockaddr_in6;
            sin6 = &mut (*ifa).address.sin6;
            if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                    && (*__a).__in6_u.__u6_addr32[3usize] == 0u32) as libc::c_int
            }) != 0
            {
                /* we skip unspecifed addresses */
                return;
            }
            if ({
                let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32) == htonl(0xfe800000u32))
                    as libc::c_int
            }) != 0
            {
                if (*stcb).asoc.scope.local_scope as libc::c_int == 0i32 {
                    return;
                }
                /* is it the right link local scope? */
                if sctp_is_scopeid_in_nets(stcb, &mut (*ifa).address.sa) == 0u32 {
                    return;
                }
            }
            if (*stcb).asoc.scope.site_scope as libc::c_int == 0i32
                && ({
                    let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                    ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                        == htonl(0xfec00000u32)) as libc::c_int
                }) != 0
            {
                return;
            }
        }
        2 => {
            let mut sin = 0 as *mut sockaddr_in;
            /* invalid if we are a v6 only endpoint */
            if (*inp).sctp_flags & 0x4000000u32 != 0 && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
            {
                return;
            }
            sin = &mut (*ifa).address.sin;
            if (*sin).sin_addr.s_addr == 0u32 {
                /* we skip unspecifed addresses */
                return;
            }
            if (*stcb).asoc.scope.ipv4_local_scope as libc::c_int == 0i32
                && (*(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t).offset(0isize)
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
                            == 168i32)
            {
                return;
            }
        }
        _ => {
            /* else, not AF_INET or AF_INET6, so skip */
            return;
        }
    }
    /* queue an asconf for this address add/delete */
    if (*inp).sctp_features & 0x20u64 == 0x20u64 {
        /* does the peer do asconf? */
        if (*stcb).asoc.asconf_supported != 0 {
            let mut status = 0;
            status = sctp_asconf_queue_add(stcb, ifa, type_0);
            /*
             * if queued ok, and in the open state, send out the
             * ASCONF.  If in the non-open state, these will be
             * sent when the state goes open.
             */
            if status == 0i32
                && ((*stcb).asoc.state & 0x7fi32 == 0x8i32
                    || (*stcb).asoc.state & 0x7fi32 == 0x20i32)
            {
                sctp_send_asconf(stcb, 0 as *mut sctp_nets, addr_locked);
            }
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_asconf_iterator_ep(
    mut inp: *mut sctp_inpcb,
    mut ptr: *mut libc::c_void,
    mut val: uint32_t,
) -> libc::c_int {
    let mut asc = 0 as *mut sctp_asconf_iterator;
    let mut l = 0 as *mut sctp_laddr;
    asc = ptr as *mut sctp_asconf_iterator;
    l = (*asc).list_of_work.lh_first;
    while !l.is_null() {
        let mut ifa = 0 as *mut sctp_ifa;
        let mut cnt_invalid = 0i32;
        ifa = (*l).ifa;
        match (*ifa).address.sa.sa_family as libc::c_int {
            10 => {
                /* invalid if we're not a v6 endpoint */
                if (*inp).sctp_flags & 0x4000000u32 == 0u32 {
                    cnt_invalid += 1;
                    if (*asc).cnt == cnt_invalid {
                        return 1i32;
                    }
                }
            }
            2 => {
                /* invalid if we are a v6 only endpoint */
                if (*inp).sctp_flags & 0x4000000u32 != 0
                    && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
                {
                    cnt_invalid += 1;
                    if (*asc).cnt == cnt_invalid {
                        return 1i32;
                    }
                }
            }
            _ => {
                /* invalid address family */
                cnt_invalid += 1;
                if (*asc).cnt == cnt_invalid {
                    return 1i32;
                }
            }
        }
        l = (*l).sctp_nxt_addr.le_next
    }
    return 0i32;
}
unsafe extern "C" fn sctp_asconf_iterator_ep_end(
    mut inp: *mut sctp_inpcb,
    mut ptr: *mut libc::c_void,
    mut val: uint32_t,
) -> libc::c_int {
    let mut asc = 0 as *mut sctp_asconf_iterator;
    let mut l = 0 as *mut sctp_laddr;
    /* Only for specific case not bound all */
    asc = ptr as *mut sctp_asconf_iterator;
    l = (*asc).list_of_work.lh_first;
    while !l.is_null() {
        let mut ifa = 0 as *mut sctp_ifa;
        let mut laddr = 0 as *mut sctp_laddr;
        ifa = (*l).ifa;
        if (*l).action == 0xc001u32 {
            laddr = (*inp).sctp_addr_list.lh_first;
            while !laddr.is_null() {
                if (*laddr).ifa == ifa {
                    (*laddr).action = 0u32;
                    break;
                } else {
                    laddr = (*laddr).sctp_nxt_addr.le_next
                }
            }
        } else if (*l).action == 0xc002u32 {
            let mut nladdr = 0 as *mut sctp_laddr;
            laddr = (*inp).sctp_addr_list.lh_first;
            while !laddr.is_null() && {
                nladdr = (*laddr).sctp_nxt_addr.le_next;
                (1i32) != 0
            } {
                /* remove only after all guys are done */
                if (*laddr).ifa == ifa {
                    sctp_del_local_addr_ep(inp, ifa);
                }
                laddr = nladdr
            }
        }
        l = (*l).sctp_nxt_addr.le_next
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_asconf_iterator_stcb(
    mut inp: *mut sctp_inpcb,
    mut stcb: *mut sctp_tcb,
    mut ptr: *mut libc::c_void,
    mut val: uint32_t,
) {
    let mut asc = 0 as *mut sctp_asconf_iterator;
    let mut l = 0 as *mut sctp_laddr;
    let mut num_queued = 0i32;
    asc = ptr as *mut sctp_asconf_iterator;

    l = (*asc).list_of_work.lh_first;
    while !l.is_null() {
        let mut ifa = 0 as *mut sctp_ifa;
        let mut type_0 = 0;
        ifa = (*l).ifa;
        type_0 = (*l).action as libc::c_int;
        /* address's vrf_id must be the vrf_id of the assoc */
        if !((*ifa).vrf_id != (*stcb).asoc.vrf_id) {
            let mut cnt_invalid = 0i32;
            let mut current_block_52: u64;
            match (*ifa).address.sa.sa_family as libc::c_int {
                10 => {
                    if (*inp).sctp_flags & 0x4000000u32 == 0u32 {
                        cnt_invalid += 1;
                        if (*asc).cnt == cnt_invalid {
                            return;
                        } else {
                            current_block_52 = 7095457783677275021;
                        }
                    } else {
                        let mut sin6 = 0 as *mut sockaddr_in6;
                        sin6 = &mut (*ifa).address.sin6;
                        if ({
                            let mut __a =
                                &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                            ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                as libc::c_int
                        }) != 0
                        {
                            /* we skip unspecifed addresses */
                            current_block_52 = 7095457783677275021;
                        } else if ({
                            let mut __a =
                                &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                            ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                                == htonl(0xfe800000u32)) as libc::c_int
                        }) != 0
                        {
                            if (*stcb).asoc.scope.local_scope as libc::c_int == 0i32 {
                                current_block_52 = 7095457783677275021;
                            } else if sctp_is_scopeid_in_nets(stcb, &mut (*ifa).address.sa) == 0u32
                            {
                                current_block_52 = 7095457783677275021;
                            } else {
                                current_block_52 = 11743904203796629665;
                            }
                        } else {
                            current_block_52 = 11743904203796629665;
                        }
                    }
                }
                2 => {
                    /* invalid if we are a v6 only endpoint */
                    if (*inp).sctp_flags & 0x4000000u32 != 0
                        && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
                    {
                        current_block_52 = 7095457783677275021;
                    } else {
                        let mut sin = 0 as *mut sockaddr_in;
                        sin = &mut (*ifa).address.sin;
                        if (*sin).sin_addr.s_addr == 0u32 {
                            current_block_52 = 7095457783677275021;
                        } else if (*stcb).asoc.scope.ipv4_local_scope as libc::c_int == 0i32
                            && (*(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                                .offset(0isize) as libc::c_int
                                == 10i32
                                || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                                    .offset(0isize)
                                    as libc::c_int
                                    == 172i32
                                    && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(1isize)
                                        as libc::c_int
                                        >= 16i32
                                    && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(1isize)
                                        as libc::c_int
                                        <= 32i32
                                || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                                    .offset(0isize)
                                    as libc::c_int
                                    == 192i32
                                    && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(1isize)
                                        as libc::c_int
                                        == 168i32)
                        {
                            current_block_52 = 7095457783677275021;
                        } else if (*inp).sctp_flags & 0x4000000u32 != 0
                            && (*inp).ip_inp.inp.inp_flags & 0x8000i32 != 0
                        {
                            cnt_invalid += 1;
                            if (*asc).cnt == cnt_invalid {
                                return;
                            } else {
                                current_block_52 = 7095457783677275021;
                            }
                        } else {
                            current_block_52 = 11743904203796629665;
                        }
                    }
                }
                _ => {
                    /* invalid address family */
                    cnt_invalid += 1;
                    if (*asc).cnt == cnt_invalid {
                        return;
                    } else {
                        current_block_52 = 7095457783677275021;
                    }
                }
            }
            match current_block_52 {
                7095457783677275021 => {}
                _ => {
                    if type_0 == 0xc001i32 {
                        /* prevent this address from being used as a source */
                        sctp_add_local_addr_restricted(stcb, ifa);
                        current_block_52 = 8464383504555462953;
                    } else if type_0 == 0xc002i32 {
                        let mut net = 0 as *mut sctp_nets;
                        net = (*stcb).asoc.nets.tqh_first;
                        while !net.is_null() {
                            /* delete this address if cached */
                            if (*net).ro._s_addr == ifa {
                                let mut rt = 0 as *mut sctp_rtentry_t;
                                sctp_free_ifa((*net).ro._s_addr);
                                (*net).ro._s_addr = 0 as *mut sctp_ifa;
                                (*net).src_addr_selected = 0u8;
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
                                /*
                                 * Now we deleted our src address,
                                 * should we not also now reset the
                                 * cwnd/rto to start as if its a new
                                 * address?
                                 */
                                (*stcb)
                                    .asoc
                                    .cc_functions
                                    .sctp_set_initial_cc_param
                                    .expect("non-null function pointer")(
                                    stcb, net
                                );
                                (*net).RTO = 0u32
                            }
                            net = (*net).sctp_next.tqe_next
                        }
                        current_block_52 = 8464383504555462953;
                    } else if type_0 == 0xc004i32 {
                        if (*(*stcb).sctp_ep).sctp_flags & 0x4u32 == 0u32 {
                            /* must validate the ifa is in the ep */
                            if sctp_is_addr_in_ep((*stcb).sctp_ep, ifa) == 0i32 {
                                current_block_52 = 7095457783677275021;
                            } else {
                                current_block_52 = 8464383504555462953;
                            }
                        } else if sctp_is_address_in_scope(ifa, &mut (*stcb).asoc.scope, 0i32)
                            == 0i32
                        {
                            current_block_52 = 7095457783677275021;
                        } else {
                            current_block_52 = 8464383504555462953;
                        }
                    } else {
                        current_block_52 = 8464383504555462953;
                    }
                    match current_block_52 {
                        7095457783677275021 => {}
                        _ => {
                            /* Need to check scopes for this guy */
                            /* queue an asconf for this address add/delete */
                            if (*inp).sctp_features & 0x20u64 == 0x20u64
                                && (*stcb).asoc.asconf_supported as libc::c_int == 1i32
                            {
                                let mut status = 0;
                                status = sctp_asconf_queue_add(stcb, ifa, type_0 as uint16_t);
                                /*
                                 * if queued ok, and in the open state, update the
                                 * count of queued params.  If in the non-open state,
                                 * these get sent when the assoc goes open.
                                 */
                                if (*stcb).asoc.state & 0x7fi32 == 0x8i32
                                    || (*stcb).asoc.state & 0x7fi32 == 0x20i32
                                {
                                    if status >= 0i32 {
                                        num_queued += 1
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        /* we skip unspecifed addresses */
        l = (*l).sctp_nxt_addr.le_next
    }
    /*
     * If we have queued params in the open state, send out an ASCONF.
     */
    if num_queued > 0i32 {
        sctp_send_asconf(stcb, 0 as *mut sctp_nets, 0i32);
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_asconf_iterator_end(mut ptr: *mut libc::c_void, mut val: uint32_t) {
    let mut asc = 0 as *mut sctp_asconf_iterator;
    let mut l = 0 as *mut sctp_laddr;
    let mut nl = 0 as *mut sctp_laddr;
    asc = ptr as *mut sctp_asconf_iterator;
    l = (*asc).list_of_work.lh_first;
    while !l.is_null() && {
        nl = (*l).sctp_nxt_addr.le_next;
        (1i32) != 0
    } {
        let mut ifa = 0 as *mut sctp_ifa;
        ifa = (*l).ifa;
        if (*l).action == 0xc001u32 {
            /* Clear the defer use flag */
            (*ifa).localifa_flags &= !(0x4i32) as libc::c_uint
        }
        sctp_free_ifa(ifa);
        free(l as *mut libc::c_void);
        ::std::intrinsics::atomic_xsub(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
        l = nl
    }
    free(asc as *mut libc::c_void);
}
/*
 * sa is the sockaddr to ask the peer to set primary to.
 * returns: 0 = completed, -1 = error
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_set_primary_ip_address_sa(
    mut stcb: *mut sctp_tcb,
    mut sa: *mut sockaddr,
) -> int32_t {
    let mut vrf_id = 0;
    let mut ifa = 0 as *mut sctp_ifa;
    /* find the ifa for the desired set primary */
    vrf_id = (*stcb).asoc.vrf_id;
    ifa = sctp_find_ifa_by_addr(sa, vrf_id, 0i32);
    if ifa.is_null() {
        /* Invalid address */
        return -(1i32);
    }
    /* queue an ASCONF:SET_PRIM_ADDR to be sent */
    if sctp_asconf_queue_add(stcb, ifa, 0xc004u16) == 0 {
        /* set primary queuing succeeded */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"set_primary_ip_address_sa: queued on tcb=%p, \x00" as *const u8
                        as *const libc::c_char,
                    stcb as *mut libc::c_void,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            sctp_print_address(sa);
        }
        if (*stcb).asoc.state & 0x7fi32 == 0x8i32 || (*stcb).asoc.state & 0x7fi32 == 0x20i32 {
            sctp_send_asconf(stcb, 0 as *mut sctp_nets, 0i32);
        }
    } else {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"set_primary_ip_address_sa: failed to add to queue on tcb=%p, \x00"
                        as *const u8 as *const libc::c_char,
                    stcb as *mut libc::c_void,
                );
            }
        }
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            sctp_print_address(sa);
        }
        return -(1i32);
    }
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn sctp_is_addr_pending(
    mut stcb: *mut sctp_tcb,
    mut sctp_ifa: *mut sctp_ifa,
) -> libc::c_int {
    let mut chk = 0 as *mut sctp_tmit_chunk;
    let mut nchk = 0 as *mut sctp_tmit_chunk;
    let mut add_cnt = 0;
    let mut del_cnt = 0;
    let mut last_param_type = 0;
    del_cnt = 0i32;
    add_cnt = del_cnt;
    last_param_type = 0u16;
    chk = (*stcb).asoc.asconf_send_queue.tqh_first;
    while !chk.is_null() && {
        nchk = (*chk).sctp_next.tqe_next;
        (1i32) != 0
    } {
        if (*chk).data.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"is_addr_pending: No mbuf data?\n\x00" as *const u8 as *const libc::c_char,
                    );
                }
            }
        } else {
            let mut offset = 0;
            let mut asconf_limit = 0;
            let mut acp = 0 as *mut sctp_asconf_chunk;
            let mut aparam_buf = [0; 512];
            let mut ph = 0 as *mut sctp_paramhdr;
            offset = 0u32;
            acp = (*(*chk).data).m_hdr.mh_data as *mut sctp_asconf_chunk;
            offset = (offset as libc::c_ulong)
                .wrapping_add(::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_ulong)
                as libc::c_uint;
            asconf_limit = ntohs((*acp).ch.chunk_length) as libc::c_uint;
            ph = sctp_m_getptr(
                (*chk).data,
                offset as libc::c_int,
                ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
                aparam_buf.as_mut_ptr(),
            ) as *mut sctp_paramhdr;
            if ph.is_null() {
                if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                    if system_base_info.debug_printf.is_some() {
                        system_base_info
                            .debug_printf
                            .expect("non-null function pointer")(
                            b"is_addr_pending: couldn\'t get lookup addr!\n\x00" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
            } else {
                let mut aph = 0 as *mut sctp_asconf_paramhdr;
                offset = offset.wrapping_add(ntohs((*ph).param_length) as libc::c_uint);
                aph = sctp_m_getptr(
                    (*chk).data,
                    offset as libc::c_int,
                    ::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_int,
                    aparam_buf.as_mut_ptr(),
                ) as *mut sctp_asconf_paramhdr;
                if aph.is_null() {
                    if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                        if system_base_info.debug_printf.is_some() {
                            system_base_info
                                .debug_printf
                                .expect("non-null function pointer")(
                                b"is_addr_pending: Empty ASCONF will be sent?\n\x00" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    }
                } else {
                    while !aph.is_null() {
                        let mut param_length = 0;
                        let mut param_type = 0;
                        param_type = ntohs((*aph).ph.param_type) as libc::c_uint;
                        param_length = ntohs((*aph).ph.param_length) as libc::c_uint;
                        if offset.wrapping_add(param_length) > asconf_limit {
                            /* parameter goes beyond end of chunk! */
                            break;
                        } else if param_length as libc::c_ulong
                            > ::std::mem::size_of::<[uint8_t; 512]>() as libc::c_ulong
                        {
                            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                                if system_base_info.debug_printf.is_some() {
                                    system_base_info.debug_printf.expect("non-null function pointer")(b"is_addr_pending: param length (%u) larger than buffer size!\n\x00"
                                                                                                          as
                                                                                                          *const u8
                                                                                                          as
                                                                                                          *const libc::c_char,
                                                                                                      param_length);
                                }
                            }
                            break;
                        } else if param_length as libc::c_ulong
                            <= ::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong
                        {
                            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                                if system_base_info.debug_printf.is_some() {
                                    system_base_info
                                        .debug_printf
                                        .expect("non-null function pointer")(
                                        b"is_addr_pending: param length(%u) too short\n\x00"
                                            as *const u8
                                            as *const libc::c_char,
                                        param_length,
                                    );
                                }
                            }
                            break;
                        } else {
                            aph = sctp_m_getptr(
                                (*chk).data,
                                offset as libc::c_int,
                                param_length as libc::c_int,
                                aparam_buf.as_mut_ptr(),
                            ) as *mut sctp_asconf_paramhdr;
                            if aph.is_null() {
                                if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                                    if system_base_info.debug_printf.is_some() {
                                        system_base_info
                                            .debug_printf
                                            .expect("non-null function pointer")(
                                            b"is_addr_pending: couldn\'t get entire param\n\x00"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                    }
                                }
                                break;
                            } else {
                                ph = aph.offset(1isize) as *mut sctp_paramhdr;
                                if sctp_addr_match(ph, &mut (*sctp_ifa).address.sa) != 0u32 {
                                    match param_type {
                                        49153 => add_cnt += 1,
                                        49154 => del_cnt += 1,
                                        _ => {}
                                    }
                                    last_param_type = param_type as uint16_t
                                }
                                offset = offset.wrapping_add(
                                    (param_length.wrapping_add(3u32) >> 2i32) << 2i32,
                                );
                                if offset >= asconf_limit {
                                    break;
                                }
                                /* get pointer to next asconf param */
                                aph = sctp_m_getptr(
                                    (*chk).data,
                                    offset as libc::c_int,
                                    ::std::mem::size_of::<sctp_asconf_paramhdr>() as libc::c_int,
                                    aparam_buf.as_mut_ptr(),
                                ) as *mut sctp_asconf_paramhdr
                            }
                        }
                    }
                }
            }
        }
        chk = nchk
    }
    /* we want to find the sequences which consist of ADD -> DEL -> ADD or DEL -> ADD */
    if add_cnt > del_cnt || add_cnt == del_cnt && last_param_type as libc::c_int == 0xc001i32 {
        return 1i32;
    }
    return 0i32;
}
unsafe extern "C" fn sctp_find_valid_localaddr(
    mut stcb: *mut sctp_tcb,
    mut addr_locked: libc::c_int,
) -> *mut sockaddr {
    let mut vrf = 0 as *mut sctp_vrf;
    let mut sctp_ifn = 0 as *mut sctp_ifn;
    if addr_locked == 0i32 {
        pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    }
    vrf = sctp_find_vrf((*stcb).asoc.vrf_id);
    if vrf.is_null() {
        if addr_locked == 0i32 {
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        }
        return 0 as *mut sockaddr;
    }
    sctp_ifn = (*vrf).ifnlist.lh_first;
    while !sctp_ifn.is_null() {
        if !((*stcb).asoc.scope.loopback_scope as libc::c_int == 0i32
            && strncmp(
                (*sctp_ifn).ifn_name.as_mut_ptr(),
                b"lo\x00" as *const u8 as *const libc::c_char,
                2u64,
            ) == 0i32)
        {
            let mut sctp_ifa = 0 as *mut sctp_ifa;
            sctp_ifa = (*sctp_ifn).ifalist.lh_first;
            while !sctp_ifa.is_null() {
                match (*sctp_ifa).address.sa.sa_family as libc::c_int {
                    2 => {
                        if (*stcb).asoc.scope.ipv4_addr_legal != 0 {
                            let mut sin = 0 as *mut sockaddr_in;
                            sin = &mut (*sctp_ifa).address.sin;
                            if !((*sin).sin_addr.s_addr == 0u32) {
                                if !((*stcb).asoc.scope.ipv4_local_scope as libc::c_int == 0i32
                                    && (*(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(0isize)
                                        as libc::c_int
                                        == 10i32
                                        || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(0isize)
                                            as libc::c_int
                                            == 172i32
                                            && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                                as *mut uint8_t)
                                                .offset(1isize)
                                                as libc::c_int
                                                >= 16i32
                                            && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                                as *mut uint8_t)
                                                .offset(1isize)
                                                as libc::c_int
                                                <= 32i32
                                        || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(0isize)
                                            as libc::c_int
                                            == 192i32
                                            && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                                as *mut uint8_t)
                                                .offset(1isize)
                                                as libc::c_int
                                                == 168i32))
                                {
                                    if !(sctp_is_addr_restricted(stcb, sctp_ifa) != 0
                                        && sctp_is_addr_pending(stcb, sctp_ifa) == 0)
                                    {
                                        /* found a valid local v4 address to use */
                                        if addr_locked == 0i32 {
                                            pthread_mutex_unlock(
                                                &mut system_base_info.sctppcbinfo.ipi_addr_mtx,
                                            );
                                        }
                                        return &mut (*sctp_ifa).address.sa;
                                    }
                                }
                            }
                        }
                    }
                    10 => {
                        if (*stcb).asoc.scope.ipv6_addr_legal != 0 {
                            if !((*sctp_ifa).localifa_flags & 0x8u32 != 0) {
                                let mut sin6 = 0 as *mut sockaddr_in6;
                                sin6 = &mut (*sctp_ifa).address.sin6;
                                if !(({
                                    let mut __a =
                                        &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                        && (*__a).__in6_u.__u6_addr32[3usize] == 0u32)
                                        as libc::c_int
                                }) != 0)
                                {
                                    if !((*stcb).asoc.scope.local_scope as libc::c_int == 0i32
                                        && ({
                                            let mut __a = &mut (*sin6).sin6_addr as *mut in6_addr
                                                as *const in6_addr;
                                            ((*__a).__in6_u.__u6_addr32[0usize]
                                                & htonl(0xffc00000u32)
                                                == htonl(0xfe800000u32))
                                                as libc::c_int
                                        }) != 0)
                                    {
                                        if !((*stcb).asoc.scope.site_scope as libc::c_int == 0i32
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
                                            if !(sctp_is_addr_restricted(stcb, sctp_ifa) != 0
                                                && sctp_is_addr_pending(stcb, sctp_ifa) == 0)
                                            {
                                                /* found a valid local v6 address to use */
                                                if addr_locked == 0i32 {
                                                    pthread_mutex_unlock(
                                                        &mut system_base_info
                                                            .sctppcbinfo
                                                            .ipi_addr_mtx,
                                                    );
                                                }
                                                return &mut (*sctp_ifa).address.sa;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
                /* we skip unspecifed addresses */
                sctp_ifa = (*sctp_ifa).next_ifa.le_next
            }
        }
        /* Skip if loopback_scope not set */
        sctp_ifn = (*sctp_ifn).next_ifn.le_next
    }
    /* no valid addresses found */
    if addr_locked == 0i32 {
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    }
    return 0 as *mut sockaddr;
}
unsafe extern "C" fn sctp_find_valid_localaddr_ep(mut stcb: *mut sctp_tcb) -> *mut sockaddr {
    let mut laddr = 0 as *mut sctp_laddr;
    laddr = (*(*stcb).sctp_ep).sctp_addr_list.lh_first;
    while !laddr.is_null() {
        if !(*laddr).ifa.is_null() {
            /* is the address restricted ? */
            if !(sctp_is_addr_restricted(stcb, (*laddr).ifa) != 0
                && sctp_is_addr_pending(stcb, (*laddr).ifa) == 0)
            {
                /* found a valid local address to use */
                return &mut (*(*laddr).ifa).address.sa;
            }
        }
        laddr = (*laddr).sctp_nxt_addr.le_next
    }
    /* no valid addresses found */
    return 0 as *mut sockaddr;
}
/*
 * builds an ASCONF chunk from queued ASCONF params.
 * returns NULL on error (no mbuf, no ASCONF params queued, etc).
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_compose_asconf(
    mut stcb: *mut sctp_tcb,
    mut retlen: *mut libc::c_int,
    mut addr_locked: libc::c_int,
) -> *mut mbuf {
    let mut m_asconf = 0 as *mut mbuf;
    let mut m_asconf_chk = 0 as *mut mbuf;
    let mut aa = 0 as *mut sctp_asconf_addr;
    let mut acp = 0 as *mut sctp_asconf_chunk;
    let mut ptr = 0 as *mut libc::c_char;
    let mut lookup_ptr = 0 as *mut libc::c_char;
    let mut lookup_used = 0u8;
    /* are there any asconf params to send? */
    aa = (*stcb).asoc.asconf_queue.tqh_first;
    while !aa.is_null() {
        if (*aa).sent as libc::c_int == 0i32 {
            break;
        }
        aa = (*aa).next.tqe_next
    }
    if aa.is_null() {
        return 0 as *mut mbuf;
    }
    /*
     * get a chunk header mbuf and a cluster for the asconf params since
     * it's simpler to fill in the asconf chunk header lookup address on
     * the fly
     */
    m_asconf_chk = sctp_get_mbuf_for_msg(
        ::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_uint,
        0i32,
        0x1i32,
        1i32,
        1i32,
    );
    if m_asconf_chk.is_null() {
        /* no mbuf's */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"compose_asconf: couldn\'t get chunk mbuf!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return 0 as *mut mbuf;
    }
    m_asconf = sctp_get_mbuf_for_msg(2048u32, 0i32, 0x1i32, 1i32, 1i32);
    if m_asconf.is_null() {
        /* no mbuf's */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"compose_asconf: couldn\'t get mbuf!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        m_freem(m_asconf_chk);
        return 0 as *mut mbuf;
    }
    (*m_asconf_chk).m_hdr.mh_len = ::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_int;
    (*m_asconf).m_hdr.mh_len = 0i32;
    acp = (*m_asconf_chk).m_hdr.mh_data as *mut sctp_asconf_chunk;
    memset(
        acp as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_asconf_chunk>() as libc::c_ulong,
    );
    /* save pointers to lookup address and asconf params */
    lookup_ptr = acp.offset(1isize) as caddr_t; /* after the header */
    ptr = (*m_asconf).m_hdr.mh_data; /* beginning of cluster */
    /* fill in chunk header info */
    (*acp).ch.chunk_type = 0xc1u8;
    (*acp).ch.chunk_flags = 0u8;
    (*acp).serial_number = htonl((*stcb).asoc.asconf_seq_out);
    (*stcb).asoc.asconf_seq_out = (*stcb).asoc.asconf_seq_out.wrapping_add(1);
    /* add parameters... up to smallest MTU allowed */
    aa = (*stcb).asoc.asconf_queue.tqh_first;
    while !aa.is_null() {
        if !((*aa).sent != 0) {
            let mut aph = 0 as *mut sctp_asconf_paramhdr;
            let mut aap = 0 as *mut sctp_asconf_addr_param;
            let mut p_length = 0;
            let mut correlation_id = 1u32;
            p_length =
                (((*aa).ap.aph.ph.param_length as libc::c_int + 3i32 >> 2i32) << 2i32) as uint32_t;
            /* will it fit in current chunk? */
            if ((*m_asconf).m_hdr.mh_len as libc::c_uint).wrapping_add(p_length)
                > (*stcb).asoc.smallest_mtu
                || ((*m_asconf).m_hdr.mh_len as libc::c_uint).wrapping_add(p_length) > 2048u32
            {
                break;
            }
            /* assign (and store) a correlation id */
            let fresh0 = correlation_id;
            correlation_id = correlation_id.wrapping_add(1);
            (*aa).ap.aph.correlation_id = fresh0;
            /*
             * fill in address if we're doing a delete this is a simple
             * way for us to fill in the correlation address, which
             * should only be used by the peer if we're deleting our
             * source address and adding a new address (e.g. renumbering
             * case)
             */
            if lookup_used as libc::c_int == 0i32
                && (*aa).special_del as libc::c_int == 0i32
                && (*aa).ap.aph.ph.param_type as libc::c_int == 0xc002i32
            {
                let mut lookup = 0 as *mut sctp_ipv6addr_param;
                let mut p_size = 0;
                let mut addr_size = 0;
                lookup = lookup_ptr as *mut sctp_ipv6addr_param;
                (*lookup).ph.param_type = htons((*aa).ap.addrp.ph.param_type);
                if (*aa).ap.addrp.ph.param_type as libc::c_int == 0x6i32 {
                    /* copy IPv6 address */
                    p_size = ::std::mem::size_of::<sctp_ipv6addr_param>() as uint16_t;
                    addr_size = ::std::mem::size_of::<in6_addr>() as uint16_t
                } else {
                    /* copy IPv4 address */
                    p_size = ::std::mem::size_of::<sctp_ipv4addr_param>() as uint16_t;
                    addr_size = ::std::mem::size_of::<in_addr>() as uint16_t
                }
                (*lookup).ph.param_length =
                    htons(((p_size as libc::c_int + 3i32 >> 2i32) << 2i32) as uint16_t);
                memcpy(
                    (*lookup).addr.as_mut_ptr() as *mut libc::c_void,
                    &mut (*aa).ap.addrp.addr as *mut [uint8_t; 16] as *const libc::c_void,
                    addr_size as libc::c_ulong,
                );
                (*m_asconf_chk).m_hdr.mh_len += (p_size as libc::c_int + 3i32 >> 2i32) << 2i32;
                lookup_used = 1u8
            }
            /* copy into current space */
            memcpy(
                ptr as *mut libc::c_void,
                &mut (*aa).ap as *mut sctp_asconf_addr_param as *const libc::c_void,
                p_length as libc::c_ulong,
            );
            /* network elements and update lengths */
            aph = ptr as *mut sctp_asconf_paramhdr;
            aap = ptr as *mut sctp_asconf_addr_param;
            /* correlation_id is transparent to peer, no htonl needed */
            (*aph).ph.param_type = htons((*aph).ph.param_type);
            (*aph).ph.param_length = htons((*aph).ph.param_length);
            (*aap).addrp.ph.param_type = htons((*aap).addrp.ph.param_type);
            (*aap).addrp.ph.param_length = htons((*aap).addrp.ph.param_length);
            (*m_asconf).m_hdr.mh_len = ((*m_asconf).m_hdr.mh_len as libc::c_uint)
                .wrapping_add((p_length.wrapping_add(3u32) >> 2i32) << 2i32)
                as libc::c_int;
            ptr = ptr.offset(((p_length.wrapping_add(3u32) >> 2i32) << 2i32) as isize);
            /*
             * these params are removed off the pending list upon
             * getting an ASCONF-ACK back from the peer, just set flag
             */
            (*aa).sent = 1u8
        }
        aa = (*aa).next.tqe_next
    }
    /* check to see if the lookup addr has been populated yet */
    if lookup_used as libc::c_int == 0i32 {
        let mut lookup_0 = 0 as *mut sctp_ipv6addr_param;
        let mut found_addr = 0 as *mut sockaddr;
        if (*(*stcb).sctp_ep).sctp_flags & 0x4u32 != 0 {
            found_addr = sctp_find_valid_localaddr(stcb, addr_locked)
        } else {
            found_addr = sctp_find_valid_localaddr_ep(stcb)
        }
        lookup_0 = lookup_ptr as *mut sctp_ipv6addr_param;
        if !found_addr.is_null() {
            let mut p_size_0 = 0;
            let mut addr_size_0 = 0;
            let mut addr_ptr = 0 as *mut libc::c_char;
            match (*found_addr).sa_family as libc::c_int {
                10 => {
                    /* copy IPv6 address */
                    (*lookup_0).ph.param_type = htons(0x6u16);
                    p_size_0 = ::std::mem::size_of::<sctp_ipv6addr_param>() as uint16_t;
                    addr_size_0 = ::std::mem::size_of::<in6_addr>() as uint16_t;
                    addr_ptr = &mut (*(found_addr as *mut sockaddr_in6)).sin6_addr as *mut in6_addr
                        as caddr_t
                }
                2 => {
                    /* copy IPv4 address */
                    (*lookup_0).ph.param_type = htons(0x5u16);
                    p_size_0 = ::std::mem::size_of::<sctp_ipv4addr_param>() as uint16_t;
                    addr_size_0 = ::std::mem::size_of::<in_addr>() as uint16_t;
                    addr_ptr =
                        &mut (*(found_addr as *mut sockaddr_in)).sin_addr as *mut in_addr as caddr_t
                }
                _ => {
                    p_size_0 = 0u16;
                    addr_size_0 = 0u16;
                    addr_ptr = 0 as caddr_t
                }
            }
            (*lookup_0).ph.param_length =
                htons(((p_size_0 as libc::c_int + 3i32 >> 2i32) << 2i32) as uint16_t);
            memcpy(
                (*lookup_0).addr.as_mut_ptr() as *mut libc::c_void,
                addr_ptr as *const libc::c_void,
                addr_size_0 as libc::c_ulong,
            );
            (*m_asconf_chk).m_hdr.mh_len += (p_size_0 as libc::c_int + 3i32 >> 2i32) << 2i32
        } else {
            /* uh oh... don't have any address?? */
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"compose_asconf: no lookup addr!\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            /* XXX for now, we send a IPv4 address of 0.0.0.0 */
            (*lookup_0).ph.param_type = htons(0x5u16);
            (*lookup_0).ph.param_length = htons(
                (((::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong)
                    .wrapping_add(3u64)
                    >> 2i32)
                    << 2i32) as uint16_t,
            );
            memset(
                (*lookup_0).addr.as_mut_ptr() as *mut libc::c_void,
                0i32,
                ::std::mem::size_of::<in_addr>() as libc::c_ulong,
            );
            (*m_asconf_chk).m_hdr.mh_len = ((*m_asconf_chk).m_hdr.mh_len as libc::c_ulong)
                .wrapping_add(
                    ((::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong)
                        .wrapping_add(3u64)
                        >> 2i32)
                        << 2i32,
                ) as libc::c_int
        }
    }
    /* chain it all together */
    (*m_asconf_chk).m_hdr.mh_next = m_asconf;
    *retlen = (*m_asconf_chk).m_hdr.mh_len + (*m_asconf).m_hdr.mh_len;
    (*acp).ch.chunk_length = htons(*retlen as uint16_t);
    return m_asconf_chk;
}
/*
 * section to handle address changes before an association is up eg. changes
 * during INIT/INIT-ACK/COOKIE-ECHO handshake
 */
/*
 * processes the (local) addresses in the INIT-ACK chunk
 */
unsafe extern "C" fn sctp_process_initack_addresses(
    mut stcb: *mut sctp_tcb,
    mut m: *mut mbuf,
    mut offset: libc::c_uint,
    mut length: libc::c_uint,
) {
    let mut tmp_param = sctp_paramhdr {
        param_type: 0,
        param_length: 0,
    };
    let mut ph = 0 as *mut sctp_paramhdr;
    if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"processing init-ack addresses\n\x00" as *const u8 as *const libc::c_char,
            );
        }
    }
    if stcb.is_null() {
        /* Un-needed check for SA */
        return;
    }
    /* convert to upper bound */
    length = length.wrapping_add(offset);
    if (offset as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
        > length as libc::c_ulong
    {
        return;
    }
    /* go through the addresses in the init-ack */
    ph = sctp_m_getptr(
        m,
        offset as libc::c_int,
        ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
        &mut tmp_param as *mut sctp_paramhdr as *mut uint8_t,
    ) as *mut sctp_paramhdr;
    while !ph.is_null() {
        let mut plen = 0;
        let mut ptype = 0;
        let mut store = sctp_sockstore {
            sin: sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            },
        };
        let mut current_block_54: u64;
        ptype = ntohs((*ph).param_type);
        plen = ntohs((*ph).param_length);
        match ptype as libc::c_int {
            6 => {
                let mut addr6_store = sctp_ipv6addr_param {
                    ph: sctp_paramhdr {
                        param_type: 0,
                        param_length: 0,
                    },
                    addr: [0; 16],
                };
                let mut a6p = 0 as *mut sctp_ipv6addr_param;
                /* get the entire IPv6 address param */
                a6p = sctp_m_getptr(
                    m,
                    offset as libc::c_int,
                    ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_int,
                    &mut addr6_store as *mut sctp_ipv6addr_param as *mut uint8_t,
                ) as *mut sctp_ipv6addr_param;
                if plen as libc::c_ulong
                    != ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong
                    || a6p.is_null()
                {
                    return;
                }
                memset(
                    &mut store as *mut sctp_sockstore as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
                );
                store.sin6.sin6_family = 10u16;
                store.sin6.sin6_port = (*stcb).rport;
                memcpy(
                    &mut store.sin6.sin6_addr as *mut in6_addr as *mut libc::c_void,
                    (*a6p).addr.as_mut_ptr() as *const libc::c_void,
                    ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
                );
                current_block_54 = 9007357115414505193;
            }
            5 => {
                let mut addr4_store = sctp_ipv4addr_param {
                    ph: sctp_paramhdr {
                        param_type: 0,
                        param_length: 0,
                    },
                    addr: 0,
                };
                let mut a4p = 0 as *mut sctp_ipv4addr_param;
                /* get the entire IPv4 address param */
                a4p = sctp_m_getptr(
                    m,
                    offset as libc::c_int,
                    ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_int,
                    &mut addr4_store as *mut sctp_ipv4addr_param as *mut uint8_t,
                ) as *mut sctp_ipv4addr_param;
                if plen as libc::c_ulong
                    != ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong
                    || a4p.is_null()
                {
                    return;
                }
                memset(
                    &mut store as *mut sctp_sockstore as *mut libc::c_void,
                    0i32,
                    ::std::mem::size_of::<sctp_sockstore>() as libc::c_ulong,
                );
                store.sin.sin_family = 2u16;
                store.sin.sin_port = (*stcb).rport;
                store.sin.sin_addr.s_addr = (*a4p).addr;
                current_block_54 = 9007357115414505193;
            }
            _ => {
                current_block_54 = 16500709197931046051;
            }
        }
        match current_block_54 {
            9007357115414505193 => {
                let mut sctp_ifa = 0 as *mut sctp_ifa;
                sctp_ifa = sctp_find_ifa_by_addr(&mut store.sa, (*stcb).asoc.vrf_id, 0i32);
                if sctp_ifa.is_null() {
                    /* are ASCONFs allowed ? */
                    if (*(*stcb).sctp_ep).sctp_features & 0x20u64 == 0x20u64
                        && (*stcb).asoc.asconf_supported as libc::c_int != 0
                    {
                        let mut status = 0;
                        status = sctp_asconf_queue_sa_delete(stcb, &mut store.sa);
                        /*
                         * if queued ok, and in correct state, send
                         * out the ASCONF.
                         */
                        if status == 0i32 && (*stcb).asoc.state & 0x7fi32 == 0x8i32 {
                            sctp_send_asconf(stcb, 0 as *mut sctp_nets, 0i32);
                        }
                    }
                }
            }
            _ => {}
        }
        /*
         * Sanity check:  Make sure the length isn't 0, otherwise
         * we'll be stuck in this loop for a long time...
         */
        if (plen as libc::c_int + 3i32 >> 2i32) << 2i32 == 0i32 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"process_initack_addrs: bad len (%d) type=%xh\n\x00" as *const u8
                        as *const libc::c_char,
                    plen as libc::c_int,
                    ptype as libc::c_int,
                );
            }
            return;
        }
        /* get next parameter */
        offset =
            offset.wrapping_add(((plen as libc::c_int + 3i32 >> 2i32) << 2i32) as libc::c_uint);
        if (offset as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            > length as libc::c_ulong
        {
            return;
        }
        ph = sctp_m_getptr(
            m,
            offset as libc::c_int,
            ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
            &mut tmp_param as *mut sctp_paramhdr as *mut uint8_t,
        ) as *mut sctp_paramhdr
    }
    /* while */
}
/* FIX ME: need to verify return result for v6 address type if v6 disabled */
/*
 * checks to see if a specific address is in the initack address list returns
 * 1 if found, 0 if not
 */
unsafe extern "C" fn sctp_addr_in_initack(
    mut m: *mut mbuf,
    mut offset: uint32_t,
    mut length: uint32_t,
    mut sa: *mut sockaddr,
) -> uint32_t {
    let mut tmp_param = sctp_paramhdr {
        param_type: 0,
        param_length: 0,
    };
    let mut ph = 0 as *mut sctp_paramhdr;
    match (*sa).sa_family as libc::c_int {
        2 | 10 => {}
        _ => return 0u32,
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
        if system_base_info.debug_printf.is_some() {
            system_base_info
                .debug_printf
                .expect("non-null function pointer")(
                b"find_initack_addr: starting search for \x00" as *const u8 as *const libc::c_char,
            );
        }
    }
    if system_base_info.sctpsysctl.sctp_debug_on & 0x20000u32 != 0 {
        sctp_print_address(sa);
    }
    /* convert to upper bound */
    length = (length).wrapping_add(offset);
    if (offset as libc::c_ulong)
        .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
        > length as libc::c_ulong
    {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"find_initack_addr: invalid offset?\n\x00" as *const u8 as *const libc::c_char,
                );
            }
        }
        return 0u32;
    }
    /* go through the addresses in the init-ack */
    ph = sctp_m_getptr(
        m,
        offset as libc::c_int,
        ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
        &mut tmp_param as *mut sctp_paramhdr as *mut uint8_t,
    ) as *mut sctp_paramhdr; /* while */
    while !ph.is_null() {
        let mut plen = 0;
        let mut ptype = 0;
        ptype = ntohs((*ph).param_type);
        plen = ntohs((*ph).param_length);
        match ptype as libc::c_int {
            6 => {
                if (*sa).sa_family as libc::c_int == 10i32 {
                    /* get the entire IPv6 address param */
                    if !(plen as libc::c_ulong
                        != ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_ulong)
                    {
                        let mut sin6 = 0 as *mut sockaddr_in6;
                        let mut a6p = 0 as *mut sctp_ipv6addr_param;
                        let mut addr6_store = sctp_ipv6addr_param {
                            ph: sctp_paramhdr {
                                param_type: 0,
                                param_length: 0,
                            },
                            addr: [0; 16],
                        };
                        a6p = sctp_m_getptr(
                            m,
                            offset as libc::c_int,
                            ::std::mem::size_of::<sctp_ipv6addr_param>() as libc::c_int,
                            &mut addr6_store as *mut sctp_ipv6addr_param as *mut uint8_t,
                        ) as *mut sctp_ipv6addr_param;
                        if a6p.is_null() {
                            return 0u32;
                        }
                        sin6 = sa as *mut sockaddr_in6;
                        /* SCTP_EMBEDDED_V6_SCOPE */
                        if memcmp(
                            &mut (*sin6).sin6_addr as *mut in6_addr as *const libc::c_void,
                            (*a6p).addr.as_mut_ptr() as *const libc::c_void,
                            ::std::mem::size_of::<in6_addr>() as libc::c_ulong,
                        ) == 0i32
                        {
                            /* found it */
                            return 1u32;
                        }
                    }
                }
            }
            5 => {
                /* INET6 */
                if (*sa).sa_family as libc::c_int == 2i32 {
                    if !(plen as libc::c_ulong
                        != ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_ulong)
                    {
                        let mut sin = 0 as *mut sockaddr_in;
                        let mut a4p = 0 as *mut sctp_ipv4addr_param;
                        let mut addr4_store = sctp_ipv6addr_param {
                            ph: sctp_paramhdr {
                                param_type: 0,
                                param_length: 0,
                            },
                            addr: [0; 16],
                        };
                        a4p = sctp_m_getptr(
                            m,
                            offset as libc::c_int,
                            ::std::mem::size_of::<sctp_ipv4addr_param>() as libc::c_int,
                            &mut addr4_store as *mut sctp_ipv6addr_param as *mut uint8_t,
                        ) as *mut sctp_ipv4addr_param;
                        if a4p.is_null() {
                            return 0u32;
                        }
                        sin = sa as *mut sockaddr_in;
                        if (*sin).sin_addr.s_addr == (*a4p).addr {
                            /* found it */
                            return 1u32;
                        }
                    }
                }
            }
            _ => {}
        }
        /* get next parameter */
        offset =
            (offset).wrapping_add(((plen as libc::c_int + 3i32 >> 2i32) << 2i32) as libc::c_uint);
        if (offset as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<sctp_paramhdr>() as libc::c_ulong)
            > length as libc::c_ulong
        {
            return 0u32;
        }
        ph = sctp_m_getptr(
            m,
            offset as libc::c_int,
            ::std::mem::size_of::<sctp_paramhdr>() as libc::c_int,
            &mut tmp_param as *mut sctp_paramhdr as *mut uint8_t,
        ) as *mut sctp_paramhdr
    }
    /* not found! */
    return 0u32;
}
/*
 * makes sure that the current endpoint local addr list is consistent with
 * the new association (eg. subset bound, asconf allowed) adds addresses as
 * necessary
 */
unsafe extern "C" fn sctp_check_address_list_ep(
    mut stcb: *mut sctp_tcb,
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut length: libc::c_int,
    mut init_addr: *mut sockaddr,
) {
    let mut laddr = 0 as *mut sctp_laddr;
    /* go through the endpoint list */
    laddr = (*(*stcb).sctp_ep).sctp_addr_list.lh_first;
    while !laddr.is_null() {
        /* be paranoid and validate the laddr */
        if (*laddr).ifa.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"check_addr_list_ep: laddr->ifa is NULL\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        } else if (*laddr).ifa.is_null() {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"check_addr_list_ep: laddr->ifa->ifa_addr is NULL\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
        } else if !(sctp_cmpaddr(&mut (*(*laddr).ifa).address.sa, init_addr) != 0) {
            /* do i have it implicitly? */
            /* check to see if in the init-ack */
            if sctp_addr_in_initack(
                m,
                offset as uint32_t,
                length as uint32_t,
                &mut (*(*laddr).ifa).address.sa,
            ) == 0
            {
                /* try to add it */
                sctp_addr_mgmt_assoc((*stcb).sctp_ep, stcb, (*laddr).ifa, 0xc001u16, 0i32);
            }
        }
        laddr = (*laddr).sctp_nxt_addr.le_next
    }
}
/*
 * makes sure that the current kernel address list is consistent with the new
 * association (with all addrs bound) adds addresses as necessary
 */
unsafe extern "C" fn sctp_check_address_list_all(
    mut stcb: *mut sctp_tcb,
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut length: libc::c_int,
    mut init_addr: *mut sockaddr,
    mut local_scope: uint16_t,
    mut site_scope: uint16_t,
    mut ipv4_scope: uint16_t,
    mut loopback_scope: uint16_t,
) {
    let mut vrf = 0 as *mut sctp_vrf;
    let mut sctp_ifn = 0 as *mut sctp_ifn;
    let mut vrf_id = 0;
    if !stcb.is_null() {
        vrf_id = (*stcb).asoc.vrf_id
    } else {
        return;
    }
    pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
    vrf = sctp_find_vrf(vrf_id);
    if vrf.is_null() {
        pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        return;
    }
    /* go through all our known interfaces */
    sctp_ifn = (*vrf).ifnlist.lh_first; /* end foreach ifn */
    while !sctp_ifn.is_null() {
        if !(loopback_scope as libc::c_int == 0i32
            && strncmp(
                (*sctp_ifn).ifn_name.as_mut_ptr(),
                b"lo\x00" as *const u8 as *const libc::c_char,
                2u64,
            ) == 0i32)
        {
            let mut sctp_ifa = 0 as *mut sctp_ifa;
            /* go through each interface address */
            sctp_ifa = (*sctp_ifn).ifalist.lh_first;
            while !sctp_ifa.is_null() {
                /* do i have it implicitly? */
                if !(sctp_cmpaddr(&mut (*sctp_ifa).address.sa, init_addr) != 0) {
                    let mut current_block_17: u64;
                    match (*sctp_ifa).address.sa.sa_family as libc::c_int {
                        2 => {
                            let mut sin = 0 as *mut sockaddr_in;
                            sin = &mut (*sctp_ifa).address.sin;
                            if ipv4_scope as libc::c_int == 0i32
                                && (*(&mut (*sin).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                                    .offset(0isize)
                                    as libc::c_int
                                    == 10i32
                                    || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(0isize)
                                        as libc::c_int
                                        == 172i32
                                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(1isize)
                                            as libc::c_int
                                            >= 16i32
                                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(1isize)
                                            as libc::c_int
                                            <= 32i32
                                    || *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(0isize)
                                        as libc::c_int
                                        == 192i32
                                        && *(&mut (*sin).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(1isize)
                                            as libc::c_int
                                            == 168i32)
                            {
                                current_block_17 = 4956146061682418353;
                            } else {
                                current_block_17 = 8693738493027456495;
                            }
                        }
                        10 => {
                            let mut sin6 = 0 as *mut sockaddr_in6;
                            sin6 = &mut (*sctp_ifa).address.sin6;
                            if local_scope as libc::c_int == 0i32
                                && ({
                                    let mut __a =
                                        &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                                        == htonl(0xfe800000u32))
                                        as libc::c_int
                                }) != 0
                            {
                                current_block_17 = 4956146061682418353;
                            } else if site_scope as libc::c_int == 0i32
                                && ({
                                    let mut __a =
                                        &mut (*sin6).sin6_addr as *mut in6_addr as *const in6_addr;
                                    ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                                        == htonl(0xfec00000u32))
                                        as libc::c_int
                                }) != 0
                            {
                                current_block_17 = 4956146061682418353;
                            } else {
                                current_block_17 = 8693738493027456495;
                            }
                        }
                        _ => {
                            current_block_17 = 8693738493027456495;
                        }
                    }
                    match current_block_17 {
                        4956146061682418353 => {}
                        _ => {
                            /* check to see if in the init-ack */
                            if sctp_addr_in_initack(
                                m,
                                offset as uint32_t,
                                length as uint32_t,
                                &mut (*sctp_ifa).address.sa,
                            ) == 0
                            {
                                /* try to add it */
                                sctp_addr_mgmt_assoc(
                                    (*stcb).sctp_ep,
                                    stcb,
                                    sctp_ifa,
                                    0xc001u16,
                                    1i32,
                                );
                            }
                        }
                    }
                }
                /* private address not in scope */
                sctp_ifa = (*sctp_ifa).next_ifa.le_next
            }
        }
        /* end foreach ifa */
        sctp_ifn = (*sctp_ifn).next_ifn.le_next
    }
    pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
}
/* skip loopback interface */
/*
 * validates an init-ack chunk (from a cookie-echo) with current addresses
 * adds addresses from the init-ack into our local address list, if needed
 * queues asconf adds/deletes addresses as needed and makes appropriate list
 * changes for source address selection m, offset: points to the start of the
 * address list in an init-ack chunk length: total length of the address
 * params only init_addr: address where my INIT-ACK was sent from
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_check_address_list(
    mut stcb: *mut sctp_tcb,
    mut m: *mut mbuf,
    mut offset: libc::c_int,
    mut length: libc::c_int,
    mut init_addr: *mut sockaddr,
    mut local_scope: uint16_t,
    mut site_scope: uint16_t,
    mut ipv4_scope: uint16_t,
    mut loopback_scope: uint16_t,
) {
    /* process the local addresses in the initack */
    sctp_process_initack_addresses(stcb, m, offset as libc::c_uint, length as libc::c_uint);
    if (*(*stcb).sctp_ep).sctp_flags & 0x4u32 != 0 {
        /* bound all case */
        sctp_check_address_list_all(
            stcb,
            m,
            offset,
            length,
            init_addr,
            local_scope,
            site_scope,
            ipv4_scope,
            loopback_scope,
        );
    } else if (*(*stcb).sctp_ep).sctp_features & 0x20u64 == 0x20u64 {
        /* subset bound case */
        /* asconf's allowed */
        sctp_check_address_list_ep(stcb, m, offset, length, init_addr);
    };
}
/* else, no asconfs allowed, so what we sent is what we get */
/*
 * sctp_bindx() support
 */
#[no_mangle]
pub unsafe extern "C" fn sctp_addr_mgmt_ep_sa(
    mut inp: *mut sctp_inpcb,
    mut sa: *mut sockaddr,
    mut type_0: uint32_t,
    mut vrf_id: uint32_t,
    mut sctp_ifap: *mut sctp_ifa,
) -> uint32_t {
    let mut ifa = 0 as *mut sctp_ifa;
    if !sctp_ifap.is_null() {
        ifa = sctp_ifap
    } else if type_0 == 0xc001u32 {
        /* For an add the address MUST be on the system */
        ifa = sctp_find_ifa_by_addr(sa, vrf_id, 0i32)
    } else if type_0 == 0xc002u32 {
        /* For a delete we need to find it in the inp */
        ifa = sctp_find_ifa_in_ep(inp, sa, 0i32)
    } else {
        ifa = 0 as *mut sctp_ifa
    }
    if !ifa.is_null() {
        let mut laddr = 0 as *mut sctp_laddr;
        if type_0 == 0xc001u32 {
            sctp_add_local_addr_ep(inp, ifa, type_0);
        } else if type_0 == 0xc002u32 {
            if (*inp).laddr_count < 2i32 {
                /* can't delete the last local address */
                return 22u32;
            }
            laddr = (*inp).sctp_addr_list.lh_first;
            while !laddr.is_null() {
                if ifa == (*laddr).ifa {
                    /* Mark in the delete */
                    (*laddr).action = type_0
                }
                laddr = (*laddr).sctp_nxt_addr.le_next
            }
        }
        if (*inp).sctp_asoc_list.lh_first.is_null() {
            /*
             * There is no need to start the iterator if
             * the inp has no associations.
             */
            if type_0 == 0xc002u32 {
                let mut nladdr = 0 as *mut sctp_laddr;
                laddr = (*inp).sctp_addr_list.lh_first;
                while !laddr.is_null() && {
                    nladdr = (*laddr).sctp_nxt_addr.le_next;
                    (1i32) != 0
                } {
                    if (*laddr).ifa == ifa {
                        sctp_del_local_addr_ep(inp, ifa);
                    }
                    laddr = nladdr
                }
            }
        } else {
            let mut asc = 0 as *mut sctp_asconf_iterator;
            let mut wi = 0 as *mut sctp_laddr;
            let mut ret = 0;
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
                return 12u32;
            }
            wi = malloc(system_base_info.sctppcbinfo.ipi_zone_laddr) as *mut sctp_laddr;
            if wi.is_null() {
                free(asc as *mut libc::c_void);
                return 12u32;
            }
            (*asc).list_of_work.lh_first = 0 as *mut sctp_laddr;
            (*asc).cnt = 1i32;
            ::std::intrinsics::atomic_xadd(&mut system_base_info.sctppcbinfo.ipi_count_laddr, 1u32);
            (*wi).ifa = ifa;
            (*wi).action = type_0;
            ::std::intrinsics::atomic_xadd(&mut (*ifa).refcount, 1u32);
            (*wi).sctp_nxt_addr.le_next = (*asc).list_of_work.lh_first;
            if !(*wi).sctp_nxt_addr.le_next.is_null() {
                (*(*asc).list_of_work.lh_first).sctp_nxt_addr.le_prev =
                    &mut (*wi).sctp_nxt_addr.le_next
            }
            (*asc).list_of_work.lh_first = wi;
            (*wi).sctp_nxt_addr.le_prev = &mut (*asc).list_of_work.lh_first;
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
                Some(
                    sctp_asconf_iterator_ep_end
                        as unsafe extern "C" fn(
                            _: *mut sctp_inpcb,
                            _: *mut libc::c_void,
                            _: uint32_t,
                        ) -> libc::c_int,
                ),
                0u32,
                0u32,
                0u32,
                asc as *mut libc::c_void,
                0u32,
                Some(
                    sctp_asconf_iterator_end
                        as unsafe extern "C" fn(_: *mut libc::c_void, _: uint32_t) -> (),
                ),
                inp,
                0u8,
            );
            if ret != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"Failed to initiate iterator for addr_mgmt_ep_sa\n\x00" as *const u8
                            as *const libc::c_char,
                    );
                }
                sctp_asconf_iterator_end(asc as *mut libc::c_void, 0u32);
                return 14u32;
            }
        }
        return 0u32;
    } else {
        /* invalid address! */
        return 99u32;
    };
}
#[no_mangle]
pub unsafe extern "C" fn sctp_asconf_send_nat_state_update(
    mut stcb: *mut sctp_tcb,
    mut net: *mut sctp_nets,
) {
    let mut aa = 0 as *mut sctp_asconf_addr;
    let mut sctp_ifap = 0 as *mut sctp_ifa;
    let mut vtag = 0 as *mut sctp_asconf_tag_param;
    let mut to = 0 as *mut sockaddr_in;
    let mut to6 = 0 as *mut sockaddr_in6;
    if net.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"sctp_asconf_send_nat_state_update: Missing net\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return;
    }
    if stcb.is_null() {
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"sctp_asconf_send_nat_state_update: Missing stcb\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return;
    }
    /* Need to have in the asconf:
     * - vtagparam(my_vtag/peer_vtag)
     * - add(0.0.0.0)
     * - del(0.0.0.0)
     * - Any global addresses add(addr)
     */
    aa =
        malloc(::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong) as *mut sctp_asconf_addr;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            aa as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong,
        );
    }
    if aa.is_null() {
        /* didn't get memory */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"sctp_asconf_send_nat_state_update: failed to get memory!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return;
    }
    (*aa).special_del = 0u8;
    /* fill in asconf address parameter fields */
    /* top level elements are "networked" during send */
    (*aa).ifa = 0 as *mut sctp_ifa; /* clear sent flag */
    (*aa).sent = 0u8;
    vtag = &mut (*aa).ap.aph as *mut sctp_asconf_paramhdr as *mut sctp_asconf_tag_param;
    (*vtag).aph.ph.param_type = 0xc008u16;
    (*vtag).aph.ph.param_length = ::std::mem::size_of::<sctp_asconf_tag_param>() as uint16_t;
    (*vtag).local_vtag = htonl((*stcb).asoc.my_vtag);
    (*vtag).remote_vtag = htonl((*stcb).asoc.peer_vtag);
    (*aa).next.tqe_next = 0 as *mut sctp_asconf_addr;
    (*aa).next.tqe_prev = (*stcb).asoc.asconf_queue.tqh_last;
    *(*stcb).asoc.asconf_queue.tqh_last = aa;
    (*stcb).asoc.asconf_queue.tqh_last = &mut (*aa).next.tqe_next;
    aa =
        malloc(::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong) as *mut sctp_asconf_addr;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            aa as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong,
        );
    }
    if aa.is_null() {
        /* didn't get memory */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"sctp_asconf_send_nat_state_update: failed to get memory!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return;
    }
    memset(
        aa as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong,
    );
    /* fill in asconf address parameter fields */
    /* ADD(0.0.0.0) */
    match (*net).ro._l_addr.sa.sa_family as libc::c_int {
        2 => {
            (*aa).ap.aph.ph.param_type = 0xc001u16;
            (*aa).ap.aph.ph.param_length =
                ::std::mem::size_of::<sctp_asconf_addrv4_param>() as uint16_t;
            (*aa).ap.addrp.ph.param_type = 0x5u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv4addr_param>() as uint16_t;
            /* No need to add an address, we are using 0.0.0.0 */
            (*aa).next.tqe_next = 0 as *mut sctp_asconf_addr;
            (*aa).next.tqe_prev = (*stcb).asoc.asconf_queue.tqh_last;
            *(*stcb).asoc.asconf_queue.tqh_last = aa;
            (*stcb).asoc.asconf_queue.tqh_last = &mut (*aa).next.tqe_next
        }
        10 => {
            (*aa).ap.aph.ph.param_type = 0xc001u16;
            (*aa).ap.aph.ph.param_length =
                ::std::mem::size_of::<sctp_asconf_addr_param>() as uint16_t;
            (*aa).ap.addrp.ph.param_type = 0x6u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv6addr_param>() as uint16_t;
            /* No need to add an address, we are using 0.0.0.0 */
            (*aa).next.tqe_next = 0 as *mut sctp_asconf_addr;
            (*aa).next.tqe_prev = (*stcb).asoc.asconf_queue.tqh_last;
            *(*stcb).asoc.asconf_queue.tqh_last = aa;
            (*stcb).asoc.asconf_queue.tqh_last = &mut (*aa).next.tqe_next
        }
        _ => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"sctp_asconf_send_nat_state_update: unknown address family\n\x00"
                            as *const u8 as *const libc::c_char,
                    );
                }
            }
            free(aa as *mut libc::c_void);
            return;
        }
    }
    aa =
        malloc(::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong) as *mut sctp_asconf_addr;
    if 0x1i32 & 0x100i32 != 0 {
        memset(
            aa as *mut libc::c_void,
            0i32,
            ::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong,
        );
    }
    if aa.is_null() {
        /* didn't get memory */
        if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
            if system_base_info.debug_printf.is_some() {
                system_base_info
                    .debug_printf
                    .expect("non-null function pointer")(
                    b"sctp_asconf_send_nat_state_update: failed to get memory!\n\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        return;
    }
    memset(
        aa as *mut libc::c_void,
        0i32,
        ::std::mem::size_of::<sctp_asconf_addr>() as libc::c_ulong,
    );
    /* fill in asconf address parameter fields */
    /* ADD(0.0.0.0) */
    match (*net).ro._l_addr.sa.sa_family as libc::c_int {
        2 => {
            (*aa).ap.aph.ph.param_type = 0xc001u16;
            (*aa).ap.aph.ph.param_length =
                ::std::mem::size_of::<sctp_asconf_addrv4_param>() as uint16_t;
            (*aa).ap.addrp.ph.param_type = 0x5u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv4addr_param>() as uint16_t;
            /* No need to add an address, we are using 0.0.0.0 */
            (*aa).next.tqe_next = 0 as *mut sctp_asconf_addr;
            (*aa).next.tqe_prev = (*stcb).asoc.asconf_queue.tqh_last;
            *(*stcb).asoc.asconf_queue.tqh_last = aa;
            (*stcb).asoc.asconf_queue.tqh_last = &mut (*aa).next.tqe_next
        }
        10 => {
            (*aa).ap.aph.ph.param_type = 0xc002u16;
            (*aa).ap.aph.ph.param_length =
                ::std::mem::size_of::<sctp_asconf_addr_param>() as uint16_t;
            (*aa).ap.addrp.ph.param_type = 0x6u16;
            (*aa).ap.addrp.ph.param_length =
                ::std::mem::size_of::<sctp_ipv6addr_param>() as uint16_t;
            /* No need to add an address, we are using 0.0.0.0 */
            (*aa).next.tqe_next = 0 as *mut sctp_asconf_addr;
            (*aa).next.tqe_prev = (*stcb).asoc.asconf_queue.tqh_last;
            *(*stcb).asoc.asconf_queue.tqh_last = aa;
            (*stcb).asoc.asconf_queue.tqh_last = &mut (*aa).next.tqe_next
        }
        _ => {
            if system_base_info.sctpsysctl.sctp_debug_on & 0x10000u32 != 0 {
                if system_base_info.debug_printf.is_some() {
                    system_base_info
                        .debug_printf
                        .expect("non-null function pointer")(
                        b"sctp_asconf_send_nat_state_update: unknown address family\n\x00"
                            as *const u8 as *const libc::c_char,
                    );
                }
            }
            free(aa as *mut libc::c_void);
            return;
        }
    }
    /* Now we must hunt the addresses and add all global addresses */
    if (*(*stcb).sctp_ep).sctp_flags & 0x4u32 != 0 {
        let mut vrf = 0 as *mut sctp_vrf;
        let mut vrf_id = 0;
        vrf_id = (*(*stcb).sctp_ep).def_vrf_id;
        vrf = sctp_find_vrf(vrf_id);
        if !vrf.is_null() {
            let mut sctp_ifnp = 0 as *mut sctp_ifn;
            pthread_mutex_lock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
            sctp_ifnp = (*vrf).ifnlist.lh_first;
            while !sctp_ifnp.is_null() {
                sctp_ifap = (*sctp_ifnp).ifalist.lh_first;
                while !sctp_ifap.is_null() {
                    let mut current_block_181: u64;
                    match (*sctp_ifap).address.sa.sa_family as libc::c_int {
                        2 => {
                            to = &mut (*sctp_ifap).address.sin;
                            if *(&mut (*to).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                                .offset(0isize) as libc::c_int
                                == 10i32
                                || *(&mut (*to).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                                    .offset(0isize)
                                    as libc::c_int
                                    == 172i32
                                    && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(1isize)
                                        as libc::c_int
                                        >= 16i32
                                    && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(1isize)
                                        as libc::c_int
                                        <= 32i32
                                || *(&mut (*to).sin_addr.s_addr as *mut in_addr_t as *mut uint8_t)
                                    .offset(0isize)
                                    as libc::c_int
                                    == 192i32
                                    && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                        as *mut uint8_t)
                                        .offset(1isize)
                                        as libc::c_int
                                        == 168i32
                            {
                                current_block_181 = 1953367063549441504;
                            } else if *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                as *mut uint8_t)
                                .offset(0isize) as libc::c_int
                                == 127i32
                            {
                                current_block_181 = 1953367063549441504;
                            } else {
                                current_block_181 = 1587619384396752891;
                            }
                        }
                        10 => {
                            to6 = &mut (*sctp_ifap).address.sin6;
                            if ({
                                let mut __a =
                                    &mut (*to6).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                    && (*__a).__in6_u.__u6_addr32[3usize] == htonl(1u32))
                                    as libc::c_int
                            }) != 0
                            {
                                current_block_181 = 1953367063549441504;
                            } else if ({
                                let mut __a =
                                    &mut (*to6).sin6_addr as *mut in6_addr as *const in6_addr;
                                ((*__a).__in6_u.__u6_addr32[0usize] & htonl(0xffc00000u32)
                                    == htonl(0xfe800000u32))
                                    as libc::c_int
                            }) != 0
                            {
                                current_block_181 = 1953367063549441504;
                            } else {
                                current_block_181 = 1587619384396752891;
                            }
                        }
                        _ => {
                            current_block_181 = 1953367063549441504;
                        }
                    }
                    match current_block_181 {
                        1587619384396752891 => {
                            sctp_asconf_queue_mgmt(stcb, sctp_ifap, 0xc001u16);
                        }
                        _ => {}
                    }
                    sctp_ifap = (*sctp_ifap).next_ifa.le_next
                }
                sctp_ifnp = (*sctp_ifnp).next_ifn.le_next
            }
            pthread_mutex_unlock(&mut system_base_info.sctppcbinfo.ipi_addr_mtx);
        }
    } else {
        let mut laddr = 0 as *mut sctp_laddr;
        laddr = (*(*stcb).sctp_ep).sctp_addr_list.lh_first;
        while !laddr.is_null() {
            if !(*laddr).ifa.is_null() {
                if !((*(*laddr).ifa).localifa_flags & 0x2u32 != 0) {
                    if !((*laddr).action == 0xc002u32) {
                        let mut current_block_190: u64;
                        sctp_ifap = (*laddr).ifa;
                        match (*sctp_ifap).address.sa.sa_family as libc::c_int {
                            2 => {
                                current_block_190 = 1457121039885383723;
                                match current_block_190 {
                                    9437034758168687938 => {
                                        to6 = &mut (*sctp_ifap).address.sin6;
                                        if ({
                                            let mut __a = &mut (*to6).sin6_addr as *mut in6_addr
                                                as *const in6_addr;
                                            ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                                && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                                && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                                && (*__a).__in6_u.__u6_addr32[3usize]
                                                    == htonl(1u32))
                                                as libc::c_int
                                        }) != 0
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else if ({
                                            let mut __a = &mut (*to6).sin6_addr as *mut in6_addr
                                                as *const in6_addr;
                                            ((*__a).__in6_u.__u6_addr32[0usize]
                                                & htonl(0xffc00000u32)
                                                == htonl(0xfe800000u32))
                                                as libc::c_int
                                        }) != 0
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else {
                                            current_block_190 = 259606973132676092;
                                        }
                                    }
                                    _ => {
                                        to = &mut (*sctp_ifap).address.sin;
                                        if *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(0isize)
                                            as libc::c_int
                                            == 10i32
                                            || *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                as *mut uint8_t)
                                                .offset(0isize)
                                                as libc::c_int
                                                == 172i32
                                                && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                    as *mut uint8_t)
                                                    .offset(1isize)
                                                    as libc::c_int
                                                    >= 16i32
                                                && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                    as *mut uint8_t)
                                                    .offset(1isize)
                                                    as libc::c_int
                                                    <= 32i32
                                            || *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                as *mut uint8_t)
                                                .offset(0isize)
                                                as libc::c_int
                                                == 192i32
                                                && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                    as *mut uint8_t)
                                                    .offset(1isize)
                                                    as libc::c_int
                                                    == 168i32
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else if *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(0isize)
                                            as libc::c_int
                                            == 127i32
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else {
                                            current_block_190 = 259606973132676092;
                                        }
                                    }
                                }
                                match current_block_190 {
                                    9467764101860050311 => {}
                                    _ => {
                                        sctp_asconf_queue_mgmt(stcb, sctp_ifap, 0xc001u16);
                                    }
                                }
                            }
                            10 => {
                                current_block_190 = 9437034758168687938;
                                match current_block_190 {
                                    9437034758168687938 => {
                                        to6 = &mut (*sctp_ifap).address.sin6;
                                        if ({
                                            let mut __a = &mut (*to6).sin6_addr as *mut in6_addr
                                                as *const in6_addr;
                                            ((*__a).__in6_u.__u6_addr32[0usize] == 0u32
                                                && (*__a).__in6_u.__u6_addr32[1usize] == 0u32
                                                && (*__a).__in6_u.__u6_addr32[2usize] == 0u32
                                                && (*__a).__in6_u.__u6_addr32[3usize]
                                                    == htonl(1u32))
                                                as libc::c_int
                                        }) != 0
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else if ({
                                            let mut __a = &mut (*to6).sin6_addr as *mut in6_addr
                                                as *const in6_addr;
                                            ((*__a).__in6_u.__u6_addr32[0usize]
                                                & htonl(0xffc00000u32)
                                                == htonl(0xfe800000u32))
                                                as libc::c_int
                                        }) != 0
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else {
                                            current_block_190 = 259606973132676092;
                                        }
                                    }
                                    _ => {
                                        to = &mut (*sctp_ifap).address.sin;
                                        if *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(0isize)
                                            as libc::c_int
                                            == 10i32
                                            || *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                as *mut uint8_t)
                                                .offset(0isize)
                                                as libc::c_int
                                                == 172i32
                                                && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                    as *mut uint8_t)
                                                    .offset(1isize)
                                                    as libc::c_int
                                                    >= 16i32
                                                && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                    as *mut uint8_t)
                                                    .offset(1isize)
                                                    as libc::c_int
                                                    <= 32i32
                                            || *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                as *mut uint8_t)
                                                .offset(0isize)
                                                as libc::c_int
                                                == 192i32
                                                && *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                                    as *mut uint8_t)
                                                    .offset(1isize)
                                                    as libc::c_int
                                                    == 168i32
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else if *(&mut (*to).sin_addr.s_addr as *mut in_addr_t
                                            as *mut uint8_t)
                                            .offset(0isize)
                                            as libc::c_int
                                            == 127i32
                                        {
                                            current_block_190 = 9467764101860050311;
                                        } else {
                                            current_block_190 = 259606973132676092;
                                        }
                                    }
                                }
                                match current_block_190 {
                                    9467764101860050311 => {}
                                    _ => {
                                        sctp_asconf_queue_mgmt(stcb, sctp_ifap, 0xc001u16);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            /* Address being deleted on this ep
             * don't list.
             */
            laddr = (*laddr).sctp_nxt_addr.le_next
        }
    }
    /* Now we must send the asconf into the queue */
    sctp_send_asconf(stcb, net, 0i32);
}
