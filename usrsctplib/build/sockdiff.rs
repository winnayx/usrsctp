diff --git a/usrsctplib/user_socket.rs b/usrsctplib/user_socket.rs
index 0e5a741..bfbd9c1 100644
--- a/usrsctplib/user_socket.rs
+++ b/usrsctplib/user_socket.rs
@@ -4976,7 +4976,7 @@ pub unsafe extern "C" fn userspace_sctp_sendmsg(mut so: *mut socket,
                         __reserve_pad: [0; 92],}; let mut iov =  
     
         [iovec{iov_base: 0 as *mut libc::c_void, iov_len: 0,}; 1]; 
-        let mut sinfo: *mut sctp_sndrcvinfo = &mut sndrcvinfo; 
+         let mut sinfo =  &mut sndrcvinfo; 
         let mut auio =
     
         uio{uio_iov: 0 as *mut iovec,
