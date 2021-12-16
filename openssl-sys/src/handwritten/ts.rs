use libc::*;

use crate::{ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OBJECT, GENERAL_NAME};
pub enum TS_MSG_IMPRINT {}
pub enum TS_REQ {}
pub enum TS_ACCURACY {}
pub enum TS_TST_INFO {}

extern "C" {
    #[cfg(ossl101)]
    pub fn i2d_TS_TST_INFO(a: *const ::TS_TST_INFO, pp: *mut *mut c_uchar) -> c_int;
    #[cfg(ossl101)]
    pub fn d2i_TS_TST_INFO(
        a: *mut *mut ::TS_TST_INFO,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ::TS_TST_INFO;

    #[cfg(ossl101)]
    pub fn TS_TST_INFO_free(a: *mut ::TS_TST_INFO);
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_version(a: *const TS_TST_INFO) -> c_long;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_policy_id(a: *mut TS_TST_INFO) -> *mut ASN1_OBJECT;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_msg_imprint(a: *mut TS_TST_INFO) -> *mut TS_MSG_IMPRINT;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_serial(a: *const TS_TST_INFO) -> *const ASN1_INTEGER;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_time(a: *const TS_TST_INFO) -> *const ASN1_GENERALIZEDTIME;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_accuracy(a: *mut TS_TST_INFO) -> *const TS_ACCURACY;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_ordering(a: *const TS_TST_INFO) -> c_int;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_nonce(a: *const TS_TST_INFO) -> *const ASN1_INTEGER;
    #[cfg(ossl101)]
    pub fn TS_TST_INFO_get_tsa(a: *mut TS_TST_INFO) -> *mut GENERAL_NAME;
}
