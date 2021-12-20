use std::ptr;

use crate::{
    asn1::{Asn1GeneralizedTimeRef, Asn1IntegerRef},
    cvt_n, cvt_p,
    x509::GeneralName,
};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl_macros::corresponds;

use crate::{asn1::Asn1Object, error::ErrorStack, pkcs7::Pkcs7Ref};

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_MSG_IMPRINT;
    fn drop = ffi::TS_MSG_IMPRINT_free;

    pub struct TsMessageImprint;
    pub struct TsMessageImprintRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_ACCURACY;
    fn drop = ffi::TS_ACCURACY_free;

    pub struct TsAccuracy;
    pub struct TsAccuracyRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_TST_INFO;
    fn drop = ffi::TS_TST_INFO_free;

    /// High level TS_TST_INFO wrapper
    ///
    /// Time Stamp Token is a data format that prove contained digest exists before the time it is time-stamped.
    /// TST_INFO is content of PKCS#7 Content Info.
    /// TST_INFO contains message digest hash, digest algorithm that is used to calculate hash, algorithm parameter,
    /// , generated time and others.
    /// TST_INFO and OpenSSL follows this RFC's implementation.
    ///
    /// [`RFC 3161`]: https://datatracker.ietf.org/doc/html/rfc3161#page-8
    pub struct TsTstInfo;
    /// Reference to [`TsTstInfo`]
    ///
    /// [`TsTstInfo`]:struct.TsTstInfo.html
    pub struct TsTstInfoRef;
}

impl TsTstInfoRef {
    to_der! {
        /// Serializes this TstInfo using DER.
        #[corresponds(i2d_TS_TST_INFO)]
        to_der,
        ffi::i2d_TS_TST_INFO
    }
}

impl TsTstInfo {
    from_der! {
        /// Deserializes a DER-encoded TstInfo structure.
        #[corresponds(d2i_TS_TST_INFO)]
        from_der,
        TsTstInfo,
        ffi::d2i_TS_TST_INFO
    }

    pub fn from_pkcs7(pcks7: Pkcs7Ref) -> Self {
        TsTstInfo(unsafe { ffi::PKCS7_to_TS_TST_INFO(pcks7.as_ptr()) })
    }

    pub fn get_version(&self) -> Result<i64, ErrorStack> {
        let version = unsafe { ffi::TS_TST_INFO_get_version(self.as_ptr()) };
        if version < 0 {
            Err(ErrorStack::get())
        } else {
            Ok(version)
        }
    }

    pub fn get_policy_id(&self) -> Result<Asn1Object, ErrorStack> {
        unsafe {
            let policy_id_ptr = cvt_p(ffi::TS_TST_INFO_get_policy_id(self.as_ptr()))?;
            Ok(Asn1Object::from_ptr(policy_id_ptr))
        }
    }

    pub fn get_msg_imprint(&self) -> Result<TsMessageImprint, ErrorStack> {
        Ok(unsafe {
            TsMessageImprint::from_ptr(cvt_p(ffi::TS_TST_INFO_get_msg_imprint(self.as_ptr()))?)
        })
    }

    pub fn get_ordering(&self) -> Result<i32, ErrorStack> {
        unsafe { cvt_n(ffi::TS_TST_INFO_get_ordering(self.as_ptr())) }
    }

    pub fn get_tsa(&self) -> Result<GeneralName, ErrorStack> {
        unsafe {
            let tsa_ptr = cvt_p(ffi::TS_TST_INFO_get_tsa(self.as_ptr()))?;
            Ok(GeneralName::from_ptr(tsa_ptr))
        }
    }
}

impl<'a> TsTstInfo {
    pub fn get_serial(&'a self) -> Result<&'a Asn1IntegerRef, ErrorStack> {
        unsafe {
            // TS_TST_INFO_get_serial just returns pointer to member of internal struct
            let serial_ptr = ffi::TS_TST_INFO_get_serial(self.as_ptr());
            if serial_ptr.is_null() {
                return Err(ErrorStack::get());
            }

            Ok(Asn1IntegerRef::from_ptr::<'a>(serial_ptr as *mut _))
        }
    }

    pub fn get_time(&'a self) -> Result<&'a Asn1GeneralizedTimeRef, ErrorStack> {
        unsafe {
            let gen_time_tpr = ffi::TS_TST_INFO_get_time(self.as_ptr());
            if gen_time_tpr.is_null() {
                return Err(ErrorStack::get());
            }
            Ok(Asn1GeneralizedTimeRef::from_ptr::<'a>(
                gen_time_tpr as *mut _,
            ))
        }
    }

    pub fn get_accuracy(&self) -> Result<&'a TsAccuracyRef, ErrorStack> {
        unsafe {
            let accuracy_ptr = ffi::TS_TST_INFO_get_accuracy(self.as_ptr());
            if accuracy_ptr.is_null() {
                return Err(ErrorStack::get());
            }
            Ok(TsAccuracyRef::from_ptr::<'a>(accuracy_ptr as *mut _))
        }
    }

    pub fn get_nonce(&self) -> Result<&'a Asn1IntegerRef, ErrorStack> {
        unsafe {
            // TS_TST_INFO_get_serial just returns pointer to member of internal struct
            let serial_ptr = ffi::TS_TST_INFO_get_nonce(self.as_ptr());
            if serial_ptr.is_null() {
                return Err(ErrorStack::get());
            }

            Ok(Asn1IntegerRef::from_ptr::<'a>(serial_ptr as *mut _))
        }
    }
}
