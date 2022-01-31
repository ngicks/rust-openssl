use std::ptr;

use crate::{
    asn1::{Asn1GeneralizedTimeRef, Asn1IntegerRef, Asn1ObjectRef, Asn1OctetStringRef},
    cvt_p,
    x509::{GeneralNameRef, X509AlgorithmRef},
};
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use crate::{error::ErrorStack, pkcs7::Pkcs7Ref};

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_TST_INFO;
    fn drop = ffi::TS_TST_INFO_free;

    /// High level TS_TST_INFO wrapper
    ///
    /// Time Stamp Token is set of hash of data, hash algorithm used to calculate the hash, and etc.
    /// Time Stamp Token is used to prove that has of data exists before the time this info is generated (genTIme).
    /// Usually this data is generated via TimeStampReq, and stored inside meta data space of source of the hash.
    ///
    /// [`RFC 3161`]: https://tools.ietf.org/html/rfc3161#page-8
    pub struct TsTstInfo;
    /// Reference to [`TsTstInfo`]
    ///
    /// [`TsTstInfo`]:struct.TsTstInfo.html
    pub struct TsTstInfoRef;
}

impl TsTstInfoRef {
    to_der! {
        /// Serializes this TsTstInfo using DER.
        #[corresponds(i2d_TS_TST_INFO)]
        to_der,
        ffi::i2d_TS_TST_INFO
    }
}

impl TsTstInfo {
    from_der! {
        /// Deserializes a DER-encoded TsTstInfo structure.
        #[corresponds(d2i_TS_TST_INFO)]
        from_der,
        TsTstInfo,
        ffi::d2i_TS_TST_INFO
    }

    /// create TsTstInfo from pkcs7 directly.
    pub fn from_pkcs7(pkcs7: &Pkcs7Ref) -> Result<Self, ErrorStack> {
        Ok(TsTstInfo(unsafe {
            cvt_p(ffi::PKCS7_to_TS_TST_INFO(pkcs7.as_ptr()))?
        }))
    }
}

impl TsTstInfoRef {
    /// version describes version of timestamp token
    /// version can only be 1 for RFC3161.
    pub fn get_version(&self) -> i64 {
        let version = unsafe { ffi::TS_TST_INFO_get_version(self.as_ptr()) };
        if version < 0 {
            panic!("Invariant Violation. TS_TST_INFO_get_version must return 1");
        } else {
            version
        }
    }

    /// returns TSAPolicyId
    /// policyId is TSA's policy under which response was generated.
    pub fn get_policy_id(&self) -> &Asn1ObjectRef {
        unsafe {
            let policy_id_ptr = ffi::TS_TST_INFO_get_policy_id(self.as_ptr());
            if policy_id_ptr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_policy_id must not return null");
            }
            Asn1ObjectRef::from_ptr(policy_id_ptr)
        }
    }

    pub fn get_msg_imprint(&self) -> &TsMessageImprintRef {
        unsafe {
            let msg_imprint_ptr = ffi::TS_TST_INFO_get_msg_imprint(self.as_ptr());
            if msg_imprint_ptr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_msg_imprint must not return null");
            }
            TsMessageImprintRef::from_ptr(msg_imprint_ptr)
        }
    }

    /// serial is 160 bits long at most.
    pub fn get_serial(&self) -> &Asn1IntegerRef {
        unsafe {
            let serial_ptr = ffi::TS_TST_INFO_get_serial(self.as_ptr());
            if serial_ptr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_serial must not return null");
            }
            Asn1IntegerRef::from_ptr(serial_ptr as *mut _)
        }
    }

    /// returns genTime
    /// genTime is the time at which the timestamp is generated.
    /// genTime must be UTC time. The last character of genTime is always Z (Zulu timezone).
    /// Granularity of time is not limited. However if the precision need not to be better than
    /// seconds, it SHOULD be limitted to one second.
    pub fn get_time(&self) -> &Asn1GeneralizedTimeRef {
        unsafe {
            let gen_time_tpr = ffi::TS_TST_INFO_get_time(self.as_ptr());
            if gen_time_tpr.is_null() {
                panic!("Invariant Violation. TS_TST_INFO_get_time must not return null");
            }
            Asn1GeneralizedTimeRef::from_ptr(gen_time_tpr as *mut _)
        }
    }

    pub fn get_accuracy(&self) -> Option<&TsAccuracyRef> {
        unsafe {
            let accuracy_ptr = ffi::TS_TST_INFO_get_accuracy(self.as_ptr());
            if accuracy_ptr.is_null() {
                None
            } else {
                Some(TsAccuracyRef::from_ptr(accuracy_ptr as *mut _))
            }
        }
    }

    /// return ordering
    /// default is FALSE
    pub fn get_ordering(&self) -> bool {
        // TS_TST_INFO_get_ordering returns just 1 or 0
        // default is false
        if unsafe { ffi::TS_TST_INFO_get_ordering(self.as_ptr()) } > 0 {
            true
        } else {
            false
        }
    }

    pub fn get_nonce(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let serial_ptr = ffi::TS_TST_INFO_get_nonce(self.as_ptr());
            if serial_ptr.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(serial_ptr as *mut _))
            }
        }
    }

    pub fn get_tsa(&self) -> Option<&GeneralNameRef> {
        unsafe {
            let tsa_ptr = ffi::TS_TST_INFO_get_tsa(self.as_ptr());
            if tsa_ptr.is_null() {
                None
            } else {
                Some(GeneralNameRef::from_ptr(tsa_ptr))
            }
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_MSG_IMPRINT;
    fn drop = ffi::TS_MSG_IMPRINT_free;

    /// High level TS_MSG_IMPRINT wrapper
    ///
    /// messageImprint contains a hash algorithm and hased message to be or to have been time-stamped.
    ///
    /// [`RFC 3161`]: https://tools.ietf.org/html/rfc3161#page-4
    pub struct TsMessageImprint;
    /// Reference to [`TsMessageImprint`]
    ///
    /// [`TsMessageImprint`]:struct.TsMessageImprint.html
    pub struct TsMessageImprintRef;
}

impl TsMessageImprintRef {
    to_der! {
        /// Serializes this TstInfo using DER.
        #[corresponds(i2d_TS_MSG_IMPRINT)]
        to_der,
        ffi::i2d_TS_MSG_IMPRINT
    }

    pub fn get_algo(&self) -> &X509AlgorithmRef {
        unsafe { X509AlgorithmRef::from_ptr(ffi::TS_MSG_IMPRINT_get_algo(self.as_ptr())) }
    }

    pub fn get_msg(&self) -> &Asn1OctetStringRef {
        unsafe { Asn1OctetStringRef::from_ptr(ffi::TS_MSG_IMPRINT_get_msg(self.as_ptr())) }
    }
}

impl TsMessageImprint {
    from_der! {
        /// Serializes this TstInfo using DER.
        #[corresponds(d2i_TS_MSG_IMPRINT)]
        from_der,
        TsMessageImprint,
        ffi::d2i_TS_MSG_IMPRINT
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::TS_ACCURACY;
    fn drop = ffi::TS_ACCURACY_free;

    /// High level TS_ACCURACY wrapper
    ///
    /// Accuracy represents the time deviation around the genTime.
    ///
    /// [`RFC 3161`]: https://tools.ietf.org/html/rfc3161#page-9
    pub struct TsAccuracy;
    /// Reference to [`TsAccuracy`]
    ///
    /// [`TsAccuracy`]:struct.TsAccuracy.html
    pub struct TsAccuracyRef;
}

impl TsAccuracyRef {
    pub fn get_seconds(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let inner = ffi::TS_ACCURACY_get_seconds(self.as_ptr());
            if inner.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(inner as *mut _))
            }
        }
    }

    pub fn get_millis(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let inner = ffi::TS_ACCURACY_get_millis(self.as_ptr());
            if inner.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(inner as *mut _))
            }
        }
    }

    pub fn get_micros(&self) -> Option<&Asn1IntegerRef> {
        unsafe {
            let inner = ffi::TS_ACCURACY_get_micros(self.as_ptr());
            if inner.is_null() {
                None
            } else {
                Some(Asn1IntegerRef::from_ptr(inner as *mut _))
            }
        }
    }
}

impl TsAccuracy {
    from_der! {
        /// Serializes this TstInfo using DER.
        #[corresponds(d2i_TS_ACCURACY)]
        from_der,
        TsAccuracy,
        ffi::d2i_TS_ACCURACY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs7::Pkcs7;
    const RFC3161_DATA: &'static [u8] = include_bytes!("../test/sample_rfc3161_cms.der");
    const TST_INFO: &'static [u8] = include_bytes!("../test/tst_info.der");

    #[test]
    fn test_from_pkcs7() {
        let pkcs7 = Pkcs7::from_der(RFC3161_DATA).unwrap();
        TsTstInfo::from_pkcs7(&pkcs7).unwrap();
    }

    #[test]
    fn test_from_der_to_der() {
        let tst_info = TsTstInfo::from_der(TST_INFO).unwrap();
        let der = tst_info.to_der().unwrap();
        assert_eq!(TST_INFO, der);
    }

    #[test]
    fn test_accuracy() {
        let tst_info = TsTstInfo::from_der(TST_INFO).unwrap();
        let acc = tst_info.get_accuracy().unwrap();

        if let Some(Ok(str)) = acc
            .get_seconds()
            .map(|i| i.to_bn().map(|bn| bn.to_string()))
        {
            assert_eq!(str, "1");
        } else {
            panic!("incorrect");
        }
        assert!(acc.get_millis().is_none());
        assert!(acc.get_micros().is_none());
    }

    #[test]
    fn test_message_imprint() {
        let tst_info = TsTstInfo::from_der(TST_INFO).unwrap();
        let msg_imprint = tst_info.get_msg_imprint();

        let algo = msg_imprint.get_algo();
        let msg = msg_imprint.get_msg();

        assert_eq!("sha256", algo.object().nid().long_name().unwrap());
        assert!(msg.as_slice().len() > 0);
    }
}
