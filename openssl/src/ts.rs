use std::ptr;

use openssl_macros::corresponds;

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
}
