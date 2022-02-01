use libc::*;
use *;

pub enum CMS_ContentInfo {}
pub enum CMS_SignerInfo {}
pub enum CMS_CertificateChoices {}
pub enum CMS_RevocationInfoChoice {}
pub enum CMS_RecipientInfo {}
pub enum CMS_ReceiptRequest {}
pub enum CMS_Receipt {}
pub enum CMS_RecipientEncryptedKey {}
pub enum CMS_OtherKeyAttribute {}

stack!(stack_st_CMS_SignerInfo);
stack!(stack_st_CMS_RecipientEncryptedKey);
stack!(stack_st_CMS_RecipientInfo);
stack!(stack_st_CMS_RevocationInfoChoice);

extern "C" {
    #[cfg(ossl101)]
    pub fn CMS_ContentInfo_free(cms: *mut ::CMS_ContentInfo);
}

const_ptr_api! {
    extern "C" {
        #[cfg(ossl101)]
        pub fn i2d_CMS_ContentInfo(a: #[const_ptr_if(ossl300)] CMS_ContentInfo, pp: *mut *mut c_uchar) -> c_int;
    }
}

extern "C" {
    #[cfg(ossl101)]
    pub fn d2i_CMS_ContentInfo(
        a: *mut *mut ::CMS_ContentInfo,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ::CMS_ContentInfo;

    #[cfg(ossl101)]
    pub fn SMIME_read_CMS(bio: *mut ::BIO, bcont: *mut *mut ::BIO) -> *mut ::CMS_ContentInfo;

    #[cfg(ossl101)]
    pub fn CMS_sign(
        signcert: *mut ::X509,
        pkey: *mut ::EVP_PKEY,
        certs: *mut ::stack_st_X509,
        data: *mut ::BIO,
        flags: c_uint,
    ) -> *mut ::CMS_ContentInfo;

    #[cfg(ossl101)]
    pub fn CMS_encrypt(
        certs: *mut stack_st_X509,
        data: *mut ::BIO,
        cipher: *const EVP_CIPHER,
        flags: c_uint,
    ) -> *mut ::CMS_ContentInfo;

    #[cfg(ossl101)]
    pub fn CMS_decrypt(
        cms: *mut ::CMS_ContentInfo,
        pkey: *mut ::EVP_PKEY,
        cert: *mut ::X509,
        dcont: *mut ::BIO,
        out: *mut ::BIO,
        flags: c_uint,
    ) -> c_int;

    #[cfg(ossl101)]
    pub fn CMS_get1_certs(cms: *mut CMS_ContentInfo) -> *mut ::stack_st_X509;

    #[cfg(ossl101)]
    pub fn CMS_get0_SignerInfos(cms: *mut CMS_ContentInfo) -> *mut stack_st_CMS_SignerInfo;

    #[cfg(ossl101)]
    pub fn CMS_SignerInfo_get0_signer_id(
        si: *mut CMS_SignerInfo,
        keyid: *mut *mut ::ASN1_OCTET_STRING,
        issuer: *mut *mut ::X509_NAME,
        sno: *mut *mut ::ASN1_INTEGER,
    ) -> c_int;

    #[cfg(ossl101)]
    pub fn CMS_SignerInfo_get0_algs(
        si: *mut ::CMS_SignerInfo,
        pk: *mut *mut ::EVP_PKEY,
        signer: *mut *mut ::X509,
        pdig: *mut *mut ::X509_ALGOR,
        psig: *mut *mut ::X509_ALGOR,
    );

    #[cfg(ossl101)]
    pub fn CMS_SignerInfo_get0_signature(si: *mut CMS_SignerInfo) -> *mut ::ASN1_OCTET_STRING;

}
