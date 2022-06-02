use libc::*;

pub enum TS_MSG_IMPRINT {}
pub enum TS_REQ {}
pub enum TS_ACCURACY {}
pub enum TS_TST_INFO {}

pub enum TS_STATUS_INFO {}
pub enum ESS_ISSUER_SERIAL {}
pub enum ESS_CERT_ID {}
pub enum ESS_SIGNING_CERT {}

stack!(stack_st_ESS_CERT_ID);

pub enum ESS_CERT_ID_V2 {}
pub enum ESS_SIGNING_CERT_V2 {}

stack!(stack_st_ESS_CERT_ID_V2);

pub enum TS_VERIFY_CTX {}
pub enum TS_RESP_CTX {}
pub enum TS_RESP {}

const_ptr_api! {
    extern "C" {
        pub fn TS_TST_INFO_dup(a: #[const_ptr_if(ossl300)] TS_TST_INFO) -> *mut TS_TST_INFO;
        pub fn TS_MSG_IMPRINT_dup(a: #[const_ptr_if(ossl300)] TS_MSG_IMPRINT) -> *mut TS_MSG_IMPRINT;
        pub fn TS_ACCURACY_dup(a: #[const_ptr_if(ossl300)] TS_ACCURACY) -> *mut TS_ACCURACY;
        pub fn TS_REQ_dup(a:#[const_ptr_if(ossl300)] TS_REQ) -> *mut TS_REQ;
        pub fn TS_RESP_dup(a: #[const_ptr_if(ossl300)] TS_RESP) -> *mut TS_RESP;
        pub fn TS_STATUS_INFO_dup(a: #[const_ptr_if(ossl300)] TS_STATUS_INFO) -> *mut TS_STATUS_INFO;
        pub fn ESS_ISSUER_SERIAL_dup(a: #[const_ptr_if(ossl300)] ESS_ISSUER_SERIAL) -> *mut ESS_ISSUER_SERIAL;
        pub fn ESS_CERT_ID_dup(a: #[const_ptr_if(ossl300)] ESS_CERT_ID) -> *mut ESS_CERT_ID;
        pub fn ESS_SIGNING_CERT_dup(a: #[const_ptr_if(ossl300)] ESS_SIGNING_CERT) -> *mut ESS_SIGNING_CERT;
        pub fn ESS_SIGNING_CERT_V2_dup(a: #[const_ptr_if(ossl300)] ESS_SIGNING_CERT_V2) -> *mut ESS_SIGNING_CERT_V2;
        pub fn ESS_CERT_ID_V2_dup(a: #[const_ptr_if(ossl300)] ESS_CERT_ID_V2) -> *mut ESS_CERT_ID_V2;
    }
}

cfg_if! {
    if #[cfg(not(osslconf = "OPENSSL_NO_STDIO"))] {
        extern "C" {
            pub fn d2i_TS_REQ_fp(fp: *mut FILE, a: *mut *mut TS_REQ) -> *mut TS_REQ;
            pub fn i2d_TS_REQ_fp(fp: *mut FILE, a: *mut TS_REQ) -> c_int;

            pub fn d2i_TS_MSG_IMPRINT_fp(fp: *mut FILE, a: *mut *mut TS_MSG_IMPRINT)
                -> *mut TS_MSG_IMPRINT;
            pub fn i2d_TS_MSG_IMPRINT_fp(fp: *mut FILE, a: *mut TS_MSG_IMPRINT) -> c_int;

            pub fn d2i_TS_RESP_fp(fp: *mut FILE, a: *mut *mut TS_RESP) -> *mut TS_RESP;
            pub fn i2d_TS_RESP_fp(fp: *mut FILE, a: *mut TS_RESP) -> c_int;

            pub fn d2i_TS_TST_INFO_fp(fp: *mut FILE, a: *mut *mut TS_TST_INFO) -> *mut TS_TST_INFO;
            pub fn i2d_TS_TST_INFO_fp(fp: *mut FILE, a: *mut TS_TST_INFO) -> c_int;
        }
    }
}

extern "C" {
    pub fn TS_REQ_new() -> *mut TS_REQ;
    pub fn TS_REQ_free(a: *mut TS_REQ);
    pub fn i2d_TS_REQ(a: *const TS_REQ, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_REQ(a: *mut *mut TS_REQ, pp: *mut *const c_uchar, length: c_long) -> *mut TS_REQ;

    pub fn d2i_TS_REQ_bio(fp: *mut ::BIO, a: *mut *mut TS_REQ) -> *mut TS_REQ;
    pub fn i2d_TS_REQ_bio(fp: *mut ::BIO, a: *mut TS_REQ) -> c_int;
    pub fn TS_MSG_IMPRINT_new() -> *mut TS_MSG_IMPRINT;
    pub fn TS_MSG_IMPRINT_free(a: *mut TS_MSG_IMPRINT);
    pub fn i2d_TS_MSG_IMPRINT(a: *const TS_MSG_IMPRINT, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_MSG_IMPRINT(
        a: *mut *mut TS_MSG_IMPRINT,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut TS_MSG_IMPRINT;

    pub fn d2i_TS_MSG_IMPRINT_bio(
        bio: *mut ::BIO,
        a: *mut *mut TS_MSG_IMPRINT,
    ) -> *mut TS_MSG_IMPRINT;

    pub fn i2d_TS_MSG_IMPRINT_bio(bio: *mut ::BIO, a: *mut TS_MSG_IMPRINT) -> c_int;

    pub fn TS_RESP_new() -> *mut TS_RESP;
    pub fn TS_RESP_free(a: *mut TS_RESP);
    pub fn i2d_TS_RESP(a: *const TS_RESP, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_RESP(
        a: *mut *mut TS_RESP,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut TS_RESP;

    pub fn PKCS7_to_TS_TST_INFO(token: *mut ::PKCS7) -> *mut TS_TST_INFO;

    pub fn d2i_TS_RESP_bio(bio: *mut ::BIO, a: *mut *mut TS_RESP) -> *mut TS_RESP;
    pub fn i2d_TS_RESP_bio(bio: *mut ::BIO, a: *mut TS_RESP) -> c_int;

    pub fn TS_STATUS_INFO_new() -> *mut TS_STATUS_INFO;
    pub fn TS_STATUS_INFO_free(a: *mut TS_STATUS_INFO);
    pub fn i2d_TS_STATUS_INFO(a: *const TS_STATUS_INFO, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_STATUS_INFO(
        a: *mut *mut TS_STATUS_INFO,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut TS_STATUS_INFO;

    pub fn TS_TST_INFO_new() -> *mut TS_TST_INFO;
    pub fn TS_TST_INFO_free(a: *mut TS_TST_INFO);
    pub fn i2d_TS_TST_INFO(a: *const TS_TST_INFO, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_TST_INFO(
        a: *mut *mut TS_TST_INFO,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut TS_TST_INFO;
    pub fn d2i_TS_TST_INFO_bio(bio: *mut ::BIO, a: *mut *mut TS_TST_INFO) -> *mut TS_TST_INFO;
    pub fn i2d_TS_TST_INFO_bio(bio: *mut ::BIO, a: *mut TS_TST_INFO) -> c_int;

    pub fn TS_ACCURACY_new() -> *mut TS_ACCURACY;
    pub fn TS_ACCURACY_free(a: *mut TS_ACCURACY);
    pub fn i2d_TS_ACCURACY(a: *const TS_ACCURACY, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_TS_ACCURACY(
        a: *mut *mut TS_ACCURACY,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut TS_ACCURACY;

    pub fn ESS_ISSUER_SERIAL_new() -> *mut ESS_ISSUER_SERIAL;
    pub fn ESS_ISSUER_SERIAL_free(a: *mut ESS_ISSUER_SERIAL);
    pub fn i2d_ESS_ISSUER_SERIAL(a: *const ESS_ISSUER_SERIAL, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_ESS_ISSUER_SERIAL(
        a: *mut *mut ESS_ISSUER_SERIAL,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ESS_ISSUER_SERIAL;

    pub fn ESS_CERT_ID_new() -> *mut ESS_CERT_ID;
    pub fn ESS_CERT_ID_free(a: *mut ESS_CERT_ID);
    pub fn i2d_ESS_CERT_ID(a: *const ESS_CERT_ID, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_ESS_CERT_ID(
        a: *mut *mut ESS_CERT_ID,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ESS_CERT_ID;

    pub fn ESS_SIGNING_CERT_new() -> *mut ESS_SIGNING_CERT;
    pub fn ESS_SIGNING_CERT_free(a: *mut ESS_SIGNING_CERT);
    pub fn i2d_ESS_SIGNING_CERT(a: *const ESS_SIGNING_CERT, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_ESS_SIGNING_CERT(
        a: *mut *mut ESS_SIGNING_CERT,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ESS_SIGNING_CERT;

    pub fn ESS_CERT_ID_V2_new() -> *mut ESS_CERT_ID_V2;
    pub fn ESS_CERT_ID_V2_free(a: *mut ESS_CERT_ID_V2);
    pub fn i2d_ESS_CERT_ID_V2(a: *const ESS_CERT_ID_V2, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_ESS_CERT_ID_V2(
        a: *mut *mut ESS_CERT_ID_V2,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ESS_CERT_ID_V2;

    pub fn ESS_SIGNING_CERT_V2_new() -> *mut ESS_SIGNING_CERT_V2;
    pub fn ESS_SIGNING_CERT_V2_free(a: *mut ESS_SIGNING_CERT_V2);
    pub fn i2d_ESS_SIGNING_CERT_V2(a: *const ESS_SIGNING_CERT_V2, pp: *mut *mut c_uchar) -> c_int;
    pub fn d2i_ESS_SIGNING_CERT_V2(
        a: *mut *mut ESS_SIGNING_CERT_V2,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut ESS_SIGNING_CERT_V2;

    pub fn TS_REQ_set_version(a: *mut TS_REQ, version: c_long) -> c_int;
    pub fn TS_REQ_get_version(a: *const TS_REQ) -> c_long;

    pub fn TS_STATUS_INFO_set_status(a: *mut TS_STATUS_INFO, i: c_int) -> c_int;
    pub fn TS_STATUS_INFO_get0_status(a: *const TS_STATUS_INFO) -> *const ::ASN1_INTEGER;
    pub fn TS_STATUS_INFO_get0_text(a: *const TS_STATUS_INFO) -> *const ::stack_st_ASN1_UTF8STRING;
    pub fn TS_STATUS_INFO_get0_failure_info(a: *const TS_STATUS_INFO) -> *const ::ASN1_BIT_STRING;

    pub fn TS_REQ_set_msg_imprint(a: *mut TS_REQ, msg_imprint: *mut TS_MSG_IMPRINT) -> c_int;
    pub fn TS_REQ_get_msg_imprint(a: *mut TS_REQ) -> *mut TS_MSG_IMPRINT;

    pub fn TS_MSG_IMPRINT_set_algo(a: *mut TS_MSG_IMPRINT, alg: *mut ::X509_ALGOR) -> c_int;
    pub fn TS_MSG_IMPRINT_get_algo(a: *mut TS_MSG_IMPRINT) -> *mut ::X509_ALGOR;
    pub fn TS_MSG_IMPRINT_set_msg(a: *mut TS_MSG_IMPRINT, d: *mut c_uchar, len: c_int) -> c_int;
    pub fn TS_MSG_IMPRINT_get_msg(a: *mut TS_MSG_IMPRINT) -> *mut ::ASN1_OCTET_STRING;

    pub fn TS_REQ_set_policy_id(a: *mut TS_REQ, policy: *const ::ASN1_OBJECT) -> c_int;
    pub fn TS_REQ_get_policy_id(a: *mut TS_REQ) -> *mut ::ASN1_OBJECT;
    pub fn TS_REQ_set_nonce(a: *mut TS_REQ, nonce: *const ::ASN1_INTEGER) -> c_int;
    pub fn TS_REQ_get_nonce(a: *const TS_REQ) -> *const ::ASN1_INTEGER;
    pub fn TS_REQ_set_cert_req(a: *mut TS_REQ, cert_req: c_int) -> c_int;
    pub fn TS_REQ_get_cert_req(a: *const TS_REQ) -> c_int;
    pub fn TS_REQ_get_exts(a: *mut TS_REQ) -> *mut ::stack_st_X509_EXTENSION;
    pub fn TS_REQ_ext_free(a: *mut TS_REQ);
    pub fn TS_REQ_get_ext_count(a: *mut TS_REQ) -> c_int;
    pub fn TS_REQ_get_ext_by_NID(a: *mut TS_REQ, nid: c_int, lastpos: c_int) -> c_int;
    pub fn TS_REQ_get_ext_by_OBJ(
        a: *mut TS_REQ,
        obj: *const ::ASN1_OBJECT,
        lastpos: c_int,
    ) -> c_int;
    pub fn TS_REQ_get_ext_by_critical(a: *mut TS_REQ, crit: c_int, lastpos: c_int) -> c_int;
    pub fn TS_REQ_get_ext(a: *mut TS_REQ, loc: c_int) -> *mut ::X509_EXTENSION;
    pub fn TS_REQ_delete_ext(a: *mut TS_REQ, loc: c_int) -> *mut ::X509_EXTENSION;
    pub fn TS_REQ_add_ext(a: *mut TS_REQ, ex: *mut ::X509_EXTENSION, loc: c_int) -> c_int;
    pub fn TS_REQ_get_ext_d2i(
        a: *mut TS_REQ,
        nid: c_int,
        crit: *mut c_int,
        idx: *mut c_int,
    ) -> *mut c_void;
    pub fn TS_REQ_print_bio(bio: *mut ::BIO, a: *mut TS_REQ) -> c_int;

    pub fn TS_RESP_set_status_info(a: *mut TS_RESP, info: *mut TS_STATUS_INFO) -> c_int;
    pub fn TS_RESP_get_status_info(a: *mut TS_RESP) -> *mut TS_STATUS_INFO;
    pub fn TS_RESP_set_tst_info(a: *mut TS_RESP, p7: *mut ::PKCS7, tst_info: *mut TS_TST_INFO);
    pub fn TS_RESP_get_token(a: *mut TS_RESP) -> *mut ::PKCS7;
    pub fn TS_RESP_get_tst_info(a: *mut TS_RESP) -> *mut TS_TST_INFO;

    pub fn TS_TST_INFO_set_version(a: *mut TS_TST_INFO, version: c_long) -> c_int;
    pub fn TS_TST_INFO_get_version(a: *const TS_TST_INFO) -> c_long;
    pub fn TS_TST_INFO_set_policy_id(a: *mut TS_TST_INFO, policy_id: *mut ::ASN1_OBJECT) -> c_int;
    pub fn TS_TST_INFO_get_policy_id(a: *mut TS_TST_INFO) -> *mut ::ASN1_OBJECT;
    pub fn TS_TST_INFO_set_msg_imprint(
        a: *mut TS_TST_INFO,
        msg_imprint: *mut TS_MSG_IMPRINT,
    ) -> c_int;
    pub fn TS_TST_INFO_get_msg_imprint(a: *mut TS_TST_INFO) -> *mut TS_MSG_IMPRINT;
    pub fn TS_TST_INFO_set_serial(a: *mut TS_TST_INFO, serial: *const ::ASN1_INTEGER) -> c_int;
    pub fn TS_TST_INFO_get_serial(a: *const TS_TST_INFO) -> *const ::ASN1_INTEGER;
    pub fn TS_TST_INFO_set_time(a: *mut TS_TST_INFO, gtime: *const ::ASN1_GENERALIZEDTIME)
        -> c_int;
    pub fn TS_TST_INFO_get_time(a: *const TS_TST_INFO) -> *const ::ASN1_GENERALIZEDTIME;
    pub fn TS_TST_INFO_set_accuracy(a: *mut TS_TST_INFO, accuracy: *mut TS_ACCURACY) -> c_int;
    pub fn TS_TST_INFO_get_accuracy(a: *mut TS_TST_INFO) -> *mut TS_ACCURACY;

    pub fn TS_ACCURACY_set_seconds(a: *mut TS_ACCURACY, seconds: *const ::ASN1_INTEGER) -> c_int;
    pub fn TS_ACCURACY_get_seconds(a: *const TS_ACCURACY) -> *const ::ASN1_INTEGER;
    pub fn TS_ACCURACY_set_millis(a: *mut TS_ACCURACY, millis: *const ::ASN1_INTEGER) -> c_int;
    pub fn TS_ACCURACY_get_millis(a: *const TS_ACCURACY) -> *const ::ASN1_INTEGER;
    pub fn TS_ACCURACY_set_micros(a: *mut TS_ACCURACY, micros: *const ::ASN1_INTEGER) -> c_int;
    pub fn TS_ACCURACY_get_micros(a: *const TS_ACCURACY) -> *const ::ASN1_INTEGER;

    pub fn TS_TST_INFO_set_ordering(a: *mut TS_TST_INFO, ordering: c_int) -> c_int;
    pub fn TS_TST_INFO_get_ordering(a: *const TS_TST_INFO) -> c_int;
    pub fn TS_TST_INFO_set_nonce(a: *mut TS_TST_INFO, nonce: *const ::ASN1_INTEGER) -> c_int;
    pub fn TS_TST_INFO_get_nonce(a: *const TS_TST_INFO) -> *const ::ASN1_INTEGER;
    pub fn TS_TST_INFO_set_tsa(a: *mut TS_TST_INFO, tsa: *mut ::GENERAL_NAME) -> c_int;
    pub fn TS_TST_INFO_get_tsa(a: *mut TS_TST_INFO) -> *mut ::GENERAL_NAME;
    pub fn TS_TST_INFO_get_exts(a: *mut TS_TST_INFO) -> *mut ::stack_st_X509_EXTENSION;
    pub fn TS_TST_INFO_ext_free(a: *mut TS_TST_INFO);
    pub fn TS_TST_INFO_get_ext_count(a: *mut TS_TST_INFO) -> c_int;
    pub fn TS_TST_INFO_get_ext_by_NID(a: *mut TS_TST_INFO, nid: c_int, lastpos: c_int) -> c_int;
    pub fn TS_TST_INFO_get_ext_by_OBJ(
        a: *mut TS_TST_INFO,
        obj: *const ::ASN1_OBJECT,
        lastpos: c_int,
    ) -> c_int;
    pub fn TS_TST_INFO_get_ext_by_critical(
        a: *mut TS_TST_INFO,
        crit: c_int,
        lastpos: c_int,
    ) -> c_int;
    pub fn TS_TST_INFO_get_ext(a: *mut TS_TST_INFO, loc: c_int) -> *mut ::X509_EXTENSION;
    pub fn TS_TST_INFO_delete_ext(a: *mut TS_TST_INFO, loc: c_int) -> *mut ::X509_EXTENSION;
    pub fn TS_TST_INFO_add_ext(a: *mut TS_TST_INFO, ex: *mut ::X509_EXTENSION, loc: c_int)
        -> c_int;
    pub fn TS_TST_INFO_get_ext_d2i(
        a: *mut TS_TST_INFO,
        nid: c_int,
        crit: *mut c_int,
        idx: *mut c_int,
    ) -> *mut c_void;

    pub fn TS_RESP_CTX_new() -> *mut TS_RESP_CTX;
    pub fn TS_RESP_CTX_free(ctx: *mut TS_RESP_CTX);
    pub fn TS_RESP_CTX_set_signer_cert(ctx: *mut TS_RESP_CTX, signer: *mut ::X509) -> c_int;
    pub fn TS_RESP_CTX_set_signer_key(ctx: *mut TS_RESP_CTX, key: *mut ::EVP_PKEY) -> c_int;
    pub fn TS_RESP_CTX_set_signer_digest(
        ctx: *mut TS_RESP_CTX,
        signer_digest: *const ::EVP_MD,
    ) -> c_int;
    pub fn TS_RESP_CTX_set_ess_cert_id_digest(ctx: *mut TS_RESP_CTX, md: *const ::EVP_MD) -> c_int;
    pub fn TS_RESP_CTX_set_def_policy(
        ctx: *mut TS_RESP_CTX,
        def_policy: *const ::ASN1_OBJECT,
    ) -> c_int;
    pub fn TS_RESP_CTX_set_certs(ctx: *mut TS_RESP_CTX, certs: *mut ::stack_st_X509) -> c_int;
    pub fn TS_RESP_CTX_add_policy(ctx: *mut TS_RESP_CTX, policy: *const ::ASN1_OBJECT) -> c_int;
    pub fn TS_RESP_CTX_add_md(ctx: *mut TS_RESP_CTX, md: *const ::EVP_MD) -> c_int;
    pub fn TS_RESP_CTX_set_accuracy(
        ctx: *mut TS_RESP_CTX,
        secs: c_int,
        millis: c_int,
        micros: c_int,
    ) -> c_int;
    pub fn TS_RESP_CTX_set_clock_precision_digits(
        ctx: *mut TS_RESP_CTX,
        clock_precision_digits: c_uint,
    ) -> c_int;
    pub fn TS_RESP_CTX_add_flags(ctx: *mut TS_RESP_CTX, flags: c_int);
    pub fn TS_RESP_CTX_set_serial_cb(ctx: *mut TS_RESP_CTX, cb: TS_serial_cb, data: *mut c_void);
    pub fn TS_RESP_CTX_set_time_cb(ctx: *mut TS_RESP_CTX, cb: TS_time_cb, data: *mut c_void);
    pub fn TS_RESP_CTX_set_extension_cb(
        ctx: *mut TS_RESP_CTX,
        cb: TS_extension_cb,
        data: *mut c_void,
    );
    pub fn TS_RESP_CTX_set_status_info(
        ctx: *mut TS_RESP_CTX,
        status: c_int,
        text: *const c_char,
    ) -> c_int;
    pub fn TS_RESP_CTX_set_status_info_cond(
        ctx: *mut TS_RESP_CTX,
        status: c_int,
        text: *const c_char,
    ) -> c_int;
    pub fn TS_RESP_CTX_add_failure_info(ctx: *mut TS_RESP_CTX, failure: c_int) -> c_int;
    pub fn TS_RESP_CTX_get_request(ctx: *mut TS_RESP_CTX) -> *mut TS_REQ;
    pub fn TS_RESP_CTX_get_tst_info(ctx: *mut TS_RESP_CTX) -> *mut TS_TST_INFO;
    pub fn TS_RESP_create_response(ctx: *mut TS_RESP_CTX, req_bio: *mut ::BIO) -> *mut TS_RESP;
    pub fn TS_RESP_verify_signature(
        token: *mut ::PKCS7,
        certs: *mut ::stack_st_X509,
        store: *mut ::X509_STORE,
        signer_out: *mut *mut ::X509,
    ) -> c_int;
    pub fn TS_RESP_verify_response(ctx: *mut TS_VERIFY_CTX, response: *mut TS_RESP) -> c_int;
    pub fn TS_RESP_verify_token(ctx: *mut TS_VERIFY_CTX, token: *mut ::PKCS7) -> c_int;

    pub fn TS_VERIFY_CTX_new() -> *mut TS_VERIFY_CTX;
    pub fn TS_VERIFY_CTX_init(ctx: *mut TS_VERIFY_CTX);
    pub fn TS_VERIFY_CTX_free(ctx: *mut TS_VERIFY_CTX);
    pub fn TS_VERIFY_CTX_cleanup(ctx: *mut TS_VERIFY_CTX);
    pub fn TS_VERIFY_CTX_set_flags(ctx: *mut TS_VERIFY_CTX, f: c_int) -> c_int;
    pub fn TS_VERIFY_CTX_add_flags(ctx: *mut TS_VERIFY_CTX, f: c_int) -> c_int;
    pub fn TS_VERIFY_CTX_set_data(ctx: *mut TS_VERIFY_CTX, b: *mut ::BIO) -> *mut ::BIO;
    pub fn TS_VERIFY_CTX_set_imprint(
        ctx: *mut TS_VERIFY_CTX,
        hexstr: *mut c_uchar,
        len: c_long,
    ) -> *mut c_uchar;
    pub fn TS_VERIFY_CTX_set_store(
        ctx: *mut TS_VERIFY_CTX,
        s: *mut ::X509_STORE,
    ) -> *mut ::X509_STORE;
    pub fn TS_VERIFY_CTS_set_certs(
        ctx: *mut TS_VERIFY_CTX,
        certs: *mut ::stack_st_X509,
    ) -> *mut ::stack_st_X509;

    pub fn TS_REQ_to_TS_VERIFY_CTX(req: *mut TS_REQ, ctx: *mut TS_VERIFY_CTX)
        -> *mut TS_VERIFY_CTX;

    pub fn TS_RESP_print_bio(bio: *mut ::BIO, a: *mut TS_RESP) -> c_int;

    pub fn TS_STATUS_INFO_print_bio(bio: *mut ::BIO, a: *mut TS_STATUS_INFO) -> c_int;

    pub fn TS_TST_INFO_print_bio(bio: *mut ::BIO, a: *mut TS_TST_INFO) -> c_int;

    pub fn TS_ASN1_INTEGER_print_bio(bio: *mut ::BIO, num: *const ::ASN1_INTEGER) -> c_int;

    pub fn TS_OBJ_print_bio(bio: *mut ::BIO, obj: *const ::ASN1_OBJECT) -> c_int;

    pub fn TS_ext_print_bio(bio: *mut ::BIO, extensions: *const ::stack_st_X509_EXTENSION)
        -> c_int;

    pub fn TS_X509_ALGOR_print_bio(bio: *mut ::BIO, alg: *const ::X509_ALGOR) -> c_int;

    pub fn TS_MSG_IMPRINT_print_bio(bio: *mut ::BIO, msg: *mut TS_MSG_IMPRINT) -> c_int;

    pub fn TS_CONF_load_cert(file: *const c_char) -> *mut ::X509;
    pub fn TS_CONF_load_certs(file: *const c_char) -> *mut ::stack_st_X509;
    pub fn TS_CONF_load_key(file: *const c_char, pass: *const c_char) -> *mut ::EVP_PKEY;
    pub fn TS_CONF_get_tsa_section(conf: *mut ::CONF, section: *const c_char) -> *const c_char;
    pub fn TS_CONF_set_serial(
        conf: *mut ::CONF,
        section: *const c_char,
        cb: TS_serial_cb,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_crypto_device(
        conf: *mut ::CONF,
        section: *const c_char,
        device: *const c_char,
    ) -> c_int;
    pub fn TS_CONF_set_default_engine(name: *const c_char) -> c_int;
    pub fn TS_CONF_set_signer_cert(
        conf: *mut ::CONF,
        section: *const c_char,
        cert: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_certs(
        conf: *mut ::CONF,
        section: *const c_char,
        certs: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_signer_key(
        conf: *mut ::CONF,
        section: *const c_char,
        key: *const c_char,
        pass: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_signer_digest(
        conf: *mut ::CONF,
        section: *const c_char,
        md: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_def_policy(
        conf: *mut ::CONF,
        section: *const c_char,
        policy: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_policies(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_digests(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_accuracy(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_clock_precision_digits(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_ordering(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_tsa_name(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_ess_cert_id_chain(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
    pub fn TS_CONF_set_ess_cert_id_digest(
        conf: *mut ::CONF,
        section: *const c_char,
        ctx: *mut TS_RESP_CTX,
    ) -> c_int;
}

pub type TS_serial_cb = ::std::option::Option<
    unsafe extern "C" fn(arg1: *mut TS_RESP_CTX, arg2: *mut c_void) -> *mut ::ASN1_INTEGER,
>;
pub type TS_time_cb = ::std::option::Option<
    unsafe extern "C" fn(
        arg1: *mut TS_RESP_CTX,
        arg2: *mut c_void,
        sec: *mut c_long,
        usec: *mut c_long,
    ) -> c_int,
>;
pub type TS_extension_cb = ::std::option::Option<
    unsafe extern "C" fn(
        arg1: *mut TS_RESP_CTX,
        arg2: *mut ::X509_EXTENSION,
        arg3: *mut c_void,
    ) -> c_int,
>;

pub type sk_EVP_MD_compfunc = ::std::option::Option<
    unsafe extern "C" fn(a: *const *const ::EVP_MD, b: *const *const ::EVP_MD) -> c_int,
>;
pub type sk_EVP_MD_freefunc = ::std::option::Option<unsafe extern "C" fn(a: *mut ::EVP_MD)>;
pub type sk_EVP_MD_copyfunc =
    ::std::option::Option<unsafe extern "C" fn(a: *const ::EVP_MD) -> *mut ::EVP_MD>;
