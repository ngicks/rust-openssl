use crate::cvt_p;
use crate::error::ErrorStack;
use crate::lib_ctx::LibCtxRef;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::ffi::CString;
use std::{mem, ptr};

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_PROVIDER;
    fn drop = ossl_provider_free;

    pub struct Provider;
    /// A reference to a [`Provider`].
    pub struct ProviderRef;
}

#[inline]
unsafe fn ossl_provider_free(p: *mut ffi::OSSL_PROVIDER) {
    ffi::OSSL_PROVIDER_unload(p);
}

impl Provider {
    /// Loads a new provider into the specified library context, disabling the fallback providers.
    ///
    /// If `ctx` is `None`, the provider will be loaded in to the default library context.
    ///
    /// This corresponds to the [`OSSL_provider_load`] function.
    ///
    /// [`OSSL_provider_load`]: https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER_load.html
    pub fn load(ctx: Option<&LibCtxRef>, name: &str) -> Result<Self, ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            let p = cvt_p(ffi::OSSL_PROVIDER_load(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                name.as_ptr(),
            ))?;

            Ok(Provider::from_ptr(p))
        }
    }

    /// Loads a new provider into the specified library context, disabling the fallback providers if `retain_fallbacks`
    /// is `false` and the load succeeds.
    ///
    /// If `ctx` is `None`, the provider will be loaded into the default library context.
    ///
    /// This corresponds to the [`OSSL_provider_try_load`] function.
    ///
    /// [`OSSL_provider_try_load`]: https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER_try_load.html
    pub fn try_load(
        ctx: Option<&LibCtxRef>,
        name: &str,
        retain_fallbacks: bool,
    ) -> Result<Self, ErrorStack> {
        let name = CString::new(name).unwrap();
        unsafe {
            let p = cvt_p(ffi::OSSL_PROVIDER_try_load(
                ctx.map_or(ptr::null_mut(), ForeignTypeRef::as_ptr),
                name.as_ptr(),
                retain_fallbacks as _,
            ))?;

            Ok(Provider::from_ptr(p))
        }
    }

    /// "Leaks" this provider handle, preventing it from being closed.
    ///
    /// By default, the provider will be closed when its [`Provider`] handle drops. If you instead want the provider to
    /// be active for the remaining duration of the program, you should call this method.
    pub fn leak(self) {
        mem::forget(self);
    }
}
