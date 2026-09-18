//! Simple crate for hiding secrets.
//!
//! Allows you to create immutable secrets, which can be exposed, and are
//! zeroïzed on drop.  This crate ensures (where possible) that you don't move
//! or print your secrets, as moving a value can result in a non-zeroïzed copy
//! left on the stack!
//!
//! Usages of the [`SecretRef::expose()`] method should be all you need to audit
//! to prove you're not leaking secrets as long as you make sure not to call
//! [`SecretBuf::with_default()`] with a secret!
//!
//! # Scope
//!
//! This crate does not cover memory protection from outside processes with
//! memory access priviledges.
//!
//! # Examples
//!
//! ## Pinned To The Stack
//!
//! ```rust
//! # use std::{io::Write, ops::Deref, pin::{Pin, pin}};
//! use hiding::{SecretBuf, SecretRef};
//!
//! let mut secret_buf = pin!(SecretBuf::with_default([0; 128]));
//! let secret_ref = secret_buf.as_mut()
//!     .store_secret(|buf: Pin<&mut [u8; 128]>| {
//!         // In practice this would be some kind of decryption
//!         write!(buf.get_mut().as_mut_slice(), "Hello, world!").unwrap();
//!     });
//!
//! // Expose the secret, should be what we "decrypted"
//! assert_eq!(&secret_ref.expose()[..13], "Hello, world!".as_bytes());
//!
//! // Dropping the ref zeroïzes the buffer
//! drop(secret_ref);
//! assert!(secret_buf.as_ref().into_iter().all(|x| x == 0));
//! ```
//!
//! ## Pinned To The Heap
//!
//! ```rust
//! # use std::{io::Write, ops::Deref, pin::Pin};
//! use hiding::{SecretBuf, SecretRef, Secret};
//!
//! let secret = Secret::with_default(
//!     [0; 128],
//!     |buf: Pin<&mut [u8; 128]>| {
//!         // In practice this would be some kind of decryption
//!         write!(buf.get_mut().as_mut_slice(), "Hello, world!").unwrap();
//!     },
//! );
//!
//! // Can acquire the ref as many times as needed
//! for _ in 0..2 {
//!     // Expose the secret, should be what we "decrypted"
//!     assert_eq!(&secret.get_ref().expose()[..13], "Hello, world!".as_bytes());
//! }
//! ```

#![doc(
    html_logo_url = "https://ardaku.github.io/mm/logo.svg",
    html_favicon_url = "https://ardaku.github.io/mm/icon.svg"
)]
#![no_std]
#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_qualifications,
    variant_size_differences
)]
#![deny(
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::missing_crate_level_docs,
    rustdoc::private_doc_tests,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::invalid_rust_codeblocks,
    rustdoc::bare_urls,
    rustdoc::unescaped_backticks,
    rustdoc::redundant_explicit_links
)]

#[cfg(feature = "alloc")]
extern crate alloc;

use core::{
    fmt,
    ops::{Deref, DerefMut},
    pin::Pin,
};

use zeroize::Zeroize;

/// Buffer used to store secrets
///
/// If you can access an instance of this type, you cannot access the secrets
/// that it used to contain.
#[repr(transparent)]
#[derive(Debug, Default)]
pub struct SecretBuf<T>(T)
where
    T: Zeroize;

impl<T> SecretBuf<T>
where
    T: Zeroize + Default,
{
    /// Initialize the buffer to [`Default::default()`].
    #[inline(always)]
    pub fn new() -> Self {
        Default::default()
    }
}

impl<T> SecretBuf<T>
where
    T: Zeroize,
{
    /// Initialize the buffer to the provided default.
    ///
    /// # Warning!
    ///
    /// Do not put secrets in `default` - The value here is not guaranteed to be
    /// zeroïzed!
    #[inline(always)]
    pub fn with_default(default: T) -> Self {
        Self(default)
    }

    /// Create a new immutable secret.
    ///
    /// # Warning!
    ///
    /// Secrets should be decrypted directly into the pinned buffer provided by
    /// the closure.  Failure to do so may result in secrets being left in
    /// memory after the types are dropped.
    #[inline(always)]
    pub fn store_secret<'a>(
        mut self: Pin<&'a mut Self>,
        f: impl FnOnce(Pin<&mut T>),
    ) -> SecretRef<'a, T>
    where
        T: Unpin,
    {
        f(unsafe {
            core::mem::transmute::<Pin<&mut SecretBuf<T>>, Pin<&mut T>>(
                self.as_mut(),
            )
        });
        unsafe { core::mem::transmute(self) }
    }
}

impl<T> Deref for SecretBuf<T>
where
    T: Zeroize,
{
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for SecretBuf<T>
where
    T: Zeroize,
{
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// _**`alloc`**_: A secret held on the heap
#[cfg(feature = "alloc")]
#[repr(transparent)]
pub struct Secret<T>(Pin<alloc::boxed::Box<zeroize::Zeroizing<T>>>)
where
    T: Zeroize;

#[cfg(feature = "alloc")]
impl<T> Secret<T>
where
    T: Zeroize,
{
    /// Create a new secret from a buffer pinned on the heap, with the buffer
    /// initialized to [`Default::default()`].
    #[inline(always)]
    pub fn new(f: impl FnOnce(Pin<&mut T>)) -> Self
    where
        T: Default,
    {
        Self::with_buf(alloc::boxed::Box::pin(SecretBuf::new()), f)
    }

    /// Create a new secret from a buffer pinned on the heap, with the buffer
    /// initialized to the provided default.
    ///
    /// # Warning!
    ///
    /// Do not put secrets in `default` - The value here is not guaranteed to be
    /// zeroïzed!
    #[inline(always)]
    pub fn with_default(default: T, f: impl FnOnce(Pin<&mut T>)) -> Self {
        Self::with_buf(
            alloc::boxed::Box::pin(SecretBuf::with_default(default)),
            f,
        )
    }

    /// Create a new secret from a buffer pinned on the heap.
    #[inline(always)]
    pub fn with_buf(
        mut buf: Pin<alloc::boxed::Box<SecretBuf<T>>>,
        f: impl FnOnce(Pin<&mut T>),
    ) -> Self {
        let buf_ref: Pin<&mut SecretBuf<T>> = buf.as_mut();

        f(unsafe {
            core::mem::transmute::<Pin<&mut SecretBuf<T>>, Pin<&mut T>>(buf_ref)
        });
        unsafe { core::mem::transmute(buf) }
    }

    /// Get as a reference to a [`SecretRef`].
    #[inline(always)]
    pub fn get_ref<'a>(&'a self) -> &'a SecretRef<'a, T>
    where
        T: Unpin,
    {
        unsafe { core::mem::transmute(self) }
    }

    /// Extract the zeroïzed buffer out of the secret to be reüsed.
    pub fn into_buf(mut self) -> Pin<alloc::boxed::Box<SecretBuf<T>>>
    where
        T: Unpin,
    {
        self.0.as_mut().get_mut().zeroize();
        unsafe { core::mem::transmute(self) }
    }
}

#[cfg(feature = "alloc")]
impl<T> fmt::Debug for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug("Secret", f)
    }
}

/// A reference to an immutable secret
#[repr(transparent)]
pub struct SecretRef<'a, T>(Pin<&'a mut SecretBuf<T>>)
where
    T: Zeroize + Unpin;

impl<T> SecretRef<'_, T>
where
    T: Zeroize + Unpin,
{
    /// Borrow and expose the secret.
    #[inline(always)]
    pub fn expose(&self) -> &T {
        &self.0.0
    }
}

impl<T> fmt::Debug for SecretRef<'_, T>
where
    T: Zeroize + Unpin,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        debug("SecretRef", f)
    }
}

impl<T> Drop for SecretRef<'_, T>
where
    T: Zeroize + Unpin,
{
    #[inline(always)]
    fn drop(&mut self) {
        self.0.as_mut().get_mut().0.zeroize()
    }
}

fn debug(name: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple(name).field(&"REDACTED").finish()
}
