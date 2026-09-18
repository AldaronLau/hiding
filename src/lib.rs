//! Simple crate for hiding secrets.
//!
//! Allows you to create immutable secrets, which can be exposed, and are
//! zeroized on drop.  This crate ensures (where possible) that you don't move
//! or print your secrets, as moving a value can result in a non-zeroized copy
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
//! // Dropping the ref zeroizes the buffer
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
//! let mut secret_buf = Box::pin(SecretBuf::with_default([0; 128]));
//! let mut secret = Secret::with_buf(
//!     secret_buf,
//!     |buf: Pin<&mut [u8; 128]>| {
//!         // In practice this would be some kind of decryption
//!         write!(buf.get_mut().as_mut_slice(), "Hello, world!").unwrap();
//!     },
//! );
//! let mut secret = secret.as_mut();
//!
//! // Can acquire the ref as many times as needed
//! for _ in 0..2 {
//!     let secret_ref = SecretRef::new(&mut secret);
//!
//!     // Expose the secret, should be what we "decrypted"
//!     assert_eq!(&secret_ref.expose()[..13], "Hello, world!".as_bytes());
//! }
//! ```

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

use core::{
    fmt,
    ops::{Deref, DerefMut},
    pin::Pin,
};

use zeroize::{Zeroize, Zeroizing};

/// Buffer used to store secrets
///
/// If you can access an instance of this type, you cannot access the secrets
/// that it used to contain.
#[repr(transparent)]
#[derive(Default)]
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
    /// zeroized!
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
        f(unsafe { core::mem::transmute(self.as_mut()) });
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

/// A secret held on the heap
#[repr(transparent)]
pub struct Secret<T>(Zeroizing<T>)
where
    T: Zeroize;

impl<T> Secret<T>
where
    T: Zeroize,
{
    /// _**`alloc`**_: Create a new secret from a buffer pinned on the heap.
    #[cfg(feature = "alloc")]
    #[inline(always)]
    pub fn new(f: impl FnOnce(Pin<&mut T>)) -> Pin<alloc::boxed::Box<Self>>
    where
        T: Default
    {
        Self::with_buf(alloc::boxed::Box::pin(SecretBuf::new()), f)
    }

    /// _**`alloc`**_: Create a new secret from a buffer pinned on the heap.
    ///
    /// # Warning!
    ///
    /// Do not put secrets in `default` - The value here is not guaranteed to be
    /// zeroized!
    #[cfg(feature = "alloc")]
    #[inline(always)]
    pub fn with_default(default: T, f: impl FnOnce(Pin<&mut T>)) -> Pin<alloc::boxed::Box<Self>>
    where
        T: Default
    {
        Self::with_buf(alloc::boxed::Box::pin(SecretBuf::with_default(default)), f)
    }

    /// _**`alloc`**_: Create a new secret from a buffer pinned on the heap.
    #[cfg(feature = "alloc")]
    #[inline(always)]
    pub fn with_buf(
        mut buf: Pin<alloc::boxed::Box<SecretBuf<T>>>,
        f: impl FnOnce(Pin<&mut T>),
    ) -> Pin<alloc::boxed::Box<Self>> {
        let buf_ref: Pin<&mut SecretBuf<T>> = buf.as_mut();

        f(unsafe { core::mem::transmute(buf_ref) });
        unsafe { core::mem::transmute(buf) }
    }
}

impl<T> fmt::Debug for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret").field(&"REDACTED").finish()
    }
}

/// A reference to an immutable secret
#[repr(transparent)]
pub struct SecretRef<'a, T>(Pin<&'a mut SecretBuf<T>>)
where
    T: Zeroize + Unpin;

impl<'a, T> SecretRef<'a, T>
where
    T: Zeroize + Unpin,
{
    /// Create a new reference to a secret.
    #[inline(always)]
    pub fn new<'b>(secret: &'b mut Pin<&'a mut Secret<T>>) -> &'b Self {
        unsafe { core::mem::transmute(secret) }
    }

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
        f.debug_tuple("SecretRef").field(&"REDACTED").finish()
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
