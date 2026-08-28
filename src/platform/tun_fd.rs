use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use crate::Result;

/// Core-owned duplicate of a TUN descriptor borrowed from the platform host.
#[derive(Debug)]
pub struct TunFd {
    fd: OwnedFd,
}

impl TunFd {
    /// Duplicates `borrowed_fd` before returning. The caller retains ownership
    /// of the original descriptor and this type closes only the duplicate. The
    /// host must supply a nonblocking descriptor because `dup` shares file
    /// status flags with the original open-file description; VCore never
    /// changes those shared flags behind the host's back.
    ///
    pub fn duplicate(borrowed_fd: RawFd) -> Result<Self> {
        // SAFETY: F_GETFL reads flags without taking ownership of the borrowed
        // descriptor and reports EBADF for an invalid FFI argument.
        let status_flags = unsafe { libc::fcntl(borrowed_fd, libc::F_GETFL) };
        if status_flags < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if status_flags & libc::O_NONBLOCK == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "host TUN descriptor must already be nonblocking",
            )
            .into());
        }

        // SAFETY: fcntl does not take ownership of the supplied descriptor. It
        // returns a fresh descriptor on success and reports EBADF for invalid
        // input, which is important at an FFI boundary.
        let duplicated = unsafe { libc::fcntl(borrowed_fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: a successful F_DUPFD_CLOEXEC call returns a newly owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(duplicated) };
        Ok(Self { fd })
    }

    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for TunFd {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::fd::AsRawFd,
        os::unix::net::UnixStream,
    };

    use super::*;

    #[test]
    fn duplicate_does_not_take_original_ownership() {
        let (mut original, mut peer) = UnixStream::pair().unwrap();
        original.set_nonblocking(true).unwrap();
        let duplicate = TunFd::duplicate(original.as_raw_fd()).unwrap();
        assert_ne!(duplicate.as_raw_fd(), original.as_raw_fd());

        // SAFETY: both descriptors are open for the duration of these calls.
        let descriptor_flags = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
        // SAFETY: the descriptor is open for the duration of this call.
        let status_flags = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);

        drop(duplicate);
        original.write_all(b"ok").unwrap();
        let mut bytes = [0; 2];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
    }

    #[test]
    fn blocking_descriptor_is_rejected_without_changing_host_flags() {
        let (original, _peer) = UnixStream::pair().unwrap();
        // SAFETY: original remains open for both flag reads.
        let before = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(before & libc::O_NONBLOCK, 0);
        let result = TunFd::duplicate(original.as_raw_fd());
        assert!(result.is_err());
        // SAFETY: a rejected duplicate never takes ownership of original.
        let after = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(after, before);
    }

    #[test]
    fn invalid_descriptor_is_rejected() {
        let result = TunFd::duplicate(-1);
        assert!(result.is_err());
    }
}
