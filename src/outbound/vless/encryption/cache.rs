use std::{
    io,
    sync::{Arc, Mutex},
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(super) struct Ticket {
    pub pfs: Zeroizing<[u8; 64]>,
    pub bytes: Zeroizing<[u8; 16]>,
    pub expires: Instant,
}

#[derive(Default)]
pub(super) struct Cache {
    ticket: Mutex<Option<Arc<Ticket>>>,
    pub cancellation: CancellationToken,
}

impl Cache {
    pub fn lookup(&self) -> io::Result<Option<Arc<Ticket>>> {
        let mut slot = self.ticket.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancellation.is_cancelled() {
            return Err(closed());
        }
        if slot.as_ref().is_some_and(|t| t.expires <= Instant::now()) {
            slot.take();
        }
        Ok(slot.clone())
    }

    pub fn publish(&self, ticket: Arc<Ticket>) -> io::Result<()> {
        let mut slot = self.ticket.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancellation.is_cancelled() {
            return Err(closed());
        }
        *slot = Some(ticket);
        Ok(())
    }

    pub fn invalidate(&self, ticket: &Arc<Ticket>) {
        let mut slot = self.ticket.lock().unwrap_or_else(|e| e.into_inner());
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, ticket))
        {
            slot.take();
        }
    }

    pub fn close(&self) {
        let mut slot = self.ticket.lock().unwrap_or_else(|e| e.into_inner());
        self.cancellation.cancel();
        slot.take();
    }
}

pub(super) fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "VLESS Encryption node stopped",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ticket(expires: Instant) -> Arc<Ticket> {
        Arc::new(Ticket {
            pfs: Zeroizing::new([0; 64]),
            bytes: Zeroizing::new([0; 16]),
            expires,
        })
    }
    #[test]
    fn expires_and_invalidates_only_the_matching_ticket_generation() {
        let cache = Cache::default();
        cache.publish(ticket(Instant::now())).unwrap();
        assert!(cache.lookup().unwrap().is_none());
        let expires = Instant::now() + std::time::Duration::from_secs(60);
        let old = ticket(expires);
        let new = ticket(expires);
        cache.publish(old.clone()).unwrap();
        cache.publish(new.clone()).unwrap();
        cache.invalidate(&old);
        assert!(Arc::ptr_eq(&cache.lookup().unwrap().unwrap(), &new));
        cache.invalidate(&new);
        assert!(cache.lookup().unwrap().is_none());
        cache.close();
        assert!(cache.publish(old).is_err());
        assert!(cache.lookup().is_err());
    }
}
