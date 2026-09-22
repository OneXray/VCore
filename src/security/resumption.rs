//! Exact per-node ticket bounds within the runtime's aggregate session budget.
//! A node has one immutable SNI and verifier; caches never cross node policies.
use std::{collections::VecDeque, sync::Mutex};

use rustls::{
    NamedGroup,
    client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue},
    pki_types::ServerName,
};

struct State {
    hint: Option<NamedGroup>,
    tls12: Option<Tls12ClientSessionValue>,
    tickets: VecDeque<Tls13ClientSessionValue>,
}

pub(super) struct NodeSessionStore {
    name: ServerName<'static>,
    capacity: usize,
    state: Mutex<State>,
}

impl std::fmt::Debug for NodeSessionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeSessionStore")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl NodeSessionStore {
    #[cfg(test)]
    pub(super) fn stored_sessions(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.tickets.len() + usize::from(state.tls12.is_some())
    }

    pub(super) fn new(name: ServerName<'static>, capacity: usize) -> Self {
        Self {
            name,
            capacity,
            state: Mutex::new(State {
                hint: None,
                tls12: None,
                tickets: VecDeque::with_capacity(capacity),
            }),
        }
    }
}

impl ClientSessionStore for NodeSessionStore {
    fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
        if name == self.name {
            self.state.lock().unwrap().hint = Some(group);
        }
    }
    fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
        if *name == self.name {
            self.state.lock().unwrap().hint
        } else {
            None
        }
    }
    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        if name != self.name || self.capacity == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.tickets.clear();
        state.tls12 = Some(value);
    }
    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        if *name == self.name {
            self.state.lock().unwrap().tls12.clone()
        } else {
            None
        }
    }
    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        if *name == self.name {
            self.state.lock().unwrap().tls12 = None;
        }
    }
    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        if name != self.name || self.capacity == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.tls12 = None;
        if state.tickets.len() == self.capacity {
            state.tickets.pop_front();
        }
        state.tickets.push_back(value);
    }
    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        if *name == self.name {
            self.state.lock().unwrap().tickets.pop_back()
        } else {
            None
        }
    }
}
