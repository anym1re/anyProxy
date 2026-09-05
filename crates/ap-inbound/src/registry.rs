use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use ap_proto::{WireAccess, WireCredential};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::InboundError;

/// Which listener an access belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Method {
    /// SOCKS5.
    Socks5,
    /// HTTP CONNECT.
    Http,
}

impl Method {
    /// The name the panel uses.
    pub fn as_stored(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
        }
    }
}

/// One account this node serves.
struct Account {
    access: Uuid,
    method: Method,
    /// The password, kept as a digest so a memory dump does not hand it over.
    password: [u8; 32],
    max_devices: Option<i32>,
}

/// What one access has used and who is using it.
#[derive(Debug, Default)]
struct Usage {
    bytes_in: i64,
    bytes_out: i64,
    /// Digests of the addresses seen this period.
    ///
    /// Digests and not addresses: the count is the only thing anyone above
    /// this needs, and an address that is never held cannot be taken. The salt
    /// is drawn once per process and never leaves it, so the digests are
    /// meaningless to anything but this run.
    devices: BTreeSet<[u8; 32]>,
}

/// What the accesses on this node are, and what they have used.
///
/// The whole point of putting this behind one type: a caller can ask whether
/// a name and password are served, and can add bytes to an access, and cannot
/// obtain a client address, because none is kept.
pub struct Registry {
    accounts: Mutex<BTreeMap<String, Account>>,
    usage: Mutex<BTreeMap<Uuid, Usage>>,
    salt: [u8; 32],
    /// Whether a new client is turned away at the door.
    ///
    /// Set by whoever watches the machine. A node that has run out of memory
    /// or of file descriptors does not serve the next client anyway; it fails
    /// it after spending on it, and takes the clients it already has down
    /// with it. Refusing at the door is the cheaper of the two, and the
    /// client's own retry finds another node or a later moment.
    shedding: AtomicBool,
}

impl Registry {
    /// Builds a registry from what the panel sent, keeping only what this
    /// node serves.
    pub fn new(accesses: &[WireAccess], salt: [u8; 32]) -> Self {
        let registry = Self {
            accounts: Mutex::new(BTreeMap::new()),
            usage: Mutex::new(BTreeMap::new()),
            salt,
            shedding: AtomicBool::new(false),
        };
        registry.replace(accesses);
        registry
    }

    /// Whether new clients are being turned away.
    pub fn shedding(&self) -> bool {
        self.shedding.load(Ordering::Relaxed)
    }

    /// Starts or stops turning new clients away. Clients already being
    /// served are not touched either way.
    pub fn set_shedding(&self, shedding: bool) {
        self.shedding.store(shedding, Ordering::Relaxed);
    }

    /// Takes a new configuration, keeping what has been used so far.
    ///
    /// Usage survives because the panel has not acknowledged it yet; the
    /// accounts do not, because the panel is where they are decided.
    pub fn replace(&self, accesses: &[WireAccess]) {
        let mut accounts = BTreeMap::new();
        for access in accesses {
            let method = match access.method.as_str() {
                "socks5" => Method::Socks5,
                "http" => Method::Http,
                // Everything else belongs to the engine, not here.
                _ => continue,
            };
            if access.state != "active" {
                continue;
            }
            let WireCredential::Login { user, pass } = &access.credential else {
                continue;
            };
            accounts.insert(
                user.clone(),
                Account {
                    access: access.id,
                    method,
                    password: Sha256::digest(pass.as_bytes()).into(),
                    max_devices: access.max_devices,
                },
            );
        }
        // What is no longer served is no longer counted. A node that kept
        // counting for an access taken off it would report that access for as
        // long as the process lived, and the panel — which cannot tell an
        // access that was withdrawn from one that was never here — refuses the
        // whole delivery. One withdrawn access would then stop the accounting
        // of every other access on the node.
        let served: std::collections::BTreeSet<Uuid> =
            accounts.values().map(|account| account.access).collect();
        if let Ok(mut usage) = self.usage.lock() {
            usage.retain(|access, _| served.contains(access));
        }
        if let Ok(mut held) = self.accounts.lock() {
            *held = accounts;
        }
    }

    /// Whether this name and password are served on this listener, and by whom.
    ///
    /// Every way of failing gives the same answer. A name that does not exist,
    /// a wrong password, an access belonging to the other listener and one the
    /// panel disabled must not be distinguishable from outside, or the answer
    /// becomes a way to enumerate what a node serves.
    pub fn admit(
        &self,
        listener: Method,
        user: &str,
        password: &str,
        from: IpAddr,
    ) -> Result<Uuid, InboundError> {
        let offered: [u8; 32] = Sha256::digest(password.as_bytes()).into();

        let Ok(accounts) = self.accounts.lock() else {
            return Err(InboundError::Refused);
        };
        let Some(account) = accounts.get(user) else {
            return Err(InboundError::Refused);
        };
        if account.method != listener {
            return Err(InboundError::Refused);
        }
        if !bool::from(account.password.ct_eq(&offered)) {
            return Err(InboundError::Refused);
        }

        let access = account.access;
        let limit = account.max_devices;
        drop(accounts);

        let device = self.device_of(from);
        let Ok(mut usage) = self.usage.lock() else {
            return Err(InboundError::Refused);
        };
        let entry = usage.entry(access).or_default();
        if let Some(limit) = limit
            && !entry.devices.contains(&device)
            && entry.devices.len() >= limit.max(0) as usize
        {
            // A device already being served goes on being served; a new one
            // beyond the limit does not start.
            return Err(InboundError::TooManyDevices);
        }
        entry.devices.insert(device);
        Ok(access)
    }

    /// Adds what one access has just moved.
    pub fn used(&self, access: Uuid, bytes_in: i64, bytes_out: i64) {
        if let Ok(mut usage) = self.usage.lock() {
            let entry = usage.entry(access).or_default();
            entry.bytes_in += bytes_in;
            entry.bytes_out += bytes_out;
        }
    }

    /// What every access has used since this process started, and how many
    /// devices used it.
    ///
    /// Counts, and nothing an address could be recovered from.
    pub fn taken(&self) -> BTreeMap<Uuid, (i64, i64, i64)> {
        let Ok(usage) = self.usage.lock() else {
            return BTreeMap::new();
        };
        usage
            .iter()
            .map(|(access, used)| {
                (
                    *access,
                    (used.bytes_in, used.bytes_out, used.devices.len() as i64),
                )
            })
            .collect()
    }

    /// The digest one address is counted by.
    fn device_of(&self, from: IpAddr) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        match from {
            IpAddr::V4(address) => hasher.update(address.octets()),
            IpAddr::V6(address) => hasher.update(address.octets()),
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an_access(method: &str, user: &str, pass: &str, state: &str) -> WireAccess {
        WireAccess {
            id: Uuid::now_v7(),
            method: method.to_owned(),
            credential: WireCredential::Login {
                user: user.to_owned(),
                pass: pass.to_owned(),
            },
            max_devices: None,
            state: state.to_owned(),
        }
    }

    fn address(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    fn registry(accesses: &[WireAccess]) -> Registry {
        Registry::new(accesses, [7u8; 32])
    }

    #[test]
    fn the_right_name_and_password_are_admitted() {
        let access = an_access("socks5", "alice", "opens the door", "active");
        let registry = registry(std::slice::from_ref(&access));
        assert_eq!(
            registry
                .admit(Method::Socks5, "alice", "opens the door", address(7))
                .unwrap(),
            access.id
        );
    }

    #[test]
    fn every_way_of_being_wrong_answers_the_same() {
        let socks = an_access("socks5", "alice", "opens the door", "active");
        let off = an_access("socks5", "bob", "also opens it", "disabled");
        let registry = registry(&[socks, off]);

        for (user, pass, why) in [
            ("alice", "wrong", "a wrong password"),
            ("nobody", "opens the door", "a name that does not exist"),
            ("bob", "also opens it", "an access the panel disabled"),
        ] {
            let outcome = registry.admit(Method::Socks5, user, pass, address(7));
            assert!(
                matches!(outcome, Err(InboundError::Refused)),
                "{why} was answered differently"
            );
        }
    }

    #[test]
    fn an_access_does_not_cross_between_listeners() {
        let socks = an_access("socks5", "alice", "opens the door", "active");
        let http = an_access("http", "carol", "opens the other", "active");
        let registry = registry(&[socks, http]);

        assert!(matches!(
            registry.admit(Method::Http, "alice", "opens the door", address(7)),
            Err(InboundError::Refused)
        ));
        assert!(matches!(
            registry.admit(Method::Socks5, "carol", "opens the other", address(7)),
            Err(InboundError::Refused)
        ));
    }

    #[test]
    fn an_access_for_the_engine_is_not_served_here() {
        let faketls = WireAccess {
            id: Uuid::now_v7(),
            method: "faketls".to_owned(),
            credential: WireCredential::Secret {
                hex: "00".repeat(16),
            },
            max_devices: None,
            state: "active".to_owned(),
        };
        let registry = registry(std::slice::from_ref(&faketls));
        assert!(matches!(
            registry.admit(Method::Socks5, "whoever", "whatever", address(7)),
            Err(InboundError::Refused)
        ));
    }

    #[test]
    fn three_visits_from_two_addresses_are_two_devices() {
        let access = an_access("socks5", "alice", "opens the door", "active");
        let registry = registry(std::slice::from_ref(&access));

        for from in [address(7), address(8), address(7)] {
            registry
                .admit(Method::Socks5, "alice", "opens the door", from)
                .unwrap();
        }
        let taken = registry.taken();
        assert_eq!(taken.get(&access.id).unwrap().2, 2);
    }

    #[test]
    fn a_new_device_beyond_the_limit_is_refused_and_the_old_one_is_not() {
        let mut access = an_access("socks5", "alice", "opens the door", "active");
        access.max_devices = Some(1);
        let registry = registry(std::slice::from_ref(&access));

        registry
            .admit(Method::Socks5, "alice", "opens the door", address(7))
            .unwrap();
        assert!(matches!(
            registry.admit(Method::Socks5, "alice", "opens the door", address(8)),
            Err(InboundError::TooManyDevices)
        ));
        // The one already being served goes on being served.
        assert!(
            registry
                .admit(Method::Socks5, "alice", "opens the door", address(7))
                .is_ok()
        );
    }

    #[test]
    fn what_was_used_is_counted_and_then_forgotten() {
        let access = an_access("socks5", "alice", "opens the door", "active");
        let registry = registry(std::slice::from_ref(&access));
        registry
            .admit(Method::Socks5, "alice", "opens the door", address(7))
            .unwrap();

        registry.used(access.id, 100, 250);
        registry.used(access.id, 50, 0);

        // Counters that only ever climb, like the engine's: what was used
        // between two readings is the difference, and the meter above takes
        // it. A counter that resets here would lose whatever was used between
        // the reset and the next reading.
        let (bytes_in, bytes_out, devices) = *registry.taken().get(&access.id).unwrap();
        assert_eq!((bytes_in, bytes_out, devices), (150, 250, 1));
    }

    #[test]
    fn nothing_it_reports_could_be_turned_back_into_an_address() {
        let access = an_access("socks5", "alice", "opens the door", "active");
        let registry = registry(std::slice::from_ref(&access));
        registry
            .admit(Method::Socks5, "alice", "opens the door", address(7))
            .unwrap();

        let reported = format!("{:?}", registry.taken());
        assert!(!reported.contains("203.0.113"), "{reported}");
        assert!(!reported.contains("alice"), "{reported}");
    }

    #[test]
    fn two_processes_do_not_agree_on_what_a_device_looks_like() {
        let access = an_access("socks5", "alice", "opens the door", "active");
        let here = Registry::new(std::slice::from_ref(&access), [1u8; 32]);
        let there = Registry::new(std::slice::from_ref(&access), [2u8; 32]);

        // The salt is per process, so a digest taken here means nothing there:
        // the same address cannot be recognised across two nodes or across a
        // restart of one.
        assert_ne!(here.device_of(address(7)), there.device_of(address(7)));
    }

    #[test]
    fn a_configuration_that_no_longer_grants_an_access_stops_serving_it() {
        let access = an_access("socks5", "alice", "opens the door", "active");
        let registry = registry(std::slice::from_ref(&access));
        assert!(
            registry
                .admit(Method::Socks5, "alice", "opens the door", address(7))
                .is_ok()
        );

        registry.replace(&[]);
        assert!(matches!(
            registry.admit(Method::Socks5, "alice", "opens the door", address(7)),
            Err(InboundError::Refused)
        ));
    }

    #[test]
    fn what_was_used_survives_a_new_configuration() {
        let access = an_access("socks5", "alice", "opens the door", "active");
        let registry = registry(std::slice::from_ref(&access));
        registry.used(access.id, 10, 20);

        // The panel has not acknowledged this yet, so a configuration arriving
        // in between must not throw it away.
        registry.replace(std::slice::from_ref(&access));
        assert_eq!(registry.taken().get(&access.id).unwrap().0, 10);
    }
}

#[cfg(test)]
mod forgetting {
    use super::*;

    fn an_access(user: &str, pass: &str) -> WireAccess {
        WireAccess {
            id: Uuid::now_v7(),
            method: "socks5".to_owned(),
            credential: WireCredential::Login {
                user: user.to_owned(),
                pass: pass.to_owned(),
            },
            max_devices: None,
            state: "active".to_owned(),
        }
    }

    #[test]
    fn an_access_taken_off_the_node_stops_being_counted() {
        // The panel cannot tell an access that was withdrawn from one that was
        // never here, so it refuses a delivery naming either. A node that kept
        // reporting a withdrawn access would take down the accounting of every
        // other access it serves along with it.
        let staying = an_access("stays", "one password");
        let going = an_access("goes", "another password");
        let registry = Registry::new(&[staying.clone(), going.clone()], [3u8; 32]);

        let here = "203.0.113.9".parse().unwrap();
        let first = registry
            .admit(Method::Socks5, "stays", "one password", here)
            .unwrap();
        let second = registry
            .admit(Method::Socks5, "goes", "another password", here)
            .unwrap();
        registry.used(first, 10, 20);
        registry.used(second, 30, 40);
        assert_eq!(registry.taken().len(), 2);

        registry.replace(&[staying]);

        let taken = registry.taken();
        assert!(
            !taken.contains_key(&second),
            "an access the node no longer serves is still being counted"
        );
        assert_eq!(
            taken.get(&first).map(|used| (used.0, used.1)),
            Some((10, 20)),
            "the access that stayed lost what it had carried"
        );
    }

    #[test]
    fn an_access_that_stays_keeps_its_totals_across_a_revision() {
        // The totals only climb, and the meter takes differences between two
        // readings. A revision that changes nothing must not look like a node
        // that has just started, or the difference would be counted twice.
        let access = an_access("stays", "one password");
        let registry = Registry::new(std::slice::from_ref(&access), [4u8; 32]);
        let id = registry
            .admit(
                Method::Socks5,
                "stays",
                "one password",
                "203.0.113.9".parse().unwrap(),
            )
            .unwrap();
        registry.used(id, 100, 200);

        registry.replace(std::slice::from_ref(&access));

        assert_eq!(
            registry.taken().get(&id).map(|used| (used.0, used.1)),
            Some((100, 200))
        );
    }
}
