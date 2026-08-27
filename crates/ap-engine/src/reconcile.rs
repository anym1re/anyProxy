use std::collections::BTreeMap;

use ap_proto::{WireAccess, WireCredential};

use crate::EngineError;
use crate::config::{access_of, user_of};

/// One change that brings the engine to what the panel asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The engine does not know this access yet.
    Create {
        /// Name it will answer to.
        username: String,
        /// The secret the client presents, as sixteen bytes of hexadecimal.
        secret_hex: String,
    },
    /// The engine knows it and should stop serving it.
    Disable {
        /// Name it answers to.
        username: String,
    },
    /// The engine knows it and should serve it again.
    Enable {
        /// Name it answers to.
        username: String,
    },
    /// The panel no longer mentions it at all.
    ///
    /// Withdrawn accesses are absent from a configuration rather than marked,
    /// so anything the engine has and the panel does not is gone for good.
    Remove {
        /// Name it answers to.
        username: String,
    },
}

/// What the engine currently has, as its users endpoint describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Present {
    /// Name it answers to.
    pub username: String,
    /// Whether it is being served.
    pub enabled: bool,
}

/// Works out the changes, in the order they are safe to make.
///
/// Withdrawals go first. An access the panel took away should stop working
/// before anything else happens, and doing it last would leave a window in
/// which a revoked client is still served while the engine works through a
/// list of additions.
pub fn plan(wanted: &[WireAccess], present: &[Present]) -> Result<Vec<Step>, EngineError> {
    let mut by_name: BTreeMap<String, &WireAccess> = BTreeMap::new();
    for access in wanted {
        by_name.insert(user_of(access.id), access);
    }

    let mut withdrawals = Vec::new();
    let mut additions = Vec::new();

    for user in present {
        match by_name.get(&user.username) {
            None => {
                // Only what this panel put there. A user the engine came with,
                // or one an operator added by hand, is left alone: removing it
                // would make the agent an instrument for clearing a node.
                if access_of(&user.username).is_some() {
                    withdrawals.push(Step::Remove {
                        username: user.username.clone(),
                    });
                }
            }
            Some(access) if access.state != "active" && user.enabled => {
                withdrawals.push(Step::Disable {
                    username: user.username.clone(),
                });
            }
            Some(access) if access.state == "active" && !user.enabled => {
                additions.push(Step::Enable {
                    username: user.username.clone(),
                });
            }
            Some(_) => {}
        }
    }

    let known: Vec<&str> = present.iter().map(|user| user.username.as_str()).collect();
    for (username, access) in &by_name {
        if known.contains(&username.as_str()) {
            continue;
        }
        let WireCredential::Secret { hex } = &access.credential else {
            return Err(EngineError::Refused(format!(
                "access {} carries a login, which this engine does not serve",
                access.id
            )));
        };
        additions.push(Step::Create {
            username: username.clone(),
            secret_hex: hex.clone(),
        });
    }

    withdrawals.extend(additions);
    Ok(withdrawals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn a_secret(byte: u8) -> String {
        hex::encode([byte; 16])
    }

    fn an_access(state: &str) -> WireAccess {
        WireAccess {
            id: Uuid::now_v7(),
            method: "faketls".to_owned(),
            credential: WireCredential::Secret {
                hex: a_secret(0x11),
            },
            max_devices: None,
            state: state.to_owned(),
        }
    }

    fn present(username: &str, enabled: bool) -> Present {
        Present {
            username: username.to_owned(),
            enabled,
        }
    }

    #[test]
    fn an_engine_that_knows_nothing_is_given_everything() {
        let access = an_access("active");
        let steps = plan(std::slice::from_ref(&access), &[]).unwrap();
        assert_eq!(
            steps,
            vec![Step::Create {
                username: user_of(access.id),
                secret_hex: a_secret(0x11),
            }]
        );
    }

    #[test]
    fn an_engine_that_already_agrees_is_left_alone() {
        let access = an_access("active");
        let steps = plan(
            std::slice::from_ref(&access),
            &[present(&user_of(access.id), true)],
        )
        .unwrap();
        assert!(steps.is_empty(), "{steps:?}");
    }

    #[test]
    fn an_access_the_panel_no_longer_mentions_is_removed() {
        let gone = Uuid::now_v7();
        let steps = plan(&[], &[present(&user_of(gone), true)]).unwrap();
        assert_eq!(
            steps,
            vec![Step::Remove {
                username: user_of(gone)
            }]
        );
    }

    #[test]
    fn a_user_that_is_not_one_of_ours_is_not_touched() {
        // The engine ships with a user of its own, and an operator may have
        // added one. Neither is the agent's to remove.
        let steps = plan(&[], &[present("default", true), present("nobody", true)]).unwrap();
        assert!(steps.is_empty(), "{steps:?}");
    }

    #[test]
    fn a_disabled_access_is_turned_off_and_an_active_one_back_on() {
        let off = an_access("disabled");
        let on = an_access("active");
        let steps = plan(
            &[off.clone(), on.clone()],
            &[
                present(&user_of(off.id), true),
                present(&user_of(on.id), false),
            ],
        )
        .unwrap();

        assert!(steps.contains(&Step::Disable {
            username: user_of(off.id)
        }));
        assert!(steps.contains(&Step::Enable {
            username: user_of(on.id)
        }));
    }

    #[test]
    fn what_is_taken_away_is_taken_away_first() {
        let gone = Uuid::now_v7();
        let added = an_access("active");
        let steps = plan(
            std::slice::from_ref(&added),
            &[present(&user_of(gone), true)],
        )
        .unwrap();

        let removal = steps
            .iter()
            .position(|step| matches!(step, Step::Remove { .. }))
            .expect("a removal");
        let addition = steps
            .iter()
            .position(|step| matches!(step, Step::Create { .. }))
            .expect("an addition");
        assert!(
            removal < addition,
            "an access was added before a revoked one was taken away: {steps:?}"
        );
    }

    #[test]
    fn a_login_is_refused_rather_than_planned() {
        let mut access = an_access("active");
        access.credential = WireCredential::Login {
            user: "someone".to_owned(),
            pass: "something".to_owned(),
        };
        assert!(matches!(plan(&[access], &[]), Err(EngineError::Refused(_))));
    }

    #[test]
    fn nothing_wanted_and_nothing_present_is_nothing_to_do() {
        assert!(plan(&[], &[]).unwrap().is_empty());
    }
}
