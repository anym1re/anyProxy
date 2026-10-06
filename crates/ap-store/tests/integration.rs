//! Exercised against a real PostgreSQL. Skipped when DATABASE_URL is absent,
//! so a machine without a database still builds and runs the unit tests.

// An integration test is a separate build target, so the relaxations in
// clippy.toml, which cover cfg(test) modules, do not reach it. Failing loudly
// is what a test is for.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ap_core::{
    Access, AccessCommon, AccessState, AnyAccess, Client, ClientState, Credential, Domain,
    Encrypted, Holder, KeyStore, Label, Node, NodeKind, NodeState, OpenMethod, Stealth,
    StealthMethod, Tag, TagName,
};
use ap_store::{
    AccessRepo, AuditRepo, BotRepo, ClientRepo, NodeRepo, Outgoing, SettingRepo, StoreError,
    TagRepo, TrafficRepo,
};
use sqlx::{PgPool, Row};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = ap_store::connect(&url, 5).await.expect("connect");
    ap_store::migrate(&pool).await.expect("migrate");
    Some(pool)
}

macro_rules! db {
    () => {
        match pool().await {
            Some(pool) => pool,
            None => return,
        }
    };
}

fn unique(prefix: &str) -> String {
    // The first half of a version 7 identifier is a millisecond timestamp, so
    // two calls inside one millisecond share it. The second half is random.
    let id = Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", &id[16..])
}

fn key() -> KeyStore {
    KeyStore::from_bytes([3u8; 32])
}

async fn a_client(pool: &PgPool) -> Client {
    let client = Client::new(
        Label::try_from(unique("c").as_str()).unwrap(),
        OffsetDateTime::UNIX_EPOCH,
    );
    ClientRepo::insert(pool, &client, None).await.unwrap();
    client
}

async fn an_open_node(pool: &PgPool) -> Node {
    let node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Mtproto,
        OffsetDateTime::UNIX_EPOCH,
    );
    NodeRepo::insert(pool, &node).await.unwrap();
    node
}

async fn an_access(pool: &PgPool, client: &Client, node: &Node) -> (AnyAccess, Credential) {
    let common = AccessCommon::new(
        Holder::Client(client.id()),
        node.id(),
        OffsetDateTime::UNIX_EPOCH,
    );
    let access = AnyAccess::Open(Access::<ap_core::Open>::new(common, OpenMethod::Socks5));
    let credential = Credential::generate_secret();
    AccessRepo::insert(pool, &access, &credential, &key())
        .await
        .unwrap();
    (access, credential)
}

#[tokio::test]
async fn migrations_apply_twice_without_complaint() {
    let pool = db!();
    ap_store::migrate(&pool).await.unwrap();
    ap_store::migrate(&pool).await.unwrap();
}

#[tokio::test]
async fn the_schema_holds_no_client_address() {
    let pool = db!();
    // A word-boundary match: "description" contains the letters of "ip"
    // and would otherwise be reported as a client address.
    let rows = sqlx::query(
        "select table_name, column_name from information_schema.columns \n         where table_schema = 'public' \n         and column_name ~ '(^|_)(ip|addr|address|host|peer)(_|$)'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let offenders: Vec<String> = rows
        .iter()
        .map(|row| {
            format!(
                "{}.{}",
                row.get::<String, _>("table_name"),
                row.get::<String, _>("column_name")
            )
        })
        .filter(|name| name != "node.address")
        .collect();
    assert!(
        offenders.is_empty(),
        "the only address in the schema belongs to a node, found {offenders:?}"
    );
}

#[tokio::test]
async fn a_client_survives_a_round_trip() {
    let pool = db!();
    let note = Encrypted::seal(&"paid until spring".to_owned(), &key()).unwrap();
    let client = Client::new(
        Label::try_from(unique("c").as_str()).unwrap(),
        OffsetDateTime::UNIX_EPOCH,
    )
    .with_note(note)
    .with_quota(50)
    .unwrap();
    ClientRepo::insert(&pool, &client, None).await.unwrap();

    let read = ClientRepo::by_label(&pool, client.label())
        .await
        .unwrap()
        .expect("client");
    assert_eq!(read.id(), client.id());
    assert_eq!(read.quota_bytes(), Some(50));
    assert_eq!(
        read.note().unwrap().open(&key()).unwrap(),
        "paid until spring"
    );
}

#[tokio::test]
async fn a_masked_node_without_a_domain_is_refused_by_the_database() {
    let pool = db!();
    let result = sqlx::query(
        "insert into node (id, label, kind, domain, state, created_at) \
         values ($1, $2, 'faketls', null, 'pending', now())",
    )
    .bind(Uuid::now_v7())
    .bind(unique("n"))
    .execute(&pool)
    .await;
    assert!(
        result.is_err(),
        "the database accepted a masked node with no domain"
    );
}

#[tokio::test]
async fn a_node_serving_in_the_open_with_a_domain_is_refused_by_the_database() {
    let pool = db!();
    let result = sqlx::query(
        "insert into node (id, label, kind, domain, state, created_at) \
         values ($1, $2, 'socks5', 'cover.example.com', 'pending', now())",
    )
    .bind(Uuid::now_v7())
    .bind(unique("n"))
    .execute(&pool)
    .await;
    assert!(
        result.is_err(),
        "the database accepted a node serving in the open with a domain"
    );
}

#[tokio::test]
async fn a_name_a_node_owns_belongs_to_one_node_only() {
    let pool = db!();
    let domain = Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap();
    for expected_ok in [true, false] {
        let node = Node::new(
            Label::try_from(unique("n").as_str()).unwrap(),
            NodeKind::Web {
                domain: domain.clone(),
            },
            OffsetDateTime::UNIX_EPOCH,
        );
        let result = NodeRepo::insert(&pool, &node).await;
        assert_eq!(
            result.is_ok(),
            expected_ok,
            "a second node took a name the first one owns"
        );
    }
}

#[tokio::test]
async fn a_borrowed_name_may_be_worn_by_more_than_one_node() {
    // A forged handshake claims a site belonging to somebody else, and several
    // nodes may claim the same popular one — imitating one site from a few
    // addresses is ordinary. Uniqueness here would forbid it, which is why the
    // index covers only the names a node holds a certificate for.
    let pool = db!();
    let domain = Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap();
    for _ in 0..2 {
        let node = Node::new(
            Label::try_from(unique("n").as_str()).unwrap(),
            NodeKind::FakeTls {
                domain: domain.clone(),
            },
            OffsetDateTime::UNIX_EPOCH,
        );
        NodeRepo::insert(&pool, &node)
            .await
            .expect("a node was refused a name another node had only borrowed");
    }
}

#[tokio::test]
async fn a_heartbeat_does_not_erase_the_build_a_node_reported() {
    // The greeting carries the agent's build and every heartbeat after it
    // carries none. Assigning it outright wiped it half a minute after each
    // node connected, leaving the panel unable to say which nodes had a fix.
    let pool = db!();
    let node = an_open_node(&pool).await;

    ap_store::PresenceRepo::seen(&pool, node.id(), "1.2.3", None, OffsetDateTime::now_utc())
        .await
        .unwrap();
    ap_store::PresenceRepo::seen(
        &pool,
        node.id(),
        "",
        Some(("up", "unknown", "open", None)),
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();

    let read = NodeRepo::by_label(&pool, node.label())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.agent_version(), Some("1.2.3"));
}

#[tokio::test]
async fn a_burned_node_is_never_moved_out_of_that_state() {
    let pool = db!();
    let node = an_open_node(&pool).await;
    assert!(
        NodeRepo::set_state(&pool, node.id(), NodeState::Burned)
            .await
            .unwrap()
    );
    assert!(
        !NodeRepo::set_state(&pool, node.id(), NodeState::Active)
            .await
            .unwrap()
    );
    let read = NodeRepo::by_label(&pool, node.label())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.state(), NodeState::Burned);
}

#[tokio::test]
async fn one_credential_is_not_issued_twice_on_a_node() {
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let credential = Credential::generate_secret();

    for expected_ok in [true, false] {
        let common = AccessCommon::new(
            Holder::Client(client.id()),
            node.id(),
            OffsetDateTime::UNIX_EPOCH,
        );
        let access = AnyAccess::Open(Access::<ap_core::Open>::new(common, OpenMethod::Socks5));
        let result = AccessRepo::insert(&pool, &access, &credential, &key()).await;
        assert_eq!(result.is_ok(), expected_ok, "a credential was reused");
        if let Err(error) = result {
            assert!(error.is_constraint_violation());
        }
    }
}

#[tokio::test]
async fn the_same_credential_may_live_on_two_nodes() {
    let pool = db!();
    let client = a_client(&pool).await;
    let credential = Credential::generate_secret();
    for _ in 0..2 {
        let node = an_open_node(&pool).await;
        let common = AccessCommon::new(
            Holder::Client(client.id()),
            node.id(),
            OffsetDateTime::UNIX_EPOCH,
        );
        let access = AnyAccess::Open(Access::<ap_core::Open>::new(common, OpenMethod::Http));
        AccessRepo::insert(&pool, &access, &credential, &key())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_method_the_node_does_not_serve_is_refused_by_the_database() {
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let result = sqlx::query(
        "insert into access (id, client_id, node_id, surface, method, credential_nonce, \
         credential_ciphertext, credential_digest, state, created_at) \
         values ($1, $2, $3, 'open', 'faketls', '\\x00', '\\x00', '\\x00', 'active', now())",
    )
    .bind(Uuid::now_v7())
    .bind(client.id())
    .bind(node.id())
    .execute(&pool)
    .await;
    assert!(result.is_err(), "an open node took a stealth method");
}

#[tokio::test]
async fn a_client_holding_an_access_cannot_be_deleted() {
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    an_access(&pool, &client, &node).await;

    let error = ClientRepo::delete(&pool, client.id())
        .await
        .expect_err("the database allowed a client with an access to be deleted");
    assert!(error.is_constraint_violation());
}

#[tokio::test]
async fn a_credential_comes_back_only_through_the_key() {
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let (access, credential) = an_access(&pool, &client, &node).await;

    let read = AccessRepo::credential(&pool, access.common().id(), &key())
        .await
        .unwrap()
        .expect("credential");
    assert_eq!(read, credential);

    let other = KeyStore::from_bytes([9u8; 32]);
    assert!(
        AccessRepo::credential(&pool, access.common().id(), &other)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn an_access_keeps_its_surface_across_a_round_trip() {
    let pool = db!();
    let client = a_client(&pool).await;
    let domain = Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap();
    let node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::FakeTls { domain },
        OffsetDateTime::UNIX_EPOCH,
    );
    NodeRepo::insert(&pool, &node).await.unwrap();

    let common = AccessCommon::new(
        Holder::Client(client.id()),
        node.id(),
        OffsetDateTime::UNIX_EPOCH,
    );
    let access = AnyAccess::Stealth(Access::<Stealth>::new(common, StealthMethod::Web));
    AccessRepo::insert(&pool, &access, &Credential::generate_secret(), &key())
        .await
        .unwrap();

    let read = AccessRepo::by_id(&pool, access.common().id())
        .await
        .unwrap()
        .expect("access");
    match read {
        AnyAccess::Stealth(read) => assert_eq!(*read.method(), StealthMethod::Web),
        AnyAccess::Open(_) => panic!("a stealth access came back as open"),
    }
}

#[tokio::test]
async fn a_tag_withdraws_every_access_under_it() {
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let tag = Tag::new(TagName::try_from(unique("t").as_str()).unwrap());
    TagRepo::insert(&pool, &tag).await.unwrap();

    for _ in 0..3 {
        let common = AccessCommon::new(
            Holder::Client(client.id()),
            node.id(),
            OffsetDateTime::UNIX_EPOCH,
        )
        .with_tag(tag.id());
        let access = AnyAccess::Open(Access::<ap_core::Open>::new(common, OpenMethod::Socks5));
        AccessRepo::insert(&pool, &access, &Credential::generate_secret(), &key())
            .await
            .unwrap();
    }

    assert_eq!(AccessRepo::revoke_by_tag(&pool, tag.id()).await.unwrap(), 3);
    for access in AccessRepo::by_client(&pool, client.id()).await.unwrap() {
        assert_eq!(access.common().state(), AccessState::Revoked);
    }
}

#[tokio::test]
async fn a_revoked_access_is_never_resumed() {
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let (access, _) = an_access(&pool, &client, &node).await;
    let id = access.common().id();

    assert!(
        AccessRepo::set_state(&pool, id, AccessState::Revoked)
            .await
            .unwrap()
    );
    assert!(
        !AccessRepo::set_state(&pool, id, AccessState::Active)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_repeated_delta_moves_the_counter_once() {
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let (access, _) = an_access(&pool, &client, &node).await;
    let id = access.common().id();
    let day = Date::from_calendar_date(2026, time::Month::August, 26).unwrap();
    let revision = Uuid::now_v7();

    assert!(
        TrafficRepo::apply_delta(
            &pool,
            revision,
            id,
            day,
            100,
            200,
            OffsetDateTime::UNIX_EPOCH
        )
        .await
        .unwrap()
    );
    assert!(
        !TrafficRepo::apply_delta(
            &pool,
            revision,
            id,
            day,
            100,
            200,
            OffsetDateTime::UNIX_EPOCH
        )
        .await
        .unwrap()
    );

    let totals = TrafficRepo::for_access(&pool, id).await.unwrap();
    assert_eq!(totals.bytes_in, 100);
    assert_eq!(totals.bytes_out, 200);
    assert_eq!(totals.total(), 300);

    assert!(
        TrafficRepo::apply_delta(
            &pool,
            Uuid::now_v7(),
            id,
            day,
            1,
            1,
            OffsetDateTime::UNIX_EPOCH
        )
        .await
        .unwrap()
    );
    assert_eq!(
        TrafficRepo::for_access(&pool, id).await.unwrap().total(),
        302
    );
    assert_eq!(
        TrafficRepo::for_client(&pool, client.id())
            .await
            .unwrap()
            .total(),
        302
    );
}

#[tokio::test]
async fn the_audit_log_accepts_entries_and_reads_them_back() {
    let pool = db!();
    let action = unique("action");
    AuditRepo::record(
        &pool,
        None,
        &action,
        Some("client/alice"),
        OffsetDateTime::now_utc(),
        serde_json::json!({ "reason": "link rendered" }),
    )
    .await
    .unwrap();

    let recent = AuditRepo::recent(&pool, 50).await.unwrap();
    assert!(recent.iter().any(|entry| entry.action == action));
}

#[tokio::test]
async fn the_application_role_cannot_rewrite_the_audit_log() {
    let pool = db!();
    AuditRepo::record(
        &pool,
        None,
        &unique("action"),
        None,
        OffsetDateTime::now_utc(),
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let mut connection = pool.acquire().await.unwrap();
    // Since PostgreSQL 16 a role that created another may administer it but
    // not become it until it grants itself that; before 16 the clause does
    // not exist and there is nothing to grant. Whether this statement is
    // taken does not matter: the next one says whether the role can be worn.
    let _ = sqlx::query("grant anyproxy_app to current_user with set true")
        .execute(&mut *connection)
        .await;
    sqlx::query("set role anyproxy_app")
        .execute(&mut *connection)
        .await
        .unwrap();

    for statement in [
        "update audit_log set action = 'rewritten'",
        "delete from audit_log",
    ] {
        let error = sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .expect_err("the application role rewrote the audit log");
        let error = StoreError::from(error);
        assert!(
            error.is_permission_denied(),
            "expected a permission error, got {error}"
        );
    }

    sqlx::query("reset role")
        .execute(&mut *connection)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_state_the_schema_does_not_know_is_refused() {
    let pool = db!();
    let result = sqlx::query(
        "insert into client (id, label, state, created_at) values ($1, $2, 'gone', now())",
    )
    .bind(Uuid::now_v7())
    .bind(unique("c"))
    .execute(&pool)
    .await;
    assert!(result.is_err(), "the database took an unknown client state");
}

#[tokio::test]
async fn a_client_state_change_is_seen_on_the_next_read() {
    let pool = db!();
    let client = a_client(&pool).await;
    assert!(
        ClientRepo::set_state(&pool, client.id(), ClientState::Suspended)
            .await
            .unwrap()
    );
    let read = ClientRepo::by_id(&pool, client.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.state(), ClientState::Suspended);
}

#[tokio::test]
async fn a_day_series_is_scoped_to_an_owner_when_asked() {
    let pool = db!();
    let owner = ap_core::AdminUser::new(
        ap_core::AdminLogin::try_from(unique("a").as_str()).unwrap(),
        "hash".to_owned(),
        Some(Encrypted::seal(&"secret".to_owned(), &key()).unwrap()),
        ap_core::Role::Reseller,
        OffsetDateTime::UNIX_EPOCH,
    )
    .unwrap();
    ap_store::AdminRepo::insert(&pool, &owner).await.unwrap();

    let mine = Client::new(
        Label::try_from(unique("c").as_str()).unwrap(),
        OffsetDateTime::UNIX_EPOCH,
    );
    ClientRepo::insert(&pool, &mine, Some(owner.id()))
        .await
        .unwrap();
    let theirs = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let (own, _) = an_access(&pool, &mine, &node).await;
    let (other, _) = an_access(&pool, &theirs, &node).await;

    // A day of its own: the sum for today grows with every other test.
    let day = Date::from_calendar_date(2001, time::Month::January, 1).unwrap();
    for (access, bytes_in, bytes_out) in [(&own, 10, 20), (&other, 100, 200)] {
        assert!(
            TrafficRepo::apply_delta(
                &pool,
                Uuid::now_v7(),
                access.common().id(),
                day,
                bytes_in,
                bytes_out,
                OffsetDateTime::UNIX_EPOCH,
            )
            .await
            .unwrap()
        );
    }

    let scoped = TrafficRepo::daily(&pool, day, Some(owner.id()))
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1, "{scoped:?}");
    assert_eq!(
        (scoped[0].day, scoped[0].bytes_in, scoped[0].bytes_out),
        (day, 10, 20)
    );

    let everyone = TrafficRepo::daily(&pool, day, None).await.unwrap();
    let that_day = everyone.iter().find(|point| point.day == day).unwrap();
    assert!(that_day.bytes_in >= 110 && that_day.bytes_out >= 220);

    let later = TrafficRepo::daily(&pool, day + time::Duration::days(1), Some(owner.id()))
        .await
        .unwrap();
    assert!(later.is_empty(), "{later:?}");
}

#[tokio::test]
async fn only_the_first_administrator_is_let_in_that_way() {
    let pool = db!();
    let an_admin = |login: String| {
        ap_core::AdminUser::new(
            ap_core::AdminLogin::try_from(login.as_str()).unwrap(),
            "hash".to_owned(),
            None,
            ap_core::Role::Superadmin,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap()
    };

    // Whether this database is empty is not this test's to decide: other
    // tests share it. What holds either way is that once one exists, the
    // door is shut.
    let first = an_admin(unique("a"));
    let _ = ap_store::AdminRepo::insert_first(&pool, &first)
        .await
        .unwrap();
    assert!(ap_store::AdminRepo::count(&pool).await.unwrap() > 0);

    let second = an_admin(unique("a"));
    assert!(
        !ap_store::AdminRepo::insert_first(&pool, &second)
            .await
            .unwrap(),
        "a second owner was let in"
    );
    assert!(
        ap_store::AdminRepo::by_login(&pool, second.login())
            .await
            .unwrap()
            .is_none(),
        "the row was written after all"
    );
}

#[tokio::test]
async fn an_access_says_what_it_carried_and_when_it_was_last_busy() {
    // The users screen was drawn with a column for each (0066). The window
    // bounds the sum only: an access quiet for a month still says when it was
    // last busy, or the column would go blank the moment it went quiet.
    let pool = db!();
    let client = a_client(&pool).await;
    let node = an_open_node(&pool).await;
    let (access, _) = an_access(&pool, &client, &node).await;
    let id = access.common().id();
    let today = OffsetDateTime::now_utc().date();
    let long_ago = today - time::Duration::days(90);

    for (day, bytes_in, bytes_out) in [(today, 10, 5), (long_ago, 1000, 1000)] {
        assert!(
            TrafficRepo::apply_delta(
                &pool,
                Uuid::now_v7(),
                id,
                day,
                bytes_in,
                bytes_out,
                OffsetDateTime::UNIX_EPOCH
            )
            .await
            .unwrap()
        );
    }

    let since = today - time::Duration::days(29);
    let rows = TrafficRepo::by_access(&pool, since, None).await.unwrap();
    let (_, carried, last_day) = rows
        .into_iter()
        .find(|(access_id, _, _)| *access_id == id)
        .expect("the access is listed");
    assert_eq!(carried, 15, "only the days inside the window are summed");
    assert_eq!(last_day, today, "the last busy day is not bounded by it");

    // A reseller is told about their own clients and no one else's.
    let stranger = Uuid::now_v7();
    let theirs = TrafficRepo::by_access(&pool, since, Some(stranger))
        .await
        .unwrap();
    assert!(!theirs.iter().any(|(access_id, _, _)| *access_id == id));
}

#[tokio::test]
async fn the_journal_is_read_a_page_at_a_time_and_counted() {
    // The journal screen has a bar of counted filters and a footer saying
    // which page of how many, and neither can be built from a bare list
    // (0067).
    let pool = db!();
    let actor = Uuid::now_v7();
    let mark = unique("kind");
    let at = OffsetDateTime::now_utc();
    for (action, target) in [
        (format!("{mark}.created"), "first"),
        (format!("{mark}.created"), "second"),
        (format!("{mark}.burned"), "third"),
    ] {
        AuditRepo::record(
            &pool,
            Some(actor),
            &action,
            Some(target),
            at,
            serde_json::json!({}),
        )
        .await
        .unwrap();
    }

    let starts = [format!("{mark}.")];
    let (page, total) = AuditRepo::page(&pool, 2, 0, Some(&starts), None)
        .await
        .unwrap();
    assert_eq!(total, 3, "the count is of what matches, not of the page");
    assert_eq!(page.len(), 2);
    let (rest, _) = AuditRepo::page(&pool, 2, 2, Some(&starts), None)
        .await
        .unwrap();
    assert_eq!(rest.len(), 1, "the second page holds what the first left");

    // A group on the screen can be more than one kind of record.
    let both = [format!("{mark}.created"), format!("{mark}.burned")];
    let (_, matching) = AuditRepo::page(&pool, 10, 0, Some(&both), None)
        .await
        .unwrap();
    assert_eq!(matching, 3);

    let counted = AuditRepo::counts(&pool, at - time::Duration::hours(1))
        .await
        .unwrap();
    let created = counted
        .iter()
        .find(|(action, _)| *action == format!("{mark}.created"))
        .map(|(_, many)| *many);
    assert_eq!(created, Some(2));

    // Nothing was recorded before the beginning of time this test cares about.
    let later = AuditRepo::counts(&pool, at + time::Duration::hours(1))
        .await
        .unwrap();
    assert!(!later.iter().any(|(action, _)| action.starts_with(&mark)));
}

#[tokio::test]
async fn a_setting_keeps_what_it_was_set_to_and_who_set_it() {
    // The panel's settings used to be constants; the screen that changes them
    // has to be able to read back what it wrote, and the journal beside it has
    // to be able to say who wrote it (0069).
    let pool = db!();
    let name = unique("probe").replace('-', "_").to_lowercase();
    let at = OffsetDateTime::now_utc();

    SettingRepo::put(&pool, &name, "first", None, at)
        .await
        .unwrap();
    let found = SettingRepo::all(&pool).await.unwrap();
    let one = found
        .iter()
        .find(|setting| setting.name == name)
        .expect("the setting is there");
    assert_eq!(one.value, "first");
    assert_eq!(one.changed_by, None);

    // Setting it again replaces the value rather than adding a second row,
    // and the time and the hand move with it.
    let later = at + time::Duration::minutes(5);
    SettingRepo::put(&pool, &name, "second", None, later)
        .await
        .unwrap();
    let found = SettingRepo::all(&pool).await.unwrap();
    let mine: Vec<_> = found
        .iter()
        .filter(|setting| setting.name == name)
        .collect();
    assert_eq!(mine.len(), 1, "one row per setting");
    assert_eq!(mine[0].value, "second");
    assert!(mine[0].changed_at > at);

    // A name the panel would never use is refused by the database rather than
    // stored and puzzled over later.
    assert!(
        SettingRepo::put(&pool, "Not A Name", "x", None, at)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_links_change_landing_mid_send_is_sent_again() {
    let pool = db!();
    let client = a_client(&pool).await;
    let at = OffsetDateTime::now_utc();
    let mine = |due: Vec<Outgoing>| -> Vec<Outgoing> {
        due.into_iter()
            .filter(|one| one.client_id == client.id())
            .collect()
    };

    BotRepo::queue_links(&pool, client.id(), at).await.unwrap();
    BotRepo::queue_links(&pool, client.id(), at).await.unwrap();
    let read = mine(BotRepo::due(&pool, at, 10_000).await.unwrap());
    assert_eq!(read.len(), 1, "two changes in a row are one message");

    // Another change while that one is on its way to Telegram.
    BotRepo::queue_links(&pool, client.id(), at).await.unwrap();
    BotRepo::done(&pool, read[0].id, read[0].revision)
        .await
        .unwrap();
    let again = mine(BotRepo::due(&pool, at, 10_000).await.unwrap());
    assert_eq!(
        again.len(),
        1,
        "the change that landed mid-send is still to go"
    );

    BotRepo::done(&pool, again[0].id, again[0].revision)
        .await
        .unwrap();
    assert!(mine(BotRepo::due(&pool, at, 10_000).await.unwrap()).is_empty());
}
