//! Exercised against a real PostgreSQL. Skipped when DATABASE_URL is absent,
//! so a machine without a database still builds and runs the unit tests.

// An integration test is a separate build target, so the relaxations in
// clippy.toml, which cover cfg(test) modules, do not reach it. Failing loudly
// is what a test is for.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ap_core::{
    Access, AccessCommon, AccessState, AnyAccess, Client, ClientState, Credential, Domain,
    Encrypted, KeyStore, Label, Node, NodeKind, NodeState, OpenMethod, Stealth, StealthMethod, Tag,
    TagName,
};
use ap_store::{AccessRepo, AuditRepo, ClientRepo, NodeRepo, StoreError, TagRepo, TrafficRepo};
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
    let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::UNIX_EPOCH);
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
async fn a_domain_belongs_to_one_node_only() {
    let pool = db!();
    let domain = Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap();
    for expected_ok in [true, false] {
        let node = Node::new(
            Label::try_from(unique("n").as_str()).unwrap(),
            NodeKind::FakeTls { domain: domain.clone() },
            OffsetDateTime::UNIX_EPOCH,
        );
        let result = NodeRepo::insert(&pool, &node).await;
        assert_eq!(result.is_ok(), expected_ok, "second node took the domain");
    }
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
        let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::UNIX_EPOCH);
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
        let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::UNIX_EPOCH);
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
        NodeKind::FakeTls {
            domain,
        },
        OffsetDateTime::UNIX_EPOCH,
    );
    NodeRepo::insert(&pool, &node).await.unwrap();

    let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::UNIX_EPOCH);
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
        let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::UNIX_EPOCH)
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
