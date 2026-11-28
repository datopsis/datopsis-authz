//! Slice 4c adversarial review: each test asserts the REQUIRED secure behaviour.
//! A failing test is a finding for owner triage, not a test to relax.
//! Run with: cargo test -p authz-core -- --ignored adversarial
use super::*;

fn table(id: &str) -> Resource {
    Resource::new("Table", id)
}
fn check(principal: &str, groups: &[&str], action: &str, resource: Resource) -> Check {
    Check {
        deny: false,
        principal: principal.into(),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        action: action.into(),
        resource,
    }
}
fn grant(subject: Resource, resource: Resource, access: &str) -> Mutation {
    Mutation::Grant {
        grant: Grant {
            subject,
            resource,
            access: access.into(),
        },
        remove: false,
    }
}
/// Evaluation errors fail closed (the service answers 503), so only an Ok
/// permit counts as access.
fn permits(s: &Store, c: &Check) -> bool {
    s.decide(c).is_ok_and(|v| v.allowed)
}
/// Two teams, each owning a namespace with one table, in one warehouse.
fn two_teams() -> Store {
    let mut s = Store::default();
    let warehouse = Resource::new("Warehouse", "wh");
    for team in ["a", "b"] {
        let ns = Resource::new("Namespace", format!("ns-{team}"));
        s.mutate(Mutation::Put {
            resource: ns.clone(),
            parent: Some(warehouse.clone()),
            owner: None,
        })
        .unwrap();
        s.mutate(Mutation::Put {
            resource: table(&format!("t-{team}")),
            parent: Some(ns.clone()),
            owner: None,
        })
        .unwrap();
        s.mutate(grant(
            Resource::new("Group", format!("team-{team}")),
            ns,
            "select",
        ))
        .unwrap();
    }
    s
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_cross_team_reads_writes_and_metadata_deny() -> Result<()> {
    let s = two_teams();
    let a = |action: &str, r: Resource| check("oidc~alice", &["team-a"], action, r);
    assert!(s.decide(&a("read_data", table("t-a")))?.allowed);
    for action in [
        "read_data",
        "get_metadata",
        "include_in_list",
        "write_data",
        "drop",
        "manage_grants",
    ] {
        assert!(
            !s.decide(&a(action, table("t-b")))?.allowed,
            "team A must not {action} team B's table"
        );
    }
    for action in [
        "list_tables",
        "include_in_list",
        "create_table",
        "manage_grants",
    ] {
        assert!(
            !s.decide(&a(action, Resource::new("Namespace", "ns-b")))?
                .allowed,
            "team A must not {action} team B's namespace"
        );
    }
    // A select grant never authorizes writes or grant management on its own data.
    for action in [
        "write_data",
        "commit",
        "drop",
        "rename",
        "manage_grants",
        "create_table",
        "undrop",
    ] {
        assert!(
            !s.decide(&a(action, table("t-a")))?.allowed,
            "select grant must not permit {action}"
        );
    }
    // Asserted groups that the principal does not hold are the caller's job to
    // drop; the decision itself must not invent membership from the principal name.
    assert!(
        !s.decide(&check("team-b", &[], "read_data", table("t-b")))?
            .allowed
    );
    Ok(())
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_identifier_tricks_do_not_alias_resources() -> Result<()> {
    let mut s = Store::default();
    let ns = Resource::new("Namespace", "Sales");
    s.mutate(Mutation::Put {
        resource: table("orders"),
        parent: Some(ns.clone()),
        owner: None,
    })?;
    s.mutate(grant(Resource::new("User", "oidc~alice"), ns, "select"))?;
    assert!(
        s.decide(&check("oidc~alice", &[], "read_data", table("orders")))?
            .allowed
    );
    // Case, Unicode look-alikes, separators, quoting and Cedar syntax in IDs are
    // distinct opaque identifiers; none may reach the granted table or namespace.
    for id in [
        "ORDERS",
        "orders ",
        "orders\0",
        "ord\u{0435}rs",
        "Sales.orders",
        "Sales\u{1f}orders",
        "orders\" || true || \"",
        "orders\\",
        "*",
        "",
    ] {
        assert!(
            !permits(&s, &check("oidc~alice", &[], "read_data", table(id))),
            "{id:?} aliased a granted table"
        );
    }
    for principal in [
        "oidc~ALICE",
        "oidc~alice\n",
        "alice",
        "oidc~alice~",
        "oidc~",
    ] {
        assert!(
            !permits(&s, &check(principal, &[], "read_data", table("orders"))),
            "{principal:?} aliased oidc~alice"
        );
    }
    // A User and a Group with the same identifier are different subjects.
    assert!(
        !s.decide(&check(
            "oidc~bob",
            &["oidc~alice"],
            "read_data",
            table("orders")
        ))?
        .allowed
    );
    Ok(())
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_policy_text_injection_in_ids_is_inert() -> Result<()> {
    let mut s = Store::default();
    s.mutate(Mutation::Put {
        resource: table("victim"),
        parent: None,
        owner: None,
    })?;
    // IDs are embedded in generated Cedar text. An attacker-chosen subject ID that
    // tries to close the string and widen the scope must stay a literal.
    for id in [
        "x\"}, action, resource) when { true }; permit(principal, action, resource",
        "x\" || principal == principal || \"",
        "x\\\" in Group::\"admins",
    ] {
        s.mutate(grant(Resource::new("User", id), table("other"), "select"))?;
    }
    let verdict = s.decide(&check("oidc~mallory", &[], "read_data", table("victim")))?;
    assert!(
        !verdict.allowed && verdict.policies.is_empty(),
        "{verdict:?}"
    );
    Ok(())
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_one_unrepresentable_grant_cannot_deny_service_to_everyone() -> Result<()> {
    // Any owner can choose a grant subject through the grant-management API.
    // A subject ID Cedar cannot parse after JSON escaping (control characters
    // such as U+0001 become `\u0001`, which is not a Cedar escape) must either be
    // rejected at mutation time or be ignored; it must not turn every subsequent
    // decision for every principal into an evaluation error (platform-wide outage).
    let mut s = two_teams();
    let before = s.decide(&check("oidc~alice", &["team-a"], "read_data", table("t-a")))?;
    assert!(before.allowed);
    let hostile = grant(Resource::new("User", "x\u{1}y"), table("t-b"), "select");
    let _accepted = s.mutate(hostile).is_ok();
    let after = s.decide(&check("oidc~alice", &["team-a"], "read_data", table("t-a")));
    assert!(
        after.as_ref().is_ok_and(|v| v.allowed),
        "an unrelated owner's grant made every decision fail: {after:?}"
    );
    Ok(())
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_grant_mutation_rejects_unsupported_shapes() {
    let mut s = two_teams();
    let bad = [
        grant(Resource::new("Server", "srv"), table("t-a"), "select"),
        grant(Resource::new("Role", "r"), table("t-a"), "select"),
        grant(
            Resource::new("User", "u"),
            Resource::new("User", "v"),
            "owner",
        ),
        grant(
            Resource::new("User", "u"),
            Resource::new("Group", "g"),
            "owner",
        ),
        grant(Resource::new("User", "u"), table("t-a"), "OWNER"),
        grant(Resource::new("User", "u"), table("t-a"), "write"),
        grant(Resource::new("User", "u"), table("t-a"), ""),
    ];
    for m in bad {
        let text = format!("{m:?}");
        assert!(s.mutate(m).is_err(), "accepted {text}");
    }
    // Hierarchy kinds and parent types are restricted, and cycles refused.
    for (resource, parent) in [
        (table("t-a"), Some(table("t-b"))),
        (Resource::new("User", "u"), None),
        (Resource::new("Group", "g"), None),
        (Resource::new("Namespace", "ns-a"), Some(table("t-a"))),
    ] {
        assert!(
            s.mutate(Mutation::Put {
                resource,
                parent,
                owner: None
            })
            .is_err()
        );
    }
    let ns = |id: &str| Resource::new("Namespace", id);
    s.mutate(Mutation::Put {
        resource: ns("child"),
        parent: Some(ns("ns-a")),
        owner: None,
    })
    .unwrap();
    assert!(
        s.mutate(Mutation::Put {
            resource: ns("ns-a"),
            parent: Some(ns("child")),
            owner: None
        })
        .is_err(),
        "namespace cycle accepted"
    );
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_upward_discovery_never_grants_data_or_management() -> Result<()> {
    let mut s = Store::default();
    let wh = Resource::new("Warehouse", "wh");
    let ns = Resource::new("Namespace", "ns");
    s.mutate(Mutation::Put {
        resource: ns.clone(),
        parent: Some(wh.clone()),
        owner: None,
    })?;
    s.mutate(Mutation::Put {
        resource: table("mine"),
        parent: Some(ns.clone()),
        owner: None,
    })?;
    s.mutate(Mutation::Put {
        resource: table("sibling"),
        parent: Some(ns.clone()),
        owner: None,
    })?;
    // An OWNER of one table may discover its ancestors, nothing more.
    s.mutate(grant(
        Resource::new("User", "oidc~o"),
        table("mine"),
        "owner",
    ))?;
    let o = |action: &str, r: Resource| check("oidc~o", &[], action, r);
    assert!(s.decide(&o("include_in_list", ns.clone()))?.allowed);
    assert!(s.decide(&o("manage_grants", table("mine")))?.allowed);
    for action in [
        "manage_grants",
        "create_table",
        "drop",
        "read_data",
        "list_tables",
    ] {
        assert!(
            !s.decide(&o(action, ns.clone()))?.allowed,
            "table owner gained {action} on its namespace"
        );
        assert!(
            !s.decide(&o(action, wh.clone()))?.allowed,
            "table owner gained {action} on its warehouse"
        );
    }
    for action in [
        "read_data",
        "get_metadata",
        "include_in_list",
        "manage_grants",
    ] {
        assert!(
            !s.decide(&o(action, table("sibling")))?.allowed,
            "table owner gained {action} on a sibling"
        );
    }
    // Exception grants never imply reads, discovery or management.
    s.mutate(grant(
        Resource::new("User", "oidc~u"),
        table("sibling"),
        "unmask",
    ))?;
    s.mutate(grant(
        Resource::new("User", "oidc~u"),
        table("sibling"),
        "unrestricted_rows",
    ))?;
    for action in [
        "read_data",
        "include_in_list",
        "manage_grants",
        "write_data",
    ] {
        assert!(
            !s.decide(&check("oidc~u", &[], action, table("sibling")))?
                .allowed
        );
    }
    assert!(
        !s.decide(&check("oidc~u", &[], "include_in_list", ns))?
            .allowed
    );
    Ok(())
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_revocation_detach_and_delete_take_effect_immediately() -> Result<()> {
    let mut s = two_teams();
    let alice = check("oidc~alice", &["team-a"], "read_data", table("t-a"));
    assert!(s.decide(&alice)?.allowed);
    // Group removal (the caller supplies live groups) denies the old principal.
    assert!(
        !s.decide(&check("oidc~alice", &[], "read_data", table("t-a")))?
            .allowed
    );
    // Detaching a table from its namespace drops inherited grants.
    s.mutate(Mutation::Put {
        resource: table("t-a"),
        parent: None,
        owner: None,
    })?;
    assert!(!s.decide(&alice)?.allowed);
    // Re-attaching under team B's namespace must not keep team A's access.
    s.mutate(Mutation::Put {
        resource: table("t-a"),
        parent: Some(Resource::new("Namespace", "ns-b")),
        owner: None,
    })?;
    assert!(!s.decide(&alice)?.allowed);
    // Deleting a user removes its direct grants, so a recycled ID starts empty.
    s.mutate(grant(
        Resource::new("User", "oidc~carol"),
        table("t-b"),
        "owner",
    ))?;
    s.mutate(Mutation::Delete {
        resource: Resource::new("User", "oidc~carol"),
    })?;
    assert!(
        !s.decide(&check("oidc~carol", &[], "read_data", table("t-b")))?
            .allowed
    );
    // Deleting a namespace removes the grants defined on it.
    s.mutate(Mutation::Delete {
        resource: Resource::new("Namespace", "ns-b"),
    })?;
    assert!(
        s.grants
            .iter()
            .all(|g| g.resource != Resource::new("Namespace", "ns-b"))
    );
    Ok(())
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_denied_and_anonymous_checks_never_permit() -> Result<()> {
    let mut s = two_teams();
    s.mutate(grant(Resource::new("User", ""), table("t-a"), "owner"))?;
    let mut c = check("", &["team-a"], "read_data", table("t-a"));
    assert!(!s.decide(&c)?.allowed, "empty principal permitted");
    c.principal = "oidc~alice".into();
    c.deny = true;
    assert!(!s.decide(&c)?.allowed, "explicit deny ignored");
    // read_self only ever matches the exact principal.
    for id in ["oidc~alice ", "OIDC~alice", "oidc~bob"] {
        assert!(
            !s.decide(&check(
                "oidc~alice",
                &[],
                "read_self",
                Resource::new("User", id)
            ))?
            .allowed
        );
    }
    Ok(())
}
