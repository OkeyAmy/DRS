use drs_core::capability::index::CapabilityIndex;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Integration tests for CapabilityIndex O(1) lookup.

#[test]
fn exact_resource_and_tool_covered() {
    let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["search"]));
    assert!(idx.covers("mcp://tools/web_search", "search"));
}

#[test]
fn exact_resource_wrong_tool_not_covered() {
    let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["search"]));
    assert!(!idx.covers("mcp://tools/web_search", "write"));
}

#[test]
fn exact_resource_wrong_resource_not_covered() {
    let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["search"]));
    assert!(!idx.covers("mcp://tools/file_read", "search"));
}

#[test]
fn wildcard_resource_covers_any_uri_under_prefix() {
    let idx = CapabilityIndex::build(&s(&["mcp://tools/*"]), &s(&["*"]));
    assert!(idx.covers("mcp://tools/web_search", "anything"));
    assert!(idx.covers("mcp://tools/delete_all", "anything"));
}

#[test]
fn wildcard_resource_does_not_cover_outside_prefix() {
    let idx = CapabilityIndex::build(&s(&["mcp://tools/*"]), &s(&["*"]));
    assert!(!idx.covers("mcp://data/secrets", "read"));
    assert!(!idx.covers("mcp://admin/purge", "exec"));
}

#[test]
fn universal_grant_covers_everything() {
    let idx = CapabilityIndex::build(&s(&["*"]), &s(&["*"]));
    assert!(idx.covers("mcp://tools/web_search", "search"));
    assert!(idx.covers("mcp://admin/delete_all", "exec"));
    assert!(idx.covers("anything://at/all", "any_op"));
}

#[test]
fn empty_index_denies_everything() {
    let idx = CapabilityIndex::build(&[], &[]);
    assert!(!idx.covers("mcp://tools/web_search", "search"));
}

#[test]
fn longest_prefix_wins_over_shorter() {
    // More specific prefix should match first
    let idx = CapabilityIndex::build(
        &s(&["mcp://tools/call/*", "mcp://tools/*"]),
        &s(&["web_search"]),
    );
    assert!(idx.covers("mcp://tools/call/web_search", "web_search"));
    assert!(idx.covers("mcp://tools/other_resource", "web_search"));
}

#[test]
fn tool_wildcard_in_parent_covers_any_tool() {
    let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["*"]));
    assert!(idx.covers("mcp://tools/web_search", "any_tool"));
    assert!(idx.covers("mcp://tools/web_search", "another_tool"));
}

#[test]
fn multiple_exact_tools_one_must_match() {
    let idx =
        CapabilityIndex::build(&s(&["mcp://res"]), &s(&["read", "list"]));
    assert!(idx.covers("mcp://res", "read"));
    assert!(idx.covers("mcp://res", "list"));
    assert!(!idx.covers("mcp://res", "delete"));
}

#[test]
fn escalation_to_admin_resource_denied() {
    let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["search"]));
    assert!(!idx.covers("mcp://admin/delete_all", "delete"));
}
