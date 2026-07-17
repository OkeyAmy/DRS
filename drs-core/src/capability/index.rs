use std::collections::HashMap;

/// Capability index built at delegation issuance time.
///
/// Implements the corrected O(1) lookup algorithm from `docs/Drs_language&algorithms.md`
/// Correction 1. Building the index is O(n log n) (happens once at issuance).
/// Lookup is O(1) for exact matches, O(k) for wildcard patterns where k is
/// typically 2–5. In practice this is O(1).
///
/// The v2 O(n·m) loop (iterating all parent caps for each child cap) is NOT used.
pub struct CapabilityIndex {
    /// Exact resource → allowed tools/abilities
    exact: HashMap<String, Vec<String>>,
    /// Namespace prefix → allowed tools/abilities (sorted by length descending for longest-match)
    prefix: Vec<(String, Vec<String>)>,
    /// Whether a universal `"*"` resource grant is present
    universal: bool,
}

impl CapabilityIndex {
    /// Builds the index from a list of allowed resources and tools.
    ///
    /// `resources` — strings like `"mcp://tools/web_search"`, `"mcp://tools/*"`, or `"*"`
    /// `tools`     — strings like `"web_search"`, `"*"`
    ///
    /// Called once at delegation creation.
    pub fn build(resources: &[String], tools: &[String]) -> Self {
        let mut exact: HashMap<String, Vec<String>> = HashMap::new();
        let mut prefix: Vec<(String, Vec<String>)> = Vec::new();
        let mut universal = false;

        for resource in resources {
            if resource == "*" {
                universal = true;
                continue;
            }
            if resource.ends_with("/*") {
                let ns = resource[..resource.len() - 1].to_string(); // strip trailing '*'
                prefix.push((ns, tools.to_vec()));
            } else {
                exact
                    .entry(resource.clone())
                    .or_default()
                    .extend(tools.iter().cloned());
            }
        }

        // Longest-match first: a more specific prefix wins over a shorter one
        prefix.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        CapabilityIndex {
            exact,
            prefix,
            universal,
        }
    }

    /// Returns `true` if `(resource, tool)` is covered by this index.
    ///
    /// Lookup order:
    /// 1. Universal grant (`"*"`) — O(1)
    /// 2. Exact resource match — O(1) HashMap lookup
    /// 3. Longest prefix match — O(k) where k = number of wildcard patterns
    pub fn covers(&self, resource: &str, tool: &str) -> bool {
        if self.universal {
            return true;
        }

        // An exact resource entry is the most specific match and is authoritative:
        // if the resource has an exact entry, the decision is whatever that entry
        // says about the tool. Falling through to the broader prefix loop here
        // would let a permissive prefix grant override a deliberately restrictive
        // exact entry for the same resource.
        if let Some(tools) = self.exact.get(resource) {
            return tool_covered(tool, tools);
        }

        for (ns_prefix, tools) in &self.prefix {
            if resource.starts_with(ns_prefix.as_str()) {
                return tool_covered(tool, tools);
            }
        }

        false
    }
}

fn tool_covered(child: &str, parent_tools: &[String]) -> bool {
    parent_tools.iter().any(|p| {
        p == "*" || p == child || (p.ends_with("/*") && child.starts_with(&p[..p.len() - 1]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_match_covered() {
        let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["search"]));
        assert!(idx.covers("mcp://tools/web_search", "search"));
    }

    #[test]
    fn exact_match_wrong_tool_not_covered() {
        let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["search"]));
        assert!(!idx.covers("mcp://tools/web_search", "write"));
    }

    #[test]
    fn wildcard_resource_covers_prefix() {
        let idx = CapabilityIndex::build(&s(&["mcp://tools/*"]), &s(&["*"]));
        assert!(idx.covers("mcp://tools/web_search", "any_tool"));
        assert!(idx.covers("mcp://tools/file_read", "any_tool"));
    }

    #[test]
    fn wildcard_resource_does_not_cover_outside_prefix() {
        let idx = CapabilityIndex::build(&s(&["mcp://tools/*"]), &s(&["*"]));
        assert!(!idx.covers("mcp://data/secrets", "read"));
    }

    #[test]
    fn universal_grant_covers_everything() {
        let idx = CapabilityIndex::build(&s(&["*"]), &s(&["*"]));
        assert!(idx.covers("anything", "anything"));
        assert!(idx.covers("mcp://tools/web_search", "search"));
    }

    #[test]
    fn escalation_denied_for_unlisted_resource() {
        let idx = CapabilityIndex::build(&s(&["mcp://tools/web_search"]), &s(&["search"]));
        assert!(!idx.covers("mcp://admin/delete_all", "delete"));
    }

    #[test]
    fn empty_index_covers_nothing() {
        let idx = CapabilityIndex::build(&[], &[]);
        assert!(!idx.covers("mcp://tools/web_search", "search"));
    }

    // F-028: a restrictive exact entry must be authoritative. Even if a broader
    // prefix grant would cover the tool, an exact entry for the same resource
    // that does NOT cover the tool must deny — no fall-through to the prefix loop.
    #[test]
    fn exact_entry_is_authoritative_over_prefix() {
        let idx = CapabilityIndex {
            exact: {
                let mut m = HashMap::new();
                m.insert("mcp://tools/database".to_string(), s(&["read"]));
                m
            },
            prefix: vec![("mcp://tools/".to_string(), s(&["*"]))],
            universal: false,
        };
        // Exact entry allows only "read" — "drop_table" must be denied despite the
        // prefix entry granting "*" for the same namespace.
        assert!(idx.covers("mcp://tools/database", "read"));
        assert!(!idx.covers("mcp://tools/database", "drop_table"));
        // A resource with no exact entry still falls through to the prefix grant.
        assert!(idx.covers("mcp://tools/other", "anything"));
    }
}
