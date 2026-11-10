//! Which members of the network the owner added as AI agents. The owner says
//! so when creating the invitation, so the label is the owner's own record,
//! not something the joining program claims about itself. It changes nothing
//! about trust: an agent is a member like any other, reaches only what is
//! shared with it, and is removed on its own. The list is kept in a file
//! beside the network so the label survives a restart.
use std::path::{Path, PathBuf};

/// At most this many agents are labelled; a network holds 32 devices.
const MAX_AGENTS: usize = 64;
/// The largest file read back.
const MAX_FILE: u64 = 16 * 1024;

#[derive(Default)]
pub struct Agents {
    nodes: Vec<String>,
    /// Where the list is kept; none keeps it in memory only.
    file: Option<PathBuf>,
}

impl Agents {
    /// The agents kept at `file`. A missing, oversized or unreadable file
    /// starts an empty list; it is replaced at the next change.
    pub fn open(file: &Path) -> Self {
        let mut nodes: Vec<String> = std::fs::File::open(file)
            .ok()
            .filter(|f| f.metadata().is_ok_and(|m| m.len() <= MAX_FILE))
            .and_then(|f| serde_json::from_reader(f).ok())
            .unwrap_or_default();
        nodes.retain(|node| valid(node));
        nodes.dedup();
        nodes.truncate(MAX_AGENTS);
        Self {
            nodes,
            file: Some(file.to_owned()),
        }
    }

    pub fn contains(&self, node: &str) -> bool {
        self.nodes.iter().any(|known| known == node)
    }

    /// Label `node` as an agent the owner added.
    pub fn add(&mut self, node: &str) {
        if !valid(node) || self.contains(node) {
            return;
        }
        if self.nodes.len() == MAX_AGENTS {
            self.nodes.remove(0);
        }
        self.nodes.push(node.to_owned());
        self.keep();
    }

    /// A member that left takes its label with it.
    pub fn forget(&mut self, node: &str) {
        let before = self.nodes.len();
        self.nodes.retain(|known| known != node);
        if self.nodes.len() != before {
            self.keep();
        }
    }

    /// Write the list beside its file and move it into place, so a crash
    /// leaves the previous list or the new one, never half of one.
    fn keep(&self) {
        let Some(file) = &self.file else { return };
        let written = (|| {
            let partial = file.with_extension("partial");
            std::fs::write(&partial, serde_json::to_vec(&self.nodes)?)?;
            std::fs::rename(&partial, file)?;
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(problem) = written {
            // The label still shows; it would only be lost at a restart.
            eprintln!("The agent labels were not saved: {problem:#}");
        }
    }
}

/// A member's node identity: a short printable token.
fn valid(node: &str) -> bool {
    (1..=128).contains(&node.len()) && node.chars().all(|c| c.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_the_owner_added_stay_labelled_across_a_restart_until_removed() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("agents.json");
        let mut agents = Agents::open(&file);
        assert!(!agents.contains("agent-node"), "No file yet: no agents");
        agents.add("agent-node");
        agents.add("agent-node");
        agents.add("not a node\n");
        // The app ends and starts again.
        let mut reopened = Agents::open(&file);
        assert!(reopened.contains("agent-node"));
        assert!(!reopened.contains("not a node\n"));
        assert!(!reopened.contains("laptop-node"));
        // Removing it from the network takes the label with it, also on disk.
        reopened.forget("agent-node");
        assert!(!Agents::open(&file).contains("agent-node"));
        // A damaged file starts an empty list.
        std::fs::write(&file, b"[not json").unwrap();
        assert!(!Agents::open(&file).contains("agent-node"));
    }
}
