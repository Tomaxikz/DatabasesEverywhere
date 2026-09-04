use std::process::Command;

/// Removes an integration-test container even when its test panics.
pub(super) struct DockerContainer {
    name: String,
}

impl DockerContainer {
    pub(super) fn started(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl Drop for DockerContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", &self.name])
            .output();
    }
}
