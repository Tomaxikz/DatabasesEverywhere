use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

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

pub(super) fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Runs `command` in container `name` with `MYSQL_PWD` set, feeding `input`
/// to its stdin.
pub(super) fn exec_mysql_family_with_input(
    name: &str,
    password: &str,
    command: &[&str],
    input: &[u8],
) -> Output {
    let mut child = Command::new("docker")
        .args(["exec", "-i", "-e", &format!("MYSQL_PWD={password}"), name])
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start database client");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("write database client input");
    child.wait_with_output().expect("wait for database client")
}
