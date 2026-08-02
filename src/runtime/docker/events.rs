use std::{collections::HashMap, pin::Pin, str::FromStr};

use bollard::{models::EventMessage, query_parameters::EventsOptionsBuilder};
use futures::{Stream, StreamExt};

use crate::{
    constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, PROTOCOL_LABEL},
    runtime::docker::{DockerError, DockerRuntime},
    shared::protocol::Protocol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedContainerAction {
    Started,
    Stopped,
    Exited { exit_code: Option<i64> },
    Destroyed,
    OutOfMemory,
    Paused,
    Resumed,
}

impl ManagedContainerAction {
    pub fn activates_container(self) -> bool {
        matches!(self, Self::Started | Self::Resumed)
    }

    pub fn deactivates_container(self) -> bool {
        matches!(
            self,
            Self::Stopped
                | Self::Exited { .. }
                | Self::Destroyed
                | Self::OutOfMemory
                | Self::Paused
        )
    }

    pub fn indicates_unexpected_failure(self) -> bool {
        match self {
            Self::OutOfMemory => true,
            Self::Exited {
                exit_code: Some(code),
            } => code != 0,
            _ => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Stopped => "stopped",
            Self::Exited { .. } => "exited",
            Self::Destroyed => "destroyed",
            Self::OutOfMemory => "out_of_memory",
            Self::Paused => "paused",
            Self::Resumed => "resumed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedContainerEvent {
    pub instance_id: String,
    pub protocol: Protocol,
    pub action: ManagedContainerAction,
}

impl DockerRuntime {
    /// Streams lifecycle transitions for DBE-owned containers. Health-status
    /// events are intentionally ignored: readiness is checked only at startup.
    pub fn managed_container_events(
        &self,
    ) -> Pin<Box<dyn Stream<Item = Result<ManagedContainerEvent, DockerError>> + Send + '_>> {
        let filters = HashMap::from([
            ("type".to_string(), vec!["container".to_string()]),
            ("label".to_string(), vec![format!("{MANAGED_LABEL}=true")]),
        ]);
        let options = EventsOptionsBuilder::default().filters(&filters).build();
        Box::pin(
            self.docker
                .events(Some(options))
                .filter_map(|event| async move {
                    match event {
                        Ok(event) => ManagedContainerEvent::from_message(event).map(Ok),
                        Err(error) => Some(Err(error.into())),
                    }
                }),
        )
    }
}

impl ManagedContainerEvent {
    fn from_message(message: EventMessage) -> Option<Self> {
        let raw_action = message.action?;
        let attributes = message.actor?.attributes?;
        if attributes.get(MANAGED_LABEL).map(String::as_str) != Some("true") {
            return None;
        }
        let instance_id = attributes.get(INSTANCE_LABEL)?.trim();
        if instance_id.is_empty() {
            return None;
        }
        let protocol = Protocol::from_str(attributes.get(PROTOCOL_LABEL)?).ok()?;
        let action = match raw_action.as_str() {
            "start" | "restart" => ManagedContainerAction::Started,
            "stop" => ManagedContainerAction::Stopped,
            "die" | "died" => ManagedContainerAction::Exited {
                exit_code: attributes
                    .get("exitCode")
                    .and_then(|exit_code| exit_code.parse().ok()),
            },
            "destroy" => ManagedContainerAction::Destroyed,
            "oom" => ManagedContainerAction::OutOfMemory,
            "pause" => ManagedContainerAction::Paused,
            "unpause" => ManagedContainerAction::Resumed,
            _ => return None,
        };
        Some(Self {
            instance_id: instance_id.to_string(),
            protocol,
            action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::EventActor;

    fn event(action: &str) -> EventMessage {
        EventMessage {
            action: Some(action.to_string()),
            actor: Some(EventActor {
                attributes: Some(HashMap::from([
                    (MANAGED_LABEL.to_string(), "true".to_string()),
                    (INSTANCE_LABEL.to_string(), "inst_pg_1".to_string()),
                    (PROTOCOL_LABEL.to_string(), "postgres".to_string()),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn parses_managed_lifecycle_events() {
        let parsed = ManagedContainerEvent::from_message(event("die")).unwrap();

        assert_eq!(parsed.instance_id, "inst_pg_1");
        assert_eq!(parsed.protocol, Protocol::Postgres);
        assert_eq!(
            parsed.action,
            ManagedContainerAction::Exited { exit_code: None }
        );
    }

    #[test]
    fn accepts_the_podman_compatibility_exit_spelling() {
        assert!(matches!(
            ManagedContainerEvent::from_message(event("died"))
                .unwrap()
                .action,
            ManagedContainerAction::Exited { .. }
        ));
    }

    #[test]
    fn preserves_nonzero_exit_codes_as_runtime_failures() {
        let mut failed = event("die");
        failed
            .actor
            .as_mut()
            .unwrap()
            .attributes
            .as_mut()
            .unwrap()
            .insert("exitCode".to_string(), "137".to_string());

        let parsed = ManagedContainerEvent::from_message(failed).unwrap();

        assert_eq!(
            parsed.action,
            ManagedContainerAction::Exited {
                exit_code: Some(137)
            }
        );
        assert!(parsed.action.indicates_unexpected_failure());
        assert!(parsed.action.deactivates_container());
    }

    #[test]
    fn ignores_health_and_unmanaged_events() {
        assert!(ManagedContainerEvent::from_message(event("health_status: healthy")).is_none());

        let mut unmanaged = event("start");
        unmanaged
            .actor
            .as_mut()
            .unwrap()
            .attributes
            .as_mut()
            .unwrap()
            .insert(MANAGED_LABEL.to_string(), "false".to_string());
        assert!(ManagedContainerEvent::from_message(unmanaged).is_none());
    }
}
