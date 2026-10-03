use super::*;

pub(super) fn is_rootless_security_option(option: &str) -> bool {
    let option = option.to_ascii_lowercase();
    option == "rootless"
        || option == "name=rootless"
        || option.split(',').any(|part| part.trim() == "rootless")
}

pub(super) fn force_remove_options() -> RemoveContainerOptions {
    RemoveContainerOptions {
        force: true,
        ..Default::default()
    }
}

pub(super) fn report_pull_progress(
    progress: Option<&(dyn Fn(DockerImagePullProgress) + Send + Sync)>,
    image: &str,
    status: &str,
) {
    if let Some(progress) = progress {
        progress(DockerImagePullProgress {
            image: image.to_string(),
            layer: None,
            status: status.to_string(),
            current: None,
            total: None,
        });
    }
}

pub(super) fn managed_container_filters(node_id: &str) -> HashMap<String, Vec<String>> {
    HashMap::from([(
        "label".to_string(),
        vec![
            format!("{MANAGED_LABEL}=true"),
            format!("{NODE_LABEL}={node_id}"),
        ],
    )])
}

pub(super) fn is_owned_managed_container(
    labels: Option<&HashMap<String, String>>,
    node_id: &str,
) -> bool {
    labels.and_then(|labels| labels.get(MANAGED_LABEL).map(String::as_str)) == Some("true")
        && labels.and_then(|labels| labels.get(NODE_LABEL).map(String::as_str)) == Some(node_id)
}

pub(super) fn storage_opt(
    enforce_disk_limits: bool,
    disk_mib: u64,
) -> Option<HashMap<String, String>> {
    if !enforce_disk_limits || disk_mib == 0 {
        return None;
    }
    Some(HashMap::from([(
        "size".to_string(),
        format!("{disk_mib}m"),
    )]))
}

pub(super) fn verify_managed_instance_labels(
    labels: &HashMap<String, String>,
    container: &str,
    protocol: Protocol,
    instance_id: &str,
    expected_node_id: Option<&str>,
) -> Result<(), DockerError> {
    let node_matches = expected_node_id.is_none_or(|expected| {
        labels
            .get(NODE_LABEL)
            .is_none_or(|actual| actual == expected)
    });
    let is_expected = labels.get(MANAGED_LABEL).map(String::as_str) == Some("true")
        && labels.get(INSTANCE_LABEL).map(String::as_str) == Some(instance_id)
        && labels.get(PROTOCOL_LABEL).map(String::as_str) == Some(protocol.as_str())
        && node_matches;
    if is_expected {
        Ok(())
    } else {
        Err(DockerError::UntrustedContainerNameCollision {
            container: container.to_string(),
            instance_id: instance_id.to_string(),
            protocol: protocol.as_str().to_string(),
        })
    }
}
