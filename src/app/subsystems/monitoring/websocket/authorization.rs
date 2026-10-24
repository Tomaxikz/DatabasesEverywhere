use crate::auth::jwt;
use crate::auth::jwt::Claims;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::server::metadata::InstanceMetadata;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub(super) enum InstanceAuthorization {
    All,
    Selected(HashMap<String, String>),
}

impl InstanceAuthorization {
    pub(super) fn selected(
        claims: &Claims,
        generations: Vec<(String, String)>,
    ) -> Result<Self, ApiError> {
        let Some(expected_digest) = claims.instance_generation_digest.as_deref() else {
            return Err(ApiError::Unauthorized);
        };
        if generations.len() != claims.instances.len()
            || jwt::instance_generation_digest(&generations) != expected_digest
        {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self::Selected(generations.into_iter().collect()))
    }

    pub(super) fn allows(&self, instance_id: &str, instance_generation: &str) -> bool {
        match self {
            Self::All => true,
            Self::Selected(instances) => instances
                .get(instance_id)
                .is_some_and(|allowed| allowed == instance_generation),
        }
    }

    /// Progress is visible for the stored instance the token binds, or for
    /// the creation attempt it binds, including that attempt's final record.
    pub(super) fn allows_progress(
        &self,
        progress: &crate::subsystems::instances::progress::InstallProgress,
        instance_generation: Option<&str>,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Selected(_) => {
                instance_generation
                    .is_some_and(|generation| self.allows(&progress.instance_id, generation))
                    || progress
                        .creation_generation()
                        .is_some_and(|generation| self.allows(&progress.instance_id, &generation))
            }
        }
    }

    /// The instance IDs a selective token names.
    pub(super) fn selected_ids(&self) -> Vec<&str> {
        match self {
            Self::All => Vec::new(),
            Self::Selected(selected) => selected.keys().map(String::as_str).collect(),
        }
    }

    pub(super) async fn metadata(
        &self,
        instances: &crate::server::state::InstanceStore,
    ) -> Vec<InstanceMetadata> {
        match self {
            Self::All => instances.list().await,
            Self::Selected(selected) => {
                let mut metadata = Vec::with_capacity(selected.len());
                for (instance_id, generation) in selected {
                    if let Some(instance) = instances
                        .get(instance_id)
                        .await
                        .filter(|instance| instance.created_at == *generation)
                    {
                        metadata.push(instance);
                    }
                }
                metadata
            }
        }
    }
}

/// Generations a WebSocket token may bind for `instance_id`: the stored
/// instance's `created_at`, and the attempt of a creation that is running or
/// just finished. Either may be absent.
pub(crate) struct BindableGenerations {
    pub stored: Option<String>,
    pub creating: Option<String>,
}

impl BindableGenerations {
    pub(crate) async fn of(state: &AppState, instance_id: &str) -> Self {
        Self {
            stored: state
                .instances
                .get(instance_id)
                .await
                .map(|metadata| metadata.created_at),
            creating: state
                .install_progress
                .get(instance_id)
                .and_then(|progress| progress.creation_generation()),
        }
    }

    /// What a newly minted token binds to: the stored instance when it exists.
    pub(crate) fn preferred(self) -> Option<String> {
        self.stored.or(self.creating)
    }
}

pub(super) async fn resolve_instance_authorization(
    state: &AppState,
    claims: &Claims,
) -> Result<InstanceAuthorization, ApiError> {
    if claims.all_instances {
        return if claims.instances.is_empty() && claims.instance_generation_digest.is_none() {
            Ok(InstanceAuthorization::All)
        } else {
            Err(ApiError::Unauthorized)
        };
    }

    let mut seen = HashSet::with_capacity(claims.instances.len());
    let mut stored_first = Vec::with_capacity(claims.instances.len());
    let mut creating_first = Vec::with_capacity(claims.instances.len());
    for instance_id in &claims.instances {
        if !seen.insert(instance_id) {
            return Err(ApiError::Unauthorized);
        }
        let generations = BindableGenerations::of(state, instance_id).await;
        let creating = generations.creating.clone().or(generations.stored.clone());
        let stored = generations.preferred().ok_or(ApiError::Unauthorized)?;
        stored_first.push((instance_id.clone(), stored));
        creating_first.push((instance_id.clone(), creating.unwrap_or_default()));
    }
    // A token minted during a creation stays valid for that attempt even when
    // the instance was stored before the socket connected.
    InstanceAuthorization::selected(claims, stored_first)
        .or_else(|_| InstanceAuthorization::selected(claims, creating_first))
}
