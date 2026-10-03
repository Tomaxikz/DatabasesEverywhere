use super::*;

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

    pub(super) fn allows_progress(
        &self,
        instance_id: &str,
        instance_generation: Option<&str>,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Selected(_) => {
                instance_generation.is_some_and(|generation| self.allows(instance_id, generation))
            }
        }
    }

    pub(super) async fn metadata(
        &self,
        instances: &crate::instance::state::InstanceStore,
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
    let mut generations = Vec::with_capacity(claims.instances.len());
    for instance_id in &claims.instances {
        if !seen.insert(instance_id) {
            return Err(ApiError::Unauthorized);
        }
        let metadata = state
            .instances
            .get(instance_id)
            .await
            .ok_or(ApiError::Unauthorized)?;
        generations.push((instance_id.clone(), metadata.created_at));
    }
    InstanceAuthorization::selected(claims, generations)
}
