use super::*;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SensitiveString(pub(super) String);

impl SensitiveString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}
