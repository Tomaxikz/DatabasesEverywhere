use super::InspectionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SharedSqlIssue {
    CrossDatabase,
    SystemNamespace,
    PrivilegedStatement,
    ExternalAccess,
    UnsupportedStatement,
    AmbiguousStatement,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MysqlCommandPolicyError {
    #[error("shared MySQL-family tenants cannot change database or physical storage layout")]
    StorageEscape,
    #[error("shared MySQL-family tenants cannot execute dynamically prepared SQL")]
    DynamicSql,
    #[error("the shared MySQL-family command could not be validated safely")]
    Invalid,
}

impl From<InspectionError> for MysqlCommandPolicyError {
    fn from(_: InspectionError) -> Self {
        Self::Invalid
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SharedSqlError {
    #[error(transparent)]
    Inspection(#[from] InspectionError),
    #[error("{message}")]
    Rejected {
        issue: SharedSqlIssue,
        message: String,
    },
}

impl SharedSqlError {
    #[cfg(test)]
    pub(super) fn issue(&self) -> Option<SharedSqlIssue> {
        match self {
            Self::Inspection(_) => None,
            Self::Rejected { issue, .. } => Some(*issue),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SharedSqlReport {
    pub(crate) statements_checked: usize,
    pub(crate) namespaces: Vec<String>,
}

#[derive(Debug)]
pub(super) struct ExecutableCommentTooLarge;

impl From<ExecutableCommentTooLarge> for MysqlCommandPolicyError {
    fn from(_: ExecutableCommentTooLarge) -> Self {
        Self::Invalid
    }
}
