#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineFamily {
    Postgres,
    Mysql,
    Document,
    Columnar,
    Resp,
    Vector,
}

impl EngineFamily {
    pub(crate) const fn is_physical(self) -> bool {
        matches!(self, Self::Resp | Self::Vector)
    }

    pub(crate) const fn is_postgres(self) -> bool {
        matches!(self, Self::Postgres)
    }

    pub(crate) const fn is_mysql(self) -> bool {
        matches!(self, Self::Mysql)
    }

    pub(crate) const fn is_columnar(self) -> bool {
        matches!(self, Self::Columnar)
    }

    pub(crate) const fn is_resp(self) -> bool {
        matches!(self, Self::Resp)
    }

    pub(crate) const fn is_document(self) -> bool {
        matches!(self, Self::Document)
    }

    pub(crate) const fn is_vector(self) -> bool {
        matches!(self, Self::Vector)
    }
}
