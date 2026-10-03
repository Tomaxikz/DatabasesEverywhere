use super::*;

#[derive(Debug)]
pub(super) struct ParseBudget {
    pub(super) values_left: usize,
    pub(super) bytes_left: usize,
}

impl ParseBudget {
    pub(super) fn consume_value(&mut self, limit: usize) -> RedisRespResult<()> {
        self.values_left =
            self.values_left
                .checked_sub(1)
                .ok_or(RedisRespError::LimitExceeded {
                    limit_name: "total response values",
                    limit,
                })?;
        Ok(())
    }

    pub(super) fn consume_bytes(&mut self, bytes: usize, limit: usize) -> RedisRespResult<()> {
        self.bytes_left =
            self.bytes_left
                .checked_sub(bytes)
                .ok_or(RedisRespError::LimitExceeded {
                    limit_name: "total response bytes",
                    limit,
                })?;
        Ok(())
    }
}
