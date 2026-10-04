use std::{future::Future, pin::Pin};
use tokio::io::AsyncBufReadExt;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Instant, timeout_at},
};

use super::{
    RedisRespError, RedisRespResult, RespConnection, RespValue,
    budget::ParseBudget,
    helpers::{command_encoded_size, map_unexpected_eof, parse_i64, parse_nullable_length},
};

impl RespConnection {
    pub async fn read_response(&mut self) -> RedisRespResult<RespValue> {
        let mut budget = ParseBudget {
            values_left: self.limits.max_total_values,
            bytes_left: self.limits.max_response_bytes,
        };
        let timeout = self.read_timeout;
        timeout_at(Instant::now() + timeout, self.read_value(0, &mut budget))
            .await
            .map_err(|_| RedisRespError::Timeout {
                operation: "read",
                timeout,
            })?
    }

    pub(super) async fn write_command(&mut self, arguments: &[&[u8]]) -> RedisRespResult<()> {
        if arguments.is_empty() {
            return Err(RedisRespError::InvalidArgument(
                "command must contain at least one argument",
            ));
        }
        if arguments.len() > self.limits.max_array_len {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound array length",
                limit: self.limits.max_array_len,
            });
        }
        if arguments
            .iter()
            .any(|argument| argument.len() > self.limits.max_bulk_len)
        {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound bulk length",
                limit: self.limits.max_bulk_len,
            });
        }
        let encoded_size = command_encoded_size(arguments)?;
        if encoded_size > self.limits.max_response_bytes {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound command bytes",
                limit: self.limits.max_response_bytes,
            });
        }

        let timeout = self.write_timeout;
        timeout_at(Instant::now() + timeout, async {
            self.io
                .write_all(format!("*{}\r\n", arguments.len()).as_bytes())
                .await?;
            for argument in arguments {
                self.io
                    .write_all(format!("${}\r\n", argument.len()).as_bytes())
                    .await?;
                self.io.write_all(argument).await?;
                self.io.write_all(b"\r\n").await?;
            }
            self.io.flush().await
        })
        .await
        .map_err(|_| RedisRespError::Timeout {
            operation: "write",
            timeout,
        })??;
        Ok(())
    }

    pub(super) fn read_value<'a>(
        &'a mut self,
        depth: usize,
        budget: &'a mut ParseBudget,
    ) -> Pin<Box<dyn Future<Output = RedisRespResult<RespValue>> + Send + 'a>> {
        Box::pin(async move {
            if depth > self.limits.max_nesting {
                return Err(RedisRespError::LimitExceeded {
                    limit_name: "nesting depth",
                    limit: self.limits.max_nesting,
                });
            }
            budget.consume_value(self.limits.max_total_values)?;

            let prefix = self.io.read_u8().await.map_err(map_unexpected_eof)?;
            budget.consume_bytes(1, self.limits.max_response_bytes)?;
            match prefix {
                b'+' => {
                    let line = self.read_line(budget).await?;
                    Ok(RespValue::Simple(line))
                }
                b'-' => {
                    let line = self.read_line(budget).await?;
                    Ok(RespValue::Error(line))
                }
                b':' => {
                    let line = self.read_line(budget).await?;
                    Ok(RespValue::Integer(parse_i64(&line, "integer")?))
                }
                b'$' => {
                    let line = self.read_line(budget).await?;
                    let length = parse_nullable_length(&line, "bulk string")?;
                    let Some(length) = length else {
                        return Ok(RespValue::Bulk(None));
                    };
                    if length > self.limits.max_bulk_len {
                        return Err(RedisRespError::LimitExceeded {
                            limit_name: "bulk length",
                            limit: self.limits.max_bulk_len,
                        });
                    }
                    budget.consume_bytes(
                        length.checked_add(2).ok_or_else(|| {
                            RedisRespError::Protocol("bulk string length overflow".to_string())
                        })?,
                        self.limits.max_response_bytes,
                    )?;
                    let mut value = vec![0_u8; length];
                    self.io
                        .read_exact(&mut value)
                        .await
                        .map_err(map_unexpected_eof)?;
                    self.read_crlf().await?;
                    Ok(RespValue::Bulk(Some(value)))
                }
                b'*' => {
                    let line = self.read_line(budget).await?;
                    let length = parse_nullable_length(&line, "array")?;
                    let Some(length) = length else {
                        return Ok(RespValue::Array(None));
                    };
                    if length > self.limits.max_array_len {
                        return Err(RedisRespError::LimitExceeded {
                            limit_name: "array length",
                            limit: self.limits.max_array_len,
                        });
                    }
                    let mut values = Vec::with_capacity(length);
                    for _ in 0..length {
                        values.push(self.read_value(depth + 1, budget).await?);
                    }
                    Ok(RespValue::Array(Some(values)))
                }
                other => Err(RedisRespError::Protocol(format!(
                    "unsupported RESP2 type prefix 0x{other:02x}"
                ))),
            }
        })
    }

    pub(super) async fn read_line(&mut self, budget: &mut ParseBudget) -> RedisRespResult<Vec<u8>> {
        let max_response_bytes = self.limits.max_response_bytes;
        self.read_line_with_response_limit(budget, max_response_bytes)
            .await
    }

    pub(super) async fn read_line_with_response_limit(
        &mut self,
        budget: &mut ParseBudget,
        max_response_bytes: usize,
    ) -> RedisRespResult<Vec<u8>> {
        let mut output = Vec::new();
        loop {
            let available = self.io.fill_buf().await.map_err(map_unexpected_eof)?;
            if available.is_empty() {
                return Err(RedisRespError::Protocol(
                    "unexpected EOF while reading RESP line".to_string(),
                ));
            }
            if let Some(cr_index) = available.iter().position(|byte| *byte == b'\r') {
                let prospective = output.len().checked_add(cr_index).ok_or_else(|| {
                    RedisRespError::Protocol("RESP line length overflow".to_string())
                })?;
                if prospective > self.limits.max_line_len {
                    return Err(RedisRespError::LimitExceeded {
                        limit_name: "line length",
                        limit: self.limits.max_line_len,
                    });
                }
                output.extend_from_slice(&available[..cr_index]);
                self.io.consume(cr_index + 1);
                budget.consume_bytes(cr_index + 1, max_response_bytes)?;
                let newline = self.io.read_u8().await.map_err(map_unexpected_eof)?;
                budget.consume_bytes(1, max_response_bytes)?;
                if newline != b'\n' {
                    return Err(RedisRespError::Protocol(
                        "RESP line was not terminated by CRLF".to_string(),
                    ));
                }
                return Ok(output);
            }

            let chunk_length = available.len();
            let prospective = output
                .len()
                .checked_add(chunk_length)
                .ok_or_else(|| RedisRespError::Protocol("RESP line length overflow".to_string()))?;
            if prospective > self.limits.max_line_len {
                return Err(RedisRespError::LimitExceeded {
                    limit_name: "line length",
                    limit: self.limits.max_line_len,
                });
            }
            output.extend_from_slice(available);
            self.io.consume(chunk_length);
            budget.consume_bytes(chunk_length, max_response_bytes)?;
        }
    }

    pub(super) async fn read_crlf(&mut self) -> RedisRespResult<()> {
        let mut delimiter = [0_u8; 2];
        self.io
            .read_exact(&mut delimiter)
            .await
            .map_err(map_unexpected_eof)?;
        if delimiter != *b"\r\n" {
            return Err(RedisRespError::Protocol(
                "bulk string was not terminated by CRLF".to_string(),
            ));
        }
        Ok(())
    }
}
