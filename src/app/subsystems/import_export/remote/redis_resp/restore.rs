use super::*;

impl RespConnection {
    /// Relays a binary DUMP response into RESTORE without buffering the serialized value.
    ///
    /// Returns `false` when the source key disappeared before DUMP produced a value.
    pub async fn relay_restore_replace(
        &mut self,
        target: &mut RespConnection,
        key: &[u8],
        expiration: RedisRestoreExpiration,
        max_serialized_length: usize,
    ) -> Result<bool, RedisRelayError> {
        self.write_command(&[b"DUMP", key])
            .await
            .map_err(RedisRelayError::Source)?;

        let source_timeout = self.read_timeout;
        let source_deadline = Instant::now() + source_timeout;
        let serialized_length = timeout_at(
            source_deadline,
            self.read_streaming_bulk_length("DUMP", max_serialized_length),
        )
        .await
        .map_err(|_| source_read_timeout(source_timeout))?
        .map_err(RedisRelayError::Source)?;
        let Some(serialized_length) = serialized_length else {
            return Ok(false);
        };

        let (ttl, use_absolute_ttl) = match expiration {
            RedisRestoreExpiration::Persistent => ("0".to_string(), false),
            RedisRestoreExpiration::AbsoluteUnixMilliseconds(deadline) => {
                (deadline.to_string(), true)
            }
        };
        let argument_lengths = [
            b"RESTORE".len(),
            key.len(),
            ttl.len(),
            serialized_length,
            b"REPLACE".len(),
            b"ABSTTL".len(),
        ];
        let argument_count = if use_absolute_ttl { 6 } else { 5 };
        target
            .validate_restore_command_size(
                &argument_lengths[..argument_count],
                serialized_length,
                max_serialized_length,
            )
            .map_err(RedisRelayError::Target)?;

        let target_timeout = target.write_timeout;
        let target_deadline = Instant::now() + target_timeout;
        timeout_at(
            target_deadline,
            target.write_restore_prefix(key, ttl.as_bytes(), serialized_length, use_absolute_ttl),
        )
        .await
        .map_err(|_| target_write_timeout(target_timeout))?
        .map_err(RedisRelayError::Target)?;

        let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
        let mut remaining = serialized_length;
        while remaining > 0 {
            let chunk_length = remaining.min(buffer.len());
            timeout_at(
                source_deadline,
                self.io.read_exact(&mut buffer[..chunk_length]),
            )
            .await
            .map_err(|_| source_read_timeout(source_timeout))?
            .map_err(|error| RedisRelayError::Source(map_unexpected_eof(error)))?;
            timeout_at(
                target_deadline,
                target.io.write_all(&buffer[..chunk_length]),
            )
            .await
            .map_err(|_| target_write_timeout(target_timeout))?
            .map_err(|error| RedisRelayError::Target(RedisRespError::Io(error)))?;
            remaining -= chunk_length;
        }

        timeout_at(source_deadline, self.read_crlf())
            .await
            .map_err(|_| source_read_timeout(source_timeout))?
            .map_err(RedisRelayError::Source)?;
        timeout_at(target_deadline, async {
            if use_absolute_ttl {
                target
                    .io
                    .write_all(b"\r\n$7\r\nREPLACE\r\n$6\r\nABSTTL\r\n")
                    .await?;
            } else {
                target.io.write_all(b"\r\n$7\r\nREPLACE\r\n").await?;
            }
            target.io.flush().await
        })
        .await
        .map_err(|_| target_write_timeout(target_timeout))?
        .map_err(|error| RedisRelayError::Target(RedisRespError::Io(error)))?;

        target
            .read_expected_simple_response("RESTORE", b"OK")
            .await
            .map_err(RedisRelayError::Target)?;
        Ok(true)
    }

    pub(super) fn validate_restore_command_size(
        &self,
        argument_lengths: &[usize],
        serialized_length: usize,
        max_serialized_length: usize,
    ) -> RedisRespResult<()> {
        if argument_lengths.is_empty() {
            return Err(RedisRespError::InvalidArgument(
                "command must contain at least one argument",
            ));
        }
        if argument_lengths.len() > self.limits.max_array_len {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound array length",
                limit: self.limits.max_array_len,
            });
        }
        if serialized_length > max_serialized_length {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound streamed bulk length",
                limit: max_serialized_length,
            });
        }
        if argument_lengths.iter().enumerate().any(|(index, length)| {
            index != RESTORE_SERIALIZED_VALUE_ARGUMENT_INDEX && *length > self.limits.max_bulk_len
        }) {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound bulk length",
                limit: self.limits.max_bulk_len,
            });
        }
        let encoded_size =
            encoded_command_size(argument_lengths.len(), argument_lengths.iter().copied())?;
        let framing_bytes = encoded_size.checked_sub(serialized_length).ok_or_else(|| {
            RedisRespError::Protocol("streamed command length underflow".to_string())
        })?;
        if framing_bytes > self.limits.max_response_bytes {
            return Err(RedisRespError::LimitExceeded {
                limit_name: "outbound command framing bytes",
                limit: self.limits.max_response_bytes,
            });
        }
        Ok(())
    }

    pub(super) async fn write_restore_prefix(
        &mut self,
        key: &[u8],
        ttl: &[u8],
        serialized_length: usize,
        use_absolute_ttl: bool,
    ) -> RedisRespResult<()> {
        self.io
            .write_all(if use_absolute_ttl {
                b"*6\r\n$7\r\nRESTORE\r\n"
            } else {
                b"*5\r\n$7\r\nRESTORE\r\n"
            })
            .await?;
        self.io
            .write_all(format!("${}\r\n", key.len()).as_bytes())
            .await?;
        self.io.write_all(key).await?;
        self.io.write_all(b"\r\n").await?;
        self.io
            .write_all(format!("${}\r\n", ttl.len()).as_bytes())
            .await?;
        self.io.write_all(ttl).await?;
        self.io.write_all(b"\r\n").await?;
        self.io
            .write_all(format!("${serialized_length}\r\n").as_bytes())
            .await?;
        Ok(())
    }

    pub(super) async fn read_streaming_bulk_length(
        &mut self,
        operation: &'static str,
        max_streaming_bulk_len: usize,
    ) -> RedisRespResult<Option<usize>> {
        let max_response_bytes = max_streaming_bulk_len
            .checked_add(self.limits.max_line_len)
            .and_then(|limit| limit.checked_add(5))
            .ok_or_else(|| {
                RedisRespError::Protocol("streaming response length overflow".to_string())
            })?;
        let mut budget = ParseBudget {
            values_left: self.limits.max_total_values,
            bytes_left: max_response_bytes,
        };
        budget.consume_value(self.limits.max_total_values)?;
        let prefix = self.io.read_u8().await.map_err(map_unexpected_eof)?;
        budget.consume_bytes(1, max_response_bytes)?;
        match prefix {
            b'$' => {
                let line = self
                    .read_line_with_response_limit(&mut budget, max_response_bytes)
                    .await?;
                let length = parse_nullable_length(&line, "bulk string")?;
                let Some(length) = length else {
                    return Ok(None);
                };
                if length > max_streaming_bulk_len {
                    return Err(RedisRespError::LimitExceeded {
                        limit_name: "streaming bulk length",
                        limit: max_streaming_bulk_len,
                    });
                }
                budget.consume_bytes(
                    length.checked_add(2).ok_or_else(|| {
                        RedisRespError::Protocol("bulk string length overflow".to_string())
                    })?,
                    max_response_bytes,
                )?;
                Ok(Some(length))
            }
            b'-' => {
                let message = self
                    .read_line_with_response_limit(&mut budget, max_response_bytes)
                    .await?;
                Err(RedisRespError::Server(
                    String::from_utf8_lossy(&message).into_owned(),
                ))
            }
            b'+' => Err(RedisRespError::UnexpectedResponse {
                operation,
                expected: "bulk string or null",
                actual: "simple string",
            }),
            b':' => Err(RedisRespError::UnexpectedResponse {
                operation,
                expected: "bulk string or null",
                actual: "integer",
            }),
            b'*' => Err(RedisRespError::UnexpectedResponse {
                operation,
                expected: "bulk string or null",
                actual: "array",
            }),
            other => Err(RedisRespError::Protocol(format!(
                "unsupported RESP2 type prefix 0x{other:02x}"
            ))),
        }
    }

    pub(super) async fn read_expected_simple_response(
        &mut self,
        operation: &'static str,
        expected: &'static [u8],
    ) -> RedisRespResult<()> {
        let timeout = self.read_timeout;
        timeout_at(Instant::now() + timeout, async {
            let mut budget = ParseBudget {
                values_left: self.limits.max_total_values,
                bytes_left: self.limits.max_response_bytes,
            };
            budget.consume_value(self.limits.max_total_values)?;
            let prefix = self.io.read_u8().await.map_err(map_unexpected_eof)?;
            budget.consume_bytes(1, self.limits.max_response_bytes)?;
            match prefix {
                b'+' => {
                    let actual = self.read_line(&mut budget).await?;
                    if actual == expected {
                        Ok(())
                    } else {
                        Err(RedisRespError::UnexpectedResponse {
                            operation,
                            expected: "expected simple string",
                            actual: "different simple string",
                        })
                    }
                }
                b'-' => {
                    let message = self.read_line(&mut budget).await?;
                    Err(RedisRespError::Server(
                        String::from_utf8_lossy(&message).into_owned(),
                    ))
                }
                b'$' => Err(RedisRespError::UnexpectedResponse {
                    operation,
                    expected: "expected simple string",
                    actual: "bulk string",
                }),
                b':' => Err(RedisRespError::UnexpectedResponse {
                    operation,
                    expected: "expected simple string",
                    actual: "integer",
                }),
                b'*' => Err(RedisRespError::UnexpectedResponse {
                    operation,
                    expected: "expected simple string",
                    actual: "array",
                }),
                other => Err(RedisRespError::Protocol(format!(
                    "unsupported RESP2 type prefix 0x{other:02x}"
                ))),
            }
        })
        .await
        .map_err(|_| RedisRespError::Timeout {
            operation: "read",
            timeout,
        })?
    }
}
