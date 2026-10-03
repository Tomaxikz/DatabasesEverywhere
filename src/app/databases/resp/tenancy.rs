use crate::databases::engine::EngineTenancy;

use super::engine::{Redis, Valkey};

impl EngineTenancy for Redis {}

impl EngineTenancy for Valkey {}
