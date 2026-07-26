use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MILLI_PER_GIB_HOUR: i64 = 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditReason {
    MonthlyBaseGrant,
    AuditedStorageEarned,
    ReplicatedStorageConsumed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditEntry {
    pub idempotency_key: String,
    pub milli_gib_hour: i64,
    pub reason: CreditReason,
    pub occurred_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Error)]
pub enum CreditError {
    #[error("credit arithmetic overflow")]
    Overflow,
    #[error("credit entry already exists")]
    Duplicate,
    #[error("invalid credit input")]
    Invalid,
}

#[derive(Default)]
pub struct CreditLedger {
    entries: Vec<CreditEntry>,
}

impl CreditLedger {
    pub fn record(&mut self, entry: CreditEntry) -> Result<(), CreditError> {
        if entry.idempotency_key.is_empty()
            || self
                .entries
                .iter()
                .any(|existing| existing.idempotency_key == entry.idempotency_key)
        {
            return Err(if entry.idempotency_key.is_empty() {
                CreditError::Invalid
            } else {
                CreditError::Duplicate
            });
        }
        self.balance_at(entry.occurred_at)?
            .checked_add(entry.milli_gib_hour)
            .ok_or(CreditError::Overflow)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn balance_at(&self, now: i64) -> Result<i64, CreditError> {
        self.entries
            .iter()
            .filter(|entry| entry.expires_at.is_none_or(|expiry| expiry > now))
            .try_fold(0_i64, |sum, entry| {
                sum.checked_add(entry.milli_gib_hour)
                    .ok_or(CreditError::Overflow)
            })
    }

    pub fn monthly_base_grant() -> i64 {
        5 * 3 * 30 * 24 * MILLI_PER_GIB_HOUR
    }

    pub fn physical_storage_cost(
        bytes: u64,
        replicas: u32,
        seconds: u64,
    ) -> Result<i64, CreditError> {
        if replicas == 0 {
            return Err(CreditError::Invalid);
        }
        let numerator = (bytes as u128)
            .checked_mul(replicas as u128)
            .and_then(|value| value.checked_mul(seconds as u128))
            .and_then(|value| value.checked_mul(MILLI_PER_GIB_HOUR as u128))
            .ok_or(CreditError::Overflow)?;
        let denominator = (1024_u128.pow(3)) * 3600;
        i64::try_from(numerator.div_ceil(denominator)).map_err(|_| CreditError::Overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_integer_replica_aware_arithmetic_and_expiry() {
        assert_eq!(CreditLedger::monthly_base_grant(), 10_800_000);
        assert_eq!(
            CreditLedger::physical_storage_cost(1024_u64.pow(3), 3, 3600).unwrap(),
            3000
        );
        let mut ledger = CreditLedger::default();
        ledger
            .record(CreditEntry {
                idempotency_key: "grant-1".into(),
                milli_gib_hour: 5000,
                reason: CreditReason::AuditedStorageEarned,
                occurred_at: 10,
                expires_at: Some(20),
            })
            .unwrap();
        assert_eq!(ledger.balance_at(19).unwrap(), 5000);
        assert_eq!(ledger.balance_at(20).unwrap(), 0);
        assert!(matches!(
            ledger.record(CreditEntry {
                idempotency_key: "grant-1".into(),
                milli_gib_hour: 1,
                reason: CreditReason::AuditedStorageEarned,
                occurred_at: 11,
                expires_at: None,
            }),
            Err(CreditError::Duplicate)
        ));
    }
}
