use crate::identity::{verify_signature, Identity, IdentityError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpellContract {
    pub contract_version: u16,
    pub contract_id: String,
    pub issuer_public_key: [u8; 32],
    pub action: String,
    pub data_scopes: Vec<String>,
    pub subject_ids: Vec<String>,
    pub max_amount_minor: u64,
    pub max_invocations: u32,
    pub human_approval_required: bool,
    pub reversible: bool,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationRequest<'a> {
    pub action: &'a str,
    pub data_scope: &'a str,
    pub subject_id: &'a str,
    pub amount_minor: u64,
    pub prior_invocations: u32,
    pub human_approved: bool,
    pub now: i64,
}

#[derive(Debug, Error)]
pub enum SpellError {
    #[error("invalid spell contract")]
    Invalid,
    #[error("spell contract is not active")]
    Time,
    #[error("requested action is outside the spell contract")]
    Action,
    #[error("requested data scope is outside the spell contract")]
    DataScope,
    #[error("requested subject is outside the spell contract")]
    Subject,
    #[error("spell budget exceeded")]
    Budget,
    #[error("spell invocation limit exceeded")]
    InvocationLimit,
    #[error("human approval is required")]
    Approval,
    #[error("spell signature verification failed")]
    Signature(#[from] IdentityError),
}

impl SpellContract {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        action: impl Into<String>,
        mut data_scopes: Vec<String>,
        mut subject_ids: Vec<String>,
        max_amount_minor: u64,
        max_invocations: u32,
        human_approval_required: bool,
        reversible: bool,
        issued_at: i64,
        expires_at: i64,
        issuer: &Identity,
    ) -> Result<Self, SpellError> {
        data_scopes.sort();
        data_scopes.dedup();
        subject_ids.sort();
        subject_ids.dedup();
        let mut contract = Self {
            contract_version: 1,
            contract_id: String::new(),
            issuer_public_key: issuer.public_key(),
            action: action.into(),
            data_scopes,
            subject_ids,
            max_amount_minor,
            max_invocations,
            human_approval_required,
            reversible,
            issued_at,
            expires_at,
            signature: Vec::new(),
        };
        contract.validate_shape()?;
        contract.contract_id = format!("spl_{}", blake3::hash(&contract.identity_bytes()).to_hex());
        contract.signature = issuer.sign(&contract.canonical_bytes()).to_vec();
        Ok(contract)
    }

    pub fn verify(&self) -> Result<(), SpellError> {
        self.validate_shape()?;
        if self.contract_id != format!("spl_{}", blake3::hash(&self.identity_bytes()).to_hex()) {
            return Err(SpellError::Invalid);
        }
        verify_signature(
            &self.issuer_public_key,
            &self.canonical_bytes(),
            &self.signature,
        )?;
        Ok(())
    }

    pub fn authorize(&self, request: &InvocationRequest<'_>) -> Result<(), SpellError> {
        self.verify()?;
        if request.now < self.issued_at || request.now > self.expires_at {
            return Err(SpellError::Time);
        }
        if request.action != self.action {
            return Err(SpellError::Action);
        }
        if !self
            .data_scopes
            .iter()
            .any(|scope| scope == request.data_scope)
        {
            return Err(SpellError::DataScope);
        }
        if !self
            .subject_ids
            .iter()
            .any(|subject| subject == request.subject_id)
        {
            return Err(SpellError::Subject);
        }
        if request.amount_minor > self.max_amount_minor {
            return Err(SpellError::Budget);
        }
        if request.prior_invocations >= self.max_invocations {
            return Err(SpellError::InvocationLimit);
        }
        if self.human_approval_required && !request.human_approved {
            return Err(SpellError::Approval);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), SpellError> {
        if self.contract_version != 1
            || self.action.is_empty()
            || self.data_scopes.is_empty()
            || self.subject_ids.is_empty()
            || self.max_invocations == 0
            || self.issued_at < 0
            || self.expires_at <= self.issued_at
            || self.data_scopes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.subject_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(SpellError::Invalid);
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        field(&mut output, b"acm.spell-contract.v1");
        output.extend_from_slice(&self.contract_version.to_be_bytes());
        field(&mut output, &self.issuer_public_key);
        field(&mut output, self.action.as_bytes());
        strings(&mut output, &self.data_scopes);
        strings(&mut output, &self.subject_ids);
        output.extend_from_slice(&self.max_amount_minor.to_be_bytes());
        output.extend_from_slice(&self.max_invocations.to_be_bytes());
        output.push(self.human_approval_required.into());
        output.push(self.reversible.into());
        output.extend_from_slice(&self.issued_at.to_be_bytes());
        output.extend_from_slice(&self.expires_at.to_be_bytes());
        output
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = self.identity_bytes();
        field(&mut output, self.contract_id.as_bytes());
        output
    }
}

fn strings(output: &mut Vec<u8>, values: &[String]) {
    output.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        field(output, value.as_bytes());
    }
}

fn field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>() -> InvocationRequest<'a> {
        InvocationRequest {
            action: "purchase",
            data_scope: "inventory",
            subject_id: "supplier-a",
            amount_minor: 2_500,
            prior_invocations: 0,
            human_approved: true,
            now: 20,
        }
    }

    #[test]
    fn enforces_action_scope_subject_budget_count_approval_and_expiry() {
        let owner = Identity::from_seed([51; 32]);
        let spell = SpellContract::issue(
            "purchase",
            vec!["inventory".into()],
            vec!["supplier-a".into()],
            5_000,
            2,
            true,
            false,
            10,
            30,
            &owner,
        )
        .unwrap();
        spell.authorize(&request()).unwrap();

        let mut rejected = request();
        rejected.human_approved = false;
        assert!(matches!(
            spell.authorize(&rejected),
            Err(SpellError::Approval)
        ));
        rejected = request();
        rejected.amount_minor = 5_001;
        assert!(matches!(
            spell.authorize(&rejected),
            Err(SpellError::Budget)
        ));
        rejected = request();
        rejected.prior_invocations = 2;
        assert!(matches!(
            spell.authorize(&rejected),
            Err(SpellError::InvocationLimit)
        ));
    }

    #[test]
    fn tampering_invalidates_the_contract() {
        let owner = Identity::from_seed([52; 32]);
        let mut spell = SpellContract::issue(
            "read",
            vec!["recipes".into()],
            vec!["self".into()],
            0,
            1,
            false,
            true,
            10,
            30,
            &owner,
        )
        .unwrap();
        spell.action = "delete".into();
        assert!(spell.verify().is_err());
    }
}
