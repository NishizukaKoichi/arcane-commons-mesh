use anyhow::{ensure, Context, Result};
use arcane_mesh_core::{
    capability::{CapabilityManifest, OfferingKind, RevenueSplit},
    compute::ExecutionAttestation,
    identity::Identity,
    legacy::{LegacyAction, LegacyDirective},
    memory::{MemoryEntry, MemoryGrant, MemoryProvenance, MemoryStatus},
    research::{ResearchRecord, ResearchRecordKind},
    spell::{InvocationRequest, SpellContract},
};
use serde::Serialize;
use std::{fs, path::Path};

#[derive(Serialize)]
struct CommonsReport {
    protocol: &'static str,
    status: &'static str,
    steps: Vec<&'static str>,
    research_record_ids: Vec<String>,
    capability_id: String,
    spell_contract_id: String,
    execution_id: String,
    memory_entry_id: String,
    legacy_directive_id: String,
    allocations_minor: Vec<(String, u64)>,
}

pub fn verify_commons() -> Result<()> {
    let researcher = Identity::from_seed([81; 32]);
    let creator = Identity::from_seed([82; 32]);
    let buyer = Identity::from_seed([83; 32]);
    let executor = Identity::from_seed([84; 32]);

    let hypothesis = ResearchRecord::issue(
        "commons-demo-research",
        ResearchRecordKind::Hypothesis,
        vec![],
        "11".repeat(32),
        100,
        &researcher,
    )?;
    hypothesis.verify()?;
    step(1, "signed research hypothesis recorded");

    let dataset = ResearchRecord::issue(
        "commons-demo-research",
        ResearchRecordKind::Dataset,
        vec![hypothesis.record_id.clone()],
        "22".repeat(32),
        101,
        &researcher,
    )?;
    dataset.verify()?;
    step(2, "encrypted dataset CID linked into causal graph");

    let analysis = ResearchRecord::issue(
        "commons-demo-research",
        ResearchRecordKind::Analysis,
        vec![dataset.record_id.clone()],
        "33".repeat(32),
        102,
        &researcher,
    )?;
    analysis.verify()?;
    step(3, "analysis version signed without replacing its parents");

    let spell = SpellContract::issue(
        "analyze",
        vec!["research:dataset:aggregate".into()],
        vec![dataset.record_id.clone()],
        5_000,
        1,
        true,
        false,
        100,
        200,
        &buyer,
    )?;
    spell.authorize(&InvocationRequest {
        action: "analyze",
        data_scope: "research:dataset:aggregate",
        subject_id: &dataset.record_id,
        amount_minor: 1_000,
        prior_invocations: 0,
        human_approved: true,
        now: 110,
    })?;
    step(4, "bounded human-approved spell authorized");

    let runtime_measurement = "44".repeat(32);
    let manifest = CapabilityManifest::issue(
        OfferingKind::CapabilityInvocation,
        "one privacy-preserving analysis",
        "55".repeat(32),
        "66".repeat(32),
        "AUD",
        1_000,
        vec![
            split("auditor", "audit", 500),
            split("creator", "creator", 6_500),
            split("market", "discovery", 500),
            split("node", "compute", 1_500),
            split("storage", "storage", 1_000),
        ],
        100,
        200,
        &creator,
    )?;
    manifest.verify()?;
    step(5, "portable capability manifest and price splits verified");

    let execution = ExecutionAttestation::issue(
        &manifest.capability_id,
        &spell.contract_id,
        &runtime_measurement,
        vec![dataset.content_cid.clone(), analysis.content_cid.clone()],
        "77".repeat(32),
        111,
        112,
        &executor,
    )?;
    execution.verify(std::slice::from_ref(&runtime_measurement))?;
    step(
        6,
        "approved runtime produced a signed compute-to-data result",
    );

    let memory = MemoryEntry::new(
        "research",
        execution.output_cid.clone(),
        MemoryProvenance::ExternalDocument,
        8_000,
        MemoryStatus::Active,
        None,
        113,
    )?;
    let grant = MemoryGrant {
        grantee_id: "analysis-assistant".into(),
        domains: vec!["research".into()],
        purpose: "result-summary".into(),
        max_reads: 1,
        writes_allowed: false,
        expires_at: 150,
    };
    grant.authorize("research", "result-summary", 0, false, 120)?;
    step(
        7,
        "Pensive memory provenance and least-privilege grant verified",
    );

    let legacy = LegacyDirective::new(
        execution.output_cid.clone(),
        LegacyAction::Transfer,
        Some("research-community".into()),
        150,
        2,
        vec![
            "guardian-a".into(),
            "guardian-b".into(),
            "guardian-c".into(),
        ],
    )?;
    legacy.authorize(150, &["guardian-a".into(), "guardian-b".into()])?;
    step(8, "time-locked multi-guardian legacy directive verified");

    let allocations = manifest.allocations()?;
    ensure!(
        allocations.iter().map(|item| item.1).sum::<u64>() == manifest.price_minor,
        "capability allocations do not conserve payment"
    );
    step(
        9,
        "payment allocation conserves value without creating votes",
    );

    let report = CommonsReport {
        protocol: "arcane-commons/1",
        status: "pass",
        steps: vec![
            "research",
            "encrypted-data-reference",
            "causal-analysis",
            "spell",
            "capability",
            "compute-to-data",
            "pensive",
            "legacy",
            "allocation",
        ],
        research_record_ids: vec![hypothesis.record_id, dataset.record_id, analysis.record_id],
        capability_id: manifest.capability_id,
        spell_contract_id: spell.contract_id,
        execution_id: execution.execution_id,
        memory_entry_id: memory.entry_id,
        legacy_directive_id: legacy.directive_id,
        allocations_minor: allocations,
    };
    let output = Path::new(".verify/verify-commons-report.json");
    fs::create_dir_all(output.parent().context("report path has no parent")?)?;
    fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    println!("verify:commons PASS — all 9 protocol steps succeeded");
    println!("evidence={}", output.display());
    Ok(())
}

fn split(recipient_id: &str, role: &str, basis_points: u16) -> RevenueSplit {
    RevenueSplit {
        recipient_id: recipient_id.into(),
        role: role.into(),
        basis_points,
    }
}

fn step(number: u8, description: &str) {
    println!("STEP-{number:02} PASS {description}");
}
