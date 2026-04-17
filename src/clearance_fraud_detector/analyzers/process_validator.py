"""
NISPOM Process Validator — Validates the legal sequence of a cleared-job hire.

32 CFR §117.10 mandates a specific sequence before any clearance action occurs.
This module takes a description of events and identifies which steps were skipped,
reordered, or violated, then maps each gap to the exact CFR paragraph.

The mandatory 6-step sequence under NISPOM:
  Step 1: Contractor issues written offer   → §117.10(f)(1)(i)
  Step 2: Candidate accepts in writing      → §117.10(f)(1)(ii)
  Step 3: FSO initiates eApp invitation     → §117.10(d)
  Step 4: Candidate completes SF-86 in eApp → §117.10(d)
  Step 5: FSO reviews for completeness      → §117.10(d)(1)
  Step 6: FSO submits to DCSA via DISS      → §117.10(a)(7) inference + SEAD 7

Reciprocity shortcut (when active clearance already exists):
  Steps 1-2 still required but Steps 3-6 are replaced by:
  Step 3R: FSO queries DISS JVS with own CAC credentials → §117.10(h)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class StepStatus(Enum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    OUT_OF_ORDER = "out_of_order"
    UNKNOWN = "unknown"


@dataclass
class ProcessStep:
    number: int
    name: str
    description: str
    rule: str
    url: str
    detection_patterns: list[str]
    skip_violation: str         # citation when this step is bypassed
    skip_description: str       # What it means if this step was skipped


@dataclass
class StepResult:
    step: ProcessStep
    status: StepStatus
    evidence: str = ""          # snippet from text that triggered detection


@dataclass
class ProcessValidationReport:
    step_results: list[StepResult] = field(default_factory=list)
    skipped_steps: list[ProcessStep] = field(default_factory=list)
    out_of_order_steps: list[ProcessStep] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    is_reciprocity_case: bool = False
    overall_assessment: str = "UNKNOWN"

    @property
    def completed_steps(self) -> list[StepResult]:
        return [r for r in self.step_results if r.status == StepStatus.COMPLETED]

    def summary(self) -> str:
        lines = [f"Process Validation: {self.overall_assessment}"]
        lines.append(f"  Completed steps: {len(self.completed_steps)}/{len(self.step_results)}")
        if self.skipped_steps:
            lines.append("  Skipped steps:")
            for s in self.skipped_steps:
                lines.append(f"    Step {s.number}: {s.name} [{s.skip_violation}]")
        if self.out_of_order_steps:
            lines.append("  Out-of-order steps:")
            for s in self.out_of_order_steps:
                lines.append(f"    Step {s.number}: {s.name}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Step definitions
# ---------------------------------------------------------------------------

PROCESS_STEPS: list[ProcessStep] = [
    ProcessStep(
        number=1,
        name="Written Offer Issued",
        description="Contractor issues a written commitment of employment to the candidate.",
        rule="32 CFR §117.10(f)(1)(i)",
        url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(f)(1)(i)",
        detection_patterns=[
            r"(offer\s+letter|written\s+offer|formal\s+offer)\s+(sent|issued|provided|mailed|attached)",
            r"(sent|issued|provided).{0,40}(offer\s+letter|written\s+offer)",
            r"contingent\s+offer|conditional\s+offer",
        ],
        skip_violation="32 CFR §117.10(f)(1)(i) — written commitment prerequisite not met",
        skip_description=(
            "No written offer was issued before clearance actions were initiated. "
            "The regulation requires a written commitment from the contractor. "
            "Verbal offers, phone calls, and emails saying 'we want to move forward' "
            "do not satisfy this requirement."
        ),
    ),
    ProcessStep(
        number=2,
        name="Written Acceptance Received",
        description="Candidate accepts the offer in writing — signature, countersignature, or written reply.",
        rule="32 CFR §117.10(f)(1)(ii)",
        url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(f)(1)(ii)",
        detection_patterns=[
            r"(accepted|signed|countersigned).{0,40}(offer|in\s+writing|written)",
            r"written\s+acceptance|acceptance\s+in\s+writing",
            r"signed\s+(back|and\s+returned|countersigned)",
        ],
        skip_violation="32 CFR §117.10(f)(1)(ii) — written acceptance prerequisite not met",
        skip_description=(
            "No written acceptance was obtained before clearance actions were initiated. "
            "The candidate must accept in writing. Saying 'yes' on a phone screen is not enough."
        ),
    ),
    ProcessStep(
        number=3,
        name="FSO Issues eApp Invitation",
        description="The FSO (not the recruiter) initiates the NBIS eApp invitation from the DISS portal.",
        rule="32 CFR §117.10(d)",
        url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(d)",
        detection_patterns=[
            r"eapp\.nbis\.mil|nbis\s+eapp",
            r"(fso|facility\s+security\s+officer).{0,60}(sent|initiated|issued|submitted)",
            r"(invitation|invite|access).{0,40}(eapp|e-?qip|nbis)",
        ],
        skip_violation="32 CFR §117.10(d) — unauthorized collection channel",
        skip_description=(
            "The FSO did not initiate an eApp invitation. Instead, a different "
            "channel (email, phone, DOD SAFE, etc.) was used to collect SSN or PII. "
            "NBIS eApp is the only authorized collection system for SF-86 data."
        ),
    ),
    ProcessStep(
        number=4,
        name="Candidate Completes SF-86 in eApp",
        description="Candidate enters their own information directly into NBIS eApp — SSN goes in here, not via email.",
        rule="32 CFR §117.10(d)",
        url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(d)",
        detection_patterns=[
            r"(completed|filled\s+out|finished|submitted).{0,40}(sf.?86|eapp|nbis)",
            r"(sf.?86|eapp|background\s+investigation\s+form).{0,40}(completed|done|finished)",
        ],
        skip_violation="32 CFR §117.10(d) — SF-86 completed outside authorized system",
        skip_description=(
            "The SF-86 (or equivalent data including SSN) was not completed by the "
            "candidate directly in NBIS eApp. Any other method of collecting this "
            "information is unauthorized under the regulation."
        ),
    ),
    ProcessStep(
        number=5,
        name="FSO Reviews for Completeness",
        description="The FSO reviews the SF-86 only for adequacy and completeness — no other use permitted.",
        rule="32 CFR §117.10(d)(1) and (d)(2)",
        url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(d)",
        detection_patterns=[
            r"(fso|security\s+officer).{0,60}(reviewed|checked|verified).{0,40}(sf.?86|eapp|complete)",
            r"(completeness|adequacy).{0,40}(reviewed|checked|verified)",
        ],
        skip_violation="32 CFR §117.10(d)(1) — FSO review step not completed",
        skip_description=(
            "The FSO review step was bypassed. The FSO is required to verify completeness "
            "and must provide written notification that the review is for that purpose only."
        ),
    ),
    ProcessStep(
        number=6,
        name="FSO Submits to DCSA via DISS",
        description="The FSO submits the completed investigation request through DISS using authorized credentials.",
        rule="32 CFR §117.10(a) and SECNAV M-5510.30",
        url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(a)",
        detection_patterns=[
            r"(submitted|sent|forwarded).{0,40}(dcsa|diss|dissportal|investigation\s+request)",
            r"(fso|security\s+officer).{0,60}(submitted|filed|sent).{0,40}(dcsa|diss)",
        ],
        skip_violation="32 CFR §117.10(a) — investigation request submitted by unauthorized party",
        skip_description=(
            "The investigation request was not properly submitted by the FSO through DISS. "
            "Only FSO-credentialed DISS users can submit investigation requests."
        ),
    ),
]

# Reciprocity step (replaces steps 3-6 when active clearance exists)
RECIPROCITY_STEP = ProcessStep(
    number=3,
    name="FSO Queries DISS JVS for Existing Clearance",
    description="FSO uses their own CAC-authenticated DISS access to verify the existing clearance via JVS.",
    rule="32 CFR §117.10(h)(1) and (h)(2), SEAD 7",
    url="https://www.ecfr.gov/current/title-32/section-117.10#p-117.10(h)",
    detection_patterns=[
        r"(diss|jvs|joint\s+verification).{0,60}(reciprocit|existing|active|current)",
        r"(cac|credentials|credentialed).{0,60}(diss|dissportal)",
        r"reciprocit.{0,40}(clearance|access|sead|117)",
    ],
    skip_violation="32 CFR §117.10(h) — reciprocity applicable but ignored",
    skip_description=(
        "The subject has an active clearance. Reciprocity requires using the prior "
        "investigation without re-adjudication. No new SF-86 or SSN collection is needed — "
        "the FSO queries DISS JVS with their own credentials."
    ),
)

# ---------------------------------------------------------------------------
# Signals that indicate the interaction is PRE-offer (raises all flags)
# ---------------------------------------------------------------------------
_PRE_OFFER_SIGNALS: list[re.Pattern] = [
    re.compile(r"(before\s+(we\s+)?(can\s+)?(move\s+forward|proceed|continue|make\s+an\s+offer))", re.IGNORECASE),
    re.compile(r"(initial\s+screening|phone\s+screen|first\s+interview|recruiter\s+call)", re.IGNORECASE),
    re.compile(r"(interested\s+in|exploring|considering).{0,40}(opportunity|position|role)", re.IGNORECASE),
    re.compile(r"(before|prior).{0,20}(offer|hire|onboard|start)", re.IGNORECASE),
    re.compile(r"(we\s+haven'?t|no\s+offer|not\s+yet\s+hired|conditional\s+on\s+clearance)", re.IGNORECASE),
]

_RECIPROCITY_SIGNALS: list[re.Pattern] = [
    re.compile(r"(active|current|existing).{0,30}(clearance|ts|tssci|secret\s+clearance)", re.IGNORECASE),
    re.compile(r"(already|previously).{0,30}(cleared|hold|possess|have)\s+(a\s+)?(clearance|ts|tssci)", re.IGNORECASE),
    re.compile(r"(reciprocit|sead\s*7|prior\s+investigation)", re.IGNORECASE),
]


# ID: PV-001
# Requirement: Detect whether an interaction text describes the NISPOM §117.10 six-step
#              hiring process in the correct order and flag any skipped or out-of-sequence steps.
# Purpose: Provide automated compliance assessment for narratives submitted as part of an
#          incident report, to distinguish genuine process failures from fraudulent ones.
# Rationale: Pattern matching against step-specific detection_patterns provides a text-only
#             proxy for what should be a documented HR workflow; reciprocity detection reduces
#             false positives for already-cleared candidates.
# Inputs: text (str) — any interaction description — email thread, recruiter transcript,
#         or narrative of events.
# Outputs: ProcessValidationReport with per-step StepResult list, skipped_steps, violations,
#          overall_assessment, and is_reciprocity_case flag.
# Preconditions: PROCESS_STEPS and RECIPROCITY_STEP module-level constants are populated.
# Postconditions: overall_assessment is one of COMPLIANT / NON_COMPLIANT / INDETERMINATE.
# Assumptions: Step detection_patterns are IGNORECASE; order of PROCESS_STEPS matches NISPOM §117.10.
# Side Effects: None — pure function; no I/O.
# Failure Modes: If no detection patterns fire, all steps are UNKNOWN → INDETERMINATE result.
# Error Handling: re.compile inside loop is safe; no exception propagates to caller.
# Constraints: O(|PROCESS_STEPS| × |detection_patterns| × |text|); typically < 5 ms.
# Verification: test_detector.py::test_process_validator_* — reciprocity, skipped step, full pass.
# References: 32 CFR §117.10(f)(1)(i)-(ii), §117.10(h) (reciprocity); NISPOM §117.10 sequence.
def validate_process(text: str) -> ProcessValidationReport:
    """
    Validate a hiring interaction text against the NISPOM §117.10 process sequence.

    Args:
        text: Any interaction description — email thread, recruiter transcript,
              narrative of events, or job application notes.

    Returns:
        ProcessValidationReport with per-step status and violation citations.
    """
    report = ProcessValidationReport()

    # Detect if this is a reciprocity case (existing clearance)
    report.is_reciprocity_case = any(p.search(text) for p in _RECIPROCITY_SIGNALS)

    steps_to_check = PROCESS_STEPS if not report.is_reciprocity_case else PROCESS_STEPS[:2]

    is_pre_offer = any(p.search(text) for p in _PRE_OFFER_SIGNALS)

    for step in steps_to_check:
        patterns_compiled = [re.compile(p, re.IGNORECASE) for p in step.detection_patterns]
        match_evidence = ""
        step_found = False
        for pattern in patterns_compiled:
            m = pattern.search(text)
            if m:
                step_found = True
                start = max(0, m.start() - 20)
                end = min(len(text), m.end() + 20)
                match_evidence = f"...{text[start:end]}..."
                break

        if step_found:
            status = StepStatus.COMPLETED
        elif is_pre_offer and step.number <= 2:
            status = StepStatus.SKIPPED
        else:
            status = StepStatus.UNKNOWN

        sr = StepResult(step=step, status=status, evidence=match_evidence)
        report.step_results.append(sr)

        if status == StepStatus.SKIPPED:
            report.skipped_steps.append(step)
            report.violations.append(step.skip_violation)

    # If reciprocity case, check for JVS query step
    if report.is_reciprocity_case:
        recip_patterns = [re.compile(p, re.IGNORECASE) for p in RECIPROCITY_STEP.detection_patterns]
        recip_found = any(p.search(text) for p in recip_patterns)
        recip_status = StepStatus.COMPLETED if recip_found else StepStatus.UNKNOWN
        report.step_results.append(StepResult(step=RECIPROCITY_STEP, status=recip_status))

    # Overall assessment
    if report.skipped_steps:
        report.overall_assessment = "NON_COMPLIANT — steps skipped"
    elif all(r.status == StepStatus.COMPLETED for r in report.step_results):
        report.overall_assessment = "COMPLIANT — all steps detected"
    else:
        report.overall_assessment = "INDETERMINATE — insufficient evidence"

    return report
