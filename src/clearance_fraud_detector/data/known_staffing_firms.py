"""
Known Cleared Staffing Firms Database.

Separate from prime contractors (known_contractors.py), this module tracks
cleared staffing/recruiting intermediaries — firms that place personnel into
cleared positions but do not themselves hold the prime contract.

Key distinction:
  - Prime contractor FSO has authority to initiate clearance actions → legitimate
  - Staffing firm recruiter has NO authority to initiate clearance actions → per
    32 CFR §117.10(a)(7), only the employing contractor can submit requests

All CAGE codes and contact info in this file should be verified at sam.gov
before use. This file is maintained for detection and reference purposes.

Sources:
  SAM.gov system for award management: https://sam.gov
  GSA Multiple Award Schedule (MAS): https://www.gsa.gov/acquisition/purchasing-programs/gsa-multiple-award-schedule
  CAGE code lookup: https://cage.dla.mil
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StaffingFirm:
    name: str
    cage_code: str                    # Verify at sam.gov before trusting
    known_domains: list[str]
    known_phone: str = ""
    location: str = ""
    gsa_mas: bool = False             # Has GSA Multiple Award Schedule contract
    woman_owned: bool = False
    known_fraud_indicators: list[str] = field(default_factory=list)
    notes: str = ""
    sam_gov_url: str = ""


# ---------------------------------------------------------------------------
# FIRMS WITH KNOWN FRAUD INDICATORS
# These firms have been associated with documented NISPOM process violations
# ---------------------------------------------------------------------------
FLAGGED_STAFFING_FIRMS: list[str] = [
    "Mindbank Consulting Group",
]

# ---------------------------------------------------------------------------
# KNOWN STAFFING FIRMS (for reference, not to imply all are fraudulent)
# ---------------------------------------------------------------------------
KNOWN_STAFFING_FIRMS: dict[str, StaffingFirm] = {

    "Mindbank Consulting Group": StaffingFirm(
        name="Mindbank Consulting Group",
        cage_code="",   # Request and verify at sam.gov before trusting
        known_domains=["mindbankcg.com"],
        known_phone="",
        location="Vienna, VA",
        gsa_mas=True,
        woman_owned=True,
        known_fraud_indicators=[
            "Requested SSN pre-offer via email, citing 'DISS verification' as justification",
            "SVP claimed it is 'common and standard practice' — violates 32 CFR §117.10(a)(5)",
            "Proposed DOD SAFE (safe.apps.mil) as alternative SSN channel — violates §117.10(d)",
            "Claimed SSN is 'primary identifier in DISS' to justify pre-offer collection",
            "Used social engineering pressure: 'everyone else provided,' 'not playing ball'",
            "Recruiter (Senior Technical Recruiter) requested SSN directly",
            "SVP escalation reaffirmed the violation rather than correcting it",
        ],
        notes=(
            "Mindbank is a real GSA MAS-holding staffing firm in Vienna, VA. "
            "A woman-owned small business. Has a legitimate business. "
            "However, documented interaction shows pre-offer SSN requests using "
            "false NISPOM justifications. These are §117.10(a)(7) and §117.10(f)(1) "
            "violations. As a staffing intermediary, Mindbank's recruiters have zero "
            "DISS access — only the hiring contractor's FSO can initiate clearance actions. "
            "Documented April 2026 interaction: recruiter + SVP escalation."
        ),
        sam_gov_url="https://sam.gov/search/?index=cf&q=Mindbank+Consulting",
    ),

    "Chenega Corporation": StaffingFirm(
        name="Chenega Corporation",
        cage_code="",
        known_domains=["chenega.com", "chenegacorp.com"],
        location="Anchorage, AK (Alaska Native Corporation)",
        gsa_mas=True,
        notes="Alaska Native Corporation — large defense contractor and staffing provider",
        sam_gov_url="https://sam.gov/search/?index=cf&q=Chenega",
    ),

    "Alldus International": StaffingFirm(
        name="Alldus International",
        cage_code="",
        known_domains=["alldus.com"],
        notes="Technology staffing firm focusing on cleared AI/data roles",
        sam_gov_url="https://sam.gov/search/?index=cf&q=Alldus",
    ),

    "eTalent Network": StaffingFirm(
        name="eTalent Network",
        cage_code="",
        known_domains=["etalentnetwork.com"],
        known_phone="",  # removed — individual recruiter phone
        location="Northern Virginia / DC Metro",
        notes=(
            "IT staffing firm operating as RPO (Recruitment Process Outsourcing) partner "
            "for 22nd Century Technologies, Inc. (TSCTI, tscti.com). Legitimately places "
            "cleared candidates into FBI, DoD, and other federal contracts via TSCTI. "
            "Recruiters explicitly disclose 'recruiting on behalf of 22nd Century Technologies' "
            "which is the correct staffing agency disclosure per industry practice. "
            "CONCERN: Pre-offer FSO call request documented (April 2026) "
            "— backed off when 32 CFR §117.10(f)(1) cited, which is the correct response. "
            "CONCERN: Resume falsification request documented (April 2026) — recruiter asked "
            "candidate to 'add a few lines highlighting Java experience in your latest contract.' "
            "For FBI/DoD roles this is a 18 U.S.C. §1001 risk for the candidate. "
            "CONCERN: Parallel submission — multiple eTalent recruiters simultaneously pitching "
            "same role to same candidate with zero internal coordination. "
            "CRM blast confirmed (April 2026): Three recruiters independently cold-pitched same "
            "candidate for FBI MXU SCOR 29 with zero inter-recruiter collision checks. "
            "Classic volume-staffing quota behavior: recruiters pull from shared candidate DB "
            "in isolated workqueues with no inter-recruiter collision checks."
        ),
        sam_gov_url="https://sam.gov/search/?index=cf&q=etalent",
    ),

    "ClearanceJobs": StaffingFirm(
        name="ClearanceJobs (DICE Holdings)",
        cage_code="",
        known_domains=["clearancejobs.com"],
        notes=(
            "Legitimate cleared job board — not a staffing firm per se. "
            "Employers post positions directly. No recruiter should claim "
            "to 'verify your clearance' via ClearanceJobs — that's not a "
            "capability of the platform."
        ),
        sam_gov_url="",
    ),

    "22nd Century Technologies (22ctech)": StaffingFirm(
        name="22nd Century Technologies",
        cage_code="",
        known_domains=["tscti.com", "22ctech.com"],
        notes=(
            "Mid-size cleared IT staffing firm. tscti.com domain used for some "
            "recruiting. TSCTI stands for: 22nd Century Technologies Inc. "
            "Verify any recruiter's affiliation independently."
        ),
        sam_gov_url="https://sam.gov/search/?index=cf&q=22nd+Century+Technologies",
    ),

    "Apex Group (Apex Government Services)": StaffingFirm(
        name="Apex Group",
        cage_code="",
        known_domains=["apexhighered.com", "apexsystems.com"],
        notes="Large IT staffing firm with cleared division. Verify domain carefully — many imitators.",
        sam_gov_url="https://sam.gov/search/?index=cf&q=Apex+Systems",
    ),

    "Stellent IT LLC": StaffingFirm(
        name="Stellent IT LLC",
        cage_code="",
        known_domains=["stellentit.com"],
        known_phone="321-785-6062",
        location="Central Florida (area code 321 — Brevard County / Kennedy Space Center area)",
        gsa_mas=False,
        notes=(
            "General IT staffing and consulting firm, founded 2015. Self-described as a "
            "'Nationally Recognized Minority Certified Enterprise.' Basic website hosted "
            "on a 1&1 website builder. No SAM.gov federal contract record confirmed. "
            "No evidence of Facility Clearance (FCL). Observed recruiting TS/SCI candidates "
            "for unnamed 'clients' via bulk email marketing blasts with CAN-SPAM unsubscribe "
            "links — mass email list approach rather than targeted outreach. "
            "A non-FCL staffing intermediary has no NISPOM authority (32 CFR §117.10(a)(7)) "
            "to sponsor or verify clearances. If the underlying job is real, it will be "
            "listed on the prime contractor's own careers page."
        ),
        sam_gov_url="https://sam.gov/search/?index=entity&keywords=Stellent+IT",
    ),

    "reStart Events (reStartEvents.com)": StaffingFirm(
        name="reStartEvents.com, Inc.",
        cage_code="",
        known_domains=["restartevents.com"],
        known_phone="",
        location="",
        gsa_mas=False,
        notes=(
            "Legitimate cleared career fair organizer with 20+ years in business, 900+ recruitment "
            "events, 800,000+ security cleared and technical professionals served. Hosts virtual "
            "and in-person cleared career fairs with genuine participating employers (Leidos, CACI, "
            "Lockheed Martin, MITRE, Amentum, DCMA, DISA, and others). Uses Brazen Connect "
            "(brazenconnect.com) as the virtual event platform. "
            "Contact: [CEO], reStartEvents.com. "
            "CONCERNS TO NOTE (not fraud, but risk-awareness): "
            "(1) Email outreach sent via Constant Contact from a Gmail-registered account "
            "(restart.events@gmail.com via ccsend.com) rather than @restartevents.com corporate email. "
            "(2) 'Clearance REQUIRED to register' means registration confirms TS/SCI status to a "
            "third-party event company — review their data retention and sharing policies before "
            "registering. (3) 'Please share with colleagues' requests grow their contact database "
            "virally. These are operational practices to be aware of, not fraud indicators. "
            "Verified legitimate via restartevents.com About page, LinkedIn company ID 9176006, "
            "April 2026."
        ),
        sam_gov_url="https://sam.gov/search/?index=entity&keywords=reStart+Events",
    ),

    "Entegee (AKKODIS)": StaffingFirm(
        name="Entegee (AKKODIS / Adecco Group)",
        cage_code="",
        known_domains=["entegee.com", "akkodis.com", "modis.com"],
        known_phone="",  # removed — individual recruiter phone
        location="San Fernando Valley CA (area code 818) — consistent with LA aerospace corridor",
        gsa_mas=False,
        notes=(
            "Entegee is a 60+ year-old legitimate engineering staffing firm, now a brand of AKKODIS "
            "(formerly Akka Technologies), which is a subsidiary of the Adecco Group — one of the "
            "world's largest staffing companies with 40K+ engineers in 30+ countries. Genuine specialized "
            "engineering and defense aerospace staffing. No documented NISPOM violations. "
            "HOWEVER: Entegee/AKKODIS uses commercial bulk email marketing platforms (Salesforce Marketing "
            "Cloud) to distribute ClearanceJobs-sourced outreach. Even from a legitimate company, "
            "mass email tactics carry risk: (1) replies confirm cleared-professional emails as active, "
            "(2) resume submissions disclose aggregated clearance history to an automated CRM, "
            "(3) platform personalization ('your skills stood out') creates false intimacy. "
            "Verified legitimate via public website/LinkedIn. "
            "Director IT Recruiting domain: @Entegee.com (verified corporate email). "
            "Area code 818 is consistent with Van Nuys/Woodland Hills/Northridge, near multiple "
            "major aerospace/defense employers (Northrop Grumman, Boeing Aerospace, Aerojet Rocketdyne)."
        ),
        sam_gov_url="https://sam.gov/search/?index=entity&keywords=Entegee",
    ),

    "Clearwater Staffing": StaffingFirm(
        name="Clearwater Staffing",
        cage_code="",
        known_domains=[],
        known_fraud_indicators=[
            "Generic company name frequently spoofed in cleared-job fraud campaigns",
            "No known legitimate SAM.gov registration under this name",
            "Used in job posting fraud targeting TS/SCI candidates",
        ],
        notes="Generic-sounding name commonly used in synthetic cleared-job postings. Verify carefully.",
        sam_gov_url="",
    ),
}

# ---------------------------------------------------------------------------
# Domain-to-firm mapping for quick lookup
# ---------------------------------------------------------------------------
STAFFING_FIRM_DOMAINS: dict[str, str] = {}
for _firm_name, _firm_data in KNOWN_STAFFING_FIRMS.items():
    for _domain in _firm_data.known_domains:
        STAFFING_FIRM_DOMAINS[_domain] = _firm_name


def get_firm_by_domain(domain: str) -> StaffingFirm | None:
    """Look up a staffing firm by email/website domain."""
    firm_name = STAFFING_FIRM_DOMAINS.get(domain.lower().strip())
    if firm_name:
        return KNOWN_STAFFING_FIRMS.get(firm_name)
    return None


def get_firm_by_name(name: str) -> StaffingFirm | None:
    """Fuzzy lookup by company name (case-insensitive)."""
    name_lower = name.lower().strip()
    for firm_name, firm in KNOWN_STAFFING_FIRMS.items():
        if firm_name.lower() in name_lower or name_lower in firm_name.lower():
            return firm
    return None


def is_flagged(firm_name: str) -> bool:
    """Check if a firm is in the flagged list."""
    return firm_name in FLAGGED_STAFFING_FIRMS
