"""
Fraud Reporting Resources — who to contact when you suspect clearance job fraud.

Organized by fraud type with the official agency name, phone number, online
form URL, and what specific fraud category they handle.
"""
from dataclasses import dataclass, field


@dataclass
class ReportingAgency:
    name: str
    handles: str                      # short description
    phone: str = ""
    url: str = ""
    form_url: str = ""
    email: str = ""
    notes: str = ""
    priority: int = 1                 # 1=critical/first call, 2=secondary, 3=supplemental
    fraud_types: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Master reporting database
# ---------------------------------------------------------------------------
REPORTING_AGENCIES: list[ReportingAgency] = [

    # ---- IDENTITY THEFT / SSN STOLEN ----------------------------------------
    ReportingAgency(
        name="IdentityTheft.gov (FTC)",
        handles="Step-by-step recovery plan if SSN/identity was stolen",
        url="https://identitytheft.gov",
        notes="Start here — creates a personalized recovery plan covering all federal agencies",
        priority=1,
        fraud_types=["ssn_stolen", "identity_theft", "pii_harvested"],
    ),
    ReportingAgency(
        name="Social Security Administration OIG",
        handles="SSN misuse, Social Security fraud",
        phone="1-800-269-0271",
        url="https://oig.ssa.gov/report",
        form_url="https://oig.ssa.gov/report",
        notes="Report misuse of your Social Security Number",
        priority=1,
        fraud_types=["ssn_stolen", "identity_theft"],
    ),
    ReportingAgency(
        name="IRS Identity Protection",
        handles="Tax fraud using stolen identity — get IP PIN",
        phone="1-800-908-4490",
        url="https://www.irs.gov/identity-theft-fraud-scams/identity-protection",
        form_url="https://www.irs.gov/identity-theft-fraud-scams/identity-theft-affidavit",
        notes="Get an Identity Protection PIN (IP PIN) to prevent fraudulent tax returns. "
              "If you already filed and someone else did too, call IRS directly.",
        priority=1,
        fraud_types=["ssn_stolen", "identity_theft", "tax_fraud"],
    ),

    # ---- CLEARANCE / DEFENSE CONTRACTORS ------------------------------------
    ReportingAgency(
        name="DCSA (Defense Counterintelligence and Security Agency)",
        handles="Fake FSO, clearance fraud, adverse foreign contact, insider threat",
        phone="571-305-6576",
        url="https://www.dcsa.mil/MC/CI/",
        form_url="https://www.dcsa.mil/Contact-Us/Inspector-General/",
        email="dcsacounterfraud@mail.mil",
        notes="Primary agency for fake FSO scams and clearance-related fraud. "
              "Report via email or phone — DCSA does NOT cold-contact candidates, "
              "agents, or recruiters. OIG hotline: 1-855-865-1508 / dcsa.ig@mail.mil.",
        priority=1,
        fraud_types=["fake_fso", "clearance_fraud", "foreign_contact", "dprk_scheme"],
    ),
    ReportingAgency(
        name="FBI — Tips & Leads (tips.fbi.gov)",
        handles="DPRK IT worker schemes, national security fraud, identity theft",
        url="https://tips.fbi.gov",
        form_url="https://tips.fbi.gov",
        notes="Use for DPRK IT worker fraud (camera-off interviews, foreign accents, "
              "Telegram-only recruiters). Also report counterintelligence concerns.",
        priority=1,
        fraud_types=["dprk_scheme", "fake_recruiter", "foreign_contact", "national_security"],
    ),
    ReportingAgency(
        name="FBI — Internet Crime Complaint Center (IC3)",
        handles="Job fraud, wire fraud, online identity theft",
        url="https://ic3.gov",
        form_url="https://ic3.gov/Home/FileComplaint",
        notes="File a complaint for job-related internet fraud. IC3 shares data with "
              "state and federal law enforcement.",
        priority=1,
        fraud_types=["job_fraud", "wire_fraud", "identity_theft", "fake_recruiter"],
    ),

    # ---- JOB / CONSUMER FRAUD -----------------------------------------------
    ReportingAgency(
        name="FTC — ReportFraud.ftc.gov",
        handles="Job scams, fake recruiters, application fees, consumer fraud",
        phone="1-877-382-4357 (1-877-FTC-HELP)",
        url="https://reportfraud.ftc.gov",
        form_url="https://reportfraud.ftc.gov/#/",
        notes="Primary consumer fraud reporting. FTC forwards reports to 3,000+ law "
              "enforcement agencies. Also report phishing emails here.",
        priority=1,
        fraud_types=["job_fraud", "fake_recruiter", "phishing", "application_fee"],
    ),

    # ---- CREDIT / FINANCIAL -------------------------------------------------
    ReportingAgency(
        name="Equifax — Fraud Alert / Credit Freeze",
        handles="Credit freeze, fraud alert to prevent new accounts",
        phone="1-888-766-0008",
        url="https://www.equifax.com/personal/credit-report-services/credit-fraud-alerts/",
        notes="Freeze credit HERE FIRST — placing a freeze at one bureau does NOT "
              "automatically freeze the others. Do all five.",
        priority=1,
        fraud_types=["ssn_stolen", "identity_theft", "credit_fraud"],
    ),
    ReportingAgency(
        name="Experian — Fraud Alert / Credit Freeze",
        handles="Credit freeze, fraud alert",
        phone="1-888-397-3742",
        url="https://www.experian.com/freeze/center.html",
        notes="Freeze credit independently from other bureaus",
        priority=1,
        fraud_types=["ssn_stolen", "identity_theft", "credit_fraud"],
    ),
    ReportingAgency(
        name="TransUnion — Fraud Alert / Credit Freeze",
        handles="Credit freeze, fraud alert",
        phone="1-800-680-7289",
        url="https://www.transunion.com/credit-freeze",
        notes="Freeze credit independently from other bureaus",
        priority=1,
        fraud_types=["ssn_stolen", "identity_theft", "credit_fraud"],
    ),
    ReportingAgency(
        name="Innovis — Credit Freeze",
        handles="4th major credit bureau — often overlooked",
        phone="1-800-540-2505",
        url="https://www.innovis.com/personal/securityFreeze",
        notes="The 4th credit bureau — most people forget this one",
        priority=2,
        fraud_types=["ssn_stolen", "identity_theft", "credit_fraud"],
    ),
    ReportingAgency(
        name="ChexSystems — Bank Account Fraud",
        handles="Prevent fraudulent bank account openings using your identity",
        phone="1-800-428-9623",
        url="https://www.chexsystems.com/security-freeze/place-freeze",
        notes="Used by banks to screen new account applicants — freeze this too",
        priority=2,
        fraud_types=["ssn_stolen", "identity_theft"],
    ),

    # ---- CYBER / PHISHING ---------------------------------------------------
    ReportingAgency(
        name="CISA — Report Phishing / Cyber Incident",
        handles="Phishing campaigns, cyber-enabled fraud, domain spoofing",
        phone="1-888-282-0870",
        url="https://www.cisa.gov/report",
        email="report@cisa.dhs.gov",
        notes="For phishing emails targeting cleared/defense workers. CISA tracks "
              "nation-state spear-phishing campaigns.",
        priority=2,
        fraud_types=["phishing", "domain_spoofing", "cyber_fraud", "dprk_scheme"],
    ),

    # ---- STATE LEVEL --------------------------------------------------------
    ReportingAgency(
        name="Virginia AG — Consumer Protection",
        handles="VA-registered fake companies, consumer fraud",
        phone="1-800-552-9963",
        url="https://www.oag.state.va.us/consumer-protection/index.php/file-a-complaint",
        form_url="https://www.oag.state.va.us/consumer-protection/index.php/file-a-complaint",
        notes="For fraudulent companies claiming to be VA-based cleared contractors",
        priority=2,
        fraud_types=["fake_company", "fake_recruiter", "job_fraud"],
    ),
    ReportingAgency(
        name="Maryland AG — Consumer Protection",
        handles="MD-registered fake companies, consumer fraud",
        phone="1-888-743-0023",
        url="https://www.marylandattorneygeneral.gov/Pages/CPD/Complaints.aspx",
        notes="For fraudulent companies claiming to be MD-based contractors",
        priority=2,
        fraud_types=["fake_company", "fake_recruiter", "job_fraud"],
    ),

    # ---- MILITARY / IC SPECIFIC ---------------------------------------------
    ReportingAgency(
        name="NCIS — Counterintelligence Tips",
        handles="Foreign intelligence threats, insider threat, espionage",
        phone="1-877-579-3648",
        url="https://www.ncis.navy.mil/report-a-crime",
        form_url="https://tips.ncis.navy.mil",
        notes="Use if you believe you were targeted by a foreign intelligence service "
              "specifically because of your clearance or government work",
        priority=2,
        fraud_types=["foreign_contact", "dprk_scheme", "espionage", "national_security"],
    ),
    ReportingAgency(
        name="USAJobs.gov — Report Fake Job Postings",
        handles="Fraudulent job postings impersonating USAJobs or federal agencies",
        url="https://www.usajobs.gov/Help/faq/application/process/",
        notes="Forward the fraudulent posting to USAJobs; legitimate federal job "
              "postings ONLY appear at usajobs.gov",
        priority=3,
        fraud_types=["fake_job_posting", "government_impersonation"],
    ),
]

# Quick lookup sets
FRAUD_TYPE_TO_AGENCIES: dict[str, list[ReportingAgency]] = {}
for _agency in REPORTING_AGENCIES:
    for _ft in _agency.fraud_types:
        FRAUD_TYPE_TO_AGENCIES.setdefault(_ft, []).append(_agency)


def get_agencies_for(fraud_type: str) -> list[ReportingAgency]:
    """Return agencies relevant to a specific fraud type, sorted by priority."""
    return sorted(
        FRAUD_TYPE_TO_AGENCIES.get(fraud_type, []),
        key=lambda a: a.priority,
    )


def get_all_fraud_types() -> list[str]:
    """Return sorted list of all supported fraud type keys."""
    return sorted(FRAUD_TYPE_TO_AGENCIES.keys())


# Immediate action checklist for when someone has already provided their SSN
IMMEDIATE_SSN_STOLEN_ACTIONS: list[str] = [
    "1. Go to identitytheft.gov — get a personalized recovery plan NOW",
    "2. Freeze credit at ALL 5 bureaus: Equifax, Experian, TransUnion, Innovis, ChexSystems",
    "3. Get an IRS Identity Protection PIN at irs.gov/ippin — prevents fraudulent tax returns",
    "4. Report to SSA OIG: oig.ssa.gov/report or call 1-800-269-0271",
    "5. File with FTC: reportfraud.ftc.gov",
    "6. File with FBI IC3: ic3.gov (if job fraud / online scam)",
    "7. Report to DCSA Counterintelligence if clearance-related: 571-305-6576 | "
       "dcsacounterfraud@mail.mil | dcsa.mil/MC/CI/ — "
       "DCSA OIG hotline: 1-855-865-1508 | dcsa.ig@mail.mil",
    "8. If a background investigation was already started under your name via NBIS/eApp, "
       "contact DCSA Applicant Knowledge Center: 878-274-5091 | DCSAAKC@mail.mil "
       "to report potential fraudulent investigation activity",
    "9. Notify your current employer's FSO — they need to know your SSN was compromised",
    "10. Monitor your credit reports weekly at annualcreditreport.com",
    "11. Set up fraud alerts with all banks / financial accounts",
]
