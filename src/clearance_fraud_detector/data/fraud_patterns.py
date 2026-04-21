"""
Regex patterns and keyword lists for clearance-job fraud detection.
Organized by fraud category with assigned risk weight (0.0 - 1.0).
"""

import re
from dataclasses import dataclass, field


@dataclass
class FraudPattern:
    name: str
    pattern: re.Pattern
    weight: float          # contribution to final risk score
    category: str
    explanation: str


def _p(regex: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(regex, flags)


# ---------------------------------------------------------------------------
# PII / Credential Harvesting
# ---------------------------------------------------------------------------
PII_PATTERNS: list[FraudPattern] = [
    FraudPattern("ssn_request", _p(r"social\s+security\s+(number|#|no\.?)"), 0.9,
                 "pii_harvest",
                 "SSN mentioned in recruiter/job email. SSN is only legitimately collected "
                 "post-conditional-offer by the FSO during eApp/SF-86 onboarding at "
                 "eapp.nbis.mil (NISPOM 32 CFR Part 117). Any recruiter asking for SSN "
                 "before a written conditional offer is a red flag."),
    FraudPattern("clearance_level_request", _p(r"(current|active|existing)\s+clearance\s+(level|status)"), 0.7,
                 "pii_harvest", "Asking clearance level before any interview is a red flag"),
    FraudPattern("bank_info_request", _p(r"(bank\s+account|routing\s+number|wire\s+transfer|direct\s+deposit\s+form)"), 0.95,
                 "pii_harvest", "Requests banking info in initial contact"),
    FraudPattern("passport_request", _p(r"(passport\s+number|copy\s+of\s+(your\s+)?passport)"), 0.85,
                 "pii_harvest", "Requests passport details before employment"),
    FraudPattern("dob_request", _p(r"(date\s+of\s+birth|birth\s+date|d\.?o\.?b\.?)"), 0.6,
                 "pii_harvest",
                 "DOB requested in recruiter/job email. DOB is legitimately collected during "
                 "the SF-86 (eApp) process post-offer. A recruiter requesting DOB at the "
                 "pre-screen or application stage has no authorized use for this data."),
]

# ---------------------------------------------------------------------------
# Upfront Fees & Financial Scams
# ---------------------------------------------------------------------------
FINANCIAL_PATTERNS: list[FraudPattern] = [
    FraudPattern("upfront_fee", _p(r"(processing\s+fee|application\s+fee|registration\s+fee|administrative\s+fee)"), 0.95,
                 "financial_scam", "Legit employers NEVER charge application fees"),
    FraudPattern("clearance_fee", _p(r"(fee\s+to\s+(obtain|get|process)\s+(a\s+)?(security\s+)?clearance|clearance\s+processing\s+fee)"), 1.0,
                 "financial_scam", "The government never charges individuals for clearances"),
    FraudPattern("gift_card_payment", _p(r"(gift\s+card|google\s+play\s+card|itunes\s+card|amazon\s+gift)"), 0.98,
                 "financial_scam", "Gift card payment requests are always scams"),
    FraudPattern("fake_check_scheme", _p(r"(deposit.{0,30}(check|cheque).{0,50}send.{0,30}(back|return|forward)|overpayment)"), 0.95,
                 "financial_scam", "Classic fake check scam pattern"),
    FraudPattern("wire_transfer", _p(r"wire\s+(transfer|the\s+money|funds)"), 0.8,
                 "financial_scam", "Wire transfer requests in job emails are red flags"),
    FraudPattern("cryptocurrency_payment", _p(r"(bitcoin|crypto(currency)?|ethereum|usdt|binance)"), 0.9,
                 "financial_scam", "Crypto payment requests are scam indicators"),
]

# ---------------------------------------------------------------------------
# Urgency / Pressure Tactics
# ---------------------------------------------------------------------------
URGENCY_PATTERNS: list[FraudPattern] = [
    FraudPattern("respond_immediately", _p(r"(respond\s+immediately|urgent(ly)?|act\s+now|limited\s+time|don[''t]\s+miss)"), 0.5,
                 "urgency", "High-pressure urgency is a manipulation tactic"),
    FraudPattern("positions_filling_fast", _p(r"(position(s)?\s+(filling|fill)\s+fast|limited\s+(seats|spots|positions)|first\s+come\s+first)"), 0.55,
                 "urgency", "Artificial scarcity pressure"),
    FraudPattern("secret_opportunity", _p(r"(confidential\s+opportunity|do\s+not\s+share|keep\s+this\s+(confidential|private|secret))"), 0.65,
                 "urgency", "Legitimate job offers are never secret"),
    FraudPattern("decision_deadline", _p(r"(must\s+decide\s+(by|within)|offer\s+expires\s+in\s+\d+\s+(hour|day))"), 0.6,
                 "urgency", "Artificial deadline is a pressure tactic"),
]

# ---------------------------------------------------------------------------
# Fake Clearance Promises
# ---------------------------------------------------------------------------
CLEARANCE_SCAM_PATTERNS: list[FraudPattern] = [
    FraudPattern("guarantee_clearance", _p(r"(guarantee\s+(you\s+)?(a\s+)?clearance|we\s+can\s+get\s+you\s+(a\s+)?clearance|clearance\s+guaranteed)"), 1.0,
                 "clearance_scam", "No one can guarantee a security clearance — this is always a scam"),
    FraudPattern("clearance_for_sale",
                 _p(r"(sell|buy|purchase)\s*.{0,20}(security\s+)?clearance"
                    r"|(we|i)\s+(can|will|could)\s+(get|obtain|provide|secure|acquire)"
                    r"\s+(you\s+)?(a\s+)?([\w/]+\s+)?clearance"
                    r"|clearance\s+(for\s+sale|sold\s+online|available\s+for\s+purchase)"), 0.95,
                 "clearance_scam",
                 "Clearances cannot be bought or sold. Note: standard job-posting language "
                 "'eligible to obtain a DoD security clearance' is NOT this pattern."),
    FraudPattern("polygraph_coaching", _p(r"(beat|pass|cheat|trick|fool).{0,20}(polygraph|lie\s+detector)"), 0.8,
                 "clearance_scam", "Polygraph coaching is illegal and a scam indicator"),
    FraudPattern("easy_ts_sci", _p(r"(easy|quick|fast|expedited).{0,30}(TS[/\s]?SCI|top\s+secret|clearance)"), 0.85,
                 "clearance_scam", "TS/SCI takes 1-2+ years — 'easy/fast' promises are lies"),
    FraudPattern("suspended_clearance", _p(r"(reinstate|restore|reactivate).{0,20}clearance.{0,40}fee"), 0.9,
                 "clearance_scam", "Charging to reinstate a clearance is not legitimate"),
]

# ---------------------------------------------------------------------------
# Impersonation / Domain Spoofing
# ---------------------------------------------------------------------------
IMPERSONATION_PATTERNS: list[FraudPattern] = [
    FraudPattern("fake_dod_claim", _p(r"(department\s+of\s+defense|d\.?o\.?d\.?|pentagon)\s+(recruiter|hiring\s+manager|representative)(?!\s{0,30}(?:with|at|for|from)\s+[A-Z])"), 0.6,
                 "impersonation", "Verify DoD-related claims carefully"),
    FraudPattern("nsa_cia_claim", _p(r"\b(NSA|CIA|DIA|NRO|NGA|ODNI|DHS|FBI)\b.{0,40}(hiring|recruit|position|job|opportunity)"), 0.55,
                 "impersonation", "IC agencies post jobs on USAJobs.gov only"),
    FraudPattern("contractor_name_mismatch", _p(r"(booz\s*allen|leidos|saic|raytheon|northrop|lockheed|l3\s*harris|caci|mantech)"), 0.3,
                 "impersonation", "Check that email domain matches company name"),
    FraudPattern("usajobs_impersonation", _p(r"(usajobs?\.(?!gov)|usa-jobs|usajobz)"), 0.9,
                 "impersonation", "Fake USAJobs domain — real site is usajobs.gov"),
]

# ---------------------------------------------------------------------------
# Suspicious Communication Patterns
# ---------------------------------------------------------------------------
COMMUNICATION_PATTERNS: list[FraudPattern] = [
    FraudPattern("personal_email_for_gov", _p(r"(gmail|yahoo|hotmail|outlook\.com|aol|proton).{0,20}(government|federal|dod|clearance|secret)"), 0.85,
                 "communication", "Government/contractor jobs never come from personal email services"),
    FraudPattern("whatsapp_telegram_contact", _p(r"(whatsapp|telegram|signal|wechat).{0,30}(contact|reach|message|interview)"), 0.75,
                 "communication", "Legitimate government contractors don't conduct hiring via chat apps"),
    FraudPattern("no_company_name", _p(r"(we\s+are\s+a\s+(leading|top|major)\s+(defense|government|federal)\s+contractor)"), 0.5,
                 "communication", "Vague company description without naming itself"),
    FraudPattern("offshore_interview", _p(r"(skype|zoom|google\s+meet).{0,50}(no\s+(in.person|face.to.face)|remote\s+only\s+interview)"), 0.4,
                 "communication", "Online-only interviews for clearance jobs are suspicious"),
    FraudPattern("send_resume_to_personal", _p(r"send.{0,20}(resume|cv).{0,20}(gmail|yahoo|hotmail|aol)"), 0.8,
                 "communication", "Sending resumes to personal email is unusual for cleared positions"),
]

# ---------------------------------------------------------------------------
# Too-Good-To-Be-True Salary / Benefits
# ---------------------------------------------------------------------------
SALARY_PATTERNS: list[FraudPattern] = [
    FraudPattern("unrealistic_salary", _p(r"(\$\s*[2-9]\d{2},\d{3}|\$[1-9]\d{3},\d{3}).{0,60}(entry.level|no\s+experience|junior|intern)"), 0.7,
                 "salary_bait", "Six-figure salary for entry-level cleared position is suspicious"),
    FraudPattern("work_from_home_clearance", _p(r"(work\s+from\s+home|remote\s+work|telecommute).{0,60}(TS[/\s]?SCI|top\s+secret|classified)"), 0.8,
                 "salary_bait", "TS/SCI work almost always requires a SCIF — fully remote is rare"),
    FraudPattern("no_experience_needed", _p(r"(no\s+experience\s+(required|needed)|experience\s+not\s+required).{0,60}clearance"), 0.65,
                 "salary_bait", "Cleared positions almost always require relevant experience"),
]

# ---------------------------------------------------------------------------
# Poor Quality / Grammar Indicators
# ---------------------------------------------------------------------------
QUALITY_PATTERNS: list[FraudPattern] = [
    FraudPattern("excessive_caps", _p(r"[A-Z]{5,}\s+[A-Z]{5,}\s+[A-Z]{5,}", re.DOTALL), 0.3,
                 "quality", "Excessive capitalization is a spam/fraud indicator"),
    FraudPattern("multiple_exclamations", _p(r"!{2,}|\?{2,}"), 0.25,
                 "quality", "Multiple exclamation marks suggest spam"),
    FraudPattern("dear_applicant", _p(r"dear\s+(applicant|candidate|job\s+seeker|friend|sir|madam)"), 0.4,
                 "quality", "Generic greeting with no name is a red flag"),
    FraudPattern("congratulations_opener", _p(r"^(congratulations|congrats).{0,50}(selected|chosen|approved|hired)"), 0.65,
                 "quality", "Premature congratulations without applying is a scam tactic"),
]

# ---------------------------------------------------------------------------
# DPRK / Foreign State-Actor IT Worker Scheme (North Korea, etc.)
# Ref: FBI/CISA Advisory AA23-129A, DOJ indictments 2023-2025
# ---------------------------------------------------------------------------
DPRK_IT_WORKER_PATTERNS: list[FraudPattern] = [
    FraudPattern("camera_off_required", _p(r"(camera\s+(must\s+be\s+)?off|no\s+video|video\s+(not\s+)?required|interview.{0,20}audio\s+only)"), 0.80,
                 "dprk_scheme", "Requiring camera-off interviews hides identity — major DPRK IT worker indicator"),
    FraudPattern("multiple_identities", _p(r"(another\s+(name|identity)|alias|different\s+name|goes?\s+by)"), 0.85,
                 "dprk_scheme", "Use of aliases or multiple identities is a state-actor scheme indicator"),
    FraudPattern("vpn_location_mismatch", _p(r"(vpn|proxy|virtual\s+location|appear.{0,15}(local|domestic|us.based))"), 0.65,
                 "dprk_scheme", "VPN usage to mask foreign location is an active scheme tactic"),
    FraudPattern("third_party_laptop", _p(r"(laptop.{0,30}(shipped|send|provided|mail).{0,20}(address|location)|farm\s+laptop|managed\s+laptop)"), 0.80,
                 "dprk_scheme", "Laptop farm / forwarding address is a known DPRK IT worker tactic"),
    FraudPattern("payment_forwarding", _p(r"(forward.{0,20}(payment|salary|funds)|remit.{0,20}(overseas|abroad|korea|china)|transfer.{0,20}overseas)"), 0.90,
                 "dprk_scheme", "Forwarding salary overseas to North Korea / China is the scheme's end goal"),
    FraudPattern("unusually_fast_hire", _p(r"(hired.{0,20}(today|immediately|right\s+now|on\s+the\s+spot)|start\s+(today|immediately|as\s+soon\s+as\s+possible).{0,30}clearance)"), 0.70,
                 "dprk_scheme", "Instant hire for cleared positions is impossible — clearances take months"),
    FraudPattern("multiple_concurrent_jobs", _p(r"(multiple\s+(jobs?|positions?|contracts?)|side\s+(jobs?|gigs?|work).{0,40}clearance|concurrent.{0,20}contracts?)"), 0.65,
                 "dprk_scheme", "DPRK workers typically juggle multiple jobs simultaneously"),
    FraudPattern("i9_pre_hire_pii", _p(r"(i.?9\s+(before|prior|first|upfront)|complete.{0,20}i.?9.{0,20}(before\s+interview|first|prior\s+to))"), 0.85,
                 "dprk_scheme", "Requesting I-9 completion before any interview is a PII-harvest tactic"),
    FraudPattern("w4_pre_hire", _p(r"(w.?4\s+(before|prior|first|upfront|immediately)|tax\s+form.{0,30}(before\s+interview|first\s+step))"), 0.80,
                 "dprk_scheme", "Requesting W-4 before hire is premature PII collection"),
    # --- FBI/CISA PSA I-101823-PSA (Oct 2023) additional indicators ---
    FraudPattern("prepayment_extortion", _p(
        r"(prepay(ment)?|advance\s+pay(ment)?|pay\s+upfront).{0,40}(work|project|contract|start)"
        r"|(repeated|additional)\s+request.{0,20}(pay(ment)?|fund)"
        r"|threat.{0,30}(release|publish|expose).{0,20}(source\s+code|proprietary|ip)"
        r"|will\s+(release|expose|publish|leak).{0,50}(source\s+code|proprietary\s+code|your\s+ip|codebase)"), 0.90,
        "dprk_scheme",
        "Prepayment demands or source-code extortion are documented DPRK IT worker scheme tactics "
        "(FBI PSA I-101823-PSA, Oct 2023). DPRK workers demand prepayment or threaten IP release."),
    FraudPattern("unsolicited_selection", _p(
        r"(you\s+(have\s+been|are|were)\s+(selected|chosen|shortlisted|pre.?approved)"
        r".{0,60}(interview|position|role|opportunity)"
        r"|congratulations.{0,40}(selected|chosen|shortlisted).{0,40}(without|before|prior\s+to)\s+"
        r"(applying|submitting|an?\s+interview|application))"), 0.75,
        "dprk_scheme",
        "Unsolicited 'you have been selected' before any application is a social engineering "
        "hook documented in DPRK IT worker and fake recruiter schemes."),
    FraudPattern("foreign_university_us_only", _p(
        r"(universit.{0,20}(china|japan|singapore|malaysia|korea|indonesia|vietnam)"
        r".{0,200}(employm.{0,20}(united\s+states|us\s+only|american)|us\s+client|american\s+compan))"
        r"|(education.{0,80}asia.{0,200}work\s+(exclusively|only|primarily).{0,30}(united\s+states|us|american))",
        re.IGNORECASE | re.DOTALL), 0.70,
        "dprk_scheme",
        "Education at Asian universities with work exclusively in the US is a documented DPRK "
        "IT worker profile indicator (FBI PSA I-101823-PSA)."),
    FraudPattern("payment_platform_switch", _p(
        r"(use\s+(different|another|alternate|new)\s+(payment|payroll|platform|method|account)"
        r"|switch\s+(to|from).{0,30}(payment|platform|payroll|venmo|zelle|cashapp|wire)"
        r"|change\s+(payment|payroll|account).{0,40}(request|asking|need))"), 0.80,
        "dprk_scheme",
        "Requesting payment platform switches mid-contract is a DPRK money laundering evasion "
        "tactic documented in FBI/CISA AA23-129A."),
]

# ---------------------------------------------------------------------------
# AI Voice / Vishing / Fake Interview Fraud
# Foreign actors use AI voice changers to disguise accents and identities
# ---------------------------------------------------------------------------
VISHING_PATTERNS: list[FraudPattern] = [
    FraudPattern("ai_voice_interview", _p(r"(voice\s+(sounds?\s+(robotic|artificial|strange|odd|synthesized))|ai.generated\s+voice|voice\s+changer|synthetic\s+voice)"), 0.85,
                 "vishing", "AI-generated/synthetic voice in interviews is a foreign fraud indicator"),
    FraudPattern("script_reading_signs", _p(r"(reading\s+from\s+(a\s+)?script|scripted\s+(answers?|responses?)|sounds?\s+scripted|rehearsed\s+answers?)"), 0.70,
                 "vishing", "Script-reading in interviews may indicate a fake/foreign actor"),
    FraudPattern("no_followup_questions", _p(r"(no\s+follow.?up\s+questions?|didn[''t].{0,10}ask\s+(any\s+)?questions?|interview\s+required\s+no\s+questions?)"), 0.60,
                 "vishing", "No follow-up questions in a technical interview is suspicious"),
    FraudPattern("immediate_offer_no_interview", _p(r"(offer.{0,20}without.{0,20}interview|hired.{0,20}no\s+interview|job.{0,20}no\s+interview\s+needed|skip.{0,15}interview)"), 0.85,
                 "vishing", "Real cleared positions require thorough in-person interviews"),
    FraudPattern("only_text_chat_interview", _p(r"(interview.{0,30}(text\s+only|chat\s+only|whatsapp|telegram|sms|text\s+message)|hiring.{0,20}via\s+(whatsapp|telegram|text))"), 0.90,
                 "vishing", "Text-only hiring is a major fraud indicator for clearance positions"),
    FraudPattern("heavy_accent_inconsistency", _p(r"(heavy\s+accent|foreign\s+accent.{0,30}(claim|said|stated)\s+(american|us\s+citizen|domestic)|accent\s+inconsistent)"), 0.75,
                 "vishing", "Claimed US citizenship but heavy foreign accent suggests identity fraud"),
    FraudPattern("telegram_only_recruiter", _p(r"(only\s+(reach|contact|available)\s+(via|on|through)\s+(telegram|whatsapp|signal)\s+|recruiter\s+(is\s+)?(only\s+)?(on|via)\s+(telegram|whatsapp))"), 0.90,
                 "vishing", "Recruiters exclusively on Telegram/WhatsApp are almost always scammers"),
]

# ---------------------------------------------------------------------------
# Identity Reconstruction / Full PII Harvest Attack
# Collecting name + SSN + DOB + address = complete identity theft package
# ---------------------------------------------------------------------------
IDENTITY_THEFT_PATTERNS: list[FraudPattern] = [
    FraudPattern("full_ssn_dob_combo", _p(r"(social\s+security.{0,60}date\s+of\s+birth|ssn.{0,60}dob|dob.{0,60}ssn|date\s+of\s+birth.{0,60}social\s+security)"), 1.0,
                 "identity_theft", "Requesting SSN + DOB combo is a complete identity theft setup"),
    FraudPattern("address_ssn_combo", _p(r"(address.{0,80}social\s+security|social\s+security.{0,80}address).{0,20}(number|#|no)"), 0.95,
                 "identity_theft", "SSN + full address enables credit fraud and identity takeover"),
    FraudPattern("mothers_maiden_name", _p(r"(mother.{0,10}maiden\s+name|maiden\s+name.{0,10}mother)"), 0.90,
                 "identity_theft", "Asking for mother's maiden name targets security question bypass"),
    FraudPattern("drivers_license_request", _p(r"(driver.{0,5}license\s+number|dl\s+number|driving\s+license\s+number)"), 0.75,
                 "identity_theft", "Requesting driver's license number before hire is PII harvesting"),
    FraudPattern("copy_of_id_request", _p(r"(send.{0,20}(copy|photo|picture|scan).{0,20}(id|identification|driver.{0,5}license|passport)|photo\s+id.{0,20}(email|send|attach))"), 0.85,
                 "identity_theft", "Requesting ID photos by email is a data theft vector"),
    FraudPattern("financial_account_pre_hire", _p(r"(bank\s+(account|routing).{0,40}(before\s+(hire|offer)|upfront|immediately|first)|financial\s+(info|information).{0,30}(before\s+start|prior\s+to))"), 0.95,
                 "identity_theft", "Bank details before any offer is financial fraud setup"),
    FraudPattern("credit_check_fee", _p(r"(credit\s+check\s+fee|pay.{0,20}credit\s+(check|report)|credit\s+history\s+fee)"), 0.90,
                 "identity_theft", "Charging for a credit check is a fraud tactic — legitimate employers pay"),
]

# ---------------------------------------------------------------------------
# Fake Job Platform / Recruitment Fraud
# ---------------------------------------------------------------------------
FAKE_PLATFORM_PATTERNS: list[FraudPattern] = [
    FraudPattern("clearancejobs_impersonation", _p(r"clearance.jobs?(?!\.com)|clearancejobz|clearancejob\.(net|org|info|co)"), 0.95,
                 "fake_platform", "Fake ClearanceJobs domain — real site is clearancejobs.com"),
    FraudPattern("linkedin_impersonation", _p(r"linked-?in\.(?!com)|1inkedin|linkedln|linkediin|link3din"), 0.90,
                 "fake_platform", "Fake LinkedIn domain"),
    FraudPattern("indeed_impersonation", _p(r"ind33d|indeeed|indeed\.(net|org|info)|indeed-jobs\."), 0.90,
                 "fake_platform", "Fake Indeed domain"),
    FraudPattern("usajobs_fake", _p(r"usajobs?\.(?!gov)|usa-jobs\.(com|net|org)|usajobz|jobs\.usa\.(com|net)"), 0.95,
                 "fake_platform", "Fake USAJobs — only usajobs.gov is official"),
    FraudPattern("fake_job_board", _p(r"(defenselinejobs|clearedjobsusa|clearedpositions|tsscipositions|tssci-jobs)\.(com|net|org)"), 0.90,
                 "fake_platform", "Known fake cleared job board domain"),
    FraudPattern("recruiter_no_company", _p(r"(independent\s+recruiter|freelance\s+recruiter|recruiting\s+agent).{0,50}(clearance|secret|ts[/\s]sci|dod|government)"), 0.70,
                 "fake_platform", "Independent recruiters rarely handle classified openings — verify carefully"),
]

# ---------------------------------------------------------------------------
# AI-Generated Content Indicators
# Fraudsters use LLMs to write convincing but tell-tale job postings
# ---------------------------------------------------------------------------
AI_GENERATED_PATTERNS: list[FraudPattern] = [
    FraudPattern("ai_perfect_grammar_foreign", _p(r"(we\s+are\s+committed\s+to\s+(excellence|diversity|inclusion).{0,100}(please\s+provide|kindly\s+submit|do\s+the\s+needful))"), 0.65,
                 "ai_generated", "AI-polished text mixed with non-native phrases suggests AI-assisted fraud"),
    FraudPattern("nonstandard_greeting", _p(r"(greetings\s+of\s+the\s+day|i\s+am\s+(mr|mrs|ms|dr)\.?\s+\w+\s+from\s+(the\s+)?(hr|human\s+resources)|i\s+do\s+hope\s+this\s+(finds?|meets?)\s+you\s+well)"), 0.60,
                 "ai_generated", "Non-native English greeting patterns common in fraud emails"),
    FraudPattern("do_the_needful", _p(r"(do\s+the\s+needful|revert\s+back|prepone|kindly\s+(do|revert|provide|send|reply))"), 0.70,
                 "ai_generated", "South/East Asian English idioms in US clearance job contexts suggest fraud"),
    FraudPattern("generic_company_description", _p(r"(we\s+are\s+a\s+(reputable|renowned|well.established|leading).{0,30}(company|firm|organization).{0,60}(defense|government|federal).{0,80}(seeking|looking\s+for|hiring))"), 0.55,
                 "ai_generated", "Generic AI-style company description without naming the actual company"),
]

# ---------------------------------------------------------------------------
# Background Investigation Manipulation
# Real clearance process is defined by DCSA — no shortcuts exist
# ---------------------------------------------------------------------------
BACKGROUND_CHECK_SCAM_PATTERNS: list[FraudPattern] = [
    FraudPattern("skip_background_check", _p(r"(no\s+background\s+(check|investigation)|background\s+(check|investigation)\s+not\s+required|skip.{0,15}background)"), 0.85,
                 "background_scam", "All cleared positions REQUIRE background investigations — this is a lie"),
    FraudPattern("accelerated_investigation", _p(r"(expedited\s+(background|investigation|clearance\s+process)|background\s+(check|investigation).{0,20}(rush|fast|quick|accelerat))"), 0.75,
                 "background_scam", "DCSA background investigations cannot be legitimately rushed through money"),
    FraudPattern("private_background_check_fee", _p(r"(private.{0,20}background\s+(check|investigation).{0,30}fee|pay.{0,20}(for\s+(your\s+)?background|background\s+(check|investigation)\s+cost))"), 0.90,
                 "background_scam", "Charging candidates for their own background investigation is fraud"),
    FraudPattern("dcsa_impersonation", _p(r"(d\.?c\.?s\.?a\.|defense\s+counterintelligence.{0,20}(agent|officer|representative)|nbib\s+agent)"), 0.70,
                 "background_scam", "Impersonating DCSA/NBIB investigators to extract PII"),
]


# ---------------------------------------------------------------------------
# FSO Impersonation Patterns
# A real FSO uses DISS to check clearance status — they NEVER ask the candidate
# to provide an SSN "for clearance verification." That is the core exploit.
# ---------------------------------------------------------------------------
FSO_IMPERSONATION_PATTERNS: list[FraudPattern] = [
    FraudPattern("fso_ssn_for_clearance_check", _p(
        r"(need\s+(your\s+)?(ssn|social\s+security).{0,60}(verify|confirm|check|look\s+up)"
        r".{0,60}clearance"
        r"|verify\s+(your\s+)?clearance.{0,60}(ssn|social\s+security)"
        r"|(ssn|social\s+security).{0,40}(required|needed)\s+to\s+(verify|confirm|check)"
        r"\s+(your\s+)?(clearance|access|eligibility))"), 1.0,
        "fso_impersonation",
        "Real FSOs look you up in DISS by name/employer — they NEVER need the candidate "
        "to supply their SSN to confirm clearance status. This is the #1 fake-FSO exploit."),
    FraudPattern("fso_dcsa_cold_contact", _p(
        r"(i\s+(am|work\s+for|represent)\s+(dcsa|nbib|defense\s+counterintelligence"
        r"|national\s+background\s+investigations)"
        r"|calling\s+(from|on\s+behalf\s+of)\s+(dcsa|nbib)"
        r"|dcsa.{0,20}(agent|officer|investigator|representative)\s+(calling|contacting)"
        r"|your\s+clearance\s+(file|record|case)\s+(is\s+)?(being\s+)?"
        r"(reviewed|held|flagged)\s+by\s+(dcsa|nbib))"), 0.95,
        "fso_impersonation",
        "DCSA investigators do NOT cold-contact job candidates. Contact DCSA fraud "
        "line 571-305-6576 to report."),
    FraudPattern("fso_clearance_suspended_threat", _p(
        r"(clearance\s+(has\s+been\s+|is\s+)?(suspended|revoked|put\s+on\s+hold|flagged)"
        r".{0,100}(provide|send|pay|submit|call)"
        r"|your\s+clearance\s+(will\s+be\s+)?(suspended|revoked)\s+(if\s+you\s+don['']?t|unless)"
        r"|reactivat.{0,10}(clearance|access).{0,60}(fee|pay|send|provide))"), 0.95,
        "fso_impersonation",
        "Clearance suspensions are processed through your CURRENT employer's FSO via "
        "official DISS notices — never via cold email or phone to candidates."),
    FraudPattern("fso_clearance_transfer_fee", _p(
        r"(fee.{0,40}(clearance|diss|background\s+investigation)"
        r"|(clearance|diss).{0,40}fee"
        r"|pay.{0,30}(to\s+)?(process|transfer|verify|initiate)\s+(your\s+)?clearance"
        r"|clearance\s+(processing|transfer|verification)\s+fee)"), 1.0,
        "fso_impersonation",
        "Clearance transfers are free and handled FSO-to-FSO through DISS. No fee exists."),
    FraudPattern("fso_diss_ssn_pull", _p(
        r"(need\s+(your\s+)?ssn\s+to\s+(pull|look\s+up|find|search|enter)\s+"
        r"(you\s+in\s+)?(diss|jpas|scattered\s+castles)"
        r"|(diss|jpas|scattered\s+castles).{0,60}(need|require|must\s+have).{0,40}ssn)"), 0.95,
        "fso_impersonation",
        "FSOs initiate DISS lookups from their credentialed accounts using name and "
        "employer — NOT by asking the candidate to provide their SSN."),
    FraudPattern("fso_id_docs_by_email", _p(
        r"(email|send|attach|forward|upload).{0,30}"
        r"(copy|photo|picture|scan|image).{0,20}"
        r"(passport|driver.{0,5}license|state\s+id|military\s+id|cac|common\s+access\s+card)"), 0.80,
        "fso_impersonation",
        "ID document photos are collected in person or via secure government portals, "
        "never by email attachment."),
    FraudPattern("shared_credentials_in_email", _p(
        r"(user\s+(name|id)\s*:?\s*\w{3,20}\s.{0,80}password\s*:?\s*\w{3,20}"
        r"|password\s*:?\s*\w{3,20}.{0,80}user\s+(name|id)\s*:?\s*\w{3,20}"
        r"|(log\s*in|login|sign\s*in).{0,80}(user\s*name|username|user\s+id).{0,80}password"
        r"|temporary\s+(user\s*name|username|password).{0,80}(provided|below|here))"),
        0.40, "fso_impersonation",
        "Generic shared credentials (username + password) included in a recruitment email. "
        "Even for low-privilege read-only systems, publishing literal credentials in email "
        "creates a perfect spoofing template: fraudsters copy the exact format, swap the "
        "URL for a credential-harvesting site, and send identical-looking emails to cleared "
        "candidates. This pattern appears in EY Government & Public Sector onboarding for "
        "their Independence compliance portal — in that context from a verified @ey.com/@eygps.us "
        "sender it is legitimate but the structural risk is real. Never credentials in email."),
    FraudPattern("do_not_copy_return_only", _p(
        r"(do\s+not\s+copy\s+(anyone|any\s+one|others?|anyone\s+else).{0,100}email"
        r"|return.{0,60}(to\s+)?(only|ONLY).{0,150}do\s+not\s+copy"
        r"|please\s+make\s+sure\s+you\s+do\s+(not|NOT)\s+copy\s+anyone"
        r"|return.{0,100}(only|ONLY).{0,100}(please\s+make\s+sure|do\s+not\s+copy))"),
        0.35, "fso_impersonation",
        "'Return this document ONLY to [addresses] — do NOT copy anyone else on the email.' "
        "While legitimate government-sector employers (EY GPS, cleared defense firms) use "
        "this instruction for clearance eligibility prescreens as an OPSEC measure, "
        "the exact same pattern is the most effective phishing isolation tactic: it prevents "
        "the recipient from forwarding to IT security, HR, or contacts who could verify the "
        "sender's identity. Always verify the sender domain independently (WHOIS lookup) and "
        "call the company's published main number before returning any document with PII."),
]

# ---------------------------------------------------------------------------
# Fake Recruiter (Pre-Hire PII Harvest)
# Distinguishes between a legitimate cleared-job recruiter and a fraud front
# designed to harvest PII or run a DPRK IT worker scheme.
# ---------------------------------------------------------------------------
FAKE_RECRUITER_PATTERNS: list[FraudPattern] = [
    FraudPattern("recruiter_ssn_before_offer", _p(
        r"(send\s+(me|us)\s+(your\s+)?(ssn|social\s+security)"
        r"|provide\s+(your\s+)?(ssn|social\s+security).{0,60}(resume|application|profile)"
        r"|(ssn|social\s+security).{0,60}(initial|first|apply|applying|application)"
        r"|need\s+(your\s+)?(ssn|social\s+security).{0,60}(before|prior\s+to).{0,60}interview)"), 0.95,
        "fake_recruiter",
        "SSN is only collected AFTER a written offer is accepted, via secure HR portal. "
        "A recruiter asking for SSN before an offer is harvesting PII."),
    FraudPattern("recruiter_full_pii_profile", _p(
        r"(full\s+(legal\s+)?name.{0,100}(ssn|social\s+security|date\s+of\s+birth)"
        r"|(ssn|social\s+security).{0,100}(address|date\s+of\s+birth|dob|passport)"
        r"|(name|address|dob|date\s+of\s+birth).{0,80}(ssn|social\s+security\s+number)"
        r".{0,80}(application|profile|form|screening))"), 1.0,
        "fake_recruiter",
        "Requesting name + SSN + DOB + address is a complete identity reconstruction "
        "attack enabling credit, tax, and benefit fraud."),
    FraudPattern("recruiter_ic_agency_claim", _p(
        r"(i\s+(am|work\s+for|represent|am\s+a\s+recruiter\s+for)\s+(nsa|cia|dia|nro|nga|odni|dhs)"
        r"|recruiter\s+(from|at|for|with)\s+(the\s+)?(nsa|cia|dia|nro|nga|odni|dhs)"
        r"|(nsa|cia|dia|nro|nga).{0,50}(recruiter|hiring\s+manager|talent\s+acquisition))"), 0.90,
        "fake_recruiter",
        "IC agencies (NSA, CIA, DIA, NRO, NGA) post ALL positions on USAJobs.gov. "
        "They do not use independent recruiters for cleared positions."),
    FraudPattern("resume_falsification_request", _p(
        r"(add\s+(a\s+few\s+)?(lines?|words?|bullets?|points?).{0,60}"
        r"(your\s+)?(resume|contract|experience|background|profile)"
        r"|update\s+your\s+resume\s+(to\s+)?(reflect|highlight|show|include)"
        r"|i\s+(can|will)\s+(update|revise|edit|modify).{0,40}your\s+resume"
        r"|highlight\s+(your\s+)?recent\s+experience\s+with.{0,60}"
        r"(your\s+)?(latest|most\s+recent|last|current)\s+(contract|position|role|project)"
        r"|can\s+you\s+add.{0,60}(to\s+)?(your\s+)?(resume|cv|profile)"
        r"|share\s+(a\s+)?(few|some)\s+(points?|lines?|bullets?|words?).{0,60}"
        r"and\s+(i|we)\s+(can|will)\s+(update|revise|edit))"),
        0.80, "fake_recruiter",
        "Recruiter asking candidate to add skills/experience to their resume, or offering "
        "to 'update the resume on your behalf.' Submitting a falsified resume to a federal "
        "contractor (FBI, DoD, IC) is a 18 U.S.C. §1001 false statement risk and can "
        "jeopardize an existing clearance during adjudication. A legitimate recruiter "
        "submits what you provide — they do not ghost-write federal contractor resume fraud."),
    FraudPattern("bulk_pii_intake_form", _p(
        r"(full\s+legal\s+name\s*[:\-]\s*$"
        r"|phone\s+no\.?\s*[:\-]\s*$"
        r"|work\s+authorization\s+status\s*[:\-]\s*$"
        r"|current\s+location.{0,25}city.{0,15}state.{0,5}\s*[:\-]\s*$"
        r"|availability\s+to\s+start.{0,40}[:\-]\s*$"
        r"|willing\s+to\s+relocate.{0,30}[:\-]"
        r"|rate\s+expectations?\s*[:\-]\s*$"
        r"|best\s+time.{0,30}(call|contact|reach).{0,30}[:\-]\s*$)",
        re.IGNORECASE | re.MULTILINE), 0.60,
        "fake_recruiter",
        "Bulk PII intake form embedded in the email: fields for full legal name, phone, "
        "work authorization, location, availability, relocation willingness, and rate "
        "expectations — all collected before any interview or offer. Legitimate recruiters "
        "gather some of this data verbally during a screen call; sending a structured form "
        "in a cold-contact email is a PII harvesting technique used to build cleared-professional "
        "contact databases without ever filling an actual position."),
    FraudPattern("criminal_history_prescreen", _p(
        r"(any\s+(misdemeanor|felony|criminal\s+(record|history|conviction))"
        r"|misdemeanor\s+or\s+felony\s+(in\s+)?(past|last)\s+\d+\s+years?"
        r"|felony\s+(conviction|charge).{0,30}(past|last)\s+\d+"
        r"|criminal\s+background.{0,40}(past|last)\s+\d+\s+years?)"),
        0.55, "fake_recruiter",
        "Criminal history question at initial recruiter contact, before any offer exists. "
        "Background check authorization (including criminal history) is only conducted "
        "post-conditional-offer, under FCRA rules, via an authorized PBSA-accredited "
        "background screening vendor — not in a cold-contact email form. Collecting this "
        "data in a pre-screen form violates EEOC guidance on criminal history inquiries "
        "and is a red flag for non-compliant or fraudulent hiring operations."),
    FraudPattern("competing_offers_intel_probe", _p(
        r"(how\s+many\s+(interviews?\s+(and\s+)?)?offers?\s+(in\s+)?pipeline"
        r"|interviews?\s+(and\s+)?offers?\s+in\s+pipeline"
        r"|other\s+(offers?|interviews?)\s+(pending|in\s+(process|pipeline))"
        r"|currently\s+(interviewing|in\s+process)\s+(with|for|at).{0,40}(other|another)"
        r"|competing\s+(offers?|opportunities?)\s+you\s+(have|are\s+considering)"
        r"|what\s+other\s+(offers?|positions?|roles?|opportunities?)\s+(are\s+you|do\s+you\s+have))"),
        0.50, "fake_recruiter",
        "Competitor intelligence probe: asking how many other interviews or offers are in "
        "your pipeline at initial recruiter contact. Legitimate recruiters may ask this "
        "near the offer stage to calibrate a competitive offer — not in a cold-contact "
        "intake form. At the pre-screen stage, this is market intelligence collection: the "
        "recruiter learns which companies are hiring cleared candidates and how long their "
        "hiring cycles are. This data is useful to staffing firms regardless of whether "
        "you get the job, and is a hallmark of resume-database-building operations."),
    FraudPattern("exclusive_sourcing_authority_claim", _p(
        r"(sole\s+(agency|provider|recruiter|source|vendor|partner).{0,80}"
        r"(recruit|sourc|hir|staffing)"
        r"|exclusive.{0,30}(recruiter|agency|staffing|source|partner).{0,80}"
        r"(for|to|of).{0,40}(recruit|sourc|hir)"
        r"|only\s+(agency|firm|company|recruiter).{0,60}(recruit|source|hire|staffing))"),
        0.45, "fake_recruiter",
        "Exclusive/sole-agency authority claim: asserting the firm is the only recruiter "
        "authorized to place candidates with the target company. This framing is a pressure "
        "tactic designed to prevent you from applying directly or through other channels. "
        "In reality, most prime defense contractors post positions on their own careers page "
        "and on multiple platforms simultaneously. An 'exclusivity' claim from a staffing "
        "intermediary has no legal force and cannot be verified. When combined with an "
        "unnamed client and a PII intake form, it is a strong indicator of either a "
        "fraudulent listing or a resume-harvesting operation."),
]


# ---------------------------------------------------------------------------
# Process Void / Ghost Employer — No Callback, No Next Steps, No Timeline
#
# Real cleared-position recruiting has a defined process: screening → interview
# → panel → offer → conditional-offer → eApp (SF-86). Every legitimate step
# comes with a named contact, a phone/email, and a stated decision window.
# Fake employers, PII harvesters, and resume-database scrapers share a common
# tell: they request your information and then go dark — no timeline, no named
# point of contact, no scheduled next step, no decision window.
#
# This pattern group detects the linguistic signatures of a process that was
# never intended to progress beyond the data-collection step.
#
# Sources: DCSA FSO training; FBI IC3 cleared-position fraud case files;
# 32 CFR §117.10 — each legitimate step has a defined FSO-auditable action.
# ---------------------------------------------------------------------------
ENGAGEMENT_GHOST_PATTERNS: list[FraudPattern] = [
    FraudPattern("resume_on_file_harvest", _p(
        r"(keep\s+(your\s+)?(resume|cv|profile)\s+on\s+file"
        r"|add\s+(you\s+)?to\s+(our\s+)?(talent\s+(pool|pipeline|database)"
        r"|database|candidate\s+pool|network)"
        r"|on\s+file\s+for\s+(future|upcoming|potential)\s+(opportunities?|openings?|positions?)"
        r"|file\s+(away|your\s+(resume|cv|profile))\s+for\s+future"
        r"|reach\s+out\s+when\s+(something|an?\s+(opening|position|role|opportunity))\s+"
        r"(comes?\s+up|opens?|arises?|becomes?\s+available))"), 0.45,
        "process_void",
        "No open position — resume harvesting language detected. 'Keep on file' / 'add to "
        "talent pool' indicates there is no actual open requisition: the message is collecting "
        "resumes speculatively. Every real cleared DoD/IC position has an active requisition "
        "tied to a contract task order. A recruiter who cannot cite a specific open req number "
        "is either mapping your clearance history for future targeting or building a resume "
        "database — not filling a real billet. Ask for the specific contract number and "
        "requisition before submitting any information."),
    FraudPattern("vague_callback_no_date", _p(
        r"(we[''ll]{1,3}\s+(be\s+in\s+touch|reach\s+out|contact\s+you|get\s+back\s+to\s+you"
        r"|follow\s+up\s+with\s+you|be\s+reaching\s+out)"
        r"(?!\s*(within|by|before|in\s+\d|on\s+\w{3,9}day|tomorrow|next\s+week"
        r"|monday|tuesday|wednesday|thursday|friday|in\s+the\s+next\s+\d))"
        r"|you[''ll]{1,3}\s+hear\s+(from\s+us|back\s+from\s+us)"
        r"(?!\s*(within|by|before|in\s+\d|on\s+\w{3,9}day|tomorrow|next\s+week))"
        r"|will\s+contact\s+you\s+soon"
        r"|will\s+follow\s+up\s+shortly"
        r"|will\s+be\s+in\s+contact\s+soon"
        r"|stay\s+tuned\s+for\s+(updates?|more\s+information|next\s+steps?)"
        r"|look\s+out\s+for\s+(an?\s+)?email\s+from\s+us)"), 0.35,
        "process_void",
        "Vague callback promise with no stated date or window. Legitimate cleared-position "
        "recruiters always give a specific next-step timeline: 'The hiring manager will call "
        "within 3 business days' or 'We will schedule a panel interview week of [date].' "
        "A blanket 'we'll be in touch' with no timeframe indicates either a bulk email blast "
        "with no real follow-up intent, or a data-collection scheme that was never meant to "
        "advance past the resume-submission step. Always ask: 'By what date should I expect "
        "to hear back?' — a legitimate recruiter will have a concrete answer."),
    FraudPattern("indefinite_opening_wait", _p(
        r"(when\s+(a\s+)?(suitable\s+)?(position|role|opportunity|opening|billet)"
        r"\s+(opens?|becomes?\s+available|comes?\s+up|arises?)"
        r"|if\s+(something|anything)\s+(suitable|matching|relevant|appropriate)"
        r"\s+(comes?\s+up|opens?|arises?|becomes?\s+available|materializes?)"
        r"|once\s+(we\s+(have|find|identify)|there\s+(is|are))\s+(a\s+)?"
        r"(suitable|matching|right)\s+(position|opening|role|opportunity|fit)"
        r"|if\s+and\s+when\s+(a\s+)?(position|role|opening|opportunity)"
        r"|contingent\s+on\s+(a\s+)?(position|role|opening|contract)\s+(opening|award|becoming\s+available))"),
        0.50, "process_void",
        "No active position — 'when something opens up' language. This confirms there is no "
        "open requisition attached to this outreach. Cleared billets are contract-funded: they "
        "exist (or do not exist) the moment a recruiter contacts you. 'When something opens' "
        "has two possible explanations: (1) the recruiter is speculatively building a resume "
        "database for future use, or (2) the interaction is a clearance-status mapping probe "
        "— contact you, establish that you're cleared and on the market, log your program "
        "history, then file it. Either way, submitting your resume, clearance level, or "
        "program history under these conditions benefits the recruiter — not you."),
    FraudPattern("no_contact_us_barrier", _p(
        r"(please\s+do\s+not\s+(call|contact|email|reach\s+out\s+to)\s+"
        r"(us|our\s+office|the\s+team|hr|our\s+office)"
        r"|do\s+not\s+(call|contact|email)\s+(us|our\s+(office|team|hr))"
        r"|refrain\s+from\s+(contacting|calling|emailing|following\s+up)"
        r"|we\s+will\s+(contact|reach\s+out|follow\s+up).{0,40}"
        r"please\s+(do\s+not|don.?t)\s+(call|contact|email|reach\s+out)"
        r"|no\s+(phone\s+calls?|calls?\s+please|inquiries?)\s*[.,]"
        r"|phone\s+calls?\s+will\s+not\s+be\s+(accepted|returned|answered))"),
        0.55, "process_void",
        "'Do not contact us' — no inbound channel provided. Legitimate cleared-position "
        "recruiting always includes a named HR contact, a phone number, and a way to follow "
        "up (often required by the candidate's FSO for reporting purposes). A recruiter who "
        "blocks all contact and demands you wait passively eliminates your ability to: "
        "(a) verify the company exists at sam.gov, (b) confirm the recruiter's identity, "
        "(c) report the contact to your FSO as required by SEAD 3 reporting guidelines. "
        "This pattern combined with a PII request is a strong ghost-employer indicator."),
    FraudPattern("submit_wait_no_step", _p(
        r"(submit\s+(your\s+)?(resume|cv|application|profile|information|details)"
        r".{0,120}"
        r"(we\s+will\s+(review|look\s+over|go\s+through|consider)"
        r"|our\s+team\s+will\s+(review|assess|evaluate)"
        r"|will\s+be\s+reviewed)"
        r"(?!.{0,120}(within|by|before|interview|schedule|call|next\s+step|contact\s+you\s+within"
        r"|in\s+\d|on\s+\w{3,9}day|business\s+days?))"
        r"|send\s+us\s+your\s+(resume|cv|ssn|application).{0,80}"
        r"and\s+(we|our\s+team)\s+will\s+(be\s+in\s+touch|follow\s+up|reach\s+out|review)"
        r"(?!.{0,80}(within|by|in\s+\d|business\s+days?|next\s+step|schedule)))"),
        0.45, "process_void",
        "Submit-and-disappear pattern: requests documents/PII with no stated review "
        "timeline, no next-step action, and no scheduled callback. Every step in a real "
        "cleared-hiring pipeline has a defined output: a technical screen, a panel interview, "
        "a conditional offer, an eApp invite. A message that says 'send us your resume and "
        "we'll review it' with no further process defined is structurally identical to a "
        "PII-collection form — the process ends when you submit. Ask: 'What is the next "
        "step after I submit, and by when should I expect a response?'"),
    FraudPattern("no_named_point_of_contact", _p(
        r"(if\s+you\s+have\s+(any\s+)?(questions?|concerns?)\s*[,.]?\s*"
        r"(?:please\s+)?(?:do\s+not\s+hesitate\s+to\s+)?(?:feel\s+free\s+to\s+)?"
        r"(?:reply\s+to\s+this\s+email|email\s+us|contact\s+us)"
        r"(?!\s+(?:at|by\s+calling|directly|your\s+)?[a-z][\w.%+-]+@[a-z\d.-]+\.[a-z]{2,})"
        r"|our\s+(recruiting|hr|talent)\s+(team|department|staff)"
        r"(?!\s*[:,]\s*[A-Z][a-z]+)"
        r"(?:.{0,60})(contact|reach|call|email)\s+us"
        r"(?!\s+at\s+[+\d(]))"
        r"|(the\s+)?recruiting\s+team\s+will\s+(reach\s+out|contact\s+you|follow\s+up)"
        r"(?!\s*[,.]?\s*(?:at|from|via)\s*[\w@.+\-]+)"
        r"(?!.{0,80}(?:call|ext|extension|\d{3}[-.\s]\d{3}[-.\s]\d{4}))"), 0.30,
        "process_void",
        "No named contact and no direct phone number provided. Every legitimate cleared "
        "staffing interaction should have: (a) a named recruiter with verifiable LinkedIn "
        "profile, (b) a company phone number that can be confirmed at sam.gov or on the "
        "public DCSA contractor registry, and (c) a direct email at the company domain — "
        "not a relay or generic inbox. 'The recruiting team will reach out' with no name "
        "attached prevents you from doing the basic due diligence required before sharing "
        "any information with an unverified party."),
]


# ---------------------------------------------------------------------------
# Social Engineering Pressure Tactics
# Verbal/written tactics used to override a candidate's compliance judgment
# and coerce SSN/PII submission before a legitimate offer exists.
# Source: real-world NISP clearance fraud cases; 32 CFR §117.10(a)(5), (f)(1)
# ---------------------------------------------------------------------------
SOCIAL_ENGINEERING_PATTERNS: list[FraudPattern] = [
    FraudPattern("everyone_else_ssn_pressure", _p(
        r"(everyone\s+else|all\s+(the\s+)?other\s+candidates?|other\s+applicants?"
        r"|everyone\s+we[''ve]+\s+(spoken|talked|interviewed)\s+with)"
        r".{0,80}(provided?|gave|sent|submitted|shared)\s+(their\s+)?"
        r"(ssn|social\s+security)"),
        0.90, "social_engineering",
        "Claiming 'everyone else provided SSN' normalizes a regulatory violation. "
        "Under 32 CFR §117.10(a)(5), collecting SSNs from multiple pre-offer candidates "
        "IS the prohibited 'cache of cleared employees' — each instance is a separate "
        "NISPOM violation."),
    FraudPattern("not_playing_ball", _p(
        r"(not\s+playing\s+ball|not\s+cooperat(ing|e)|being\s+difficult"
        r"|making\s+this\s+hard(er)?|being\s+uncooperative"
        r"|if\s+you\s+(don[''t]+|won[''t]+|refuse\s+to|are\s+not\s+going\s+to)\s+cooperat)"),
        0.85, "social_engineering",
        "Framing regulatory compliance as 'not cooperating' is a manipulation tactic. "
        "Refusing to provide SSN pre-offer complies with 32 CFR §117.10(f)(1)(i)-(ii) — "
        "it is not a personal choice but a legal requirement."),
    FraudPattern("skip_over_candidate", _p(
        r"(skip\s+over\s+you|pass\s+on\s+you|move\s+on\s+to\s+(other|next|another)\s+candidates?"
        r"|have\s+to\s+(skip|pass|move\s+on)"
        r"|other\s+candidates?\s+(are\s+)?(ready|willing|available|waiting)"
        r".{0,60}(ssn|information|proceed))"),
        0.80, "social_engineering",
        "Artificial scarcity + threat of exclusion is a pressure tactic. A real position "
        "with actual clearance requirements does not evaporate when a candidate cites "
        "the regulation governing the process."),
    FraudPattern("ssn_normalized_as_standard", _p(
        r"(standard\s+(practice|procedure|process)|everyone\s+does\s+it|normal\s+(practice|process)"
        r"|industry\s+standard|required\s+by\s+(all|our)\s+(clients?|companies?|employers?))"
        r".{0,80}(ssn|social\s+security|provide|submit)"),
        0.75, "social_engineering",
        "Pre-offer SSN collection is not 'standard practice' — it violates "
        "32 CFR §117.10(f)(1)(i)-(ii). Industry custom cannot override federal regulation."),
    FraudPattern("ssn_immediate_deadline", _p(
        r"(ssn|social\s+security).{0,80}"
        r"(today|right\s+now|immediately|asap|a\.s\.a\.p|within\s+[0-9]+\s+(hour|day)"
        r"|by\s+end\s+of\s+(day|business))"),
        0.70, "social_engineering",
        "Artificial deadline for SSN submission. Legitimate clearance processes "
        "have no 24-hour SSN collection windows — this is coercion."),
    FraudPattern("dod_safe_ssn_channel", _p(
        r"(dod\s+safe.{0,80}(ssn|pii|social\s+security|personal\s+information)"
        r"|(ssn|pii|social\s+security|personal\s+information).{0,80}dod\s+safe"
        r"|(send|submit|upload).{0,40}(ssn|pii|social\s+security)"
        r".{0,60}(dod\s+safe|safe\.apps\.mil))"),
        0.90, "social_engineering",
        "DOD SAFE (safe.apps.mil) is an unclassified file transfer tool — NOT an "
        "authorized SSN collection channel. Under 32 CFR §117.10(d), SSN goes only "
        "into NBIS eApp (eapp.nbis.mil). Any request to send PII via DOD SAFE has no "
        "regulatory basis and bypasses the mandated secure portal."),
    FraudPattern("common_practice_ssn_normalization", _p(
        r"(common\s+(and\s+)?(standard\s+)?practice.{0,80}(ssn|social\s+security|pii)"
        r"|standard\s+practice.{0,60}(companies?).{0,60}(ssn|social\s+security)"
        r"|(not\s+(an?\s+)?unusual|normal|common)\s+(request|practice)"
        r".{0,80}(ssn|social\s+security|pii))"),
        0.80, "social_engineering",
        "Framing pre-offer SSN collection as 'common/standard practice' is a normalization "
        "tactic. Custom cannot override 32 CFR §117.10(f)(1)(i)-(ii). 'Common practice' "
        "of pre-offer SSN collection among recruiters describes §117.10(a)(5) violations, "
        "not a lawful standard."),
]

# ---------------------------------------------------------------------------
# CAGE Code / FCL Evasion Patterns
# Every NISP-covered facility has a public CAGE code (verifiable at sam.gov)
# and a known FCL level. Inability to provide these is a strong indicator
# of a non-NISP or fraudulent operation.
# ---------------------------------------------------------------------------
CAGE_FCL_PATTERNS: list[FraudPattern] = [
    FraudPattern("cage_code_deflection", _p(
        r"(can[''t]+\s+(give|provide|share|disclose).{0,20}cage"
        r"|cage.{0,30}(confidential|classified|proprietary|not\s+available|not\s+public)"
        r"|(don[''t]+|i\s+don[''t]+).{0,30}(have|know).{0,30}cage"
        r"|cage\s+(code\s+)?not\s+(available|disclosed|provided)"
        r"|what[''s]+\s+(a\s+)?cage\s+code)"),
        0.85, "cage_fcl_evasion",
        "CAGE codes are public DoD-facility identifiers searchable at sam.gov. "
        "Any NISP-covered facility's FSO can instantly provide their CAGE code. "
        "Refusal or ignorance of CAGE codes indicates the entity is not DCSA-registered."),
    FraudPattern("fcl_not_disclosed", _p(
        r"(fcl.{0,30}(confidential|classified|not\s+available"
        r"|can[''t]+\s+(share|provide|disclose)|private|secret|not\s+disclosed)"
        r"|facility\s+clearance.{0,30}(can[''t]+\s+(share|provide|disclose)"
        r"|confidential|not\s+public)"
        r"|(don[''t]+|i\s+don[''t]+).{0,20}(have|know).{0,20}fcl)"),
        0.80, "cage_fcl_evasion",
        "FCL is a known, non-secret attribute of every NISP facility. The FSO is "
        "required to know it. A cleared facility that cannot state its own FCL is "
        "not operating a legitimate NISP program."),
    FraudPattern("fake_offer_ssn_request", _p(
        r"(offer\s+(letter|attached|enclosed|provided|signed).{0,100}(ssn|social\s+security)"
        r"|(ssn|social\s+security).{0,100}offer\s+(letter|attached|provided|signed)"
        r"|now\s+that\s+you\s+have\s+(the\s+)?offer.{0,60}(ssn|social\s+security))"),
        0.85, "cage_fcl_evasion",
        "Fake offer letter + SSN request is a two-stage PII harvest. Verify independently: "
        "(1) CAGE code at sam.gov, (2) domain age at whois.domaintools.com, "
        "(3) callback via the company's sam.gov-listed number — not the number in the email. "
        "A real offer triggers an eApp invitation from eapp.nbis.mil — SSN never goes to a person."),
    FraudPattern("offer_conditioned_on_ssn", _p(
        r"(offer\s+(is\s+)?(contingent|conditional|dependent)\s+on.{0,60}(ssn|social\s+security)"
        r"|(must|need\s+to)\s+provide\s+(your\s+)?(ssn|social\s+security)"
        r".{0,60}(finalize|complete|process)\s+(the\s+)?offer"
        r"|(ssn|social\s+security)\s+(required|needed)\s+to\s+"
        r"(finalize|issue|complete|sign)\s+(the\s+)?offer)"),
        0.90, "cage_fcl_evasion",
        "SSN is never a condition of an offer letter. Under 32 CFR §117.10(f)(1), "
        "the written offer exists FIRST — SSN collection follows through eApp post-acceptance. "
        "SSN as a prerequisite to the offer itself inverts the legal process entirely."),
]

# ---------------------------------------------------------------------------
# NISPOM Process Misrepresentation
# Fraudsters misrepresent the NISPOM clearance process — e.g., claiming FCRA
# background checks verify clearance level, or that investigations start
# before a written offer. These patterns detect those false framings.
# ---------------------------------------------------------------------------
NISPOM_MISREPRESENTATION_PATTERNS: list[FraudPattern] = [
    FraudPattern("recruiter_claims_diss_access", _p(
        r"(i\s+(can|will|am\s+going\s+to)\s+(check|pull|look|search|find).{0,30}(diss|jpas)"
        r"|let\s+me\s+(pull|check|look|search).{0,30}(diss|jpas)"
        r"|we\s+(have|got)\s+(diss|jpas)\s+(access|account)"
        r"|i\s+have\s+(diss|jpas)\s+(access|account|login|credentials)"
        r"|(recruiter|hr|talent).{0,40}(diss|jpas)\s+(access|account|system))"),
        0.90, "nispom_misrepresentation",
        "DISS JVS is restricted to credentialed FSOs with DoD CAC login at dissportal.nbis.mil. "
        "Recruiters and HR have NO access to DISS. A recruiter claiming they can 'check you in "
        "DISS' is either impersonating an FSO or fabricating a pretext for SSN collection."),
    FraudPattern("investigation_before_offer_claimed", _p(
        r"(investigation|clearance\s+process|background).{0,60}(start|begin|initiate)"
        r".{0,60}(before|prior\s+to|without).{0,40}(offer|hire|employment)"
        r"|can\s+(process|run|initiate|start).{0,40}clearance\s+without.{0,40}offer"),
        0.85, "nispom_misrepresentation",
        "32 CFR §117.10(f)(1)(i)-(ii) requires BOTH a written offer AND written acceptance "
        "before any investigation can be initiated. No exception exists. A claim that the "
        "clearance process starts without an offer violates NISPOM directly."),
    FraudPattern("fcra_pretext_for_clearance", _p(
        r"(standard\s+background\s+check.{0,60}(ssn|social\s+security).{0,60}clearance"
        r"|background\s+check.{0,60}(verify|check|confirm).{0,40}clearance"
        r"|consent\s+for\s+background\s+check.{0,80}clearance\s+(level|status|verify)"
        r"|(fcra|fair\s+credit).{0,60}clearance\s+(level|status|verify))"),
        0.80, "nispom_misrepresentation",
        "FCRA civilian background checks and NISPOM clearance verification are completely "
        "separate legal processes. FCRA checks (credit, criminal, employment) do NOT access "
        "DISS and cannot verify clearance level. Conflating them to justify pre-offer SSN "
        "collection misrepresents both the FCRA and NISPOM."),
    FraudPattern("clearance_self_attestation_request", _p(
        r"(eligibility\s+level\s*:|eligibility\s+determination\s*:|ce\s+date\s*:|investigation\s+type\s*:)"
        r"|"
        r"(verify|confirm|provide|fill\s+in).{0,60}"
        r"(eligibility\s+(level|determination)|ce\s+date|investigation\s+type)"
        r"|"
        r"(eligibility\s+level|eligibility\s+determination).{0,80}"
        r"(investigation\s+type|ce\s+date)"),
        0.75, "nispom_misrepresentation",
        "An FSO asking the candidate to self-report their Eligibility Level, Eligibility "
        "Determination, CE Date, and Investigation Type is backwards. A credentialed FSO "
        "querying DISS JVS already receives all four fields from the authoritative government "
        "record — they do not need to ask the candidate. This request indicates the FSO "
        "either lacks DISS access (cannot verify) or is acting pre-hire (§117.10(a)(7)). "
        "Self-attestation is not a substitute for DISS JVS lookup and undermines the "
        "security system. 22nd Century Technologies/TSCTI pattern: April 2026."),
    FraudPattern("suffice_the_clearance_language", _p(
        r"(suffice|satisfy|fulfill|complete).{0,40}(the\s+)?(clearance|eligibility|verification)"
        r"|"
        r"(clearance|eligibility|verification).{0,40}(suffice|satisfied|fulfilled)"),
        0.65, "nispom_misrepresentation",
        "The phrase 'this should suffice the clearance' applied to candidate-provided data "
        "reveals that self-reported information is being used in place of an authoritative "
        "DISS JVS query. A real FSO-completed DISS query needs no 'sufficing' — the result "
        "comes directly from DCSA's system of record."),
]

# ---------------------------------------------------------------------------
# Offer Letter Fraud
# Fraudulent offer letters used as PII-harvest vehicles — either containing
# an SSN field directly, conditioning employment on SSN provision, or sent
# from free email domains with no verifiable company identity.
# ---------------------------------------------------------------------------
OFFER_LETTER_FRAUD_PATTERNS: list[FraudPattern] = [
    FraudPattern("offer_letter_ssn_field", _p(
        r"(social\s+security\s+(number|#|no\.?)\s*:|ssn\s*:)"
        r".{0,20}"
        r"(___|_+|\[\s*\]|blanks?|fill\s+in|enter\s+here|\(required\))"),
        0.95, "offer_letter_fraud",
        "SSN field present on offer letter itself. Under 32 CFR §117.10(d), SSN is entered "
        "directly by the employee into NBIS eApp at eapp.nbis.mil — it never appears as a "
        "fillable field on a paper or PDF offer letter. This is a fake offer used to harvest SSN."),
    FraudPattern("offer_letter_bank_field", _p(
        r"(bank\s+account|routing\s+number|account\s+number)\s*:"
        r".{0,20}(___|_+|\[\s*\]|fill\s+in|enter\s+here)"),
        0.97, "offer_letter_fraud",
        "Bank account field on offer letter. Banking info belongs on W-4/direct-deposit forms "
        "during HR onboarding after the first day — never on an offer letter."),
    FraudPattern("offer_no_company_address", _p(
        r"(offer\s+letter|employment\s+offer|letter\s+of\s+offer).{0,200}"
        r"(?!.{0,200}\d{3,5}\s+\w+\s+(street|st|avenue|ave|road|rd|blvd|drive|dr|suite|ste))"),
        0.50, "offer_letter_fraud",
        "Offer letter with no verifiable physical company address. Legitimate employers "
        "include their SAM.gov-registered address on official correspondence.",
        ),
    FraudPattern("offer_free_email_sender", _p(
        r"(from|sender|contact|reply.?to).{0,30}"
        r"@(gmail|yahoo|hotmail|outlook|icloud|aol|live|msn)\.com"),
        0.80, "offer_letter_fraud",
        "Offer letter sent from a free email domain. US government contractors "
        "use corporate email domains — never gmail, yahoo, or hotmail for official offers."),
    FraudPattern("offer_expires_today", _p(
        r"(this\s+offer\s+expires?\s+(today|tonight|in\s+\d+\s+hours?)"
        r"|must\s+(accept|respond|sign).{0,30}(today|immediately|right\s+now|tonight)"
        r"|offer\s+valid\s+(for\s+)?(24|12|48)\s+hours?\s+only)"),
        0.65, "offer_letter_fraud",
        "Abnormal urgency on offer letter. Legitimate cleared-position offers give "
        "reasonable review time. Pressure to sign immediately is a social engineering tactic."),
]

# ---------------------------------------------------------------------------
# Mass Email Blast / Cleared Professional List Harvesting
#
# Patterns that identify bulk commercial email campaigns targeting cleared
# professionals. Key distinction from legitimate recruiting:
#   ‣ Real targeted recruiters do NOT use bulk email marketing services
#   ‣ Unsubscribe links = CAN-SPAM compliant bulk blast, not personal outreach
#   ‣ Clicking "unsubscribe" or "update preferences" confirms your email is
#     active to both the sender and any list-broker who purchased the send
#   ‣ "Let me know if interested" sent to a list = clearance status fishing
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Clearance Holder Self-Identification Harvesting
# Even legitimate companies use mass ClearanceJobs/LinkedIn outreach to build
# high-value databases of confirmed active cleared professionals. Each reply
# from a cleared holder: (1) confirms the email is live, (2) confirms they are
# actively seeking roles, (3) discloses clearance history via resume.
# These databases have significant monetary and intelligence value.
# ---------------------------------------------------------------------------
CLEARANCE_HARVEST_PATTERNS: list[FraudPattern] = [
    FraudPattern("ive_been_trying_to_reach_you", _p(
        r"(i[''\u2019]?ve\s+been\s+(trying|attempting)\s+to\s+reach\s+you"
        r"|been\s+(trying|attempting)\s+to\s+(reach|contact|get\s+in\s+touch\s+with)\s+you"
        r"|i\s+(called|texted|emailed)\s*(and|/|,)\s*(texted|called|emailed)"
        r"|(tried|attempting)\s+to\s+reach\s+you)"),
        0.25, "clearance_harvest",
        "False-intimacy pressure opener — 'I've been trying to reach you / I called/texted.' "
        "This is template text injected by mass recruiting platforms (ClearanceJobs, LinkedIn "
        "Recruiter, Bullhorn) to create social obligation in the recipient. It implies a "
        "pre-existing relationship that does not exist. Increases reply rates from cleared "
        "professionals who feel rude not responding to someone who 'tried to call them.' "
        "The objective is confirming active, interested cleared-professional contacts."),
    FraudPattern("skills_stood_out_on_platform", _p(
        r"(your\s+(impressive|strong|great|excellent|outstanding|relevant)\s+"
        r"(background|experience|skills?|profile|qualifications?|expertise)"
        r".{0,70}(stood\s+out|caught\s+(my|our)\s+eye|came\s+to\s+(my|our)?\s*attention)"
        r"|(your\s+(profile|background|experience|skills?).{0,50}"
        r"(clearancejobs|linkedin|indeed|dice|ziprecruiter|monster))"
        r"|(stood\s+out\s+(in|on)\s+(clearancejobs|linkedin|indeed|dice|ziprecruiter)))"),
        0.20, "clearance_harvest",
        "Template-driven flattery preamble: 'Your impressive skills stood out on ClearanceJobs.' "
        "Automated recruiting CRMs (Bullhorn, HubSpot, Salesforce) inject the candidate's "
        "profile headline into mass outreach templates — this is not evidence of individual "
        "review. The flattery is engineered to lower defenses and increase reply rates. "
        "Responding to this confirms your cleared-professional email as active and responsive, "
        "increasing your profile's value in CRM contact databases and any list exchanges."),
    FraudPattern("send_resume_asap_harvest", _p(
        r"(send\s+(me|us|your)\s*?(resume|cv)\s+(asap|a\.s\.a\.p\.?|immediately|right\s+away|today|urgently|now)"
        r"|(please\s+)?(send|forward|attach|submit|email)\s+(your\s+)?(resume|cv)\s+"
        r"(asap|a\.s\.a\.p\.?|urgently|immediately|right\s+away|today|now)"
        r"|(resume|cv)\s+(asap|a\.s\.a\.p\.?|urgently|immediately|today))"),
        0.35, "clearance_harvest",
        "Resume-harvest urgency tactic. A cleared professional's resume aggregates employer "
        "names (DoD contractors), program names, clearance level, facility names, and "
        "access history — all sensitive PII. Replying with a resume to unverified mass "
        "outreach: (1) confirms your email is live, (2) confirms active job seeking, "
        "(3) discloses your clearance history to an unvetted party. The ASAP urgency "
        "prevents the verification check that would expose the opportunity as unconfirmed. "
        "Databases of verified cleared-professional resumes have significant resale value "
        "in defense staffing markets and espionage-adjacent data brokers."),
    FraudPattern("req_closes_soon_urgency", _p(
        r"(req(uisition)?\s+(closes?|closing|fill[si]?ng?)\s+soon"
        r"|position.{0,20}(closes?|closing|fill[si]?ng?).{0,10}(soon|fast|quickly)"
        r"|(priority|urgent|hot)\s+(req|position|opening|role|opportunity)"
        r".{0,40}(closes?|fills?|closing|filling)"
        r"|before\s+this\s+(priority|urgent|req|position|role|opening)\s+(closes?|fills?)"
        r"|req\s+closes?\s+soon)"),
        0.25, "clearance_harvest",
        "Artificial scarcity urgency: 'priority req closes soon / position filling fast.' "
        "Real DoD/aerospace cleared positions have contract-driven timelines, not "
        "marketing-email urgency windows. This language prevents recipients from "
        "taking time to verify the recruiter's credentials, the client company's FCL, "
        "or the job posting on the prime contractor's careers page. The urgency is "
        "manufactured to maximize resume volume before due diligence catches up."),
    FraudPattern("candidate_privacy_statement_bulk_send", _p(
        r"(candidate\s+privacy\s+(information\s+)?statement"
        r"|candidate\s+privacy\s+policy"
        r"|to\s+read\s+our\s+candidate\s+privacy"
        r"|candidate\s+privacy\s+information\s+notice"
        r"|how\s+we\s+(will\s+)?use\s+your\s+(information|data).{0,60}(statement|policy|notice))"),
        0.25, "clearance_harvest",
        "Candidate Privacy Information Statement link — legal proof this email was sent via "
        "a commercial bulk email marketing platform (Salesforce Marketing Cloud, HubSpot, "
        "Pardot, etc.) with CAN-SPAM / CCPA compliance footers. Genuine individual recruiter "
        "outreach never contains legal compliance footers. The 'personalized' content (your "
        "name, skills, clearance level) was auto-populated from a contact list sourced from "
        "ClearanceJobs, LinkedIn, or a data broker. Your confirmed reply adds your cleared "
        "profile to the sender's CRM as a verified, responsive contact — a data point with "
        "resale and targeting value."),
    FraudPattern("share_with_colleagues_list_amplification", _p(
        r"(please\s+share.{0,100}(friends?|colleagues?|contacts?|connections?|network)"
        r".{0,80}(looking|searching|seeking|currently|interested|career)"
        r"|share.{0,60}(colleagues?|contacts?|friends?|connections?|network)"
        r".{0,80}(looking|seeking|interested|job|opportunity|career|benefit)"
        r"|(colleagues?|contacts?|friends?|connections?)\s+who\s+(are\s+)?(currently\s+)?"
        r"(looking|searching|seeking|interested))"
        ),
        0.20, "clearance_harvest",
        "Viral list-building tactic: 'Please share with friends/colleagues who are looking.' "
        "This request grows a cleared-professional contact database beyond its original recipients. "
        "Every 'forward' confirms additional cleared individuals as active job seekers — expanding "
        "a commercially valuable database of verified TS/SCI or cleared professional emails. "
        "Legitimate employers post openings; they don't recruit by asking candidates to become "
        "unsolicited distribution chains for their outreach campaigns."),
    FraudPattern("career_fair_clearance_aggregation", _p(
        r"(career\s+fair|hiring\s+event|virtual\s+event|virtual\s+career).{0,300}"
        r"(ts/?sci|top\s+secret|active\s+clearance|security\s+clearance|clearance\s+required)"
        r"|(ts/?sci|top\s+secret|active\s+(security\s+)?clearance).{0,100}"
        r"(required|is\s+required).{0,400}(career\s+fair|hiring\s+event|virtual\s+career)"
        r"|(register|sign.?up).{0,200}"
        r"(ts/?sci|top\s+secret|active\s+(security\s+)?clearance).{0,100}(required|is\s+required)"
        r"|(ts/?sci|top\s+secret|active\s+(security\s+)?clearance).{0,100}(required|is\s+required)"
        r".{0,200}(register|sign.?up)"
        ),
        0.30, "clearance_harvest",
        "Virtual career fair or hiring event requiring clearance to register — this is "
        "clearance-status self-identification at scale. When thousands of cleared professionals "
        "register for a 'clearance required' virtual event, the organizer aggregates a database "
        "of confirmed cleared individuals, their clearance levels, active job-seeking status, "
        "contact information, and employer history (from uploaded resumes). Even when the event "
        "organizer is legitimate, the registration process creates a concentrated high-value "
        "database. Per 32 CFR §117.10(a)(7), only the employing contractor holding an FCL may "
        "initiate clearance actions — a third-party event organizer has no NISPOM authority "
        "over the individuals' clearance data they aggregate. Verify the event organizer "
        "before registering and read their data retention and sharing policies."),
]

# ---------------------------------------------------------------------------
# Pre-Screen Clearance Questionnaire / Structured Form Data Harvest
#
# The SGS Consulting pattern (April 2025): structured Yes/No table asking
# active clearance status, level/tier, previous clearance, investigation type,
# and "Legal Full Name (as in Passport/DL)" — at initial recruiter contact
# before any interview or offer.
#
# Real NISPOM process: FSOs verify clearance via DISS (dissportal.nbis.mil).
# Recruiters have no authority to collect clearance data via email forms.
# Ref: 32 CFR §117.10; DCSA SEAD-3; SGS Consulting / MIT LL FFRDC, April 2025
# ---------------------------------------------------------------------------
PRE_SCREEN_CLEARANCE_FORM_PATTERNS: list[FraudPattern] = [
    FraudPattern("pre_screen_clearance_table",
                 _p(r"(active\s+clearance\s*[:\|?].{0,30}(yes|no)"
                    r"|(does\s+the\s+candidate\s+have|candidate\s+clearance).{0,50}"
                    r"(active|current).{0,30}(clearance|secret|ts/?sci)"
                    r"|(current\s+clearance\s+(level|tier)|clearance\s+tier)\s*[:\|?]"
                    r"|(previous\s+clearance\s+(level|tier)|prior\s+clearance\s+(level|tier))"
                    r"|clearance\s+last\s+active\s*[:\|]"
                    r"|investigation\s+type\s*[:\|].{0,60}(sbi|sbpr|t5r?|t3r?|tier\s*[3-5]))"
                    ),
                 0.65, "pre_screen_form",
                 "Structured pre-screen clearance questionnaire: table/form asking active "
                 "clearance status (Yes/No), level/tier, previous clearance, and investigation "
                 "type at initial recruiter contact — before any interview or offer. "
                 "A real FSO verifies clearance through DISS (32 CFR §117.10); no recruiter "
                 "has authority to collect this data from candidates via email form. "
                 "Pattern: SGS Consulting / MIT Lincoln Lab FFRDC phishing, April 2025."),
    FraudPattern("legal_name_passport_prescreen",
                 _p(r"(legal\s+(full\s+)?name\s*.{0,10}(passport|driver.{0,3}s?\s*licen|p/?p\b|dl\b)"
                    r"|(name\s+as\s+(it\s+)?(appears?|is\s+listed|shown)\s+(on|in)\s+"
                    r"(your\s+)?(passport|id|driver.{0,3}s?\s*licen|government\s+id))"
                    r"|(legal\s+name\s+as\s+in\s+(passport|dl\b|id|government\s+id))"
                    r"|(full\s+legal\s+name.{0,30}(passport|driver.{0,3}s?\s*licen|government\s+id))"
                    r"|(as\s+(listed|shown|appears?)\s+(on|in)\s+(your\s+)?(passport|dl\b|id\b)))"
                    ),
                 0.70, "pre_screen_form",
                 "Request for legal name as it appears on passport or driver's license "
                 "at initial recruiter contact, before any interview or offer. "
                 "Legitimate cleared employers collect this post-offer via NBIS eApp "
                 "(eapp.nbis.mil), not in a pre-screen email form. This is a PII "
                 "harvesting technique enabling identity linking and targeted attacks."),
    FraudPattern("clearance_history_multi_field",
                 _p(r"(clearance\s+(level|tier|status)\s*[:\|?].{0,300}"
                    r"(investigation\s+type|previous\s+clearance|prior\s+clearance|last\s+active)"
                    r"|(investigation\s+type|previous\s+clearance|prior\s+clearance)\s*[:\|?]"
                    r".{0,300}(clearance\s+(level|tier|status)|last\s+active|inactive\s+since))",
                    re.IGNORECASE | re.DOTALL),
                 0.65, "pre_screen_form",
                 "Multi-field clearance history data collection (level + investigation type + "
                 "previous clearance) in a single recruiter email or form. This structured "
                 "data aggregation mirrors DISS JVS fields — accessible only to credentialed "
                 "FSOs, not recruiters. No pre-offer collection of this data is authorized."),
    FraudPattern("anonymous_cleared_client", _p(
        r"(client\s*[:\-]\s*(an?\s+)?(aerospace|defense|government|federal|dod|military)"
        r"(\s+(and|&|/|\s)\s*(defense|government|aerospace|military|technology|tech|contractor))?"
        r"\s+client"
        r"|our\s+(aerospace|defense|government|federal|dod|military)(\s+(and|&)\s+(defense|government|aerospace))?"
        r"\s+client"
        r"|confidential\s+(client|company).{0,60}(clearance|cleared|secret|ts.?sci)"
        r"|hiring\s+company\s*[:\-]\s*confidential"
        r"|company\s*[:\-]\s*confidential.{0,40}(clearance|cleared|secret|ts.?sci))"),
        0.55, "pre_screen_form",
        "Anonymous client for a cleared position: the hiring company is described only as "
        "'an aerospace & defense client' or 'confidential client' rather than named. "
        "Every real cleared billet is tied to a specific FCL-holding prime contractor — "
        "the company name is not secret. Anonymous-client postings prevent you from: "
        "(a) verifying the company holds an FCL at sam.gov, "
        "(b) confirming the position exists on the company's own careers page, "
        "(c) reporting the contact to your FSO with an identified entity as required by SEAD 3. "
        "Staffing firms use anonymous-client language to prevent direct applications and to "
        "protect their placement fee — it is not a security requirement."),
]

# ---------------------------------------------------------------------------
# Foreign Intelligence Front Organization Patterns
#
# NCSC/FBI/DCSA April 2025 joint advisory: foreign intelligence entities pose
# as consulting firms, headhunters, think tanks, and research organizations
# to target current and former USG/cleared personnel for collection.
#
# Hallmarks: paid consulting for "strategic insights"; think-tank/advisory
# framing; escalating requests for government-experience commentary;
# immediate payment for policy analysis; cleared colleague referral requests.
#
# Ref: NCSC-FBI-DCSA advisory 2025-04-08; AFOSI Public Affairs 2025-04-21;
#      FBI "Think Before You Link" counterintelligence advisory
# ---------------------------------------------------------------------------
FOREIGN_FRONT_PATTERNS: list[FraudPattern] = [
    FraudPattern("think_tank_consulting_front",
                 _p(r"(think\s+tank|policy\s+(institute|center|foundation|group)"
                    r"|research\s+(institute|center|foundation|organization|group)"
                    r"|strategic\s+(studies|research|analysis|institute|consulting)"
                    r"|national\s+security\s+(consultant|consulting|research|analysis)"
                    r"|(advisory|consulting)\s+(firm|group|organization)\s+.{0,100}"
                    r"(clearance|cleared|government|dod|intel|defense|national\s+security))"
                    ),
                 0.45, "foreign_front",
                 "Think tank, policy institute, or strategic consulting firm framing combined "
                 "with cleared/defense/national security focus. NCSC/FBI/DCSA April 2025: "
                 "adversaries pose as consulting firms, think tanks, and research organizations "
                 "to recruit cleared government personnel. Verify via SAM.gov CAGE code, "
                 "domain WHOIS (check registration date), and callback to published main number."),
    FraudPattern("paid_analysis_report_request",
                 _p(r"(paid\s+(consulting|analysis|research|report|study|engagement)"
                    r".{0,100}(government|defense|dod|policy|national\s+security|clearance)"
                    r"|(government|defense|dod|policy|national\s+security)"
                    r".{0,100}(paid\s+(consulting|analysis|research|report|study|engagement))"
                    r"|(strategic\s+insights?|policy\s+analysis|market\s+research)"
                    r".{0,80}(compensation|paid|payment|honorarium|stipend|consulting\s+fee)"
                    r"|(compensation|paid|payment|honorarium|stipend)\s*.{0,80}"
                    r"(strategic\s+insights?|policy\s+analysis|government\s+experience))",
                    re.IGNORECASE | re.DOTALL),
                 0.65, "foreign_front",
                 "Offer of paid consulting or analysis based on government/cleared experience. "
                 "AFOSI April 2025: adversaries offer lucrative consulting opportunities "
                 "starting with policy commentary before escalating to sensitive information. "
                 "Immediate payment for government insights is a documented foreign "
                 "intelligence elicitation technique. Report to your FSO."),
    FraudPattern("expert_government_insights_solicitation",
                 _p(r"(your\s+(government|dod|intel|cleared|defense|federal)\s+"
                    r"(experience|background|insights?|expertise|perspective|knowledge))"
                    r".{0,100}"
                    r"(analysis|report|research|study|brief|opinion|assessment|commentary)"
                    r"|(share\s+(your\s+)?(insights?|perspective|experience|expertise|knowledge)"
                    r".{0,80}(government|dod|intel|cleared|defense|policy|national\s+security))"
                    r"|(expert\s+(opinion|analysis|perspective|insight|commentary)"
                    r".{0,80}(government|defense|intelligence|national\s+security|dod))",
                    re.IGNORECASE | re.DOTALL),
                 0.55, "foreign_front",
                 "Soliciting policy commentary or insights based on government/cleared "
                 "work experience from an unvetted party. AFOSI advisory: adversaries build "
                 "trust via harmless commentary requests before escalating to sensitive "
                 "information. Any external request for analysis based on your government/ "
                 "cleared access history is CI-reportable."),
    FraudPattern("social_graph_colleague_referral",
                 _p(r"(know\s+(anyone|any\s+colleagues?|others?|someone)\s+"
                    r"(who\s+(might\s+be\s+a?\s+)?(good\s+fit|interested|qualified|available)"
                    r"|with\s+(clearance|ts/?sci|cleared|dod\s+background))"
                    r"|(do\s+you\s+know|could\s+you\s+recommend|any\s+colleagues?)\s+.{0,60}"
                    r"(cleared|clearance|ts/?sci|government|dod|defense)"
                    r"|(colleagues?|contacts?|friends?|connections?)\s+who\s+(might|may|could|are)"
                    r"\s+.{0,60}(cleared|hold\s+a\s+clearance|ts/?sci|interested\s+in)"
                    r"|refer\s+.{0,30}cleared\s+(professional|colleague|contact|friend))"
                    ),
                 0.40, "foreign_front",
                 "Request for referrals of cleared colleagues or contacts. Social-graph "
                 "expansion tactic: each referral maps additional cleared personnel as "
                 "secondary targets. FBI advisory: in the cleared community, professional "
                 "contacts are typically other cleared individuals — providing referrals to "
                 "unvetted parties extends their cleared-professional network database."),
]

# ---------------------------------------------------------------------------
# Credential / Certificate Document Harvest
#
# Fake recruiters request certification PDFs, CAC details, or non-existent
# 'clearance certificates'. These contain PII sufficient for targeted phishing.
# Ref: Cloud Security Alliance advisory April 2025 — certificate PDF harvest;
#      DCSA — CAC is controlled government property, never shared externally
# ---------------------------------------------------------------------------
CREDENTIAL_HARVEST_PATTERNS: list[FraudPattern] = [
    FraudPattern("certification_pdf_request",
                 _p(r"(send|email|attach|share|provide|forward|upload)\s+"
                    r"(me|us|over)?\s*(a\s+)?(copy\s+of\s+)?(your\s+)?"
                    r"(cissp|ccsp|ccsk|cism|oscp|ceh|comptia|security\+|aws\s+cert"
                    r"|azure\s+cert|giac|gsec|gpen|gwapt|gcih|gcia|gcfe|gcfa"
                    r"|casp\+?|cysa\+?|cisa|sscp|pentest\+?)"
                    r".{0,50}(certificate|certification|cert\b|badge|pdf)"
                    ),
                 0.55, "credential_harvest",
                 "Request to send a security/IT certification PDF by email. Cert PDFs contain "
                 "name, email address, and verification code — enough PII for a targeted "
                 "phishing profile. Employers verify certifications independently via Credly "
                 "or the certification body's public portal. They never need the PDF. "
                 "Ref: CSA Security Careers advisory April 2025."),
    FraudPattern("clearance_certificate_document_request",
                 _p(r"(send|email|attach|share|provide|forward|upload)\s+"
                    r"(me|us|over)?\s*(a\s+)?(copy\s+of\s+)?(your\s+)?"
                    r"(clearance\s+certificate|clearance\s+letter|sf.?86\s+summary"
                    r"|eqip\s+(printout|summary|results?)|clearance\s+verification\s+(letter|document)"
                    r"|nac\s+letter|investigation\s+results?|eligibility\s+(letter|document)"
                    r"|security\s+clearance\s+(certificate|document|letter|proof))"
                    ),
                 0.90, "credential_harvest",
                 "Request for a clearance certificate or SF-86 summary document. No such "
                 "document legitimately exists in recruiter interactions — clearance status "
                 "is verified FSO-to-FSO through DISS. This is PII harvesting or an attempt "
                 "to social-engineer disclosure of investigation details."),
    FraudPattern("cac_piv_request",
                 _p(r"(send|provide|share|upload|scan|photograph)\s+(me|us)?\s*(your\s+)?"
                    r"(cac\b|common\s+access\s+card|piv\s+card|smart\s+card|dod\s+id\s+card)"
                    r".{0,60}(number|certificate|details|information|photo|image|copy|scan)"
                    ),
                 0.90, "credential_harvest",
                 "Request for CAC/PIV card details or photos. CAC cards are controlled "
                 "government-issued property — no legitimate recruiting interaction involves "
                 "sharing CAC details. This is identity theft setup or an attempt to create "
                 "a fraudulent DoD identity credential."),
]

# ---------------------------------------------------------------------------
# Workforce Mapping / Cleared Community Profiling
#
# Distinct from outright fraud: these patterns detect interactions that collect
# intelligence value even when the sender is a real company with a real domain.
#
# The threat — documented in FBI "Think Before You Link" advisory
# (fbi.gov/investigate/counterintelligence/the-china-threat/
#  clearance-holders-targeted-on-social-media-nevernight-connection):
#
#   ‣ Replying confirms email is active + person is clearance-eligible
#   ‣ Sending a resume discloses cleared employer chain, program history,
#     clearance level, home address, and facility associations
#   ‣ Providing references exposes additional cleared professionals
#   ‣ Answering clearance status probes confirms current access level
#   ‣ Naming programs discloses access compartments and IC work history
# ---------------------------------------------------------------------------
WORKFORCE_MAPPING_PATTERNS: list[FraudPattern] = [
    FraudPattern("active_clearance_level_probe",
                 _p(r"(do\s+you\s+(currently|presently)?\s*"
                    r"(hold|have|possess|maintain)\s+(an?\s+)?"
                    r"(active|current|valid|existing)\s*(security\s+)?clearance"
                    r"|what\s+(is|['’]s)\s+your\s+(current|active|existing)?\s*"
                    r"(clearance|security\s+clearance)\s*(level|status|tier)?"
                    r"|is\s+your\s+clearance\s+(active|current|valid|still\s+active|in\s+scope)"
                    r"|currently\s+(hold|possess|have|maintain)\s+(a\s+)?"
                    r"(ts/?sci|top\s+secret|secret\s+clearance|security\s+clearance)"
                    r"|your\s+(current|active|existing)\s+(clearance\s+level|clearance\s+status))"),
                 0.60, "workforce_mapping",
                 "Probing for ACTIVE/CURRENT clearance status — not just eligibility. "
                 "Standard job-posting language ('eligible to obtain') is different. "
                 "Per FBI 'Think Before You Link': clearance holders should be cautious when "
                 "anyone asks about clearance status online. Confirming active access level "
                 "maps you as a verified cleared resource in an unvetted contact database."),
    FraudPattern("classified_program_history_probe",
                 _p(r"(what\s+(programs?|projects?|contracts?)\s+"
                    r"(have\s+you\s+)?(worked\s+on|worked\s+with|supported?|been\s+involved)"
                    r"|(detail|describe)\s+.{0,30}(classified|cleared|government|dod|intel)\s*(work|experience)"
                    r"|(classified|government|intel(ligence)?)\s+programs?\s+.{0,30}(tell|describe|detail|discuss)"
                    r"|(tell|describe|discuss)\s+.{0,30}(classified|cleared|dod)\s+(work|experience|programs?))"),
                 0.75, "workforce_mapping",
                 "Asking about classified programs/projects before a formal employment relationship. "
                 "Program names, contract numbers, and compartment descriptions are sensitive. "
                 "Real recruiters ask about skills — not program names. "
                 "Report to your FSO if anyone asks you to name classified programs pre-offer."),
    FraudPattern("cleared_reference_early_request",
                 _p(r"(references?\s+(before|prior\s+to|upfront|at\s+this\s+(stage|point|time))"
                    r"|(provide|send|share|list)\s+(your\s+)?(professional\s+)?references?"
                    r"\s+(now|today|immediately|before|first|at\s+this\s+(stage|time))"
                    r"|need\s+(your\s+)?references?\s+(before|prior|now|today|first))"),
                 0.50, "workforce_mapping",
                 "References requested before any interview for a cleared position. "
                 "Cleared professional references are themselves likely cleared individuals "
                 "— early collection builds a secondary database of cleared personnel. "
                 "This is a social-graph expansion tactic."),
    FraudPattern("employer_chain_mining",
                 _p(r"(what\s+(cleared\s+)?contractors?\s+(have\s+you|you\s+have)\s+(worked\s+(for|with)|been\s+employed)"
                    r"|which\s+(defense|government)\s+(contractors?|companies?|firms?)"
                    r".{0,50}(worked?\s+(for|with)|employed?\s+by)"
                    r"|(list|name|tell\s+me)\s+.{0,20}(previous|past|former|prior)"
                    r"\s+(cleared\s+)?(employers?|contractors?|companies?))"),
                 0.60, "workforce_mapping",
                 "Asking for a list of all cleared contractors or defense employers. "
                 "Your cleared employer chain is an access map revealing facility clearances, "
                 "program offices, and the personnel security network you are connected to. "
                 "Disclose employer history only through official post-offer onboarding channels."),
    FraudPattern("cold_outreach_clearance_focus",
                 _p(r"(found|came\s+across|saw|noticed)\s+(your\s+)?(profile|background|resume)"
                    r".{0,100}(clearance|cleared|ts/?sci|top\s+secret|secret)"
                    r"|(clearance|cleared\s+background|ts/?sci)"
                    r".{0,80}(makes?\s+you|perfect\s+(fit|match)|exactly\s+what|stood\s+out|caught\s+(my|our)\s+eye)"),
                 0.35, "workforce_mapping",
                 "Cold outreach citing your clearance as the primary qualification. "
                 "FBI advisory: foreign intelligence entities specifically target clearance "
                 "holders on professional networking sites. Responding confirms your email "
                 "belongs to a clearance-eligible person and adds you to a verified "
                 "cleared-professional contact database."),
]


MASS_EMAIL_BLAST_PATTERNS: list[FraudPattern] = [
    FraudPattern("bulk_email_unsubscribe", _p(
        r"(to\s+unsubscribe\s+from\s+future\s+(emails?|messages?)"
        r"|unsubscribe\s+(from|here|at|link)"
        r"|update\s+your\s+email\s+preferences"
        r"|email\s+preferences\s+click"
        r"|manage\s+(your\s+)?email\s+(subscriptions?|preferences)"
        r"|opt.?out\s+of\s+(future\s+)?emails?)"),
        0.35, "spam_blast",
        "Unsubscribe or email-preference link detected — this is a bulk commercial email "
        "marketing blast, not a targeted personal outreach. Legitimate recruiters doing "
        "cleared-position outreach do not send mass email campaigns. "
        "CRITICAL: Do NOT click the unsubscribe/preferences link. Clicking it confirms your "
        "email address is live and actively monitored, potentially adding it to list-broker "
        "databases that sell verified cleared-professional contact lists. This is a known "
        "technique for building targetable lists of TS/SCI-cleared individuals."),
    FraudPattern("click_here_tracking_link", _p(
        r"click\s+here\s+to\s+(unsubscribe|update|opt.?out|manage|remove)"
        r"|click\s+here\s+if\s+you\s+(no\s+longer|don.?t\s+want|wish\s+to\s+stop)"),
        0.25, "spam_blast",
        "'Click here' tracking link pointing to an unsubscribe or preference-management page. "
        "In bulk email marketing platforms (Mailchimp, Constant Contact, HubSpot, etc.), "
        "these links are unique per recipient — clicking one registers your email as "
        "confirmed-active in the sender's CRM and any downstream list exchange. A confirmed "
        "cleared-professional email address has significant value in targeted social "
        "engineering and recruitment fraud databases."),
    FraudPattern("clearance_status_fishing", _p(
        r"(you\s+must\s+have|must\s+hold|required.{0,20}(active|current))\s+"
        r"(ts/?sci|top\s+secret|secret\s+clearance|active\s+clearance)"
        r".{0,200}"
        r"(let\s+me\s+know\s+if\s+you\s+(are|re)\s+interested"
        r"|reply\s+if\s+interested"
        r"|please\s+respond\s+if\s+(you\s+are|interested)"
        r"|reach\s+out\s+if\s+(you\s+have|you.?re\s+interested))"),
        0.40, "spam_blast",
        "Email requires active clearance AND invites the recipient to self-identify as "
        "interested — sent via a bulk email blast. This combination is a clearance status "
        "fishing technique: anyone who replies has voluntarily confirmed to an unvetted "
        "third party that they hold an active security clearance. Databases of confirmed "
        "cleared individuals are high-value targets for foreign intelligence, social "
        "engineering, and credential theft campaigns. Non-cleared staffing intermediaries "
        "have no legitimate need to collect clearance-status confirmations from mass "
        "email blast responses. See also: 32 CFR §117.10(a)(7) — only the employing "
        "contractor (with an FCL) may initiate or verify clearance actions."),
    FraudPattern("non_cleared_staffing_tscisci_blast", _p(
        r"(staffing\s+(specialist|consultant|firm|agency|company|representative)"
        r"|recruiting\s+on\s+behalf\s+of\s+(one\s+of\s+our\s+clients?|our\s+client)"
        r"|one\s+of\s+our\s+clients?.{0,60}(ts/?sci|top\s+secret|clearance))"),
        0.30, "spam_blast",
        "Third-party staffing intermediary recruiting for a TS/SCI role. "
        "Under 32 CFR §117.10(a)(7), only the contractor holding a Facility Clearance (FCL) "
        "can initiate or verify a security clearance — a staffing firm acting as a "
        "middleman has zero NISPOM authority to sponsor, initiate, or verify clearances "
        "for an unnamed 'client'. The actual hiring company should be named; if it is not, "
        "verify the staffing firm holds an FCL at sam.gov before engaging. "
        "If the job is real, it will be posted on the prime contractor's own careers page."),
]


ALL_PATTERNS: list[FraudPattern] = (
    PII_PATTERNS
    + FINANCIAL_PATTERNS
    + URGENCY_PATTERNS
    + CLEARANCE_SCAM_PATTERNS
    + IMPERSONATION_PATTERNS
    + COMMUNICATION_PATTERNS
    + SALARY_PATTERNS
    + QUALITY_PATTERNS
    + DPRK_IT_WORKER_PATTERNS
    + VISHING_PATTERNS
    + IDENTITY_THEFT_PATTERNS
    + FAKE_PLATFORM_PATTERNS
    + AI_GENERATED_PATTERNS
    + BACKGROUND_CHECK_SCAM_PATTERNS
    + FSO_IMPERSONATION_PATTERNS
    + FAKE_RECRUITER_PATTERNS
    + ENGAGEMENT_GHOST_PATTERNS
    + SOCIAL_ENGINEERING_PATTERNS
    + CAGE_FCL_PATTERNS
    + NISPOM_MISREPRESENTATION_PATTERNS
    + OFFER_LETTER_FRAUD_PATTERNS
    + CLEARANCE_HARVEST_PATTERNS
    + MASS_EMAIL_BLAST_PATTERNS
    + PRE_SCREEN_CLEARANCE_FORM_PATTERNS
    + FOREIGN_FRONT_PATTERNS
    + CREDENTIAL_HARVEST_PATTERNS
    + WORKFORCE_MAPPING_PATTERNS
)
