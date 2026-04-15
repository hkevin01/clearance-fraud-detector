"""
Domain analysis: detect spoofed/typosquatted domains, personal email services,
and mismatches between claimed company and sender domain.
"""
import re
from dataclasses import dataclass

import tldextract

from ..data.known_contractors import (
    ALL_LEGITIMATE_DOMAINS,
    KNOWN_FAKE_RECRUITING_DOMAINS,
    LEGITIMATE_CONTRACTORS,
)
from ..parsers.email_parser import EmailDocument

# Free email providers — never legitimate for cleared-job recruitment
FREE_EMAIL_PROVIDERS: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "proton.me", "tutanota.com",
    "mail.com", "icloud.com", "live.com", "msn.com", "ymail.com",
    # Consumer messaging / file share domains misused by scammers
    "163.com", "qq.com", "126.com", "sina.com", "naver.com",
}

# Common typosquatting patterns (simplified Levenshtein check by precomputed known fakes)
KNOWN_FAKE_DOMAINS: set[str] = KNOWN_FAKE_RECRUITING_DOMAINS | {
    "usajobs.net", "usajobs.org", "usa-jobs.gov.com",
    "dod-careers.com", "nsa-jobs.com", "cia-careers.gov.com",
}


@dataclass
class DomainFinding:
    severity: str       # "high" | "medium" | "low"
    finding: str
    detail: str


def analyze_domains(doc: EmailDocument) -> list[DomainFinding]:
    findings: list[DomainFinding] = []
    sender_domain = doc.sender_domain
    reply_domain = doc.reply_to_domain

    # 1. Free email provider used for cleared-job outreach
    if sender_domain in FREE_EMAIL_PROVIDERS:
        findings.append(DomainFinding(
            severity="high",
            finding="Free email provider",
            detail=f"Sender uses '{sender_domain}' — legitimate defense employers use corporate domains",
        ))

    # 2. Reply-To diverges from From domain (phishing indicator)
    if reply_domain and sender_domain and reply_domain != sender_domain:
        findings.append(DomainFinding(
            severity="high",
            finding="Reply-To domain mismatch",
            detail=f"Sender domain '{sender_domain}' differs from Reply-To domain '{reply_domain}'",
        ))

    # 3. Known fake/spoofed domains
    if sender_domain in KNOWN_FAKE_DOMAINS or reply_domain in KNOWN_FAKE_DOMAINS:
        findings.append(DomainFinding(
            severity="high",
            finding="Known fraudulent domain",
            detail=f"Domain '{sender_domain or reply_domain}' is on the known-fake list",
        ))

    # 4. Contractor name in body but email domain doesn't match
    body = doc.full_text.lower()

    # Suppress contractor name/domain mismatch checks when the email clearly
    # discloses a legitimate multi-party context:
    #   - Career fairs: organizer legitimately lists many exhibiting contractors
    #   - Staffing agency disclosure: "recruiting on behalf of [Company]" is the
    #     correct way for a staffing firm to identify the end client
    LEGITIMATE_LISTING_CONTEXT_PHRASES: tuple[str, ...] = (
        # Career fair / hiring event organizer context
        "companies participating",
        "companies attending",
        "career fair",
        "virtual career fair",
        "hiring event",
        "employers participating",
        "employers attending",
        "register for the event",
        "cleared career",
        "cleared virtual",
        "cleared hiring",
        # Staffing agency / RPO disclosed third-party context
        "recruiting on behalf of",
        "staffing on behalf of",
        "placement on behalf of",
        "working on behalf of",
        "on behalf of our client",
        # RPO/exclusive sourcing partner disclosures (e.g., eTalent Network for TSCTI)
        "sole agency that does recruitment",
        "sole agency for",
        "exclusive recruiter for",
        "exclusive agency for",
        "recruitment sourcing for",
        "sole staffing partner",
        "staffing partner for",
    )
    is_legitimate_listing_context = any(phrase in body for phrase in LEGITIMATE_LISTING_CONTEXT_PHRASES)

    if not is_legitimate_listing_context:
        for company, valid_domains in LEGITIMATE_CONTRACTORS.items():
            # Use word-boundary matching to avoid substring false positives:
            # "IDA" must not match "candidates"; "EY" must not match "Hey"
            company_lower = company.lower().split()[0]  # first word of company name
            if re.search(r'\b' + re.escape(company_lower) + r'\b', body):
                if sender_domain and not any(sender_domain.endswith(d) for d in valid_domains):
                    if sender_domain not in FREE_EMAIL_PROVIDERS:  # already flagged above
                        findings.append(DomainFinding(
                            severity="medium",
                            finding=f"Contractor name/domain mismatch: {company}",
                            detail=(
                                f"Email mentions '{company}' but sender domain is '{sender_domain}'. "
                                f"Expected one of: {', '.join(valid_domains)}"
                            ),
                        ))

    # 5. Suspicious TLD for government/contractor impersonation
    extracted = tldextract.extract(sender_domain)
    tld = extracted.suffix
    domain_name = extracted.domain
    gov_keywords = ["dod", "nsa", "cia", "dia", "fbi", "pentagon", "army", "navy", "airforce"]
    if any(k in domain_name for k in gov_keywords) and tld not in ("mil", "gov"):
        findings.append(DomainFinding(
            severity="high",
            finding="Government keyword in non-.gov/.mil domain",
            detail=f"'{sender_domain}' uses a government-sounding name but is not a .gov/.mil address",
        ))

    # 6. Subdomain abuse (e.g., nsa.gov.evildomain.ru)
    if re.search(r"\.(gov|mil)\.", sender_domain):
        findings.append(DomainFinding(
            severity="high",
            finding="Subdomain impersonating .gov/.mil",
            detail=f"'{sender_domain}' uses .gov or .mil as a subdomain, not the root TLD",
        ))

    # 7. Chinese consumer email domains used by DPRK/foreign actor schemes
    china_domains = {"163.com", "qq.com", "126.com", "sina.com", "sohu.com"}
    if sender_domain in china_domains or (reply_domain and reply_domain in china_domains):
        findings.append(DomainFinding(
            severity="high",
            finding="Chinese consumer email in US clearance recruiting context",
            detail=f"'{sender_domain or reply_domain}' is a Chinese consumer platform — "
                   "associated with foreign IT worker fraud schemes",
        ))

    # 8. Domain registered recently heuristic (keyword: jobs/careers/hire + generic TLDs)
    extracted2 = tldextract.extract(sender_domain)
    if re.search(r"(jobs?|career|hire|staffing|recruit)", extracted2.domain, re.I) and \
            extracted2.suffix in ("xyz", "online", "site", "shop", "store", "info", "biz"):
        findings.append(DomainFinding(
            severity="high",
            finding="Suspicious recruiting domain with low-trust TLD",
            detail=f"'{sender_domain}' combines recruiting keywords with a low-trust TLD "
                   "— commonly used in fraudulent job schemes",
        ))

    return findings
