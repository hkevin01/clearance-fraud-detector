"""
Known legitimate defense contractors and their official email domains.
Used to detect impersonation / spoofing attempts.
"""

# ---------------------------------------------------------------------------
# Legitimate cleared job boards and platforms
# ---------------------------------------------------------------------------
LEGITIMATE_JOB_BOARDS: dict[str, str] = {
    "ClearanceJobs": "clearancejobs.com",
    "ClearedJobs.net": "clearedjobs.net",
    "USAJobs": "usajobs.gov",
    "LinkedIn": "linkedin.com",
    "Indeed": "indeed.com",
    "Dice": "dice.com",
}

# ---------------------------------------------------------------------------
# Known fake / typosquatted recruitment domains
# ---------------------------------------------------------------------------
KNOWN_FAKE_RECRUITING_DOMAINS: set[str] = {
    # ClearanceJobs fakes
    "clearancejobs.net", "clearancejobs.org", "clearancejobz.com",
    "clearance-jobs.com", "clearancejob.com", "clearedjobs.com",
    # USAJobs fakes
    "usajobs.net", "usajobs.org", "usa-jobs.gov.com", "usajobz.com",
    "jobs.usa.com", "usajobbz.com",
    # LinkedIn fakes
    "linked-in.com", "linkediin.com", "linkedln.com", "1inkedin.com",
    "link3din.com", "linkd-in.com",
    # Indeed fakes
    "ind33d.com", "indeeed.com", "indeed.net", "indeed-jobs.com",
    # Contractor impersonators
    "boo-zallen.com", "boozallenhamilton.net", "boozallen-careers.com",
    "leidos-careers.com", "leidos-jobs.com",
    "saicjobs.com", "saic-careers.com",
    "raytheonjobs.net", "raytheon-careers.net",
    "northropgrummanjobs.com", "northrop-careers.com",
    "lmco-careers.com", "lm-careers.com", "lockheed-careers.com",
    "l3harriscareers.com", "l3harris-jobs.com",
    "caci-jobs.net", "caci-careers.com",
    "mantech-careers.com", "mantechjobs.com",
    # Government impersonators
    "dod-careers.com", "dod-hiring.com",
    "nsa-jobs.com", "nsa-careers.com", "nsacareers.net",
    "cia-careers.gov.com", "cia-jobs.com",
    "pentagon-hiring.com", "dodhiring.com",
    "dia-careers.com", "dia-jobs.com",
}

LEGITIMATE_CONTRACTORS: dict[str, list[str]] = {
    "Booz Allen Hamilton": ["boozallen.com"],
    "Leidos": ["leidos.com"],
    "SAIC": ["saic.com"],
    "Raytheon": ["rtx.com", "raytheon.com"],
    "Northrop Grumman": ["northropgrumman.com"],
    "Lockheed Martin": ["lmco.com", "lockheedmartin.com"],
    "General Dynamics": ["gd.com", "generaldynamics.com"],
    "L3Harris": ["l3harris.com"],
    "CACI": ["caci.com"],
    "ManTech": ["mantech.com"],
    "DXC Technology": ["dxc.com"],
    "Accenture Federal": ["accenture.com", "accenturefederal.com"],
    "Deloitte": ["deloitte.com", "deloittefederal.com"],
    "BAE Systems": ["baesystems.com"],
    "Peraton": ["peraton.com"],
    "Engility": ["engility.com"],
    "KEYW": ["keywcorp.com"],
    "Parsons": ["parsons.com"],
    "PAE": ["pae.com"],
    "MITRE": ["mitre.org"],
    "RAND": ["rand.org"],
    "IDA": ["ida.org"],
    "Noblis": ["noblis.org"],
    "In-Q-Tel": ["iqt.org"],
    # Additional major cleared contractors
    "Amentum": ["amentum.com"],
    "GDIT (General Dynamics IT)": ["gdit.com"],
    "Chenega": ["chenega.com"],
    "Textron": ["textron.com"],
    "Vectrus": ["vectrus.com"],
    "Unison": ["unisonus.com"],
    "Alion Science": ["alionscience.com"],
    "Engenuity": ["engenuity-inc.com"],
    "Jacobs Engineering": ["jacobs.com"],
    "Tetra Tech": ["tetratech.com"],
    "Kratos Defense": ["kratosdefense.com"],
    "Vencore": ["vencore.com"],
    "SciTec": ["scitec.com"],
    "Sabre Systems": ["sabresystems.com"],
    "Engility Holdings": ["engility.com"],
    "Titan Corporation": ["titan.com"],
    "DLT Solutions": ["dlt.com"],
    "Dynamics Research": ["drc.com"],
    "RedSeal Networks": ["redseal.net"],
    "KeyW Holding": ["keyw.com"],
    "Ridgeline International": ["ridgelineintl.com"],
    "Sentek Global": ["sentekglobal.com"],
    # Cleared staffing firms — verified SAM/GSA registered (see VERIFIED_CONTRACTORS below)
    "Mindbank Consulting Group": ["mindbank.com"],
    "Marathon TS": ["marathonts.com"],
    "Kforce": ["kforce.com"],
    "22nd Century Technologies": ["tscti.com"],
    "eTalent Network": ["etalentnetwork.com"],   # TSCTI exclusive RPO staffing partner (verified etalentnetwork.com/clients)
    # Big 4 / major advisory with federal contracting presence
    "EY (Ernst & Young)": ["ey.com", "eygps.us"],   # eygps.us = EY Government & Public Sector; WHOIS verified EY-owned, est. 2021-03-31
}

# ---------------------------------------------------------------------------
# Verified contractor registry — cross-referenced against SAM.gov, GSA eLibrary,
# and official company websites. Last verified April 2026.
# ---------------------------------------------------------------------------
VERIFIED_CONTRACTORS: dict[str, dict] = {
    "Mindbank Consulting Group": {
        "legal_name": "MINDBANK CONSULTING GROUP, L.L.C.",
        "uei": "QJ8VM18ZNML4",
        "cage": "4X5F9",
        "address": "501 Church St NE, Suite 205, Vienna, VA 22180-4734",
        "phone": "703-893-4700",
        "email_domain": "mindbank.com",
        "gsa_contract": "GS-35F-708GA",
        "gsa_contract_end": "2037-09-26",
        "certifications": ["WOSB", "SBA-Certified WOSB"],
        "founded": 1986,
        "services": "IT staffing, cleared professional staffing, enterprise IT support, wireless",
        "clients": "Federal agencies, state/local government, Fortune 1000",
        "note": "Active GSA MAS contract. Secondary offices in Lakewood CO. "
                "CAUTION: website footer contains typo email info@maindbank.com — "
                "correct email uses @mindbank.com",
        "verified_sources": ["GSA eLibrary", "HigherGov", "Official website"],
    },
    "Marathon TS": {
        "legal_name": "MARATHON TS, INC.",
        "uei": "MLU5PYN4P9A7",
        "cage": "5RTU8",
        "duns": "832258086",
        "address": "21145 Whitfield Pl, Suite 106, Sterling, VA 20165-7282",
        "phone": "703-230-4200",
        "email_domain": "marathonts.com",
        "contacts": {
            "CEO": "Pamela K. Siek (psiek@marathonts.com)",
            "President": "Mark Krial (mkrial@marathonts.com)",
            "VP Gov Services": "Zach Tessier",
            "Dir Gov & Client Svcs": "Maddie Durham",
        },
        "gsa_contract": "47QTCA24D00BV",
        "gsa_contract_end": "2029-06-26",
        "gsa_ultimate_end": "2044-06-26",
        "certifications": [
            "WOSB (SBA-Certified, March 13 2024)",
            "Self-Certified Small Disadvantaged Business",
            "TOP SECRET Facility Clearance",
            "DCAA-Approved Accounting System",
            "CMMI Level 3",
            "ISO 9000 Series",
            "Previously HUBZone (2010-2018)",
        ],
        "naics_primary": "541519",
        "sam_registered": "2009-10-20",
        "founded": 2006,
        "offices": [
            "Sterling VA (HQ)",
            "St. Louis MO",
            "San Diego CA",
        ],
        "services": (
            "IT solutions, cleared professional staffing/talent acquisition, "
            "custom app development, network/systems engineering, GIS, "
            "intelligence analysis, IT security, O&M support"
        ),
        "clients": [
            "Department of State",
            "Department of Energy (NREL)",
            "DHS / FEMA",
            "Department of the Navy",
            "Defense Health Agency",
            "Leidos (subcontract)",
            "Millennium Challenge Corporation",
        ],
        "federal_awards_total": "$155.6M (prime + sub)",
        "prime_contracts": 5,
        "subcontracts": 268,
        "teaming_partners": 40,
        "note": (
            "Legitimate cleared IT staffing/services firm. Actively recruiting cleared "
            "professionals for federal programs. Uses JobDiva ATS for job applications. "
            "Data Science SME roles are consistent with their intelligence analysis practice area."
        ),
        "verified_sources": ["GSA eLibrary", "CAGE.report", "HigherGov", "Official website"],
    },
    "EY": {
        "legal_name": "ERNST & YOUNG LLP",
        "dba": "EY",
        "uei": "ECMMFNMSLXM7",
        "cage": "5Y673",
        "duns": "096974717",
        "address": "5 Times Square, New York, NY 10036",
        "gov_office": "1775 Tysons Blvd, Suite 1800, Tysons, VA 22102",
        "regional_offices": {
            "Charleston WV": "500 Virginia St E, Suite 900, Charleston, WV 25301 | 304-343-8972 (~30 staff, accounting/advisory)",
        },
        "email_domain": "ey.com",
        "gsa_contract": "GS-00F-290CA",
        "gsa_contract_end": "2030-09-07",
        "certifications": [],
        "naics_primary": "541211",
        "entity_structure": "Partnership / LLP",
        "state_of_incorporation": "Delaware",
        "founded": 1894,
        "sam_registered": "2003-04-10",
        "contacts": {
            "Gov Business POC": "David Lewandoski (david.lewandoski@ey.com), Tysons VA",
        },
        "services": (
            "Audit/assurance, management consulting, federal advisory, "
            "strategy & transactions, tax, cybersecurity/risk, IT transformation, "
            "ERP implementation, compliance, financial management"
        ),
        "clients": [
            "Federal civilian agencies",
            "Department of Defense",
            "Intelligence Community",
            "Federal financial management",
        ],
        "federal_awards_total": "$4.5B (contracts $4.3B + subcontracts $169.2M + grants)",
        "note": (
            "One of the Big 4 professional services firms. Major federal advisory and "
            "IT consulting presence. Government contracting hub is Tysons VA office. "
            "Email domain is @ey.com — do NOT accept @ernst-young.com, @ey-advisory.com, "
            "or any variant."
        ),
        "verified_sources": ["CAGE.report", "HigherGov", "Official website (ey.com)"],
    },
    "22nd Century Technologies (TSCTI)": {
        "legal_name": "22ND CENTURY TECHNOLOGIES, INC.",
        "dba": "TSCTI",
        "uei": "QT2VZ9L1VPQ1",
        "cage": "3DYY9",
        "address": "8251 Greensboro Dr, Ste 900, McLean, VA 22102",
        "email_domain": "tscti.com",
        "gsa_contract": "47QRCA25DU640",
        "naics_primary": "541511",  # Custom Computer Programming Services
        "sam_registered": "2003-03-03",
        "founded": "1997-03-24",
        "certifications": [
            "CMBE (Certified National Minority Business Enterprise)",
            "CMMi Level 3",
            "ISO 9001",
            "ISO 20000",
            "ISO 27001",
        ],
        "size": "6,000+ employees, 600+ Cyber SMEs nationwide",
        "services": (
            "IT solutions, cybersecurity, cloud computing, software development, "
            "systems integration, managed IT, cleared professional staffing"
        ),
        "clients": [
            "FBI CJIS Division (MXU program, Clarksburg WV — $35M since 2016)",
            "US Army",
            "Department of State",
            "Department of Homeland Security",
            "Federal civilian agencies",
        ],
        "salary_benchmarks": {
            "source": "Glassdoor (20+ employee reports, Apr 2026)",
            "software_developer": "$92,000 – $130,000",
            "applications_developer": "$104,000 – $141,000",
            "senior_software_engineer": "up to $153,000",
            "fair_pay_score": "1.8 / 5 (below market per employee self-reports)",
            "note": (
                "TS/SCI roles at FBI MXU Clarksburg WV typically $115K–$145K. "
                "Salaries in this range are LEGITIMATE for cleared SW developers — "
                "they should NOT trigger salary_bait fraud patterns. "
                "Compare: GDIT Cyber Developer SME @ FBI ECS Clarksburg: $139K–$188K (TheLadders, 2025)."
            ),
        },
        "staffing_partner": {
            "name": "eTalent Network",
            "domain": "etalentnetwork.com",
            "role": "Exclusive RPO (Recruitment Process Outsourcing) partner for TSCTI hiring",
            "source": (
                "etalentnetwork.com/clients (direct quote): "
                "'E-talent network is responsible for carrying out the recruitment process "
                "for 22nd Century Technologies'"
            ),
        },
        "note": (
            "Active federal IT contractor with FBI CJIS MXU program presence in Clarksburg WV. "
            "Forbes America's Best Large Employers confirmed. "
            "Recruiting emails from @etalentnetwork.com are legitimate — "
            "eTalent Network is TSCTI's verified RPO staffing partner. "
            "Always verify specific role and program through tscti.com/careers before providing PII. "
            "Apply via tscti.com/careers or the Workday/ATS portal, not via Telegram."
        ),
        "verified_sources": [
            "SAM.gov via G2Xchange (UEI QT2VZ9L1VPQ1, CAGE 3DYY9, NAICS 541511)",
            "GSA eLibrary contract 47QRCA25DU640",
            "Forbes America's Best Large Employers",
            "Glassdoor TSCTI page (20+ salary reports, Apr 2026)",
            "etalentnetwork.com/clients (direct confirmation of TSCTI staffing relationship)",
        ],
    },
    "eTalent Network": {
        "legal_name": "ETALENTNETWORK",
        "email_domain": "etalentnetwork.com",
        "relationship": "TSCTI exclusive RPO/staffing partner (confirmed by eTalent Network website)",
        "services": (
            "IT staffing, Recruitment Process Outsourcing (RPO), "
            "cleared professional placement, general staffing"
        ),
        "clients": [
            "22nd Century Technologies / TSCTI (primary client, confirmed on their website)",
            "Optimize Manpower Solutions, Inc.",
            "Government/Public Sector contractors",
        ],
        "note": (
            "eTalent Network is the official RPO/staffing partner for TSCTI. "
            "Email @etalentnetwork.com is legitimate for TSCTI-related cleared job outreach. "
            "Direct quote from etalentnetwork.com/clients: "
            "'E-talent network is responsible for carrying out the recruitment process "
            "for 22nd Century Technologies.' "
            "CAUTION: eTalent Network serves multiple employer clients; verify the exact "
            "client/program before proceeding."
        ),
        "verified_sources": [
            "etalentnetwork.com/clients — direct quote confirming TSCTI recruiting role",
            "etalentnetwork.com/about — staffing/RPO mission statement",
        ],
    },
}

GOVERNMENT_DOMAINS: set[str] = {
    "mil", "gov", "us",
    "army.mil", "navy.mil", "airforce.mil", "marines.mil",
    "dod.gov", "nsa.gov", "cia.gov", "fbi.gov", "dia.mil",
    "nro.mil", "nga.mil", "disa.mil", "darpa.mil",
    "state.gov", "dhs.gov", "dni.gov", "dni.mil",
}

ALL_LEGITIMATE_DOMAINS: set[str] = set()
for domains in LEGITIMATE_CONTRACTORS.values():
    ALL_LEGITIMATE_DOMAINS.update(domains)
ALL_LEGITIMATE_DOMAINS.update(GOVERNMENT_DOMAINS)
