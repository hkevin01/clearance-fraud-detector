"""
CAGE Code Reference Database — Known Legitimate Prime Contractors.

CAGE (Commercial and Government Entity) codes are 5-character alphanumeric
identifiers assigned by the Defense Logistics Agency to entities that do
business with the U.S. government.

This file contains CAGE codes for known prime defense contractors, sourced
from public SAM.gov records. ALL entries should be independently verified at:
  https://sam.gov/search/?index=cf

IMPORTANT:
  - This data is for cross-reference only — NOT for making security decisions alone
  - CAGE codes for classified facilities may have restricted detail on sam.gov
  - Always verify directly: https://sam.gov/content/cage-codes
  - DoD DLA CAGE program: https://cage.dla.mil/Home/Procedures

Format: CAGE_CODES[cage_code] = {name, primary_domain, sam_url}
"""
from __future__ import annotations


CAGE_CODES: dict[str, dict[str, str]] = {
    # Raytheon Technologies / RTX
    "1DT27": {
        "name": "Raytheon Intelligence & Space",
        "primary_domain": "rtx.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=1DT27",
    },
    # Lockheed Martin
    "OH859": {
        "name": "Lockheed Martin Corporation",
        "primary_domain": "lockheedmartin.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=OH859",
    },
    # Northrop Grumman
    "K1097": {
        "name": "Northrop Grumman Systems Corporation",
        "primary_domain": "northropgrumman.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=K1097",
    },
    # General Dynamics
    "1T014": {
        "name": "General Dynamics Corporation",
        "primary_domain": "gd.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=1T014",
    },
    # Booz Allen Hamilton
    "17038": {
        "name": "Booz Allen Hamilton Inc.",
        "primary_domain": "boozallen.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=17038",
    },
    # SAIC
    "1CFK8": {
        "name": "Science Applications International Corporation (SAIC)",
        "primary_domain": "saic.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=1CFK8",
    },
    # Leidos
    "1DTD7": {
        "name": "Leidos Inc.",
        "primary_domain": "leidos.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=1DTD7",
    },
    # CACI
    "93836": {
        "name": "CACI International Inc.",
        "primary_domain": "caci.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=93836",
    },
    # ManTech
    "1F4PH": {
        "name": "ManTech International Corporation",
        "primary_domain": "mantech.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=1F4PH",
    },
    # L3Harris Technologies
    "L3TEC": {
        "name": "L3Harris Technologies Inc.",
        "primary_domain": "l3harris.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=L3Harris",
    },
    # Peraton
    "5A3R5": {
        "name": "Peraton Inc.",
        "primary_domain": "peraton.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=5A3R5",
    },
    # Parsons Corporation
    "04960": {
        "name": "Parsons Corporation",
        "primary_domain": "parsons.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=04960",
    },
    # BAE Systems
    "UK780": {
        "name": "BAE Systems Inc.",
        "primary_domain": "baesystems.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=BAE+Systems",
    },
    # DXC Technology
    "16RF7": {
        "name": "DXC Technology Company",
        "primary_domain": "dxc.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=16RF7",
    },
    # Unison Group / Unison Holdings
    "78HH0": {
        "name": "Unison Group LLC",
        "primary_domain": "unisongroup.com",
        "sam_url": "https://sam.gov/search/?index=cf&q=78HH0",
    },
}


# Reverse lookup: domain → CAGE code
DOMAIN_TO_CAGE: dict[str, str] = {
    entry["primary_domain"]: code
    for code, entry in CAGE_CODES.items()
}


def lookup_cage(cage_code: str) -> dict[str, str] | None:
    """
    Look up a CAGE code in the local database.

    Returns the entry dict or None if not found.
    Note: absence does NOT mean the code is invalid — it means it's not
    in our limited local database. Always verify at sam.gov.
    """
    return CAGE_CODES.get(cage_code.strip().upper())


def lookup_by_domain(domain: str) -> str | None:
    """
    Look up the CAGE code for a known domain.

    Returns the CAGE code string or None.
    """
    return DOMAIN_TO_CAGE.get(domain.lower().strip())


def build_sam_url(cage_or_name: str) -> str:
    """
    Build a SAM.gov search URL for a CAGE code or company name.

    Args:
        cage_or_name: Either a CAGE code or a company name string.

    Returns:
        A SAM.gov search URL.
    """
    return f"https://sam.gov/search/?index=cf&q={cage_or_name.replace(' ', '+')}"
