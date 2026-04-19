"""
CLI: fraud-check command using Typer + Rich output.
Usage:
  fraud-check scan email.eml
  fraud-check scan-text "email body text" --subject "Job Offer" --sender "jobs@gmail.com"
  fraud-check scan-job "job posting text"
  fraud-check scan-call "call transcript or notes"
  fraud-check scan-contact "FSO or recruiter message"
  fraud-check scan-number "703-594-4241" --company "22nd Century Tech" --ssn-requested
  fraud-check verify-company "Marathon TS"
  fraud-check compliance-check "email or message text"
  fraud-check verify-offer offer_letter.txt
  fraud-check explain --patterns ssn_request --patterns dod_safe_ssn_channel
  fraud-check generate-report --company "Bad Corp" --recruiter "Jane Doe"
  fraud-check report-fraud
  fraud-check demo
"""
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from .detector import EmailFraudDetector
from .analyzers.contact_analyzer import ContactType
from .report_generator import IncidentReportInput, quick_report, generate_submission_guide
from .scoring.scorer import Verdict
from .reporting import REPORTING_AGENCIES, IMMEDIATE_SSN_STOLEN_ACTIONS
from .data.known_contractors import VERIFIED_CONTRACTORS, LEGITIMATE_CONTRACTORS

app = typer.Typer(
    name="fraud-check",
    help=(
        "Clearance-job fraud detector. Analyzes emails, job postings, and "
        "call transcripts for fake companies, PII harvesting, AI voice fraud, "
        "and DPRK IT worker schemes."
    ),
)
console = Console()
detector = EmailFraudDetector()

VERDICT_COLORS = {
    Verdict.CLEAN: "green",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.LIKELY_FRAUD: "orange3",
    Verdict.FRAUD: "bold red",
}

VERDICT_ICONS = {
    Verdict.CLEAN: "✅",
    Verdict.SUSPICIOUS: "⚠️",
    Verdict.LIKELY_FRAUD: "🚨",
    Verdict.FRAUD: "🛑",
}

_RISK_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}


def _print_report(score, source: str = "") -> None:
    color = VERDICT_COLORS[score.verdict]
    icon = VERDICT_ICONS[score.verdict]

    verdict_text = Text(f"{icon}  {score.verdict.value}  (score: {score.total_score:.3f})", style=f"bold {color}")
    console.print(Panel(verdict_text, title=f"[bold]Fraud Analysis{f': {source}' if source else ''}[/bold]", border_style=color))

    # Score breakdown
    if score.category_breakdown:
        table = Table(title="Score Breakdown", box=box.SIMPLE, show_header=True)
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Bar", min_width=20)
        for cat, val in sorted(score.category_breakdown.items(), key=lambda x: -x[1]):
            bar_len = int(val / 0.35 * 20)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            table.add_row(cat, f"{val:.3f}", bar)
        console.print(table)

    # Top reasons
    if score.top_reasons:
        console.print("\n[bold yellow]Top Risk Signals:[/bold yellow]")
        for i, reason in enumerate(score.top_reasons, 1):
            console.print(f"  {i}. {reason}")

    # Domain findings
    if score.domain_findings:
        console.print("\n[bold red]Domain Analysis:[/bold red]")
        for df in score.domain_findings:
            sev_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(df.severity, "white")
            console.print(f"  [{sev_color}][{df.severity.upper()}][/{sev_color}] {df.finding}: {df.detail}")

    # NLP suspicious URLs
    if score.nlp_findings.suspicious_urls:
        console.print("\n[bold red]Suspicious URLs:[/bold red]")
        for url in score.nlp_findings.suspicious_urls:
            console.print(f"  • {url}")

    console.print()


def _print_vishing_report(analysis, source: str = "") -> None:
    """Print vishing/call-transcript analysis results."""
    if analysis.is_suspicious_call:
        risk_color = "bold red" if analysis.risk_score >= 0.60 else "red" if analysis.risk_score >= 0.40 else "yellow"
        icon = "🛑" if analysis.risk_score >= 0.60 else "🚨"
    else:
        risk_color = "green"
        icon = "✅"

    label = "SUSPICIOUS CALL" if analysis.is_suspicious_call else "CALL APPEARS CLEAN"
    verdict_text = Text(f"{icon}  {label}  (risk: {analysis.risk_score:.3f})", style=f"bold {risk_color}")
    console.print(Panel(
        verdict_text,
        title=f"[bold]Call / Interview Analysis{f': {source}' if source else ''}[/bold]",
        border_style=risk_color.split()[-1],
    ))

    if analysis.findings:
        table = Table(title="Call Red Flags", box=box.SIMPLE, show_header=True)
        table.add_column("Severity", style="bold", min_width=8)
        table.add_column("Category", style="cyan", min_width=16)
        table.add_column("Finding", style="white")
        for f in sorted(analysis.findings, key=lambda x: x.weight, reverse=True):
            sev_style = _RISK_COLORS.get(f.severity, "white")
            table.add_row(
                Text(f.severity.upper(), style=sev_style),
                f.category,
                f.finding,
            )
        console.print(table)

        console.print("\n[bold yellow]Detailed Explanations:[/bold yellow]")
        for i, f in enumerate(sorted(analysis.findings, key=lambda x: x.weight, reverse=True), 1):
            sev_style = _RISK_COLORS.get(f.severity, "white")
            console.print(f"  {i}. [{sev_style}][{f.severity.upper()}][/{sev_style}] {f.finding}")
            console.print(f"     {f.detail}")
    else:
        console.print("[green]No suspicious call indicators detected.[/green]")
        console.print("\n[bold cyan]What a legitimate cleared-job call looks like:[/bold cyan]")
        console.print("  • Recruiter uses verifiable corporate email domain (not gmail/yahoo/outlook.com)")
        console.print("  • Video call with camera on; recruiter has LinkedIn profile matching company")
        console.print("  • No SSN, DOB, or passport details requested on the call — only post-offer via HR portal")
        console.print("  • Formal written offer comes before any personal data collection")
        console.print("  • FSO introductions happen after offer acceptance, via company-issued communication")

    _print_protective_advice_call(analysis)
    console.print()


def _print_job_posting_report(analysis, source: str = "") -> None:
    """Print job-posting analysis results."""
    if analysis.is_fraudulent:
        risk_color = "bold red" if analysis.risk_score >= 0.60 else "red" if analysis.risk_score >= 0.40 else "yellow"
        icon = "🛑" if analysis.risk_score >= 0.60 else "🚨"
        label = "FRAUDULENT JOB POSTING"
    else:
        risk_color = "green"
        icon = "✅"
        label = "JOB POSTING APPEARS LEGITIMATE"

    verdict_text = Text(f"{icon}  {label}  (risk: {analysis.risk_score:.3f})", style=f"bold {risk_color}")
    console.print(Panel(
        verdict_text,
        title=f"[bold]Job Posting Analysis{f': {source}' if source else ''}[/bold]",
        border_style=risk_color.split()[-1],
    ))

    if analysis.findings:
        table = Table(title="Job Posting Red Flags", box=box.SIMPLE, show_header=True)
        table.add_column("Severity", style="bold", min_width=8)
        table.add_column("Category", style="cyan", min_width=20)
        table.add_column("Finding", style="white")
        for f in sorted(analysis.findings, key=lambda x: x.weight, reverse=True):
            sev_style = _RISK_COLORS.get(f.severity, "white")
            table.add_row(
                Text(f.severity.upper(), style=sev_style),
                f.category,
                f.finding,
            )
        console.print(table)

        console.print("\n[bold yellow]Detailed Explanations:[/bold yellow]")
        for i, f in enumerate(sorted(analysis.findings, key=lambda x: x.weight, reverse=True), 1):
            sev_style = _RISK_COLORS.get(f.severity, "white")
            console.print(f"  {i}. [{sev_style}][{f.severity.upper()}][/{sev_style}] {f.finding}")
            console.print(f"     {f.detail}")
    else:
        console.print("[green]No job-posting fraud indicators detected.[/green]")

    _print_protective_advice_job(analysis)
    console.print()


def _print_protective_advice_call(analysis) -> None:
    """Print actionable protective advice based on vishing findings."""
    if not analysis.is_suspicious_call:
        return
    tips = []
    cats = {f.category for f in analysis.findings}
    if "pii_harvest" in cats:
        tips.append("[bold red]NEVER provide SSN, DOB, bank info, or passport details over a phone/video call.[/bold red]")
    if "dprk_scheme" in cats:
        tips.append("Report to the FBI IC3 (ic3.gov) and your organization's security officer — this matches DPRK IT worker scheme indicators.")
    if "ai_voice_fraud" in cats:
        tips.append("Request an in-person meeting or a video call with a known corporate email contact before proceeding.")
    if "fake_recruiter" in cats:
        tips.append("Verify the recruiter on LinkedIn using the company's official domain. Real recruiters have verifiable corporate profiles.")
    if tips:
        console.print("\n[bold cyan]Protective Actions:[/bold cyan]")
        for tip in tips:
            console.print(f"  • {tip}")


def _print_protective_advice_job(analysis) -> None:
    """Print actionable protective advice based on job posting findings."""
    if not analysis.is_fraudulent:
        return
    tips = []
    cats = {f.category for f in analysis.findings}
    if "pii_harvest" in cats:
        tips.append("[bold red]Do NOT submit SSN, DOB, or passport details as part of any initial job application.[/bold red]")
    if "clearance_fraud" in cats:
        tips.append(
            "Report to DCSA Counterintelligence: 571-305-6576 | dcsacounterfraud@mail.mil | "
            "dcsa.mil/MC/CI/ — Only DCSA adjudicates clearances. No employer can guarantee or "
            "expedite a clearance, and no clearance is ever 'pre-approved' before investigation."
        )
    if "financial_fraud" in cats:
        tips.append("Legitimate employers NEVER charge fees. Report application fees to the FTC (reportfraud.ftc.gov).")
    if "dprk_scheme" in cats:
        tips.append("Report to FBI (tips.fbi.gov) — this matches documented North Korean IT worker scheme characteristics.")
    if "fake_platform" in cats or "identity_concealment" in cats:
        tips.append("Verify the employer on SAM.gov, ClearanceJobs.com, or the company's official government-contracted profile.")
    if tips:
        console.print("\n[bold cyan]Protective Actions:[/bold cyan]")
        for tip in tips:
            console.print(f"  • {tip}")


_CONTACT_TYPE_COLORS = {
    ContactType.CLEAN: "green",
    ContactType.SUSPICIOUS_RECRUITER: "yellow",
    ContactType.SUSPICIOUS_FSO: "yellow",
    ContactType.FAKE_RECRUITER: "bold red",
    ContactType.FAKE_FSO: "bold red",
    ContactType.MIXED: "bold red",
}

_CONTACT_TYPE_ICONS = {
    ContactType.CLEAN: "✅",
    ContactType.SUSPICIOUS_RECRUITER: "⚠️",
    ContactType.SUSPICIOUS_FSO: "⚠️",
    ContactType.FAKE_RECRUITER: "🛑",
    ContactType.FAKE_FSO: "🛑",
    ContactType.MIXED: "🛑",
}

_CONTACT_TYPE_LABELS = {
    ContactType.CLEAN: "CONTACT APPEARS LEGITIMATE",
    ContactType.SUSPICIOUS_RECRUITER: "SUSPICIOUS RECRUITER CONTACT",
    ContactType.SUSPICIOUS_FSO: "SUSPICIOUS FSO CONTACT",
    ContactType.FAKE_RECRUITER: "FAKE RECRUITER — DO NOT COMPLY",
    ContactType.FAKE_FSO: "FAKE FSO — DO NOT PROVIDE SSN",
    ContactType.MIXED: "MIXED FSO + RECRUITER FRAUD SIGNALS",
}


def _print_contact_report(analysis, source: str = "") -> None:
    """Print FSO/recruiter contact analysis results."""
    ct = analysis.contact_type
    color = _CONTACT_TYPE_COLORS[ct]
    icon = _CONTACT_TYPE_ICONS[ct]
    label = _CONTACT_TYPE_LABELS[ct]

    score_line = (
        f"  FSO risk: {analysis.fso_score:.3f}  |  "
        f"Recruiter risk: {analysis.recruiter_score:.3f}  |  "
        f"Combined: {analysis.risk_score:.3f}"
    )
    if analysis.legit_signals:
        score_line += f"  |  Legit signals: {analysis.legit_signals}"

    verdict_text = Text(f"{icon}  {label}", style=f"bold {color}")
    console.print(Panel(
        verdict_text,
        subtitle=score_line,
        title=f"[bold]FSO / Recruiter Contact Analysis{f': {source}' if source else ''}[/bold]",
        border_style=color.split()[-1],
    ))

    if analysis.findings:
        # Separate FSO and recruiter findings
        fso_findings = [f for f in analysis.findings if f.actor_type == "fso_impersonation"]
        rec_findings = [f for f in analysis.findings if f.actor_type == "fake_recruiter"]

        if fso_findings:
            table = Table(title="FSO Impersonation Red Flags", box=box.SIMPLE, show_header=True)
            table.add_column("Severity", style="bold", min_width=8)
            table.add_column("Finding", style="white")
            for f in sorted(fso_findings, key=lambda x: x.weight, reverse=True):
                sev_style = _RISK_COLORS.get(f.severity, "white")
                table.add_row(Text(f.severity.upper(), style=sev_style), f.finding)
            console.print(table)

        if rec_findings:
            table = Table(title="Fake Recruiter Red Flags", box=box.SIMPLE, show_header=True)
            table.add_column("Severity", style="bold", min_width=8)
            table.add_column("Finding", style="white")
            for f in sorted(rec_findings, key=lambda x: x.weight, reverse=True):
                sev_style = _RISK_COLORS.get(f.severity, "white")
                table.add_row(Text(f.severity.upper(), style=sev_style), f.finding)
            console.print(table)

        console.print("\n[bold yellow]Detailed Explanations:[/bold yellow]")
        for i, f in enumerate(sorted(analysis.findings, key=lambda x: x.weight, reverse=True), 1):
            sev_style = _RISK_COLORS.get(f.severity, "white")
            actor_color = "red" if "fso" in f.actor_type else "magenta"
            console.print(
                f"  {i}. [{sev_style}][{f.severity.upper()}][/{sev_style}] "
                f"[{actor_color}][{f.actor_type}][/{actor_color}] {f.finding}"
            )
            console.print(f"     {f.detail}")

    elif ct == ContactType.CLEAN:
        if analysis.legit_signals:
            console.print("[green]Legitimate contact signals detected. No fraud indicators found.[/green]")
        else:
            console.print(
                "[yellow]No fraud indicators detected, but no strong legitimate signals either.[/yellow]"
            )
            console.print("\n[bold yellow]Verify independently before proceeding:[/bold yellow]")
            console.print("  • Confirm the company's SAM.gov registration: [blue]sam.gov/search[/blue]")
            console.print("  • Confirm active GSA/federal contract: [blue]gsaelibrary.gsa.gov[/blue]")
            console.print("  • Look up the recruiter's corporate email domain on LinkedIn")
            console.print("  • Call the company's PUBLISHED main number and ask to be connected — don't use contact info from the message")
            console.print("  • Run: [bold]fraud-check verify-company \"Company Name\"[/bold] to cross-check local verified database")

    _print_protective_advice_contact(analysis)
    console.print()


def _print_protective_advice_contact(analysis) -> None:
    """Print specific protective advice for FSO/recruiter contact fraud."""
    if not analysis.is_suspicious:
        if not analysis.safe_to_provide_ssn:
            console.print(
                "\n[bold yellow]Reminder:[/bold yellow] Even with legitimate contact, "
                "provide SSN only AFTER a formal written offer, via secure HR portal only — "
                "never by email or over the phone."
            )
        return

    tips = []
    ct = analysis.contact_type
    cats = {f.actor_type for f in analysis.findings}

    if ct in (ContactType.FAKE_FSO, ContactType.SUSPICIOUS_FSO, ContactType.MIXED):
        tips.append(
            "[bold red]DO NOT provide your SSN — a real FSO verifies clearance status "
            "through DISS using your name and employer. They never need you to supply your SSN.[/bold red]"
        )
        tips.append(
            "Call the company's main published phone number and ask for the FSO by name "
            "to verify identity — do not use contact info supplied in the suspicious message."
        )
        tips.append(
            "Report suspected fake FSO contact to DCSA Counterintelligence: "
            "571-305-6576 | dcsacounterfraud@mail.mil | dcsa.mil/MC/CI/"
        )

    if ct in (ContactType.FAKE_RECRUITER, ContactType.SUSPICIOUS_RECRUITER, ContactType.MIXED):
        tips.append(
            "[bold red]DO NOT provide SSN, DOB, or passport details to a recruiter — "
            "SSN is only collected post-offer via secure HR onboarding portal.[/bold red]"
        )
        tips.append(
            "Verify the recruiter on LinkedIn using their corporate domain email. "
            "Search the company on SAM.gov to confirm they hold an active facility clearance."
        )

    if "fso_impersonation" in cats or "fake_recruiter" in cats:
        tips.append(
            "If you already provided SSN/DOB: freeze credit at all 5 bureaus "
            "(Equifax, Experian, TransUnion, Innovis, ChexSystems), get an IRS Identity "
            "Protection PIN at irs.gov/ippin, and notify your current FSO."
        )
        tips.append("File with FBI IC3 at ic3.gov and FTC at reportfraud.ftc.gov.")
        tips.append(
            "Run [bold]fraud-check report-fraud --ssn-given[/bold] for the complete "
            "immediate action checklist with all agency contacts."
        )

    if tips:
        console.print("\n[bold cyan]Protective Actions:[/bold cyan]")
        for tip in tips:
            console.print(f"  • {tip}")


@app.command(name="scan-contact")
def scan_contact(
    message: str = typer.Argument(
        ...,
        help="Recruiter/FSO message text, or path to a .txt file",
    ),
):
    """
    Analyze a recruiter message or FSO contact email/transcript.

    Distinguishes between:
      - FAKE FSO exploiting the clearance verification process to steal SSN
      - FAKE RECRUITER running PII harvest, financial fraud, or DPRK scheme

    Key rule: A real FSO verifies clearance through DISS — they NEVER ask YOU
    to supply your SSN "to verify your clearance level."

    Examples:
      fraud-check scan-contact "Our FSO needs your SSN to verify your clearance in DISS."
      fraud-check scan-contact recruiter_email.txt
    """
    maybe_path = Path(message)
    if maybe_path.exists() and maybe_path.suffix.lower() in (".txt", ".md", ".log"):
        message = maybe_path.read_text(encoding="utf-8", errors="replace")

    analysis = detector.analyze_contact(message)
    _print_contact_report(analysis, source="contact message")
    raise typer.Exit(1 if analysis.is_suspicious else 0)


@app.command(name="scan-number")
def scan_number(
    number: str = typer.Argument(..., help="Phone number to check (any format)"),
    company: str = typer.Option("", "--company", "-c", help="Company the caller claimed to represent"),
    region: str = typer.Option("", "--region", "-r", help="Location caller claimed to be in"),
    ssn: bool = typer.Option(False, "--ssn-requested", help="Set if SSN/DOB was requested on this call"),
    pre_offer: bool = typer.Option(False, "--pre-offer", help="Set if call happened before a formal written offer"),
):
    """
    Check a phone number used by a recruiter or FSO contact.

    Compares against published numbers for known cleared staffing firms,
    flags geographic mismatches, VoIP usage, and SSN-over-phone requests.

    Examples:
      fraud-check scan-number "703-594-4241" --company "22nd Century Tech" --ssn-requested --pre-offer
      fraud-check scan-number "703-436-9068" --company "Mindbank" --region "Vienna VA"
    """
    analysis = detector.analyze_phone_number(
        number,
        claimed_company=company,
        claimed_region=region,
        ssn_requested=ssn,
        pre_offer=pre_offer,
    )
    _print_phone_report(analysis)
    raise typer.Exit(1 if analysis.is_suspicious else 0)


def _print_phone_report(analysis) -> None:
    """Print phone number analysis results."""
    if not analysis.is_valid:
        console.print(f"[red]Invalid phone number: {analysis.number_raw}[/red]")
        return

    # Determine color and icon from verdict
    if analysis.risk_score >= 0.65 or any(f.weight >= 1.0 for f in analysis.findings):
        color, icon = "bold red", "🛑"
    elif analysis.is_suspicious:
        color, icon = "red", "🚨"
    elif analysis.matched_company:
        color, icon = "green", "✅"
    else:
        color, icon = "yellow", "⚠️"

    # Header panel
    verdict_text = Text(f"{icon}  {analysis.verdict}", style=f"bold {color}")
    meta = (
        f"  {analysis.number_e164}  |  "
        f"Type: {analysis.line_type}  |  "
        f"Region: {analysis.region or 'unknown'}  |  "
        f"Risk: {analysis.risk_score:.3f}"
    )
    if analysis.carrier_name:
        meta += f"  |  Carrier: {analysis.carrier_name}"
    console.print(Panel(
        verdict_text,
        subtitle=meta,
        title="[bold]Phone Number Analysis[/bold]",
        border_style=color.split()[-1],
    ))

    # Findings table
    if analysis.findings:
        table = Table(title="Findings", box=box.SIMPLE, show_header=True)
        table.add_column("Severity", min_width=8, style="bold")
        table.add_column("Finding", style="white")
        for f in sorted(analysis.findings, key=lambda x: x.weight, reverse=True):
            if f.weight <= 0:
                sev_style = "green"
                sev_label = "INFO ✅"
            else:
                sev_style = _RISK_COLORS.get(f.severity, "white")
                sev_label = f.severity.upper()
            table.add_row(Text(sev_label, style=sev_style), f.finding)
        console.print(table)

        console.print("\n[bold yellow]Details:[/bold yellow]")
        for i, f in enumerate(sorted(analysis.findings, key=lambda x: x.weight, reverse=True), 1):
            sev_style = "green" if f.weight <= 0 else _RISK_COLORS.get(f.severity, "white")
            console.print(f"  {i}. [{sev_style}]{f.finding}[/{sev_style}]")
            console.print(f"     {f.detail}")

    # Secure SSN channels reminder
    console.print("\n[bold cyan]Secure SSN Collection — Legitimate Channels Only:[/bold cyan]")
    channels = [
        (
            "NBIS eApp",
            "eapp.nbis.mil",
            "THE authorized SF-86 portal — FSO-initiated post conditional-offer; "
            "you receive a direct link; never a recruiter-sent URL",
        ),
        (
            "DOD SAFE",
            "safe.apps.mil",
            "[red]NOT for SF-86 submission[/red] — DoD secure file transfer (DISA) for "
            "supporting CUI/PII documents only; 7-day auto-delete; requires DoD CAC by sender",
        ),
        (
            "Workday / ADP / SAP",
            "via company HR portal link",
            "Commercial HR platforms for employment paperwork — link arrives via official corporate email domain",
        ),
        (
            "In person / I-9",
            "at company facility",
            "I-9 identity verification must be completed in person — never by phone, email, or text",
        ),
    ]
    t2 = Table(box=box.SIMPLE, show_header=True)
    t2.add_column("Platform", style="cyan", min_width=22)
    t2.add_column("Where", style="white", min_width=30)
    t2.add_column("Used For", style="dim")
    for name, where, used in channels:
        t2.add_row(name, where, used)
    console.print(t2)
    console.print(
        "\n  [bold red]NEVER[/bold red] provide SSN/DOB: over the phone, by email, "
        "via text/WhatsApp/Telegram, or on any site reached by clicking a link in a message.\n"
    )


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to .eml file"),
):
    """Analyze a .eml email file for clearance-job fraud indicators."""
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(1)
    score = detector.analyze_eml_file(path)
    _print_report(score, source=str(path))
    raise typer.Exit(0 if score.verdict == Verdict.CLEAN else 1)


@app.command(name="scan-text")
def scan_text(
    body: str = typer.Argument(..., help="Email body text to analyze"),
    subject: str = typer.Option("", "--subject", "-s", help="Email subject line"),
    sender: str = typer.Option("", "--sender", "-f", help="Sender email address"),
):
    """Analyze raw email text for fraud indicators."""
    score = detector.analyze_text(body, subject=subject, sender=sender)
    _print_report(score, source="text input")
    raise typer.Exit(0 if score.verdict == Verdict.CLEAN else 1)


@app.command(name="scan-call")
def scan_call(
    transcript: str = typer.Argument(
        ...,
        help="Call transcript text, or path to a .txt file containing the transcript",
    ),
):
    """
    Analyze a phone/video call transcript or interview notes for vishing,
    AI voice fraud, and DPRK IT worker scheme indicators.

    Pass text directly or provide a path to a .txt file.

    Examples:
      fraud-check scan-call "The interviewer had camera off and asked for my SSN..."
      fraud-check scan-call interview_notes.txt
    """
    # Accept file path as well as raw text
    maybe_path = Path(transcript)
    if maybe_path.exists() and maybe_path.suffix.lower() in (".txt", ".md", ".log"):
        transcript = maybe_path.read_text(encoding="utf-8", errors="replace")

    analysis = detector.analyze_call_transcript(transcript)
    _print_vishing_report(analysis, source="call transcript")
    raise typer.Exit(1 if analysis.is_suspicious_call else 0)


@app.command(name="scan-job")
def scan_job(
    posting: str = typer.Argument(
        ...,
        help="Job posting text, or path to a .txt file containing the posting",
    ),
):
    """
    Analyze a job posting for fake clearance job indicators — including
    PII harvesting in applications, impossible promises, DPRK scheme signals,
    and fake company characteristics.

    Pass text directly or provide a path to a .txt file.

    Examples:
      fraud-check scan-job "TS/SCI position — no experience needed, $400k/yr, work from home..."
      fraud-check scan-job job_posting.txt
    """
    maybe_path = Path(posting)
    if maybe_path.exists() and maybe_path.suffix.lower() in (".txt", ".md"):
        posting = maybe_path.read_text(encoding="utf-8", errors="replace")

    analysis = detector.analyze_job_posting(posting)
    _print_job_posting_report(analysis, source="job posting")
    raise typer.Exit(1 if analysis.is_fraudulent else 0)


@app.command(name="compliance-check")
def compliance_check(
    text: str = typer.Argument(
        ...,
        help="Recruiter/FSO message text, or path to a .txt file",
    ),
):
    """
    Check a recruiter or FSO message for NISPOM §117.10 violations.

    Maps the interaction text to specific regulatory sections with verbatim
    CFR text, severity level, and recommended action.

    Examples:
      fraud-check compliance-check "Please provide your SSN so I can verify your clearance in DISS."
      fraud-check compliance-check tscti_email.txt
    """
    maybe_path = Path(text)
    if maybe_path.exists() and maybe_path.suffix.lower() in (".txt", ".md", ".log"):
        text = maybe_path.read_text(encoding="utf-8", errors="replace")

    report = detector.check_compliance(text)

    if not report.has_violations:
        console.print(Panel(
            Text("✅  COMPLIANT — No §117.10 violations detected", style="bold green"),
            title="[bold]NISPOM §117.10 Compliance Check[/bold]",
            border_style="green",
        ))
        raise typer.Exit(0)

    color = "bold red" if any(v.severity == "critical" for v in report.violations) else "red"
    console.print(Panel(
        Text(f"🚨  {len(report.violations)} VIOLATION(S) DETECTED", style=color),
        title="[bold]NISPOM §117.10 Compliance Check[/bold]",
        border_style="red",
    ))

    for i, v in enumerate(report.violations, 1):
        sev_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(
            v.severity, "white"
        )
        console.print(f"\n[{sev_color}]Violation {i}: {v.rule}[/{sev_color}]")
        console.print(f"  Category:    {v.category}")
        console.print(f"  Severity:    [{sev_color}]{v.severity.upper()}[/{sev_color}]")
        console.print(f"\n  Verbatim CFR:\n    {v.verbatim[:300]}")
        console.print(f"\n  What This Means:\n    {v.what_violated}")
        console.print(f"\n  Source:  {v.url}")

    console.print(
        f"\n[dim]Source: 32 CFR Part 117 (NISPOM) — "
        f"https://www.ecfr.gov/current/title-32/section-117.10[/dim]"
    )
    raise typer.Exit(1)


@app.command(name="verify-offer")
def verify_offer(
    path_or_text: str = typer.Argument(
        ...,
        help="Path to offer letter text file, or quoted offer letter text",
    ),
    sender: str = typer.Option("", "--sender", "-s", help="Sender email address"),
):
    """
    Analyze an offer letter for fake/fraudulent indicators.

    Checks for: SSN fields on offer, offer conditioned on SSN, free email
    domains, missing physical address, urgency pressure, and absence of
    proper eApp process references.

    Examples:
      fraud-check verify-offer offer_letter.txt
      fraud-check verify-offer offer_letter.txt --sender "hr@gmail.com"
    """
    maybe_path = Path(path_or_text)
    if maybe_path.exists() and maybe_path.suffix.lower() in (".txt", ".md", ".pdf"):
        text = maybe_path.read_text(encoding="utf-8", errors="replace")
        source = str(maybe_path)
    else:
        text = path_or_text
        source = "offer letter text"

    analysis = detector.verify_offer_letter(text, sender_email=sender)

    risk_style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": "dim"}.get(
        analysis.overall_risk, "white"
    )
    icon = {"HIGH": "🛑", "MEDIUM": "⚠️", "LOW": "✅", "UNKNOWN": "❓"}.get(analysis.overall_risk, "?")

    console.print(Panel(
        Text(f"{icon}  OFFER LETTER RISK: {analysis.overall_risk}  "
             f"(legitimacy: {analysis.legitimacy_score:.0%})", style=f"bold {risk_style}"),
        title=f"[bold]Offer Letter Analysis: {source}[/bold]",
        border_style=risk_style.split()[-1],
    ))

    if analysis.red_flags:
        table = Table(title="Red Flags", box=box.SIMPLE)
        table.add_column("Field", style="bold red", min_width=22)
        table.add_column("Issue", style="white")
        table.add_column("Rule", style="cyan")
        for f in analysis.red_flags:
            table.add_row(f.field_name, f.message[:80], f.rule or "—")
        console.print(table)

    if analysis.yellow_flags:
        table = Table(title="Cautions", box=box.SIMPLE)
        table.add_column("Field", style="bold yellow", min_width=22)
        table.add_column("Issue", style="white")
        for f in analysis.yellow_flags:
            table.add_row(f.field_name, f.message[:80])
        console.print(table)

    if analysis.green_flags:
        table = Table(title="Legitimate Signals", box=box.SIMPLE)
        table.add_column("Field", style="bold green", min_width=22)
        table.add_column("Finding", style="white")
        for f in analysis.green_flags:
            table.add_row(f.field_name, f.message[:80])
        console.print(table)

    console.print(
        "\n[dim]Remember: SSN only goes into eapp.nbis.mil (NBIS eApp) — "
        "never on a paper/PDF offer letter.[/dim]\n"
    )
    raise typer.Exit(0 if analysis.overall_risk in ("LOW", "UNKNOWN") else 1)


@app.command(name="explain")
def explain_violations(
    patterns: list[str] = typer.Option(
        [],
        "--pattern", "-p",
        help="Fraud pattern name (repeatable). E.g.: --pattern ssn_request",
    ),
    categories: list[str] = typer.Option(
        [],
        "--category", "-c",
        help="Violation category (repeatable). E.g.: --category non_employee_check",
    ),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all known pattern and category names"),
):
    """
    Look up 32 CFR §117.10 citations for detected fraud patterns or violation categories.

    Shows verbatim CFR text, plain-English explanation, correct process,
    what to say to the recruiter/FSO, and which agency to report to.

    Examples:
      fraud-check explain --pattern ssn_request
      fraud-check explain --pattern dod_safe_ssn_channel --pattern clearance_self_attestation_request
      fraud-check explain --category non_employee_check --category cache_building
      fraud-check explain --list
    """
    from .scoring.explainer import PATTERN_TO_CITATION, CATEGORY_TO_CITATION

    if list_all:
        console.print("[bold cyan]Known pattern names:[/bold cyan]")
        for name in sorted(PATTERN_TO_CITATION.keys()):
            cits = ", ".join(PATTERN_TO_CITATION[name])
            console.print(f"  {name:<48} → {cits}")
        console.print("\n[bold cyan]Known category names:[/bold cyan]")
        for name in sorted(CATEGORY_TO_CITATION.keys()):
            cits = ", ".join(CATEGORY_TO_CITATION[name])
            console.print(f"  {name:<48} → {cits}")
        raise typer.Exit(0)

    if not patterns and not categories:
        console.print("[yellow]Provide at least one --pattern or --category, or use --list[/yellow]")
        raise typer.Exit(1)

    report = detector.explain_findings(
        pattern_names=list(patterns) or None,
        category_names=list(categories) or None,
    )

    if not report.explanations:
        console.print("[yellow]No citations found for the provided names.[/yellow]")
        console.print("Use [bold]fraud-check explain --list[/bold] to see all known names.")
        raise typer.Exit(1)

    console.print(Panel(
        Text(f"📖  {len(report.explanations)} CFR Citation(s) Found", style="bold cyan"),
        title="[bold]32 CFR §117.10 Violation Explainer[/bold]",
        border_style="cyan",
    ))

    for i, exp in enumerate(report.explanations, 1):
        console.print(f"\n[bold cyan]{'═' * 60}[/bold cyan]")
        console.print(f"[bold white]VIOLATION {i}: {exp.rule}[/bold white]")
        console.print(f"[blue]{exp.url}[/blue]")
        console.print(f"\n[bold]VERBATIM TEXT:[/bold]\n  [italic]{exp.verbatim[:300]}[/italic]")
        console.print(f"\n[bold]WHAT THIS MEANS:[/bold]\n  {exp.plain_english}")
        console.print(f"\n[bold]CORRECT PROCESS:[/bold]\n  {exp.correct_process}")
        console.print(f"\n[bold green]WHAT TO SAY:[/bold green]\n  {exp.response_script}")
        console.print(f"\n[bold red]REPORT TO:[/bold red] {exp.report_to}")

    if report.reporting_agencies:
        console.print(f"\n[bold cyan]All Applicable Reporting Agencies:[/bold cyan]")
        seen: set[str] = set()
        for agency in report.reporting_agencies:
            if agency not in seen:
                console.print(f"  • {agency}")
                seen.add(agency)
    console.print()
    raise typer.Exit(0)


@app.command(name="generate-report")
def generate_incident_report(
    company: str = typer.Option(..., "--company", "-c", help="Company or recruiter firm name"),
    recruiter: str = typer.Option("", "--recruiter", "-r", help="Recruiter or contact name"),
    violations: list[str] = typer.Option(
        [], "--violation", "-v",
        help="Violation description (repeatable)",
    ),
    interaction: str = typer.Option("", "--interaction", "-i", help="Interaction text or path to .txt file"),
    output: str = typer.Option("text", "--format", "-f", help="Output format: text or markdown"),
    save: str = typer.Option("", "--save", "-o", help="Save report to this file path"),
    ssn_given: bool = typer.Option(
        False, "--ssn-given",
        help="Set if you already provided your SSN — adds identity-theft recovery steps to the guide",
    ),
    steps: bool = typer.Option(
        True, "--steps/--no-steps",
        help="Include step-by-step DCSA/NBIS/FBI submission guide (default: on)",
    ),
):
    """
    Generate a DCSA/FBI-ready incident report for a fraudulent interaction.

    Produces a structured report with timeline, violations, and step-by-step
    instructions for submitting to DCSA, NBIS, FBI, and FTC.

    Examples:
      fraud-check generate-report --company "Mindbank Consulting Group" \\
          --recruiter "[Recruiter Name]" \\
          --violation "Pre-offer SSN request via email" \\
          --violation "SVP reaffirmed violation" \\
          --interaction mindbank_emails.txt

      fraud-check generate-report --company "BadCorp" \\
          --violation "Clearance self-attestation form" \\
          --format markdown --save report.md

      fraud-check generate-report --company "TSCTI" --ssn-given \\
          --violation "SSN provided before written offer" --save incident.txt
    """
    interaction_text = ""
    if interaction:
        maybe_path = Path(interaction)
        if maybe_path.exists():
            interaction_text = maybe_path.read_text(encoding="utf-8", errors="replace")
        else:
            interaction_text = interaction

    inp = IncidentReportInput(
        company_name=company,
        recruiter_name=recruiter or "Unknown",
        violations=list(violations) or ["Undocumented NISPOM §117.10 violation"],
        narrative=interaction_text,
    )
    report = detector.generate_incident_report(inp)

    if output == "markdown":
        rendered = report.render_markdown()
        if steps:
            rendered += "\n\n---\n\n## Step-by-Step Submission Guide\n\n"
            rendered += "```\n" + generate_submission_guide(ssn_compromised=ssn_given) + "\n```"
    else:
        rendered = report.render()
        if steps:
            rendered += "\n\n" + generate_submission_guide(ssn_compromised=ssn_given)

    if save:
        Path(save).write_text(rendered, encoding="utf-8")
        console.print(f"[green]Report saved to: {save}[/green]")
        if steps:
            console.print("[dim]Includes step-by-step DCSA/NBIS/FBI submission guide.[/dim]")
    else:
        console.print(rendered)

    raise typer.Exit(0)


@app.command()
def demo():
    """Run demo analysis on built-in example fraud and clean emails, calls, and job postings."""
    # --- Email examples ---
    email_examples = [
        {
            "label": "FRAUD EMAIL — Fee + SSN + AI voice interview",
            "subject": "Urgent: TS/SCI Position Available — Act Now!!!",
            "sender": "recruiter@dod-careers-hiring.com",
            "body": (
                "Dear Applicant, CONGRATULATIONS!!! You have been SELECTED for a Top Secret/SCI "
                "position. We can GUARANTEE your clearance! Please provide your Social Security Number "
                "and date of birth to begin processing. There is a processing fee of $150 required "
                "upfront. Send payment via Bitcoin or gift card. This is a CONFIDENTIAL opportunity — "
                "do not share. Respond IMMEDIATELY! Contact us on Telegram @cleared_jobs_official for "
                "your audio-only interview. Camera is not required. Camera must be off during interview."
            ),
        },
        {
            "label": "FRAUD EMAIL — DPRK IT worker scheme signals",
            "subject": "Remote TS/SCI Developer Role — $300k — Start Immediately",
            "sender": "hr@defenselinejobs.xyz",
            "body": (
                "Greetings of the day! I am Mr. James from HR department. We are a confidential "
                "government contractor seeking cleared remote developers. TS/SCI, work from home 100%. "
                "Equipment will be shipped to your home address. No background check required for "
                "this expedited hire. Kindly provide your SSN, date of birth, and I-9 prior to "
                "interview. Forward your resume via WhatsApp +1-202-555-0198. "
                "Salary: $300,000/year. Start immediately. No experience required."
            ),
        },
        {
            "label": "LEGITIMATE EMAIL — Real contractor outreach",
            "subject": "Software Engineer (TS/SCI) — Leidos — Chantilly VA",
            "sender": "talent@leidos.com",
            "body": (
                "Hi, I came across your profile on LinkedIn and wanted to reach out about a "
                "cleared software engineer role at Leidos in Chantilly, VA. The position requires "
                "an active TS/SCI with polygraph. Please apply via leidos.com/careers. "
                "The SF-86/EQIP process is sponsored upon offer. No fees required. "
                "In-person interviews at Chantilly office. Happy to answer questions about the "
                "DCSA adjudication and background investigation process."
            ),
        },
    ]

    console.rule("[bold cyan]EMAIL ANALYSIS DEMOS[/bold cyan]")
    for ex in email_examples:
        console.rule(f"[bold]{ex['label']}[/bold]")
        score = detector.analyze_text(ex["body"], subject=ex["subject"], sender=ex["sender"])
        _print_report(score, source=ex["label"])

    # --- Call transcript examples ---
    call_examples = [
        {
            "label": "FRAUD CALL — AI voice + DPRK indicators",
            "transcript": (
                "I spoke with a recruiter named 'John Smith' who claimed to be from Booz Allen. "
                "The voice sounded robotic and artificial — clearly AI-generated voice. "
                "He required camera off during the entire interview, audio only. "
                "He asked me to verify my SSN and date of birth over the phone right now. "
                "He said I was hired on the spot and to complete the I-9 before we hang up. "
                "He told me to contact him only via Telegram @bah_recruiter_john. "
                "He mentioned my laptop would be shipped to a forwarding address."
            ),
        },
        {
            "label": "CLEAN CALL — Legitimate recruiter",
            "transcript": (
                "Spoke with Sarah at Leidos talent acquisition. Normal video call, both cameras on. "
                "She described the TS/SCI software engineer role in Chantilly. "
                "She mentioned the SF-86 process and EQIP system. Discussed polygraph requirements. "
                "HR will send a formal offer via corporate Leidos email. "
                "In-person interview scheduled at the Chantilly office next Tuesday."
            ),
        },
    ]

    console.rule("[bold cyan]CALL TRANSCRIPT ANALYSIS DEMOS[/bold cyan]")
    for ex in call_examples:
        console.rule(f"[bold]{ex['label']}[/bold]")
        analysis = detector.analyze_call_transcript(ex["transcript"])
        _print_vishing_report(analysis, source=ex["label"])

    # --- Job posting examples ---
    job_examples = [
        {
            "label": "FRAUD JOB POSTING — DPRK scheme / PII harvest",
            "text": (
                "Hiring: Remote TS/SCI Full Stack Developer — $400,000/year — No Experience Required\n\n"
                "We are a confidential employer seeking cleared developers. No background check required "
                "for this expedited position. Work fully remote from home. Interview is audio-only, "
                "camera off required. Please include your SSN and date of birth in your application. "
                "Application fee: $50 processing. Laptop will be shipped to your provided address. "
                "We guarantee your TS/SCI clearance. Start immediately. "
                "Apply via Telegram: @cleared_remote_jobs"
            ),
        },
        {
            "label": "LEGITIMATE JOB POSTING — Real defense contractor",
            "text": (
                "Position: Systems Engineer III — Active TS/SCI Required\n"
                "Location: Chantilly, VA (on-site in SCIF)\n"
                "Company: Booz Allen Hamilton (boozallen.com)\n\n"
                "Job Summary: Support intelligence community customer in systems engineering role. "
                "Requires active TS/SCI with full-scope polygraph. 5+ years experience required. "
                "Salary range: $120,000–$160,000 based on experience. "
                "Full benefits, 401k matching. Apply at boozallen.com/careers. "
                "Booz Allen will sponsor clearance reinvestigation if needed after offer."
            ),
        },
    ]

    console.rule("[bold cyan]JOB POSTING ANALYSIS DEMOS[/bold cyan]")
    for ex in job_examples:
        console.rule(f"[bold]{ex['label']}[/bold]")
        analysis = detector.analyze_job_posting(ex["text"])
        _print_job_posting_report(analysis, source=ex["label"])


@app.command(name="verify-company")
def verify_company(
    name: str = typer.Argument(..., help="Company name to look up (full or partial)"),
    show_contacts: bool = typer.Option(False, "--contacts", "-c", help="Show contact details"),
):
    """
    Look up a company in the verified cleared contractor registry.

    Cross-references SAM.gov UEI, CAGE code, GSA contract, certifications,
    and known address against the built-in verified database.

    Examples:
      fraud-check verify-company "Marathon TS"
      fraud-check verify-company "Mindbank" --contacts
      fraud-check verify-company "Kforce"
    """
    name_lower = name.lower()

    # Try exact match first, then partial
    match_key = None
    for key in VERIFIED_CONTRACTORS:
        if name_lower == key.lower():
            match_key = key
            break
    if not match_key:
        for key in VERIFIED_CONTRACTORS:
            if name_lower in key.lower() or key.lower() in name_lower:
                match_key = key
                break
    # Also try against LEGITIMATE_CONTRACTORS for a softer hit
    legit_match = None
    if not match_key:
        for key in LEGITIMATE_CONTRACTORS:
            if name_lower in key.lower() or key.lower() in name_lower:
                legit_match = key
                break

    if match_key:
        info = VERIFIED_CONTRACTORS[match_key]
        console.print(Panel(
            Text(f"✅  VERIFIED LEGITIMATE CONTRACTOR", style="bold green"),
            title=f"[bold]{match_key}[/bold]",
            border_style="green",
        ))
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("Field", style="cyan", min_width=22)
        t.add_column("Value", style="white")
        t.add_row("Legal Name", info.get("legal_name", "—"))
        t.add_row("SAM UEI", info.get("uei", "—"))
        t.add_row("CAGE Code", info.get("cage", "—"))
        t.add_row("DUNS", info.get("duns", "—"))
        t.add_row("Registered Address", info.get("address", "—"))
        t.add_row("Published Phone", info.get("phone", "—"))
        t.add_row("Email Domain", "@" + info.get("email_domain", "—"))
        t.add_row("GSA Contract", info.get("gsa_contract", "—"))
        t.add_row("GSA Contract End", info.get("gsa_ultimate_end", info.get("gsa_contract_end", "—")))
        if info.get("founded"):
            t.add_row("Founded", str(info["founded"]))
        if info.get("certifications"):
            t.add_row("Certifications", "\n".join(info["certifications"]))
        if info.get("offices"):
            t.add_row("Offices", ", ".join(info["offices"]))
        t.add_row("Services", info.get("services", "—"))
        if info.get("federal_awards_total"):
            t.add_row("Federal Awards", info["federal_awards_total"])
        t.add_row("Verified Via", ", ".join(info.get("verified_sources", [])))
        console.print(t)

        if info.get("clients"):
            console.print("[bold cyan]Known Federal Clients:[/bold cyan]")
            for c in (info["clients"] if isinstance(info["clients"], list) else [info["clients"]]):
                console.print(f"  • {c}")

        if show_contacts and info.get("contacts"):
            console.print("\n[bold cyan]Published Contacts:[/bold cyan]")
            for role, contact in info["contacts"].items():
                console.print(f"  [{role}] {contact}")

        if info.get("note"):
            console.print(f"\n[bold yellow]Note:[/bold yellow] {info['note']}")

        console.print()
        console.print(
            "[dim]Always verify independently: "
            "sam.gov/search · gsaelibrary.gsa.gov · highergov.com[/dim]"
        )
        raise typer.Exit(0)

    elif legit_match:
        console.print(Panel(
            Text(f"⚠️  IN KNOWN CONTRACTOR LIST — No detailed record yet", style="bold yellow"),
            title=f"[bold]{legit_match}[/bold]",
            border_style="yellow",
        ))
        console.print(f"  Domains: {', '.join(LEGITIMATE_CONTRACTORS[legit_match])}")
        console.print("\n  This company is in the known legitimate contractors list but does not")
        console.print("  yet have a full verified record. Cross-check at:")
        console.print("  • sam.gov/search")
        console.print("  • gsaelibrary.gsa.gov")
        console.print("  • highergov.com")
        raise typer.Exit(0)

    else:
        console.print(Panel(
            Text(f"❓  NOT IN VERIFIED DATABASE", style="bold red"),
            title=f"[bold]Unknown: {name}[/bold]",
            border_style="red",
        ))
        console.print("  This company is not in the local verified database.")
        console.print("  Verify manually at these official sources:\n")
        sources = [
            ("SAM.gov Entity Search",         "https://sam.gov/search/?index=entity"),
            ("GSA eLibrary",                  "https://gsaelibrary.gsa.gov"),
            ("USASpending.gov",               "https://usaspending.gov/search"),
            ("HigherGov",                     "https://highergov.com/awardee/"),
            ("CAGE Code Lookup",              "https://cage.report"),
            ("Virginia SCC Business Search",  "https://cis.scc.virginia.gov"),
        ]
        t2 = Table(box=box.SIMPLE, show_header=False)
        t2.add_column("Source", style="cyan")
        t2.add_column("URL", style="blue")
        for src, url in sources:
            t2.add_row(src, url)
        console.print(t2)
        raise typer.Exit(1)


@app.command(name="report-fraud")
def report_fraud(
    fraud_type: str = typer.Option(
        "",
        "--type", "-t",
        help=(
            "Fraud type filter. Options: ssn_stolen, identity_theft, fake_fso, "
            "fake_recruiter, job_fraud, dprk_scheme, phishing, credit_fraud, "
            "clearance_fraud, foreign_contact"
        ),
    ),
    ssn_given: bool = typer.Option(
        False, "--ssn-given",
        help="Set this flag if you already provided your SSN — shows immediate action checklist"
    ),
):
    """
    Show who to report clearance job fraud to — official agencies, phone numbers, and forms.

    Filter by fraud type or show all agencies. Use --ssn-given if you already
    provided your SSN for the immediate response checklist.

    Examples:
      fraud-check report-fraud
      fraud-check report-fraud --type fake_fso
      fraud-check report-fraud --type ssn_stolen --ssn-given
      fraud-check report-fraud --type dprk_scheme
    """
    if ssn_given:
        console.print(Panel(
            Text("🚨  YOU PROVIDED YOUR SSN — TAKE THESE STEPS IMMEDIATELY", style="bold red"),
            border_style="red",
        ))
        for step in IMMEDIATE_SSN_STOLEN_ACTIONS:
            console.print(f"  {step}")
        console.print()

    # Filter agencies
    if fraud_type:
        from .reporting import FRAUD_TYPE_TO_AGENCIES, get_all_fraud_types
        if fraud_type not in FRAUD_TYPE_TO_AGENCIES:
            valid = ", ".join(get_all_fraud_types())
            console.print(f"[red]Unknown fraud type '{fraud_type}'.[/red]")
            console.print(f"Valid types: {valid}")
            raise typer.Exit(1)
        agencies = FRAUD_TYPE_TO_AGENCIES[fraud_type]
        title = f"Reporting Agencies — {fraud_type.replace('_', ' ').title()}"
    else:
        agencies = REPORTING_AGENCIES
        title = "All Fraud Reporting Agencies"

    console.print(Panel(
        Text(f"📋  {title}", style="bold cyan"),
        border_style="cyan",
    ))

    # Group by priority
    by_priority: dict[int, list] = {}
    for agency in agencies:
        by_priority.setdefault(agency.priority, []).append(agency)

    priority_labels = {1: "🔴 CRITICAL — Contact First", 2: "🟠 Secondary", 3: "🟢 Supplemental"}

    for priority in sorted(by_priority.keys()):
        console.print(f"\n[bold]{priority_labels.get(priority, f'Priority {priority}')}[/bold]")
        t = Table(box=box.SIMPLE, show_header=True)
        t.add_column("Agency", style="bold white", min_width=32)
        t.add_column("Phone", style="cyan", min_width=18)
        t.add_column("Online Form / URL", style="blue", min_width=35)
        t.add_column("Handles", style="dim")
        for ag in by_priority[priority]:
            t.add_row(
                ag.name,
                ag.phone or "—",
                ag.form_url or ag.url,
                ag.handles,
            )
        console.print(t)

        # Print notes for critical agencies
        if priority == 1:
            for ag in by_priority[priority]:
                if ag.notes:
                    console.print(f"  [dim]{ag.name}:[/dim] {ag.notes}")

    console.print()
    console.print(
        "[bold yellow]How to verify a recruiter or company before engaging:[/bold yellow]\n"
        "  • sam.gov/search — confirm active SAM registration\n"
        "  • gsaelibrary.gsa.gov — confirm active GSA contract\n"
        "  • fraud-check verify-company \"Company Name\" — built-in verified database\n"
        "  • fraud-check scan-number \"phone number\" — check a caller's phone number\n"
        "  • fraud-check scan-contact \"message text\" — analyze a recruiter or FSO message\n"
        "  • fraud-check scan-job \"posting text\" — analyze a suspicious job posting\n"
    )
    console.print(
        "[bold cyan]Generate a full DCSA/NBIS/FBI-ready incident report:[/bold cyan]\n"
        "  fraud-check generate-report --company \"Company Name\" "
        "--violation \"what was requested\"\n"
        "  Add [bold]--ssn-given[/bold] if you already provided your SSN — "
        "adds identity-theft recovery steps.\n"
        "\n"
        "[bold cyan]NBIS contacts (if background investigation process was abused):[/bold cyan]\n"
        "  Industry/FSO Contact Center: (878) 274-1765\n"
        "    dcsa.ncr.nbis.mbx.contact-center@mail.mil\n"
        "    https://www.dcsa.mil/Systems-Applications/National-Background-Investigation-Services-NBIS/\n"
        "  NBIS Agency Support (FSOs/SSOs): (878) 274-5080\n"
        "    dcsa.boyers.nbis.mbx.nbis-agency-support@mail.mil\n"
        "  Applicant eApp portal (the ONLY authorized SSN submission channel):\n"
        "    https://eapp.nbis.mil\n"
    )


# ---------------------------------------------------------------------------
# Workforce mapping renderer
# ---------------------------------------------------------------------------

_WM_VERDICT_COLORS = {
    "CLEAN": "green",
    "COMMERCIAL_HARVEST": "yellow",
    "CI_RISK": "red",
    "CONFIRMED_COLLECTION": "bold red",
}

_WM_VERDICT_ICONS = {
    "CLEAN": "✅",
    "COMMERCIAL_HARVEST": "⚠️",
    "CI_RISK": "🚨",
    "CONFIRMED_COLLECTION": "🛑",
}

_WM_VERDICT_LABELS = {
    "CLEAN": "CLEAN — No CI collection indicators",
    "COMMERCIAL_HARVEST": "COMMERCIAL HARVEST — Resume/data collection risk",
    "CI_RISK": "CI RISK — Likely intelligence collection attempt",
    "CONFIRMED_COLLECTION": "CONFIRMED CI COLLECTION — Report to FSO immediately",
}


def _print_workforce_report(analysis, source: str = "") -> None:
    """Print workforce mapping / CI collection analysis results."""
    v = analysis.verdict.value
    color = _WM_VERDICT_COLORS.get(v, "white")
    icon = _WM_VERDICT_ICONS.get(v, "?")
    label = _WM_VERDICT_LABELS.get(v, v)

    verdict_text = Text(f"{icon}  {label}  (risk: {analysis.risk_score:.3f})", style=f"bold {color}")
    ci_note = "  ⚑ CI-REPORTABLE to FSO" if analysis.is_ci_reportable else ""
    console.print(Panel(
        verdict_text,
        subtitle=ci_note or None,
        title=f"[bold]Workforce Mapping / CI Collection Analysis{f': {source}' if source else ''}[/bold]",
        border_style=color.split()[-1],
    ))

    if analysis.signals:
        table = Table(title="Collection Signals Detected", box=box.SIMPLE, show_header=True)
        table.add_column("Severity", style="bold", min_width=10)
        table.add_column("Category", style="cyan", min_width=22)
        table.add_column("Signal", style="white")
        for sig in sorted(analysis.signals, key=lambda s: s.weight, reverse=True):
            sev_style = _RISK_COLORS.get(sig.severity, "white")
            table.add_row(
                Text(sig.severity.upper(), style=sev_style),
                sig.category,
                sig.description,
            )
        console.print(table)

        console.print("\n[bold yellow]Signal Details:[/bold yellow]")
        for i, sig in enumerate(sorted(analysis.signals, key=lambda s: s.weight, reverse=True), 1):
            sev_style = _RISK_COLORS.get(sig.severity, "white")
            console.print(f"  {i}. [{sev_style}][{sig.severity.upper()}][/{sev_style}] {sig.description}")
            if sig.detail:
                console.print(f"     {sig.detail}")

    if analysis.collection_vectors:
        console.print("\n[bold red]Collection Vectors:[/bold red]")
        for vec in analysis.collection_vectors:
            console.print(f"  • {vec}")

    if analysis.fbi_indicator_matches:
        console.print("\n[bold red]FBI 'Think Before You Link' Indicators:[/bold red]")
        for match in analysis.fbi_indicator_matches:
            console.print(f"  ⚑ {match}")

    if not analysis.has_named_company:
        console.print("\n[yellow]⚠️  Anonymous client — cleared positions from nameless clients expose you to mapping.[/yellow]")
    if not analysis.has_requisition:
        console.print("[yellow]⚠️  No requisition number — real cleared billets have contract-tied req numbers.[/yellow]")

    if analysis.recommendations:
        console.print("\n[bold cyan]Recommendations:[/bold cyan]")
        for rec in analysis.recommendations:
            console.print(f"  → {rec}")

    if analysis.is_ci_reportable:
        console.print(Panel(
            Text(
                "⚑  Report this contact to your FSO (Facility Security Officer).\n"
                "   SEAD 3 requires reporting suspicious contact from foreign nationals or\n"
                "   contacts that appear to solicit classified or sensitive information.\n"
                "   DCSA CI: 571-305-6576 | dcsacounterfraud@mail.mil | dcsa.mil/MC/CI/",
                style="bold red",
            ),
            border_style="red",
        ))

    console.print()


@app.command(name="scan-workforce")
def scan_workforce(
    message: str = typer.Argument(
        ...,
        help="Recruiter/contact message text, or path to a .txt file",
    ),
    sender: str = typer.Option("", "--sender", "-s", help="Sender email address"),
    subject: str = typer.Option("", "--subject", "-t", help="Message subject line"),
    channel: str = typer.Option(
        "email",
        "--channel", "-c",
        help="How contact arrived: email, linkedin, clearancejobs, phone, telegram, whatsapp, signal",
    ),
):
    """
    Analyze a recruiter message for workforce mapping / CI collection patterns.

    This is distinct from fraud detection: the message may come from a real company
    with a legitimate domain yet still serve intelligence collection objectives —
    mapping active cleared professionals, building resume databases of program access
    history, or harvesting the social graph of cleared networks.

    Based on FBI 'Think Before You Link' advisory and DCSA SEAD 3 reporting guidance.

    Examples:
      fraud-check scan-workforce "What programs have you supported? Who are your cleared references?"
      fraud-check scan-workforce outreach.txt --sender "recruiter@consulting.com" --channel linkedin
    """
    maybe_path = Path(message)
    if maybe_path.exists() and maybe_path.suffix.lower() in (".txt", ".md", ".log"):
        message = maybe_path.read_text(encoding="utf-8", errors="replace")

    analysis = detector.analyze_workforce_mapping(
        message,
        sender=sender,
        subject=subject,
        contact_channel=channel,
    )
    _print_workforce_report(analysis, source="workforce mapping scan")
    raise typer.Exit(1 if analysis.is_ci_reportable else 0)


@app.command(name="scan-all")
def scan_all(
    message: str = typer.Argument(
        ...,
        help="Message body text, or path to a .txt / .eml file",
    ),
    subject: str = typer.Option("", "--subject", "-t", help="Message subject"),
    sender: str = typer.Option("", "--sender", "-s", help="Sender email address"),
    channel: str = typer.Option(
        "email",
        "--channel", "-c",
        help="Contact channel: email, linkedin, clearancejobs, phone, telegram, whatsapp, signal",
    ),
):
    """
    Full unified analysis — fraud detection + workforce mapping + NISPOM compliance
    in a single pass.

    Produces a combined risk score that integrates:
      • Email fraud signals (rule engine + domain + NLP)
      • Workforce mapping / CI collection patterns (FBI advisory)
      • NISPOM §117.10 regulatory compliance violations

    Use this command when you want the complete threat picture for a single message.

    Examples:
      fraud-check scan-all "Our FSO needs your SSN to verify clearance before we extend an offer."
      fraud-check scan-all outreach.txt --sender "hr@anonymous.com" --channel linkedin
      fraud-check scan-all suspicious_email.eml
    """
    # Accept .eml files directly
    maybe_path = Path(message)
    if maybe_path.exists():
        if maybe_path.suffix.lower() == ".eml":
            # For .eml we run all three layers manually and build a FullAnalysis
            from .analyzers.nispom_compliance import check_compliance as _cc
            from .analyzers.workforce_mapping_analyzer import analyze_workforce_mapping as _awm
            from .parsers.email_parser import parse_eml_file as _pef
            from .detector import FullAnalysis
            doc = _pef(maybe_path)
            fraud_score = detector.analyze_document(doc)
            wm = _awm(doc.full_text, sender=doc.sender, subject=doc.subject, contact_channel=channel)
            compliance = _cc(doc.full_text)
            # Reuse analyze_all logic via the detector method
            result = detector.analyze_all(
                text=doc.full_text,
                subject=doc.subject,
                sender=doc.sender,
                contact_channel=channel,
            )
        elif maybe_path.suffix.lower() in (".txt", ".md", ".log"):
            message = maybe_path.read_text(encoding="utf-8", errors="replace")
            result = detector.analyze_all(
                text=message, subject=subject, sender=sender, contact_channel=channel
            )
        else:
            console.print(f"[red]Unsupported file type: {maybe_path.suffix}[/red]")
            raise typer.Exit(1)
    else:
        result = detector.analyze_all(
            text=message, subject=subject, sender=sender, contact_channel=channel
        )

    # ---- Combined risk header ----
    if result.combined_risk >= 0.70:
        combined_color, combined_icon = "bold red", "🛑"
    elif result.combined_risk >= 0.45:
        combined_color, combined_icon = "red", "🚨"
    elif result.combined_risk >= 0.20:
        combined_color, combined_icon = "yellow", "⚠️"
    else:
        combined_color, combined_icon = "green", "✅"

    console.print(Panel(
        Text(
            f"{combined_icon}  {result.combined_verdict}\n"
            f"    Combined risk: {result.combined_risk:.3f}  |  "
            f"Fraud score: {result.fraud_score.total_score:.3f}  |  "
            f"CI reportable: {'YES ⚑' if result.is_ci_reportable else 'no'}",
            style=f"bold {combined_color}",
        ),
        title="[bold]Unified Threat Analysis — All Layers[/bold]",
        border_style=combined_color.split()[-1],
    ))

    # ---- Top signals ----
    if result.top_signals:
        console.print("\n[bold yellow]Top Signals Across All Layers:[/bold yellow]")
        for i, sig in enumerate(result.top_signals, 1):
            console.print(f"  {i}. {sig}")

    # ---- Fraud score detail ----
    console.rule("[bold]Layer 1 — Email Fraud Analysis[/bold]")
    _print_report(result.fraud_score, source="fraud layer")

    # ---- Workforce mapping detail ----
    console.rule("[bold]Layer 2 — Workforce Mapping / CI Collection[/bold]")
    _print_workforce_report(result.workforce_mapping, source="CI layer")

    # ---- NISPOM compliance detail ----
    console.rule("[bold]Layer 3 — NISPOM §117.10 Compliance[/bold]")
    if result.compliance.has_violations:
        for i, v in enumerate(result.compliance.violations, 1):
            sev_color = {"critical": "bold red", "high": "red", "medium": "yellow"}.get(
                v.severity, "white"
            )
            console.print(f"[{sev_color}]  Violation {i}: {v.rule} [{v.severity.upper()}][/{sev_color}]")
            console.print(f"    {v.what_violated}")
    else:
        console.print("[green]  ✅  No NISPOM §117.10 violations detected[/green]")

    console.print()
    exit_code = 1 if result.is_high_risk or result.is_ci_reportable else 0
    raise typer.Exit(exit_code)

