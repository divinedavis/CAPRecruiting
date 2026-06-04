#!/usr/bin/env python3
"""
CAPRecruiting — Paying Members report generator.

Produces a styled PDF of all paid/upgraded accounts, grouped by how they pay:
  - Stripe (online card subscription)   -> payment plan looked up live from Stripe
  - In-person payment (redeemed token)  -> Paid in full (annual)
  - Manually granted / upgraded         -> no recorded payment method

Adds a PAYMENT PLAN column showing whether each member pays Monthly or Paid in full.

Usage:
  python3 payments_report.py [--out /path/report.pdf] [--email a@b.com,c@d.com]

SMTP + Stripe creds come from the bearcats .env (same vars main.py uses).
"""
import os
import sys
import sqlite3
import argparse
from datetime import datetime, timezone

import stripe
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable, KeepTogether,
)

DB_PATH = os.environ.get("RECRUITING_DB", "/home/recruiting/bearcats/recruiting.db")

# ── palette (matches the web report) ────────────────────────────────────────
NAVY   = colors.HexColor("#0a1628")
RED    = colors.HexColor("#c0392b")
GOLD   = colors.HexColor("#c79a3a")
GRAY   = colors.HexColor("#6b7280")
LIGHT  = colors.HexColor("#f6f7f9")
LINE   = colors.HexColor("#e5e7eb")

TIER_BG = {
    "premium":    colors.HexColor("#fdeccb"),
    "essentials": colors.HexColor("#d6f3e0"),
    "advanced":   colors.HexColor("#d6e6fb"),
}
TIER_FG = {
    "premium":    colors.HexColor("#8a6d1f"),
    "essentials": colors.HexColor("#1f7a45"),
    "advanced":   colors.HexColor("#1c5fb0"),
}

# ── paragraph styles ─────────────────────────────────────────────────────────
ST_SUB    = ParagraphStyle("sub", fontName="Helvetica", fontSize=8.5, textColor=GRAY, leading=12)
ST_SECT   = ParagraphStyle("sect", fontName="Helvetica-Bold", fontSize=12, textColor=NAVY, leading=15)
ST_NOTE   = ParagraphStyle("note", fontName="Helvetica", fontSize=7.5, textColor=GRAY, leading=10)
ST_CELL   = ParagraphStyle("cell", fontName="Helvetica", fontSize=7.5, textColor=NAVY, leading=9)
ST_HEAD   = ParagraphStyle("head", fontName="Helvetica-Bold", fontSize=6.5, textColor=GRAY, leading=8)
ST_STATN  = ParagraphStyle("statn", fontName="Helvetica-Bold", fontSize=22, textColor=NAVY, leading=24)
ST_STATL  = ParagraphStyle("statl", fontName="Helvetica", fontSize=7, textColor=GRAY, leading=9)


def tier_pill(tier):
    bg = TIER_BG.get(tier)
    fg = TIER_FG.get(tier, NAVY)
    if not bg:
        return Paragraph(tier or "", ST_CELL)
    style = ParagraphStyle(
        "pill_" + tier, fontName="Helvetica-Bold", fontSize=6.5, textColor=fg,
        backColor=bg, alignment=TA_CENTER, leading=11, borderPadding=(2, 3, 2, 3),
    )
    return Paragraph(tier, style)


def fmt_date(val):
    if not val:
        return ""
    s = str(val)
    return s[:10]


def get_plan_for_stripe(sub_id):
    """Return ('Monthly'|'Paid in full (annual)'|..., status) from live Stripe."""
    try:
        s = stripe.Subscription.retrieve(sub_id)
        price = s["items"]["data"][0]["price"]
        rec = price.get("recurring") or {}
        interval = rec.get("interval")
        label = {"month": "Monthly", "week": "Weekly",
                 "year": "Paid in full (annual)"}.get(interval, interval or "Subscription")
        return label, s.get("status", "")
    except Exception as e:
        sys.stderr.write(f"  Stripe lookup failed for {sub_id}: {e}\n")
        return "Subscription", ""


def load_data(con):
    con.row_factory = sqlite3.Row
    paid_tiers = ("essentials", "advanced", "premium")

    stripe_rows = con.execute(
        "SELECT id, username, email, subscription_tier, created_at, stripe_subscription_id "
        "FROM users WHERE stripe_subscription_id IS NOT NULL AND stripe_subscription_id != '' "
        "ORDER BY id"
    ).fetchall()

    inperson_rows = con.execute(
        "SELECT u.id, u.username, u.email, u.subscription_tier, u.created_at, u.in_person_paid_until, "
        "  (SELECT MAX(t.used_at) FROM in_person_payment_tokens t "
        "     WHERE t.user_id = u.id AND t.used_at IS NOT NULL) AS token_used "
        "FROM users u "
        "WHERE (u.stripe_subscription_id IS NULL OR u.stripe_subscription_id = '') "
        "  AND u.in_person_paid_until IS NOT NULL ORDER BY u.id"
    ).fetchall()

    manual_rows = con.execute(
        "SELECT id, username, email, subscription_tier, created_at "
        "FROM users WHERE (stripe_subscription_id IS NULL OR stripe_subscription_id = '') "
        "  AND in_person_paid_until IS NULL AND subscription_tier IN (?, ?, ?) ORDER BY id",
        paid_tiers,
    ).fetchall()
    return stripe_rows, inperson_rows, manual_rows


def stat_card(number, label):
    inner = Table([[Paragraph(str(number), ST_STATN)], [Paragraph(label, ST_STATL)]],
                  colWidths=[1.55 * inch])
    inner.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.75, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (0, 0), 9),
        ("BOTTOMPADDING", (0, 0), (0, 0), 1),
        ("TOPPADDING", (0, 1), (0, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return inner


def section_header(title, count):
    return [
        Spacer(1, 14),
        Paragraph(f'{title} <font size=8 color="#6b7280">({count})</font>', ST_SECT),
        Spacer(1, 3),
        HRFlowable(width="100%", thickness=1.4, color=GOLD, spaceAfter=2),
    ]


def data_table(headers, rows, col_widths):
    head_cells = [Paragraph(h, ST_HEAD) for h in headers]
    table_data = [head_cells] + rows
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, LINE),
        ("LINEBELOW", (0, -1), (-1, -1), 0.75, LINE),
    ]
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
    t.setStyle(TableStyle(style))
    return t


def build_pdf(out_path, stripe_rows, inperson_rows, manual_rows, plan_map):
    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        leftMargin=0.55 * inch, rightMargin=0.55 * inch,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        title="CAPRecruiting — Paying Members",
    )
    flow = []

    # title
    title = Paragraph(
        '<font color="#0a1628"><b>CAP</b></font>'
        '<font color="#c0392b"><b>Recruiting</b></font>'
        '<font color="#0a1628"><b> — Paying Members</b></font>',
        ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20, leading=24),
    )
    flow.append(title)
    today = datetime.now(timezone.utc).strftime("%B %-d, %Y")
    flow.append(Paragraph(
        f"Subscription &amp; payment report · generated {today} · source: recruiting.db (live)", ST_SUB))
    flow.append(Spacer(1, 12))

    total = len(stripe_rows) + len(inperson_rows) + len(manual_rows)
    cards = Table([[
        stat_card(total, "TOTAL PAID/UPGRADED ACCOUNTS"),
        stat_card(len(stripe_rows), "STRIPE (ONLINE CARD)"),
        stat_card(len(inperson_rows), "IN-PERSON PAYMENT"),
        stat_card(len(manual_rows), "MANUALLY GRANTED"),
    ]], colWidths=[1.73 * inch] * 4)
    cards.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    flow.append(cards)

    # ── Stripe ───────────────────────────────────────────────────────────────
    flow += section_header("Stripe — online card subscription", len(stripe_rows))
    rows = []
    for r in stripe_rows:
        plan = plan_map.get(r["stripe_subscription_id"], "Subscription")
        rows.append([
            Paragraph(str(r["id"]), ST_CELL), Paragraph(r["username"] or "", ST_CELL),
            Paragraph(r["email"] or "", ST_CELL), tier_pill(r["subscription_tier"]),
            Paragraph(plan, ST_CELL), Paragraph(fmt_date(r["created_at"]), ST_CELL),
        ])
    flow.append(data_table(
        ["#", "USERNAME", "EMAIL", "TIER", "PAYMENT PLAN", "SIGNED UP"], rows,
        [0.32 * inch, 1.25 * inch, 2.3 * inch, 0.85 * inch, 1.45 * inch, 0.95 * inch]))
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(
        "Have an active <font name='Courier'>stripe_subscription_id</font>; payment plan is read "
        "live from Stripe (monthly vs. annual). <b>test6</b> is an internal test account.", ST_NOTE))

    # ── In-person ──────────────────────────────────────────────────────────────
    flow += section_header("In-person payment", len(inperson_rows))
    rows = []
    for r in inperson_rows:
        paid_date = fmt_date(r["token_used"]) or fmt_date(r["created_at"])
        rows.append([
            Paragraph(str(r["id"]), ST_CELL), Paragraph(r["username"] or "", ST_CELL),
            Paragraph(r["email"] or "", ST_CELL), tier_pill(r["subscription_tier"]),
            Paragraph("Paid in full", ST_CELL), Paragraph(paid_date, ST_CELL),
            Paragraph(fmt_date(r["in_person_paid_until"]), ST_CELL),
        ])
    flow.append(data_table(
        ["#", "USERNAME", "EMAIL", "TIER", "PAYMENT PLAN", "PAID (TOKEN)", "PAID UNTIL"], rows,
        [0.3 * inch, 1.15 * inch, 2.0 * inch, 0.8 * inch, 1.1 * inch, 0.9 * inch, 0.9 * inch]))
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(
        "Paid in full for one year via a redeemed payment token; access set through "
        "<font name='Courier'>in_person_paid_until</font>.", ST_NOTE))

    # ── Manual ──────────────────────────────────────────────────────────────────
    flow += section_header("Manually granted / upgraded", len(manual_rows))
    rows = []
    for r in manual_rows:
        rows.append([
            Paragraph(str(r["id"]), ST_CELL), Paragraph(r["username"] or "", ST_CELL),
            Paragraph(r["email"] or "", ST_CELL), tier_pill(r["subscription_tier"]),
            Paragraph("—", ST_CELL), Paragraph(fmt_date(r["created_at"]), ST_CELL),
        ])
    flow.append(data_table(
        ["#", "USERNAME", "EMAIL", "TIER", "PAYMENT PLAN", "CREATED"], rows,
        [0.32 * inch, 1.25 * inch, 2.3 * inch, 0.85 * inch, 1.45 * inch, 0.95 * inch]))
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(
        "No Stripe subscription and no in-person token on file — early sign-ups / admin grants "
        "(no recorded payment method, so no payment plan). "
        "<b>playerben@caprecruiting.com</b> is an internal account.", ST_NOTE))

    flow.append(Spacer(1, 16))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=LINE, spaceAfter=4))
    flow.append(Paragraph(
        "CAPRecruiting · recruiting.db on 167.71.170.219 · Payment method inferred from "
        "<font name='Courier'>stripe_subscription_id</font>, "
        "<font name='Courier'>in_person_paid_until</font>, and "
        "<font name='Courier'>subscription_tier</font>; payment plan (monthly vs. paid in full) "
        "from the live Stripe billing interval and the annual in-person token. "
        "Dollar amounts are not stored in the app DB — for exact charges/payouts see the Stripe dashboard.",
        ST_NOTE))

    doc.build(flow)


def send_email(recipients, pdf_path):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.application import MIMEApplication

    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    pwd  = os.environ.get("SMTP_PASSWORD", "")
    today = datetime.now(timezone.utc).strftime("%B %-d, %Y")

    msg = MIMEMultipart()
    msg["Subject"] = f"CAPRecruiting — Paying Members report ({today})"
    msg["From"] = f"Collegiate Athletic Planning <{user}>"
    msg["To"] = ", ".join(recipients)
    body = (
        f"Hi,\n\nAttached is the monthly CAPRecruiting paying-members report "
        f"(generated {today}).\n\nIt now includes a Payment Plan column showing whether each "
        f"member pays monthly or paid in full, alongside how they paid (Stripe card, in-person "
        f"token, or manual grant).\n\n— Collegiate Athletic Planning\n"
    )
    msg.attach(MIMEText(body, "plain"))
    with open(pdf_path, "rb") as f:
        part = MIMEApplication(f.read(), _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename="caprecruiting_payments.pdf")
    msg.attach(part)

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, pwd)
        server.sendmail(user, recipients, msg.as_string())
    print(f"  Emailed report to: {', '.join(recipients)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/home/recruiting/bearcats/caprecruiting_payments.pdf")
    ap.add_argument("--email", default="", help="comma-separated recipient list")
    args = ap.parse_args()

    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    con = sqlite3.connect(DB_PATH)
    stripe_rows, inperson_rows, manual_rows = load_data(con)

    plan_map = {}
    for r in stripe_rows:
        sub_id = r["stripe_subscription_id"]
        plan, status = get_plan_for_stripe(sub_id)
        plan_map[sub_id] = plan

    build_pdf(args.out, stripe_rows, inperson_rows, manual_rows, plan_map)
    print(f"Wrote {args.out}  "
          f"(stripe={len(stripe_rows)}, in_person={len(inperson_rows)}, manual={len(manual_rows)})")

    if args.email:
        recipients = [e.strip() for e in args.email.split(",") if e.strip()]
        if recipients:
            send_email(recipients, args.out)


if __name__ == "__main__":
    main()
