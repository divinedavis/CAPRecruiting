#!/usr/bin/env python3
"""
Daily cron script: notifies and downgrades in-person payment users whose membership expires.
Run daily at 9am: 0 9 * * * /home/recruiting/bearcats/venv/bin/python3 /home/recruiting/bearcats/expire_in_person.py
"""
import sys
import os
sys.path.insert(0, '/home/recruiting/bearcats')

from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:////home/recruiting/bearcats/recruiting.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)

SMTP_HOST     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SITE_URL      = os.environ.get("SITE_URL", "https://bearcatrecruiting.com")


def send_renewal_email(to_email: str, username: str):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Bearcats Recruiting membership needs to be renewed"
    msg["From"] = f"Collegiate Athletic Planning <{SMTP_USER}>"
    msg["To"] = to_email
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;">
      <img src="{SITE_URL}/static/cap-logo.png" alt="CAP" style="height:50px;margin-bottom:24px;">
      <h2 style="color:#0a1628;">Time to Renew Your Membership</h2>
      <p>Hi {username},</p>
      <p>Your Collegiate Athletic Planning Essentials membership, which was activated via in-person registration, has expired today.</p>
      <p>To continue being visible to college coaches and accessing all Essentials features, please renew your membership.</p>
      <p style="margin:28px 0;">
        <a href="{SITE_URL}/upgrade" style="background:#0a1628;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;">Renew My Membership</a>
      </p>
      <p style="color:#6b7280;font-size:13px;">If you have any questions, reply to this email or contact your recruiter.</p>
    </div>"""
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())
        print(f"  Renewal email sent to {to_email}")
    except Exception as e:
        print(f"  Email error for {to_email}: {e}")


def run():
    db = Session()
    try:
        now = datetime.utcnow()
        # Find users whose in-person membership expires today or earlier, still on essentials
        from sqlalchemy import text
        expired_users = db.execute(text(
            "SELECT id, username, email, subscription_tier, in_person_paid_until "
            "FROM users "
            "WHERE in_person_paid_until IS NOT NULL "
            "AND in_person_paid_until <= :now "
            "AND subscription_tier = 'essentials'"
        ), {"now": now}).fetchall()

        if not expired_users:
            print(f"[{now.date()}] No expired in-person memberships.")
            return

        print(f"[{now.date()}] Found {len(expired_users)} expired in-person membership(s):")
        for row in expired_users:
            user_id, username, email, tier, paid_until = row
            print(f"  User {user_id} ({username}) — expired {paid_until}")
            # Send renewal notification email
            if email:
                send_renewal_email(email, username)
            # Downgrade to free and clear the in_person_paid_until marker
            db.execute(text(
                "UPDATE users SET subscription_tier='free', in_person_paid_until=NULL WHERE id=:uid"
            ), {"uid": user_id})
            print(f"  Downgraded {username} to free tier")

        db.commit()
        print("Done.")
    finally:
        db.close()


if __name__ == "__main__":
    run()
