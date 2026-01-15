import httpx
from typing import Optional
from config import settings


class EmailService:
    API_URL = "https://api.resend.com/emails"

    async def send_verification(self, email: str, code: str) -> tuple[bool, Optional[str]]:
        # Dev mode: print to console
        if not settings.RESEND_API_KEY or settings.ENVIRONMENT == "development":
            print(f"\n{'='*50}")
            print(f"  TRACE VERIFICATION CODE")
            print(f"  Email: {email}")
            print(f"  Code:  {code}")
            print(f"{'='*50}\n")
            return True, None

        html = f"""
        <div style="background:#0a0a0a;color:#e0e0e0;font-family:monospace;padding:30px;max-width:500px;">
            <pre style="color:#00ffff;margin:0 0 20px 0;">
▀█▀ █▀█ ▄▀█ █▀▀ █▀▀
 █  █▀▄ █▀█ █▄▄ ██▄
            </pre>
            <p style="margin:0 0 10px 0;">Your verification code:</p>
            <div style="font-size:32px;letter-spacing:8px;color:#00ffff;padding:20px;background:#111;text-align:center;border:1px solid #333;">
                {code}
            </div>
            <p style="color:#666;margin:20px 0 0 0;font-size:12px;">
                Expires in 5 minutes. If you didn't request this, ignore this email.
            </p>
        </div>
        """

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self.API_URL,
                    headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}"},
                    json={
                        "from": settings.EMAIL_FROM,
                        "to": [email],
                        "subject": f"TRACE Verification: {code}",
                        "html": html,
                    },
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    return True, None
                return False, f"Email failed: {resp.status_code}"
        except Exception as e:
            return False, str(e)


email_service = EmailService()
