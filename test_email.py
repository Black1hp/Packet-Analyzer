#!/usr/bin/env python3
"""
Test script to verify email sending functionality.
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Email configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "")  # Email should be in .env file
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "")  # Password should be in .env file
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")  # Admin email should be in .env file

def test_email_sending():
    """Test email sending functionality."""
    print(f"Using email configuration:")
    print(f"  SMTP Server: {SMTP_SERVER}")
    print(f"  SMTP Port: {SMTP_PORT}")
    print(f"  Sender Email: {SENDER_EMAIL}")
    print(f"  Admin Email: {ADMIN_EMAIL}")
    
    try:
        # Create message
        msg = MIMEMultipart("alternative")
        msg["From"] = SENDER_EMAIL
        msg["To"] = ADMIN_EMAIL
        msg["Subject"] = "🧪 Network Forensics Email Test"
        
        # Create message body
        text_content = """
        This is a test email from the Network Forensics system.
        
        If you received this email, it means the email sending functionality is working correctly.
        """
        
        html_content = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; }
                .container { max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; }
                .header { background-color: #4CAF50; color: white; padding: 10px; text-align: center; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Network Forensics Email Test</h2>
                </div>
                <div style="padding: 20px;">
                    <p>This is a test email from the Network Forensics system.</p>
                    <p>If you received this email, it means the email sending functionality is working correctly.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Attach text and HTML versions
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))
        
        # Connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.set_debuglevel(1)  # Enable debug output
            print("Starting TLS connection...")
            server.starttls()
            print("Logging in...")
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            print("Sending message...")
            server.send_message(msg)
            print("Email sent successfully!")
            
        return True
        
    except Exception as e:
        print(f"Error sending test email: {e}")
        return False

if __name__ == "__main__":
    test_email_sending()
