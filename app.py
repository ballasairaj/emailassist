import os.path
import base64
import imaplib
import email
from email.header import decode_header
import google.auth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def fetch_emails(creds):
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com')
        auth_string = 'user=%s\1auth=Bearer %s\1\1' % ('sairaj93812@gmail.com', creds.token)
        mail.authenticate('XOAUTH2', lambda x: auth_string)
        mail.select('inbox')
        status, messages = mail.search(None, 'ALL')
        if status != 'OK':
            logging.error("Failed to search emails.")
            return []
        email_ids = messages[0].split()
        emails = []
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, '(RFC822)')
            if status != 'OK':
                logging.error(f"Failed to fetch email with ID {email_id}.")
                continue
            msg = email.message_from_bytes(msg_data[0][1])
            emails.append(msg)
        return emails
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP error: {e}")
        return []

def parse_email(msg):
    subject, encoding = decode_header(msg["Subject"])[0]
    if isinstance(subject, bytes):
        subject = subject.decode(encoding if encoding else 'utf-8')
    
    # Decode email sender
    from_ = msg.get("From")
    
    # Parse the email body
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            try:
                # get the email body
                body = part.get_payload(decode=True).decode()
                if "attachment" not in content_disposition:
                    break
            except Exception as e:
                logging.error(f"Failed to decode email body: {e}")
                body = ""
    else:
        body = msg.get_payload(decode=True).decode()
    
    return subject, from_, body

def summarize_email(body):
    # This is a placeholder function. You can implement your own logic to summarize the email body.
    # For now, it just returns the first 100 characters of the email body.
    return body[:100] + '...' if len(body) > 100 else body

if __name__ == "__main__":
    creds = authenticate_gmail()
    if not creds or not creds.valid:
        logging.error("Failed to authenticate.")
    else:
        logging.info("Authentication successful.")
    emails = fetch_emails(creds)
    if not emails:
        logging.error("Failed to fetch emails.")
    else:
        logging.info(f"Fetched {len(emails)} emails.")
        for msg in emails:
            subject, from_, body = parse_email(msg)
            logging.info(f"Subject: {subject}")
            logging.info(f"From: {from_}")
            logging.info("Summary: " + summarize_email(body))
            logging.info("\n" + "="*50 + "\n")