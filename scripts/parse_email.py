import email
import sys

def parse_email(file_path):
    print("Script started")
    
    with open(file_path, "r", encoding="utf-8-sig") as f:
        msg = email.message_from_file(f)
    
    print("From:   ", msg["From"])
    print("To:     ", msg["To"])
    print("Subject:", msg["Subject"])
    print("Date:   ", msg["Date"])
    
    print("\n--- Body ---")
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                print(part.get_payload(decode=True).decode())
    else:
        print(msg.get_payload())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_email.py <email_file>")
    else:
        parse_email(sys.argv[1])