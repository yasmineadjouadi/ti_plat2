import requests
import re
import os
from dotenv import load_dotenv

load_dotenv()  



MX_API_KEY = os.getenv("MX_API_KEY")


def validate_email_format(email: str):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def check_mx_with_mxtoolbox(domain: str):
    url = f"https://api.mxtoolbox.com/api/v1/Lookup/mx/{domain}"

    headers = {
        "Authorization": MX_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "MXToolbox API error"}


def get_email_report(email: str):

    if not validate_email_format(email):
        return {
            "email": email,
            "valid_format": False,
            "status": "Invalid email format"
        }

    domain = email.split("@")[1]

    mx_data = check_mx_with_mxtoolbox(domain)

    return {
        "email": email,
        "valid_format": True,
        "domain": domain,
        "mxtoolbox_response": mx_data
    }