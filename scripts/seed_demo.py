"""Create demo records through real APIs. Run after migrate/create-admin and all servers."""

import os

import requests
from dotenv import load_dotenv


def main():
    load_dotenv()
    prefix = os.getenv("API_PREFIX", "/api/natalio-hassoun")
    users = os.getenv("USERS_URL", "http://127.0.0.1:8001") + prefix
    playbooks = os.getenv("PLAYBOOKS_URL", "http://127.0.0.1:8009") + prefix
    password = os.getenv("DEMO_PASSWORD", "")
    if len(password) < 12 or "CHANGE_ME" in password:
        raise SystemExit("Set DEMO_PASSWORD to a strong demo password first.")
    response = requests.post(users + "/users/login", json={"identifier": os.environ["ADMIN_USERNAME"],
                             "password": os.environ["ADMIN_PASSWORD"]}, timeout=10)
    response.raise_for_status()
    headers = {"Authorization": "Bearer " + response.json()["data"]["access_token"]}
    ids = {}
    for suffix, role in (("analyst", "security_analyst"), ("employee", "regular_employee"), ("auditor", "auditor")):
        username = "demo." + suffix
        response = requests.post(users + "/users/register", headers=headers, json={
            "full_name": "Demo " + suffix.title(), "username": username,
            "email": username + "@example.edu", "password": password,
            "department": "Security", "role": role}, timeout=15)
        if response.status_code == 409:
            response = requests.get(users + "/users/" + username, headers=headers, timeout=10)
        response.raise_for_status()
        ids[suffix] = response.json()["data"]["id"]
    for category, severity in (("Phishing", "High"), ("Malware", "Critical")):
        response = requests.post(playbooks + "/playbooks", headers=headers, json={
            "name": category + " response", "description": "Training workflow for " + category.lower(),
            "incident_category": category, "severity": severity}, timeout=15)
        response.raise_for_status()
        playbook_id = response.json()["data"]["id"]
        for step, description in enumerate(("Review available evidence", "Contain affected systems", "Verify recovery"), 1):
            response = requests.post(f"{playbooks}/playbooks/{playbook_id}/actions", headers=headers,
                                     json={"description": description, "step_number": step,
                                           "assigned_user_id": ids["analyst"]}, timeout=15)
            response.raise_for_status()
    print("Demo users and two playbooks with actions created through APIs. No credentials printed.")
    print("Repeating this script reuses demo users but creates additional playbooks.")


if __name__ == "__main__":
    main()
