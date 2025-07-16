import pandas as pd
import json
import random
from datetime import timedelta
from tqdm import tqdm

# CONFIGURATION
DATE_START = "2025-06-01"
DATE_END = "2025-06-30"
OUTPUT_FILE = "AuditLogs_Expanded.csv"
OFFICE_HOURS = (9, 17)

VALID_IT_DEPARTMENTS = ["IT Support", "Engineering"]

OFFICE_IPS = {
    "London": "86.23.123.45",
    "New York": "66.249.64.1",
    "Dublin": "78.137.97.10"
}

ROLES = [
    "Global Administrator", "User Administrator",
    "Security Administrator", "Exchange Administrator"
]

OPS = [
    "AddMemberToGroup", "RemoveMemberFromGroup",
    "UpdateDevice", "UpdateUser", "AddUser"
]

FIRST_NAMES = [
    "alex", "sam", "charlie", "jordan", "riley", "taylor", "chris", "pat", "morgan", "drew",
    "casey", "jamie", "avery", "kai", "reese", "devon", "bailey", "quinn", "skyler", "dallas",
    "blake", "cameron", "emerson", "finley", "hayden", "kendall", "lane", "marley", "parker", "rowan",
    "sawyer", "sloane", "spencer", "teagan", "val", "wren", "zane", "zephyr", "logan", "reagan"
]

LAST_NAMES = [
    "doe", "smith", "johnson", "parker", "murray", "harris", "edwards", "stone", "rivers", "knight",
    "foster", "bennett", "carter", "clarke", "day", "ellis", "french", "graham", "holland", "irving",
    "jones", "keaton", "lewis", "morgan", "nelson", "owens", "pratt", "quincy", "reed", "sanders",
    "taylor", "upton", "vance", "walsh", "xavier", "young", "zimmer", "wright", "evans", "anderson"
]

def random_office_time(day):
    start = OFFICE_HOURS[0] * 60
    end = OFFICE_HOURS[1] * 60
    return day + timedelta(minutes=random.randint(start, end))

def build_target_properties(op, actor, target_email, role_name=None):
    if op in ["AddMemberToRole", "RemoveMemberFromRole"]:
        return json.dumps({
            "RoleName": role_name or random.choice(ROLES),
            "User": target_email
        })
    elif op in ["AddUser", "DeleteUser"]:
        return json.dumps({
            "UserPrincipalName": target_email,
            "Department": random.choice(["Sales", "Legal", "Marketing"]),
            "CreatedBy": actor
        })
    elif op == "UpdateUser":
        return json.dumps({
            "UserPrincipalName": target_email,
            "UpdatedField": "Title",
            "OldValue": "Analyst",
            "NewValue": "Senior Analyst"
        })
    elif op == "UpdateDevice":
        return json.dumps({
            "DeviceId": f"device-{random.randint(1000,9999)}",
            "ComplianceStatus": "Updated"
        })
    elif op in ["AddMemberToGroup", "RemoveMemberFromGroup"]:
        return json.dumps({
            "Group": f"group-{random.randint(100,999)}",
            "User": target_email
        })
    return "{}"

def generate_random_user_email(existing):
    if not FIRST_NAMES or not LAST_NAMES:
        raise ValueError("FIRST_NAMES or LAST_NAMES list is empty!")

    while True:
        email = f"{random.choice(FIRST_NAMES)}.{random.choice(LAST_NAMES)}@contoso.com"
        if email not in existing:
            existing.add(email)
            return email

def generate_auditlogs(identity_path):
    identity_df = pd.read_csv(identity_path)
    print(f"Loaded identities: {len(identity_df)}")
    it_users = identity_df[identity_df["Department"].isin(VALID_IT_DEPARTMENTS)]
    print(f"Filtered IT users: {len(it_users)}")

    logs = []
    date_range = pd.date_range(DATE_START, DATE_END)
    used_fake_emails = set()
    pending_deletes = []

    for _, user in tqdm(it_users.iterrows(), total=len(it_users), desc="Generating logs"):
        email = user["UserPrincipalName"]
        city = user["OfficeLocation"]
        ip = OFFICE_IPS.get(city, "10.0.0.1")
        is_bourne = email.lower() == "jason.bourne@contoso.com"

        if is_bourne:
            continue

        for day in date_range:
            # Add & Remove privileged role
            target_email = it_users.sample(1)["UserPrincipalName"].values[0]
            role_name = random.choice(ROLES)
            props = build_target_properties("AddMemberToRole", email, target_email, role_name)

            logs.append({
                "TimeGenerated": random_office_time(day).isoformat(),
                "OperationName": "AddMemberToRole",
                "InitiatedBy": f"{email} ({ip})",
                "TargetProperties": props
            })

            logs.append({
                "TimeGenerated": random_office_time(day).isoformat(),
                "OperationName": "RemoveMemberFromRole",
                "InitiatedBy": f"{email} ({ip})",
                "TargetProperties": props
            })

            # 5–10 random operations
            for _ in range(random.randint(5, 10)):
                op = random.choice(OPS)
                target_email = generate_random_user_email(used_fake_emails)
                props = build_target_properties(op, email, target_email)

                logs.append({
                    "TimeGenerated": random_office_time(day).isoformat(),
                    "OperationName": op,
                    "InitiatedBy": f"{email} ({ip})",
                    "TargetProperties": props
                })

                if op == "AddUser":
                    # Track to generate a matching DeleteUser
                    pending_deletes.append((target_email, email, city, day))

    # Inject DeleteUser entries
    for target_email, actor_email, city, base_day in pending_deletes:
        ip = OFFICE_IPS.get(city, "10.0.0.1")
        delete_time = random_office_time(base_day + timedelta(days=random.randint(0, 3)))
        props = build_target_properties("DeleteUser", actor_email, target_email)
        logs.append({
            "TimeGenerated": delete_time.isoformat(),
            "OperationName": "DeleteUser",
            "InitiatedBy": f"{actor_email} ({ip})",
            "TargetProperties": props
        })

    # Inject Jason Bourne's anomaly role escalations (linked to 2025-06-18 sign-in)
    jason_email = "jason.bourne@contoso.com"
    jason_ip = "92.63.194.12"  # Suspicious IP

    anomaly_base_time = pd.to_datetime("2025-06-18T12:45:00")

    logs.append({
        "TimeGenerated": (anomaly_base_time + timedelta(minutes=2)).isoformat(),  # 12:47
        "OperationName": "AddMemberToRole",
        "InitiatedBy": f"{jason_email} ({jason_ip})",
        "TargetProperties": build_target_properties(
            "AddMemberToRole", jason_email, jason_email, "User Administrator"
        )
    })

    logs.append({
        "TimeGenerated": (anomaly_base_time + timedelta(minutes=60)).isoformat(),  # 13:45
        "OperationName": "AddMemberToRole",
        "InitiatedBy": f"{jason_email} ({jason_ip})",
        "TargetProperties": build_target_properties(
            "AddMemberToRole", jason_email, jason_email, "Global Administrator"
        )
    })


    # Output file
    auditlogs_df = pd.DataFrame(logs)
    auditlogs_df.sort_values("TimeGenerated", inplace=True)
    auditlogs_df.to_csv(OUTPUT_FILE, index=False)
    print(f"✅ AuditLogs generated: {len(auditlogs_df)} rows → saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_auditlogs("IdentityInfo.csv")
