import pandas as pd
import json
import random
from datetime import timedelta
import string

# === CONFIG ===
DATE_START = "2025-06-01"
DATE_END   = "2025-06-30"
OUTPUT_FILE = "SigninLogs_Expanded.csv"

SUSPICIOUS_IPS = [
    ("185.254.75.23", "Moscow, RU"),
    ("103.87.199.12", "Kuala Lumpur, MY"),
    ("185.220.101.1", "Bucharest, RO"),
    ("45.142.120.5", "Amsterdam, NL"),
    ("109.74.204.61", "Stockholm, SE")
]

APPS = [
    "Office 365 Exchange Online", "Microsoft Teams", "Azure Portal",
    "OneDrive", "SharePoint Online", "Outlook Mobile", "Power BI"
]

LOCATION_MAP = {
    "London": {"IP": "86.23.123.45", "Country": "UK"},
    "New York": {"IP": "66.249.64.1", "Country": "USA"},
    "Dublin": {"IP": "78.137.97.10", "Country": "IE"}
}

FAILURE_POOL = [
    (50057, "User account is disabled. The account has been disabled by an administrator."),
    (50055, "Invalid password, entered expired password."),
    (53003, "Access has been blocked due to conditional access policies."),
    (50074, "Strong Authentication is required."),
    (70044, "The session has expired or is invalid due to sign-in frequency checks by conditional access."),
    (50140, "Keep me signed in interrupt when the user was signing in."),
    (50076, "Location change or admin config requires MFA to access the resource."),
    (50126, "Invalid username or password."),
    (500121, "Authentication failed during strong authentication request.")
]

def random_unknown_device():
    rand_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return f"unknown-{rand_id}"

def device_name(city):
    return f"device-{city.lower()[:3]}-{random.randint(1,50)}"

def random_office_hour_time(day):
    start_minute = 9 * 60
    end_minute = 17 * 60
    rand_min = random.randint(start_minute, end_minute)
    return day + timedelta(minutes=rand_min)

def random_anytime(day):
    return day + timedelta(minutes=random.randint(0, 1439))

def random_failure_code():
    return random.choice(FAILURE_POOL)

def generate_signin_logs(identity_df):
    date_range = pd.date_range(DATE_START, DATE_END)
    new_logs = []

    for _, user_row in identity_df.iterrows():
        email = user_row["UserPrincipalName"]
        city = user_row["OfficeLocation"]
        primary_ip = LOCATION_MAP[city]["IP"]
        primary_location = f"{city}, {LOCATION_MAP[city]['Country']}"
        suspicious_target = "jason.bourne" in email or random.random() < 0.3

        for day in date_range:
            successes = random.randint(3, 10)
            legit_fails = random.randint(0, 2)
            suspicious_fails = 1 if suspicious_target and random.random() < 0.3 else 0

            for _ in range(successes):
                signin_time = random_office_hour_time(day)
                new_logs.append({
                    "TimeGenerated": signin_time.isoformat(),
                    "UserPrincipalName": email,
                    "AppDisplayName": random.choice(APPS),
                    "ResultType": 0,
                    "ResultDescription": "Sign-in succeeded",
                    "IPAddress": primary_ip,
                    "Location": primary_location,
                    "DeviceDetail": json.dumps({
                        "DisplayName": device_name(city),
                        "IsCompliant": True,
                        "IsManaged": True,
                        "OperatingSystem": random.choice(["Windows", "macOS", "iOS", "Android"]),
                        "Browser": random.choice(["Chrome", "Edge", "Firefox"])
                    })
                })

            for _ in range(legit_fails):
                signin_time = random_anytime(day)
                result_type, result_desc = random_failure_code()
                new_logs.append({
                    "TimeGenerated": signin_time.isoformat(),
                    "UserPrincipalName": email,
                    "AppDisplayName": random.choice(APPS),
                    "ResultType": result_type,
                    "ResultDescription": result_desc,
                    "IPAddress": primary_ip,
                    "Location": primary_location,
                    "DeviceDetail": json.dumps({
                        "DisplayName": device_name(city),
                        "IsCompliant": False,
                        "IsManaged": False,
                        "OperatingSystem": random.choice(["Windows", "Linux"]),
                        "Browser": random.choice(["Unknown", "Chrome"])
                    })
                })

            for _ in range(suspicious_fails):
                signin_time = random_anytime(day)
                suspicious_ip_entry = random.choice(SUSPICIOUS_IPS)
                suspicious_ip, suspicious_loc = suspicious_ip_entry
                result_type, result_desc = random_failure_code()
                new_logs.append({
                    "TimeGenerated": signin_time.isoformat(),
                    "UserPrincipalName": email,
                    "AppDisplayName": random.choice(APPS),
                    "ResultType": result_type,
                    "ResultDescription": result_desc,
                    "IPAddress": suspicious_ip,
                    "Location": suspicious_loc,
                    "DeviceDetail": json.dumps({
                        "DisplayName": random_unknown_device(),
                        "IsCompliant": False,
                        "IsManaged": False,
                        "OperatingSystem": random.choice(["Linux", "Unknown"]),
                        "Browser": random.choice(["Unknown", "Tor", "Firefox"])
                    })
                })

    df = pd.DataFrame(new_logs)
    df.sort_values("TimeGenerated", inplace=True)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"✅ Generated {len(df)} new sign-in logs and saved to: {OUTPUT_FILE}")

# === EXECUTE ===
if __name__ == "__main__":
    print("log creation starting")
    identity_df = pd.read_csv("IdentityInfo.csv")
    generate_signin_logs(identity_df)
