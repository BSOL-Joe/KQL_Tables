import pandas as pd
import json
import random
from datetime import timedelta
import string


# === CONFIG ===
DATE_START = "2025-06-01"
DATE_END   = "2025-06-30"
OUTPUT_FILE = "SigninLogs_Expanded.csv"

# Suspicious IP pools
SUSPICIOUS_IPS = [
    ("185.254.75.23", "Moscow, RU"),
    ("103.87.199.12", "Kuala Lumpur, MY"),
    ("185.220.101.1", "Bucharest, RO"),
    ("45.142.120.5", "Amsterdam, NL"),
    ("109.74.204.61", "Stockholm, SE")
]

# App usage
APPS = [
    "Office 365 Exchange Online", "Microsoft Teams", "Azure Portal",
    "OneDrive", "SharePoint Online", "Outlook Mobile", "Power BI"
]

# Office IP mapping
LOCATION_MAP = {
    "London": {"IP": "86.23.123.45", "Country": "UK"},
    "New York": {"IP": "66.249.64.1", "Country": "USA"},
    "Dublin": {"IP": "78.137.97.10", "Country": "IE"}
}

def random_unknown_device():
    """Generate a random unknown device name"""
    rand_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return f"unknown-{rand_id}"

def device_name(city):
    return f"device-{city.lower()[:3]}-{random.randint(1,50)}"

def random_office_hour_time(day):
    """Generate a random time within 9am-5pm"""
    start_minute = 9 * 60    # 9:00
    end_minute = 17 * 60     # 17:00
    rand_min = random.randint(start_minute, end_minute)
    return day + timedelta(minutes=rand_min)

def random_anytime(day):
    """Generate a random time any time in the day"""
    return day + timedelta(minutes=random.randint(0, 1439))

def generate_signin_logs(identity_df, existing_df):
    date_range = pd.date_range(DATE_START, DATE_END)
    new_logs = []

    for _, user_row in identity_df.iterrows():
        email = user_row["UserPrincipalName"]
        city = user_row["OfficeLocation"]
        primary_ip = LOCATION_MAP[city]["IP"]
        primary_location = f"{city}, {LOCATION_MAP[city]['Country']}"

        # Target for suspicious? Always Jason Bourne + 30% random
        suspicious_target = "jason.bourne" in email or random.random() < 0.3

        for day in date_range:
            successes = random.randint(3, 10)   # 3-10 successful logins per day
            legit_fails = random.randint(0, 2)  # up to 2 legit failures
            suspicious_fails = 1 if suspicious_target and random.random() < 0.3 else 0

            # Successful logins (only during 9am-5pm)
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

            # Legitimate failures (anytime)
            for _ in range(legit_fails):
                signin_time = random_anytime(day)
                new_logs.append({
                    "TimeGenerated": signin_time.isoformat(),
                    "UserPrincipalName": email,
                    "AppDisplayName": random.choice(APPS),
                    "ResultType": 1,
                    "ResultDescription": "Incorrect password",
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

            # Suspicious failures (anytime)
            for _ in range(suspicious_fails):
                suspicious_ip_entry = random.choice(SUSPICIOUS_IPS)
                suspicious_ip = suspicious_ip_entry[0]
                suspicious_loc = suspicious_ip_entry[1]
                signin_time = random_anytime(day)
                new_logs.append({
                    "TimeGenerated": signin_time.isoformat(),
                    "UserPrincipalName": email,
                    "AppDisplayName": random.choice(APPS),
                    "ResultType": 1,
                    "ResultDescription": "Sign-in failed due to invalid credentials",
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

    # Combine with existing logs
    combined_df = pd.concat([existing_df, pd.DataFrame(new_logs)], ignore_index=True)
    combined_df.sort_values("TimeGenerated", inplace=True)
    return combined_df

if __name__ == "__main__":
    # Load IdentityInfo & SigninLogs
    identity_df = pd.read_csv("IdentityInfo.csv")
    existing_signin_df = pd.read_csv("SigninLogs.csv")

    # Generate & merge
    expanded_df = generate_signin_logs(identity_df, existing_signin_df)

    # Save result
    expanded_df.to_csv(OUTPUT_FILE, index=False)
    print(f"✅ Expanded SigninLogs saved as {OUTPUT_FILE} with {len(expanded_df)} entries")
