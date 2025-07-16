import pandas as pd
import random
from datetime import datetime, timedelta
from tqdm import tqdm

# === CONFIGURATION ===
DATE_START = "2025-06-01"
DATE_END = "2025-06-30"
OUTPUT_FILE = "OfficeActivity_Expanded.csv"
IDENTITY_FILE = "IdentityInfo.csv"

OFFICE_HOURS = (9, 17)
ANOMALY_USER = "jason.bourne@contoso.com"
ANOMALY_IP = "92.63.194.12"

SHAREPOINT_URLS = [
    "https://contoso.sharepoint.com/sites/marketing",
    "https://contoso.sharepoint.com/sites/hr",
    "https://contoso.sharepoint.com/sites/finance",
    "https://contoso.sharepoint.com/sites/engineering"
]

CLIENT_APPS = ["Outlook", "Teams", "Browser", "SharePoint", "Office 365 Web"]
ACTIVITIES = [
    "TeamsSessionStarted", "FileAccessed", "FileModified",
    "MailItemsAccessed", "MoveToDeletedItems"
]

OFFICE_IPS = {
    "London": "86.23.123.45",
    "New York": "66.249.64.1",
    "Dublin": "78.137.97.10"
}

# === HELPERS ===
def random_office_time(day):
    start = OFFICE_HOURS[0] * 60
    end = OFFICE_HOURS[1] * 60
    return day + timedelta(minutes=random.randint(start, end))

def generate_file_name():
    base_names = ["Report", "Budget", "Strategy", "Plan", "Presentation"]
    extensions = [".docx", ".xlsx", ".pptx", ".pdf"]
    return f"{random.choice(base_names)}_{random.randint(1,100)}{random.choice(extensions)}"

# === MAIN LOGIC ===
def generate_officeactivity(identity_csv, output_csv):
    identity_df = pd.read_csv(identity_csv)
    users = identity_df["UserPrincipalName"].tolist()
    date_range = pd.date_range(DATE_START, DATE_END)
    logs = []

    for user in tqdm(users, desc="Generating OfficeActivity logs"):
        user_info = identity_df[identity_df["UserPrincipalName"] == user].iloc[0]
        ip = OFFICE_IPS.get(user_info["OfficeLocation"], "10.0.0.1")
        is_managed = True

        for day in date_range:
            for _ in range(random.randint(5, 15)):
                operation = random.choice(ACTIVITIES)
                log = {
                    "TimeGenerated": random_office_time(day).isoformat(),
                    "UserPrincipalName": user,
                    "OperationName": operation,
                    "SiteUrl": random.choice(SHAREPOINT_URLS),
                    "FileName": generate_file_name() if "File" in operation else "",
                    "TargetFolder": "Inbox" if operation == "MoveToDeletedItems" else "",
                    "ClientAppUsed": random.choice(CLIENT_APPS),
                    "IPAddress": ip,
                    "IsManagedDevice": is_managed
                }
                logs.append(log)

    # === Inject Anomaly Activity for Jason Bourne ===
    anomaly_day = pd.to_datetime("2025-06-18")
    for i, (operation, folder) in enumerate([
        ("MailItemsAccessed", "Inbox"),
        ("MoveToDeletedItems", "Inbox"),
        ("FileAccessed", "SharedDocs"),
        ("TeamsSessionStarted", "")
    ]):
        logs.append({
            "TimeGenerated": (anomaly_day + timedelta(minutes=45 + i * 2)).isoformat(),
            "UserPrincipalName": ANOMALY_USER,
            "OperationName": operation,
            "SiteUrl": "https://contoso.sharepoint.com/sites/engineering",
            "FileName": generate_file_name() if "File" in operation else "",
            "TargetFolder": folder,
            "ClientAppUsed": random.choice(CLIENT_APPS),
            "IPAddress": ANOMALY_IP,
            "IsManagedDevice": False  # suspicious device
        })

    # Save
    df = pd.DataFrame(logs)
    df.sort_values("TimeGenerated", inplace=True)
    df.to_csv(output_csv, index=False)
    print(f"✅ Saved {len(df)} logs to: {output_csv}")

# === RUN ===
if __name__ == "__main__":
    generate_officeactivity(IDENTITY_FILE, OUTPUT_FILE)
