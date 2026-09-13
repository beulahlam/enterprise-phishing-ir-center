import json
from pathlib import Path
from datetime import datetime, timezone


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

CASE_FILE = Path("cases/INC-001-auto-analysis.json")
OUTPUT_DIR = Path("logs")
OUTPUT_FILE = OUTPUT_DIR / "splunk_phishing_events.json"


# ---------------------------------------------------------
# LOAD PHISHING INVESTIGATION
# ---------------------------------------------------------

def load_case(case_file):
    with open(case_file, "r", encoding="utf-8") as file:
        return json.load(file)


# ---------------------------------------------------------
# CREATE SPLUNK EVENT
# ---------------------------------------------------------

def create_splunk_event(case):

    threat_intel = case.get("threat_intelligence", [])

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "event_type": "phishing_investigation",

        "case_id": case.get("case_id"),

        "subject": case.get("email", {}).get("subject"),

        "sender": case.get("email", {}).get("from"),

        "reply_to": case.get("email", {}).get("reply_to"),

        "risk_score": case.get("risk_score"),

        "severity": case.get("severity"),

        "escalation_required": case.get(
            "escalation_required"
        ),

        "indicators": case.get(
            "indicators",
            {}
        ),

        "iocs": case.get(
            "iocs",
            {}
        ),

        "mitre_attack": case.get(
            "mitre_attack",
            {}
        ),

        "threat_intelligence": threat_intel
    }

    return event


# ---------------------------------------------------------
# EXPORT EVENT
# ---------------------------------------------------------

def export_event(event):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    events = []

    if OUTPUT_FILE.exists():
        try:
            with open(
                OUTPUT_FILE,
                "r",
                encoding="utf-8"
            ) as file:
                existing_data = json.load(file)

                if isinstance(existing_data, list):
                    events = existing_data
                elif isinstance(existing_data, dict):
                    events = [existing_data]

        except json.JSONDecodeError:
            events = []

    events = [
    existing_event
    for existing_event in events
    if existing_event.get("case_id") != event.get("case_id")
    ]

    events.append(event)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4
        )


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    print("=" * 60)
    print("SPLUNK SIEM EVENT EXPORT")
    print("=" * 60)

    case = load_case(CASE_FILE)

    event = create_splunk_event(case)

    export_event(event)

    print(f"\nCase ID   : {event['case_id']}")
    print(f"Severity  : {event['severity']}")
    print(f"Risk Score: {event['risk_score']}")

    print(
        "\nSplunk event exported to:"
    )

    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()