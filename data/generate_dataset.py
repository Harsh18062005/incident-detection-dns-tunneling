import csv
import random
import string


OUTPUT_FILE = "data/dns_traffic.csv"


def random_string(length):
    characters = string.ascii_lowercase + string.digits
    return "".join(random.choice(characters) for _ in range(length))


def generate_normal_domain():
    domains = [
        "google.com",
        "youtube.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "wikipedia.org",
        "stackoverflow.com",
    ]

    return random.choice(domains)


def generate_suspicious_domain():
    subdomain = random_string(random.randint(35, 70))
    return f"{subdomain}.example.com"


def generate_dataset():
    rows = []

    # Normal DNS traffic
    for _ in range(80):
        rows.append({
            "source_ip": f"192.168.1.{random.randint(2, 50)}",
            "query": generate_normal_domain(),
            "query_type": random.choice(["A", "AAAA", "MX"]),
            "label": "normal"
        })

    # Suspicious DNS traffic
    for _ in range(20):
        rows.append({
            "source_ip": f"192.168.1.{random.randint(2, 10)}",
            "query": generate_suspicious_domain(),
            "query_type": "TXT",
            "label": "suspicious"
        })

    random.shuffle(rows)

    with open(OUTPUT_FILE, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["source_ip", "query", "query_type", "label"]
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"Dataset created successfully: {OUTPUT_FILE}")
    print(f"Total DNS queries: {len(rows)}")


if __name__ == "__main__":
    generate_dataset()