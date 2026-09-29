import pandas as pd

from detection.feature_extractor import (
    get_domain_length,
    get_subdomain_count,
    calculate_entropy,
    get_query_frequency,
    get_query_type
)

df = pd.read_csv("data/dns_traffic.csv")

queries = df["query"]

# Calculate DNS features

df["domain_length"] = queries.apply(get_domain_length)

df["subdomain_count"] = queries.apply(get_subdomain_count)

df["entropy"] = queries.apply(calculate_entropy)

query_frequency = get_query_frequency(queries)

df["query_frequency"] = queries.map(query_frequency)

df["query_type_feature"] = df["query_type"].apply(get_query_type)


df.to_csv("data/dns_features.csv", index=False)