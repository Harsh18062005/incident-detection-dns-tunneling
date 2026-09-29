import math



def get_domain_length(query):
    return len(query)


def get_subdomain_count(query):
    parts = query.split(".")
    return len(parts) - 2



def calculate_entropy(query):
    probabilities = []

    for character in set(query):
        probability = query.count(character) / len(query)
        probabilities.append(probability)

    entropy = 0

    for probability in probabilities:
        entropy -= probability * math.log2(probability)

    return entropy



def get_query_frequency(queries):
    frequency = {}

    for query in queries:
        frequency[query] = frequency.get(query, 0) + 1

    return frequency



def get_query_type(query_type):
    return query_type
