"""
Sample data processor with various code quality issues.
"""

import json


def load_data(filename):
    """Load data from JSON file."""
    # BUG: No error handling for missing file or invalid JSON
    f = open(filename)  # RESOURCE LEAK: File not closed
    data = json.load(f)
    return data


def process_records(records):
    """Process list of records."""
    results = []
    # PERFORMANCE: Inefficient list concatenation
    for record in records:
        if record["status"] == "active":  # BUG: KeyError if 'status' missing
            results = results + [record]  # PERFORMANCE: Use append instead
    return results


def save_results(data, filename):
    """Save results to file."""
    # BUG: Overwrites file without confirmation
    # BUG: No error handling
    with open(filename, "w") as f:
        f.write(str(data))  # BUG: Using str() instead of json.dumps()


def validate_email(email):
    """Validate email address."""
    # CODE SMELL: Naive validation, should use regex or library
    if "@" in email and "." in email:
        return True
    return False


def get_database_connection():
    """Get database connection."""
    # SECURITY: Hardcoded credentials
    DB_USER = "admin"
    DB_PASS = "password123"
    DB_HOST = "localhost"

    # This would connect to database (simplified for example)
    return f"Connected to {DB_HOST} as {DB_USER}"


class DataCache:
    """Simple cache implementation."""

    def __init__(self):
        self.cache = {}

    def get(self, key):
        """Get value from cache."""
        # BUG: No handling for missing key
        return self.cache[key]

    def set(self, key, value):
        """Set value in cache."""
        # ISSUE: No cache size limit, could cause memory issues
        self.cache[key] = value

    def clear(self):
        """Clear cache."""
        self.cache = {}
