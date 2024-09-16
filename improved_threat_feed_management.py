#!/usr/bin/env python3

"""
Improved Threat Feed Management Script with Enhanced Menu

This script allows you to manage threat feeds using the Lookout API.
It provides a user-friendly interface for creating, viewing, updating, and deleting threat feeds.

Usage:
    python improved_threat_feed_management.py

Requirements:
    - Python 3.x
    - requests library (install using: pip install requests)

Configuration:
    - Create an 'api_key.txt' file in the same directory as the script and paste your API key.

Author:
    Frank Gravato (Lookout-SE)

"""

import requests
import json
import sys
import os
import tempfile
import uuid
import re
import logging
from urllib.parse import urlparse
from typing import List, Optional, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API endpoint URL
BASE_URL = "https://api.lookout.com/mgmt/threat-feeds/api/v1"

# File paths
API_KEY_FILE = "api_key.txt"
FEED_ID_FILE = "feed_id.txt"

# Headers for API requests
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def load_api_key() -> Optional[str]:
    """Load API key from file."""
    try:
        with open(API_KEY_FILE, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        logger.error(f"API key file '{API_KEY_FILE}' not found.")
        return None

def get_bearer(api_key: str) -> Optional[str]:
    """Get access token using the API key."""
    logger.info("Validating API key")
    token_url = "https://api.lookout.com/oauth2/token"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {"grant_type": "client_credentials"}

    try:
        response = requests.post(token_url, headers=headers, data=data)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if access_token:
            logger.info("Access token retrieved successfully")
            return access_token
        else:
            logger.error("Access token not found in the response")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error occurred during token retrieval: {e}")
        return None

def get_feed_guids(access_token: str) -> Optional[List[str]]:
    """Get the feed GUIDs for the tenant."""
    url = f"{BASE_URL}/threat-feeds"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        feed_guids = response.json()
        logger.info(f"Retrieved {len(feed_guids)} feed GUIDs")
        return feed_guids
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving feed GUIDs: {e}")
        return None

def get_feed_metadata(feed_id: str, access_token: str) -> Optional[Dict]:
    """Get the metadata for a specific feed."""
    url = f"{BASE_URL}/threat-feeds/{feed_id}"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        metadata = response.json()
        logger.info(f"Retrieved metadata for feed {feed_id}")
        return metadata
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving feed metadata: {e}")
        return None

def save_feed_id(feed_id: str) -> None:
    """Save feed ID to file."""
    with open(FEED_ID_FILE, "w") as file:
        file.write(feed_id)

def load_feed_id() -> Optional[str]:
    """Load feed ID from file."""
    try:
        with open(FEED_ID_FILE, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        return None

def create_threat_feed(feed_type: str, title: str, description: str, access_token: str) -> Optional[str]:
    """Create a new threat feed."""
    if feed_type not in ["CSV"]:
        logger.error("Invalid feed type. Allowed value: CSV")
        return None
    if len(title) < 8 or len(title) > 255:
        logger.error("Title must be between 8 and 255 characters.")
        return None
    if len(description) < 8 or len(description) > 255:
        logger.error("Description must be between 8 and 255 characters.")
        return None

    url = f"{BASE_URL}/threat-feeds"
    payload = {
        "feedType": feed_type,
        "title": title,
        "description": description
    }
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        feed_id = response.json()["feedId"]
        save_feed_id(feed_id)
        logger.info(f"Threat feed created with ID: {feed_id}")
        return feed_id
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            error_message = e.response.json().get("detail", "")
            if "Tenant reached the max allowed feed limit" in error_message:
                logger.error("Tenant has reached the maximum allowed feed limit.")
            else:
                logger.error(f"Error creating threat feed: {e.response.status_code} - {error_message}")
        else:
            logger.error(f"Error creating threat feed: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating threat feed: {e}")
        return None

def upload_threat_domains(feed_id: str, threat_domains: List[str], access_token: str, upload_type: str = "Incremental") -> None:
    """Upload a list of threat domains to a threat feed."""
    url = f"{BASE_URL}/threat-feeds/{feed_id}/elements?uploadType={upload_type}"
    boundary = str(uuid.uuid4())
    headers = HEADERS.copy()
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            temp_file.write("ACTION,DOMAIN\n")
            for domain in threat_domains:
                temp_file.write(f"{domain}\n")
            temp_file_path = temp_file.name

        with open(temp_file_path, "rb") as file:
            data = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{os.path.basename(temp_file_path)}\"\r\nContent-Type: text/csv\r\n\r\n{file.read().decode()}\r\n--{boundary}--\r\n"

        response = requests.post(url, headers=headers, data=data.encode())
        response.raise_for_status()
        logger.info("Threat domains uploaded successfully.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error uploading threat domains: {e}")
    finally:
        os.unlink(temp_file_path)

def get_threat_domains(feed_id: str, access_token: str) -> Optional[List[str]]:
    """Get the list of threat domains for a threat feed."""
    url = f"{BASE_URL}/threat-feeds/{feed_id}/elements"
    headers = HEADERS.copy()
    headers["Accept"] = "text/csv"
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.text.split("\n")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving threat domains: {e}")
        return None

def delete_threat_feed(feed_id: str, access_token: str) -> None:
    """Delete a threat feed."""
    url = f"{BASE_URL}/threat-feeds/{feed_id}"
    headers = HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
        logger.info("Threat feed deleted successfully.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deleting threat feed: {e}")

def update_feed_content(feed_id: str, source_url: str, access_token: str) -> None:
    """Update feed content from online sources."""
    try:
        response = requests.get(source_url, verify=False)
        response.raise_for_status()
        content = response.content.decode("utf-8")

        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            temp_file.write("ACTION,DOMAIN\n")
            for line in content.split('\n'):
                if not line.startswith(("http://", "https://")):
                    line = "https://" + line
                parsed_url = urlparse(line)
                domain = parsed_url.netloc
                if domain_pattern.match(domain):
                    temp_file.write(f"ADD,{domain}\n")
            temp_file_path = temp_file.name

        with open(temp_file_path, "rb") as file:
            threat_domains = file.read().decode("utf-8").split("\n")[1:]
            upload_threat_domains(feed_id, threat_domains, access_token)

        logger.info("Feed content updated successfully.")
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 404:
            logger.error(f"Error: The source URL {source_url} is not found (404 error).")
        else:
            logger.error(f"Error downloading content from source URL: {e}")
    finally:
        if 'temp_file_path' in locals():
            os.unlink(temp_file_path)

def display_main_menu() -> None:
    """Display the main menu options."""
    print("\n=== Threat Feed Management System ===")
    print("1. View and Manage Existing Feeds")
    print("2. Create a New Threat Feed")
    print("3. Exit")

def display_feed_menu() -> None:
    """Display the feed management menu options."""
    print("\n--- Feed Management Menu ---")
    print("1. List All Feeds")
    print("2. View Feed Details")
    print("3. Update Feed Content")
    print("4. Delete Feed")
    print("5. Return to Main Menu")

def list_feeds(access_token: str) -> None:
    """List all existing feeds."""
    feed_guids = get_feed_guids(access_token)
    if feed_guids:
        print("\nExisting threat feeds:")
        for i, guid in enumerate(feed_guids, 1):
            metadata = get_feed_metadata(guid, access_token)
            if metadata:
                print(f"{i}. Feed ID: {guid}")
                print(f"   Title: {metadata['title']}")
                print(f"   Elements Count: {metadata['elementsCount']}")
                print("---")
    else:
        print("No existing threat feeds found.")

def view_feed_details(access_token: str) -> None:
    """View details of a specific feed with options to add or remove domains."""
    feed_id = select_feed(access_token)
    if not feed_id:
        return

    while True:
        metadata = get_feed_metadata(feed_id, access_token)
        if not metadata:
            print("Unable to retrieve feed metadata.")
            return

        print("\nFeed Details:")
        print(f"Feed ID: {feed_id}")
        print(f"Title: {metadata['title']}")
        print(f"Description: {metadata['description']}")
        print(f"Feed Type: {metadata['feedType']}")
        print(f"Elements Count: {metadata['elementsCount']}")
        print(f"Last Updated: {metadata['elementsUploadedAt']}")
        
        print("\nOptions:")
        print("1. View domains")
        print("2. Add domain")
        print("3. Remove domain")
        print("4. Return to previous menu")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            view_domains(feed_id, access_token)
        elif choice == '2':
            add_domain_to_feed(feed_id, access_token)
        elif choice == '3':
            remove_domain_from_feed(feed_id, access_token)
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")

def view_domains(feed_id: str, access_token: str) -> None:
    """View domains in the feed with pagination."""
    domains = get_threat_domains(feed_id, access_token)
    if not domains:
        print("No domains found in this feed.")
        return

    page_size = 20
    current_page = 0
    total_pages = (len(domains) + page_size - 1) // page_size

    while True:
        start = current_page * page_size
        end = min(start + page_size, len(domains))
        print("\nThreat domains:")
        for i, domain in enumerate(domains[start:end], start=start+1):
            print(f"{i}. {domain}")
        
        print(f"\nShowing {start+1}-{end} of {len(domains)} domains.")
        choice = input("Enter 'n' for next page, 'p' for previous page, or 'q' to quit: ").lower()
        if choice == 'n' and current_page < total_pages - 1:
            current_page += 1
        elif choice == 'p' and current_page > 0:
            current_page -= 1
        elif choice == 'q':
            break
        else:
            print("Invalid choice or no more pages.")

def select_feed(access_token: str) -> Optional[str]:
    """Helper function to select a feed from the list."""
    feed_guids = get_feed_guids(access_token)
    if not feed_guids:
        print("No existing threat feeds found.")
        return None

    print("\nSelect a feed:")
    for i, guid in enumerate(feed_guids, 1):
        metadata = get_feed_metadata(guid, access_token)
        if metadata:
            print(f"{i}. {metadata['title']} (ID: {guid})")

    while True:
        try:
            choice = int(input("Enter the number of the feed: "))
            if 1 <= choice <= len(feed_guids):
                return feed_guids[choice - 1]
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a valid number.")
def create_new_feed(access_token: str) -> None:
    """Create a new threat feed."""
    print("\n--- Create a New Threat Feed ---")
    feed_type = input("Enter the feed type (e.g., CSV): ")
    title = input("Enter the feed title: ")
    description = input("Enter the feed description: ")
    feed_id = create_threat_feed(feed_type, title, description, access_token)
    if feed_id:
        print(f"\nNew threat feed created successfully!")
        print(f"Feed ID: {feed_id}")
        add_domains = input("Would you like to add domains to this feed now? (y/n): ").lower()
        if add_domains == 'y':
            add_domains_to_feed(feed_id, access_token)

def add_domain_to_feed(feed_id: str, access_token: str) -> None:
    """Add a domain to the feed."""
    domain = input("Enter the domain to add: ")
    action = input("Enter the action (ADD or DELETE): ").upper()
    if action not in ['ADD', 'DELETE']:
        print("Invalid action. Please use ADD or DELETE.")
        return

    upload_threat_domains(feed_id, [f"{action},{domain}"], access_token)
    print(f"Domain '{domain}' has been {action.lower()}ed to the feed.")

def remove_domain_from_feed(feed_id: str, access_token: str) -> None:
    """Remove a domain from the feed."""
    domain = input("Enter the domain to remove: ")
    upload_threat_domains(feed_id, [f"DELETE,{domain}"], access_token)
    print(f"Domain '{domain}' has been removed from the feed.")

# Make sure to update the upload_threat_domains function to handle single domain additions/removals efficiently
def upload_threat_domains(feed_id: str, threat_domains: List[str], access_token: str, upload_type: str = "Incremental") -> None:
    """Upload a list of threat domains to a threat feed."""
    url = f"{BASE_URL}/threat-feeds/{feed_id}/elements?uploadType={upload_type}"
    boundary = str(uuid.uuid4())
    headers = HEADERS.copy()
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            temp_file.write("ACTION,DOMAIN\n")
            for domain in threat_domains:
                temp_file.write(f"{domain}\n")
            temp_file_path = temp_file.name

        with open(temp_file_path, "rb") as file:
            data = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{os.path.basename(temp_file_path)}\"\r\nContent-Type: text/csv\r\n\r\n{file.read().decode()}\r\n--{boundary}--\r\n"

        response = requests.post(url, headers=headers, data=data.encode())
        response.raise_for_status()
        logger.info("Threat domains updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating threat domains: {e}")
    finally:
        os.unlink(temp_file_path)

def manage_feeds(access_token: str) -> None:
    """Manage existing feeds."""
    while True:
        display_feed_menu()
        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            list_feeds(access_token)
        elif choice == "2":
            view_feed_details(access_token)
        elif choice == "3":
            feed_id = select_feed(access_token)
            if feed_id:
                source_url = input("Enter the source URL for updating feed content: ")
                update_feed_content(feed_id, source_url, access_token)
        elif choice == "4":
            feed_id = select_feed(access_token)
            if feed_id:
                confirm = input(f"Are you sure you want to delete the feed with ID {feed_id}? (y/n): ").lower()
                if confirm == 'y':
                    delete_threat_feed(feed_id, access_token)
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

def main() -> None:
    """Main function to run the threat feed management script."""
    api_key = load_api_key()
    if not api_key:
        logger.error("Please provide a valid API key in the 'api_key.txt' file.")
        return

    access_token = get_bearer(api_key)
    if not access_token:
        logger.error("Failed to retrieve access token. Please check your API key.")
        return

    while True:
        display_main_menu()
        choice = input("Enter your choice (1-3): ")

        if choice == "1":
            manage_feeds(access_token)
        elif choice == "2":
            create_new_feed(access_token)
        elif choice == "3":
            print("Thank you for using the Threat Feed Management System. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()            