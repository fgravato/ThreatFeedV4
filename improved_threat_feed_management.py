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
from typing import List, Optional, Dict, Tuple
import argparse
from dataclasses import dataclass
import time
import shutil

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

@dataclass
class MenuContext:
    """Class to maintain menu navigation context"""
    current_feed_id: Optional[str] = None
    current_feed_title: Optional[str] = None
    breadcrumb: List[str] = None
    
    def __post_init__(self):
        if self.breadcrumb is None:
            self.breadcrumb = ["Main Menu"]
    
    def update_feed(self, feed_id: Optional[str], feed_title: Optional[str]) -> None:
        self.current_feed_id = feed_id
        self.current_feed_title = feed_title
    
    def push_breadcrumb(self, menu_name: str) -> None:
        self.breadcrumb.append(menu_name)
    
    def pop_breadcrumb(self) -> None:
        if len(self.breadcrumb) > 1:
            self.breadcrumb.pop()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API endpoint URL
BASE_URL = "https://api.lookout.com/mgmt/threat-feeds/api/v1"

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Threat Feed Management System")
    parser.add_argument("--list-feeds", action="store_true", help="List all feeds")
    parser.add_argument("--create-feed", nargs=3, metavar=("TYPE", "TITLE", "DESCRIPTION"), help="Create a new feed")
    parser.add_argument("--view-feed", metavar="FEED_ID", help="View details of a specific feed")
    parser.add_argument("--update-feed", nargs=2, metavar=("FEED_ID", "SOURCE_URL"), help="Update feed content")
    parser.add_argument("--upload-type", choices=["INCREMENTAL", "OVERWRITE"], default="OVERWRITE", help="Upload type for updating feed content")
    parser.add_argument("--delete-feed", metavar="FEED_ID", help="Delete a feed")
    parser.add_argument("--add-domain", nargs=2, metavar=("FEED_ID", "DOMAIN"), help="Add domain to feed")
    parser.add_argument("--remove-domain", nargs=2, metavar=("FEED_ID", "DOMAIN"), help="Remove domain from feed")
    return parser.parse_args()

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

def upload_threat_domains(feed_id: str, domains: List[Tuple[str, Optional[str]]], access_token: str, upload_type: str = "INCREMENTAL") -> None:
    """Upload a list of threat domains to a threat feed.
    
    Args:
        feed_id: The ID of the feed to update
        domains: List of tuples (domain, action). For INCREMENTAL type, action should be 'add' or 'delete'.
                For OVERWRITE type, action should be None.
        access_token: The API access token
        upload_type: Upload type, either 'INCREMENTAL' or 'OVERWRITE'
    """
    url = f"{BASE_URL}/threat-feeds/{feed_id}/elements?uploadType={upload_type}"
    boundary = str(uuid.uuid4())
    headers = HEADERS.copy()
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    headers["Authorization"] = f"Bearer {access_token}"

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
            if upload_type == "INCREMENTAL":
                temp_file.write("domain,action\n")
                for domain, action in domains:
                    temp_file.write(f"{domain},{action}\n")
            else:  # OVERWRITE
                temp_file.write("domain\n")
                for domain, _ in domains:
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

def update_feed_content(feed_id: str, source_url: str, access_token: str, upload_type: str = "OVERWRITE") -> None:
    """Update feed content from online sources.
    
    Args:
        feed_id: The ID of the feed to update
        source_url: The URL to download threat feed content from
        access_token: The API access token
        upload_type: Upload type, either 'INCREMENTAL' or 'OVERWRITE' (default: OVERWRITE)
    """
    # Suppress insecure request warnings since we intentionally use verify=False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    columns, _ = get_terminal_size()
    print("\n" + "=" * columns)
    print(f"{Colors.BOLD}Update Feed Content{Colors.ENDC}")
    print("=" * columns)
    
    print(f"\n{Colors.BLUE}Feed Settings:{Colors.ENDC}")
    print(f"Source URL: {source_url}")
    print(f"Upload Type: {upload_type}")
    
    print(f"\n{Colors.YELLOW}Downloading content...{Colors.ENDC}")
    
    try:
        response = requests.get(source_url, verify=False)
        response.raise_for_status()
        content = response.content.decode("utf-8")
        
        print(f"{Colors.YELLOW}Processing domains...{Colors.ENDC}")

        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        domains = []

        for line in content.split('\n'):
            if not line.startswith(("http://", "https://")):
                line = "https://" + line
            parsed_url = urlparse(line)
            domain = parsed_url.netloc
            if domain_pattern.match(domain):
                if upload_type == "INCREMENTAL":
                    domains.append((domain, "add"))
                else:  # OVERWRITE
                    domains.append((domain, None))

        if domains:
            upload_threat_domains(feed_id, domains, access_token, upload_type)

        print(f"\n{Colors.GREEN}Feed content updated successfully!{Colors.ENDC}")
        logger.info("Feed content updated successfully.")
        time.sleep(1)
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 404:
            logger.error(f"Error: The source URL {source_url} is not found (404 error).")
        else:
            logger.error(f"Error downloading content from source URL: {e}")
    finally:
        if 'temp_file_path' in locals():
            os.unlink(temp_file_path)

def get_terminal_size() -> Tuple[int, int]:
    """Get terminal size for proper formatting"""
    columns, rows = shutil.get_terminal_size()
    return columns, rows

def display_header(menu_context: MenuContext) -> None:
    """Display formatted header with breadcrumb and current feed info"""
    columns, _ = get_terminal_size()
    print("\n" + "=" * columns)
    print(f"{Colors.HEADER}{Colors.BOLD}Threat Feed Management System{Colors.ENDC}")
    
    # Display breadcrumb
    breadcrumb = " > ".join(menu_context.breadcrumb)
    print(f"{Colors.BLUE}{breadcrumb}{Colors.ENDC}")
    
    # Display current feed if selected
    if menu_context.current_feed_title:
        print(f"{Colors.YELLOW}Current Feed: {menu_context.current_feed_title} ({menu_context.current_feed_id}){Colors.ENDC}")
    print("=" * columns)

def display_shortcuts() -> None:
    """Display available navigation shortcuts"""
    print(f"\n{Colors.GREEN}Navigation Shortcuts:{Colors.ENDC}")
    print("b: Back to previous menu | h: Home menu | q: Quit")

def display_main_menu(menu_context: MenuContext) -> None:
    """Display the main menu options."""
    display_header(menu_context)
    print("\nOptions:")
    print(f"{Colors.BOLD}1.{Colors.ENDC} View and Manage Existing Feeds")
    print(f"{Colors.BOLD}2.{Colors.ENDC} Create a New Threat Feed")
    print(f"{Colors.BOLD}3.{Colors.ENDC} Exit")
    display_shortcuts()

def display_feed_menu(menu_context: MenuContext) -> None:
    """Display the feed management menu options."""
    display_header(menu_context)
    print("\nFeed Management Options:")
    print(f"{Colors.BOLD}1.{Colors.ENDC} List All Feeds")
    print(f"{Colors.BOLD}2.{Colors.ENDC} View Feed Details")
    print(f"{Colors.BOLD}3.{Colors.ENDC} Update Feed Content")
    print(f"{Colors.BOLD}4.{Colors.ENDC} Delete Feed")
    print(f"{Colors.BOLD}5.{Colors.ENDC} Return to Main Menu")
    display_shortcuts()

def list_feeds(access_token: str, menu_context: MenuContext) -> None:
    """List all existing feeds."""
    menu_context.push_breadcrumb("Feed List")
    while True:
        display_header(menu_context)
        feed_guids = get_feed_guids(access_token)
        
        if feed_guids:
            print(f"\n{Colors.BOLD}Existing threat feeds:{Colors.ENDC}")
            for i, guid in enumerate(feed_guids, 1):
                metadata = get_feed_metadata(guid, access_token)
                if metadata:
                    print(f"{Colors.BOLD}{i}.{Colors.ENDC} {Colors.BLUE}{metadata['title']}{Colors.ENDC}")
                    print(f"   Feed ID: {guid}")
                    print(f"   Elements Count: {metadata['elementsCount']}")
                    print(f"   Last Updated: {metadata['elementsUploadedAt']}")
                    print("   " + "-" * 50)
        else:
            print(f"{Colors.YELLOW}No existing threat feeds found.{Colors.ENDC}")
        
        print("\nOptions:")
        print("1. Refresh list")
        print("2. Return to previous menu")
        display_shortcuts()
        
        choice = input("\nEnter your choice (1-2) or shortcut: ")
        should_exit, should_return = handle_navigation_input(choice, menu_context)
        
        if should_exit:
            sys.exit(0)
        elif should_return or choice == "2":
            menu_context.pop_breadcrumb()
            break
        elif choice == "1":
            continue
        else:
            print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
            time.sleep(1)

def view_feed_details(access_token: str, menu_context: MenuContext) -> None:
    """View details of a specific feed with options to add or remove domains."""
    feed_id = select_feed(access_token)
    if not feed_id:
        return

    menu_context.push_breadcrumb("Feed Details")
    while True:
        metadata = get_feed_metadata(feed_id, access_token)
        if not metadata:
            print(f"{Colors.RED}Unable to retrieve feed metadata.{Colors.ENDC}")
            menu_context.pop_breadcrumb()
            return

        menu_context.update_feed(feed_id, metadata['title'])
        display_header(menu_context)
        
        print(f"\n{Colors.BOLD}Feed Details:{Colors.ENDC}")
        print(f"{Colors.BLUE}Title:{Colors.ENDC} {metadata['title']}")
        print(f"{Colors.BLUE}Description:{Colors.ENDC} {metadata['description']}")
        print(f"{Colors.BLUE}Feed Type:{Colors.ENDC} {metadata['feedType']}")
        print(f"{Colors.BLUE}Elements Count:{Colors.ENDC} {metadata['elementsCount']}")
        print(f"{Colors.BLUE}Last Updated:{Colors.ENDC} {metadata['elementsUploadedAt']}")
        
        print(f"\n{Colors.BOLD}Options:{Colors.ENDC}")
        print(f"{Colors.BOLD}1.{Colors.ENDC} View domains")
        print(f"{Colors.BOLD}2.{Colors.ENDC} Add domain")
        print(f"{Colors.BOLD}3.{Colors.ENDC} Remove domain")
        print(f"{Colors.BOLD}4.{Colors.ENDC} Return to previous menu")
        display_shortcuts()
        
        choice = input("\nEnter your choice (1-4) or shortcut: ")
        should_exit, should_return = handle_navigation_input(choice, menu_context)
        
        if should_exit:
            sys.exit(0)
        elif should_return or choice == "4":
            menu_context.update_feed(None, None)
            menu_context.pop_breadcrumb()
            break
        elif choice == '1':
            view_domains(feed_id, access_token)
        elif choice == '2':
            add_domain_to_feed(feed_id, access_token)
        elif choice == '3':
            remove_domain_from_feed(feed_id, access_token)
        else:
            print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
            time.sleep(1)

def view_domains(feed_id: str, access_token: str) -> None:
    """View domains in the feed with pagination."""
    domains = get_threat_domains(feed_id, access_token)
    if not domains:
        print(f"{Colors.YELLOW}No domains found in this feed.{Colors.ENDC}")
        time.sleep(1)
        return

    page_size = 20
    current_page = 0
    total_pages = (len(domains) + page_size - 1) // page_size
    columns, _ = get_terminal_size()

    while True:
        print("\n" + "=" * columns)
        print(f"{Colors.BOLD}Threat Domains{Colors.ENDC}")
        print("=" * columns)
        
        start = current_page * page_size
        end = min(start + page_size, len(domains))
        
        for i, domain in enumerate(domains[start:end], start=start+1):
            if i % 2 == 0:
                print(f"{Colors.BLUE}{i}.{Colors.ENDC} {domain}")
            else:
                print(f"{Colors.BOLD}{i}.{Colors.ENDC} {domain}")
        
        print("\n" + "-" * columns)
        print(f"Showing {Colors.GREEN}{start+1}-{end}{Colors.ENDC} of {Colors.GREEN}{len(domains)}{Colors.ENDC} domains")
        print(f"Page {Colors.YELLOW}{current_page + 1}{Colors.ENDC} of {Colors.YELLOW}{total_pages}{Colors.ENDC}")
        print("\nNavigation:")
        print("n: Next page | p: Previous page | q: Return to previous menu")
        display_shortcuts()
        
        choice = input("\nEnter your choice: ").lower()
        
        if choice == 'n' and current_page < total_pages - 1:
            current_page += 1
        elif choice == 'p' and current_page > 0:
            current_page -= 1
        elif choice == 'q' or choice == 'b':
            break
        elif choice == 'h':
            break
        else:
            print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
            time.sleep(1)

def select_feed(access_token: str) -> Optional[str]:
    """Helper function to select a feed from the list."""
    feed_guids = get_feed_guids(access_token)
    if not feed_guids:
        print(f"{Colors.YELLOW}No existing threat feeds found.{Colors.ENDC}")
        time.sleep(1)
        return None

    columns, _ = get_terminal_size()
    print("\n" + "=" * columns)
    print(f"{Colors.BOLD}Select a Feed{Colors.ENDC}")
    print("=" * columns)
    
    for i, guid in enumerate(feed_guids, 1):
        metadata = get_feed_metadata(guid, access_token)
        if metadata:
            print(f"\n{Colors.BOLD}{i}.{Colors.ENDC} {Colors.BLUE}{metadata['title']}{Colors.ENDC}")
            print(f"   Feed ID: {guid}")
            print(f"   Elements Count: {metadata['elementsCount']}")
            print("   " + "-" * 50)

    print("\nNavigation shortcuts available (b: Back, q: Quit)")
    while True:
        try:
            choice = input(f"\nEnter feed number (1-{len(feed_guids)}) or shortcut: ")
            if choice.lower() in ['b', 'q']:
                return None
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(feed_guids):
                return feed_guids[choice_num - 1]
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
                time.sleep(1)
        except ValueError:
            if choice.lower() in ['b', 'q']:
                return None
            print(f"{Colors.RED}Please enter a valid number.{Colors.ENDC}")
            time.sleep(1)
def create_new_feed(access_token: str) -> None:
    """Create a new threat feed."""
    columns, _ = get_terminal_size()
    print("\n" + "=" * columns)
    print(f"{Colors.BOLD}Create a New Threat Feed{Colors.ENDC}")
    print("=" * columns)
    
    print(f"\n{Colors.BLUE}Feed Type:{Colors.ENDC}")
    print("Currently supported: CSV")
    feed_type = input("Enter the feed type: ")
    
    print(f"\n{Colors.BLUE}Feed Title:{Colors.ENDC}")
    print("Must be between 8 and 255 characters")
    title = input("Enter the feed title: ")
    
    print(f"\n{Colors.BLUE}Feed Description:{Colors.ENDC}")
    print("Must be between 8 and 255 characters")
    description = input("Enter the feed description: ")
    
    print(f"\n{Colors.YELLOW}Creating feed...{Colors.ENDC}")
    feed_id = create_threat_feed(feed_type, title, description, access_token)
    
    if feed_id:
        print(f"\n{Colors.GREEN}New threat feed created successfully!{Colors.ENDC}")
        print(f"{Colors.BLUE}Feed ID:{Colors.ENDC} {feed_id}")
        
        add_domains = input(f"\n{Colors.YELLOW}Would you like to add a domain to this feed now? (y/n):{Colors.ENDC} ").lower()
        if add_domains == 'y':
            add_domain_to_feed(feed_id, access_token)
    else:
        print(f"\n{Colors.RED}Failed to create feed. Please check the requirements and try again.{Colors.ENDC}")
        time.sleep(2)

def add_domain_to_feed(feed_id: str, access_token: str) -> None:
    """Add a domain to the feed."""
    columns, _ = get_terminal_size()
    print("\n" + "=" * columns)
    print(f"{Colors.BOLD}Add Domain to Feed{Colors.ENDC}")
    print("=" * columns)
    
    print(f"\n{Colors.BLUE}Domain:{Colors.ENDC}")
    print("Enter the domain to add (e.g., example.com)")
    domain = input("Domain: ")
    
    print(f"\n{Colors.BLUE}Action:{Colors.ENDC}")
    print("add: Add domain to feed")
    print("delete: Remove domain from feed")
    action = input("Enter action: ").lower()
    
    if action not in ['add', 'delete']:
        print(f"\n{Colors.RED}Invalid action. Please use add or delete.{Colors.ENDC}")
        time.sleep(1)
        return

    print(f"\n{Colors.YELLOW}Processing...{Colors.ENDC}")
    upload_threat_domains(feed_id, [(domain, action)], access_token, "INCREMENTAL")
    print(f"\n{Colors.GREEN}Domain '{domain}' has been {action}ed to the feed.{Colors.ENDC}")
    time.sleep(1)

def remove_domain_from_feed(feed_id: str, access_token: str) -> None:
    """Remove a domain from the feed."""
    columns, _ = get_terminal_size()
    print("\n" + "=" * columns)
    print(f"{Colors.BOLD}Remove Domain from Feed{Colors.ENDC}")
    print("=" * columns)
    
    print(f"\n{Colors.BLUE}Domain:{Colors.ENDC}")
    print("Enter the domain to remove (e.g., example.com)")
    domain = input("Domain: ")
    
    print(f"\n{Colors.YELLOW}Processing...{Colors.ENDC}")
    upload_threat_domains(feed_id, [(domain, "delete")], access_token, "INCREMENTAL")
    print(f"\n{Colors.GREEN}Domain '{domain}' has been removed from the feed.{Colors.ENDC}")
    time.sleep(1)

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

def handle_navigation_input(choice: str, menu_context: MenuContext) -> Tuple[bool, bool]:
    """Handle navigation shortcuts
    Returns: (should_exit, should_return)
    """
    if choice.lower() == 'b':
        menu_context.pop_breadcrumb()
        return False, True
    elif choice.lower() == 'h':
        menu_context.breadcrumb = ["Main Menu"]
        menu_context.update_feed(None, None)
        return False, True
    elif choice.lower() == 'q':
        print(f"\n{Colors.GREEN}Thank you for using the Threat Feed Management System. Goodbye!{Colors.ENDC}")
        return True, False
    return False, False

def manage_feeds(access_token: str, menu_context: MenuContext) -> None:
    """Manage existing feeds."""
    menu_context.push_breadcrumb("Feed Management")
    
    while True:
        display_feed_menu(menu_context)
        choice = input("\nEnter your choice (1-5) or shortcut: ")
        
        should_exit, should_return = handle_navigation_input(choice, menu_context)
        if should_exit:
            sys.exit(0)
        elif should_return:
            return

        if choice == "1":
            list_feeds(access_token, menu_context)
        elif choice == "2":
            view_feed_details(access_token, menu_context)
        elif choice == "3":
            feed_id = select_feed(access_token)
            if feed_id:
                source_url = input("Enter the source URL for updating feed content: ")
                print("\nUpload Types:")
                print("1. OVERWRITE - Replace all domains")
                print("2. INCREMENTAL - Add new domains")
                upload_type = input("Enter upload type (1-2, default: 1): ")
                upload_type = "INCREMENTAL" if upload_type == "2" else "OVERWRITE"
                update_feed_content(feed_id, source_url, access_token, upload_type)
                print(f"\n{Colors.GREEN}Feed content updated successfully!{Colors.ENDC}")
                time.sleep(1)
        elif choice == "4":
            feed_id = select_feed(access_token)
            if feed_id:
                confirm = input(f"{Colors.RED}Are you sure you want to delete the feed with ID {feed_id}? (y/n): {Colors.ENDC}").lower()
                if confirm == 'y':
                    delete_threat_feed(feed_id, access_token)
                    print(f"\n{Colors.GREEN}Feed deleted successfully!{Colors.ENDC}")
                    time.sleep(1)
        elif choice == "5":
            menu_context.pop_breadcrumb()
            break
        else:
            print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
            time.sleep(1)

def main() -> None:
    """Main function to run the threat feed management script."""
    args = parse_args()
    api_key = load_api_key()
    if not api_key:
        logger.error("Please provide a valid API key in the 'api_key.txt' file.")
        return

    access_token = get_bearer(api_key)
    if not access_token:
        logger.error("Failed to retrieve access token. Please check your API key.")
        return

    # Handle command line arguments
    if args.list_feeds:
        list_feeds(access_token, MenuContext())
    elif args.create_feed:
        feed_type, title, description = args.create_feed
        create_threat_feed(feed_type, title, description, access_token)
    elif args.view_feed:
        metadata = get_feed_metadata(args.view_feed, access_token)
        if metadata:
            print(json.dumps(metadata, indent=2))
    elif args.update_feed:
        feed_id, source_url = args.update_feed
        update_feed_content(feed_id, source_url, access_token, args.upload_type)
    elif args.delete_feed:
        delete_threat_feed(args.delete_feed, access_token)
    elif args.add_domain:
        feed_id, domain = args.add_domain
        upload_threat_domains(feed_id, [(domain, "add")], access_token, "INCREMENTAL")
    elif args.remove_domain:
        feed_id, domain = args.remove_domain
        upload_threat_domains(feed_id, [(domain, "delete")], access_token, "INCREMENTAL")
    else:
        # If no arguments are provided, run the interactive menu
        menu_context = MenuContext()
        
        while True:
            display_main_menu(menu_context)
            choice = input("\nEnter your choice (1-3) or shortcut: ")
            
            should_exit, _ = handle_navigation_input(choice, menu_context)
            if should_exit:
                break

            if choice == "1":
                manage_feeds(access_token, menu_context)
            elif choice == "2":
                menu_context.push_breadcrumb("Create New Feed")
                create_new_feed(access_token)
                menu_context.pop_breadcrumb()
            elif choice == "3":
                print(f"\n{Colors.GREEN}Thank you for using the Threat Feed Management System. Goodbye!{Colors.ENDC}")
                break
            else:
                print(f"{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
                time.sleep(1)

if __name__ == "__main__":
    main()
