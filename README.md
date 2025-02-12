# Improved Threat Feed Management System

This system allows you to manage threat feeds using the Lookout API. It provides a user-friendly interface for creating, viewing, updating, and deleting threat feeds, as well as managing the domains within those feeds.

## Features

- Create new threat feeds
- List existing threat feeds
- View feed details
- Update feed content from online sources
- Delete threat feeds
- Add and remove domains from feeds
- User-friendly command-line interface with color coding
- Command-line argument support for automation
- Pagination for viewing domains
- Enhanced error handling and logging
- Input validation for user inputs
- Breadcrumb navigation
- Universal navigation shortcuts

## Prerequisites

- Python 3.x
- pip (Python package installer)

## Installation

1. Install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Create an `api_key.txt` file in the root directory of the project and paste your Lookout API key into it:

   ```
   echo "your-api-key-here" > api_key.txt
   ```

## Usage

### Interactive Mode

To run the Threat Feed Management System in interactive mode, execute the following command in your terminal:

```
python improved_threat_feed_management.py
```

The system will present you with a menu-driven interface with the following features:

- Color-coded interface for better readability
- Breadcrumb navigation showing your current location
- Universal navigation shortcuts (b: Back, h: Home, q: Quit)
- Context-aware menus showing current feed information

Main menu options:
1. View and Manage Existing Feeds
2. Create a New Threat Feed
3. Exit

### Command-line Arguments

The script supports command-line arguments for automation:

- `--list-feeds`: List all feeds
- `--create-feed TYPE TITLE DESCRIPTION`: Create a new feed
- `--view-feed FEED_ID`: View details of a specific feed
- `--update-feed FEED_ID SOURCE_URL`: Update feed content
- `--upload-type {INCREMENTAL,OVERWRITE}`: Specify upload type for updating feed content (default: OVERWRITE)
- `--delete-feed FEED_ID`: Delete a feed
- `--add-domain FEED_ID DOMAIN`: Add a domain to a feed
- `--remove-domain FEED_ID DOMAIN`: Remove a domain from a feed

Example:
```bash
# List all feeds
python improved_threat_feed_management.py --list-feeds

# Create a new feed
python improved_threat_feed_management.py --create-feed CSV "My New Feed" "Description of my new feed"

# Update feed content with INCREMENTAL mode
python improved_threat_feed_management.py --update-feed feed-id-123 https://example.com/threats.txt --upload-type INCREMENTAL
```

## Feed Content Upload Types

The system supports two types of feed content updates:

### 1. OVERWRITE Mode (Default)
- Replaces all existing domains in the feed
- Uses a simple CSV format with a single 'domain' column
- Example CSV:
  ```
  domain
  example.com
  malicious.com
  ```

### 2. INCREMENTAL Mode
- Adds or removes specific domains from the feed
- Uses CSV format with 'domain' and 'action' columns
- Supported actions: 'add' or 'delete'
- Example CSV:
  ```
  domain,action
  example.com,add
  malicious.com,delete
  ```

## Enhancements

1. **Improved Navigation**:
   - Added breadcrumb navigation showing current location
   - Implemented universal navigation shortcuts
   - Added context-aware headers showing current feed
   - Enhanced visual hierarchy with color coding

2. **Feed Content Management**:
   - Added support for INCREMENTAL and OVERWRITE upload types
   - Improved CSV format handling according to API specifications
   - Enhanced domain processing with better validation
   - Added clear progress indicators for content updates

3. **User Interface**:
   - Added color coding for better readability
   - Enhanced visual feedback for operations
   - Improved error messages and warnings
   - Added operation status indicators
   - Enhanced menu organization and flow

4. **Command-line Improvements**:
   - Added upload type control via command line
   - Enhanced argument handling
   - Improved feedback for command-line operations

5. **Other Improvements**:
   - Enhanced error handling and validation
   - Added confirmation prompts for critical actions
   - Improved progress indicators
   - Added support for interactive domain management

## Troubleshooting

If you encounter any issues:

1. Ensure your API key is correct and properly saved in the `api_key.txt` file.
2. Check your internet connection, as the script needs to communicate with the Lookout API.
3. Verify that you have the required Python version and all dependencies installed.
4. Check the CSV format matches the selected upload type (INCREMENTAL or OVERWRITE).

## Navigation Shortcuts

The following shortcuts are available throughout the application:

- `b`: Go back to the previous menu
- `h`: Return to the home/main menu
- `q`: Quit the application

## Contributing

Contributions to improve the Threat Feed Management System are welcome. Please feel free to submit pull requests or open issues to discuss proposed changes or report bugs.

## Author

Frank Gravato (Lookout-SE)
