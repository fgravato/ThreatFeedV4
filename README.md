# Improved Threat Feed Management System

This system allows you to manage threat feeds using the Lookout API. It provides a user-friendly interface for creating, viewing, updating, and deleting threat feeds, as well as managing the domains within those feeds.

## Features

- Create new threat feeds
- List existing threat feeds
- View feed details
- Update feed content from online sources
- Delete threat feeds
- Add and remove domains from feeds
- User-friendly command-line interface
- Command-line argument support for automation
- Pagination for viewing domains
- Enhanced error handling and logging
- Input validation for user inputs

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

The system will present you with a menu-driven interface. Here are the main options:

1. View and Manage Existing Feeds
2. Create a New Threat Feed
3. Exit

### Command-line Arguments

The script now supports command-line arguments for automation:

- `--list-feeds`: List all feeds
- `--create-feed TYPE TITLE DESCRIPTION`: Create a new feed
- `--view-feed FEED_ID`: View details of a specific feed
- `--update-feed FEED_ID SOURCE_URL`: Update feed content
- `--delete-feed FEED_ID`: Delete a feed
- `--add-domain FEED_ID DOMAIN`: Add a domain to a feed
- `--remove-domain FEED_ID DOMAIN`: Remove a domain from a feed

Example:
```
python improved_threat_feed_management.py --list-feeds
python improved_threat_feed_management.py --create-feed CSV "My New Feed" "Description of my new feed"
```

## Enhancements

1. **Command-line argument support**: Added for automation purposes using the `argparse` module.
2. **Pagination**: Implemented for viewing domains in large datasets.
3. **Enhanced error handling**: Improved error messages and logging throughout the script.
4. **Input validation**: Added more rigorous input validation for user inputs.
5. **Confirmation prompts**: Added for critical actions like deleting feeds.
6. **Progress indicators**: Implemented for operations that might take some time.
7. **Interactive mode for adding domains**: Users can now add multiple domains without returning to the main menu.

## Troubleshooting

If you encounter any issues:

1. Ensure your API key is correct and properly saved in the `api_key.txt` file.
2. Check your internet connection, as the script needs to communicate with the Lookout API.
3. Verify that you have the required Python version and all dependencies installed.

## Contributing

Contributions to improve the Threat Feed Management System are welcome. Please feel free to submit pull requests or open issues to discuss proposed changes or report bugs.

## Author

Frank Gravato (Lookout-SE)

