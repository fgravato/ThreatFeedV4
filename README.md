# Threat Feed Management System

This system allows you to manage threat feeds using the Lookout API. It provides a user-friendly interface for creating, viewing, updating, and deleting threat feeds.

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

To run the Threat Feed Management System, execute the following command in your terminal:

```
python main.py
```

The system will present you with a menu-driven interface. Here are the main options:

1. View and Manage Existing Feeds
2. Create a New Threat Feed
3. Exit

### View and Manage Existing Feeds

This option allows you to:

- List all existing feeds
- View details of a specific feed
- Update feed content from a source URL
- Delete a feed

### Create a New Threat Feed

This option guides you through the process of creating a new threat feed. You'll be prompted to enter:

- Feed type (e.g., CSV)
- Feed title
- Feed description

After creating the feed, you'll have the option to add domains to it immediately.


## Troubleshooting

If you encounter any issues:

1. Ensure your API key is correct and properly saved in the `api_key.txt` file.
2. Check your internet connection, as the script needs to communicate with the Lookout API.
3. Verify that you have the required Python version and all dependencies installed.

## Contributing

Contributions to improve the Threat Feed Management System are welcome. Please feel free to submit pull requests or open issues to discuss proposed changes or report bugs.

