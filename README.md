
Description
This script fetches events from a remote API and inserts them into a local database and handles errors and duplicates.

API Reference
The script uses the following APIs:

fetch_events: Fetches events from the remote API.
insert_data:  Inserts events into the local database.

Contributing
To contribute to the project, fork the repository and submit a pull request. Please include a description of the changes and any relevant tests.

License
This project is licensed under the MIT License. See LICENSE.txt for details.

Acknowledgements
This project uses the following external libraries:

requests: for making API requests
tqdm:     for displaying the progress bar

Contact Information
For questions or issues, contact Jvnunes at [Your Email].

Example Use Case
To import events from a remote API into a local database, run the following command:

Tests:
    Time Based:
        168763 events DB:
            continue_import_events: 2:14 minutes
            import_events_index_timestamp