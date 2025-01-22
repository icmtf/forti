from pyinet.common.easynet import EasyNet
import os
import csv
from datetime import datetime, timedelta
from typing import List, Dict

def get_easynet_inventory():
    # Initialize EasyNet client with environment variables
    easynet = EasyNet(
        apigee_base_uri=os.environ.get('APIGEE_BASE_URI'),
        apigee_token_endpoint=os.environ.get('APIGEE_TOKEN_ENDPOINT'),
        apigee_easynet_endpoint=os.environ.get('APIGEE_EASYNET_ENDPOINT'),
        apigee_certificate=os.environ.get('CYBERARK_CERTIFICATE'),
        apigee_key=os.environ.get('CYBERARK_KEY'),
        easynet_key=os.environ.get('EASYNET_KEY'),
        easynet_secret=os.environ.get('EASYNET_SECRET'),
        ca_requests_bundle=os.environ.get('REQUESTS_CA_BUNDLE')
    )
    
    return easynet.get_devices(size=10, vendor="Fortinet")

def save_comparison_to_csv(comparison_data: List[Dict], output_file: str = None):
    """
    Save comparison data to CSV file
    
    Args:
        comparison_data (List[Dict]): List of comparison records
        output_file (str): Output file path. If None, generates timestamped filename
    """
    # Define the fieldnames for the CSV
    fieldnames = [
        'IP', 'IP_INET', 'IP_EN',
        'Hostname', 'Hostname_INET', 'Hostname_EN',
        'Serial', 'Serial_INET', 'Serial_EN',
        'Status', 'Last_Update', 'Vendor', 'Date_Status'
    ]
    
    # Process Date Status for each record before saving
    for record in comparison_data:
        if record['Last_Update']:
            try:
                update_date = datetime.strptime(record['Last_Update'], '%Y-%m-%d')
                week_ago = datetime.now() - timedelta(days=7)
                record['Date_Status'] = 'OK' if update_date > week_ago else 'WARNING'
            except ValueError:
                record['Date_Status'] = 'ERROR'
        else:
            record['Date_Status'] = 'N/A'
    
    if output_file is None:
        # Get timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"forti_comparison_{timestamp}.csv"
    else:
        filename = output_file
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    
    # Write to CSV
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(comparison_data)
        
    return filename