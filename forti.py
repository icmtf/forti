from rich.console import Console
from rich.table import Table
from rich.text import Text
from common import get_inet_inventory
from forti_common import get_easynet_inventory, save_comparison_to_csv
from datetime import datetime, timedelta
from typing import Dict, List
import logging
import os
import argparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def compare_inventories(inet_devices: List[Dict], easynet_devices: List[Dict]) -> List[Dict]:
    result = []
    
    # Create dictionaries for faster lookup
    inet_by_ip = {dev['adminip']: dev for dev in inet_devices}
    easynet_by_ip = {dev['ip']: dev for dev in easynet_devices}
    
    # Compare all devices
    all_ips = set(inet_by_ip.keys()) | set(easynet_by_ip.keys())
    
    for ip in all_ips:
        inet_dev = inet_by_ip.get(ip)
        easynet_dev = easynet_by_ip.get(ip)
        
        record = {
            'IP': None, 'IP_INET': None, 'IP_EN': None,
            'Hostname': None, 'Hostname_INET': None, 'Hostname_EN': None,
            'Serial': None, 'Serial_INET': None, 'Serial_EN': None,
            'Status': None,
            'Last_Update': None,
            'Vendor': None,
            'Date_Status': None
        }
        
        if inet_dev and easynet_dev:
            # Device exists in both inventories
            matches = 0
            # Check IP (always true in this case)
            matches += 1
            # Check Hostname (case-insensitive)
            if inet_dev['hostname'].lower() == easynet_dev['hostname'].lower():
                matches += 1
            # Check Serial
            if inet_dev['serial'] == easynet_dev['serial_number']:
                matches += 1
            
            record.update({
                'IP': ip,
                'Hostname': inet_dev['hostname'].lower() if inet_dev['hostname'].lower() == easynet_dev['hostname'].lower() else None,
                'Serial': inet_dev['serial'] if inet_dev['serial'] == easynet_dev['serial_number'] else None,
                'Last_Update': easynet_dev['last_update'],
                'Vendor': easynet_dev['vendor']
            })
            
            # Set status based on matches
            if matches == 3:
                record['Status'] = 'OK'
            elif matches == 2:
                record['Status'] = 'Diff'
            else:
                record['Status'] = 'KO'
                
            # Add differences if any exist
            if inet_dev['hostname'].lower() != easynet_dev['hostname'].lower():
                if inet_dev['hostname'].lower() == easynet_dev['hostname'].lower():
                    record['Hostname_INET'] = f'({inet_dev["hostname"]}).lower'
                    record['Hostname_EN'] = f'({easynet_dev["hostname"]}).lower'
                else:
                    record['Hostname_INET'] = inet_dev['hostname']
                    record['Hostname_EN'] = easynet_dev['hostname']
            if inet_dev['serial'] != easynet_dev['serial_number']:
                record['Serial_INET'] = inet_dev['serial']
                record['Serial_EN'] = easynet_dev['serial_number']
                
        else:
            # Device exists only in one inventory
            if inet_dev:
                record.update({
                    'IP_INET': ip,
                    'Hostname_INET': inet_dev['hostname'],
                    'Serial_INET': inet_dev['serial']
                })
            else:
                record.update({
                    'IP_EN': ip,
                    'Hostname_EN': easynet_dev['hostname'],
                    'Serial_EN': easynet_dev['serial_number'],
                    'Last_Update': easynet_dev['last_update'],
                    'Vendor': easynet_dev['vendor']
                })
        
        result.append(record)
    
    # Sort results
    sorted_result = sorted(result, key=lambda x: (
        not bool(x['IP']),
        not bool(x['IP_EN']),
        bool(x['IP_INET'])
    ))
    
    return sorted_result

def create_comparison_table(comparison_data: List[Dict]) -> Table:
    table = Table(title="Inventory Comparison")
    
    # Add columns with appropriate styles
    table.add_column("#", style="bright_white")
    table.add_column("IP", style="bright_yellow")
    table.add_column("IP_INET", style="red3")
    table.add_column("IP_EN", style="orange1")
    table.add_column("Hostname", style="bright_green")
    table.add_column("Hostname_INET", style="green4")
    table.add_column("Hostname_EN", style="green")
    table.add_column("Serial", style="bright_cyan")
    table.add_column("Serial_INET", style="blue3")
    table.add_column("Serial_EN", style="bright_blue")
    table.add_column("Status", style="white")
    table.add_column("Last Update", style="white")
    table.add_column("Vendor", style="yellow")
    table.add_column("Date Status", style="white")
    
    for idx, record in enumerate(comparison_data):
        # Check date for Last Update
        last_update_style = "white"
        if record['Last_Update']:
            try:
                update_date = datetime.strptime(record['Last_Update'], '%Y-%m-%d')
                week_ago = datetime.now() - timedelta(days=7)
                last_update_style = "green" if update_date > week_ago else "yellow1"
            except ValueError:
                last_update_style = "white"
        
        # Calculate Date Status
        date_status = "N/A"
        date_status_style = "white"
        if record['Last_Update']:
            try:
                update_date = datetime.strptime(record['Last_Update'], '%Y-%m-%d')
                week_ago = datetime.now() - timedelta(days=7)
                if update_date > week_ago:
                    date_status = "OK"
                    date_status_style = "green"
                else:
                    date_status = "WARNING"
                    date_status_style = "yellow1"
            except ValueError:
                date_status = "ERROR"
                date_status_style = "red"

        # Set style for Status
        status_style = {
            'OK': 'green',
            'Diff': 'yellow',
            'KO': 'red'
        }.get(record['Status'], 'white')
        
        table.add_row(
            str(idx + 1),
            str(record['IP'] or ''),
            str(record['IP_INET'] or ''),
            str(record['IP_EN'] or ''),
            str(record['Hostname'] or ''),
            str(record['Hostname_INET'] or ''),
            str(record['Hostname_EN'] or ''),
            str(record['Serial'] or ''),
            str(record['Serial_INET'] or ''),
            str(record['Serial_EN'] or ''),
            Text(str(record['Status'] or ''), style=status_style),
            Text(str(record['Last_Update'] or ''), style=last_update_style),
            str(record['Vendor'] or ''),
            Text(date_status, style=date_status_style)
        )
    
    return table

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Compare Fortinet device inventories')
    parser.add_argument('--csv', nargs='?', const=True, help='Export comparison data to CSV. Optional path can be provided')
    args = parser.parse_args()

    # Initialize Rich console
    console = Console()

    # Get inventory data from INET
    inet_inventory = get_inet_inventory(
        # vendor="fortinet",
        status="active",
        selectcol=[
            "adminip",
            "hostname",
            "vendor",
            "country",
            "role",
            "serial"
        ]
    )

    try:
        # Get EasyNet data
        easynet_devices = get_easynet_inventory()
        
        # Create and process comparison data
        comparison_data = compare_inventories(
            inet_inventory.get("results", []),
            easynet_devices
        )

        if args.csv:
            # Save to CSV if --csv flag is provided
            output_file = save_comparison_to_csv(comparison_data, args.csv if isinstance(args.csv, str) else None)
            logger.info(f"Comparison data has been exported to {output_file}")
        else:
            # Display tables as before
            # Create and print INET table
            inet_table = Table(title="INET Inventory - Fortinet Devices")
            
            # Add columns for INET
            inet_table.add_column("Admin IP", style="cyan")
            inet_table.add_column("Hostname", style="green")
            inet_table.add_column("Vendor", style="yellow")
            inet_table.add_column("Country", style="blue")
            inet_table.add_column("Role", style="magenta")
            inet_table.add_column("Serial", style="red")

            # Add rows for INET
            for device in inet_inventory.get("results", []):
                try:
                    row_data = [
                        str(device.get("adminip") or "N/A"),
                        str(device.get("hostname") or "N/A"),
                        str(device.get("vendor") or "N/A"),
                        str(device.get("country") or "N/A"),
                        str(device.get("role") or "N/A"),
                        str(device.get("serial") or "N/A")
                    ]
                    inet_table.add_row(*row_data)
                except Exception as e:
                    logger.error(f"Error processing INET device: {device}")
                    logger.error(f"Error details: {str(e)}")
                    continue

            # Print INET table
            console.print(inet_table)
            console.print()  # Empty line for separation
            
            # Create EasyNet table
            easynet_table = Table(title="EasyNet Inventory - Fortinet Devices")
            
            # Add columns for EasyNet
            easynet_table.add_column("IP Address", style="cyan")
            easynet_table.add_column("Hostname", style="green")
            easynet_table.add_column("Vendor", style="yellow")
            easynet_table.add_column("Country", style="blue")
            easynet_table.add_column("Zone", style="magenta")
            easynet_table.add_column("Serial", style="red")
            easynet_table.add_column("Last Updated", style="white")
            
            # Add rows for EasyNet
            for device in easynet_devices:
                try:
                    row_data = [
                        str(device.get("ip") or "N/A"),
                        str(device.get("hostname") or "N/A"),
                        str(device.get("vendor") or "N/A"),
                        str(device.get("country") or "N/A"),
                        str(device.get("zone") or "N/A"),
                        str(device.get("serial_number") or "N/A"),
                        str(device.get("last_update") or "N/A")
                    ]
                    easynet_table.add_row(*row_data)
                except Exception as e:
                    logger.error(f"Error processing EasyNet device: {device}")
                    logger.error(f"Error details: {str(e)}")
                    continue

            # Print EasyNet table
            console.print(easynet_table)
            console.print()  # Empty line for separation

            # Create and print comparison table
            comparison_table = create_comparison_table(comparison_data)
            console.print(comparison_table)

    except Exception as e:
        logger.error(f"Error getting EasyNet inventory: {str(e)}")

if __name__ == "__main__":
    main()