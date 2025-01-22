from rich.console import Console
from rich.table import Table
from common import get_inet_inventory
from pyinet.common.easynet import EasyNet
import logging
import os

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    
    return easynet.get_devices()

def main():
    # Initialize Rich console
    console = Console()

    # Get inventory data from INET
    inet_inventory = get_inet_inventory(
        vendor="fortinet",
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

    # Get and print EasyNet data
    try:
        easynet_devices = get_easynet_inventory()
        
        # Filter only Fortinet devices
        fortinet_devices = [device for device in easynet_devices if device.get("vendor", "").lower() == "fortinet"]
        
        # Create EasyNet table
        easynet_table = Table(title="EasyNet Inventory - Fortinet Devices")
        
        # Add columns for EasyNet według nowej specyfikacji
        easynet_table.add_column("IP Address", style="cyan")
        easynet_table.add_column("Hostname", style="green")
        easynet_table.add_column("Vendor", style="yellow")
        easynet_table.add_column("Country", style="blue")
        easynet_table.add_column("Zone", style="magenta")
        easynet_table.add_column("Serial", style="red")
        
        # Add rows for EasyNet
        for device in fortinet_devices:
            try:
                row_data = [
                    str(device.get("ip") or "N/A"),
                    str(device.get("hostname") or "N/A"),
                    str(device.get("vendor") or "N/A"),
                    str(device.get("country") or "N/A"),
                    str(device.get("zone") or "N/A"),
                    str(device.get("serial_number") or "N/A")
                ]
                easynet_table.add_row(*row_data)
            except Exception as e:
                logger.error(f"Error processing EasyNet device: {device}")
                logger.error(f"Error details: {str(e)}")
                continue

        # Print EasyNet table
        console.print(easynet_table)

    except Exception as e:
        logger.error(f"Error getting EasyNet inventory: {str(e)}")

if __name__ == "__main__":
    main()
