from rich.console import Console
from rich.table import Table
from common import get_inet_inventory
import logging

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    # Initialize Rich console
    console = Console()

    # Get inventory data from INET with filter
    inventory = get_inet_inventory(
        vendor="fortinet",  # dodajemy filtr dla testów
        status="active",    # tylko aktywne urządzenia
        selectcol=[
            "adminip",
            "hostname",
            "vendor",
            "country",
            "role",
            "serial"
        ]
    )

    # Log the received data structure
    logger.info(f"Received inventory data: {inventory}")
    
    if not inventory or 'results' not in inventory:
        logger.error("No results found in inventory data")
        return

    # Create and configure table
    table = Table(title="INET Inventory - Fortinet Devices")
    
    # Add columns
    table.add_column("Admin IP", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("Vendor", style="yellow")
    table.add_column("Country", style="blue")
    table.add_column("Role", style="magenta")
    table.add_column("Serial", style="red")

    # Add rows with detailed error handling
    for device in inventory.get("results", []):
        try:
            row_data = [
                str(device.get("adminip") or "N/A"),
                str(device.get("hostname") or "N/A"),
                str(device.get("vendor") or "N/A"),
                str(device.get("country") or "N/A"),
                str(device.get("role") or "N/A"),
                str(device.get("serial") or "N/A")
            ]
            logger.debug(f"Adding row: {row_data}")
            table.add_row(*row_data)
        except Exception as e:
            logger.error(f"Error processing device: {device}")
            logger.error(f"Error details: {str(e)}")
            continue

    # Print table
    console.print(table)

if __name__ == "__main__":
    main()
