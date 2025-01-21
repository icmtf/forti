from rich.console import Console
from rich.table import Table
from common import get_inet_inventory

def main():
    # Initialize Rich console
    console = Console()

    # Get inventory data from INET
    inventory = get_inet_inventory(
        selectcol=[
            "adminip",
            "hostname",
            "vendor",
            "country",
            "role",
            "serial"
        ]
    )

    # Create and configure table
    table = Table(title="INET Inventory")
    
    # Add columns
    table.add_column("Admin IP", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("Vendor", style="yellow")
    table.add_column("Country", style="blue")
    table.add_column("Role", style="magenta")
    table.add_column("Serial", style="red")

    # Add rows
    for device in inventory.get("results", []):
        table.add_row(
            device.get("adminip", "N/A"),
            device.get("hostname", "N/A"),
            device.get("vendor", "N/A"),
            device.get("country", "N/A"),
            device.get("role", "N/A"),
            device.get("serial", "N/A")
        )

    # Print table
    console.print(table)

if __name__ == "__main__":
    main()
