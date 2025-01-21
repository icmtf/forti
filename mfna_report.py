import os
import urllib3, json, csv
import ipaddress

import asyncio
from jinja2 import Environment, FileSystemLoader

from common import MFNA, get_inet_inventory, check_device
from pyinet.utils.cyberark import get_password
from pyinet.utils.mail import py_mail

urllib3.disable_warnings()


async def main(inet_inventory, mfna_inventory, inactive_inet_inventory, cyberark_svc_account):
    # Dirty trick to pull IP and hostname out and turn it into a tuple-key.
    mfna_dict = {(device["primaryIPAddress"], device["hostName"].lower()): device for device in mfna_inventory}
    # Similar action but this time only IP is pulled out as a key.
    mfna_ip_dict = {device["primaryIPAddress"]: device for device in mfna_inventory}
    hostname_and_ip_count = 0
    ip_only_count = 0
    missing_count = 0
    for inet_device in inet_inventory["results"]:
        ip = inet_device["adminip"]
        hostname = inet_device["hostname"]
        inet_device["ports"] = []
        try:
            ipaddress.ip_address(ip)
            if (ip, hostname) in mfna_dict:
                inet_device["mfna_hostName"] = mfna_dict[(ip, hostname)]['hostName']
                inet_device["mfna_status"] = "Hostname and IP"
                hostname_and_ip_count += 1
            elif ip in mfna_ip_dict:
                inet_device["mfna_hostName"] = mfna_ip_dict[ip]['hostName']
                inet_device["mfna_status"] = "IP only"
                ip_only_count += 1
            elif ip not in mfna_dict:
                inet_device["mfna_hostName"] = "N/A"
                inet_device["mfna_status"] = "Missing"
                missing_count += 1
        except ValueError:
            inet_device["mfna_status"] = "Bad IP"
            inet_device["mfna_hostName"] = "N/A"
    tasks = []
    bad_ip_devices = []
    for device in inet_inventory["results"]:
        if "Bad IP" in device["mfna_status"]:
            # We want devices with bad IP so let's simply append to the end of the list.
            # But first let's turn every value to False so we don't have to deal with nulls.
            device.update(
                {
                    "ip": device["adminip"],
                    "open_ports": {"ssh": False, "http": False, "https": False, "mcafee": False},
                    "ssh_account": {"svc_account": False, "cyberarkaccount": False},
                }
            )
            bad_ip_devices.append(device)
        else:
            tasks.append(check_device(device, svc_account=cyberark_svc_account))
    results = await asyncio.gather(*tasks)
    # Async function finished so let's only ad Bad IPs and we're done.
    results.extend(bad_ip_devices)

    # Dump the dict as the context for Jinja and render HTML output.
    with open("output.json", "w") as output_json_file:
        output_json_file.write(json.dumps(results, indent=2))
    env = Environment(loader=FileSystemLoader("."))
    env.globals.update(enumerate=enumerate)
    template = env.get_template("template_inet_vs_mfna.html")
    counters = {
        "hostname_and_ip_count": hostname_and_ip_count,
        "ip_only_count": ip_only_count,
        "missing_count": missing_count,
        "bad_ip_count": len(bad_ip_devices)
    }
    rendered_template = template.render(results=results, counters=counters)
    with open("output.html", "w") as output_html_file:
        output_html_file.write(rendered_template)
    # CSV output is nifty as well.
    with open("output.csv", "w") as output_csv_file:
        csv_writer = csv.writer(output_csv_file)
        # Header names.
        csv_writer.writerow(
            [
                "adminip",
                "country",
                "environment",
                "hostname",
                "type",
                "vendor",
                "port22open",
                "port80open",
                "port443open",
                "port4712open",
                "mfna_status",
                "mfna_hostName",
                "svcfruxinetp_GAIA@ssh",
                "cyberarkaccount@ssh",
            ]
        )
        for line in results:
            row_values = [
                line["ip"],
                line["country"],
                line["environment"],
                line["hostname"],
                line["type"],
                line["vendor"],
                line["open_ports"]["ssh"],
                line["open_ports"]["http"],
                line["open_ports"]["https"],
                line["open_ports"]["mcafee"],
                line["mfna_status"],
                line["mfna_hostName"],
                line["ssh_account"]["svc_account"],
                (line["ssh_account"]["cyberarkaccount"] if line["ssh_account"]["cyberarkaccount"] != None else "null"),
            ]
            csv_writer.writerow(row_values)

    # Before we're done with the report - let's do a reverse check.
    # We need to include also inactive devices to.
    active_plus_inactive_inet_inventory = inet_inventory["results"] + inactive_inet_inventory["results"]
    # Once again. Dirty trick to pull IP and hostname out and turn it into a tuple-key.
    inet_ips_and_hosts = {
        (device["adminip"], device["hostname"].lower()): device for device in active_plus_inactive_inet_inventory
    }
    active_inet_ips = {device["adminip"]: device for device in inet_inventory["results"]}
    inactive_inet_ips = {device["adminip"]: device for device in inactive_inet_inventory["results"]}
    inet_hostnames = {device["hostname"]: device for device in inet_inventory["results"]}
    mfna_ip_exists_count = 0
    mfna_decomm_count = 0
    mfna_missing_count = 0
    mfna_ip_mismatch_count = 0
    for mfna_device in mfna_inventory:
        mfna_ip = mfna_device["primaryIPAddress"]
        mfna_hostname = mfna_device["hostName"].lower()
        if mfna_ip in active_inet_ips:
            mfna_device["inet_status"] = "OK"
            mfna_ip_exists_count += 1
        elif mfna_ip in inactive_inet_ips:
            mfna_device["inet_status"] = "Decomm"
            mfna_decomm_count += 1
        elif mfna_hostname in inet_hostnames:
            mfna_device["inet_status"] = "IP mismatch"
            mfna_ip_mismatch_count += 1
        else:
            mfna_device["inet_status"] = "Missing"
            mfna_missing_count += 1
    # Now that we enriched the mfna_inventory dict - let's use it as J2 context.
    with open("mfna_vs_inet.json", "w") as output_json_file:
        output_json_file.write(json.dumps(mfna_inventory, indent=2))
    env = Environment(loader=FileSystemLoader("."))
    env.globals.update(enumerate=enumerate)
    template = env.get_template("template_mfna_vs_inet.html")
    counters = {
        "mfna_ip_exists_count": mfna_ip_exists_count,
        "mfna_decomm_count": mfna_decomm_count,
        "mfna_missing_count": mfna_missing_count,
        "mfna_ip_mismatch_count": mfna_ip_mismatch_count
    }
    rendered_mfna_vs_inet_template = template.render(results=mfna_inventory, counters=counters)
    with open("mfna_vs_inet.html", "w") as output_html_file:
        output_html_file.write(rendered_mfna_vs_inet_template)

    # CSV output is nifty as well.
    with open("mfna_vs_inet.csv", "w") as output_csv_file:
        csv_writer = csv.writer(output_csv_file)
        # Header names.
        csv_writer.writerow(
            [
                "primaryIPAddress",
                # "country",
                # "environment",
                "hostName",
                # "type",
                # "vendor",
                "inet_status",
            ]
        )
        for line in mfna_inventory:
            row_values = [
                line["primaryIPAddress"],
                # line['deviceCustom1'],
                # line['deviceCustom4'],
                line["hostName"],
                # line['deviceType'],
                # line['vendor'],
                line["inet_status"],
            ]
            csv_writer.writerow(row_values)
    # Mail the results.
    py_mail(
        Subject="[beta] INET vs MFNA inventory",
        Body=rendered_template,
        # To = ["lukasz.bryzek@externe.bnpparibas.com"],  # DEBUG:
        To = ["dl.fr.cib.inet@bnpparibas.com", "kamil.turula@bpsspl.bnpparibas.com", "lukasz.bryzek@externe.bnpparibas.com"],
        Attachments=[
            "output.html",
            "output.csv",
            "output.json",
            "mfna_vs_inet.html",
            "mfna_vs_inet.json",
            "mfna_vs_inet.csv",
        ],
    )


if __name__ == "__main__":
    svc_account = get_password("svcfruxinetp_GAIA")
    # Set up MFNA instance.
    mfna = MFNA.get_instance(
        # mfna_uri="https://10.153.214.21",  # Dev MFNA
        # eldap_username=os.environ.get("eldap_login"),
        # eldap_password=os.environ.get("eldap_password"),
        mfna_uri="https://na.cib.echonet",
        eldap_username=svc_account["user"],
        eldap_password=svc_account["password"],
    )
    # Get MFNA Inventory.
    mfna_security_devices = mfna.get_instance().command(command="list device", group="Security")

    inet_inventory = get_inet_inventory(
        # role="management",
        # country="fr",
        # vendor="checkpoint",
        status="active",
        selectcol=[
            "adminip",
            "hostname",
            "vendor",
            "country",
            "role",
            "type",
            "environment",
            "cyberarkaccount",
            "status",
        ],
    )
    # Quickly remove from the list of devices items that are role=cisadmin or role=cisprod
    inet_inventory['results'] = [
        item for item in inet_inventory['results']
        if item['role'] not in ('cisadmin', 'cisprod')
    ]
    inactive_inet_inventory = get_inet_inventory(
        status="notactive",
        selectcol=[
            "adminip",
            "hostname",
            "vendor",
            "country",
            "role",
            "type",
            "environment",
            "cyberarkaccount",
            "status",
        ],
    )
    asyncio.run(main(inet_inventory, mfna_security_devices, inactive_inet_inventory, cyberark_svc_account=svc_account))