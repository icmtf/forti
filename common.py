import socket
import ipaddress
import json
import logging
from threading import Lock
from urllib.parse import urlencode

import requests
import validators
import asyncio
from netmiko import ConnectHandler
from netmiko import NetMikoAuthenticationException, NetMikoTimeoutException

from pyinet.utils.cyberark import get_password

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Increase minimum Paramiko logging Level or else it will flood with INFO logs about connection.
logging.getLogger("paramiko").setLevel(logging.WARNING)

SVC_EXCLUDED_VENDOR = ["mcafee", "infoblox", "avi"]

def get_inet_inventory(**params) -> dict:
    BASE_URI = "https://inet-services.cib.echonet/inventory/api/"
    parameters = {}
    for param_name, param_value in params.items():
        if param_name == "selectcol" and isinstance(param_value, list):
            parameters[param_name] = ",".join(param_value)
        else:
            parameters.update({param_name: param_value})
    try:
        response = requests.get(url=f"{BASE_URI}?{urlencode(parameters)}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to get inventory data: {e}")
        return {}
    return response.json()


async def is_port_open(ip, port, timeout=2):
    loop = asyncio.get_event_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(s, (ip, port)), timeout)
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False


async def try_ssh_login(hostname, ip, port, username, password):
    device = {
        "device_type": "autodetect",
        "host": ip,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 5,
    }
    try:
        with ConnectHandler(**device) as conn:
            return True
    except:
        return False


async def check_device(device, svc_account):
    open_ports = {
        "ssh": await is_port_open(device["adminip"], 22),
        "http": await is_port_open(device["adminip"], 80),
        "https": await is_port_open(device["adminip"], 443),
        "mcafee": await is_port_open(device["adminip"], 4712),
    }
    svc_account_login_result = None
    inet_cyberark_account_login_result = None

    if device["cyberarkaccount"] != None:
        cyberark_account = get_password(device["cyberarkaccount"])
        if open_ports["ssh"]:
            if device["vendor"] not in SVC_EXCLUDED_VENDOR:
                svc_account_login_result = await try_ssh_login(
                    device["hostname"], device["adminip"], 22, svc_account["user"], svc_account["password"]
                )
            if cyberark_account != 404:
                inet_cyberark_account_login_result = await try_ssh_login(
                    device["hostname"],
                    device["adminip"],
                    22,
                    cyberark_account["user"],
                    cyberark_account["password"],
                )

    else:
        if open_ports["ssh"] and device["vendor"] not in SVC_EXCLUDED_VENDOR:
            ipaddress.ip_address(device["adminip"])
            svc_account_login_result = await try_ssh_login(
                device["hostname"], device["adminip"], 22, svc_account["user"], svc_account["password"]
            )
    return {
        "hostname": device["hostname"],
        "ip": device["adminip"],
        "open_ports": open_ports,
        "ssh_account": {
            "svc_account": svc_account_login_result,
            "cyberarkaccount": inet_cyberark_account_login_result,
        },
        "vendor": device["vendor"],
        "role": device["role"],
        "type": device["type"],
        "country": device["country"],
        "environment": device["environment"],
        "mfna_status": device["mfna_status"],
        "mfna_hostName": device["mfna_hostName"].lower(),
        "status_in_inet": device['status']
    }


class MFNA:
    "MFNA Class"
    _instance = None
    _lock = Lock()

    def __init__(self, mfna_uri: str, eldap_username: str, eldap_password: str) -> None:
        if not validators.url(mfna_uri):
            raise Exception(f"The MFNA URI provided is not a valid URI! ({mfna_uri})")
        self.BASE_URI = mfna_uri
        self.eldap_username = eldap_username
        self.eldap_password = eldap_password
        print(eldap_username)

    @classmethod
    def get_instance(cls, *args, **kwargs) -> "MFNA":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(*args, **kwargs)
        return cls._instance

    def _get_access_token(self) -> dict:
        auth_endpoint = "/nom-na/idp/oauth2/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "grant_type": "password",
            "username": self.eldap_username,
            "password": self.eldap_password,
            "client_id": "id1",
            "client_secret": "secret1",
        }
        try:
            response = requests.post(url=f"{self.BASE_URI}{auth_endpoint}", headers=headers, data=payload, verify=False)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to obtain access token: {e}")
            return {}

    def get_token(self) -> dict:
        token = self._get_access_token()
        return token["access_token"]

    def command(self, command: str, **params) -> dict:
        api_endpoint = "/nom/api/automation/v1/wrapper"
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.get_token()}"}
        payload = {"command": command, "parameters": {}}
        for param_name, param_value in params.items():
            payload["parameters"][param_name] = param_value
        response = requests.post(
            url=f"{self.BASE_URI}{api_endpoint}", headers=headers, data=json.dumps(payload), verify=False
        )
        return response.json()
