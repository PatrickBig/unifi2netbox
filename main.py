import json
from dotenv import load_dotenv
from slugify import slugify
import os
import re
import sys
import pyotp
import requests
import warnings
import logging
import pynetbox
import ipaddress
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
# Suppress only the InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

load_dotenv()
logger = logging.getLogger(__name__)
# Define threads for each layer
MAX_CONTROLLER_THREADS = 5  # Number of UniFi controllers to process concurrently
MAX_SITE_THREADS = 8  # Number of sites to process concurrently per controller
MAX_DEVICE_THREADS = 8  # Number of devices to process concurrently per site
MAX_THREADS = 8 # Define threads based on available system cores or default

class Unifi:
    """
    Handles interactions with UniFi API, including session management, authentication,
    and making API requests.

    This class is designed to manage authentication and handle sessions for interacting
    with UniFi API endpoints. It supports saving and loading session details to and from
    a file to minimize frequent reauthentication. It also includes methods for making
    authenticated requests using various HTTP methods.

    :ivar base_url: Base URL of the UniFi API, retrieved from environment variable
    :ivar username: Username for authentication, retrieved from environment variable
    :ivar password: Password for authentication, retrieved from environment variable
    :ivar mfa_secret: Secret key for Multi-Factor Authentication, retrieved from environment variable
    :ivar udm_pro: Specific path for UDM-Pro; initialized as an empty string
    :ivar session_cookie: Cookie for managing UniFi sessions, initializes as None
    :ivar csrf_token: CSRF token for API requests, initializes as None
    :type base_url: str
    :type username: str
    :type password: str
    :type mfa_secret: str
    :type udm_pro: str
    :type session_cookie: Optional[str]
    :type csrf_token: Optional[str]
    """
    SESSION_FILE = os.path.expanduser("~/.unifi_session.json")

    def __init__(self, base_url=None, username=None, password=None, mfa_secret=None):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.mfa_secret = mfa_secret
        self.udm_pro = ''
        self.session_cookie = None
        self.csrf_token = None
        self.load_session_from_file()

        if not all([self.base_url, self.username, self.password, self.mfa_secret]):
            raise ValueError("Missing required environment variables: BASE_URL, USERNAME, PASSWORD, or MFA_SECRET")

    def save_session_to_file(self):
        session_data = {
            "session_cookie": self.session_cookie,
            "csrf_token": self.csrf_token
        }
        with open(self.SESSION_FILE, "w") as f:
            json.dump(session_data, f)
        logger.info("Session data saved to file.")

    def load_session_from_file(self):
        if os.path.exists(self.SESSION_FILE):
            with open(self.SESSION_FILE, "r") as f:
                session_data = json.load(f)
                self.session_cookie = session_data.get("session_cookie")
                self.csrf_token = session_data.get("csrf_token")
                logger.info("Loaded session data from file.")

    def authenticate(self, retry_count=0, max_retries=3):
        """Logs in and retrieves a session cookie and CSRF token."""
        if retry_count >= max_retries:
            logger.error("Max authentication retries reached. Aborting authentication.")
            raise Exception("Authentication failed after maximum retries.")

        login_endpoint = f"{self.base_url}/api/{self.udm_pro}login"
        if not self.mfa_secret:
            raise ValueError("MFA_SECRET is missing or invalid.")

        otp = pyotp.TOTP(self.mfa_secret).now()
        payload = {
            "username": self.username,
            "password": self.password,
            "ubic_2fa_token": otp,
        }

        session = requests.Session()
        session.timeout = 10

        try:
            response = session.post(login_endpoint, json=payload, verify=False)
            response_data = response.json()
            response.raise_for_status()
            if response_data.get("meta", {}).get("rc") == "ok":
                logger.info("Logged in successfully.")
                self.session_cookie = session.cookies.get("unifises")
                self.csrf_token = session.cookies.get("csrf_token")
                self.save_session_to_file()
                return
            elif response_data.get("meta", {}).get("msg") == "api.err.Invalid2FAToken":
                logger.warning("Invalid 2FA token detected. Waiting for the next token...")
                # Wait for the current TOTP token to expire (~30 seconds for most TOTP systems)
                # Adjust the timing based on your specific TOTP configuration.
                import time
                time.sleep(30)
                # Retry authentication with the next token
                return self.authenticate(retry_count=retry_count + 1, max_retries=max_retries)
            else:
                logger.error(f"Login failed: {response_data.get('meta', {}).get('msg')}")
                raise Exception("Login failed.")
        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error occurred: {http_err}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication error: {e}. Retrying ({retry_count + 1}/{max_retries})...")
            self.authenticate(retry_count=retry_count + 1)
        except json.JSONDecodeError as json_err:
            logger.error(f"Failed to decode JSON response: {json_err}")
            return None

    def make_request(self, endpoint, method="GET", data=None, retry_count=0, max_retries=3):
        """Makes an authenticated request to the UniFi API."""
        if not self.session_cookie or not self.csrf_token:
            print("No valid session. Authenticating...")
            self.authenticate()

        try:
            if method.upper() not in ["GET", "POST", "PUT", "DELETE"]:
                raise ValueError(f"Unsupported HTTP method: {method}")
        except ValueError as e:
            logger.error(e)
            return None

        headers = {
            "X-CSRF-Token": self.csrf_token,
            "Content-Type": "application/json"
        }
        cookies = {
            "unifises": self.session_cookie
        }

        url = f"{self.base_url}{endpoint}"

        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, cookies=cookies, verify=False)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, headers=headers, cookies=cookies, verify=False)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, headers=headers, cookies=cookies, verify=False)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, cookies=cookies, verify=False)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            # Handle session expiry
            if response.status_code == 401:
                logger.warning("Session expired. Re-authenticating...")
                self.authenticate()
                return self.make_request(endpoint, method, data, retry_count=0)
            elif response.status_code == 400:
                # Log API errors for debugging
                logger.error(f"Request failed with 400: {response.text}")
                return None  # Handle site context or other app-level issues.

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"An error occurred: {e}")
            return None

def normalize_site_name(name):
    """
    Normalize the Ubiquity site name by:
    - Removing 2-character uppercase abbreviations (e.g., "AH").
    - Removing anything in parentheses
    - Replacing non-breaking spaces with regular spaces.
     - Removing hyphens.
    - Stripping leading/trailing whitespace.
    """

    # Replace non-breaking spaces with regular spaces
    name = name.replace('\xa0', ' ')

    # Remove anything in parentheses
    name = re.sub(r'\([^)]*\)', '', name)

    # Remove 2-character uppercase abbreviations
    parts = name.split()
    filtered_parts = [part for part in parts if not re.match(r'^[A-Z]{2}$', part)]

    # Remove hyphens
    name = name.replace('-', '')

    # Join the result into a single string and strip spaces
    normalized = ' '.join(filtered_parts).strip()
    return normalized
def prepare_netbox_sites(netbox_sites):
    """
    Pre-process NetBox sites by normalizing their names.

    :param netbox_sites: List of NetBox site dictionaries (each containing 'name').
    :return: A dictionary mapping normalized names to the original NetBox site objects.
    """
    normalized_netbox_sites = {}
    for netbox_site in netbox_sites:
        normalized_name = normalize_site_name(netbox_site.name)
        normalized_netbox_sites[normalized_name] = netbox_site
    return normalized_netbox_sites

def match_sites_to_netbox(ubiquity_desc, normalized_netbox_sites):
    """
    Match Ubiquity site with normalized NetBox sites by comparing substrings.

    :param ubiquity_desc: The description of the Ubiquity site.
    :param normalized_netbox_sites: A dictionary mapping normalized NetBox site names to site objects.
    :return: The matched NetBox site, or None if no match is found.
    """
    normalized_name = normalize_site_name(ubiquity_desc)
    logger.debug(f'Normalized Ubiquity description: "{ubiquity_desc}" -> "{normalized_name}"')

    for netbox_normalized, netbox_site in normalized_netbox_sites.items():

        # Check if the normalized Ubiquity name is a substring of the normalized NetBox site name
        if normalized_name in netbox_normalized:
            logger.debug(f'Matched Ubiquity site "{ubiquity_desc}" to NetBox site "{netbox_site.name}"')
            return netbox_site

    logger.debug(f'No match found for Ubiquity site "{ubiquity_desc}"')
    return None

def setup_logging(min_log_level=logging.INFO):
    """
    Sets up logging to separate files for each log level.
    Only logs from the specified `min_log_level` and above are saved in their respective files.
    Includes console logging for the same log levels.

    :param min_log_level: Minimum log level to log. Defaults to logging.INFO.
    """
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    if not os.access(logs_dir, os.W_OK):
        raise PermissionError(f"Cannot write to log directory: {logs_dir}")

    # Log files for each level
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    # Create the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all log levels

    # Define a log format
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Set up file handlers for each log level
    for level_name, level_value in log_levels.items():
        if level_value >= min_log_level:
            log_file = os.path.join(logs_dir, f"{level_name.lower()}.log")
            handler = logging.FileHandler(log_file)
            handler.setLevel(level_value)
            handler.setFormatter(log_format)

            # Add a filter so only logs of this specific level are captured
            handler.addFilter(lambda record, lv=level_value: record.levelno == lv)
            logger.addHandler(handler)

    # Set up console handler for logs at `min_log_level` and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(min_log_level)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)

    logging.info(f"Logging is set up. Minimum log level: {logging.getLevelName(min_log_level)}")

def load_config(config_path="config/config.yaml"):
    """
    Reads the configuration from a YAML file.

    :param config_path: Path to the YAML configuration file.
    :return: A dictionary of the configuration.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r") as file:
        try:
            config = yaml.safe_load(file)  # Use safe_load to avoid executing malicious YAML code
            return config
        except yaml.YAMLError as e:
            raise Exception(f"Error reading configuration file: {e}")

def process_device(unifi, nb, site, device, nb_ubiquity, tenant):
    """Process a device and add it to NetBox."""
    try:
        logger.info(f"Processing device {device['name']} at site {site}...")

        # Determine device role
        if str(device.get("is_access_point", "false")).lower() == "true":
            nb_device_role = wireless_role
        else:
            nb_device_role = lan_role

        if not device.get("serial"):
            logger.warning(f"Missing serial number for device {device.get('name')}. Skipping...")
            return

        # VRF creation
        vrf_name = f"vrf_{site}"
        vrf = None
        try:
            vrf = nb.ipam.vrfs.get(name=vrf_name)
        except ValueError as e:
            error_message = str(e)
            if "get() returned more than one result." in error_message:
                logger.warning(f"Multiple VRFs with name {vrf_name} found. Using 1st one in the list.")
                vrfs = nb.ipam.vrfs.filter(name=vrf_name)
                for vrf_item in vrfs:
                    vrf = vrf_item
                    break
            else:
                logger.exception(f"Failed to get VRF {vrf_name} for site {site}: {e}. Skipping...")
                return

        if not vrf:
            vrf = nb.ipam.vrfs.create({"name": vrf_name})
            if vrf:
                logger.info(f"VRF {vrf_name} with ID {vrf.id} successfully added to NetBox.")

        # Device Type creation
        nb_device_type = nb.dcim.device_types.get(model=device["model"], manufacturer_id=nb_ubiquity.id)
        if not nb_device_type:
            try:
                nb_device_type = nb.dcim.device_types.create({"manufacturer": nb_ubiquity.id, "model": device["model"],
                                                              "slug": slugify(f'{nb_ubiquity.name}-{device["model"]}')})
                if nb_device_type:
                    logger.info(f"Device type {device['model']} with ID {nb_device_type.id} successfully added to NetBox.")
            except pynetbox.core.query.RequestError as e:
                logger.error(f"Failed to create device type for {device['name']} at site {site}: {e}")
                return
            if len(device.get("port_table", [])) > 0:
                for port in device["port_table"]:
                    if port["media"] == "GE":
                        port_type = "1000base-t"
                        try:
                            template = nb.dcim.interface_templates.create({
                                "device_type": nb_device_type.id,
                                "name": port["name"],
                                "type": port_type,
                            })
                            if template:
                                logger.info(f"Interface template {port['name']} with ID {template.id} successfully added to NetBox.")
                        except pynetbox.core.query.RequestError as e:
                            logger.exception(f"Failed to create interface template for {device['name']} at site {site}: {e}")

        # Check for existing device
        if nb.dcim.devices.get(site_id=site.id, serial=device["serial"]):
            logger.info(f"Device {device['name']} with serial {device['serial']} already exists. Skipping...")
            return

        # Create NetBox Device
        try:
            nb_device = nb.dcim.devices.create({
                "name": device["name"],
                "device_type": nb_device_type.id,
                "role": nb_device_role.id,
                "site": site.id,
                "serial": device["serial"],
            })
            if nb_device:
                logger.info(f"Device {device['name']} serial {device['serial']} with ID {nb_device.id} successfully added to NetBox.")
        except pynetbox.core.query.RequestError as e:
            error_message = str(e)
            if "Device name must be unique per site" in error_message:
                logger.warning(f"Device name {device['name']} already exists at site {site}. "
                               f"Trying with name {device['name']}_{device['serial']}.")
                try:
                    nb_device = nb.dcim.devices.create({
                        "name": f"{device['name']}_{device['serial']}",
                        "device_type": nb_device_type.id,
                        "role": nb_device_role.id,
                        "site": site.id,
                        "serial": device["serial"],
                    })
                    if nb_device:
                        logger.info(f"Device {device['name']} with ID {nb_device.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e2:
                    logger.exception(f"Failed to create device {device['name']} serial {device['serial']} at site {site}: {e2}")
                    return
            else:
                logger.exception(f"Failed to create device {device['name']} serial {device['serial']} at site {site}: {e}")
                return

        # Add primary IP if available
        try:
            ipaddress.ip_address(device["ip"])
        except ValueError:
            logger.warning(f"Invalid IP {device['ip']} for device {device['name']}. Skipping...")
            return
        # get the prefix that this IP address belongs to
        prefixes = nb.ipam.prefixes.filter(contains=device['ip'], vrf_id=vrf.id)
        if not prefixes:
            logger.warning(f"No prefix found for IP {device['ip']} for device {device['name']}. Skipping...")
            return
        for prefix in prefixes:
            # Extract the prefix length (mask) from the prefix
            subnet_mask = prefix.prefix.split('/')[1]
            ip = f'{device["ip"]}/{subnet_mask}'
            break
        if nb_device:
            interface = nb.dcim.interfaces.get(device_id=nb_device.id, name="vlan.1")
            if not interface:
                try:
                    interface = nb.dcim.interfaces.create(device=nb_device.id,
                                                          name="vlan.1",
                                                          type="virtual",
                                                          enabled=True,
                                                          vrf_id=vrf.id,)
                    if interface:
                        logger.info(
                            f"Interface vlan.1 for device {device['name']} with ID {interface.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(
                        f"Failed to create interface vlan.1 for device {device['name']} at site {site}: {e}")
                    return
            nb_ip = nb.ipam.ip_addresses.get(address=ip, vrf_id=vrf.id, tenant_id=tenant.id)
            if not nb_ip:
                try:
                    nb_ip = nb.ipam.ip_addresses.create({
                        "assigned_object_id": interface.id,
                        "assigned_object_type": 'dcim.interface',
                        "address": ip,
                        "vrf_id": vrf.id,
                        "tenant_id": tenant.id,
                        "status": "active",
                    })
                    if nb_ip:
                        logger.info(f"IP address {ip} with ID {nb_ip.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f"Failed to create IP address {ip} for device {device['name']} at site {site}: {e}")
                    return
            if nb_ip:
                nb_device.primary_ip4 = nb_ip.id
                nb_device.save()
                logger.info(f"Device {device['name']} with IP {ip} added to NetBox.")

    except Exception as e:
        logger.exception(f"Failed to process device {device['name']} at site {site}: {e}")

def process_site(unifi, nb, site, nb_site, nb_ubiquity, tenant):
    """
    Process devices for a given site and add them to NetBox.
    """
    path = f"/api/s/{site}/stat/device"
    devices = unifi.make_request(path).get("data", [])
    logger.debug(f"Processing {len(devices)} devices for site {site}...")

    with ThreadPoolExecutor(max_workers=MAX_DEVICE_THREADS) as executor:
        futures = []
        for device in devices:
            futures.append(executor.submit(process_device, unifi, nb, nb_site, device, nb_ubiquity, tenant))

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing a device at site {site}: {e}")


def process_controller(unifi_url, unifi_username, unifi_password, unifi_mfa_secret, nb, nb_ubiquity, tenant,
                       normalized_netbox_sites):
    """
    Process all sites and devices for a specific UniFi controller.
    """
    logger.info(f"Processing UniFi controller: {unifi_url}")

    try:
        # Create a Unifi instance and authenticate
        unifi = Unifi(unifi_url, unifi_username, unifi_password, unifi_mfa_secret)
        unifi.authenticate()

        # Fetch sites
        u_sites_response = unifi.make_request("/api/self/sites")
        u_sites = u_sites_response.get("data", [])
        logger.info(f"Found {len(u_sites)} sites for controller {unifi_url}")

        with ThreadPoolExecutor(max_workers=MAX_SITE_THREADS) as executor:
            futures = []
            for site in u_sites:
                ubiquity_desc = site["desc"]
                nb_site = match_sites_to_netbox(ubiquity_desc, normalized_netbox_sites)

                if not nb_site:
                    logger.warning(f"No match found for Ubiquity site: {ubiquity_desc}. Skipping...")
                    continue

                futures.append(executor.submit(process_site, unifi, nb, site["name"], nb_site, nb_ubiquity, tenant))

            # Wait for all site-processing threads to complete
            for future in as_completed(futures):
                future.result()

    except Exception as e:
        logger.error(f"Error processing controller {unifi_url}: {e}")


def process_all_controllers(unifi_url_list, unifi_username, unifi_password, unifi_mfa_secret, nb, nb_ubiquity, tenant,
                            normalized_netbox_sites):
    """
    Process all UniFi controllers in parallel.
    """
    with ThreadPoolExecutor(max_workers=MAX_CONTROLLER_THREADS) as executor:
        futures = []
        for url in unifi_url_list:
            futures.append(
                executor.submit(process_controller, url, unifi_username, unifi_password, unifi_mfa_secret, nb,
                                nb_ubiquity, tenant, normalized_netbox_sites))

        # Wait for all controller-processing threads to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.exception(f"Error processing one of the UniFi controllers {url}: {e}")
                continue

def fetch_site_devices(unifi, site_name):
    """Fetch devices for a specific site."""
    logger.info(f"Fetching devices for site {site_name}...")
    path = f"/api/s/{site_name}/stat/device"
    devices = unifi.make_request(path).get("data", [])
    return {site_name: devices}

def process_all_sites(unifi, normalized_netbox_sites, nb, nb_ubiquity, tenant):
    """Process all sites and their devices concurrently."""
    u_sites_response = unifi.make_request("/api/self/sites")
    u_sites = u_sites_response.get("data", [])

    sites = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Fetch all devices per site concurrently
        future_to_site = {executor.submit(fetch_site_devices, unifi, site["name"]): site for site in u_sites}
        for future in as_completed(future_to_site):
            site = future_to_site[future]
            try:
                site_result = future.result()
                site_name = list(site_result.keys())[0]
                sites[site_name] = site_result[site_name]
                logger.info(f"Successfully fetched devices for site {site_name}")
            except Exception as e:
                logger.error(f"Error fetching devices for site {site['name']}: {e}")

    logger.info(f"Fetched {len(sites)} sites. Starting device processing...")

    # Process devices in parallel
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_device = {}
        for site, devices in sites.items():
            nb_site = normalized_netbox_sites.get(site)
            if not nb_site:
                logger.warning(f"No matching NetBox site found for Ubiquity site {site}. Skipping...")
                continue
            for device in devices:
                future = executor.submit(process_device, unifi, nb, nb_site, device, nb_ubiquity, tenant)
                future_to_device[future] = (site, device)

        for future in as_completed(future_to_device):
            site, device = future_to_device[future]
            try:
                future.result()
                logger.info(f"Successfully processed device {device['name']} at site {site}.")
            except Exception as e:
                logger.error(f"Error processing device {device['name']} at site {site}: {e}")

def parse_successful_log_entries(log_file):
    """
    Parses a log file to find entries containing 'successfully added to NetBox'
    and builds a dictionary with 'device' and 'ip address' lists of IDs.

    :param log_file: Path to the log file
    :return: Dictionary with lists of IDs for 'device' and 'ip address'
    """
    # Dictionary to store the resulting lists
    result = {
        "device": [],
        "ip address": []
    }

    # Regular expression to extract the ID from the log entry
    id_pattern_device = re.compile(r"^Device .* with ID (\d+) successfully added to NetBox")
    id_pattern_ip = re.compile(r"^IP address .* with ID (\d+) successfully added to NetBox")

    with open(log_file, "r") as file:
        for line in file:
            # Start processing the log entry only after `INFO -`
            if "INFO - " in line:
                log_content = line.split("INFO - ", 1)[1]  # Extract the part after "INFO - "

                # Match and classify the log entry
                if match := id_pattern_device.match(log_content):
                    result["device"].append(int(match.group(1)))  # Extract and add device ID
                elif match := id_pattern_ip.match(log_content):
                    result["ip address"].append(int(match.group(1)))  # Extract and add IP address ID

    return result


if __name__ == "__main__":
    # Configure logging
    setup_logging(logging.INFO)
    config = load_config()
    try:
        unifi_url_list = config['UNIFI']['URLS']
    except ValueError:
        logger.exception("Unifi URL is missing from configuration.")
        raise SystemExit(1)

    try:
        unifi_username = os.getenv('UNIFI_USERNAME')
        unifi_password = os.getenv('UNIFI_PASSWORD')
        unifi_mfa_secret = os.getenv('UNIFI_MFA_SECRET')
    except KeyError:
        logger.exception("Unifi username or password is missing from environment variables.")
        raise SystemExit(1)

    # Connect to Netbox
    try:
        netbox_url = config['NETBOX']['URL']
    except ValueError:
        logger.exception("Netbox URL is missing from configuration.")
        raise SystemExit(1)
    try:
        netbox_token = os.getenv('NETBOX_TOKEN')
    except KeyError:
        logger.exception("Netbox token is missing from environment variables.")
        raise SystemExit(1)

    # Create a custom HTTP session as this script will often exceed the default pool size of 10
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)

    # Adjust connection pool size
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    nb = pynetbox.api(netbox_url, token=netbox_token, threading=True)
    nb.http_session.verify = False
    nb.http_session = session  # Attach the custom session

    nb_ubiquity = nb.dcim.manufacturers.get(slug='ubiquity')
    try:
        tenant_name = config['NETBOX']['TENANT']
    except ValueError:
        logger.exception("Netbox tenant is missing from configuration.")
        raise SystemExit(1)

    tenant = nb.tenancy.tenants.get(name=tenant_name)

    try:
        wireless_role_name = config['NETBOX']['ROLES']['WIRELESS']
    except KeyError:
        logger.exception("Netbox wireless role is missing from configuration.")
        raise SystemExit(1)
    try:
        lan_role_name = config['NETBOX']['ROLES']['LAN']
    except KeyError:
        logger.exception("Netbox lan role is missing from configuration.")
        raise SystemExit(1)

    wireless_role = nb.dcim.device_roles.get(slug=wireless_role_name.lower())
    lan_role = nb.dcim.device_roles.get(slug=lan_role_name.lower())
    if not wireless_role:
        wireless_role = nb.dcim.device_roles.create({'name': wireless_role_name, 'slug': wireless_role_name.lower()})
        if wireless_role:
            logger.info(f"Wireless role {wireless_role_name} with ID {wireless_role.id} successfully added to Netbox.")
    if not lan_role:
        lan_role = nb.dcim.device_roles.create({'name': lan_role_name, 'slug': lan_role_name.lower()})
        if lan_role:
            logger.info(f"LAN role {lan_role_name} with ID {lan_role.id} successfully added to Netbox.")

    netbox_sites = nb.dcim.sites.all()

    # Preprocess NetBox sites
    normalized_netbox_sites = prepare_netbox_sites(netbox_sites)

    if not nb_ubiquity:
        nb_ubiquity = nb.dcim.manufacturers.create({'name': 'Ubiquity Networks', 'slug': 'ubiquity'})
        if nb_ubiquity:
            logger.info(f"Ubiquity manufacturer with ID {nb_ubiquity.id} successfully added to Netbox.")

    # Process all UniFi controllers in parallel
    process_all_controllers(unifi_url_list, unifi_username, unifi_password, unifi_mfa_secret, nb, nb_ubiquity,
                            tenant,
                            normalized_netbox_sites)
