# NetBox and UniFi Integration

This project provides a mechanism to integrate **NetBox** with **UniFi**, allowing you to synchronize devices and manage conflicts while maintaining accurate data within NetBox.

## Features

- **Device Synchronization**: Automatically create or update devices from UniFi into NetBox.
- **Conflict Resolution**: Handle duplicate VRFs, IP addresses, and prefixes with advanced error handling and retry mechanisms.
- **Custom Connection Management**: Optimize performance with configurable connection pooling for NetBox API communications.
- **Error Logging**: Logs errors and warnings for easier debugging and monitoring.

## Requirements

- Python 3.12 or later
- Installed Python packages:
  - `pynetbox`
  - `requests`
  - `pyotp`
  - `PyYAML`
  - `python-dotenv`
  - `python-slugify`
  - `urllib3`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mrzepa/unifi2netbox.git
   cd netbox-unifi-integration
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3Create a `.env` file at the root of the project to store sensitive information such as usernames, passwords, and tokens. The `.env` file should look like this:
   ```plaintext
   UNIFI_USERNAME=your-unifi-username
   UNIFI_PASSWORD=your-unifi-password
   UNIFI_MFA_SECRET=your-unifi-mfa-secret
   NETBOX_TOKEN=your-netbox-api-token
   ```

4Copy the sample configuration file to `config/config.yaml`:
   ```bash
   cp config/config.yaml.SAMPLE config/config.yaml
   ```
   
5. Update the `config/config.yaml` file with your company-specific information (such as URLs, roles, and tenant names). For example:
   ```yaml
   UNIFI:
     URLS:
       - https://<controller-ip>:8443
   NETBOX:
     URL: http://localhost:8080
     ROLES:
       WIRELESS: Wireless AP
       LAN: Switch
     TENANT: Organization Name
   ```
## Obtaining the UniFi OTP Seed (MFA Secret)

The OTP seed (also referred to as the MFA Secret) is required for Multi-Factor Authentication and must be added to the `.env` file. Follow these steps to obtain it:

1. **Log in to your UniFi account**:
   Go to [https://account.ui.com](https://account.ui.com) and log in with your UniFi credentials.

2. **Access your profile**:
   Once logged in, select your profile in the top-right corner of the page.

3. **Manage security settings**:
   In the profile menu, select **Manage Security**.

4. **Retrieve the MFA Secret**:
   Under the "Multi-Factor Authentication" section:
   - Click: Add New Method.
   - Select App authentication.
   - Select "Enter code manually", or use a QR code scanner.
   - The text output will contain the OTP seed (a base32 string). This is your `UNIFI_MFA_SECRET`.
   - Make sure to select App authentication as your primary MFA.

5. Add the OTP seed to your `.env` file:
   ```plaintext
   UNIFI_MFA_SECRET=your-otp-seed
   ```

If you do not have 2FA enabled, you will need to set it up to generate a new OTP seed.

## Usage

### Running the Integration Script

Once the `.env` and `config/config.yaml` files are properly set up, you can run the script:

```bash
python main.py
```

### Logging

All logs are written to the `logs` directory. Logs are organized by severity (e.g., `info.log`, `error.log`) for easier debugging. Example of an error log:

```plaintext
2025-01-22 14:24:54,390 - ERROR - Unable to delete VRF at site X: '409 Conflict'
```

### Handling Conflicts

If there are conflicts (e.g., duplicate device names, VRFs, or IP addresses), the script:
- Logs the issue in the error log.
- Attempts to resolve it automatically where possible.
- Skips problematic devices or sites if the issue cannot be resolved.

## Contributing

Contributions are welcome! To contribute to this project:
1. Fork the repository.
2. Create a branch for your feature or bugfix:
   ```bash
   git checkout -b feature/my-feature
   ```
3. Commit your changes and push the branch:
   ```bash
   git commit -m "Add my feature"
   git push origin feature/my-feature
   ```
4. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- This project was inspired by the need for unified network management.
- Built with ❤️ using Python, NetBox, and UniFi APIs.