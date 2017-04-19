# ACOS-Upgrade
Python script to update the running version of ACOS on an A10 TPS.  Running
this script will upgrade the ACOS software on an A10 appliance or a fleet of
appliances. Can read in IP Addresses or hostnames from the CLI or a file, 
(hosts.txt), found in the working directory at runtime.

##### Contains options for the following:
 - Overwrite the currently booted image or upgrade the standby image
 - Specify using data plane or out-of-band-management port
 - Set the newly installed image to be used at the next boot
 - Save the configuration
 - Reboot the applicance following the upgrade

##### Usage
```
usage: acos_upgrade.py [-h] [-f DEVICES_FILE] [-i URL] [-m] [--overwrite]
                       [-p PASSWORD] [--reboot] [-s] [-u USERNAME] [-v] [-w]
                       [--version] [--dryrun]
                       [device [device ...]]

Running this script will upgrade the ACOS software on an A10 appliance.
Contains options to overwrite the currently booted image or upgrade the
standby image.

positional arguments:
  device                A10 device hostname or IP address. Multiple devices
                        may be included separated by a space.

optional arguments:
  -h, --help            show this help message and exit
  -f DEVICES_FILE, --file DEVICES_FILE
                        Simple text file containing a list of devices, one per
                        line, to upgrade.
  -i URL, --image URL   Remote file path for upgrade image. Format: (tftp|ftp|
                        scp|sftp)://[user[:password]@]host[:port]/file
  -m, --use-mgmt        Attempt an upgrade via the management interface.
  --overwrite           Overwrite the currently booted image. Default action
                        will upgrade the non-booted image version
  -p PASSWORD, --password PASSWORD
                        ACOS Administrator password
  --reboot              Instruct the A10 appliance to reboot following the
                        image upgrade (also executes a "write memory" command)
  -s, --set-bootimage   Set ACOS to use the new image on next boot.
  -u USERNAME, --username USERNAME
                        ACOS Administrator username. (default: )
  -v                    Enable verbose detail
  -w, --write           Save the configuration to non-volatile memory.
  --version             Print the current version information and exit.
  --dryrun              Performs the log-in actions and show commands, but
                        does not actually make changes to devices.
```
