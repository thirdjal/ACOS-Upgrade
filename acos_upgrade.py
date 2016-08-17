#!/usr/bin/env python
#
# Copyright 2016, John Lawrence <jlawrence AT a10networks DOT com>
#
# v0.3: 20160720 - Display the ACOS installed versions
# v0.4: 20160721 - Added option to reboot following an upgrade
# v0.5: 20160721 - Improved handling of connection errors
# v0.6: 20160725 - Allow multiple devices to be included in the arguments list
# v0.7: 20160728 - Corrected axapi_status() to not crash
# v0.8: 20160730 - Minor formatting and improvements
# v0.9: 20160802 - Handle reboot module in ACOS 3.2
# v0.10: 20160808 - Refactor axapi_status() to operate more cleanly
#
# Requires:
#   - Python 2.7.x
#   - ACOS   3.0 or higher
#   - axapi  V3
#
# TODO: Add option to run multiple threads simultaneously
# TODO: Figure out how to deal w/ TLS_1.2 requirement when OpenSSL < 1.0.1
# TODO: Read defaults from an external file (e.g. acos_upgrade.config)


import argparse
import getpass
import json
import logging
import requests
import sys


# DEFAULT SETTINGS
# Settings here will override the built-in defaults. Can be overridden by 
# runtime arguments supplied at the CLI.
devices_file = 'hosts.txt'
upgrade_url = 'tftp://10.8.8.1/ACOS_non_FTA_3_2_1-SP2_5.64.upg'
username = 'admin'
use_mgmt = False
password = None
verbose = 0


#
# Create and capture the command-line arguments
#
parser = argparse.ArgumentParser(description='Running this script will        \
     upgrade the ACOS software on an A10 appliance. Contains options to       \
     overwrite the currently booted image or upgrade the standby image.')
devices = parser.add_mutually_exclusive_group()
devices.add_argument('-f', '--file', dest='devices_file', default=devices_file,
                     help='Simple text file containing a list of devices,     \
                     one per line, to upgrade')
devices.add_argument('device', nargs='*', default='',
                     help='A10 device hostname or IP address. Multiple        \
                     devices may be included separated by a space.')
parser.add_argument('-i', '--image', metavar="URL", default=upgrade_url,
                    help='Remote file path for upgrade image.  Format:        \
                    (tftp|ftp|scp|sftp)://[user[:password]@]host[:port]/file')
parser.add_argument('-m', '--use-mgmt', dest='use_mgmt', action='store_true',
                    default=use_mgmt,
                    help='Attempt the upgrade via built-in management interface')
parser.add_argument('--overwrite', action='store_true',
                    help='Overwrite the currently booted image. Default       \
                    action will upgrade the non-booted image version')
parser.add_argument('-p', '--password', default=password,
                    help='ACOS Administrator password')
parser.add_argument('--reboot', action='store_const', const=1, default=0,
                    help='Instruct the A10 appliance to reboot following the  \
                    image upgrade (also executes a "write memory" command)')
parser.add_argument('-s', '--set-bootimage', dest='set_bootimage',
                    action='store_true',
                    help='Set ACOS to use the new image on next boot')
parser.add_argument('-u', '--username', default=username,
                    help='ACOS Administrator username (default: {})'
                    .format(username))
parser.add_argument("-v", "--verbose", action='count', default=verbose,
                    help="Enable verbose detail")
parser.add_argument("-w", "--write", action='store_true',
                    help="Save the configuration to non-volatile memory")
try:
    args = parser.parse_args()
    devices = args.device
    devices_file = args.devices_file
    overwrite_bootimage = args.overwrite
    reboot = args.reboot
    password = args.password
    username = args.username
    upgrade_url = args.image
    use_mgmt = args.use_mgmt
    set_bootimage = args.set_bootimage
    verbose = args.verbose
    write_memory = args.write
except IOError as msg:
    parser.error(str(msg))


#
# Done with arguments. The actual program begins here.
#
def main():
    """docstring for main"""
    upgrade = get_url_components(upgrade_url)

    for appliance in device_list:
        appliance = Acos(appliance)

        a = appliance.authenticate(username, password)
        if a == 'FAIL':
            continue
        
        appliance.get_hostname()

        appliance.show_version()

        b = appliance.get_bootimage()
        if b == 'FAIL':
            continue

        if overwrite_bootimage:
            appliance.upgrade_image(upgrade, 'active')
        else:
            appliance.upgrade_image(upgrade)
        appliance.show_bootimage()

        if write_memory:
            appliance.write_memory()
        if reboot:
            appliance.write_memory()
            appliance.reboot()
        else:
            appliance.logoff()
        print('')
    print('DONE\n')


def read_devices_file(the_file):
    """docstring for read_devices_file"""
    print('  INFO: Looking for device addresses in {}'.format(the_file))
    try:
        devices_in_file = []
        number_of_devices = 0
        plural = ''
        with open(the_file) as f:
            for device in f.readlines():
                if device.startswith('#') or device.rstrip() == '':
                    # Skip comments and blank lines
                    continue
                devices_in_file.append(device.rstrip())
                number_of_devices = len(devices_in_file)
            if number_of_devices != 1:
                plural = 'es'
            print('  INFO: Found {} device address{}.'
                  .format(number_of_devices, plural))
            return devices_in_file
    except Exception as e:
        print('\n  ERROR: {}'.format(e))
        sys.exit(1)


def get_url_components(url):
    """docstring for get_url_components"""
    sliced_url = url.split('://', 1)
    upgrade_protocol = sliced_url[0]
    remainder = sliced_url[1]
    
    sliced_url = remainder.split('/', 1)
    server = sliced_url[0]
    path_and_file = sliced_url[1]
    upgrade_file = path_and_file[
        path_and_file.rfind('/', 0, len(path_and_file)) + 1:len(path_and_file)]
    server_has_credentials = server.find('@', 0, len(server))
    if server_has_credentials > 0:
        server_sliced = server.split('@', 1)
        server_authentication = server_sliced[0]
        server_address = server_sliced[1]
    else:
        server_authentication = None
        server_address = server
    
    url_components = {'protocol': upgrade_protocol.upper(),
                  'authentication': server_authentication,
                  'address': server_address,
                  'path': path_and_file,
                  'filename': upgrade_file,
                  'uri': url}
    return url_components


def axapi_status(result):
    """docstring for get_axapi_status"""
    if result.status_code == requests.codes.ok:
        status = 'OK'
        return status
    elif 'response' in result.json():
        status = result.json()['response']['status']
        if status == 'fail':
            error_msg = '\n  ERROR: {}'.format(
                result.json()['response']['err']['msg'])
            return error_msg
        else:
            return status
    else:
        status = result.status_code
        return status


class Acos(object):
    """docstring for Acos"""
    def __init__(self, address):
        self.device = address
        self.base_url = 'https://' + address + '/axapi/v3/'
        self.current_image = None
        self.headers = {'content-type': 'application/json'}
        self.token = None
        self.hostname = None
        self.versions = {}
    
    def authenticate(self, user, passwd):
        """docstring for authenticate"""
        print('\nLogging onto {}...'.format(self.device))
        module = 'auth'
        method = 'POST'
        payload = {"credentials": {"username": user, "password": passwd}}
        try:
            r = self.axapi_call(module, method, payload)
        except Exception as e:
            print('  ERROR: Unable to connect to {} - {}'.format(self.device, e))
            return 'FAIL'
        try:
            token = r.json()['authresponse']['signature']
            self.headers['Authorization'] = 'A10 {}'.format(token)
        except Exception as e:
            print('\n  ERROR: {}'.format(e))
            return 'FAIL'

    def axapi_call(self, module, method='GET', payload=None):
        """docstring for axapi"""
        url = self.base_url + module
        if method == 'POST' and payload:
            r = requests.post(url, data=json.dumps(payload),
                              headers=self.headers, verify=False)
        elif method == 'POST':
            r = requests.post(url, headers=self.headers, verify=False)
        else:
            r = requests.get(url, headers=self.headers, verify=False)
        if verbose:
            print(r.content)
        return r

    def get_hostname(self):
        """docstring for get_hostname"""
        module = 'hostname'
        r = self.axapi_call(module)
        hostname = r.json()['hostname']['value']
        print("   {}: Logged on successfully".format(hostname))
        self.hostname = hostname
    
    def show_version(self):
        """docstring for show_version"""
        module = 'version/oper'
        r = self.axapi_call(module)
        self.versions = r.json()['version']['oper']

    def get_bootimage(self):
        """docstring for bootimage"""
        try:
            boot_location = self.versions['boot-from']
            if boot_location == 'HD_PRIMARY':
                self.current_image = 'primary'
            elif boot_location == 'HD_SECONDARY':
                self.current_image = 'secondary'
        except Exception as e:
            print('\n  ERROR: {}'.format(e))
            return 'FAIL'
        print("   {}: Booted from the {} image" 
              .format(self.hostname, self.current_image))
        return self.current_image
    
    def upgrade_image(self, upgrade, image_location='standby'):
        """docstring for upgrade_image"""
        if image_location == 'active':
            upgrade_location = self.current_image
        elif image_location == 'standby':
            if self.current_image == 'primary':
                upgrade_location = 'secondary'
            elif self.current_image == 'secondary':
                upgrade_location = 'primary'
            else:
                print('Something went wrong')
                return 'FAIL'
        else:
            print('\n  ERROR: Invalid upgrade location')
            return 'FAIL'
        
        short_upgrade_location = upgrade_location[:3]
        print("   {}: Upgrading {} image using {}" 
              .format(self.hostname, upgrade_location, upgrade['protocol']))
        print('      This may take some time...')
        module = 'upgrade/hd'
        method = 'POST'
        payload = {"hd": {"image": short_upgrade_location,
                          "use-mgmt-port": int(use_mgmt),
                          "file-url": upgrade['uri']}}
        r = self.axapi_call(module, method, payload)
        print('      {}'.format(axapi_status(r)))

        if set_bootimage:
            print("   {} Updating bootimage to {}..." 
                  .format(self.hostname, upgrade_location))
            module = 'bootimage'
            method = 'POST'
            payload = {"bootimage": {"hd-cfg": {"hd": 1, short_upgrade_location: 1}}}
            r = self.axapi_call(module, method, payload)
            print('      {}'.format(axapi_status(r)))

    def write_memory(self):
        """docstring for write_memory"""
        print("   {}: Saving configuration".format(self.hostname))
        module = 'write/memory'
        method = 'POST'
        r = self.axapi_call(module, method)
        print('      {}'.format(axapi_status(r)))

    def show_bootimage(self):
        """docstring for show_bootimage"""
        module = 'bootimage/oper'
        r = self.axapi_call(module)
        bootimage = r.json()['bootimage']['oper']
        star = '(*)'
        pri_star = ''
        sec_star = ''
        if bootimage['hd-default'] == 'hd-pri':
            pri_star = star
        elif bootimage['hd-default'] == 'hd-sec':
            sec_star = star
        print('')
        print('      {}: ACOS Versions'.format(self.hostname))
        print('      --------------------------------------------')
        print('      HD Primary:   {} {}'.format(bootimage['hd-pri'], pri_star))
        print('      HD Secondary: {} {}'.format(bootimage['hd-sec'], sec_star))
        print('      --------------------------------------------')
        print('')
        pass

    def reboot(self):
        """docstring for reboot"""
        print("   {}: Rebooting. The appliance will be unavailable for up to 5\
              minutes...".format(self.hostname))
        module = 'reboot'
        method = 'POST'
        r = self.axapi_call(module, method)
        print('      {}'.format(axapi_status(r)))

    def logoff(self):
        """docstring for logoff"""
        print("   {}: Logging off...".format(self.hostname))
        module = 'logoff'
        method = 'POST'
        r = self.axapi_call(module, method)
        print('      {}'.format(axapi_status(r)))


if __name__ == '__main__':
    #
    # Apply the defaults and arguments
    #
    print('')
    device_list = []
    if devices_file:
        print('  INFO: Looking for device file: {}'.format(devices_file))
        device_list = read_devices_file(devices_file)
    elif devices:
        device_list = devices
    if verbose < 2:
        logging.captureWarnings(True)
    if use_mgmt:
        print('  INFO: Will attempt upgrade via interface management')
    if not password:
        password = getpass.getpass('\nEnter password for {}: '.format(username))
    print('  INFO: Upgrading from {}'.format(upgrade_url))
    
    finished = False
    while not finished:
        try:
            print('Starting ACOS Upgrade')
            main()
            finished = True
        except KeyboardInterrupt:
            print('Exiting')
            finished = True
