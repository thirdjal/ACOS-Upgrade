#!/usr/bin/env python
#
# Copyright 2017, John Lawrence <jlawrence AT a10networks DOT com>
#
# v0.3:  20160720 - Display the ACOS installed versions
# v0.4:  20160721 - Added option to reboot following an upgrade
# v0.5:  20160721 - Improved handling of connection errors
# v0.6:  20160725 - Allow multiple devices to be included in the arguments list
# v0.7:  20160728 - Corrected axapi_status() to not crash
# v0.8:  20160730 - Minor formatting and improvements
# v0.9:  20160802 - Handle reboot module in ACOS 3.2
# v0.10: 20160808 - Refactor axapi_status() to operate more cleanly
# v0.11: 20170418 -
#
# Requires:
#   - Python 2.7.x
#   - ACOS   3.0 or higher
#   - axapi  V3
#
# TODO: Add option to run multiple threads simultaneously
# TODO: Figure out how to deal w/ TLS_1.2 requirement when OpenSSL < 1.0.1

import argparse
from getpass import getpass

import logging

import display
import file
from Acos import Acos

__version__ = 0.11
__author__ = 'A10 Networks, Inc.'


def main():
    display.header("A10 Threat Protection System Image Upgrade",
                   version=__version__, author=__author__)
    options, url = initialize()
    event_loop(options, url)


def event_loop(options, upgrade_url):
    for appliance in options['devices']:
        appliance = Acos(appliance, options)

        a = appliance.authenticate(options['admin_username'],
                                   options['admin_password'])
        if a == 'FAIL':
            continue

        appliance.get_hostname()

        appliance.show_version()

        b = appliance.get_bootimage()
        if b == 'FAIL':
            continue

        # TODO: Add a "Dry Run option to not execute config level commands"
        if not options['dry_run']:
            u = appliance.upgrade_image(upgrade_url,
                                        options['overwrite_bootimage'])
            if u == 'FAIL':
                continue

        appliance.show_bootimage()

        if options['write_memory'] and not options['dry_run']:
            appliance.write_memory()

        if options['reboot'] and not options['dry_run']:
            appliance.write_memory()
            appliance.reboot()
        else:
            appliance.logoff()

        print('')
    print('DONE\n')

    return options


def initialize():
    defaults = {
        "config_file"        : "defaults.conf",
        "devices_file"       : "devices.txt",
        "admin_username"     : "",
        "admin_password"     : "",
        "upgrade_url"        : "",
        "use-mgmt"           : False,
        "overwrite_bootimage": False,
        "print_version"      : False,
        "reboot"             : False,
        "set_bootimage"      : False,
        "verbosity"          : 0,
        "write_memory"       : False,
        "dry_run"            : False,
    }
    parameters = get_parameters_from_file(defaults)
    parameters = get_parameters_from_arguments(parameters)

    if parameters['print_version']:
        exit(0)

    if parameters['verbosity'] < 2:
        logging.captureWarnings(True)

    if not parameters['upgrade_url']:
        display.write("")
        display.write("  What is the URL for the upgrade file?")
        display.write(
                "    e.g. 'scp://username:password@servername/path/to/file'")
        parameters['upgrade_url'] = display.prompt("  > ")
        display.write("")
    # TODO: Better error handling with badly formed URLs
    try:
        url = get_uri_components(parameters['upgrade_url'])
    except:
        display.fatal("Do not recognize {} as a properly formatted URL!"
                      .format((parameters['upgrade_url'])))

    if not parameters['devices']:
        parameters['devices'] = get_devices_from_file(
                parameters['devices_file'])

    if parameters['verbosity'] > 0:
        display.info("Using enhanced display output.")

    if len(parameters['devices']) == 1:
        plural = ''
    else:
        plural = 's'
    display.info("Upgrade {} device{} to {}"
                 .format(len(parameters['devices']), plural, url['filename']))
    display.info("from {} using {}."
                 .format(url['servername'], url['protocol']))

    if parameters['use-mgmt']:
        display.info('Upgrade using the management interface.')

    if parameters['overwrite_bootimage']:
        display.info('Overwrite the currently running bootimage location.')
    else:
        display.info('Upgrading the backup/unbooted bootimage location.')

    if parameters['set_bootimage']:
        display.info("Mark the new image to be used during the next reboot.")

    if parameters['reboot'] or parameters['write_memory']:
        display.info('Save the current running configuration to NVRAM.')

    if parameters['reboot']:
        display.warn('Reboot devices following image upgrade.')

    if parameters['dry_run']:
        display.warn('Dry run option set, will not make any changes.')

    if not parameters['admin_username']:
        display.write('')
        parameters['admin_username'] = display.prompt("login: ")

    if not parameters['admin_password']:
        parameters['admin_password'] = getpass('Enter password for {}: '
                                         .format(parameters['admin_username']))

    display.write('')
    return parameters, url


def get_parameters_from_file(options):
    full_filename = file.get_full_path(options['config_file'])
    updated_options = options

    if file.exists(full_filename):
        updated_options = file.import_settings(full_filename, options)

    return updated_options


def get_parameters_from_arguments(options):
    updated_options = options
    p = argparse.ArgumentParser(description='Running this script will \
         upgrade the ACOS software on an A10 appliance. Contains options to \
         overwrite the currently booted image or upgrade the standby image.')
    devices = p.add_mutually_exclusive_group()
    devices.add_argument('-f', '--file', dest='devices_file',
                         default=options['devices_file'],
                         help='Simple text file containing a list of devices, \
                         one per line, to upgrade.')
    devices.add_argument('device', nargs='*',
                         default=None,
                         help='A10 device hostname or IP address. Multiple \
                         devices may be included separated by a space.')
    p.add_argument('-i', '--image', metavar="URL",
                   default=options['upgrade_url'],
                   help='Remote file path for upgrade image.  Format: \
                   (tftp|ftp|scp|sftp)://[user[:password]@]host[:port]/file')
    p.add_argument('-m', '--use-mgmt', dest='use_mgmt', action='store_true',
                   default=options['use-mgmt'],
                   help='Attempt an upgrade via the management interface.')
    p.add_argument('--overwrite', action='store_true',
                   default=options['overwrite_bootimage'],
                   help='Overwrite the currently booted image. Default \
                   action will upgrade the non-booted image version')
    p.add_argument('-p', '--password',
                   default=options['admin_password'],
                   help='ACOS Administrator password')
    p.add_argument('--reboot', action='store_true',
                   default=options['reboot'],
                   help='Instruct the A10 appliance to reboot following the \
                   image upgrade (also executes a "write memory" command)')
    p.add_argument('-s', '--set-bootimage', dest='set', action='store_true',
                   default=options['set_bootimage'],
                   help='Set ACOS to use the new image on next boot.')
    p.add_argument('-u', '--username',
                   default=options['admin_username'],
                   help='ACOS Administrator username. (default: {})'
                   .format(options['admin_username']))
    p.add_argument("-v", action='count', dest='verbosity',
                   default=options['verbosity'],
                   help="Enable verbose detail")
    p.add_argument("-w", "--write", action='store_true',
                   default=options['write_memory'],
                   help="Save the configuration to non-volatile memory.")
    p.add_argument('--version', action='store_true',
                   default=options['print_version'],
                   help="Print the current version information and exit.")
    p.add_argument('--dryrun', action='store_true',
                   default=options['dry_run'],
                   help="Performs the log-in actions and show commands, but \
                   does not actually make changes to devices.")
    try:
        args = p.parse_args()
        updated_options['devices'] = args.device
        updated_options['devices_file'] = args.devices_file
        updated_options['dry_run'] = args.dryrun
        updated_options['overwrite_bootimage'] = args.overwrite
        updated_options['reboot'] = args.reboot
        updated_options['admin_password'] = args.password
        updated_options['admin_username'] = args.username
        updated_options['upgrade_url'] = args.image
        updated_options['use-mgmt'] = args.use_mgmt
        updated_options['set_bootimage'] = args.set
        updated_options['verbosity'] = args.verbosity
        updated_options['print_version'] = args.version
        updated_options['write_memory'] = args.write
    except IOError as msg:
        p.error(str(msg))

    return updated_options


def get_devices_from_file(filename):
    """
    Reads in a list of devices from a plain text file and returns the list.
    
    :param filename: The name of a file containing device names or IP 
    addresses.
    :return: A populated list of device names and/or IP addresses.
    """

    full_filename = file.get_full_path(filename)
    devices = []
    if file.exists(full_filename):
        devices = file.read(full_filename)
    return devices


def get_uri_components(url):
    """
    Given a full uniform resource identifier, break out the components into a
    dictionary
    :param url: 
    :return: 
    """
    protocol, sliced_url = url.split('://', 1)
    servername, pathname = sliced_url.split('/', 1)
    filename = pathname[pathname.rfind('/', 0, len(pathname)) + 1:len(
            pathname)]

    username = None
    password = None
    if servername.find('@', 0, len(servername)) > 0:
        authentication, servername = servername.split('@', 1)
        if authentication.find(':', 0, len(authentication)) > 1:
            username, password = authentication.split(':', 1)
        else:
            username = authentication

    port = None
    if servername.find(':', 0, len(servername)) > 0:
        servername, port = servername.split(':', 1)

    uri_components = {'protocol'  : protocol.upper(),
                      'username'  : username,
                      'password'  : password,
                      'servername': servername,
                      'port'      : port,
                      'pathname'  : pathname,
                      'filename'  : filename,
                      'uri'       : url}
    return uri_components


if __name__ == '__main__':
    finished = False
    while not finished:
        try:
            main()
            finished = True
        except KeyboardInterrupt:
            print("^C")
            finished = True
