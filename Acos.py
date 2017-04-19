import display

import json
import requests
import time


class Acos(object):
    """docstring for Acos"""

    def __init__(self, device, parameters):
        self.device = device
        self.base_url = 'https://' + device + '/axapi/v3/'
        self.current_image = None
        self.headers = {'content-type': 'application/json'}
        self.token = None
        self.hostname = device
        self.versions = {}
        self.set_bootimage = bool(parameters['set_bootimage'])
        self.use_mgmt = bool(parameters['use-mgmt'])
        self.verbosity = int(parameters['verbosity'])

    def authenticate(self, user, passwd):
        """docstring for authenticate"""
        display.info('Logging on...', self.device)
        axapi_module = 'auth'
        method = 'POST'
        payload = {"credentials": {"username": user, "password": passwd}}
        try:
            r = self.axapi_call(axapi_module, method, payload)
        except Exception as e:
            display.error('Unable to connect - {}'
                          .format(e),
                          self.hostname)
            return 'FAIL'
        try:
            token = r.json()['authresponse']['signature']
            self.headers['Authorization'] = 'A10 {}'.format(token)
        except Exception as e:
            display.error(e, self.hostname)
            return 'FAIL'

    def axapi_call(self, axapi_module, method='GET', payload=None):
        """docstring for axapi"""
        url = self.base_url + axapi_module
        if self.verbosity > 0:
            display.debug(url, self.hostname)
        if self.verbosity > 1:
            display.debug("Payload = {}".format(payload), self.hostname)

        if method == 'POST' and payload:
            r = requests.post(url, data=json.dumps(payload),
                              headers=self.headers, verify=False)
        elif method == 'POST':
            r = requests.post(url, headers=self.headers, verify=False)
        else:
            r = requests.get(url, headers=self.headers, verify=False)
        if self.verbosity > 0:
            display.debug(r.content, self.hostname)
        return r

    def axapi_status(self, result):
        """docstring for get_axapi_status"""
        try:
            json_result = result.json()
            if 'response' in json_result:
                status = json_result['response']['status']
                if status == 'fail':
                    error_msg = json_result['response']['err']['msg']
                    return error_msg
                else:
                    return status
        except:
            if self.verbosity > 1:
                display.debug(result.status_code, self.hostname)
            if 200 <= result.status_code < 300:
                status = 'OK'
                return status
            else:
                status = 'fail'
                return status

    def get_hostname(self):
        """docstring for get_hostname"""
        axapi_module = 'hostname'
        r = self.axapi_call(axapi_module)
        self.hostname = r.json()['hostname']['value']
        display.info("Logged on successfully", self.hostname)

    def show_version(self):
        """docstring for show_version"""
        axapi_module = 'version/oper'
        r = self.axapi_call(axapi_module)
        self.versions = r.json()['version']['oper']
        display.info("Current running ACOS is {}."
                     .format(self.versions['sw-version']), self.hostname)

    def get_bootimage(self):
        """docstring for bootimage"""
        try:
            boot_location = self.versions['boot-from']
            if boot_location == 'HD_PRIMARY':
                self.current_image = 'primary'
            elif boot_location == 'HD_SECONDARY':
                self.current_image = 'secondary'
        except Exception as e:
            display.error(e, self.hostname)
            return 'FAIL'
        display.info("Booted from the {} image location,"
                     .format(self.current_image), self.hostname)
        return self.current_image

    def upgrade_image(self, upgrade, upgrade_bootimage=False):
        """docstring for upgrade_image"""
        if upgrade_bootimage:
            upgrade_location = self.current_image
        else:
            if self.current_image == 'primary':
                upgrade_location = 'secondary'
            elif self.current_image == 'secondary':
                upgrade_location = 'primary'
            else:
                display.fatal('Something went wrong',
                              self.hostname)
                return 'FAIL'

        short_upgrade_location = upgrade_location[:3]
        display.info("Upgrading {} image via {}"
                     .format(upgrade_location, upgrade['protocol']),
                     self.hostname)
        display.info('The upgrade process may take some time...',
                     self.hostname)
        axapi_module = 'upgrade/hd'
        method = 'POST'
        payload = {"hd": {"image": short_upgrade_location,
                          "use-mgmt-port": int(self.use_mgmt),
                          "file-url": upgrade['uri']}}
        r = self.axapi_call(axapi_module, method, payload)
        status = self.axapi_status(r)

        if r.status_code == 202:  # This means we have more data to gather
            self.upgrade_status()
        elif status == 'fail':
            display.error(status, self.hostname)
            return 'FAIL'
        else:
            display.info(status, self.hostname)

        if self.set_bootimage:
            self.update_bootimage(upgrade_location, short_upgrade_location)

    def update_bootimage(self, upgrade_location, short_upgrade_location):
        display.info("Updating bootimage to {}..."
                     .format(upgrade_location), self.hostname)
        axapi_module = 'bootimage'
        method = 'POST'
        payload = {
            "bootimage": {"hd-cfg": {"hd": 1, short_upgrade_location: 1}}}
        r = self.axapi_call(axapi_module, method, payload)
        display.info(self.axapi_status(r), self.hostname)

    def upgrade_status(self):
        """docstring for upgrade_status"""
        axapi_module = 'upgrade-status/oper'
        method = 'GET'

        latest_status = 0
        upgrading = True
        while upgrading:
            r = self.axapi_call(axapi_module, method)
            if r.status_code == 200:
                current_status = r.json()['upgrade-status']['oper']['status']
                if current_status != latest_status:
                    latest_status = current_status
                    message = r.json()['upgrade-status']['oper']['message']
                    if current_status == 10:
                        upgrading = False
                    elif current_status > 7:
                        display.error(message, self.hostname)
                        upgrading = False
                        continue
                    display.info(message, self.hostname)
            else:
                print(r)
                upgrading = False
            time.sleep(3)

    def write_memory(self):
        """docstring for write_memory"""
        display.info("Saving configuration...", self.hostname)
        axapi_module = 'write/memory'
        method = 'POST'
        r = self.axapi_call(axapi_module, method)
        display.info(self.axapi_status(r), self.hostname)

    def show_bootimage(self):
        """docstring for show_bootimage"""
        axapi_module = 'bootimage/oper'
        r = self.axapi_call(axapi_module)
        bootimage = r.json()['bootimage']['oper']
        star = '(*)'
        pri_star = ''
        sec_star = ''
        if bootimage['hd-default'] == 'hd-pri':
            pri_star = star
        elif bootimage['hd-default'] == 'hd-sec':
            sec_star = star
        display.info('show bootimage', self.hostname)
        display.write('                       (* = Default)')
        display.write('                           Version')
        display.write(' -----------------------------------------------')
        display.write(' Hard Disk primary         {} {}'
                      .format(bootimage['hd-pri'], pri_star))
        display.write(' Hard Disk secondary       {} {}'
                      .format(bootimage['hd-sec'], sec_star))
        display.write('')

    def reboot(self):
        """docstring for reboot"""
        display.info("Rebooting. The appliance could be unavailable for up to 5\
              minutes...", self.hostname)
        axapi_module = 'reboot'
        method = 'POST'
        r = self.axapi_call(axapi_module, method)
        display.info(self.axapi_status(r), self.hostname)

    def logoff(self):
        """docstring for logoff"""
        display.info("Logging off...", self.hostname)
        axapi_module = 'logoff'
        method = 'POST'
        r = self.axapi_call(axapi_module, method)
        display.info(self.axapi_status(r), self.hostname)
