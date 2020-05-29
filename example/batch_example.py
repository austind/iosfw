# -*- coding: utf-8 -*-

import iosfw
import getpass

hosts = ['switch1.example.com', 'switch2', 'switch3', 'switch4', '172.16.32.54']
whoami = getpass.getuser()
username = input("Username [{}]: ".format(whoami)) or whoami
password = getpass.getpass()
secret = getpass.getpass("Enable secret: ")

upgrade_args = {
    'hostname': None,
    'username': username,
    'password': password,
    'optional_args': {
        'secret': secret
    }
}

for host in hosts:
    upgrade_args['hostname'] = host
    device = iosfw.iosfw(**upgrade_args)
    device.open()
    device.upgrade()
    device.close()
