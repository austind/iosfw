# -*- coding: utf-8 -*-

import iosfw
import getpass

hosts = ['switch1.example.com', 'switch2', 'switch3', 'switch4', '172.16.32.54']
current_user = getpass.getuser()
username = input("Username [{}]: ".format(current_user)) or current_user
password = getpass.getpass()

upgrade_args = {
    'hostname': None,
    'username': username,
    'password': password,
    'optional_args': None
}

for host in hosts:
    upgrade_args['hostname'] = host
    device = iosfw.iosfw(**upgrade_args)
    device.upgrade()
    device.close()
