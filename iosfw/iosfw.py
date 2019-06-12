#!/usr/bin/env python2.7

import datetime
import getpass
import hashlib
import logging
import napalm
from netmiko import FileTransfer, SCPConn
import os
import re
import time
from tqdm import tqdm
import yaml

""" An API built upon NAPALM and Netmiko to manage Cisco IOS firmware. """


class iosfw(object):
    def __init__(self, hostname=None, username=None, password=None,
                 timeout=60, driver='ios', optional_args=None,
                 config_file='./config/config.yaml',
                 image_file='./config/images.yaml'):
        """ Initializes connection and file transfer """

        # Config
        self.config_file = config_file
        self.config      = self._read_yaml_file(config_file)
        self.image_file  = image_file
        self.image_info  = self._read_yaml_file(image_file)

        # Logging
        self.log_method = self.config['log_method']
        self.log_file = self.config['log_file']
        self.file_log_level = self.config['file_log_level']
        self.console_log_level = self.config['console_log_level']
        file_level = getattr(logging, self.file_log_level.upper(), None)
        console_level = getattr(logging, self.console_log_level.upper(), None)
        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.DEBUG)
        if self.log_method == 'tee' or self.log_method == 'file':
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            fh = logging.FileHandler(self.log_file)
            fh.setLevel(file_level)
            fh.setFormatter(formatter)
            self.log.addHandler(fh)

        if self.log_method == 'tee' or self.log_method == 'console':
            formatter = logging.Formatter('%(message)s')
            ch = logging.StreamHandler()
            ch.setLevel(console_level)
            ch.setFormatter(formatter)
            self.log.addHandler(ch)

        self.log.debug('Config file: {}'.format(self.config_file))
        self.log.debug('Config parameters: {}'.format(self.config))
        self.log.debug('Image file: {}'.format(self.image_file))
        self.log.debug('Image info: {}'.format(self.image_info))

        # Set up connection
        if hostname is None:
            hostname = str(raw_input('Hostname or IP: '))
        if username is None:
            whoami = getpass.getuser()
            username = str(raw_input('Username [{}]: '.format(whoami))) \
                or whoami
        if password is None:
            password = getpass.getpass()
        if optional_args is None:
            optional_args = {}
            secret = getpass.getpass('Enable secret: ')
            optional_args.update({'secret': secret})
            if self.config['ssh_config_file']:
                optional_args.update({'ssh_config_file':
                                       self.config['ssh_config_file']})

        napalm_driver = napalm.get_network_driver(driver)
        self.napalm = napalm_driver(hostname=hostname, username=username,
                                    password=password, timeout=timeout,
                                    optional_args=optional_args)
        
        self.log.info('Opening connection to {}...'.format(hostname))
        self.napalm.open()

        # Aliases and info
        self.device = self.napalm.device                # Netmiko session
        self.facts = self.napalm.get_facts()            # NAPALM facts
        self.os_version = self.facts['os_version']
        self.model = self.facts['model']
        self.hostname = self.facts['hostname']
        self.fqdn = self.facts['fqdn']
        self.transport = self.napalm.transport          # ssh or telnet
        self.upgrade_image_exists = False
        self.upgrade_image_valid = False
        self.upgrade_space_available = False
        self.running_image_path = self.get_running_image()
        self.running_image_name = self.get_basename(self.running_image_path)
        self.running_image_feature_set = \
            self._get_image_feature_set(self.running_image_name)
        self.upgrade_image_name = self.get_upgrade_image_name()
        self.upgrade_version = self.get_upgrade_version()
        self.running_version = self.get_running_version()
        self.upgrade_image_src_path = \
            self._get_src_path(self.upgrade_image_name)
        self.upgrade_image_dest_path = \
            self._get_dest_path(self.upgrade_image_name)
        self.boot_image_path = self.get_boot_image()
        self.upgrade_installed = self.check_upgrade_installed()
        self.needs_upgrade = self.check_needs_upgrade()
        self.upgrade_cmd = self._get_upgrade_cmd()
        if 'copy' in self.upgrade_cmd:
            self.upgrade_method = 'manual'
        else:
            self.upgrade_method = 'auto'
        self.transfer_proto = self.config['transfer_proto']
        self.needs_reload = self.check_needs_reload()
        self.reload_scheduled = self.check_reload_scheduled()
        if self.config['delete_old_image'] != 'never':
            self.can_delete_old_image = True
        else:
            self.can_delete_old_image = False
        self.log.info("Connected to {} ({}) as {} via {}".format( \
                      self.hostname, self.model, self.device.username, \
                      self.transport))
        self.log_upgrade_status()


    def log_upgrade_status(self, refresh=False):
        """ Logs upgrade-related facts about device """
        if refresh:
            self.refresh_upgrade_status()
        if self.upgrade_installed:
            if self.needs_reload:
                self.log.info("Upgrade status: FIRMWARE INSTALLED")
                self.log.info("Running version: {}".format(self.running_version))
                if self.reload_scheduled:
                    time = self.reload_scheduled['absolute_time']
                    self.log.info("Reload status: RELOAD SCHEDULED for {}".format(time))
                else:
                    self.log.info("Reload status: NEEDS RELOAD")
            else:
                self.log.info("Upgrade status: COMPLETE")
                self.log.info("Running version: {}".format(self.running_version))
        else:
            self.log.info("Upgrade status: NEEDS UPGRADE")
            self.log.info("Upgrade version: {}".format(self.upgrade_version))
            self.log.info("Running version: {}".format(self.running_version))


    def refresh_upgrade_status(self, log=False):
        """ Updates device status """
        self.boot_image_path = self.get_boot_image()
        self.upgrade_installed = self.check_upgrade_installed()
        self.needs_reload = self.check_needs_reload()
        self.reload_scheduled = self.check_reload_scheduled()
        if log:
            self.log_upgrade_status()

   
    def __del__(self):
        self.napalm.__del__()


    def _get_upgrade_cmd(self):
        """ Returns a command string for auto-upgrade, if supported """
        image_src = self._get_src_path()
        image_dest = self._get_dest_path()
        cmds = [
            'request',
            'software',
            'archive',
            'copy',
        ]        
        for cmd in cmds:
            output = self.device.send_command(cmd + ' ?')
            if 'Unknown' not in output:
                method = cmd
                break
        if method == 'request':
            return 'request platform software package install switch all ' \
                   'file {} new auto-copy'.format(image_src)
        if method == 'software':
            return 'software install ' \
                   'file {} new on-reboot'.format(image_src)
        if method == 'archive':
            flags = ' '
            if self.config['delete_old_image'] == 'never':
                flags += '/safe /leave-old-sw '
            else:
                flags += '/overwrite '
            return 'archive download-sw{}{}'.format(flags, image_src)
        if method == 'copy':
            return 'copy {} {}'.format(image_src, image_dest)


    def _strip_extension(self, file_name=None):
        """ Returns a file name without the extension """
        if file_name is None:
            file_name = self.upgrade_image_name
        split = self.upgrade_image_name.split('.')
        del split[-1]
        return '.'.join(split)


    def _get_src_path(self, file_name=None, local=False):
        """ Returns full source file path """
        proto = self.config['transfer_proto']
        un = self.config['transfer_username']
        pw = self.config['transfer_password'] or ''
        path = self.config['transfer_path']
        src = self.config['transfer_source']
        if file_name is None:
            file_name = self.upgrade_image_name
        if proto == 'scp' or local:
            path = self.config['src_image_path']
            return '{}/{}'.format(path, file_name)
        elif proto == 'ftp':
            return '{}://{}:{}@{}{}{}'.format(proto, un, pw, src, path,
                                              file_name)
        else:
            return '{}://{}{}{}'.format(proto, src, path, file_name)


    def _get_dest_path(self, file_name=None, absolute=True):
        """ Returns full destination file path
            absolute (bool):
                True = path includes dest_filesystem
                False = path does not include dest_filesystem
        """
        if file_name is None:
            file_name = self.upgrade_image_name
        full_path = ""
        if absolute:
            full_path += self.config['dest_filesystem']
        full_path += "%s%s" % (self.config['dest_image_path'], \
                             file_name)
        return full_path


    def _read_yaml_file(self, file_name):
        """ Reads and parses YAML file """
        with open(file_name, "r") as f:
            file_contents = f.read()
            parsed_yaml = yaml.load(file_contents)
        return parsed_yaml


    def _file_md5(self, file_name):
        """ Compute MD5 hash of local file_name """
        with open(file_name, "rb") as f:
            file_contents = f.read()
            file_hash = hashlib.md5(file_contents).hexdigest()
        return file_hash


    def _get_image_feature_set(self, file_name):
        """ Parses the feature set string from an IOS file name
            
            e.g.: ipbasek9, universalk9, ipservicesk9
        """
        return re.split(r'[-\.]', file_name)[1]


    def _check_image_feature_set(self, file_name):
        """ Checks if a given image's feature set matches the running
            image's feature set.

            Ignores K9 in the feature set string, so 'ipbasek9'
            matches 'ipbase'

        """
        regex = r'[Kk]9'
        set1 = re.sub(regex, '', self.running_image_feature_set)
        set2 = re.sub(regex, '', file_name)

        return set1 == set2


    def _scp_tqdm(self, t):
        """ Provides progress bar """
        # https://github.com/tqdm/tqdm/blob/master/examples/tqdm_wget.py
        last_b = [0]
        def update_to(filename, size, sent):
            t.total = size
            t.desc = filename
            t.update(sent - last_b[0])
            last_b[0] = sent
        return update_to


    def _write_config(self):
        """ Writes running configuration to NVRAM """
        cmd = 'write memory'
        output = self.device.send_command_expect(cmd)


    def _send_write_config_set(self, config_set):
        """ Sends configuration set to device and writes to NVRAM """
        output = self.device.send_config_set(config_set)
        if 'Invalid input' not in output:
            self._write_config()
            return True
        else:
            msg = "Device reports invalid configuration commands.\n" \
                  "Commands: %s\nOutput: %s\n" % \
                  (config_set, output)
            raise ValueError(msg)


    def close(self):
        """ Closes all connections to device and logs """
        self.napalm.close()
        handlers = self.log.handlers[:]
        for h in handlers:
            h.close()
            self.log.removeHandler(h)


    def _ensure_enable_not_config(self):
        """ Places device in enable mode and takes out of config mode """
        if not self.device.check_enable_mode():
            self.device.enable()
        if self.device.check_config_mode():
            self.device.exit_config_mode()


    def get_upgrade_image_name(self):
        """ Returns the file name of the device's upgrade image  """
        for file_name, attrs in self.image_info.iteritems():
            if self.model in attrs['models']:
                if self.config['match_feature_set']:
                    if not self._check_image_feature_set(file_name):
                        continue
                upgrade_image_path = self._get_src_path(file_name)
                if self.config['transfer_source'] != 'localhost':
                    return file_name
                elif os.path.exists(upgrade_image_path):
                    upgrade_image_md5 = self._file_md5(upgrade_image_path)
                    if upgrade_image_md5.lower() == attrs['md5'].lower():
                        return file_name
                    else:
                        msg = "MD5 for image %s does not match MD5 in " \
                              "config.\nImage MD5: %s\nConfig MD5: \n" \
                              % (file_name, attrs['md5'], upgrade_image_md5)
                        raise ValueError(msg)
                else:
                    msg = "Image file does not exist: %s" % upgrade_image_path
                    raise ValueError(msg)
        msg = "Could not find upgrade image for model %s in image file %s." \
              % (self.model, self.image_file)
        raise ValueError(msg)


    def get_basename(self, file_path):
        """ Returns a file name from a file path
            
            Example input: 'flash:/c3750-ipbase-mz.122-25.SEE1.bin'
            Example output: 'c3750-ipbase-mz.122-25.SEE1.bin'

        """
        return re.split(r'[:/]', file_path)[-1]


    def get_upgrade_version(self, raw=False):
        """ Parses image name to return IOS version string """
        if 'SPA' in self.upgrade_image_name:
            # IOS XE
            pattern = r'(\d+\.\d+\.\d+)\.SPA'
            match = re.search(pattern, self.upgrade_image_name)
            if match:
                if raw:
                    return match.group(1)
                else:
                    return re.sub('\.0', '.', match.group(1))
        else:
            # IOS
            pattern = r'(\d{3})-(\d+)\.(\w+)'
            match = re.search(pattern, self.upgrade_image_name)
            if match:
                if raw:
                    return match.group(0)
                else:
                    train = '{}.{}'.format(match.group(1)[:2], match.group(1)[2:])
                    throttle = match.group(2)
                    rebuild = match.group(3)
                    return '{}({}){}'.format(train, throttle, rebuild)


    def get_running_version(self):
        """ Parses self.os_version for IOS version string """
        pattern = r'ersion ([^,]+),'
        match = re.search(pattern, self.os_version)
        if match:
            return match.group(1)


    def get_running_image(self):
        """ Returns the remote path of the image running in memory """
        search_string = 'System image file is '
        output = self.device.send_command('show ver | i %s' % search_string)
        if search_string in output:
            return output.replace(search_string, '').replace('"', '')
        else:
            msg = "Could not find running image. Last output:\n%s" \
                  % output
            raise ValueError(msg)


    def get_boot_image(self):
        """ Returns the remote path of the image used on next reload """
        cmd = 'show boot | include BOOT'
        output = self.device.send_command(cmd)
        # TODO: Better validation here
        return output.split(': ')[-1].strip()


    def set_boot_image(self, new_boot_image_path=None):
        """ Configures device to boot given image on next reload """
        if new_boot_image_path is None:
            new_boot_image_path = self.upgrade_image_dest_path
        config_set = [
            'no boot system',
            'boot system {}'.format(new_boot_image_path)
        ]
        return self._send_write_config_set(config_set)


    def ensure_boot_image(self, new_boot_image_path=None):
        """ Ensures the given image is set to boot, if not already.
            
            new_boot_image_path (str): full destination path to boot image,
                including filesystem

            Does nothing if already set.
        """
        if new_boot_image_path is None:
            new_boot_image_path = self.upgrade_image_dest_path
        self.log.info("Checking boot image...")
        current_boot_image_path = self.get_boot_image()
        if current_boot_image_path != new_boot_image_path:
            self.log.info("Setting boot image to {}...".format(new_boot_image_path))
            if self.set_boot_image(new_boot_image_path):
                confirm = self.get_boot_image()
                if confirm == new_boot_image_path:
                    self.log.info("Success! New boot image set to {}.".format(confirm))
        else:
            self.log.info("Boot image already set to {}.".format(new_boot_image_path))


    def check_scp(self):
        """ Checks if SCP is enabled """
        # I could find no more "correct" way of verifying SCP is running
        cmd = "show run | include scp"
        output = self.napalm.device.send_command_expect(cmd)
        if 'ip scp server enable' in output:
            return True
        else:
            return False


    def fix_scp(self):
        """ Attempts to enable/fix SCP """
        config_set = self.config['fix_scp']
        if config_set:
            output = self.device.send_config_set(config_set)
            if 'Invalid input' not in output:
                output += self.device.send_command_expect('write memory')
                return True
            else:
                raise ValueError("Problem fixing SCP config. Last output: " \
                                 "\n{}".format(output))
        else:
            msg = "No 'fix_scp' values found in {}. Cannot proceed.".format( \
                   self.config_file)
            raise ValueError(msg)


    def ensure_scp(self):
        """ Enables SCP if it is not already running properly. """
        self.log.info("Checking SCP...")
        check = self.check_scp()
        if check:
            self.log.info("SCP already enabled and running.")
        else:
            self.log.info("SCP not running. Enabling now...")
            fixed = self.fix_scp()
            if fixed:
                self.log.info("SCP enabled successfully!")


    def check_upgrade_image_running(self):
        """ Check if running image is the current version """
        if self.upgrade_version in self.os_version:
            return True
        else:
            return False


    def check_needs_upgrade(self):
        """ Inverse of check_upgrade_image_running() """
        if self.check_upgrade_image_running():
            return False
        else:
            return True


    def check_upgrade_installed(self):
        """ Checks if upgrade package is already installed """
        version = self.get_upgrade_version(raw=True)
        if 'packages.conf' in self.boot_image_path:
            conf = self.device.send_command('more flash:packages.conf')
            if version in conf:
                return True
            else:
                return False
        elif version in self.boot_image_path:
            return True
        else:
            return False


    def check_needs_reload(self):
        """ Check if running image does not equal boot image """
        if self.upgrade_method == 'auto':
            if self.check_needs_upgrade() and self.check_upgrade_installed():
                return True
            else:
                return False
        else:
            if self.running_image_path != self.boot_image_path:
                return True
            else:
                return False


    def check_reload_scheduled(self):
        """ Check if a reload is scheduled """
        self._ensure_enable_not_config()
        output = self.device.send_command('show reload')
        pattern = r'^Reload scheduled for (.+?) \(in (.+?)\).*$'
        match = re.match(pattern, output)
        if match:
            return {'absolute_time': match.group(1), \
                    'relative_time': match.group(2)}
        else:
            return False


    def cancel_reload(self):
        """ Cancels pending reload, if any """
        cmd = 'reload cancel'
        output = self.device.send_command_timing(cmd)
        if 'ABORTED' in output:
            # strange, we need an [enter] to get our prompt back
            # after `reload cancel`
            output += self.device.send_command_timing("\n")
            return True
        elif 'No reload is scheduled' in output:
            return True
        else:
            raise ValueError("Unexpected output from `%s`:\n%s" \
                             % (cmd, output))


    def schedule_reload(self, reload_at=None, reload_in=None,
        save_modified_config=True):
        """ Schedules reload
            Overwrites pending reload, if already scheduled
            Defaults to midnight tonight (technically, 00:00 tomorrow)
        
            reload_at (str)
                Absolute time to reload device at in 'hh:mm' format
            reload_in (str)
                Relative time (delay from now) before reloading
                device in 'mmm' or 'hhh:mm' format
            save_modified_config (bool)
                Whether or not to save outstanding config changes,
                if any
        """
        # Should be hh:mm, but h:mm is valid; IOS prepends 0
        # e.g.: `reload at 7:35` schedules reload at 07:35 (7:35am)
        reload_at_pattern = r'^\d{1,2}:\d{2}$'
        reload_in_pattern = r'^\d{1,3}$|^\d{1,3}:\d{2}$'
        
        if reload_at is None:
            reload_at = self.config['reload_at']
        if reload_in is None:
            reload_in = self.config['reload_in']

        # Validate inputs
        if reload_at is str and reload_in is str:
            raise ValueError("Use either reload_in or reload_at, not both")
        if reload_at is not str and reload_in is not str:
            reload_at = '00:00'
        if reload_at:
            reload_at = str(reload_at).strip()
            if re.match(reload_at_pattern, reload_at):
                cmd = 'reload at %s' % reload_at
            else:
                raise ValueError("reload_at must be 'hh:mm' or 'h:mm' " \
                                 "('%s' given)" % reload_at)
        if reload_in:
            reload_in = str(reload_in).strip()
            if re.match(reload_in_pattern, reload_in):
                cmd = 'reload in %s' % reload_in
            else:
               raise ValueError("reload_in must be 'mmm' or 'hhh:mm' " \
                                "('%s' given)" % reload_in)

        # Schedule the reload
        self._ensure_enable_not_config()
        output = self.device.send_command_timing(cmd)
        if 'Save?' in output:
            if save_modified_config:
                response = 'yes'
            else:
                response = 'no'
            output += self.device.send_command(response,
                                               expect_string=r'Proceed',
                                               delay_factor=2)
        if 'Proceed' in output:
            output += self.device.send_command_timing("\n")
        else:
            raise ValueError("Unexpected output from `%s`:\n%s" \
                            % (cmd, output))
        check_reload_scheduled = self.check_reload_scheduled()
        if check_reload_scheduled:
            return check_reload_scheduled
        else:
            raise ValueError("Tried to schedule reload with `%s`, " \
                             "but check_reload_scheduled() failed. Output:\n%s" \
                             % (cmd, output))


    def ensure_reload(self):
        """ Schedules a reload, if not already scheduled. """
        scheduled = self.check_reload_scheduled()
        if not scheduled:
            self.log.info("Scheduling reload...")
            scheduled = self.schedule_reload()
        self.log.info("Reload scheduled for {} ({} away)".format(\
                      scheduled['absolute_time'],
                      scheduled['relative_time']))
 
 
    def ensure_reload_if_needed(self):
        """ Schedules reload if needed """
        if self.needs_reload:
            self.ensure_reload()
        else:
            self.log.info('No reload needed.')
 
 
    def _delete_file(self, file_name):
        """ Deletes a remote file from device """
        cmd = 'del /recursive /force {}'.format(file_name)
        self.device.send_command_timing(cmd)


    def ensure_file_deleted(self, file_name):
        """ Deletes a remote file from device only if it exists
        
        Returns (bool):
            - True: changes made
            - False: no changes made

        """
        if self.ft.check_file_exists():
            self._delete_file(file_name)
            if self.ft.check_file_exists():
                msg = "Attempted file deletion, but file still exists."
                raise ValueError(msg)
            else:
                return True
        else:
            return False


    def _init_transfer(self, src_file=None):
        """ Sets up file transfer session.
            
            Even if we don't use scp to copy
            the image, the class is still useful for checking image
            existence, free space, etc.
        
        """
        if src_file is None:
            src_file = self.upgrade_image_src_path
        if self.transport == 'ssh':
            dest_file = self._get_dest_path(absolute=False)
            ft_args = {
                'ssh_conn': self.device,
                'source_file': src_file,
                'dest_file': dest_file,
                'file_system': self.config['dest_filesystem'],
            }
            self.ft = FileTransfer(**ft_args)
        elif self.transport == 'telnet':
            self.ft = None
            raise NotImplemented
        else:
            raise ValueError("Transport must be ssh or telnet.")


    def request_scp_transfer(self):
        """ Begins SCP file transfer with progress """
        import scp
        self.ensure_scp()
        ssh_connect_params = self.ft.ssh_ctl_chan._connect_params_dict()
        self.ft.scp_conn = self.ft.ssh_ctl_chan._build_ssh_client()
        self.ft.scp_conn.connect(**ssh_connect_params)
        if not self.ft:
            self._init_transfer()
        source = self.upgrade_image_src_path
        dest = self.upgrade_image_dest_path
        with tqdm(unit='b', unit_scale=True, ascii=True) as t:
            self.progress = self._scp_tqdm(t)
            self.ft.scp_client = scp.SCPClient(\
                self.ft.scp_conn.get_transport(), \
                progress=self.progress)
            self.ft.scp_client.put(source, dest)


    def request_transfer(self):
        """ Starts file transfer and upgrade process """
        if self.transfer_proto == 'scp':
            self.request_scp_transfer()
        else:
            cmd = self.upgrade_cmd
            self.log.info('Transferring image with: {}'.format(cmd))
            self.log.info(self.device.send_command(cmd, delay_factor=100))


    def request_install(self):
        """ Requests automated upgrade """
        cmd = self.upgrade_cmd
        self.log.info('Installing new firmware...')
        self.log.debug(cmd)
        msg = 'NOTE: No status updates possible during install, ' \
              'which may take 10 minutes or longer.'
        self.log.info(msg)
        # TODO: Log timestamps
        output = self.device.send_command(cmd, delay_factor=100)
        self.log.debug(output)
        if 'Error' in output:
            self.log.info('Install failed. See debug log for details.')
        else:
            self.log.info('Install complete!')


    def ensure_install(self):
        """ Checks if upgrade is necessary, requesting if so """
        src_file = self._get_src_path(local=True)
        self._init_transfer(src_file)
        if not self.upgrade_installed:
            self.log.info('Upgrade package not installed.')
            self.ensure_free_space()
            self.request_install()
        else:
            self.log.info('Upgrade package installed!')


    def ensure_free_space(self):
        """ Checks for available free space, clearing if possible """
        self.log.info("Checking free space...")
        self.upgrade_space_available = self.ft.verify_space_available()
        if self.upgrade_space_available:
            self.log.info("Found enough free space!")
        else:
            self.log.info("Not enough space.")
            if self.can_delete_old_image:
                self.log.info("Removing old image...")
                self._delete_file(self.running_image_path)
                self.log.info("Old image deleted.")
            else:
                msg = "Not enough space, and can't delete old image."
                raise ValueError(msg)


    def copy_validate_image(self):
        """ Copies and validates image file """
        if self.ft.verify_space_available():
            self.log.info("Starting transfer. Expect this to take several minutes...")
            self.request_transfer()
            self.log.info("Transfer complete! Verifying hash...")
            if self.ft.verify_file():
                self.log.info("Hash verified!")
            else:
                msg = "Failed hash check after transfer. Can't continue."
                raise ValueError(msg)
        else:
            msg = "Not enough space for upgrade image. Can't continue."
            raise ValueError(msg)


    def ensure_image_state(self):
        """ If possible, transfers and verifies image on device """
        self._init_transfer()
        self.log.info("Checking device for upgrade image {}...".format(\
                      self.upgrade_image_dest_path))
        self.upgrade_image_exists = self.ft.check_file_exists()
        if self.upgrade_image_exists:
            self.log.info("Found! Verifying hash...")
            self.upgrade_image_valid = self.ft.verify_file()
            if self.upgrade_image_valid:
                self.log.info("Hash verified!")
            else:
                self.log.warning("Failed hash check. Re-copying image.")
                self.copy_validate_image()
        else:
            self.log.info("Not found.")
            self.ensure_free_space()
            self.copy_validate_image()


    def upgrade(self):
        """ Performs firmware upgrade on device """
        
        self.log.info("===============================================")

        if self.needs_upgrade:
            self.log.info("Starting upgrade on {}...".format(self.hostname))
            if self.upgrade_method == 'manual':
                self.ensure_image_state()
                self.ensure_boot_image()
            else:
                self.ensure_install()
            self.refresh_upgrade_status()
            self.ensure_reload_if_needed()
            self.log.info("Upgrade on {} complete!".format(self.hostname))
        else:
            self.log.info("Already running current firmware! Nothing to do.")

        self.log.info("===============================================")


