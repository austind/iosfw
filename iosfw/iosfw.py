#!/usr/bin/env python2.7

import napalm
from netmiko import FileTransfer, SCPConn
from tqdm import tqdm
import re
import datetime
import time
import yaml
import hashlib
import getpass
import os
import logging

""" An API built upon NAPALM and Netmiko to manage Cisco IOS firmware. """

class upgrade(object):
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
            secret = getpass.getpass('Enable secret: ')
            optional_args = { 'secret': secret }

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
        self.upgrade_image_src_path = \
            self._get_src_path(self.upgrade_image_name)
        self.upgrade_image_dest_path = \
            self._get_dest_path(self.upgrade_image_name)
        self.boot_image_path = self.get_boot_image()
        self.needs_upgrade = self.check_needs_upgrade()
        self.log_upgrade_facts()
        if self.config['delete_old_image'] != 'never':
            self.can_delete_old_image = True
        else:
            self.can_delete_old_image = False

    def log_upgrade_facts(self):
        """ Logs upgrade-related facts about device """
        self.log.info("Connected to {} ({}) as {} via {}".format( \
                      self.hostname, self.model, self.device.username, \
                      self.transport))
        if self.needs_upgrade:
            self.log.info('Firmware status: NEEDS UPGRADE to {}'.format( \
                     self.upgrade_image_name))
        else:
            self.log.info('Firmware status: UP-TO-DATE')
   
    def __del__(self):
        self.napalm.__del__()

    def _get_src_path(self, file_name=None):
        """ Returns full source file path """
        if file_name is None:
            file_name = self.upgrade_image_name
        src_image_path = self.config['src_image_path']
        return "%s/%s" % (src_image_path, file_name)

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

    def close(self):
        """ Closes all connections to device and logs """
        self.napalm.close()
        handlers = self.log.handlers[:]
        for h in handlers:
            h.close()
            self.log.removeHandler(h)

    def ensure_enable_not_config(self):
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
                if os.path.exists(upgrade_image_path):
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

    def check_upgrade_image_running(self):
        """ Check if running image is the current version """
        if self.running_image_path == self.upgrade_image_dest_path:
            return True
        else:
            return False

    def check_needs_upgrade(self):
        """ Inverse of check_upgrade_image_running() """
        if self.check_upgrade_image_running():
            return False
        else:
            return True

    def check_needs_reload(self):
        """ Check if running image does not equal boot image """
        if self.running_image_path != self.boot_image_path:
            return True
        else:
            return False

    def check_reload(self):
        """ Check if a reload is scheduled """
        self.ensure_enable_not_config()
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
        self.ensure_enable_not_config()
        output = self.device.send_command_timing(cmd)
        if 'Save?' in output:
            if save_modified_config:
                response = 'yes'
            else:
                response = 'no'
            output += self.device.send_command_timing(response)
        if 'Proceed with reload?' in output:
            output += self.device.send_command_timing("\n")
        else:
            raise ValueError("Unexpected output from `%s`:\n%s" \
                            % (cmd, output))
        check_reload = self.check_reload()
        if check_reload:
            return check_reload
        else:
            raise ValueError("Tried to schedule reload with `%s`, " \
                             "but check_reload() failed. Output:\n%s" \
                             % (cmd, output))

    def ensure_reload(self):
        """ Schedules a reload, if not already scheduled. """
        self.log.info("Checking reload status ...")
        scheduled = self.check_reload()
        if not scheduled:
            self.log.info("No reload scheduled. Scheduling...")
            scheduled = self.schedule_reload()
        self.log.info("Reload scheduled for {} ({} away)".format(\
                      scheduled['absolute_time'],
                      scheduled['relative_time']))
 
    def delete_file(self, file_name):
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
            self.delete_file(file_name)
            if self.ft.check_file_exists():
                msg = "Attempted file deletion, but file still exists."
                raise ValueError(msg)
            else:
                return True
        else:
            return False

    def init_file_transfer(self):
        """ Sets file transfer session """
        if self.transport == 'ssh':
            self.ensure_scp()
            dest_file = self._get_dest_path(absolute=False)
            ft_args = {
                'ssh_conn': self.device,
                'source_file': self.upgrade_image_src_path,
                'dest_file': dest_file,
                'file_system': self.config['dest_filesystem'],
            }
            self.ft = FileTransfer(**ft_args)
            # This method does not provide progress info
            #self.ft.establish_scp_conn()
        elif self.transport == 'telnet':
            self.ft = None
            raise NotImplemented
        else:
            raise ValueError("Transport must be ssh or telnet.")


    def scp_tqdm(self, t):
        """ Provides progress bar """
        # https://github.com/tqdm/tqdm/blob/master/examples/tqdm_wget.py
        last_b = [0]
        def update_to(filename, size, sent):
            t.total = size
            t.desc = filename
            t.update(sent - last_b[0])
            last_b[0] = sent
        return update_to


    def copy_with_progress(self):
        """ Starts SCP copy using tqdm progress bar """
        # SCP on 3560-X takes ~7min for 20.3MB (avg. 47.7Kbps)
        # Doing `sh proc cpu hist` suggests CPU is bottlenecking
        # Likely faster with http or tftp
        import scp
        ssh_connect_params = self.ft.ssh_ctl_chan._connect_params_dict()
        self.ft.scp_conn = self.ft.ssh_ctl_chan._build_ssh_client()
        self.ft.scp_conn.connect(**ssh_connect_params)
        if not self.ft:
            self.init_file_transfer()
        source = self.upgrade_image_src_path
        dest = self.upgrade_image_dest_path
        with tqdm(unit='b', unit_scale=True, ascii=True) as t:
            self.progress = self.scp_tqdm(t)
            self.ft.scp_client = scp.SCPClient(\
                self.ft.scp_conn.get_transport(), \
                progress=self.progress)
            self.ft.scp_client.put(source, dest)

    def copy_validate_image(self):
        """ Copies and validates image file """
        if self.ft.verify_space_available():
            self.log.info("Starting transfer. Expect this to take several minutes...")
            #self.ft.transfer_file()
            self.copy_with_progress()
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
            self.log.info("Not found. Checking free space...")
            self.upgrade_space_available = self.ft.verify_space_available()
            if self.upgrade_space_available:
                self.log.info("Found enough free space!")
                self.copy_validate_image()
            else:
                self.log.info("Not enough space.")
                if self.can_delete_old_image:
                    self.log.info("Removing old image...")
                    self.delete_file(self.running_image_path)
                    self.log.info("Old image deleted.")
                    self.copy_validate_image()
                else:
                    msg = "Not enough space, and can't delete old image."
                    raise ValueError(msg)

    def upgrade(self):
        """ Performs firmware upgrade on device """
        
        self.log.info("===============================================")

        if self.needs_upgrade:
            self.log.info("Starting upgrade on {}...".format(self.hostname))
            self.init_file_transfer()
            self.ensure_image_state()
            self.ensure_boot_image()
            self.ensure_reload()
            self.log.info("Upgrade on {} complete!".format(self.hostname))
        else:
            self.log.info("Already running current firmware! Nothing to do.")

        self.log.info("===============================================")

