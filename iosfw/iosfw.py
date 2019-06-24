# -*- coding: utf-8 -*-

from datetime import datetime
import getpass
import hashlib
import logging
import napalm
from netmiko import FileTransfer
import os
import re
import scp
from time import sleep
from tqdm import tqdm
import yaml

""" An API built upon NAPALM and Netmiko to manage Cisco IOS firmware. """

# TODO: Fix SCP from iosfw
# TODO: Fix clock/NTP as needed
# TODO: Handle exceptions in connection open/close
# TODO: Refactor __init__() into methods
# TODO: Ensure reachability to transfer_source


class iosfw(object):
    def __init__(
        self,
        hostname=None,
        username=None,
        password=None,
        timeout=60,
        driver="ios",
        optional_args=None,
        config_file="./config/config.yaml",
        image_file="./config/images.yaml",
    ):
        """ Initializes connection and file transfer """

        # Config
        self.config_file = config_file
        self.config = self._read_yaml_file(config_file)
        self.image_file = image_file
        self.image_info = self._read_yaml_file(image_file)

        # Logging
        self.log_method = self.config["log_method"]
        self.log_file = self.config["log_file"]
        self.file_log_level = self.config["file_log_level"]
        self.console_log_level = self.config["console_log_level"]
        file_level = getattr(logging, self.file_log_level.upper(), None)
        console_level = getattr(logging, self.console_log_level.upper(), None)
        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.DEBUG)
        if self.log_method == "tee" or self.log_method == "file":
            fmt_str = "%(asctime)s [%(levelname)s] %(message)s"
            formatter = logging.Formatter(fmt_str)
            fh = logging.FileHandler(self.log_file)
            fh.setLevel(file_level)
            fh.setFormatter(formatter)
            self.log.addHandler(fh)
        if self.log_method == "tee" or self.log_method == "console":
            formatter = logging.Formatter("%(message)s")
            ch = logging.StreamHandler()
            ch.setLevel(console_level)
            ch.setFormatter(formatter)
            self.log.addHandler(ch)
        self.log.debug("Config file: {}".format(self.config_file))
        self.log.debug("Config parameters: {}".format(self.config))
        self.log.debug("Image file: {}".format(self.image_file))
        self.log.debug("Image info: {}".format(self.image_info))

        # Set up connection
        if hostname is None:
            hostname = str(input("Hostname or IP: "))
        if username is None:
            whoami = getpass.getuser()
            username = str(input("Username [{}]: ".format(whoami))) or whoami
        if password is None:
            password = getpass.getpass()
        if optional_args is None:
            optional_args = {}
            secret = getpass.getpass("Enable secret: ")
            optional_args.update({"secret": secret})
            if self.config["ssh_config_file"]:
                optional_args.update(
                    {"ssh_config_file": self.config["ssh_config_file"]}
                )
        napalm_driver = napalm.get_network_driver(driver)
        self.napalm = napalm_driver(
            hostname=hostname,
            username=username,
            password=password,
            timeout=timeout,
            optional_args=optional_args,
        )
        self.log.info("===============================================")
        self.log.info("Opening connection to {}...".format(hostname))
        self.napalm.open()

        # Aliases and info
        self.device = self.napalm.device  # Netmiko session
        self.facts = self.napalm.get_facts()  # NAPALM facts
        self.os_version = self.facts["os_version"]
        self.model = self.facts["model"]
        self.hostname = self.facts["hostname"]
        self.fqdn = self.facts["fqdn"]
        self.transport = self.napalm.transport  # ssh or telnet
        self.upgrade_image_exists = False
        self.upgrade_image_valid = False
        self.upgrade_space_available = False
        self.transfer_proto = self.config["transfer_proto"]
        self.transfer_source = self.config["transfer_source"]
        self.exec_timeout = self.get_exec_timeout()
        self.running_image_path = self.get_running_image()
        self.running_image_name = self._get_basename(self.running_image_path)
        self.running_image_feature_set = self._get_image_feature_set(
            self.running_image_name
        )
        self.upgrade_image_name = self.get_upgrade_image_name()
        self.upgrade_version = self.get_upgrade_version()
        self.running_version = self.get_running_version()
        self.upgrade_image_src_path = self._get_src_path(
            self.upgrade_image_name, local=True
        )
        self.upgrade_image_dest_path = self._get_dest_path(self.upgrade_image_name)
        self.boot_image_path = self.get_boot_image()
        self.firmware_installed = self.check_firmware_installed()
        self.needs_upgrade = self.check_needs_upgrade()
        self.upgrade_cmd = self._get_upgrade_cmd()
        self.upgrade_method = self._get_upgrade_method()
        self.transfer_proto = self.config["transfer_proto"]
        self.needs_reload = self.check_needs_reload()
        self.reload_scheduled = self.check_reload_scheduled()
        self.old_images = self.get_old_images()
        if self.config["delete_running_image"] != "never":
            self.can_delete_running_image = True
        else:
            self.can_delete_running_image = False
        if self.config["delete_old_images"] != "never":
            self.can_delete_old_images = True
        else:
            self.can_delete_old_images = False
        self.log.info(
            "Connected to {} ({}) as {} via {}".format(
                self.hostname, self.model, self.device.username, self.transport
            )
        )
        self.log_upgrade_state()

    def log_upgrade_state(self, refresh=False):
        """ Logs upgrade-related facts about device """
        if refresh:
            self.refresh_upgrade_state()
        self.log.info("Running version: {}".format(self.running_version))
        self.log.info("Upgrade version: {}".format(self.upgrade_version))
        if self.firmware_installed:
            if self.needs_reload:
                self.log.info("Upgrade status: FIRMWARE INSTALLED")
                if self.reload_scheduled:
                    t = self.reload_scheduled["absolute_time"]
                    msg = "Reload status: RELOAD SCHEDULED for {}".format(t)
                    self.log.info(msg)
                else:
                    self.log.info("Reload status: NEEDS RELOAD")
            else:
                self.log.info("Upgrade status: COMPLETE")
        else:
            self.log.info("Upgrade status: NEEDS UPGRADE")

    def refresh_upgrade_state(self, log=False):
        """ Updates device status """
        self.running_image_path = self.get_running_image()
        self.boot_image_path = self.get_boot_image()
        self.firmware_installed = self.check_firmware_installed()
        self.needs_reload = self.check_needs_reload()
        self.reload_scheduled = self.check_reload_scheduled()
        self.old_images = self.get_old_images()
        if log:
            self.log_upgrade_state()

    def __del__(self):
        # Proxied SSH connections generate a harmless ProcessLookupError
        # on exit
        try:
            self.napalm.__del__()
        except OSError.ProcessLookupError:
            pass

    def _get_upgrade_cmd(self):
        """ Returns a command string for auto-upgrade, if supported """
        flags = " "
        image_src = self._get_src_path()
        image_dest = self._get_dest_path()
        if self.transfer_source == "localhost":
            img = image_dest
        else:
            img = image_src
        cmds = ["request", "software install", "archive download-sw", "copy"]
        for cmd in cmds:
            output = self.device.send_command(cmd + " ?")
            if "Incomplete command" in output:
                method = cmd
                if (
                    "allow-feature-upgrade" in output
                    and not self.config["match_feature_set"]
                ):
                    flags += "/allow-feature-upgrade "
                break
        if method == "request":
            if "ISR" in self.model:
                target = "node"
            else:
                target = "switch all"
            return (
                "request platform software package install {} "
                "file {} new auto-copy".format(target, img)
            )
        if method == "software install":
            return "software install file {} new on-reboot".format(img)
        if method == "archive download-sw":
            if self.config["delete_running_image"] == "never":
                flags += "/safe /leave-old-sw "
            else:
                flags += "/overwrite "
            return "archive download-sw{}{}".format(flags, img)
        if method == "copy":
            return "copy {} {}".format(image_src, image_dest)

    def _get_upgrade_method(self):
        """ Checks whether IOS supports automatic or manual upgrade """
        if re.search(r"^copy", self.upgrade_cmd):
            return "manual"
        else:
            return "auto"

    def _strip_extension(self, file_name=None):
        """ Returns a file name without the extension """
        if file_name is None:
            file_name = self.upgrade_image_name
        split = self.upgrade_image_name.split(".")
        del split[-1]
        return ".".join(split)

    def _get_src_path(self, file_name=None, local=False):
        """ Returns full source file path """
        proto = self.config["transfer_proto"]
        un = self.config["transfer_username"] or ""
        pw = self.config["transfer_password"] or ""
        path = self.config["transfer_path"]
        src = self.config["transfer_source"]
        if file_name is None:
            file_name = self.upgrade_image_name
        if proto == "scp" or local:
            path = self.config["src_image_path"]
            return "{}/{}".format(path, file_name)
        elif proto == "ftp":
            return "{}://{}:{}@{}{}{}".format(proto, un, pw, src, path, file_name)
        else:
            return "{}://{}{}{}".format(proto, src, path, file_name)

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
            full_path += self.config["dest_filesystem"]
        full_path += "{}{}".format(self.config["dest_image_path"], file_name)
        return full_path

    def _read_yaml_file(self, file_name):
        """ Reads and parses YAML file """
        with open(file_name, "r") as f:
            file_contents = f.read()
            parsed_yaml = yaml.load(file_contents, Loader=yaml.FullLoader)
        return parsed_yaml

    def _file_md5(self, file_name):
        """ Compute MD5 hash of local file_name """
        with open(file_name, "rb") as f:
            file_contents = f.read()
            file_hash = hashlib.md5(file_contents).hexdigest()
        return file_hash

    def _check_remote_file_exists(self, file_path):
        """ Checks if a file exists on the remote filesystem """
        cmd = "dir {}".format(file_path)
        output = self.device.send_command(cmd)
        if "No such file" in output:
            return False
        elif "Directory of" in output:
            return True
        else:
            self.log.critical(
                "Unexpected output from "
                "_check_remote_file_exists(): \n"
                "{}".format(output)
            )
            return False

    def _get_image_feature_set(self, file_name):
        """ Parses the feature set string from an IOS file name

            e.g.: ipbasek9, universalk9, ipservicesk9
        """
        split = re.split(r"[-\.]", file_name)
        if split:
            if len(split) > 1:
                return split[1]
            else:
                return False
        else:
            return False

    def _check_image_feature_set(self, file_name):
        """ Checks if a given image's feature set matches the running
            image's feature set.

            Ignores K9 in the feature set string, so 'ipbasek9'
            matches 'ipbase'

        """
        regex = r"[Kk]9"
        set1 = re.sub(regex, "", self.running_image_feature_set)
        set2 = re.sub(regex, "", self._get_image_feature_set(file_name))
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
        cmd = "write memory"
        output = self.device.send_command_expect(cmd)
        if "OK" in output:
            return True
        else:
            self.log.warning(
                "Unexpected output from `write memory`: \n" "{}".format(output)
            )
            return False

    def _send_write_config_set(self, config_set):
        """ Sends configuration set to device and writes to NVRAM """
        output = self.device.send_config_set(config_set)
        if "Invalid input" not in output:
            self._write_config()
            return True
        else:
            self.log.critical(
                "Device reports invalid configuration "
                "commands.\nCommands: {}\nOutput: "
                "{}\n".format(config_set, output)
            )
            return False

    def close(self):
        """ Closes all connections to device and logs """
        # Proxied SSH connections generate a harmless ProcessLookupError
        # on exit
        try:
            self.napalm.close()
        except OSError.ProcessLookupError:
            pass
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
        for file_name, attrs in self.image_info.items():
            if self.model in attrs["models"]:
                if self.config["match_feature_set"]:
                    if not self._check_image_feature_set(file_name):
                        continue
                upgrade_image_path = self._get_src_path(file_name)
                if self.config["transfer_source"] != "localhost":
                    return file_name
                elif os.path.exists(upgrade_image_path):
                    upgrade_image_md5 = self._file_md5(upgrade_image_path)
                    if upgrade_image_md5.lower() == attrs["md5"].lower():
                        return file_name
                    else:
                        msg = (
                            "MD5 for image {} "
                            "does not match MD5 in "
                            "config.\nImage MD5: {} "
                            "\nConfig MD5: {}\n".format(
                                file_name, attrs["md5"], upgrade_image_md5
                            )
                        )
                        self.log.critical(msg)
                        return False
                else:
                    self.log.critical(
                        "Image file does not exist: " "{}".format(upgrade_image_path)
                    )
                    return False
        self.log.critical(
            "Could not find upgrade image for model "
            "{} in image file "
            "{}.".format(self.model, self.image_file)
        )
        return False

    def _get_basename(self, file_path):
        """ Returns a file name from a file path

            Example input: 'flash:/c3750-ipbase-mz.122-25.SEE1.bin'
            Example output: 'c3750-ipbase-mz.122-25.SEE1.bin'

        """
        return re.split(r"[:/]", file_path)[-1]

    def _get_path(self, file_path, include_trailing_slash=False):
        """ Returns a file's path, not including the file itself """
        basename = self._get_basename(file_path)
        if not include_trailing_slash:
            basename = "/{}".format(basename)
        return file_path.replace(basename, "")

    def _get_version_from_file(self, file_name, raw=False):
        """ Returns a version string from a file name """
        # c2900-universalk9-mz.SPA.157-3.M4b.bin
        # c2960s-universalk9-tar.152-2.E9.tar
        # c2960x-universalk9-tar.152-4.E8.tar
        # c3550-ipbase-tar.122-44.SE6.tar
        # c3550-ipbasek9-mz.122-44.SE6.bin
        # c3560-ipbasek9-mz.122-55.SE12.bin
        # c3560-ipbasek9-tar.122-55.SE12.tar
        # c3560e-ipbasek9-mz.150-2.SE11.bin
        # c3560e-ipbasek9-tar.150-2.SE11.tar
        # c3560e-universalk9-mz.152-4.E8.bin
        # c3560e-universalk9-tar.152-4.E8.tar
        # c3750-ipbaselmk9-tar.122-55.SE12.tar
        # c3750e-ipbasek9-mz.150-2.SE11.bin
        # c3750e-universalk9-tar.152-4.E8.tar
        # cat3k_caa-universalk9.16.03.08.SPA.bin
        # cat9k_iosxe.16.11.01.SPA.bin
        pattern = r"(\d+\.\d+\.\d+)\.SPA"
        match = re.search(pattern, file_name)
        if match:
            if raw:
                return match.group(1)
            else:
                return re.sub(r"\.0", ".", match.group(1))

        pattern = r"(\d{3})-(\d+)\.(\w+)"
        match = re.search(pattern, file_name)
        if match:
            if raw:
                return match.group(0)
            else:
                train = "{}.{}".format(match.group(1)[:2], match.group(1)[2:])
                throttle = match.group(2)
                rebuild = match.group(3)
                return "{}({}){}".format(train, throttle, rebuild)

    def get_upgrade_version(self, raw=False):
        """ Parses image name to return IOS version string """
        return self._get_version_from_file(self.upgrade_image_name, raw)

    def get_running_version(self):
        """ Parses self.os_version for IOS version string """
        pattern = r"ersion ([^,]+),"
        match = re.search(pattern, self.os_version)
        if match:
            return match.group(1)
        else:
            return False

    def get_running_image(self):
        """ Returns the remote path of the image running in memory """
        search_string = "System image file is "
        cmd = "show ver | i {}".format(search_string)
        output = self.device.send_command(cmd)
        if search_string in output:
            return output.replace(search_string, "").replace('"', "")
        else:
            self.log.critical(
                "Could not find running image. " "Last output:\n{}".format(output)
            )
            return False

    def get_boot_image(self):
        """ Returns the remote path of the image used on next reload """
        cmd = "show boot | include BOOT"
        output = self.device.send_command(cmd)
        if "Invalid input" in output:
            self.log.debug(
                "Device does not support `show boot`. " "Checking running config..."
            )
            cmd = "show run | i boot"
            output = self.device.send_command(cmd)
            self.log.debug("Output from `{}`: \n{}".format(cmd, output))
            if "boot system" in output:
                match = re.search(r"boot system ([^\n]+)\n", output)
                self.log.debug("Found boot image {}".format(match.group(1)))
                return match.group(1)
            else:
                self.log.debug(
                    "No `boot system` directives found in config. "
                    "Inferring first image in dest_fs."
                )
                return self.get_installed_images()[0]
        else:
            return output.split(": ")[-1].strip()

    def get_installed_images(self):
        """ Returns list of images installed on dest_fs """
        results = []
        dest_fs = self.config["dest_filesystem"]
        cmd = "dir {}".format(dest_fs)
        output = self.device.send_command_timing(cmd)
        for line in output.split("\n"):
            file_name = re.split(r"\s+", line)[-1]
            # c3560e-universalk9-mz.152-4.E8
            # c3560-ipbasek9-mz.122-55.SE12
            # c2900-universalk9-mz.SPA.152-4.M4.bin
            # pattern = r'\w+-\w+-\w+.\d+-\w+\.\w+'
            pattern = r"\d+-\w+\.\w+"
            match = re.search(pattern, file_name)
            if match:
                results.append("{}/{}".format(dest_fs, file_name))
        return results

    def get_old_images(self):
        """ Checks dest_filesystem for old image files """
        results = []
        installed_images = self.get_installed_images()
        for image in installed_images:
            img_version = self._get_version_from_file(image)
            if (
                img_version != self.running_version
                and img_version != self.upgrade_version
            ):
                results.append(image)
        return results

    def get_exec_timeout(self):
        """ Returns config line for line vty exec-timeout, if exists """
        cmd = "sh run | i exec-timeout"
        self.log.debug("Executing command `{}`...".format(cmd))
        output = self.device.send_command(cmd)
        self.log.debug("Command output:\n{}".format(output))
        if output:
            output = output.split("\n")
            return output[-1]

    def disable_exec_timeout(self):
        """ Disables line vty exec-timeout """
        config_set = ["line vty 0 15", "no exec-timeout"]
        self.log.info("Disabling line vty exec-timeout...")
        return self._send_write_config_set(config_set)

    def ensure_exec_timeout_disabled(self):
        """ Disables line vty exec timeout, if not already disabled """
        if self.exec_timeout:
            return self.disable_exec_timeout()
        else:
            return True

    def restore_exec_timeout(self):
        """ Restores line vty exec-timeout """
        if self.exec_timeout != " exec-timeout 0 0":
            config_set = ["line vty 0 15", self.exec_timeout]
            self.log.info("Restoring line vty exec-timeout...")
            return self._send_write_config_set(config_set)
        else:
            return True

    def ensure_exec_timeout_restored(self):
        """ Restores line vty exec-timeout, if needed """
        if self.exec_timeout != " exec-timeout 0 0":
            return self.restore_exec_timeout()
        else:
            return True

    def set_boot_image(self, new_boot_image_path=None):
        """ Configures device to boot given image on next reload """
        if new_boot_image_path is None:
            new_boot_image_path = self.upgrade_image_dest_path
        config_set = ["no boot system", "boot system {}".format(new_boot_image_path)]
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
                    return True
        else:
            self.log.info("Boot image already set to {}.".format(new_boot_image_path))
            return True

    def check_scp(self):
        """ Checks if SCP is enabled """
        # I could find no more "correct" way of verifying SCP is running
        cmd = "show run | include scp"
        output = self.napalm.device.send_command_expect(cmd)
        if "ip scp server enable" in output:
            return True
        else:
            return False

    def fix_scp(self):
        """ Attempts to enable/fix SCP """
        config_set = self.config["fix_scp"]
        if config_set:
            output = self.device.send_config_set(config_set)
            if "Invalid input" not in output:
                output += self.device.send_command_expect("write memory")
                return True
            else:
                self.log.critical(
                    "Problem fixing SCP config. Last output: " "\n{}".format(output)
                )
                return False
        else:
            self.log.critical(
                "No 'fix_scp' values found in {}. Cannot proceed.".format(
                    self.config_file
                )
            )
            return False

    def fix_ntp(self):
        """ Fixes NTP if possible """
        fix_ntp_cmds = self.config["fix_ntp"]
        cmd = "show run | i ntp"
        ntp_config = self.device.send_command(cmd).split("\n")
        null_ntp_cmds = []
        for line in ntp_config:
            null_ntp_cmds.append("no {}".format(line))
        self.log.debug("Removing existing NTP config: \n{}".format(null_ntp_cmds))
        output = self.device.send_config_set(null_ntp_cmds)
        self.log.debug("Output: \n{}".format(output))
        self.log.debug("Sending new NTP config: \n{}".format(fix_ntp_cmds))
        output += self.device.send_config_set(fix_ntp_cmds)
        self.log.debug("Output: \n{}".format(output))

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
        if self.upgrade_version == self.running_version:
            return True
        else:
            return False

    def check_needs_upgrade(self):
        """ Inverse of check_upgrade_image_running() """
        if self.check_upgrade_image_running():
            return False
        else:
            return True

    def check_firmware_installed(self):
        """ Checks if upgrade package is already installed """
        version = self.get_upgrade_version(raw=True)
        dest_fs = self.config["dest_filesystem"]
        files = self.device.send_command("dir {}".format(dest_fs))
        if "packages.conf" in self.boot_image_path:
            conf = self.device.send_command("more flash:packages.conf")
            if version in conf:
                return True
            else:
                return False
        if version in files:
            return True
        else:
            return False

    def check_needs_reload(self):
        """ Check if running image does not equal boot image """
        if self.upgrade_method == "auto":
            if self.check_needs_upgrade() and self.check_firmware_installed():
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
        output = self.device.send_command("show reload")
        pattern = r"Reload scheduled for (.+?) \(in (.+?)\)"
        match = re.search(pattern, output)
        if match:
            return {"absolute_time": match.group(1), "relative_time": match.group(2)}
        else:
            return False

    def cancel_reload(self):
        """ Cancels pending reload, if any """
        cmd = "reload cancel"
        output = self.device.send_command_timing(cmd)
        if "ABORTED" in output:
            # strange, we need an [enter] to get our prompt back
            # after `reload cancel`
            output += self.device.send_command_timing("\n")
            return True
        elif "No reload is scheduled" in output:
            return True
        else:
            self.log.critical("Unexpected output from `{}`:" "\n{}".format(cmd, output))
            return False

    def schedule_reload(
        self, reload_at=None, reload_in=None, save_modified_config=True
    ):
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
        reload_at_pattern = r"^\d{1,2}:\d{2}$"
        reload_in_pattern = r"^\d{1,3}$|^\d{1,3}:\d{2}$"

        if reload_at is None:
            reload_at = self.config["reload_at"]
        if reload_in is None:
            reload_in = self.config["reload_in"]

        # Validate inputs
        if reload_at is str and reload_in is str:
            raise ValueError("Use either reload_in or reload_at, not both")
        if reload_at is not str and reload_in is not str:
            reload_at = "00:00"
        if reload_at:
            reload_at = str(reload_at).strip()
            if re.match(reload_at_pattern, reload_at):
                cmd = "reload at {}".format(reload_at)
            else:
                self.log.critical(
                    "reload_at must be 'hh:mm' or "
                    "'h:mm' ('{}' given)".format(reload_at)
                )
                return False
        if reload_in:
            reload_in = str(reload_in).strip()
            if re.match(reload_in_pattern, reload_in):
                cmd = "reload in {}".format(reload_in)
            else:
                self.log.critical(
                    "reload_in must be 'mmm' or 'hhh:mm' "
                    "('{}' given)".format(reload_in)
                )
                return False

        # Schedule the reload
        self._ensure_enable_not_config()
        e = r"(Save|Proceed|\#)"
        output = self.device.send_command(cmd, expect_string=e)
        if "The date and time must be set first" in output:
            self.log.debug("Clock not set.")
            if self.config["fix_ntp"]:
                self.log.debug("Attempting NTP fix...")
                self.fix_ntp()
                self.log.debug("Waiting 30 seconds for NTP to sync...")
                sleep(30)
                return self.schedule_reload()
            else:
                self.log.critical(
                    "No fix_ntp parameters given. " "Cannot continue with reload."
                )
                return False

        if "Save?" in output:
            if save_modified_config:
                response = "yes"
            else:
                response = "no"
            output += self.device.send_command(
                response, expect_string=r"Proceed", delay_factor=2
            )
        if "Proceed" in output:
            output += self.device.send_command_timing("\n")
        else:
            self.log.critical("Unexpected output from `{}`:" "\n{}".format(cmd, output))
            return False
        check_reload_scheduled = self.check_reload_scheduled()
        if check_reload_scheduled:
            return check_reload_scheduled
        else:
            msg = (
                "Tried to schedule reload with `{}`, "
                "but check_reload_scheduled() failed. "
                "Output:\n{}".format(cmd, output)
            )
            self.log.critical(msg)
            return False

    def ensure_reload_scheduled(self):
        """ Schedules a reload, if not already scheduled. """
        scheduled = self.check_reload_scheduled()
        if not scheduled:
            self.log.info("Scheduling reload...")
            return self.schedule_reload()
        else:
            return scheduled
        self.log.info(
            "Reload scheduled for {} ({} away)".format(
                scheduled["absolute_time"], scheduled["relative_time"]
            )
        )

    def _delete_file(self, file_name):
        """ Deletes a remote file from device """
        cmd = "del /recursive /force {}".format(file_name)
        output = self.device.send_command_timing(cmd)
        # Successful command returns no output
        if output:
            self.log.critical("Unexpected output from `del`: \n{}".format(output))
            return False
        else:
            return True

    def ensure_file_removed(self, file_name, delete_path=True):
        """ Deletes a remote file from device only if it exists.
            Optionally deletes the full path (any parent folders).

        """
        if delete_path:
            path = self._get_path(file_name)
            if path != self.config["dest_filesystem"]:
                self.log.info("Removing {}...".format(path))
                return self._delete_file(path)
            else:
                self.log.info("Removing {}...".format(file_name))
                return self._delete_file(file_name)
        else:
            return self._delete_file(file_name)

    def delete_running_image(self):
        """ Deletes currently running image, including folder """
        self.ensure_file_removed(self.running_image_path)
        self.log.info("Running image deleted.")

    def remove_old_images(self):
        """ Deletes images on dest_filesystem that are not running """
        cmd = "request platform software package clean switch all"
        output = self.device.send_command(cmd, expect_string=r"(proceed|\#)")
        self.log.debug(output)
        if "Nothing to " in output:
            self.log.info("Found no old images to remove.")
            return True
        elif "proceed" in output:
            self.log.debug("Proceeding with package clean...")
            output += self.device.send_command("y", expect_string=r"\#")
            if "Files deleted" in output:
                self.log.info("Removed old images.")
                return True
            else:
                self.log.warning(
                    "Unexpected output from remove_old_images():" "\n{}".format(output)
                )
                return False
        elif "Invalid input" in output:
            if self.old_images:
                for image in self.old_images:
                    if self._check_remote_file_exists(image):
                        if self.ensure_file_removed(image):
                            self.log.info("Removed successfully.")
        else:
            self.log.critical(
                "Unexpected output from remove_old_images():\n{}".format(output)
            )
            return False

    def _init_transfer(self, src_file=None, dest_file=None):
        """ Sets up file transfer session.

            Even if we don't use scp to copy
            the image, the class is still useful for checking image
            existence, free space, etc.

        """
        if src_file is None:
            src_file = self.upgrade_image_src_path
        if dest_file is None:
            dest_file = self._get_dest_path(absolute=False)
        if self.transport == "ssh":
            ft_args = {
                "ssh_conn": self.device,
                "source_file": src_file,
                "dest_file": self._get_dest_path(dest_file, absolute=False),
                "file_system": self.config["dest_filesystem"],
            }
            self.ft = FileTransfer(**ft_args)
        elif self.transport == "telnet":
            self.ft = None
            raise NotImplementedError
        else:
            raise ValueError("Transport must be ssh or telnet.")

    def request_scp_transfer(self):
        """ Begins SCP file transfer with progress """
        self.ensure_scp()
        self._init_transfer()
        source = self.upgrade_image_src_path
        dest = self.upgrade_image_dest_path
        ssh_connect_params = self.ft.ssh_ctl_chan._connect_params_dict()
        self.ft.scp_conn = self.ft.ssh_ctl_chan._build_ssh_client()
        self.ft.scp_conn.connect(**ssh_connect_params)
        with tqdm(unit="b", unit_scale=True, ascii=True) as t:
            self.progress = self._scp_tqdm(t)
            self.ft.scp_client = scp.SCPClient(
                self.ft.scp_conn.get_transport(), progress=self.progress
            )
            self.ft.scp_client.put(source, dest)

    def request_transfer(self):
        """ Starts file transfer and upgrade process """
        if self.transfer_proto == "scp":
            self.request_scp_transfer()
        else:
            cmd = self.upgrade_cmd
            self.log.debug("Transferring image with: {}".format(cmd))
            output = self.device.send_command(cmd, expect_string=r"filename")
            output += self.device.send_command(
                "\n", delay_factor=100, expect_string=r"copied"
            )
            self.device.find_prompt()

    def request_install(self):
        """ Requests automated upgrade """
        cmd = self.upgrade_cmd
        self.log.info("Installing new firmware...")
        self.log.debug("Upgrade command: {}".format(cmd))
        if self.upgrade_method == "manual":
            if self.copy_validate_image():
                self.ensure_boot_image()
                return True
            else:
                return False
        else:
            self.log.info(
                "NOTE: No status updates possible during install. "
                "Expect this to take at least 10 minutes, and in some "
                "cases, significantly longer."
            )
            output = self.device.send_command(cmd, delay_factor=100)
            self.log.debug(output)
            if "Error" in output:
                self.log.critical("Install failed:")
                for line in output.split("\n"):
                    if "Error" in line:
                        self.log.critical(line)
                return False
            elif "All software images installed" in output or "SUCCESS" in output:
                self.log.info("Install successful!")
                return True
            else:
                self.log.critical(
                    "Unexpected output from " "request_install():\n" "{}".format(output)
                )
                return False

    def ensure_install(self):
        """ Checks if firmware install is necessary, requesting if so """
        src_file = self._get_src_path(local=True)
        self._init_transfer(src_file)
        if not self.firmware_installed:
            if self.ensure_free_space():
                if self.transfer_source == "localhost":
                    if self.request_transfer():
                        self.request_install()
                return self.request_install()
        else:
            self.log.info("New firmware already installed!")
            return True

    def ensure_free_space(self):
        """ Checks for available free space, clearing if possible """
        self.log.info("Checking free space...")
        self.upgrade_file_size = os.stat(self.upgrade_image_src_path).st_size
        # Estimate 10% decompression overhead
        comp_overhead = self.upgrade_file_size * 1.1
        if self.ft.remote_space_available() >= comp_overhead:
            self.log.info("Found enough free space!")
            return True
        else:
            self.log.info("Not enough space.")
            if self.old_images and self.can_delete_old_images:
                self.log.info("Removing old images...")
                self.remove_old_images()
                # Need to wait after deleting image before checking
                # free space, or we get an exception
                sleep(30)
                if self.ft.verify_space_available():
                    return True
            else:
                if self.can_delete_running_image:
                    self.log.info("Removing running image...")
                    self.delete_running_image()
                    sleep(30)
                    if self.ft.verify_space_available():
                        return True
                    else:
                        self.log.critical("Still not enough space." "Cannot continue.")
                        return False
                else:
                    self.log.critical("Still not enough space." "Cannot continue.")
                    return False

    def copy_validate_image(self):
        """ Copies and validates image file """
        if self.ft.verify_space_available():
            msg = "Starting transfer. Expect this to take several minutes..."
            self.log.info(msg)
            self.request_transfer()
            self.log.info("Transfer complete! Verifying hash...")
            if self.ft.verify_file():
                self.log.info("Hash verified!")
                return True
            else:
                self.log.critical("Failed hash check after transfer. Can't continue.")
                return False
        else:
            self.log.critical("Not enough space for upgrade image. Can't continue.")
            return False

    def ensure_image_state(self):
        """ If possible, transfers and verifies image on device """
        self._init_transfer()
        self.log.info(
            "Checking device for upgrade image {}...".format(
                self.upgrade_image_dest_path
            )
        )
        self.upgrade_image_exists = self.ft.check_file_exists()
        if self.upgrade_image_exists:
            self.log.info("Found! Verifying hash...")
            self.upgrade_image_valid = self.ft.verify_file()
            if self.upgrade_image_valid:
                self.log.info("Hash verified!")
                return True
            else:
                self.log.warning("Failed hash check. Re-copying image.")
                return self.copy_validate_image()
        else:
            self.log.info("Not found.")
            self.ensure_free_space()
            return self.copy_validate_image()

    def ensure_old_image_removal(self):
        """ Deletes old images if requested """
        if self.config["delete_old_images"] == "always":
            return self.remove_old_images()

    def ensure_running_image_removal(self):
        """ Removes running image if requested """
        if self.config["delete_running_image"] == "always":
            if self._check_remote_file_exists(self.running_image_path):
                self.log.info("Removing running image...")
                return self.delete_running_image()

    def upgrade(self):
        """ Performs firmware upgrade """
        start_t = datetime.now()
        start = start_t.strftime("%X %Y-%m-%d")
        if self.needs_upgrade and not self.firmware_installed:
            self.log.info(
                "Starting upgrade on {} " "at {}...".format(self.hostname, start)
            )
            if self.config["disable_exec_timeout"]:
                self.ensure_exec_timeout_disabled()
            if self.ensure_install():
                self.refresh_upgrade_state()
                self.ensure_old_image_removal()
                self.ensure_running_image_removal()
                self.ensure_reload_scheduled()
                status = "completed"
            else:
                status = "failed"
            if self.config["disable_exec_timeout"]:
                self.ensure_exec_timeout_restored()
            end_t = datetime.now()
            end = end_t.strftime("%X %Y-%m-%d")
            self.log.info("Upgrade on {} {} at {}".format(self.hostname, status, end))
        elif self.needs_reload and not self.reload_scheduled:
            self.ensure_reload_scheduled()
        else:
            self.log.info("No action needed.")
        end_t = datetime.now()
        self.log.info("Total time elapsed: {}".format(end_t - start_t))
