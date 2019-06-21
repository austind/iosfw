# iosfw

## Overview

Automates the entire IOS firmware upgrade process:
* Transfer the new image
* Verify image integrity
* Extract or install
* Set boot parameters
* Schedule reload

Supports several upgrade methods, depending on running IOS version:
* `archive download-sw`
* `software install`
* `request platform software package install`
* Or if those fail, plain `copy` 

Other features:
* YAML-based config
* Logs progress to console and/or file, with configurable verbosity
* Works with ad-hoc upgrades (interactive) or batch jobs (non-interactive)

Requires:
* Python 3.x
* netmiko
* napalm
* tqdm

Tested on:
* Catalyst 3560
* Catalyst 3560-X
* Catalyst 3750
* Catalyst 3750-X
* Catalyst 2960-S
* Catalyst 2960-X
* Catalyst 3650
* Catalyst 3850
* ISR 2921
* C892FSP

Not tested on:
* Nexus 3k/9k
* Catalyst 9k series

**NOTE: Use at your own risk.** This is beta software in active development. It works well in my environment, but serious bugs are possible. See known issues below.

## Usage

1. Review [`config/config.yaml`](https://github.com/austind/iosfw/blob/master/config/config.yaml) and [`config/images.yaml`](https://github.com/austind/iosfw/blob/master/config/images.yaml) and match them to your requirements. Defaults are sane enough for most environments, but don't take any chances :)
1. Copy your IOS images defined in `images.yaml` to the `src_image_path` defined in `config.yaml`.

**Note:** Pay special attention if you have devices of the *same* model, but need *different* IOS images (e.g., ipbase vs ipservices). In that case, define both images in `images.yaml` and add the same model to their respective `models` lists. Then, change `match_feature_set` to `true` in `config.yaml`.

### Interactive

```
>>> from iosfw import iosfw
>>> device = iosfw('ios-sw-1')
Username [austindcc]:
Password:
Enable secret:
Opening connection to ios-sw-1...
Connected to ios-sw-1 (WS-C3560X-48P) as adecoup via ssh
Running version: 12.2(55)SE8
Upgrade version: 15.2(4)E8
Upgrade status: NEEDS UPGRADE
>>> device.upgrade()
Starting upgrade on ios-sw-1 at 14:34:09 06/13/19...
Checking free space...
Found enough free space!
Installing new firmware...
NOTE: No status updates possible during install, which may take 10 minutes or longer.
Install successful!
Removing running image...
Deleting flash:/c3560e-universalk9-mz.122-55.SE8...
Running image deleted.
Scheduling reload...
Reload scheduled for 00:00:00 PDT Fri Jun 14 2019 (9 hours and 16 minutes away)
Upgrade on ios-sw-1 completed at 14:43:32 06/13/19
Total time elapsed: 0:09:23.224298
```

### Automated

See [`example/batch_example.py`](https://github.com/austind/iosfw/blob/master/example/batch_example.py)

## Known issues

* During testing, Catalyst 3750-X models tested took unusually long to install. The install succeeded, but `iosfw` did not recognize install completion and eventually times out. This left them with properly upgrade IOS, but no scheduled reload.
* Catalyst 3k series (3650 and 3850) with IOS running in BUNDLE mode (booted directly to the .bin file), will not succeed in upgrading with `request platform software package install`. Upgrading them requires a different manual process that is not yet implemented:
    * Remove existing IOS with `del /force flash:/cat*.pkg`
    * Remove existing packages.conf with `del /force flash:/packages.conf`
    * Remove boot variables with `no boot system` in config mode
    * Copy upgrade image with `copy <source> flash:`
    * Install upgrade image with `request platform software package expand switch all file flash:/<file>`
    * Set boot variable with `boot system flash:/<file>`
    * Schedule reload with `reload at 00:00`
* Currently, `iosfw` does not check to ensure `transfer_source` in `config.yaml` is reachable. If not reachable, the install command will fail, but not timeout for more than 30 minutes. Most commonly, `transfer_source` may not be reachable due to sending the requests out the incorrect interface. You can specify the source interface for TFTP and FTP transfers with `ip (ftp|tftp) source-interface <iface>` in config mode. Checking reachability and attempting an automated resolution is a feature on the roadmap.

## Notes

* Expect devices to take between 10 and 30 minutes to come back after reload, especially if upgrading from 12.x to 15.x, due to microcode updates.
* The `iosfw` class exposes all of NAPALM's config parameters, and stores the NAPALM session under `self.napalm`, so you can use all of NAPALM's features easily.
* Same goes for netmiko - stored as `self.device` - so you can send arbitrary commands with `iosfw.device.send_command('my arbitrary command')`
