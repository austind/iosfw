# iosfw

Automatic Cisco IOS firmware upgrades

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)

Requires:
* Python 3.6+
* [`netmiko`](https://github.com/ktbyers/netmiko)
* [`napalm`](https://github.com/napalm-automation/napalm)
* [`tqdm`](https://github.com/tqdm/tqdm)

## Overview

Automates the entire upgrade process:
* Determines correct upgrade image for each platform
* Transfer the new image
* Verify image integrity
* Extract archive and install
* Optionally remove old image(s)
* Set boot parameters
* Schedule reload

Auto-detects best upgrade method available:
* `archive download-sw`
* `software install`
* `request platform software package install`
* If those fail, plain `copy` followed by `set boot ...`

Supported platforms:
* Catalyst 3550
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

Currently unsupported platforms:
* Nexus 3k/9k
* Catalyst 9k series
* ISR 4300

**NOTE: Use at your own risk.** It works well in my environment, but serious bugs are possible. Test thoroughly in a lab environment, and see known issues below.

## Usage

### Preparation

1. Rename [`config/config.yaml.example`](https://github.com/austind/iosfw/blob/master/config/config.yaml.example) to `config.yaml`, and review [`config/images.yaml`](https://github.com/austind/iosfw/blob/master/config/images.yaml), matching both to your requirements. Defaults are sane, but don't take any chances :)
1. Copy your IOS images defined in `images.yaml` to the `src_image_path` defined in `config.yaml`.

**Note:** Pay special attention if you have devices of the *same* model, but need *different* IOS images (e.g., ipbase vs ipservices). In that case, define both images in `images.yaml` and add the same model to their respective `models` lists. Then, change `match_feature_set` to `true` in `config.yaml`.

### Interactive Example

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

### Automated Example

See [`example/batch_example.py`](https://github.com/austind/iosfw/blob/master/example/batch_example.py)

## Known issues

* As of 0.9.0, SCP image transfer directly from `iosfw` no longer works. I recommend setting up an FTP server on a separate host and setting `config.yaml` accordingly.
* Catalyst 3k series (3650 and 3850) with IOS running in BUNDLE mode (booted directly to the .bin file), will not succeed in upgrading with `request platform software package install`. Upgrading them requires a different manual process that is not yet implemented:
    * Remove existing IOS packages: `del /force flash:/cat*.pkg`
    * Remove existing packages.conf: `del /force flash:/packages.conf`
    * Remove boot variables: `no boot system` in config mode
    * Copy upgrade image: `copy <source> flash:`
    * Install upgrade image: `request platform software package expand switch all file flash:/<file>`
    * Set boot variable: `boot system flash:/<file>`
    * Schedule reload: `reload at 00:00`
* Currently, `iosfw` does not check to ensure `transfer_source` is reachable. If not reachable, the install command will fail, but not timeout for more than 30 minutes. Most commonly, `transfer_source` may not be reachable due to sending the requests out the incorrect interface. You can specify the source interface for TFTP and FTP transfers with `ip (ftp|tftp) source-interface <iface>` in config mode.
* When using SSH proxy, `iosfw` throws a `ProcessLookupError` on exit. I have not found a way to catch or suppress this.

## Wishlist

* [Nornir](https://github.com/nornir-automation/nornir) integration
* Fix native SCP image transfer option (broken as of 0.9.0)
* Accept a pre-existing `napalm` connection object
* Verify reachability of `transfer_source`, attempting fix as needed
* More consistent debug output
* Break `__init__()` into separate methods, with more verbose feedback
* ISR 4300 support
* N3K/N9K support

Contributions welcome.

## Notes

* Expect most upgrades to take 8-10 minutes per device, with one notable exception: Catalyst 3750-X took no less than 40 minutes in testing.
* Expect devices to take between 10 and 30 minutes to come back after reload, especially if upgrading trains or major versions, due to microcode updates.
* The automated install commands (`archive download-sw` and `request platform software package install`) download the upgrade package twice, for reasons I did not determine.
* FTP and HTTP seem to be the fastest transfer methods. Even then, the download appears constrained by platform CPU resources, averaging about 4Mbps in most tests, while some newer platforms achieved 20Mbps.
* The `iosfw` class exposes all of NAPALM's config parameters, and stores the NAPALM session under `self.napalm`, so you can use all of NAPALM's features easily.
* Same goes for netmiko - stored as `self.device` - so you can send arbitrary commands with `iosfw.device.send_command('my arbitrary command')`
