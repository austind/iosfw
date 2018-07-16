# iosfw

## Overview

Built upon NAPALM and Netmiko to take most of the headache out of IOS upgrades.

Automates this process:
1. Check and (if necessary) fix/enable SCP
1. Check for adequate free space on device's `flash`
   1. (Optional) Deletes old image to clear space if needed
1. Copies new image via SCP with progress
1. Verifies copied image MD5 hash
1. Sets `boot system` pointing to the new image
1. Schedules reload for a configurable time

Features:
* YAML-based config
* Logs progress to console and/or file with configurable verbosity
* Works with ad-hoc upgrades (interactive) or batch jobs (non-interactive)

## Usage

1. Review [`config/config.yaml`](https://github.com/austind/iosfw/blob/master/config/config.yaml) and [`config/images.yaml`](https://github.com/austind/iosfw/blob/master/config/images.yaml) and match them to your requirements. Defaults are sane enough for most environments, but don't take any chances :)
1. Copy your IOS images defined in `images.yaml` to the `src_image_path` defined in `config.yaml`.

**Note:** Pay special attention if you have devices of the *same* model, but need *different* IOS images (e.g., ipbase vs ipservices). In that case, define both images in `images.yaml` and add the same model to their respective `models` lists. Then, change `match_feature_set` to `true` in `config.yaml`.

### Interactive

Basic example:

```py
import iosfw
device = iosfw.upgrade('ios-sw-1')
device.upgrade()
device.close()
```

Sample output:

```
[austindcc@jumphost iosfw]$ python2.7
Python 2.7.13 (default, Mar 14 2017, 15:43:22)
[GCC 4.4.7 20120313 (Red Hat 4.4.7-17)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import iosfw
>>> device = iosfw.upgrade('ios-sw-1')
Username [austindcc]:
Password:
Enable secret:
Opening connection to ios-sw-1...
Connected to ios-sw-1 (WS-C3560X-48P) as austindcc via ssh
Firmware status: NEEDS UPGRADE to c3560e-ipbasek9-mz.150-2.SE11.bin
>>> device.upgrade()
===============================================
Starting upgrade on ios-sw-1...
Checking SCP...
SCP not running. Enabling now...
SCP enabled successfully!
Checking device for upgrade image flash:/c3560e-ipbasek9-mz.150-2.SE11.bin...
Not found. Checking free space...
Found enough free space!
Starting transfer. Expect this to take several minutes...
c3560e-ipbasek9-mz.150-2.SE11.bin100%|##############################| 20.3M/20.3M [07:07<00:00, 47.5Kb/s]
Transfer complete! Verifying hash...
Hash verified!
Checking boot image...
Setting boot image to flash:/c3560e-ipbasek9-mz.150-2.SE11.bin...
Success! New boot image set to flash:/c3560e-ipbasek9-mz.150-2.SE11.bin.
Checking reload status ...
No reload scheduled. Scheduling...
Reload scheduled for 00:00:00 PDT Tue Jul 17 2018 (10 hours and 2 minutes away)
Upgrade on ios-sw-1 complete!
===============================================
>>> device.close()
>>>
```

### Automated

See [`example/batch_example.py`](https://github.com/austind/iosfw/blob/master/example/batch_example.py)

## Notes

* Tested on various versions of IOS 12.x upgrading to 12.x and 15.x, but YMMV.
* Expect devices to take between 10 and 30 minutes to come back after reload, especially if upgrading from 12.x to 15.x, due to microcode updates.
* The `iosfw.upgrade` class exposes all of NAPALM's config parameters, and stores the NAPALM session under `self.napalm`, so you can use all of NAPALM's features easily.
* Same goes for netmiko - stored as `self.device` - so you can send arbitrary commands with `iosfw.device.send_command('my arbitrary command')`
* Tested on Python 2.7 but probably fine on 3.x
