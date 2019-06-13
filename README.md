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

**NOTE:** This is beta software in active development. It works well in my environment, but serious bugs are possible. Use at your own risk.

## Usage

1. Review [`config/config.yaml`](https://github.com/austind/iosfw/blob/master/config/config.yaml) and [`config/images.yaml`](https://github.com/austind/iosfw/blob/master/config/images.yaml) and match them to your requirements. Defaults are sane enough for most environments, but don't take any chances :)
1. Copy your IOS images defined in `images.yaml` to the `src_image_path` defined in `config.yaml`.

**Note:** Pay special attention if you have devices of the *same* model, but need *different* IOS images (e.g., ipbase vs ipservices). In that case, define both images in `images.yaml` and add the same model to their respective `models` lists. Then, change `match_feature_set` to `true` in `config.yaml`.

### Interactive

```py
>>> from iosfw import iosfw
>>> device = iosfw('ios-sw-1')
Username [austindcc]:
Password:
Enable secret:
Opening connection to palermoidf2c...
Connected to PalermoIDF2c (WS-C3560X-48P) as adecoup via ssh
Running version: 12.2(55)SE8
Upgrade version: 15.2(4)E8
Upgrade status: NEEDS UPGRADE
>>> device.upgrade()
Starting upgrade on PalermoIDF2c at 14:34:09 06/13/19...
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
Upgrade on PalermoIDF2c completed at 14:43:32 06/13/19
Total time elapsed: 0:09:23.224298
```

### Automated

See [`example/batch_example.py`](https://github.com/austind/iosfw/blob/master/example/batch_example.py)

## Notes

* Tested on various versions of IOS 12.x upgrading to 12.x and 15.x, but YMMV.
* Expect devices to take between 10 and 30 minutes to come back after reload, especially if upgrading from 12.x to 15.x, due to microcode updates.
* The `iosfw` class exposes all of NAPALM's config parameters, and stores the NAPALM session under `self.napalm`, so you can use all of NAPALM's features easily.
* Same goes for netmiko - stored as `self.device` - so you can send arbitrary commands with `iosfw.device.send_command('my arbitrary command')`
* Tested on Python 2.7. Porting to 3.x in the works.
