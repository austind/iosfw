## 0.9.8
* New platform: Catalyst 9k

## 0.9.7
* Bug fix: Regressions in get_upgrade_cmd()
* New feature: Override default reload params from `config.yaml` when calling `upgrade()`
* New feature: get_all_boot_images()
* New platform: Catalyst 9200

## 0.9.6
* New platform: ASR920 support
* New platform: ISR 4331 support
* New feature: Control creds in config.yaml
* Bug fix: Unrequested debug output
* Bug fix: Several issues in `schedule_reload()`
* Refactor: move connection to `open()` method

## 0.9.5
* Bug fix: `reload_at` variable ignored
* Bug fix: Disable reload ignored
* Bug fix: Incomplete reload logging
* New feature: Immediate reload
* New feature: Staggered reload
