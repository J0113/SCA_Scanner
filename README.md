# SCA_Scanner

Standalone tool to scan a system Compliance status with Security Configuration Assessment (SCA) in YAML format.

- Wazuh explains how SCA works [here](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/how-it-works.html).
- And provides CIS benchmarks [here](https://github.com/wazuh/wazuh/tree/main/ruleset/sca).

## TODO:
- [X] Runs on Windows 
- [X] Runs on MacOS
- [ ] Runs on Linux
- [ ] Log to logfile
- [ ] Output to file (in multiple formats, CSV, JSON and TEXT)
- [X] Variable support
- [X] Support check conditions [(All, any, none)](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#condition)
- [X] Rule type ['Directory'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Rule type ['Process'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Rule type ['Commands'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Rule type ['Registry (Windows Only)'](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#rules)
- [X] Support all [Content comparison operators](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#id8)
- [X] Support all [Numeric comparison operators](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#id9)
- [X] Pass all [examples](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html#examples)
