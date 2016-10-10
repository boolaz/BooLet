# Boolaz Log Examination Tool (with anomaly detection) - v1.2

This tool is aimed at optimizing analysis of HTTP logs and finding anomalies in the raw logs in an automated manner, based upon a custom set of Yara rules (SQLi, XSS, directory traversal, shells and PHP shells ...). booLet has the ability to also generate reports and exports based on filters applied to the raw logs.

booLet may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incidents.

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) for a demo.

------------

## Requirements

Boolet 1.2 has been developed in python 2.7 and successfully tested on Linux Ubuntu 14.04 LTS (version 1.1 also works on MacOSX 10.11.6 El Capitan and Windows 8.1x64)

### python modules

Boolet 1.2 requires four additional python modules to work

- [geoip2](https://pypi.python.org/pypi/geoip2) (2.2.0)
- [pyasn](https://pypi.python.org/pypi/pyasn) (1.5.0b6)
- [yara-python](https://pypi.python.org/pypi/yara-python) (3.5.0)
- [PyYAML](https://pypi.python.org/pypi/pyYAML) (3.12)

Installing the required modules can be achieved by the following commands :

    sudo -H pip install geoip2
    sudo -H pip install pyasn
    sudo -H pip install pyYAML
    sudo -H pip install yara-python

### Installing on Windows and Mac

For now, booLet 1.2 doesn't work fine on Windows and Mac due to the use of Yara-Python which is not properly implemented for those operating systems.
Windows and mac users may use [booLet 1.1](https://github.com/boolaz/BooLet/tree/master/booLet_1.1) instead but won't benefit from automatic anomaly detection.

------------

## usage

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) to get help on usage.
