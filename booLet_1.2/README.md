Boolaz Log Examination Tool (with automatic anomaly detection) - v1.2
=====================================================================

This tool is aimed at optimizing analysis of HTTP logs and finding anomalies in the raw logs in an automated manner, based upon a custom set of Yara rules (SQLi, XSS, directory traversal, shells and PHP shells ...). booLet has the ability to also generate reports and exports based on filters applied to the raw logs.

booLet may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incidents.

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) for a demo.

Requirements
------------

Boolet 1.2 has been developed in python 2.7 and successfully tested on Linux Ubuntu 14.04 LTS and Windows 8.1x64 (version 1.1 also works on MacOSX 10.11.6 El Capitan)

Boolet 1.2 requires three additional python modules to work

- [geoip2](https://pypi.python.org/pypi/geoip2)
- [pyasn](https://pypi.python.org/pypi/pyasn)
- [yara-python](https://pypi.python.org/pypi/yara-python)

Installing the required modules can be achieved by the following commands :

sudo -H pip install geoip2
sudo -H pip install pyasn
sudo -H pip install yara-python

In order to install pyasn on windows, you will also need

- [Microsoft Visual C++ Compiler for Python 2.7] (https://www.microsoft.com/en-us/download/details.aspx?id=44266)

If you're a windows user, and you don't want to mess with python, you can also use the stand-alone binary version of BooLET.
- [BooLET for windows](https://github.com/boolaz/BooLet/blob/master/booLet_1.2/windows/)

usage
-----

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) to get help on usage.
