# Boolaz Log Examination Tool (with anomaly detection) - v1.2

This tool is aimed at optimizing analysis of HTTP logs and finding anomalies in the raw logs in an automated manner, based upon a custom set of Yara rules (SQLi, XSS, directory traversal, shells and PHP shells ...). booLet has the ability to also generate reports and exports based on filters applied to the raw logs.

booLet may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incidents.

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) for a demo.

------------

## Requirements

Boolet 1.2 has been developed in python 2.7 and successfully tested on Linux Ubuntu 14.04 LTS and Windows 8.1x64 (version 1.1 also works on MacOSX 10.11.6 El Capitan)

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

### Installing on Linux

On linux yara can be installed like other python modules

    sudo -H pip install yara-python

### Installing on Windows

On windows, installing yara-python via pip seems to be the hardest way.

you will prefer to install yara from the binaries
- [Yara binaries for windows](http://yara.readthedocs.io/en/v3.4.0/gettingstarted.html#installing-on-windows) 

In order to install pyasn on windows, you will also need

- [Microsoft Visual C++ Compiler for Python 2.7] (https://www.microsoft.com/en-us/download/details.aspx?id=44266)

And if you don't want to mess with python, you can also use the stand-alone binary version of BooLET.
- [BooLET 1.2 for windows](https://github.com/boolaz/BooLet/blob/master/booLet_1.2/windows/)

------------

## usage

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) to get help on usage.
