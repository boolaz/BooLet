Boolaz Log Examination Tool - v1.1
==================================

This tool is aimed at optimizing analysis of HTTP logs, with the ability to produce reports based on filters applied to the raw logs.
It may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incident.

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) for a demo.

Requirements
------------

Boolet 1.1 has been developed in python 2.7 and successfully tested on Linux Ubuntu 14.04 LTS and Windows 8.1x64. Contrarily to later versions, booLet 1.1 also works on MacOSX 10.11.6 El Capitan.

Boolet requires two additional python modules

- [geoip2](https://pypi.python.org/pypi/geoip2)
- [pyasn](https://pypi.python.org/pypi/pyasn)

On a mac, installing the required modules can be achieved by the following commands :

    sudo easy_install pip
    sudo -H pip install geoip2
    sudo -H pip install pyasn

In order to install pyasn on windows, you will also need

- [Microsoft Visual C++ Compiler for Python 2.7] (https://www.microsoft.com/en-us/download/details.aspx?id=44266)

If you're a windows user, you can also use the stand-alone binary version of BooLET.
- [BooLET for windows](https://github.com/boolaz/BooLet/blob/master/booLet_1.1/windows/)

usage
-----

Have a look at the [general presentation](https://github.com/boolaz/BooLet/blob/master/README.md) to get help on usage.
