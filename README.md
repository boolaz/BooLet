     ____              _          _   
    |  _ \            | |        | |  
    | |_) | ___   ___ | |     ___| |_
    |  _ < / _ \ / _ \| |    / _ \ __|
    | |_) | (_) | (_) | |___|  __/ |_
    |____/ \___/ \___/|______\___|\__|

# Boolaz Log Examination Tool

This tool is aimed at optimizing analysis of HTTP logs, with the ability to produce reports based on filters applied to the raw logs.
It may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incident.

# Requirements

Boolet has been developed in python and require two additional modules
- [geoip2](https://pypi.python.org/pypi/geoip2)
- [pyasn](https://pypi.python.org/pypi/pyasn)

# Usage

Once you have all modules properly installed, you can import your raw logs.

.. code-block:: bash

  $ booLet.py --import combined access.*

For now, booLet supports three formats of logs : combined, common, and iponly (one IP per line)

The previous command will create a SQLite database, parse your logs, and populate the database with the data.

