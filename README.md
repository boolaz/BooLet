     ____              _          _   
    |  _ \            | |        | |  
    | |_) | ___   ___ | |     ___| |_
    |  _ < / _ \ / _ \| |    / _ \ __|
    | |_) | (_) | (_) | |___|  __/ |_
    |____/ \___/ \___/|______\___|\__|

Boolaz Log Examination Tool
===========================

This tool is aimed at optimizing analysis of HTTP logs, with the ability to produce reports based on filters applied to the raw logs.
It may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incident.

Requirements
------------

Boolet has been developed in python and require two additional modules
- [geoip2](https://pypi.python.org/pypi/geoip2)
- [pyasn](https://pypi.python.org/pypi/pyasn)

How to import your log files
----------------------------

Once you have all modules properly installed, you can import your raw logs.

    $ booLet.py --import combined access.*

For now, booLet supports three formats of logs : ``combined``, ``common``, and ``iponly`` (one IP per line)

The previous command will create a SQLite database, parse your logs, and populate the database with the data. It also generates a CSV file containing the summary the the imported log files (start, end, nb of lines, nb of unique IP)

    /-----------------------------------/ 
    /  Storing HTTP logs into database  / 
    /-----------------------------------/
    file|Start|End|number of lines|nb of unique IP
    www.brunovalentin.com.log|03/Jul/2016 06:37:04|06/Jul/2016 20:07:21|14161|906
    www.brunovalentin.com.log.1|26/Jun/2016 06:53:16|03/Jul/2016 06:36:23|29494|1685
    /--------------------------------/ 
    /        Generating IP table     / 
    /--------------------------------/
    /----------------------------------/ 
    /      	Generating ASN table       / 
    /----------------------------------/
    /----------------------------------/ 
    /   Updating geoip and ASN infos   / 
    /----------------------------------/

You are now ready to submit your requests to the database. 

How to query data
-----------------
