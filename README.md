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

Each and every line of log is now associated with the additional fields regarding the IP address (country name, country ISO code, city, Autonomous System (ASN), ASN description, and IP range the IP address belongs to)

How to query data
-----------------
you can retrieve your log data based upon selected fields

example

    $ booLet.py --fields dhicu

will give you the following result

    ...
    2016-07-06|19:58:29|194.187.170.111|FR|/page/2/
    2016-07-06|19:58:32|194.187.170.111|FR|/a-propos/
    2016-07-06|19:58:37|194.187.170.111|FR|/dev/boofadet/
    2016-07-06|19:59:49|208.78.55.117|MF|/mac/clavier-mac-francais-windows/
    2016-07-06|19:59:55|194.187.170.111|FR|/category/trucs-de-geek/
    ...

The following fields may be used :

    i: ip
    d: date
    h: time
    m: method
    u: url
    t: http status code
    z: size
    r: referer
    a: agent
    c: country code
    n: country name
    y: city
    s: asn
    g: asn range
    l: asn label

Filtering data
--------------
If you just want to narrow down your search to specific information, you can also filter information based upon specific fields

This example displays fields ``dhiuns`` where ``country code=(BE or ES or DE)`` and ``time begins with "16:"``

    $ booLet.py --fields dhiuns --country BE,ES,DE --time 16:

will produce the following output

    2016-06-28|16:27:10|136.243.56.239|/feed/|Germany|AS24940
    2016-06-28|16:27:10|136.243.56.239|/feed/|Germany|AS24940
    2016-06-29|16:08:24|85.26.90.2|/|Belgium|AS12392
    2016-06-29|16:10:11|85.26.90.2|/investigation-numerique/encase-forensic-8-fin-juin/|Belgium|AS12392
    2016-06-29|16:10:13|85.26.90.2|/investigation-numerique/effacement-chimique-disque-dur/|Belgium|AS12392
    2016-06-29|16:11:21|85.26.90.2|/page/2/|Belgium|AS12392
    2016-06-29|16:11:22|85.26.90.2|/ul/monitorssetup-1024x669.jpeg|Belgium|AS12392
    2016-06-29|16:13:18|85.26.90.2|/sans-categorie/des-machines-virtuelles-oui-mes-des-ecrans-cest-mieux/|Belgium|AS12392
    2016-06-29|16:13:19|85.26.90.2|/securite-info/rechercher-traces-meterpreter-en-memoire-volatility/|Belgium|AS12392
    2016-06-29|16:24:54|136.243.56.239|/feed/|Germany|AS24940
    2016-06-30|16:27:31|136.243.56.239|/feed/|Germany|AS24940
    2016-07-06|16:30:29|109.128.211.78|/|Belgium|AS5432

Export Output
--------------
When you're happy with your output, you have multiple options to save it to a distinct output file.
- Use the > sign to redirect to a new file
- Boolet has also a ``--out`` option to export in a csv file (pipe separated fields)

example

    $ booLet.py --fields dhi --out outfile.csv

will generate the following file :

    2016-06-26|06:54:10|146.185.251.48
    2016-06-26|06:57:39|146.185.251.210
    2016-06-26|07:00:09|94.228.34.250
    2016-06-26|07:00:21|146.185.251.48
    2016-06-26|07:00:35|37.187.109.125
    2016-06-26|07:00:36|91.134.167.121
    2016-06-26|07:01:04|86.247.45.90
