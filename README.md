     ____              _          _   
    |  _ \            | |        | |  
    | |_) | ___   ___ | |     ___| |_
    |  _ < / _ \ / _ \| |    / _ \ __|
    | |_) | (_) | (_) | |___|  __/ |_
    |____/ \___/ \___/|______\___|\__|

Boolaz Log Examination Tool (with anomaly detection)
====================================================

The latest version is [BooLET 1.2](https://github.com/boolaz/BooLet/blob/master/booLet_1.2/) (initially published on 10/10/2016)

This tool is aimed at optimizing analysis of HTTP logs and finding anomalies in the raw logs in an automated manner, based upon a custom set of Yara rules (SQLi, XSS, directory traversal, shells and PHP shells ...). booLet has the ability to also generate reports and exports based on filters applied to the raw logs.

booLet may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incidents.

[![ScreenShot](https://raw.githubusercontent.com/boolaz/BooLet/master/screenshot/boolet.png)](https://youtu.be/mcDYH6CiiYs)

For a demo video, click on the picture above

Requirements
------------

Boolet 1.2 has been developed in python 2.7 and successfully tested on Linux Ubuntu 14.04 LTS and Windows 8.1x64 (version 1.1 also works on MacOSX 10.11.6 El Capitan)

Boolet 1.2 requires three additional python modules to work

- [geoip2](https://pypi.python.org/pypi/geoip2) (2.2.0)
- [pyasn](https://pypi.python.org/pypi/pyasn) (1.5.0b6)
- [yara-python](https://pypi.python.org/pypi/yara-python) (3.5.0)

Installing the required modules can be achieved by the following commands :

    sudo -H pip install geoip2
    sudo -H pip install pyasn
    sudo -H pip install yara-python

In order to install pyasn on windows, you will also need

- [Microsoft Visual C++ Compiler for Python 2.7] (https://www.microsoft.com/en-us/download/details.aspx?id=44266)

If you're a windows user, and you don't want to mess with python, you can also use the stand-alone binary version of BooLET.
- [BooLET for windows](https://github.com/boolaz/BooLet/blob/master/booLet_1.2/windows/)

How to import your log files
----------------------------

Once you have all modules properly installed, you can import your raw logs.

    $ booLet.py --import combined access.*

For now, booLet supports three formats of logs : ``combined``, ``common``, and ``iponly`` (one IP per line)

The previous command will create a SQLite database, parse your logs, and populate the database with the data. It will also generate a CSV file containing the summary of the imported log files (start, end, nb of lines, nb of unique IP)

During this phase, boolet ignores the following types of file : ``ico jpg png js css gif woff svg robots.txt`` to focus more on static HTML pages and dynamic content such as PHP scripts.

In addition, Boolet ignores visits from most common bots as they are generally not of interest in the scope of a forensic investigation.

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

Each and every line of log is now associated with additional fields regarding IP addresses (country name, country ISO code, city, Autonomous System (ASN), ASN description, and IP range the IP address belongs to)

How to query data
-----------------
you can retrieve your log data based upon selected fields in the requested order

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

How to filter output
--------------------
If you want to narrow down your search and to be presented with more accurate information, you can also filter data upon specific fields

This example displays fields ``dhiuns`` where ``country code=(BE or ES or DE)`` and ``time begins with "16:"``

    $ booLet.py --fields dhiuns --country BE,ES,DE --time 16:

output :

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

Of course you're free to chose the fields order : ``dhiuns`` is not ``idhsnu``

How to export output data
-------------------------
When you're happy with your output, you have two options to save it to an output file.

- Use the > sign to redirect to a new file

    ``$ booLet.py --fields dhi > outfile.csv``

- Boolet has also a ``--out`` option to export in a csv file (pipe separated fields)

    ``$ booLet.py --fields dhi --out outfile.csv``

Both will generate the following file, named outfile.csv :

    2016-06-26|06:54:10|146.185.251.48
    2016-06-26|06:57:39|146.185.251.210
    2016-06-26|07:00:09|94.228.34.250
    2016-06-26|07:00:21|146.185.251.48
    2016-06-26|07:00:35|37.187.109.125
    2016-06-26|07:00:36|91.134.167.121
    2016-06-26|07:01:04|86.247.45.90
    ...

This format has been adopted because it is as easy to read as to process with bash tools like awk, cut or sort.

Todo list
---------
- update functionality for geoip and asn databases
- add more input formats

Stay tuned for updates and please, feel free to report any bug to the author.
