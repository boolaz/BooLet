     ____              _          _   
    |  _ \            | |        | |  
    | |_) | ___   ___ | |     ___| |_
    |  _ < / _ \ / _ \| |    / _ \ __|
    | |_) | (_) | (_) | |___|  __/ |_
    |____/ \___/ \___/|______\___|\__|

# Boolaz Log Examination Tool (with anomaly detection)

**The latest version is [BooLET 1.2](https://github.com/boolaz/BooLet/blob/master/booLet_1.2/)** (initially published on 10/10/2016). See [Changelog](https://github.com/boolaz/BooLet/blob/master/CHANGELOG.md) for release notes.

This tool is aimed at optimizing analysis of HTTP logs and finding anomalies in the raw logs in an automated manner, based upon a custom set of Yara rules (SQLi, XSS, directory traversal, shells and PHP shells ...). booLet has the ability to also generate reports and exports based on filters applied to the raw logs.

booLet may be used by forensic investigators, or sysadmins to quickly review HTTP logs and determine the causes of incidents.

[![ScreenShot](https://raw.githubusercontent.com/boolaz/BooLet/master/screenshot/boolet.png)](https://youtu.be/mcDYH6CiiYs)

For a demo video, click on the picture above

-----------------

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

booLet 1.2 is not currently available for those operating systems. A compatible version will be online soon.
For the time being, Windows and mac users may use [booLet 1.1](https://github.com/boolaz/BooLet/tree/master/booLet_1.1) instead but won't benefit from automatic anomaly detection.

-----------------

## How to import your log files

Once you have all modules properly installed, you can import your raw logs.

    $ booLet.py --import combined access.*

For now, booLet supports three formats of logs : ``combined``, ``common``, and ``iponly`` (one IP per line)

The previous command will create a SQLite database, parse your logs, and populate the database with the data. It will also generate a CSV file containing the summary of the imported log files (start, end, nb of lines, nb of unique IP)

During this phase, boolet ignores the following types of file : ``ico jpg png js css gif woff svg robots.txt`` to focus more on static HTML pages and dynamic content such as PHP scripts.

In addition, Boolet ignores visits from most common bots as they are generally not of interest in the scope of a forensic investigation.

    ==> Storing HTTP logs into database <=====================
    file|Start|End|number of lines|nb of unique IP
    www.brunovalentin.com.log|03/Jul/2016 06:37:04|06/Jul/2016 20:07:21|14161|906
    www.brunovalentin.com.log.1|26/Jun/2016 06:53:16|03/Jul/2016 06:36:23|29494|1685

    ==> Generating IP table <=====================

    ==> Generating ASN table <=====================

    ==> Updating geoip and ASN infos <=====================

    ==> Summary <=====================
    Total anomalies in fields : 199/344070

    Anomalies in referer: 7/114694
    Anomalies in uri: 63/114684
    Anomalies in agent: 129/114692

    directory traversal (dirtrav) : 8
    SQL Injection attempt (sqli) : 1
    shell access attempt (shell) : 132
    encoded string (encoded) : 57
    Unusual long field (longfield) : 2

You are now ready to submit your requests to the database.

Each and every line of log is now associated with additional fields regarding IP addresses (country name, country ISO code, city, Autonomous System (ASN), ASN description, and IP range the IP address belongs to)

-----------------

## How to query data

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
    o: type of anomaly detected

-----------------

## How to filter output

If you want to narrow down your search and to be presented with more accurate information, you can also filter data upon specific fields

This example displays fields ``dhiuns`` where ``country code=(BE or ES or DE)`` and ``time begins with "16:"``

    $ booLet12.py --fields dhiuns --country BE,ES,DE --time 16:

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

You can also search for lines with anomalies

    Ex: boolet12.py -f oiur --anomaly sqli,dirtrav
    Ex: boolet12.py -f oiur --anomaly all

### example with anomalies

The following example will retrieve only SQL Injections,SQL file downloads and directory traversals and will display the following fields (odhiu : anomaly, date, time, ip, uri)

    booLet12.py -f odhiu --anomaly sqlfile,sqli,dirtrav

The result will be as following :

    sqlfile|2014-12-07|04:24:49|46.161.41.257|/Agenda.sql
    encoded,shell,sqli|2014-12-10|17:21:19|61.182.202.257|/insert+into%3A%2C%45%56%76%54%4E%3A%2E%45
    dirtrav|2014-12-03|10:10:22|74.208.69.198|/vtigercrm/modules/com_vtiger_workflow/sortfieldsjson.php?module_name=../../../../../../../..//etc/asterisk/sip_additional.conf%00
    dirtrav|2014-12-18|21:34:49|202.62.155.257|/cart.php?a=byroe&templatefile=../../../configuration.php%00
    dirtrav|2014-12-23|20:43:49|192.99.68.257|/?lang=../../../../../../../../../../../proc/self/environ
    dirtrav|2014-12-23|20:46:04|192.99.68.257|/?lang=../../../../../../../../../../../proc/self/environ%00
    dirtrav|2015-01-04|23:56:34|82.97.16.257|//cgi-bin/webcm?getpage=../html/menus/menu2.html&var:lang=%26%20allcfgconv%20-C%20voip%20-c%20-o%20-%20../../../../../var/tmp/voip.cfg%20%26
    dirtrav|2015-01-05|02:19:43|82.97.16.257|//cgi-bin/webcm?getpage=../html/menus/menu2.html&var:lang=%26%20allcfgconv%20-C%20voip%20-c%20-o%20-%20../../../../../var/tmp/voip.cfg%20%26
    dirtrav|2015-01-05|02:55:11|82.97.16.257|//cgi-bin/webcm?getpage=../html/menus/menu2.html&var:lang=%26%20allcfgconv%20-C%20voip%20-c%20-o%20-%20../../../../../var/tmp/voip.cfg%20%26
    dirtrav|2015-01-07|00:10:00|216.121.118.257|/index.php?page=../../../../../../../../../../../proc/self/environ

use the --help option of boolet for more options

-----------------

## How to export output data

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

## Todo list

- update functionality for geoip and asn databases
- add more input formats

Stay tuned for updates and please, feel free to report any bug to the author.
