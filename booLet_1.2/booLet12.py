#!/usr/bin/python
# -*- coding: utf-8 -*-
# ---------------------------------------------------------
# Name       : BooLET.py
# Purpose    : Log Examination Tool with anomaly detection
# Revision   : 1.2 (01/09/2016)
# Author     : Bruno Valentin - bruno@boolaz.com
# Updates    : https://github.com/boolaz/BooLet
# Reference  : http://www.brunovalentin.com/dev/
# ---------------------------------------------------------

import os,sys,re,getopt
from sys import argv
from datetime import datetime
import geoip2.database
import sqlite3 as lite
import pyasn, yaml
from src.booLetLib import *

reload(sys)
sys.setdefaultencoding("utf-8")

softdesc={"name":"booLet",
          "version":"1.2", \
          "release":"01/09/2016", \
          "purpose":"Log Examination Tool with automatic anomaly detection", \
          "link":"https://github.com/boolaz/booLet" }

log_formats = {
    'common':'([^ ]+) [^ ]+ [^ ]+ \[([^:]+):([^ ]+) (.*?)\] "([^ ]+) ?([^ ]*) ?([^ ]*)" (\d+) ([\d\-]+)(.*?)(.*?)',
    'combined':'^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) ?(\S+)? ?(\S+).*" (\S+) (\S+) "(.+)?" "(.*)"$',
    'iponly':'([^|\n]+)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)'
}

# -----------------------------------------------------------
def create_new_database(db):  # creation d'une base vide
    with db:
        db.execute("DROP TABLE IF EXISTS logs")
        db.execute("CREATE TABLE logs(IP TEXT, ladate TEXT,lheure TEXT, \
         method TEXT,uri TEXT, status INT, size INT, referer TEXT, agent TEXT, \
         anomflags TEXT)")
        db.execute("CREATE INDEX _IP_LOGS ON logs(IP ASC)")
        db.execute("CREATE INDEX _ladate_LOGS ON logs(ladate ASC)")
        db.execute("CREATE INDEX _lheure_LOGS ON logs(lheure ASC)")
        db.execute("CREATE INDEX _method_LOGS ON logs(method ASC)")
        db.execute("CREATE INDEX _uri_LOGS ON logs(uri ASC)")
        db.execute("CREATE INDEX _status_LOGS ON logs(status ASC)")
        db.execute("CREATE INDEX _flags_LOGS ON logs(anomflags)")

# -----------------------------------------------------------
def format_line(line,log_format):

    global log_formats

    regex=log_formats[log_format]
    try:
        logip,logdate,logtime,logtz,logmethod,loguri,logversion,logstatus, \
        logsize,referer,logagent=re.match(regex, line).groups()
        # print re.match(regex, line).groups()
    except:
        print u"The following line raises an exception : \n{0}".format(line)
        # print re.match(regex, line).groups()
        sys.exit(2)
    return(logip,logdate,logtime,logtz,logmethod,loguri,logversion,logstatus,
        logsize,referer,logagent)

# -----------------------------------------------------------
def upload_logs_in_db(db,outdir,log_format,fichiers):

    excluded_agents=".*({}).*".format("|".join(boocfg['crawl_excl']['list']))
    excluded_uri=".*\.({})(\?|&)?".format("|".join(boocfg['uri_excl']['list']))
    uri_comp = re.compile(excluded_uri, flags=re.I)
    agents_comp = re.compile(excluded_agents, flags=re.I)

    # global log_formats
    db.row_factory = lite.Row  # @UndefinedVariable

    title("Storing HTTP logs into database")

    # summary.csv 
    resume_file = open(outdir + '/' + 'summary.csv',"w")
    resume_line=u"{0}|{1}|{2}|{3}|{4}".format("file","Start","End",
        "number of lines","nb of unique IP")
    print resume_line
    resume_file.write("SUMMARY\n")
    resume_file.write(resume_line+"\n")

    # for each logfile --> processing lines of log
    detail_fichiers=[]
    for fichier in fichiers:

        fd = open(fichier,"r")
        lignes_total= 0
        for line in fd:
            lignes_total+= 1

        # compiles rulesets
        AnomUri.compile_ruleset()
        AnomRef.compile_ruleset()
        AnomAgt.compile_ruleset()

        nb_lines=0
        ip=[]
        les_lignes=[]
        infile = open(fichier,"r")
        for line in infile:
            nb_lines+=1

            # matches the line
            # print u"{0} : {1}/{2}".format(fichier,nb_lines,lignes_total)
            logip,logdate,logtime,logtz,logmethod,loguri,logversion,logstatus,\
             logsize,referer,logagent=format_line(line,log_format)

            # determines beginning and end of the time period
            if nb_lines==1: debut=u"{0} {1}".format(logdate,logtime)
            fin=u"{0} {1}".format(logdate,logtime)
            if logdate:
                logdate = u"{0}".format(datetime.strptime(logdate, "%d/%b/%Y"))
                date_stamp = logdate[0:logdate.find(' ')]
            else:
                date_stamp=''

            # unknown ip --> appends ip array
            if logip not in ip: ip.append(logip)

            # Discards the line or not ?
            uri_discard=False
            if boocfg['uri_excl']['discard']:
                if uri_comp.match("{0!s}".format(loguri)):
                    uri_discard=True
            crawl_discard=False
            if boocfg['crawl_excl']['discard']:
                if agents_comp.match("{0!s}".format(logagent)):
                    crawl_discard=True

            # if no reason to discard the line
            if not (uri_discard or crawl_discard):
                
                # matches against yara rules
                if (loguri):
                    MyAnomUri=AnomUri("{}".format(loguri))
                    my_anom_uri_flags=MyAnomUri.search()

                if (referer):
                    MyAnomRef=AnomRef("{}".format(referer))
                    my_anom_ref_flags=MyAnomRef.search()

                if (logagent):
                    MyAnomAgt=AnomAgt("{}".format(logagent))
                    my_anom_agt_flags=MyAnomAgt.search()

                # concat lists without duplicates
                my_flags=list(set().union(my_anom_uri_flags,my_anom_agt_flags,
                    my_anom_ref_flags))

                # converts lists to comma separated strings
                if (my_flags):
                    for i, item in enumerate(my_flags):
                        my_flags[i] = "-{}-".format(item)
                    insert_flags=','.join(my_flags)
                else :
                    insert_flags=''

                # adds to les_lignes
                les_lignes.append((logip,date_stamp,logtime,logmethod, \
                    loguri,logstatus,logsize, referer, logagent,insert_flags))


        # inserts lines
        with db:
            cur = db.cursor()
            sql="INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?,?);"
            db.executemany(sql,les_lignes)

        # Summary --> file summary.csv
        detail_fichiers.append((os.path.basename(fichier),debut,fin,nb_lines,
            len(ip)))
        resume_line=u"{0!s}|{1!s}|{2!s}|{3!s}|{4!s}".format(
            os.path.basename(fichier),debut,fin,nb_lines,len(ip))
        print resume_line
        resume_file.write(resume_line+"\n")
        infile.closed

    resume_file.closed


# -----------------------------------------------------------
def create_ip_table(db):

    title("Generating IP table")

    ip_list=[]

    with db:
        cur = db.cursor()

        db.execute("DROP TABLE IF EXISTS ips")
        db.execute("""CREATE TABLE ips(IP TEXT, isocode TEXT, country_name TEXT,
                      city_name TEXT, asn INT, range TEXT, asnlabel TEXT)""")
        db.execute("CREATE UNIQUE INDEX _IP_IPS ON ips(IP ASC)")
        db.execute("CREATE INDEX _isocode_IPS ON ips(isocode ASC)")
        db.execute("CREATE INDEX _asn_IPS ON ips(asn ASC)")

        sql="SELECT DISTINCT IP FROM logs;"
        results=cur.execute(sql)
        for mon_ip in results:
            ip_list.append((mon_ip[0],'-','-','-','-','-','-'))
        sql="INSERT INTO ips VALUES (?,?,?,?,?,?,?);"
        db.executemany(sql,ip_list)


# -----------------------------------------------------------
def create_asn_table(db):

    title("Generating ASN table")

    fichier=script_path+"/booLet_extres/ASNList.txt"
    asn_list=[]
    les_lignes=[]

    infile = open(fichier,"r")
    for line in infile:
        regex = '([^ ]+) +(.+)'
        asn,asnLabel=re.match(regex, line).groups()
        asnlabel="%s" % unicode(asnLabel)  # @UndefinedVariable
        les_lignes.append((asn,asnlabel))

    with db:
        db.execute("DROP TABLE IF EXISTS asns")
        db.execute("CREATE TABLE asns(asn TEXT, asnlabel TEXT)")
        db.execute("CREATE UNIQUE INDEX _asn_asns ON asns(asn ASC)")

        sql="INSERT INTO asns VALUES (?,?);"
        db.executemany(sql,les_lignes)

    infile.closed


# -----------------------------------------------------------
def maj_location_asn(db):

    title("Updating geoip and ASN infos")

    reader = geoip2.database.Reader(script_path+
        '/booLet_extres/GeoLite2-City.mmdb')
    asn_db = pyasn.pyasn(script_path+'/booLet_extres/ipasn_20150224.dat')
    les_lignes=[]
    with db:
        cur = db.cursor()
        sql="SELECT IP FROM ips;"
        results=cur.execute(sql)
    for mon_ip in results:
        country_name=city_name=iso_code='-'

        try:
            response = reader.city(mon_ip[0])
        except:
            country_name=city_name=iso_code='-'
        else:
            if response.country.names:
                if "fr" in response.country.names: 
                    country_name=response.country.names['fr']
                if response.country.names!='' : 
                    country_name=response.country.name

            if response.city.name:
                if response.city.name!='':
                    city_name=response.city.name
                else: city_name='-'

            if response.country.iso_code in ['','None'] : iso_code='-'
            else: iso_code="{0!s}".format(response.country.iso_code)

        try:
            asn,range=asn_db.lookup(mon_ip[0])
        except:
            asn=range='-'
        else:
            if ("{0!s}".format(asn)).lower()=='none': asn=range='-'
            else: asn="AS{0!s}".format(asn)

        les_lignes.append((iso_code,country_name,city_name,asn,range,mon_ip[0]))

    with db:
        cur = db.cursor()
        sql="""UPDATE ips SET isocode=?, country_name=?, city_name=?, asn=?, 
               range=? WHERE IP=?"""
        db.executemany(sql,les_lignes)

        sql="""SELECT DISTINCT(i.asn),a.asnlabel FROM ips i, asns a 
               WHERE i.asn = a.asn;"""
        results=cur.execute(sql)
        values=[]
        for result in results:
            values.append((result[1],result[0]))
        sql="UPDATE ips SET asnlabel=? WHERE asn=?"
        db.executemany(sql,values)

# -----------------------------------------------------------
def get(db,fields='idhmutzracnysglo',condition='',outfile=''):

    if outfile:
        dest = open(outfile,"w")
        print ("/--------------------------------/ \n\
/     Exporting output file      /\n\
/--------------------------------/")
    if condition: condition="WHERE "+condition

    if fields=='all': fields='idhmutzracnysgl'
    fields_nb=len(fields)

    db.row_factory = lite.Row  # @UndefinedVariable

    with db:
        cur = db.cursor()
        sql=("SELECT logs.*,  ips.* FROM logs LEFT JOIN ips ON ips.IP=logs.IP "
            +condition+" ORDER BY logs.ladate ASC, logs.lheure ASC;")
        lignes=cur.execute(sql)

    if outfile:
        header_line=""
        cpt=0
        for field in fields:
            cpt+=1
            if   field in "i" : header_line+="IP Address"
            elif field in "d" : header_line+="Date"
            elif field in "h" : header_line+="Time"
            elif field in "m" : header_line+="Method"
            elif field in "u" : header_line+="URI"
            elif field in "t" : header_line+="Status code"
            elif field in "z" : header_line+="Size"
            elif field in "r" : header_line+="Referer"
            elif field in "a" : header_line+="Agent"
            elif field in "c" : header_line+="Country code"
            elif field in "n" : header_line+="Country"
            elif field in "y" : header_line+="City"
            elif field in "s" : header_line+="ASN"
            elif field in "g" : header_line+="IP range"
            elif field in "l" : header_line+="Operator name"
            elif field in "o" : header_line+="Anomalies"
            if cpt<fields_nb: header_line+="|"
        dest.write(header_line+"\n")

    for ligne in lignes:
        (isocode,country_name,city_name,asn,range,asnlabel)=(
            "%s" % ligne["isocode"],"%s" % ligne["country_name"],
            "%s" % ligne["city_name"],"%s" % ligne["asn"],"%s" % ligne["range"],
            "%s" % ligne["asnlabel"])

        output_line=""
        cpt=0
        for field in fields:
            cpt+=1
            if   field in "i" : output_line+="%s" % ligne["IP"]
            elif field in "d" : output_line+="%s" % ligne["ladate"]
            elif field in "h" : output_line+="%s" % ligne["lheure"]
            elif field in "m" : output_line+="%s" % ligne["method"]
            elif field in "u" : output_line+="%s" % ligne["uri"]
            elif field in "t" : output_line+="%s" % ligne["status"]
            elif field in "z" : output_line+="%s" % ligne["size"]
            elif field in "r" : output_line+=ligne["referer"]
            elif field in "a" : output_line+=ligne["agent"]
            elif field in "c" : output_line+=isocode
            elif field in "n" : output_line+=country_name
            elif field in "y" : output_line+=city_name
            elif field in "s" : output_line+=asn
            elif field in "g" : output_line+=range
            elif field in "l" : output_line+=asnlabel
            elif field in "o" : 
                # gets rid of - characters around each flag
                anomflags=re.sub(r'^-|-$', '', ligne["anomflags"])
                anomflags=re.sub(r'-,-', ',', anomflags)
                output_line+="%s" % anomflags
            if cpt<fields_nb: output_line+="|"

        output_line=output_line.encode('UTF-8')
        if outfile: dest.write(output_line+"\n")
        else: print output_line

# -----------------------------------------------------------
def make_clause(field,items):
    clause="("
    list=("%s" % items).split(",")
    cpt=0
    for item in list:
        cpt+=1
        if field in ("logs.ladate", "logs.lheure","logs.IP"): 
            clause+="%s LIKE '%s%%'" % (field,item)
        elif field in ("logs.uri","logs.agent","logs.referer","ips.asnlabel"): 
            clause+="%s LIKE '%%%s%%'" % (field,item)
        elif field in ("logs.anomflags"):
            if (item=='all'):
                clause+="%s is not ''" % (field)
            else:
                # adds "-" in front of, and behind item to match items in DB
                item="-{}-".format(item)
                clause+="%s LIKE '%%%s%%'" % (field,item)
        else : 
            clause+="%s ='%s'" % (field,item)
        if cpt < len(list): clause+=" OR "
    clause+=")"
    return(clause)

# -----------------------------------------------------------
def ready():
    print "\nDatabase is now ready for querying..."
    print "Use boolet.py -f ??? to query"
    print "Ex: boolet.py -f dhicl --country FR,ES"
    print "Ex: boolet.py -f oiur --anomaly sqli,dirtrav\n"
    return True

# -----------------------------------------------------------
def main(argv):
    #global db_file
    global log_formats

    chemin,fields,importation,columns,out=('','','','','')
    clauses=[]

    # Banner
    my_banner=Banner(softdesc)
    my_banner.display()

    # arguments and options
    try:
        opts, args = getopt.getopt(argv, \
            "hf:i:o:", \
            ["help","fields=","import=","out=","ip=","date=","time=","method=",
            "uri=","status=","referer=","agent=","asn=","country=","isp=",
            "anomaly="])
    except getopt.GetoptError:
        usage(usage_text)
        sys.exit(2)

    if opts :
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage(usage_text)
                sys.exit()
            elif opt in ("-i", "--import"):
                log_format = "%s" % arg
                if log_formats.has_key(log_format):
                    importation=1
                else:
                    print ("Format type \"{0}\" doesn't exist. BooLET is using combined format instead").format(log_format)
                    log_format = "combined"
                    importation=1
            elif opt in ("-f", "--fields"):
                columns = "%s" % arg
            elif opt in ("-o", "--out"):
                out= "%s" % arg

            elif opt in ("--ip"):
                clauses.append(make_clause('logs.IP',"%s" % arg))
            elif opt in ("--date"):
                clauses.append(make_clause('logs.ladate',"%s" % arg))
            elif opt in ("--time"):
                clauses.append(make_clause('logs.lheure',"%s" % arg))
            elif opt in ("--method"):
                clauses.append(make_clause('logs.method',"%s" % arg))
            elif opt in ("--uri"):
                clauses.append(make_clause('logs.uri',"%s" % arg))
            elif opt in ("--status"):
                clauses.append(make_clause('logs.status',"%s" % arg))
            elif opt in ("--referer"):
                clauses.append(make_clause('logs.referer',"%s" % arg))
            elif opt in ("--agent"):
                clauses.append(make_clause('logs.agent',"%s" % arg))
            elif opt in ("--asn"):
                clauses.append(make_clause('ips.asn',"%s" % arg))
            elif opt in ("--country"):
                clauses.append(make_clause('ips.isocode',"%s" % arg.upper()))
            elif opt in ("--isp"):
                clauses.append(make_clause('ips.asnlabel',"%s" % arg))
            elif opt in ("--anomaly"):
                clauses.append(make_clause('logs.anomflags',"%s" % arg))

            globalclause=" AND ".join(clauses)
    else:
        usage(usage_text)
        sys.exit(2)

    rep_travail=os.path.dirname(chemin)
    if rep_travail=="": rep_travail="."

    DB = lite.connect(rep_travail + "/" + boocfg['files']['db_file'])  

    # importation of data
    if importation:
        create_new_database(DB)
        upload_logs_in_db(DB,rep_travail,log_format,args)
        create_ip_table(DB)
        create_asn_table(DB)
        maj_location_asn(DB)

        title("Summary")
        Anomalies.stats()
        ready()

    # get by columns
    if columns:
        get(DB,fields=columns,outfile=out,condition=globalclause)

if __name__ == "__main__":
    script_path=os.path.dirname(os.path.realpath(__file__))
    with open(script_path+"/src/config.yml", 'r') as ymlfile:
      boocfg=yaml.load(ymlfile)
    main(sys.argv[1:])
