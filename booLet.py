#!/usr/bin/python
# -*- coding: utf-8 -*-
# ----------------------------------------------------
# Name 		: BooLET.py
# Purpose	: HTTP Log Examination and filtering Tool
# Revision	: 1.0 (24/07/2016)
# Author 	: Bruno Valentin - bruno@brunovalentin.com
# Updates	: https://github.com/boolaz/BooLet     
# Reference : http://www.brunovalentin.com/dev/
# ----------------------------------------------------

import os,sys,re,getopt
from sys import argv
from datetime import datetime
import geoip2.database
import sqlite3 as lite
import pyasn

reload(sys)
sys.setdefaultencoding("utf-8")

# -----------------------------------------------------------
version="1.0"
release_date="24/07/2016"

script_path=os.path.dirname(os.path.realpath(__file__))
db_file='apachelogs.db'

log_formats = {
	'common':'([^ ]+) [^ ]+ [^ ]+ \[([^:]+):([^ ]+) (.*?)\] "([^ ]+) ?([^ ]*) ?([^ ]*)" (\d+) ([\d\-]+)(.*?)(.*?)', 
	'combined':'^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] \" *(\S+) ?(.*?) ?(\S+)?\" (\S+) (\S+) "([^"]*)" "([^"]*)"',
	'iponly':'([^ ]+)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)(.*?)' 
}
excluded_uri = '.*(\.(ico|jpg|png|js|css|gif|woff|svg)(\?|&)?|robots\.txt)'

excluded_agents = '.*((bingbot|OrangeBot|Googlebot|DotBot|Exabot|Baiduspider|MJ12bot|YandexBot|SMTBot|Googlebot\-Mobile|Applebot|AhrefsBot|Cliqzbot|msnbot\-media|Twitterbot)/|baidu\.com|ia_archiver|ysearch/slurp|internal dummy connection).*'

banner = (" \n\
****************************************************** \n\
* BooLET {0} ({1}) - brvltn@gmail.com         * \n\
* Boolaz Log Extamination Tool (HTTP log processing) * \n\
* Updates : https://github.com/boolaz/BooLet         * \n\
******************************************************".format(version,release_date))

usage_str = (" \n\
IMPORTING RAW LOGS AND CREATING LOG DATABASE \n\
 booLet.py --import combined nom_fichiers_log \n\
 available formats : combined, common, iponly \n\
   \n\
EXTRACTING COLUMNS \n\
 booLet.py --field idhmutzracnysgl\n\
  i: ip \n\
  d: date \n\
  h: time \n\
  m: method \n\
  u: url \n\
  t: http status code \n\
  z: size \n\
  r: referer \n\
  a: agent \n\
  c: country code \n\
  n: country name \n\
  y: city \n\
  s: asn \n\
  g: asn range \n\
  l: asn label \n\
   \n\
CONDITIONS AND FILTERS \n\
 booLet.py --ip 41.123.12.43,132,23,56,131 --agent msie  \n\
  --ip @IP\n\
  --date XXXX/XX/XX\n\
  --time XX:XX:XX \n\
  --method \n\
  --uri \n\
  --status \n\
  --referer \n\
  --agent \n\
  --asn \n\
  --country ISO_country_code \n\
  --isp \n\
   \n\
EXPORTING RESULTS \n\
 booLet.py --out output.csv \n")

# -----------------------------------------------------------
def usage():
	global banner,usage_str
	print banner
	print usage_str

# -----------------------------------------------------------
def create_new_database(db):  # creation d'une base vide
	with db:
		db.execute("DROP TABLE IF EXISTS logs") 
		db.execute("CREATE TABLE logs(IP TEXT, ladate TEXT,lheure TEXT, method TEXT,uri TEXT, status INT, \
			size INT, referer TEXT, agent TEXT)")
		db.execute("CREATE INDEX _IP_LOGS ON logs(IP ASC)")
		db.execute("CREATE INDEX _ladate_LOGS ON logs(ladate ASC)")
		db.execute("CREATE INDEX _lheure_LOGS ON logs(lheure ASC)")
		db.execute("CREATE INDEX _method_LOGS ON logs(method ASC)")
		db.execute("CREATE INDEX _uri_LOGS ON logs(uri ASC)")
		db.execute("CREATE INDEX _status_LOGS ON logs(status ASC)")

# -----------------------------------------------------------
def format_line(line,log_format):

	global log_formats

	regex=log_formats[log_format]
	try:
		logip,logdate,logtime,logtz,logmethod,loguri,logversion,logstatus,logsize,referer,logagent=re.match(regex, line).groups()
	except:
		print u"The following line raises an exception : \n{0}".format(line)
		#print re.match(regex, line).groups()
		sys.exit(2)
	return(logip,logdate,logtime,logtz,logmethod,loguri,logversion,logstatus,logsize,referer,logagent)

# -----------------------------------------------------------
def upload_logs_in_db(db,outdir,log_format,fichiers):
	
	global excluded_uri,excluded_agents
	# global log_formats
	db.row_factory = lite.Row  # @UndefinedVariable

	print (" \n\
/-----------------------------------/ \n\
/  Storing HTTP logs into database  / \n\
/-----------------------------------/")

	resume_file = open(outdir + '/' + 'summary.csv',"w")
	resume_line=u"{0}|{1}|{2}|{3}|{4}".format("file","Start","End","number of lines","nb of unique IP")
	print resume_line
	resume_file.write("SUMMARY\n")
	resume_file.write(resume_line+"\n")

	# analyse de chaque fichier
	detail_fichiers=[]
	for fichier in fichiers:
		
		fd = open(fichier,"r")
		lignes_total= 0
		for line in fd:
			lignes_total+= 1
			
		nb_lines=0
		ip=[]
		les_lignes=[]
		infile = open(fichier,"r")
		for line in infile:
			nb_lines+=1
			# print u"{0} : {1}/{2}".format(fichier,nb_lines,lignes_total)
			logip,logdate,logtime,logtz,logmethod,loguri,logversion,logstatus,logsize,referer,logagent=format_line(line,log_format)

			if nb_lines==1: debut=u"{0} {1}".format(logdate,logtime)
			fin=u"{0} {1}".format(logdate,logtime)
			if logdate:
				logdate = u"{0}".format(datetime.strptime(logdate, "%d/%b/%Y"))
				date_stamp = logdate[0:logdate.find(' ')]
			else:
				date_stamp=''

			if logip not in ip: ip.append(logip)

			if not re.match(excluded_uri, "{0!s}".format(loguri), flags=re.I) and not re.match(excluded_agents, "{0!s}".format(logagent)) :
				les_lignes.append((logip,date_stamp,logtime,logmethod,loguri,logstatus,logsize, referer, logagent))

		with db:	
			cur = db.cursor()
			sql="INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?);"
			db.executemany(sql,les_lignes)

		detail_fichiers.append((os.path.basename(fichier),debut,fin,nb_lines,len(ip)))
		resume_line=u"{0!s}|{1!s}|{2!s}|{3!s}|{4!s}".format(os.path.basename(fichier),debut,fin,nb_lines,len(ip))
		print resume_line
		resume_file.write(resume_line+"\n")
		infile.closed

	resume_file.closed
	print


# -----------------------------------------------------------
def create_ip_table(db):

	print ("/--------------------------------/ \n\
/        Generating IP table     / \n\
/--------------------------------/")

	ip_list=[]

	with db:	
		cur = db.cursor()

		db.execute("DROP TABLE IF EXISTS ips") 
		db.execute("CREATE TABLE ips(IP TEXT, isocode TEXT, country_name TEXT, city_name TEXT, asn INT, range TEXT, asnlabel TEXT)")
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

	print ("/----------------------------------/ \n\
/      	Generating ASN table       / \n\
/----------------------------------/")

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

	print ("/----------------------------------/ \n\
/   Updating geoip and ASN infos   / \n\
/----------------------------------/")

	reader = geoip2.database.Reader(script_path+'/booLet_extres/GeoLite2-City.mmdb')
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
			pass

		if response.country.names:
			if "fr" in response.country.names: country_name=response.country.names['fr']
			if response.country.names<>'' : country_name=response.country.name


		if response.city.name: 
			if response.city.name<>'':
				city_name=response.city.name
			else: city_name='-'

		if response.country.iso_code in ['','None'] : iso_code='-'
		else: iso_code="{0!s}".format(response.country.iso_code)


		asn,range=asn_db.lookup(mon_ip[0])
		if ("{0!s}".format(asn)).lower()=='none': asn=range='-'
		else: asn="AS{0!s}".format(asn)

		les_lignes.append((iso_code,country_name,city_name,asn,range,mon_ip[0]))

	with db:	
		cur = db.cursor()
		sql="UPDATE ips SET isocode=?, country_name=?, city_name=?, asn=?, range=? WHERE IP=?"
		db.executemany(sql,les_lignes)

		sql="SELECT DISTINCT(i.asn),a.asnlabel FROM ips i, asns a WHERE i.asn = a.asn;"
		results=cur.execute(sql)
		values=[]
		for result in results:
			values.append((result[1],result[0]))
		sql="UPDATE ips SET asnlabel=? WHERE asn=?"
		db.executemany(sql,values)


# -----------------------------------------------------------
def get(db,fields='idhmutzracnysgl',condition='',outfile=''):

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
		sql="SELECT logs.*,  ips.* FROM logs LEFT JOIN ips ON ips.IP=logs.IP "+condition+" ORDER BY logs.ladate ASC, logs.lheure ASC;"
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
			if cpt<fields_nb: header_line+="|"
		dest.write(header_line+"\n")

	for ligne in lignes:
		(isocode,country_name,city_name,asn,range,asnlabel)=("%s" % ligne["isocode"],"%s" % ligne["country_name"],"%s" % ligne["city_name"],"%s" % ligne["asn"],"%s" % ligne["range"],"%s" % ligne["asnlabel"])

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
			if cpt<fields_nb: output_line+="|"

		output_line=output_line.encode('UTF-8')
		if outfile: dest.write(output_line+"\n")
		else: print output_line

def make_clause(field,items):
	clause="(" 
	list=("%s" % items).split(",")
	cpt=0
	for item in list:
		cpt+=1
		if field in ("logs.ladate", "logs.lheure","logs.IP"): clause+="%s LIKE '%s%%'" % (field,item)
		elif field in ("logs.uri","logs.agent","logs.referer","ips.asnlabel"): clause+="%s LIKE '%%%s%%'" % (field,item)
		else : clause+="%s ='%s'" % (field,item)
		if cpt < len(list): clause+=" OR "
	clause+=")"
	return(clause)

# -----------------------------------------------------------
def main(argv): 

	global db_file
	global log_formats

	chemin,fields,importation,columns,out=('','','','','')
	clauses=[]

	# détection des arguments
	try:                                
		opts, args = getopt.getopt(argv, \
	        "hf:i:o:", \
	        ["help","fields=","import=","out=","ip=","date=","time=","method=","uri=","status=","referer=","agent=","asn=","country=","isp="])
	except getopt.GetoptError:          
		usage()                         
		sys.exit(2)   

	if opts :
		for opt, arg in opts:                
			if opt in ("-h", "--help"):      
				usage()                     
				sys.exit()
			elif opt in ("-i", "--import"):             
				log_format = "%s" % arg
				if log_formats.has_key(log_format): 
					importation=1
				else:
					print "Format type \"{0}\" doesn't exist. BooLET is using combined format instead".format(log_format)   
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
		
			globalclause=" AND ".join(clauses)
	else:
		usage()                         
		sys.exit(2)  

	#os.system('clear')

	rep_travail=os.path.dirname(chemin)
	if rep_travail=="": rep_travail="."

	DB = lite.connect(rep_travail + "/" + db_file)   # @UndefinedVariable

	if importation:
		print banner
		create_new_database(DB)
		upload_logs_in_db(DB,rep_travail,log_format,args)
		create_ip_table(DB)
		create_asn_table(DB)
		maj_location_asn(DB)
		print "\nDatabase is now ready for querying...\n"

	if columns:
		get(DB,fields=columns,outfile=out,condition=globalclause)

if __name__ == "__main__":
	main(sys.argv[1:])