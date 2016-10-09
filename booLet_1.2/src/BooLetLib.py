# !/usr/bin/python
# -*- coding: utf-8 -*-
import re,sys,os
import yara

# -----------------------------------------------------------
usage_text="""IMPORTING RAW LOGS AND CREATING LOG DATABASE     
booLet.py --import %FORMAT_TYPE% logfile_name     

FORMAT TYPES 
  combined : apache combined
  common : apache common
  iponly : list of IP addresses
       
EXTRACTING COLUMNS     
 booLet.py --field idhmutzracnysgl    
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
  o: type of anomaly
       
CONDITIONS AND FILTERS     
 booLet.py --ip 41.123.12.43,132,23,56,131 --agent msie --anomaly sqli,dirtrav    
  --ip @IP    
  --date XXXX-XX-XX    
  --time XX:XX:XX     
  --method     
  --uri     
  --status     
  --referer     
  --agent     
  --asn     
  --country ISO_country_code     
  --isp     
  --anomaly XX     
        all : display all anomalies 
        sqli : SQL injections
        ... : any type of anomaly detected during the scans
       
EXPORTING RESULTS     
 booLet.py --out output.csv
"""

# -----------------------------------------------------------
def usage(usage_text):
    """Usage"""
    print usage_text

# --------------------------------------
def title(title_label):
  """display title"""
  print """
==> {} <=====================""".format(title_label)

# -----------------------------------------------------------
class Banner(object):
    """Banner for the program"""
    def __init__(self, banner_values):
        super(Banner, self).__init__()
        self.banner_values = banner_values

    def display(self):
        print("""
****************************************************** \n\
* {0} {1} ({2}) \n\
* {3}           \n\
* Author : Bruno Valentin (bruno@boolaz.com) \n\
* Updates : {4} \n\
******************************************************""" \
         .format(self.banner_values['name'],self.banner_values['version'],
                 self.banner_values['release'],self.banner_values['purpose'],
                 self.banner_values['link']))

# --------------------------------------
class Anomalies(object):
    """This class deals with anomalies in logs"""
    anomaly_line_nb=0
    anomalies_nb=0
    processed_nb=0
    anomaly_nb_by_type=dict()
    description=dict()

    def __init__(self, log_line):
        """class init"""
        super(Anomalies, self).__init__()

    def display(self):
        """display None"""
        return False

    @staticmethod
    def stats():
        """stats on anomalies"""

        # displays global stats
        print ("Total anomalies in fields : {}/{}"
          .format(Anomalies.anomaly_line_nb,Anomalies.get_nb_processed()))
        print

        # displays values for each child class of Anomaly
        for child_object in [cls for cls in Anomalies.__subclasses__()]:
            child_object.stats_by_field()
        print

        # then displays values for each anomaly identified
        for anomaly,value in Anomalies.anomaly_nb_by_type.items():
            print("{} ({}) : {}".format(Anomalies.description[anomaly], 
                anomaly, value))
        return True

    @classmethod
    def compile_ruleset(cls):
        """compile the rules from the yara files"""
        script_path=os.path.dirname(os.path.realpath(__file__))
        anomalies_file=script_path+"/"+cls.rules_filename
        cls.anomalies_rules = yara.compile(anomalies_file,
          externals= {
          'strval': '', 
          'strlen': 0
          })
        return True

    @classmethod
    def stats_by_field(cls):
        """generates stats for each field"""
        print ("Anomalies in {}: {}/{}"
            .format(cls.field_label,cls.get_nb_anomalies()
              ,cls.get_nb_processed()))

    @classmethod
    def count_anomalies(cls,value):
        """count anomalies in the current sub-class and the parent class"""
        if value==0:
            cls.anomalies_nb=1
            Anomalies.anomalies_nb=1
        else:
            cls.anomalies_nb+=value
            Anomalies.anomalies_nb+=value

    @classmethod
    def get_nb_anomalies(cls):
        """ return nb of anomalies in current class"""
        return "{}".format(cls.anomalies_nb)

    @classmethod
    def get_nb_processed(cls):
        """ return nb of processed lines in current class"""
        return "{}".format(cls.processed_nb)

    def search(self):
        """matches the line against the anomalies ruleset"""
        matches = self.anomalies_rules.match(data=self.log_line,
          externals= {
          'strval': self.log_line, 
          'strlen': len(self.log_line)
          })
        try:
            yaras=dict()
            yaras=matches['main']
        except:
            matching_causes=list()
        else:
            Anomalies.anomaly_line_nb+=1
            self.count_anomalies(1)
            matching_causes=list()
            for yara in yaras:
                matching_causes.append(yara['rule'])
                description=yara['meta']['description']
                if yara['rule'] not in Anomalies.anomaly_nb_by_type:
                    Anomalies.description[yara['rule']]=description
                    Anomalies.anomaly_nb_by_type[yara['rule']]=1
                else:
                    Anomalies.anomaly_nb_by_type[yara['rule']]+=1

        return(matching_causes)

# --------------------------------------
class AnomRef(Anomalies):
    """This class deals with anomalies in referer"""

    # variables which are specific to this subclass
    field_label="referer"
    rules_filename="anomaly_referer.yar"
    anomalies_nb=0
    processed_nb=0

    def __init__(self, log_line):
        """counts processed lines (current + parent)"""
        self.log_line = log_line
        self.__class__.processed_nb+=1
        self.__class__.__base__.processed_nb+=1

# --------------------------------------
class AnomUri(Anomalies):
    """This class deals with anomalies in uri"""

    # variables specific to this subclass
    field_label="uri"
    rules_filename="anomaly_uri.yar"
    anomalies_nb=0
    processed_nb=0

    def __init__(self, log_line):
        """counts processed lines (current + parent)"""
        self.log_line = log_line
        self.__class__.processed_nb+=1
        self.__class__.__base__.processed_nb+=1

# --------------------------------------
class AnomAgt(Anomalies):
    """This class deals with anomalies in Agent field"""

    # variables specific to this subclass
    field_label="agent"
    rules_filename="anomaly_agent.yar"
    anomalies_nb=0
    processed_nb=0

    def __init__(self, log_line):
        """counts processed lines (current + parent)"""
        self.log_line = log_line
        self.__class__.processed_nb+=1
        self.__class__.__base__.processed_nb+=1
