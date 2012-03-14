#!/usr/bin/python
#serkan.capkan
"""
USAGE: /opt/scripts/accessLog_activeIps.py [ (access log file) | LAST  ] 
	LAST			:	determine last access log file and process file
	[access log file]	:	process file
NOTE:
	- log file location	:	/storage/nswl/2012/03/14/20120314-08.log
	- log format		:	2012-11-14.10:11:32 100.100.100.100 GET www.abc.com 200 - [Back:172.20.7.51] [0sec.] [9500micros.] [byteRcvd:1055] [byteSent:237] / Agent:Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)	
"""


depth=30
log_file_path="/storage/nswl/"


import sys
import subprocess
import datetime 
from array import array
from operator import itemgetter


if not len(sys.argv) > 1:
	print __doc__
	sys.exit(1)


#determine file
if sys.argv[1] == "LAST":
        now = datetime.datetime.now()
        year=now.strftime('%Y')
        month=now.strftime('%m')
        day=now.strftime('%d')
        hour=now.strftime('%H')         
        file = log_file_path+year+"/"+month+"/"+day+"/"+year+month+day+"-"+hour+".log"
else:
        file=sys.argv[1]


print "\n -> processing for file: ", file,"\n"
try:
	file=open(file,"r")
except IOError:
	print "error while opennig file"
	print __doc__
	sys.exit(1)


#get only ips
ip_list=[]
for line in file:
	splited_line=line.split()
	ip_list.append(splited_line[1])


#uniq
uniq_ip_list=set(ip_list)
uniq_ip_list=list(uniq_ip_list)


#count
ip_list_counted=[]
ip_list_counted_all=[]
for ip in uniq_ip_list:
	ip_list_counted=(ip,ip_list.count(ip))
	ip_list_counted_all.append(ip_list_counted)

#sort via count
ip_list_counted_all.sort(key=itemgetter(1), reverse = True)


count=0
for ip_count in ip_list_counted_all:
	# check it has a record at whois.db
	who=""
	subprocess.call(["touch","/tmp/whois.db"])
	whoisdb_file=open("/tmp/whois.db","r")
	for line in whoisdb_file:
        	if ip_count[0] in line:
			line=line.rstrip('\n')
                	who=line.split("^")
			who=" "+who[1]	
			break

	 # if new get whois name		
	if who == "":
		who_text=subprocess.Popen(["/usr/bin/whois",ip_count[0]], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		for who_line in who_text.stdout:
			if ("netname" in who_line or "descr" in who_line or "OrgName" in who_line or "Network-Name" in who_line):
				#if there are no "space", split with ":"
				if not ( ' ' in who_line ):
                                        who_line=who_line.rstrip('\n')
                                        who_line=who_line.split(":")
                                        if ( len(who_line) == 3 ):
                                                who=who+who_line[2]+" "
                                        elif ( len(who_line) == 2) :
                                                who=who+who_line[1]+" "
                                        else:   
                                                who=who+who_line[0]+" "				
				else:
					who_line=who_line.split()
					who=who+who_line[1]+" "
		# add new records to internal whoisdb
		whoisdb_file=open("/tmp/whois.db","a")
		whoisdb_file.write(ip_count[0]+"^"+who+"\n")




	#break if depth is ok		
	if count == depth:
		break
	else:
		count = count + 1


        #print results
        print "%s\t%s\t\t%s" % ( ip_count[1],ip_count[0],who )



print "\n -> finished\n\n"



