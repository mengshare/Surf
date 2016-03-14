#!/usr/bin/env python
#coding=utf-8

import json
import sys
import re
import os
import urllib
config = {}
General = {}
Proxy = {}
Rule = {}
DOMAINKEYWORD = {}
DOMAINSUFFIX = {}
IPCIDR = {}
Hosts = {}
Agent = {}
GEOIP = {}
urls = {"abclite普通版":"http://abclite.cn/abclite.conf",
"abclite去广告版":"http://abclite.cn/abclite_ADB.conf",
"逗比极客全能版":"https://o2kpvanmz.qnssl.com/rules_public.conf",
"逗比极客精简版":"https://o2kpvanmz.qnssl.com/rules_public_s.conf",
"surge":"http://surge.one/surge.conf",
"surge_main":"http://surge.pm/main.conf"}
hosx = """iosapps.itunes.apple.com = 175.43.124.244
streamingaudio.itunes.apple.com = 175.43.124.244
aod.itunes.apple.com = 175.43.124.244
radio.itunes.apple.com = 184.87.100.246
radio-services.itunes.apple.com = 184.87.100.246
radio-activity.itunes.apple.com = 184.87.100.246
search.itunes.apple.com = 184.87.97.50
play.itunes.apple.com = 118.123.106.105
upp.itunes.apple.com = 118.123.106.105
client-api.itunes.apple.com = 118.123.106.105"""

for h in  hosx.split("\n"):
	r = h.split("=")
	Hosts[r[0].strip()] = r[1].strip()
print Hosts
def convert(file):
	dict = {}
	i = 0 
	for line in file:
		i = i+ 1
		print ++i
		if re.match('#', line):
			print "# and pass"
			continue
		if re.match('//', line):
			print "// and pass"
			continue
		if len(line) <=2:
			print "no need" + line
			continue
		
		if re.match('\[General\]', line):
			print "Found General"
			dict = General
			continue
		elif re.match('\[Hosts\]', line): 
			print "Found Hosts"
			dict = Hosts
			continue
		elif re.match('\[Host\]', line): 
			print "Found Hosts"
			dict = Hosts
			continue
		elif re.match('\[Proxy\]', line):
			print "Found Proxy"
			dict = Proxy
			continue
		elif re.match('\[Rule\]', line):
			dict = Rule
			print "Found Proxy"
			continue
		else :
			 #print "Not found block this is rule" + 
			 pass
		#print line
		list  = line.split('=')
		if len(list) >1:
			print list
			x = list[1].split(',')
			if  len(x)> 1:
				if dict ==  Proxy:
					hostconfig = {}
					hostconfig['protocol'] =  x[0].strip()
					hostconfig['host'] =  x[1].strip()
					hostconfig['port'] =  x[2].strip()
					if len(x) >= 4:
						hostconfig['method'] =  x[3].strip()
					if len(x) >= 5:
						hostconfig['passwd'] =  x[4].strip()
					#hostconfig['xx'] =  x[5]
					dict[list[0].strip()] = hostconfig
				else:
					print line
					dict[list[0].strip()] =  [str(j).strip() for j in x]
			else:
				dict[list[0].strip()] = str(list[1]).strip()
			
		else:
			if re.match('DOMAIN-KEYWORD',line):
				k  = line.split(',')
				#k.remove(k[0])
				#r = ', '.join([str(x) for x in k]) 
				rule = {}
				rule["Proxy"] = k[2].strip()
				if len(k) > 3:
					rule["force-remote-dns"] = k[3].strip()
				# try:
				# 	rule["force-remote-dns"] = k[3].strip()
				# except Exception, e:
				# 	print e
				
				DOMAINKEYWORD[k[1].strip()] = rule 
			elif re.match('DOMAIN-SUFFIX',line):
				k  = line.split(',')
				#k.remove(k[0])
				#r = ', '.join([str(x) for x in k]) 
				rule = {}
				rule["Proxy"] = k[2].strip()
				if len(k) > 3:
					rule["force-remote-dns"] = k[3].strip()
				# try:
				# 	rule["force-remote-dns"] = k[3].strip()
				# except Exception, e:
				# 	print e
				
				DOMAINSUFFIX[k[1].strip()] = rule
			elif re.match('DOMAIN',line):
				k  = line.split(',')
				#k.remove(k[0])
				#r = ', '.join([str(x) for x in k]) 
				rule = {}
				rule["Proxy"] = k[2].strip()
				if len(k) > 3:
					rule["force-remote-dns"] = k[3].strip()
				# try:
				# 	rule["force-remote-dns"] = k[3].strip()
				# except Exception, e:
				# 	print e
				
				DOMAINSUFFIX[k[1].strip()] = rule
			elif re.match('IP-CIDR',line):
				k  = line.split(',')
				#k.remove(k[0])
				#r = ', '.join([str(x) for x in k]) 
				rule = {}
				rule["Proxy"] = k[2].strip()
				if len(k) > 3:
					rule["no-resolve"] = k[3].strip()
				# try:
				# 	rule["no-resolve"] = k[3].strip()
				# except Exception, e:
				# 	print e
				
				IPCIDR[k[1].strip()] = rule
			elif re.match('USER-AGENT',line):
				k  = line.split(',')
				#k.remove(k[0])
				#r = ', '.join([str(x) for x in k]) 
				rule = {}
				rule["Proxy"] = k[2].strip()				
				Agent[k[1].strip()] = rule
			elif re.match('GEOIP',line):
				k  = line.split(',')
				#k.remove(k[0])
				#r = ', '.join([str(x) for x in k]) 
				rule = {}
				rule["Proxy"] = k[2].strip()				
				GEOIP[k[1]] = rule
			elif re.match('FINAL',line):
				k  = line.split(',')
				#k.remove(k[0])
				#r = ', '.join([str(x) for x in k]) 
				#rule = {}
				#rule["Proxy"] = k[2].strip()				
				#GEOIP[k[1]] = rule
				Rule["FINAL"] = k[1].strip()
			else:
				#this section shoud Hosts
				k  = line.split(' ')
				if len(k) > 1:
					ip = k[0]
					for index in range(1,len(k)):
						host = k[index]
						Hosts[host] = ip.strip()
				else:
					print "host format error"	
	#print dict
	print "[General]"
	print General
	General["author"] = "surfing"
	General["commnet"] = "this is comment"
	print "[Proxy]"
	print Proxy
	print "[Rule]"
	Rule["DOMAIN-KEYWORD"] = DOMAINKEYWORD
	Rule["DOMAIN-SUFFIX"] = DOMAINSUFFIX
	Rule["IP-CIDR"] = IPCIDR
	Rule["USER-AGENT"] = Agent
	Rule["GEOIP"] = GEOIP
	#print Rule
	print "cool"

	config["Hosts"] = Hosts
	config["Rule"] = Rule
	config["Proxy"] = Proxy
	config["General"] = General
	
	
	
	#saveRuslt()
	# print "[DOMAINKEYWORD]"
	# print DOMAINKEYWORD
	# print "[DOMAINSUFFIX]"
	# print DOMAINSUFFIX
	# print "[IPCIDR]"
	# print IPCIDR
def saveRuslt(name):
	#print config
	s = json.dumps(config)
	f = open(name,"w")
	f.write(s)
	f.close()
def process(surgeconfig,name):
	dir = os.getcwd()
	#surgeconfig = sys.argv[1]
	print surgeconfig
	#paths = os.path.split(surgeconfig)
	#fname = os.path.basename(surgeconfig)
	#name = fname.split('.')[0]
	#dest = os.path.dirname(surgeconfig) + name + '.json'
	dest = dir + "/json/" + name + '.json'
	file = open(surgeconfig)
	convert(file)
	saveRuslt(dest)
	file.close() 
	print "abc"
def download():
	#dir = pwd
	for key in urls:
		u =  urls[key]#url.split("/")[-1]
		fn = "download/" + key + ".conf"#//u.split("/")[-1]
		print "downloading    " + u + " to "  + fn
 		#urllib.urlretrieve (u, fn)
 		#print hosx.split("\n")
 		#exit()

 		webFile = urllib.urlopen(u)
 		localFile = open(fn, 'w')
 		localFile.write(webFile.read())
 		#localFile.write(hosx)
 		webFile.close()
 		localFile.close()
 		fp = os.getcwd() + "/" + fn
 		print "process " + fp
 		process(fp,key)

if __name__ == '__main__':
	download()
	exit()
	if len(sys.argv) == 1:
		print "add surge config file path"
		exit()
	
