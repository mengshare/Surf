#!/usr/bin/env python
#coding=utf-8

import json
import sys
import re
import os
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
def convert(file):
	dict = {}
	i = 0 
	for line in file:
		i = i+ 1
		if re.match('#', line):
			continue
		if re.match('//', line):
			continue
		if len(line) <=2:
			continue
		
		if re.match('\[General\]', line):
			dict = General
			continue
		elif re.match('\[Hosts\]', line):
			dict = Hosts
			continue
		elif re.match('\[Proxy\]', line):
			dict = Proxy
			continue
		elif re.match('\[Rule\]', line):
			dict = Rule
			continue
		else :
			 pass
		list  = line.split('=')
		if len(list) >1:
			x = list[1].split(',')
			if  len(x)> 1:
				if dict ==  Proxy:
					hostconfig = {}
					hostconfig['protocol'] =  x[0].strip()
					hostconfig['host'] =  x[1].strip()
					hostconfig['port'] =  x[2].strip()
					hostconfig['method'] =  x[3].strip()
					hostconfig['passwd'] =  x[4].strip()
					#hostconfig['xx'] =  x[5]
					dict[list[0].strip()] = hostconfig
				else:
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
	General["author"] = "surfing"
	General["commnet"] = "this is comment"
	Rule["DOMAIN-KEYWORD"] = DOMAINKEYWORD
	Rule["DOMAIN-SUFFIX"] = DOMAINSUFFIX
	Rule["IP-CIDR"] = IPCIDR
	Rule["USER-AGENT"] = Agent
	Rule["GEOIP"] = GEOIP

	config["Hosts"] = Hosts
	config["Rule"] = Rule
	config["Proxy"] = Proxy
	config["General"] = General
	
	
	
	#saveRuslt()
def saveRuslt(name):
	s = json.dumps(config)
	f = open(name,"w")
	f.write(s)
	f.close()
if __name__ == '__main__':
	if len(sys.argv) == 1:
		exit()
	surgeconfig = sys.argv[1]
	#paths = os.path.split(surgeconfig)
	fname = os.path.basename(surgeconfig)
	name = fname.split('.')[0]
	dest = os.path.dirname(surgeconfig) + name + '.json'
	file = open(surgeconfig)
	convert(file)
	saveRuslt(dest)
	file.close() 
