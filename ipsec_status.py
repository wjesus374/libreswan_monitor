#!/usr/bin/python
# -*- encoding: utf-8 -*-

#sudo pip install ipsecparse
from ipsecparse import loads
import re
import subprocess
from subprocess import Popen, PIPE, STDOUT
import os

####
#ipsec_status, err = subprocess.Popen(['ipsec', 'status'], stdout=subprocess.PIPE).communicate()
ipsec_status, err = subprocess.Popen(['cat', 'ipsec.status'], stdout=subprocess.PIPE).communicate()

####
#Apontar o arquivo de configuração do ipsec
ipsec_conf_file = 'cliente.conf'



sline = '========================================================================================================================================'
ssline = '----------------------------------------------------------------------------------------------------------------------------------------'

config = loads(open(ipsec_conf_file).read())

#Main dict
data = {}
#ipsec global dict
globaldict = {}
globaldict['total'] = []

sline = '========================================================================================================================================'
ssline = '----------------------------------------------------------------------------------------------------------------------------------------'
print(sline)
print('\t\t\t\t\tLibreSwan Status v.1.1 - by. wjesus')


for info in config:
	name = info[1]
	print(sline)
	print('Nome: [%s]' %name)

	for linfo in config[info]:
		if 'leftid' in linfo:
			#print('Chave: [%s]' %linfo)
			#print('Valor: [%s]' %config[info][linfo])
			leftid = config[info][linfo]
			print('Local: [%s]' %leftid)
		if re.search('right$',linfo):
			rightid = config[info][linfo]
			print('Publico: [%s]' %rightid)

	#Definir o set com o nome das conexões
	conn_names = {}
	conn_names = set()

	for linha in ipsec_status.splitlines():

		if name in linha:
			conn = re.search('"('+name+'.*)"',linha)
			cname = conn.group(1)
			#Adicionar nome da conexão no set
			conn_names.add(cname)

		total = re.search('Total IPsec connections..(.*)',linha)
		if total:
			#print(sline)
			#print(total.group(1))
			#print(sline)
			globaldict['total'].append({'Conexoes':total.group(1)})

	#Mostrar configurações globais
	#Visual only
	print(sline)

	for globalconf in globaldict:
		for info in globaldict[globalconf]:
			print('%s' %(info))

	#Visual only
	print(sline)

	#Loop em todos nomes das conexões
	for cname in conn_names:
		#Criar entrada com nome da conexao
		data[cname] = []
		#Se encontrar o nome da conexão na linha
		for linha in ipsec_status.splitlines():
			if cname in linha:
				#Verificar se está estabelecida
				if re.search('IPsec SA established',linha):
					lifetime = re.search('EVENT_SA_REPLACE in (.*)s;',linha)
					if lifetime:
						#data[cname].append({'status': 'Established'})
						#Compatibilidade com strongswan status
						data[cname].append({'status': 'INSTALLED'})
						data[cname].append({'lifetime': lifetime.group(1)})
						data[cname].append({'remote': rightid})
						data[cname].append({'local': leftid})
		
					lifetime = re.search('EVENT_SA_EXPIRE in (.*)s;',linha)
		
					if lifetime:
						data[cname].append({'status': 'Expire'})
						data[cname].append({'lifetime': lifetime.group(1)})
						data[cname].append({'remote': rightid})
						data[cname].append({'local': leftid})

				#Verificar o criador da conexão
				ownerid =  re.search('eroute owner: (.*)$',linha)
	
				if ownerid:
					#Guardar o ownerid
					data[cname].append({'ownerid': ownerid.group(1)})
					#Guardar a linha da conexão
					###192.168.1.1/32===192.168.2.1<192.168.2.1>[8.8.8.8]...8.8.4.4<8.8.4.4>===192.168.15.1/24; erouted
					conn_line = re.search(':.(.*\;)',linha)
					data[cname].append({'conn_line': conn_line.group(1)})
					#print(conn_line.group(1))
					#print(ownerid.group(1))

	for lname in data:
		name = lname
		for info in data[lname]:
			if 'status' in info:
				lstatus = info['status']
			if 'lifetime' in info:
				lifetime = info['lifetime']
			if 'remote' in info:
				lremote = info['remote']
			if 'local' in info:
				llocal = info['local']
			if 'conn_line' in info:
				conn_line = info['conn_line']
				if 'unrouted' in conn_line:
					lstatus = 'unrouted'
					subnet = ''
					subnet2 = ''
				elif 'erouted' in conn_line:
			                subnet = re.search('^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*===',conn_line)
					subnet = subnet.group(1)

					subnet2 = re.search('>===([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*$',conn_line)
					subnet2 = subnet2.group(1)

			if 'ownerid' in info:
					ownerid = info['ownerid']
		if not 'unrouted' in lstatus:
			print("[%s] | Name: [%s] | State: [%s] | Lifetime: [%s]\t| Remote: [%s] \t| Local: [%s]" %(ownerid,lname,lstatus,lifetime,subnet,subnet2))
		#print("[%s] | Name: [%s] | State: [%s] | Lifetime: [%s]\t| Remote: [%s]| Local: [%s] | Subnet: [%s] \t| Subnet2: [%s]" %(ownerid,lname,lstatus,lifetime,lremote,llocal,subnet,subnet2))
	#Visual only
	print(sline)
