#!/usr/bin/python

Ture = True

import json
import sys


try:
	import requests
except ImportError:
	print 'Please install the python-requests module.'
	sys.exit(-1)

# Disable warnings (TODO: suppress only certificate warnings)
requests.packages.urllib3.disable_warnings()

#
# Specify URL and credentials before use
#
URL = 'https://sat6.example.com'
USERNAME = 'admin'
PASSWORD = 'redhat'
# Set this to 'True' to get the output nicely formatted on multiple lines.
# Set it to 'False' to get each host on one line.
MULTIPLE_LINES = Ture
#
# Specify URL and credentials before use
#

# URL for the API to your deployed Satellite 6 server
SAT_API = '%s/katello/api/v2/' % URL
# Katello-specific API
KATELLO_API = '%s/katello/api/' % URL
POST_HEADERS = {'content-type': 'application/json'}
# Ignore SSL for now
SSL_VERIFY = False

def get_json(location):
	"""
	Performs a GET using the passed URL location
	"""

	r = requests.get(location, auth=(USERNAME, PASSWORD), verify=SSL_VERIFY)

	return r.json()


def post_json(location, json_data):
	"""
	Performs a POST and passes the data to the URL location
	"""

	result = requests.post(
		location,
		data=json_data,
		auth=(USERNAME, PASSWORD),
		verify=SSL_VERIFY,
		headers=POST_HEADERS)

	return result.json()

def one_liners():

	print 'This script connects to the API of a Satellite 6 server and prints information about the Content Hosts on that Satellite. The output contains the following infromation (one line per host):'
	print 'ORGANIZATION   LOCATION   NAME   ID   ACTIVATION KEYS   LIFECYCLE ENVIRONMENT   CONTENT VIEW   DISTRIBUTION   VIRTUAL/PHYSICAL KATELLO-AGENT INSTALLED   STATUS   LAST REPORT   ENTITLEMENT STATUS   ERRATA COUNT: TOTAL(SECURITY, BUGFIX, ENHANCEMENT)   ARCHITECTURE   CPU(S)   TOTAL MEMORY   IPv4 ADDRESS'
	hosts = get_json(SAT_API + 'systems/')
        for host in hosts['results']:
                
		facts = get_json(SAT_API + 'systems/' + host['id'] + '?fields=full')
                
		output = ''
                output += facts['environment']['organization']['name'] + '\t'
                output += facts['location'] + '\t'
                output += facts['name'] + '\t'
                output += facts['id'] + '\t'
                
		for ak in facts['activation_keys']:
                        output += ak['name'] + ' '
                
		output += '\t'
                output += facts['environment']['name'] + '\t'
                output += facts['content_view']['name'] + '\t'
                output += facts['distribution'] + '\t'
                output += facts['type'] + '\t'

		if facts['katello_agent_installed']:
                        output += 'True \t'
                else:
                        output += 'False \t'
                
		output += facts['host']['status'] + '\t'
                output += facts['host']['last_report'] + '\t'
                output += facts['entitlementStatus'] + '\t'
                
		errata_total = str(facts['errata_counts']['total'])
		errata_security = str(facts['errata_counts']['security'])
		errata_bugfix = str(facts['errata_counts']['bugfix'])
		errata_enhancement = str(facts['errata_counts']['enhancement'])
		output += errata_total + '(' + errata_security + ', ' + errata_bugfix + ', ' + errata_enhancement + ') \t'
		
		output += facts['facts']['lscpu.architecture'] + '\t'
		output += facts['facts']['cpu.cpu(s)'] + '\t'
                output += facts['facts']['dmi.memory.size'] + '\t'
		output += facts['facts']['network.ipv4_address'] + '\t'

		#output += facts[''] + '\t'

                print output
	

def multiple_lines():
	
	print 'This script connects to the API of a Satellite 6 server and prints information about the Content Hosts on that Satellite.'
	hosts = get_json(SAT_API + 'systems/')
        for host in hosts['results']:

                facts = get_json(SAT_API + 'systems/' + host['id'] + '?fields=full')
		
		print facts['name']
                print '\t Organization: \t\t' + facts['environment']['organization']['name']
                print '\t Location: \t\t' + facts['location']
                print '\t ID: \t\t\t' + facts['id']
		
		#print '\t : \t' + 
                
		output = '\t Activation keys: \t'
		for ak in facts['activation_keys']:
                        output += ak['name'] + ' '
		print output
                
                print '\t Environment: \t\t' + facts['environment']['name'] + '\t'
                print '\t Content View: \t\t' +facts['content_view']['name'] + '\t'
                print '\t Distribution: \t\t' +facts['distribution'] + '\t'
                print '\t Virtual/Physical: \t' +facts['type'] + '\t'

                if facts['katello_agent_installed']:
                        print '\t Katello-Agent: \tInstalled'
                else:
                        print '\t Katello-Agent: \tNot installed'

                print '\t Status: \t\t' + facts['host']['status'] + '\t'
                print '\t Last report: \t\t' + facts['host']['last_report'] + '\t'
                print '\t Subscription: \t\t' + facts['entitlementStatus'] + '\t'

                print '\t Errata total: \t\t' + str(facts['errata_counts']['total'])
                print '\t\t Security: \t' + str(facts['errata_counts']['security'])
                print '\t\t Bugfixes: \t' + str(facts['errata_counts']['bugfix'])
                print '\t\t Enhancements: \t' + str(facts['errata_counts']['enhancement'])

                print '\t Architecture: \t\t' + facts['facts']['lscpu.architecture'] + '\t'
                print '\t CPU(s): \t\t' + facts['facts']['cpu.cpu(s)'] + '\t'
                print '\t Memory: \t\t' + facts['facts']['dmi.memory.size'] + '\t'
                print '\t IPv4 address: \t\t' + facts['facts']['network.ipv4_address'] + '\t'

                #output += facts[''] + '\t'

                print ''


if MULTIPLE_LINES:
	multiple_lines()
else:
	one_liners()
