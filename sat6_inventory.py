#!/usr/bin/python

import json
import sys


try:
	import requests
except ImportError:
	print "Please install the python-requests module."
	sys.exit(-1)

# Disable warnings (TODO: suppress only certificate warnings)
requests.packages.urllib3.disable_warnings()

#
# Specify URL and credentials before use
#
URL = "https://sat6.example.com"
USERNAME = "admin"
PASSWORD = "redhat"
#
# Specify URL and credentials before use
#

# URL for the API to your deployed Satellite 6 server
SAT_API = "%s/katello/api/v2/" % URL
# Katello-specific API
KATELLO_API = "%s/katello/api/" % URL
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

def main():
	"""
	Get all systems and then extract information from them
	"""
	
	print 'ORGANIZATION \t LOCATION \t NAME \t ID \t ACTIVATION KEYS \t LIFECYCLE ENVIRONMENT \t CONTENT VIEW \t DISTRIBUTION \t KATELLO-AGENT INSTALLED \t STATUS \t ENTITLEMENT'
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
                
		if facts['katello_agent_installed']:
                        output += 'True \t'
                else:
                        output += 'False \t'
                
		output += facts['host']['status'] + '\t'
                # output += facts['host']['last_report'] + '\t'
                output += facts['entitlementStatus'] + '\t'
                # output += facts['type'] + '\t'
                # TODO: Errata and facts
                #output += facts[''] + '\t'
                print output
	

if __name__ == "__main__":
	main()
