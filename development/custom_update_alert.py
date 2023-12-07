import os
import requests
import tomllib
import sys


url = os.environ['ELASTIC_URL']
api_key = os.environ['ELASTIC_TOKEN']
headers = {
	'Content-Type': 'application/json;charset=UTF-8',
	'kbn-xsrf': 'true',
	'Authorization': "ApiKey " + api_key
}

def update_rule(file, path):
	file = file
	full_path = path

	data=""

	data = "{\n"
	if file.endswith('.toml'):
		with open(full_path,'rb') as toml:
			alert = tomllib.load(toml)	

			if alert['rule']['type'] == 'query': # query based alert
				required_fields = ['author', 'description','name','rule_id','risk_score','severity','type','query', 'threat']
			elif alert['rule']['type'] == 'eql': # event correlation alert
				required_fields = ['author', 'description','name','rule_id','risk_score','severity','type','query', 'language', 'threat']
			elif alert['rule']['type'] == 'threshold': # threshold based alert
				required_fields = ['author', 'description','name','rule_id','risk_score','severity','type','query', 'threshold', 'threat']
			else:
				print('Invalid rule type:', alert['rule']['type'], 'in ', full_path)

			for field in alert['rule']:
				if field in required_fields:
					if type(alert['rule'][field]) == list:
						data += '  ' + '"' + field + '"' + ':' + str(alert['rule'][field]).replace("'",'"') + ',\n'
					elif type(alert['rule'][field]) == str:
						if field == 'description':
								data += '  ' + '"' + field + '"' + ':' + '"' + str(alert['rule'][field]).replace('\n', ' ').replace('"','\\\"').replace('\\','\\\\') + '",\n'
						elif field == 'query':
								data += '  ' + '"' + field + '"' + ':' + '"' + str(alert['rule'][field]).replace('\n', ' ').replace('"','\\\"').replace("'","\'") + '",\n'
						else:
							data += '  ' + '"' + field + '"' + ':' + '"' + str(alert['rule'][field]).replace('\n', ' ').replace('"','\\\"') + '",\n'
					elif type(alert['rule'][field]) == int:
						data += '  ' + '"' + field + '"' + ':' + str(alert['rule'][field]) + ',\n'
					elif type(alert['rule'][field]) == dict:
						data += '  ' + '"' + field + '"' + ':' + str(alert['rule'][field]).replace("'",'"') + ',\n'
			data += ' "enabled": true\n}'		
			
	full_url = ''
	rule_id = alert['rule']['rule_id']
	full_url = url + '?ruleid=' + rule_id

	elastic_data = requests.put(url, headers=headers, data=data).json()
	# print(elastic_data)


	try:
		if elastic_data['status_code'] == 404:
				elastic_data = requests.post(url, headers=headers, data=data).json()
				print(elastic_data)
	except:
			print(elastic_data['name'], 'has been uploaded!\n')