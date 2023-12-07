import tomllib
import sys
import os
import shutil
import requests
import custom_update_alert
import custom_mitre

failure = 0
file = sys.argv[1]
full_path = sys.argv[2]
event = sys.argv[3]
getBKUP = True
try:
	GH_URL = os.environ['GH_URL']
except:
	pass

if file.startswith('BKUP_') != True:
	with open(full_path,'rb') as toml:
		alert = tomllib.load(toml)	

		if alert['rule']['type'] == 'query': # query based alert
			required_fields = ['description','name','rule_id','risk_score','severity','type','query']
		elif alert['rule']['type'] == 'eql': # event correlation alert
			required_fields = ['description','name','rule_id','risk_score','severity','type','query', 'language']
		elif alert['rule']['type'] == 'threshold': # threshold based alert
			required_fields = ['description','name','rule_id','risk_score','severity','type','query', 'threshold']
		else:
			print('Invalid rule type:', alert['rule']['type'], 'in ', full_path)

		present_fields = []
		missing_fields = []
 
		try:
			if alert['metadata']['creation_date']:
				pass
		except:
			missing_fields.append('creation_date')
		
		for field in alert['rule']:
			present_fields.append(field)

		for field in required_fields:
			if field not in present_fields:
				missing_fields.append(field)

		if missing_fields:
			print("The following fields do not exist in", file + ":", str(missing_fields))
			if "/validated/" in full_path:
				shutil.move('./detections/validated/'+file, './detections/failed/'+file)
				if getBKUP:
					response = requests.get(GH_URL+file)
					with open('./detections/validated/BKUP_'+file, mode='wb') as oldfile:
						oldfile.write(response.content)
			failure = 1
		elif custom_mitre.checkMitreID(file, full_path):
			failure = 1
		else:
			print(file, '- passed the validation check')
			if '/failed/' in full_path:
				shutil.move('./detections/failed/'+file, './detections/validated/'+file)
				os.remove('./detections/validated/BKUP_'+file)
			else:
				custom_update_alert.update_rule(file, full_path)
else: 
	failure = 1

			


if failure != 0:
	sys.exit(1)