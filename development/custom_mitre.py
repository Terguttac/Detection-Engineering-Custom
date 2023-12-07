import requests
import os
import tomllib
import sys

url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers = {
	'accept': 'application/json'
}

mitreData = requests.get(url, headers=headers).json()
mitreMapped = {}
# failure = 0

for object in mitreData['objects']:
	tactics = []
	if object['type'] == 'attack-pattern':
		if 'external_references' in object:
			for reference in object['external_references']:
				if 'external_id' in reference:
					if reference['external_id'].startswith("T"):
						if 'kill_chain_phases' in object:
							for tactic in object['kill_chain_phases']:
								tactics.append(tactic['phase_name'])
						technique = reference['external_id']
						name = object['name']
						url = reference['url']

						if 'x_mitre_deprecated' in object:
							deprecated = object['x_mitre_deprecated']
							filtered_object = {'tactics': tactics, 'technique':technique, 'name':name, 'url':url, 'deprecated':deprecated}
							mitreMapped[technique] = filtered_object
						else:
							filtered_object = {'tactics': tactics, 'technique':technique, 'name':name, 'url':url, 'deprecated':'False'}
							mitreMapped[technique] = filtered_object

def checkMitreID(file, full_path):
	alert_data = {}
	file = file
	full_path = full_path
	failure = False
# for root, dirs, files in os.walk('detections/'):
	# for file in files:
	if file.endswith('.toml'):
		# full_path = os.path.join(root, file)
		with open(full_path,'rb') as toml:
			alert = tomllib.load(toml)	
			filtered_object_array = []
			if alert['rule']['threat'][0]['framework'] == 'MITRE ATT&CK':
				for threat in alert['rule']['threat']:
					technique_id = threat['technique'][0]['id']
					technique_name = threat['technique'][0]['name']

					if 'tactic' in threat:
						tactic = threat['tactic']['name']
					else:
						tactic = 'none'


					if 'subtechnique' in threat['technique'][0]:
						subtechnique = threat['technique'][0]['subtechnique'][0]
						subtechnique_id = subtechnique['id']
						subtechnique_name = subtechnique['name']
					else:
						subtechnique_id	= 'none'
						subtechnique_name = 'none'

					filtered_object = {'tactic': tactic, 'technique_id':technique_id, 'technique_name':technique_name, 'subtechnique_id':subtechnique_id, 'subtechnique_name':subtechnique_name}
					filtered_object_array.append(filtered_object)
					alert_data[file] = filtered_object_array

	mitre_tactic_list = ['none', 'reconnaissance', 'resource development', 'initial access', 'execution', 'persistence', 'privilege escalation', 'defense evation', 'credential access', 'discovery', 'lateral movement', 'collection', 'command and control', 'exfiltration', 'impact']

	for file in alert_data:
		for line in alert_data[file]:
			tactic = line['tactic'].lower()
			technique_id = line['technique_id']
			subtechnique_id = line['subtechnique_id']

			#Check to ensure MITRE Tactics exist
			if tactic not in mitre_tactic_list:
				print("The MITRE Tactic supplied does not exist. \nTactic:", tactic, "\nFile:", file,'\n\n')
				failure = 1
			
			#Check to make sure the Mitre TID is valid
			try:
				if mitreMapped[technique_id]:
					pass
			except KeyError:
				print('Invalid MITRE Technique ID. \nTechnique ID:', technique_id, '\nFile:',file,'\n\n')
				failure = 1
			
			#Check to see if MITRE TID + Name combination is valid
			try:
				mitre_name = mitreMapped[technique_id]['name']
				alert_name = line['technique_name']
				if alert_name != mitre_name:
					print('MITRE Technique ID and Name mismatch. \nFile:', file, '\nExpected: ', mitre_name.upper(), 'but given', alert_name.upper(),'\n\n')
					failure = 1
			except KeyError:
				pass
			
			#Check if subTID + Name entry is valid
			try:
				if subtechnique_id != 'none':
					mitre_name = mitreMapped[subtechnique_id]['name']
					alert_name = line['subtechnique_name']
					if alert_name != mitre_name:
						print('MITRE Sub-Technique ID and Name mismatch. \nFile:', file, '\nExpected: ', mitre_name.upper(), 'but given', alert_name.upper(),'\n\n')
						failure = 1
			except KeyError:
				pass
			
			#Check to see if technique is deprecated
			try:
				if mitreMapped[technique_id]['deprecated'] == True:
					print('Deprecated MITRE Technique ID.', '\nTechnique ID:',technique_id, '\nFile:',file)
					failure = 1
			except KeyError:
				pass

	if failure != 0:
		return True
		# sys.exit(1)
