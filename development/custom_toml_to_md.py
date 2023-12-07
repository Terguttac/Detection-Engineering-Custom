import tomllib
import os
import datetime
from dateutil.relativedelta import relativedelta

list = {}

today = datetime.date.today()
current_month = str(today).split("-")[0] + "-" + str(today).split("-")[1]
one_month_ago = str(today - relativedelta(months=1)).split("-")[0] + "-" + str(today - relativedelta(months=1)).split("-")[1]
two_months_ago = str(today - relativedelta(months=2)).split("-")[0] + "-" + str(today - relativedelta(months=2)).split("-")[1]

current = {}
one_month = {}
two_months = {}

GH_URL = os.environ['GH_URL']

def write_table_headers():
    outF.write("| Alert | Date | Author | Risk Score | Severity | Tactic | MITRE Links |\n")
    outF.write("| --- | --- | --- | :---: | --- | --- | --- |\n")

def write_table(month):
    for line in month.values():
        date = line['date']
        name = line['name']
        author = ', '.join(line['author'])
        risk_score = str(line['risk_score'])
        severity = line['severity']

        tactic = ''
        tech = ''
        techs = []
        subtech = ''
        tech_links = []
        subtech_links = []
        for technique in line['mitre']:
            tactic = technique['tactic']
            tech = technique['technique']
            if technique['subtech'] == "none":
                del technique['subtech']
            else:
                subtech = technique['subtech'].replace('.','/')
                subtech_links.append("["+subtech.replace('/','.')+"]"+"("+"https://attack.mitre.org/techniques/"+subtech+")")
            tech_links.append("["+tech+"]"+"("+"https://attack.mitre.org/techniques/"+tech+")")

        alert_link = "["+line['name']+"]"+"("+GH_URL+line['file']+")"

        if len(subtech_links) == 0:
            subtech_links = ''
        outF.write("|" + alert_link + "|" + date + "|" + author + "|" + risk_score  + "|" + severity + "|" + tactic + "|" + ' '.join(tech_links) + " " + ' '.join(subtech_links) + "|\n")



for root, dirs, files in os.walk("detections/validated/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                date = alert['metadata']['creation_date']
                name = alert['rule']['name']
                author = (alert['rule']['author'])
                risk_score = alert['rule']['risk_score']
                severity = alert['rule']['severity']
                filtered_object_array = []

                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for threat in alert['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']

                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else:
                            tactic = "none"

                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"

                        technique = technique_id
                        subtech = subtechnique_id
                        alert_file = full_path
                        
                        obj = {'tactic': tactic, 'technique': technique, 'subtech': subtech, 'subtech': subtech}
                        filtered_object_array.append(obj)
                obj = {'name': name, 'date': date, 'author': author, 'risk_score': risk_score, 'severity': severity, 'mitre': filtered_object_array, 'file': alert_file}
                
                year = date.split("/")[0]
                month = date.split("/")[1]
                date_compare = year + "-" + month
                
                if date_compare == current_month:
                    current[file] = obj
                elif date_compare == one_month_ago:
                    one_month[file] = obj
                elif date_compare == two_months_ago:
                    two_months[file] = obj

                list[file] = obj

temp_readme = ''

with open('./README.md', 'r') as readme:
    for line in readme:
        if line != "# Recently Created Detections\n":
            temp_readme += line
        else:
            break

output_path = './README.md'
outF = open(output_path, "w")

outF.write(temp_readme)

outF.write("# Recently Created Detections\n")

outF.write("## This Month\n")
write_table_headers()
write_table(current)

outF.write("## Last Month\n")
write_table_headers()
write_table(one_month)

outF.write("## Two Months Ago\n")
write_table_headers()
write_table(two_months)

outF.close()
