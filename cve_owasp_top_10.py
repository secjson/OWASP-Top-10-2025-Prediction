import requests
import json


#if 'problemTypes' in cve_json.keys():
#	print('here')
#	for problemType in cve_json['problemTypes']:
#		if 'descriptions' in problemType.keys():
#			for description in problemType['descriptions']:
#				if 'cweId' in description.keys():
#					print(description['cweId'])

#print(cve_json['containers']['cna']['problemTypes'][0]['descriptions'])

count = '1'
not_found = 0
cwe_dict = dict()

while(True):

	if not_found > 50:
		break

	if len(count) < 4:
		count = f"{'0'*(4-len(count))}{count}"

	r = requests.get(f'https://cveawg.mitre.org/api/cve/CVE-2024-{count}')

	if r.status_code == '404':
		not_found+=1
	else:
		not_found=0


	cve_json = r.json()
	cwe = None

	try:
		for problemType in cve_json['containers']['cna']['problemTypes']:
			if "descriptions" in problemType.keys():
				for description in problemType['descriptions']:
					if 'cweId' in description.keys():
						cwe = description['cweId']
						print(f"CVE-2024-{count} - {cwe}")
						if cwe not in cwe_dict.keys():
							cwe_dict[cwe] = 0
						else:
							cwe_dict[cwe]+=1

		for entry in cve_json['containers']['adp']:
			if 'problemTypes' in entry.keys():
				for problemType in entry['problemTypes']:
					if "descriptions" in problemType.keys():
						for description in problemType['descriptions']:
							if 'cweId' in description.keys():
								cwe = description['cweId']
								print(f"CVE-2024-{count} - {cwe}")
								if cwe not in cwe_dict.keys():
									cwe_dict[cwe] = 0
								else:
									cwe_dict[cwe]+=1
	except:
		print('rip')

	count = str(int(count)+1)

print(cwe_dict)
f = open('2024_cwe_stats','w')
f.write(json.dumps(cwe_dict)
f.close()