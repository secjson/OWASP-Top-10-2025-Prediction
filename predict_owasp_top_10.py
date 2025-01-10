import re
import os
import networkx as nx
import matplotlib.pyplot as plt

def get_owasp_2021_cwes():
	owasp_2021_mappings = dict()
	owasp_2021_mappings['a01_broken_access_control'] = ['CWE-22','CWE-23','CWE-35','CWE-59','CWE-200','CWE-201','CWE-219','CWE-264','CWE-275','CWE-276','CWE-284','CWE-285','CWE-352','CWE-359','CWE-377','CWE-402','CWE-425','CWE-441','CWE-497','CWE-538','CWE-540','CWE-548','CWE-552','CWE-566','CWE-601','CWE-639','CWE-651','CWE-668','CWE-706','CWE-862','CWE-863','CWE-913','CWE-922','CWE-1275']
	owasp_2021_mappings['a02_cryptographic_failures'] = ['CWE-261','CWE-296','CWE-310','CWE-319','CWE-321','CWE-322','CWE-323','CWE-324','CWE-325','CWE-326','CWE-327','CWE-328','CWE-329','CWE-330','CWE-331','CWE-335','CWE-336','CWE-337','CWE-338','CWE-340','CWE-347','CWE-523','CWE-720','CWE-757','CWE-759','CWE-760','CWE-780','CWE-818','CWE-916']
	owasp_2021_mappings['a03_injection'] = ['CWE-20','CWE-74','CWE-75','CWE-77','CWE-78','CWE-79','CWE-80','CWE-83','CWE-87','CWE-88','CWE-89','CWE-90','CWE-91','CWE-93','CWE-94','CWE-95','CWE-96','CWE-97','CWE-98','CWE-99','CWE-100','CWE-113','CWE-116','CWE-138','CWE-184','CWE-470','CWEE-471','CWE-564','CWE-610','CWE-643','CWE-644','CWE-652','CWE-917']
	owasp_2021_mappings['a04_insecure_design'] = ['CWE-73','CWE-183','CWE-209','CWE-213','CWE-235','CWE-256','CWE-257','CWE-266','CWE-269','CWE-280','CWE-311','CWE-312','CWE-313','CWE-316','CWE-419','CWE-430','CWE-434','CWE-444','CWE-451','CWE-472','CWE-501','CWE-522','CWE-525','CWE-539','CWE-579','CWE-598','CWE-602','CWE-642','CWE-646','CWE-650','CWE-653','CWE-656','CWE-657','CWE-799','CWE-807','CWE-840','CWE-841','CWE-927','CWE-1021','CWE-1173']
	owasp_2021_mappings['a05_security_misconfiguration'] = ['CWE-2','CWE-11','CWE-13','CWE-15','CWE-16','CWE-260','CWE-315','CWE-520','CWE-526','CWE-537','CWE-541','CWE-547','CWE-611','CWE-614','CWE-756','CWE-776','CWE-942','CWE-1004','CWE-1032','CWE-1174']
	owasp_2021_mappings['a06_vulnerable_and_outdated_components'] = ['CWE-937','CWE-1035','CWE-1104']
	owasp_2021_mappings['a07_identification_and_authentication_failures'] = ['CWE-255','CWE-259','CWE-287','CWE-288','CWE-290','CWE-294','CWE-295','CWE-297','CWE-300','CWE-302','CWE-304','CWE-306','CWE-307','CWE-346','CWE-384','CWE-521','CWE-613','CWE-620','CWE-640','CWE-798','CWE-940','CWE-1216']
	owasp_2021_mappings['a08_software_and_data_integrity_failures'] = ['CWE-345','CWE-353','CWE-426','CWE-494','CWE-502','CWE-565','CWE-784','CWE-829','CWE-830','CWE-915']
	owasp_2021_mappings['a09_security_logging_and_monitoring_failures'] = ['CWE-117','CWE-223','CWE-532','CWE-778']
	owasp_2021_mappings['a10_ssrf'] = ['CWE-918']

	return owasp_2021_mappings

def regex_cwe(file_path):
	#cwe_pattern = r"\"cweId\":.*\"(CWE-.*)\""
	cwe_pattern = r"CWE-\d*"
	base_score_pattern = r"\"baseScore\":.?(.*),"
	base_score = None

	with open(file_path,'r') as f:
		text = f.read()

		cwe_match = re.findall(cwe_pattern,text)
		baseScore_match = re.findall(base_score_pattern,text)

		for i in range(0,len(baseScore_match)):
			baseScore_match[i] = baseScore_match[i].replace('"',"").replace("'","")

		print(baseScore_match)

		try:
			if baseScore_match:
				base_score = round(sum([float(i) for i in baseScore_match])/len(baseScore_match),2)
		except:
			base_score = None

		if cwe_match:
			return cwe_match,base_score

	return None,None

def cwe_gatherer(directory):
	cwes_dict = dict()
	owasp_2021_mappings = get_owasp_2021_cwes()
	#cwe_with_base_score = dict()
	#Read all files recursively
	for root, dirs, files in os.walk(directory):
		for file in files:
			file_path = os.path.join(root, file)
            
			print(file_path)

			cwes,base_score = regex_cwe(file_path)
			if cwes:
				for cwe in cwes:
					if cwe not in cwes_dict.keys():
						cwes_dict[cwe]=dict()
						cwes_dict[cwe]['count']=1
						if base_score:
							cwes_dict[cwe]['baseScoreTotal']=base_score
							cwes_dict[cwe]['baseScoreCount']=1
						else:
							print(f"Base Score not found for {file_path}")
							cwes_dict[cwe]['baseScoreTotal']=0
							cwes_dict[cwe]['baseScoreCount']=0

						for entry in owasp_2021_mappings.keys():
							if cwe in owasp_2021_mappings[entry]:
								cwes_dict[cwe]['OWASP 2021 Mapping']=entry
					else:
						cwes_dict[cwe]['count']+=1
						if base_score:
							cwes_dict[cwe]['baseScoreTotal']+=base_score
							cwes_dict[cwe]['baseScoreCount']+=1
						else:
							print(f"Base Score not found for {file_path}")

	# Calculate base score averages
	for entry in cwes_dict.keys():
		if cwes_dict[entry]['baseScoreCount'] != 0:
			cwes_dict[entry]['baseScoreAverage'] = round(cwes_dict[entry]['baseScoreTotal']/cwes_dict[entry]['baseScoreCount'],2)
		else:
			cwes_dict[entry]['baseScoreAverage'] = 0

	return cwes_dict#, cwe_with_base_score

def data_analysis(cwes_dict):
	sorted_list = sorted(cwes_dict.keys(), key=lambda x: (cwes_dict[x]['count'], cwes_dict[x]['baseScoreAverage']), reverse=True)
	print(sorted_list)

	for i in range(0,50):
		print(f"{sorted_list[i]} - {cwes_dict[sorted_list[i]]}")

	# Graph CVE count based on OWASP Top 10 2021 Category
	owasp_category_count=dict()
	for cwe in cwes_dict.keys():
		if 'OWASP 2021 Mapping' in cwes_dict[cwe].keys():
			mapping=cwes_dict[cwe]['OWASP 2021 Mapping']

			if mapping not in owasp_category_count.keys():
				owasp_category_count[mapping]=cwes_dict[cwe]['count']
			else:
				owasp_category_count[mapping]+=cwes_dict[cwe]['count']

	print(owasp_category_count)

	owasp_categories=[]
	category_count=[]

	for category in owasp_category_count.keys():
		owasp_categories.append(category)
		category_count.append(owasp_category_count[category])

	plt.bar(owasp_categories, category_count)
	plt.xlabel('OWASP Top 10 2021 Categories')
	plt.ylabel('Count')
	plt.title('2021-2024 OWASP Top 10 2021 CVE Category Counts')
	plt.xticks(rotation=45,ha='right')
	plt.tight_layout()
	plt.show()




def main():
	#read_files_recursively('./cvelist/2024')
	#cwe_match,base_score = regex_cwe('./cvelist/2024/13xxx/CVE-2024-13111.json')
	#print(cwe_match)
	#print(base_score)
	#regex_cwe('./cvelist/2024/0xxx/CVE-2024-0949.json')

	cwes_dict = cwe_gatherer('./cvelist')
	print(cwes_dict)

	data_analysis(cwes_dict)

	
	#count=0
	#for cwe in twenty_four_cwes.keys():
	#	count+=twenty_four_cwes[cwe]

	#print(count)

main()