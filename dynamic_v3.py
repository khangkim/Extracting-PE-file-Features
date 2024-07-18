import requests
import json
import re
import os
import csv
import sys
import argparse
import ast
import threading
import array
import time

HEADERS = {"Authorization": "Bearer BHjsFvgfjQN7hiYXnVJjEg"}
list_paths = []

def send(): 
    task_ids = []
    for path in list_paths:
        REST_URL = "http://localhost:8888/tasks/create/file"
        file_name = os.path.basename(path)
        
        with open(path, "rb") as sample:
            files = {"file": (file_name, sample)}
            data = {
                "timeout": 120 
            }
            
            r = requests.post(REST_URL, headers=HEADERS, files=files, data=data)
            if r.status_code == 200:
                task_ids.append(r.json()["task_id"])

    return task_ids
	
def get_tasks():
	REST_URL = "http://localhost:8888/tasks/list"
	r = requests.get(REST_URL, headers=HEADERS)
	data = r.json()
	return data['tasks']
		
def get_report(id):
	REST_URL = "http://localhost:8888/tasks/report/" + id
	r = requests.get(REST_URL, headers=HEADERS,stream = True)
	if r.status_code == 200:
		report=""
		for chunk in r.iter_content(chunk_size=1024*1024):
			if chunk:
				report += chunk
		report = json.loads(report)
		return report
	else: 
		return None

def delete_task(id):
	REST_URL = "http://localhost:8888/tasks/delete/" + id
	r = requests.get(REST_URL, headers=HEADERS) 


def get_api_calls(report):
	
    api_calls = []
    if 'behavior' in report and 'processes' in report['behavior']:
        processes = report['behavior']['processes']
		# Danh sach cac cuoc goi api va ma trang thai cua no [(api1,status1),(api2,status2),...]
        for process in processes:
            if 'calls' in process:
                for call in process['calls']:
                    api_calls.append((call['api'],call['status']))
	# Dic cac cuoc goi api va so lan thanh cong, that bai {api: {'success':x, fail:x}}
    api_counts = {}
    for api, result in api_calls:
        if api not in api_counts:
            api_counts[api] = {'success': 0, 'fail': 0}
        if result == 1:
            api_counts[api]['success'] += 1
        else:
            api_counts[api]['fail'] += 1
	
	# Chuoi cac cuoc goi api "api1 success1 fail1, api2 success2 fail2,..."
    api_string = ''
    for api,count in api_counts.items():
        api_string += "{} {} {},".format(api, count['success'], count['fail'])
						
    return api_string
	
def get_registry_actions(report,name):
	regkey_opened = []
	regkey_read = []
	regkey_written = []
	regkey_deleted = []
	if 'behavior' in report and 'summary' in report['behavior']:
		summary = report['behavior']['summary']
		if 'regkey_opened' in summary:
			regkey_opened = summary['regkey_opened']
		if 'regkey_read' in summary:
			regkey_read = summary['regkey_read']
		if 'regkey_written' in summary:
			regkey_written = summary['regkey_written']
		if 'regkey_deleted' in summary:
			regkey_deleted = summary['regkey_deleted']
		regkey = [name,len(regkey_opened), len(regkey_read), len(regkey_written), len(regkey_deleted)]
		return regkey
	else:
		return [name,0,0,0,0]
			

def get_file_actions(report,name):
	file_opened = []
	file_read = []
	if 'behavior' in report and 'summary' in report['behavior']:
		summary = report['behavior']['summary']				
		if 'file_opened' in summary:
			file_opened = summary['file_opened']
		if 'file_read' in summary:
			file_read = summary['file_read']

		files = [name,len(file_opened), len(file_read)]
		return files	
	else: 
		return[name,0,0]
		
def get_dns_requests(report):
    
    requests = ""
    if 'network' in report and 'dns' in report['network']:
        dns = report['network']['dns']		
        for request in dns:
            requests += "{},".format(request['request'])

    return requests
	
def get_urls(report):
    
    if 'network' in report and 'http' in report['network']:
        http = report['network']['http']
        urls = ""	
        for url in http:
            urls += "{},".format(url['uri'])
	
    return urls

def extract():
    tasks = get_tasks()
    while len(tasks) > 0:
        tasks = get_tasks()
        print("tasks: " + str(len(tasks)))
        for t in tasks:
            if t['status'] == 'reported':
                id = t['id']
                name = os.path.basename(t['target'])
                print(name + ": " + t['status'])
                report = get_report(str(id))
                if report: 	
                    apis = [name,get_api_calls(report)]
                    with open(path1, 'a') as file: 
                        writer = csv.writer(file)
                        writer.writerow(apis)

                    registry = get_registry_actions(report,name)
                    with open(path2, 'a') as file: 
                        writer = csv.writer(file)
                        writer.writerow(registry)
                    
                    files = get_file_actions(report,name)
                    with open(path3, 'a') as file: 
                        writer = csv.writer(file)
                        writer.writerow(files)
                    
                    dns = [name,get_dns_requests(report)]
                    with open(path4, 'a') as file: 
                        writer = csv.writer(file)
                        writer.writerow(dns)
                    
                    urls = [name,get_urls(report)]
                    with open(path5, 'a') as file: 
                        writer = csv.writer(file)
                        writer.writerow(urls)
                        
                delete_task(str(id))
        time.sleep(10)

	

if __name__ == '__main__':
	
    parser = argparse.ArgumentParser(description='You need add some argument')
    parser.add_argument('-s', type=str, required=False, help='The dataset folder path')
    parser.add_argument('-d', type=str, required=False, help='The dataset folder path')
   
    args = parser.parse_args()
    source_path = args.s

    path1 ="./apis.csv"
    path2 ="./registry.csv"
    path3 ="./files.csv"
    path4 ="./dns.csv"
    path5 ="./urls.csv"

    if source_path:
        for item in os.listdir(source_path):
            item_path = os.path.join(source_path, item)
            if os.path.isfile(item_path):
                if item.endswith(".exe") | item.endswith(".EXE") :
                    list_paths.append(item_path)
					
        api_feature =["name","api success fail"]
        registry_feature =["name","regkey_opened", "regkey_read", "regkey_written", "regkey_deleted"]
        file_feature = ["name","file_opened", "file_read" ]
        dns_feature = ["name","dns"]
        url_feature = ["name","url"]
        with open(path1, 'wb') as file: 
            writer = csv.writer(file)
            writer.writerow(api_feature)
        with open(path2, 'wb') as file: 
            writer = csv.writer(file)
            writer.writerow(registry_feature)   
        with open(path3, 'wb') as file: 
            writer = csv.writer(file)
            writer.writerow(file_feature)
        with open(path4, 'wb') as file: 
            writer = csv.writer(file)
            writer.writerow(dns_feature)
        with open(path5, 'wb') as file: 
            writer = csv.writer(file)
            writer.writerow(url_feature)
        
        send()
		
    extract()

	
	
	
	
























