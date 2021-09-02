import os
from flask import Flask, request
import requests
import json
import time
import validators

app = Flask(__name__)
app.config["DEBUG"] = True
url_scan_api_key = os.getenv('URLSCAN_API_KEY')
virus_total_api_key = os.getenv('VIRUS_TOTAL_API_KEY')


def validate_ip_domain_decorator(func):
    def wrapper(req_type, data):
        if(req_type == 'ip'):            
            ip_parts = data.split('.')
            for num in ip_parts:
                if(int(num) > 255 or int(num) < 0):
                    return "Invalid IP address format"
        else:
            if not validators.domain(data):
                return "Invalid domain name format"

        return func(req_type, data)
    return wrapper



@validate_ip_domain_decorator
def get_union_of_both_scan_results(req_type, data):
    url_scan_result = url_scan_main(req_type, data)
    virus_total_result = virus_total_main(req_type, data)
    final_result = dict()

    final_result["urlscan"] = url_scan_result["urlscan"]
    final_result["urlscan_status_code"] = url_scan_result["status_code"]

    final_result["virustotal"] = virus_total_result["virustotal"]
    final_result["virustotal_status_code"] = virus_total_result["status_code"]    

    if url_scan_result["malicious"] == None:
        final_result["malicious"] = virus_total_result["malicious"]
        return final_result

    if virus_total_result["malicious"] == None:
        final_result["malicious"] = url_scan_result["malicious"]
        return final_result

    final_result["malicious"] = url_scan_result["malicious"] and virus_total_result["malicious"]
    
    return final_result


@app.route("/ip/<string:ip_value>", methods=['GET'])
@app.route("/domain/<string:domain_name>", methods=['GET'])
def scan_url_by_path(ip_value=None, domain_name=None):
    req_type = ""
    data = ""
    if(ip_value):
        req_type = "ip"
        data = ip_value
    else:
        req_type = "domain"
        data = domain_name
    return get_union_of_both_scan_results(req_type, data)


@app.route("/", methods=['GET'])
def scan_url_by_params():
    req_type = request.args.get('type')
    data = request.args.get('data')
    if req_type == None or data == None:
        return "Invalid params"
    return get_union_of_both_scan_results(req_type, data)

@app.route("/", methods=['POST'])
def scan_url_by_json():
    req_type = request.json['type']
    data = request.json['data']
    if req_type == None or data == None:
        return "Invalid JSON"
    return get_union_of_both_scan_results(req_type, data)

def url_scan_main(req_type, data_to_scan):
    result_dict = dict()
    
    headers = {'API-Key' : url_scan_api_key, 'Content-Type' : 'application/json'}
    data = {"url" : data_to_scan, "visibility" : "public"}
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
        response.raise_for_status()
    except requests.HTTPError as exception:
            return {"urlscan" : "Unknown error occured", "malicious" : None, "status_code" : response.status_code}

    uuid = response.json()['uuid']

    flag = True
    # print("before while loop")
    retries = 21
    result_api_response = None

    while(retries > 0):
        retries -= 1
        # print(retries)

        try:
            result_api_response = requests.get('https://urlscan.io/api/v1/result/' + uuid + '/')
            result_api_response.raise_for_status()

            if(result_api_response.status_code == 200):
                # print(result_api_response.status_code)
                break
        except requests.HTTPError as exception:
            # print(exception)
            if(result_api_response.status_code == 404):
                if flag:
                  time.sleep(30)
                  flag = False
                else:                    
                    # print('https://urlscan.io/api/v1/result/' + uuid + '/')
                    # print(result_api_response.status_code)
                    time.sleep(5)
            else:
                return {"urlscan" : "Unknown error occured", "malicious" : None, "status_code" : result_api_response.status_code}

    response_dict = result_api_response.json()
    # print(response_dict)

    if 'verdicts' not in response_dict:
        result_dict = {"urlscan" : "Couldn't fetch response in 130s", "malicious" : None}
    else:
        is_malicious = response_dict['verdicts']['overall']['malicious']
        result_dict = {"urlscan" : response_dict, "malicious" : is_malicious}
    
    result_dict["status_code"] = result_api_response.status_code
    
    return result_dict


def virus_total_main(req_type, data_to_scan):
    result_dict = dict()

    if req_type == 'ip':
        params = {'apikey' : virus_total_api_key, 'ip' : data_to_scan}
        try:
            result_api_response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=params)
            result_api_response.raise_for_status()
        except requests.HTTPError as exception:
            result_dict = {"virustotal" : "Unknown error occured", "malicious" : None, "status_code" : result_api_response.status_code}            
            return result_dict

        response_dict = result_api_response.json()
        result_dict = {"virustotal" : response_dict, "malicious" : None}
    else:
        params = {'apikey' : virus_total_api_key,'domain' : data_to_scan}
        try:
            result_api_response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params)
            result_api_response.raise_for_status()
        except requests.HTTPError as exception:
            result_dict = {"virustotal" : "Unknown error occured", "malicious" : None, "status_code" : result_api_response.status_code}
            return result_dict

        response_dict = result_api_response.json()
        # return response_dict

        if "Webutation domain info" not in response_dict:
            result_dict = {"virustotal" : "Couldn't fetch the response", "malicious" : None}
        else:            
            safety_status = response_dict["Webutation domain info"]["Verdict"]
            is_malicious = False if (safety_status == "safe") else True
            result_dict = {"virustotal" : response_dict, "malicious" : is_malicious}

    result_dict["status_code"] = result_api_response.status_code

    return result_dict


if __name__ == "__main__":
    app.run()