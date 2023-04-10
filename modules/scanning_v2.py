import json
import logging
import time


import requests

batch_limit = 100
class Scanning_v2:
    def __init__(self, token, endpoint_url, fetch_pipeline_data):
        self.token = token
        self.endpoint_url = endpoint_url
        self.fetch_pipeline_data = fetch_pipeline_data

    def scanning_v2_prom_exporter(self):
        try:
            if self.fetch_pipeline_data == "yes":
                images_pipeline = query_scanning_v2_pipeline_images_batch(self.endpoint_url, self.token)
            else:
                images_pipeline = []
            images_runtime = query_scanning_v2_runtime_images_batch(self.endpoint_url, self.token)

            print("# of images in Pipeline (Scanning v2) - " + str(len(images_pipeline)))
            print("# of images in Runtime (Scanning v2) - " + str(len(images_runtime)))

            images_scanning_v2 = images_pipeline + images_runtime

            images_runtime_exploit_hasfix_inuse = query_scanning_v2_image_details(images_runtime, self.endpoint_url, self.token)

        except:
            raise

        return images_scanning_v2, images_runtime_exploit_hasfix_inuse

def query_scanning_v2_pipeline_images_batch(secure_url, secure_api_token):
    image_data_list, next_cursor = query_scanning_v2_pipeline_images("", secure_url, secure_api_token)
    try:
        while next_cursor is not None:
            image_data_list_temp, next_cursor = query_scanning_v2_pipeline_images(next_cursor, secure_url, secure_api_token)
            image_data_list = image_data_list + image_data_list_temp
            print("Total pipeline images fetched - " + str(len(image_data_list)))
    except:
        raise

    return image_data_list


def query_scanning_v2_pipeline_images(next_cursor, secure_url, secure_api_token):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/scanning/scanresults/v2/results' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + \
          '&sortBy=scanDate&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    image_data_list = []
    image_data_dict = {}

    if response.status_code == 200:

        all_pipeline_images = json.loads(response.text)
        all_images_res = all_pipeline_images["data"]
        next_cursor = all_pipeline_images["page"]["next"]

        for x in all_images_res:
            image_data_dict["imageId"] = x["imageId"]
            image_data_dict["policyStatus"] = x['policyEvaluationsResult'][:4]

            if x["vulnsBySev"] != None:
                image_data_dict["critical"] = x["vulnsBySev"][2]
                image_data_dict["high"] = x["vulnsBySev"][3]
                image_data_dict["medium"] = x["vulnsBySev"][5]
                image_data_dict["low"] = x["vulnsBySev"][6]
                image_data_dict["negligible"] = x["vulnsBySev"][7]
            else:
                image_data_dict["critical"] = 0
                image_data_dict["high"] = 0
                image_data_dict["medium"] = 0
                image_data_dict["low"] = 0
                image_data_dict["negligible"] = 0

            image_data_dict["imagePullString"] = x["imagePullString"]
            imagePull_list = x["imagePullString"].split("/")
            if len(imagePull_list) > 1:
                image_data_dict["repo"] = imagePull_list.pop(0)
                image_data_dict["image_name"] = imagePull_list.pop()
                image_data_dict["reg"] = "/".join(imagePull_list)
            else:
                image_data_dict["repo"] = ""
                image_data_dict["image_name"] = x["imagePullString"]
                image_data_dict["reg"] = ""
            image_data_dict["asset_type"] = ""
            image_data_dict["cluster_name"] = ""
            image_data_dict["namespace_name"] = ""
            image_data_dict["container_name"] = ""
            image_data_dict["workload_name"] = ""
            image_data_dict["workload_type"] = ""
            image_data_dict["node_name"] = ""
            image_data_dict["running"] = "no"

            image_data_dict["in_use_critical"] = 0
            image_data_dict["in_use_high"] = 0
            image_data_dict["in_use_medium"] = 0
            image_data_dict["in_use_low"] = 0
            image_data_dict["in_use_negligible"] = 0

            image_data_dict["exploitCount"] = x["exploitCount"]

            image_data_dict["origin"] = "pipeline"
            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return image_data_list, next_cursor


def query_scanning_v2_runtime_images_batch(secure_url, secure_api_token):
    image_data_list, next_cursor = query_scanning_v2_runtime_images("", secure_url, secure_api_token)
    try:
        while next_cursor is not None:
            image_data_list_temp, next_cursor = query_scanning_v2_runtime_images(next_cursor, secure_url, secure_api_token)
            image_data_list = image_data_list + image_data_list_temp
            print("Total runtime images fetched - " + str(len(image_data_list)))
    except:
        raise

    return image_data_list


def query_scanning_v2_runtime_images(next_cursor, secure_url, secure_api_token):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/scanning/runtime/v2/workflows/results' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + \
          '&order=desc&sort=runningVulnsBySev&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    image_data_list = []
    image_data_dict = {}

    if response.status_code == 200:

        response_text = json.loads(response.text)
        all_images_res = response_text["data"]
        next_cursor = response_text["page"]["next"]

        a = 0
        for x in all_images_res:

            image_data_dict["resultId"] = x["resultId"]
            image_data_dict["imageId"] = ""
            image_data_dict["imagePullString"] = x["recordDetails"]["mainAssetName"]
            image_data_dict["policyStatus"] = x['policyEvaluationsResult'][:4]

            if x["vulnsBySev"] != None:
                image_data_dict["critical"] = x["vulnsBySev"][2]
                image_data_dict["high"] = x["vulnsBySev"][3]
                image_data_dict["medium"] = x["vulnsBySev"][5]
                image_data_dict["low"] = x["vulnsBySev"][6]
                image_data_dict["negligible"] = x["vulnsBySev"][7]
            else:
                image_data_dict["critical"] = 0
                image_data_dict["high"] = 0
                image_data_dict["medium"] = 0
                image_data_dict["low"] = 0
                image_data_dict["negligible"] = 0

            if x["runningVulnsBySev"] != None:
                image_data_dict["in_use_critical"] = x["runningVulnsBySev"][2]
                image_data_dict["in_use_high"] = x["runningVulnsBySev"][3]
                image_data_dict["in_use_medium"] = x["runningVulnsBySev"][5]
                image_data_dict["in_use_low"] = x["runningVulnsBySev"][6]
                image_data_dict["in_use_negligible"] = x["runningVulnsBySev"][7]
            else:
                image_data_dict["in_use_critical"] = 0
                image_data_dict["in_use_high"] = 0
                image_data_dict["in_use_medium"] = 0
                image_data_dict["in_use_low"] = 0
                image_data_dict["in_use_negligible"] = 0

            image_data_dict["asset_name"] = x["recordDetails"]["mainAssetName"]
            imagePull_list = x["recordDetails"]["mainAssetName"].split("/")
            if len(imagePull_list) > 1:
                image_data_dict["repo"] = imagePull_list.pop(0)
                image_data_dict["image_name"] = imagePull_list.pop()
                image_data_dict["reg"] = "/".join(imagePull_list)
            else:
                image_data_dict["repo"] = ""
                image_data_dict["image_name"] = x["recordDetails"]["mainAssetName"]
                image_data_dict["reg"] = ""

            image_data_dict["asset_type"] = x["recordDetails"]["labels"]["asset.type"]
            image_data_dict["cluster_name"] = x["recordDetails"]["labels"]["kubernetes.cluster.name"]

            if image_data_dict["asset_type"] == "workload":
                image_data_dict["namespace_name"] = x["recordDetails"]["labels"]["kubernetes.namespace.name"]
                image_data_dict["container_name"] = x["recordDetails"]["labels"]["kubernetes.pod.container.name"]
                image_data_dict["workload_name"] = x["recordDetails"]["labels"]["kubernetes.workload.name"]
                image_data_dict["workload_type"] = x["recordDetails"]["labels"]["kubernetes.workload.type"]
                image_data_dict["node_name"] = ""
            elif image_data_dict["asset_type"] == "host":
                image_data_dict["node_name"] = x["recordDetails"]["labels"]["kubernetes.node.name"]
                image_data_dict["cluster_name"] = ""
                image_data_dict["namespace_name"] = ""
                image_data_dict["container_name"] = ""
                image_data_dict["workload_name"] = ""
                image_data_dict["workload_type"] = ""

            image_data_dict["running"] = "yes"
            image_data_dict["origin"] = "runtime"
            image_data_dict["exploitCount"] = x["exploitCount"]

            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
            a = a + 1
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return image_data_list, next_cursor


def query_scanning_v2_image_details(runtime_images, secure_url, secure_api_token):

    auth_string = "Bearer " + secure_api_token
    a = 0
    for image in runtime_images:
        url = secure_url + '/api/scanning/scanresults/v2/results/' + image["resultId"] + \
        "/vulnPkgs?filter=vulnHasFix = true and vulnIsExploitable = true and vulnIsRunning = true"

        print(a)
        a = a + 1
        if a % 20 == 0:
            print("sleeping for 5 seconds...")
            time.sleep(5)
        while True:
            try:
                response = requests.get(url, headers={"Authorization": auth_string})
                print("url - " + url)
            except Exception as ex:
                logging.error("Received an exception while invoking the url: " + url)
                logging.error(ex)

            if response.status_code == 200:
                response_text = json.loads(response.text)
                matched_total = response_text["page"]["matched"]
                image["fix_exploitable_running"] = matched_total
                break
            else:
                logging.error("Received an error trying to get the response from: " + url)
                logging.error("Error message: " + response.text)
                print(response.headers)
                if "Rate limit exceeded" in response.text:
                    print(response.headers)
                    print("Got rate limit exceeded error message. Sleeping for 2 mins and retrying.")
                    time.sleep(120)
                    print("retrying..." + str(a-1))
                    continue
                else:
                    raise

    return runtime_images
