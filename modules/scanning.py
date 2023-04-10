import json
import logging

import requests
from sdcclient import SdScanningClient

status_list = ["pass", "fail", "unknown"]
batch_limit = 100

class Scanning:
    def __init__(self, endpoint_url, token):
        self.token = token
        self.endpoint_url = endpoint_url


    def scanning_prom_exporter(self):
        try:
            all_images_with_distro = query_build_images_using_sdk(self.endpoint_url, self.token)
            all_images = query_build_images_batch(self.endpoint_url, self.token)
            all_runtime_images = query_runtime_images_batch(self.endpoint_url, self.token)

        except:
            raise

        for curr_build_image in all_images:
            curr_build_image["running"] = "no"
            curr_build_image["distro"] = "unknown"
            curr_build_image["containers"] = 0
            curr_build_image["cluster"] = ""
            for curr_runtime_image in all_runtime_images:
                if curr_build_image["imageId"] == curr_runtime_image["imageId"]:
                    curr_build_image["containers"] = len(curr_runtime_image["containers"])
                    curr_build_image["running"] = "yes"
                    curr_build_image["cluster"] = curr_runtime_image["cluster"]
            for curr_distro_image in all_images_with_distro:
                if curr_build_image["imageId"] == curr_distro_image["imageId"]:
                    curr_build_image["distro"] = curr_distro_image["distro"]

        origin_set = set()
        reg_set = set()
        repo_set = set()
        distro_set = set()

        for image in all_images:
            origin_set.add(image.get("origin"))
            reg_set.add(image.get("reg"))
            repo_set.add(image.get("repo"))
            distro_set.add(image.get("distro"))

            # fixing None type - if None found, replace it with unknown
            if image["distro"] is None:
                image["distro"] = "unknown"
            if image["origin"] is None:
                image["origin"] = "unknown"
            if image["reg"] is None:
                image["reg"] = "unknown"
            if image["repo"] is None:
                image["repo"] = "unknown"

        origin_list = list(origin_set)
        reg_list = list(reg_set)
        repo_list = list(repo_set)
        distro_list = list(distro_set)

        final_dict = {}
        for image in all_images:
            for distro in distro_list:
                if image.get("distro") == distro:
                    for origin in origin_list:
                        if image.get("origin") == origin:
                            for reg in reg_list:
                                if image.get("reg") == reg:
                                    for repo in repo_list:
                                        if image.get("repo") == repo:
                                            for status in status_list:
                                                if image.get("status") == status:
                                                    key_string = image.get("distro") + "|" + image.get(
                                                        "origin") + "|" + image.get("reg") + "|" + \
                                                                 image.get("repo") + "|" + image.get(
                                                        "status") + "|" + image.get('running') + "|" + \
                                                                 str(image.get("containers")) + "|" + image.get("cluster")
                                                    if key_string in final_dict:
                                                        final_dict[key_string] = final_dict[key_string] + 1
                                                    else:
                                                        final_dict[key_string] = 1
        return final_dict


def query_runtime_images_batch(secure_url, secure_api_token):
    global batch_limit
    offset = 0
    runtime_images = query_runtime_images(offset, secure_url, secure_api_token)
    try:
        while len(runtime_images) == batch_limit + offset:
            offset = offset + batch_limit
            runtime_images = runtime_images + query_runtime_images(offset, secure_url, secure_api_token)
    except:
        raise

    return runtime_images


def query_runtime_images(offset, secure_url, secure_api_token):
    auth_string = "Bearer " + secure_api_token
    url = secure_url + "/api/scanning/v1/query/containers"
    headers_dict = {'Content-Type': 'application/json', 'Authorization': auth_string}

    global batch_limit

    clusters_list = query_cluster_names(secure_url, secure_api_token)
    all_runtime_images = []
    for cluster in clusters_list:
        if cluster != "non-k8s":
            payload = json.dumps({
                "scope": "kubernetes.cluster.name = \"" + cluster + "\"",
                "skipPolicyEvaluation": False,
                "useCache": True,
                "offset": offset,
                "limit": batch_limit
            })

            try:
                response = requests.request("POST", url, headers=headers_dict, data=payload)
            except Exception as ex:
                logging.error("Received an exception while invoking the url: " + url)
                logging.error(ex)
                raise

            if response.status_code == 200:
                runtime_images = json.loads(response.text)
                runtime_images = runtime_images["images"]

                print("total runtime images found - " + str(len(runtime_images)) + " for cluster - " + cluster)

                for image in runtime_images:
                    image["cluster"] = cluster

                all_runtime_images = all_runtime_images + runtime_images


            else:
                logging.error("Received an error trying to get the response from: " + url)
                logging.error("Error message: " + response.text)
                raise

    return all_runtime_images


def query_cluster_names(secure_url, secure_api_token):
    print("in query_cluster_names")

    url = secure_url + "/api/data/entity/metadata"
    auth_string = "Bearer " + secure_api_token

    payload = json.dumps({
        "metrics": [
            "kubernetes.cluster.name"
        ]
    })

    headers_dict = {'Content-Type': 'application/json', 'Authorization': auth_string}

    try:
        response = requests.request("POST", url, headers=headers_dict, data=payload)
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    if response.status_code == 200:
        clusters = json.loads(response.text)
        clusters = clusters["data"]

        print("total runtime clusters found - " + str(len(clusters)))

        clusters_list = []
        for cluster in clusters:
            clusters_list.append(cluster["kubernetes.cluster.name"])
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return clusters_list


def query_build_images_batch(secure_url, secure_api_token):
    global batch_limit
    offset = 0
    image_data_list = query_build_images(offset, secure_url, secure_api_token)
    try:
        while len(image_data_list) == batch_limit + offset:
            offset = offset + batch_limit
            image_data_list = image_data_list + query_build_images(offset, secure_url, secure_api_token)
    except:
        raise

    return image_data_list


def query_build_images(offset, secure_url, secure_api_token):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/scanning/v1/resultsDirect?limit=' + str(batch_limit) + '&offset=' + str(
        offset) + '&sort=desc&sortBy=scanDate&output=json'

    print("in query_build_images - limit - " + str(batch_limit) + ' -- offset - ' + str(offset))

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    image_data_list = []
    image_data_dict = {}

    if response.status_code == 200:

        all_build_images = json.loads(response.text)
        all_images_res = all_build_images["results"]

        for x in all_images_res:
            image_data_dict["imageId"] = x["imageId"]
            if "origin" in x:
                image_data_dict["origin"] = x["origin"]
            else:
                image_data_dict["origin"] = "NOT FOUND"
            image_data_dict["analysis_status"] = x["analysisStatus"]
            image_data_dict["reg"] = x["registry"]
            image_data_dict["repo"] = x["repository"]
            if "policyStatus" in x:
                if x["policyStatus"] == "STOP":
                    image_data_dict["status"] = "fail"
                else:
                    image_data_dict["status"] = "pass"
            else:
                image_data_dict["status"] = "unknown"

            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return image_data_list


def query_build_images_using_sdk(secure_url, secure_api_token):
    sdc_client = SdScanningClient(secure_api_token, secure_url)

    try:
        ok, response = sdc_client.list_images()
    except Exception as ex:
        logging.error("Received an exception while invoking the list_images() sdk using secure_url: " + secure_url)
        logging.error(ex)
        raise

    if ok:
        all_images_res = json.loads(json.dumps(response, indent=2))
        image_data_list = []
        image_data_dict = {}

        for x in all_images_res:
            image_data_dict["imageId"] = x["image_detail"][0]["imageId"]
            image_data_dict["distro"] = x["image_content"]["metadata"]["distro"]
            image_data_list.append(image_data_dict.copy())
            image_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from list_images sdk: ")
        logging.error("Error message: " + response.text)
        raise

    return image_data_list
