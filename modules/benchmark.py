import logging
import json
import requests



class Benchmark():
    def __init__(self, endpoint_url, token):
        self.secure_api_token = token
        self.secure_url = endpoint_url


    def benchmark_prom_exporter(self):
        authString = "Bearer " + self.secure_api_token
        benchmark_data_list = []
        benchmark_data_dict = {}

        print("in benchmark prom exporter")

        url = self.secure_url + '/api/benchmarks/v2/tasks'
        try:
            response = requests.get(url, headers={"Authorization": authString})
        except Exception as ex:
            logging.error("Received an exception while invoking the url: " + url)
            logging.error(ex)
            raise

        if response.status_code == 200:
            benchmark_tasks = json.loads(response.text)

            for benchmark_task in benchmark_tasks:
                if benchmark_task["enabled"]:
                    url = self.secure_url + '/api/benchmarks/v2/tasks/' + str(benchmark_task["id"]) + '/results/' + \
                          benchmark_task["lastRunStartedId"]
                    try:
                        response = requests.get(url, headers={"Authorization": authString})
                    except Exception as ex:
                        logging.error("Received an exception while invoking the url: " + url)
                        logging.error(ex)
                        raise
                    if response.status_code == 200:
                        benchmark = json.loads(response.text)
                        benchmark_data_dict["platform"] = benchmark_task["platform"]
                        benchmark_data_dict["name"] = benchmark_task["name"]
                        benchmark_data_dict["schema"] = benchmark_task["schema"]
                        benchmark_data_dict["enabled"] = benchmark_task["enabled"]
                        benchmark_data_dict["resource_pass"] = str(benchmark["counts"]["resources"]["pass"])
                        benchmark_data_dict["resource_fail"] = str(benchmark["counts"]["resources"]["fail"])
                        benchmark_data_dict["resource_warn"] = str(benchmark["counts"]["resources"]["warn"])
                        benchmark_data_dict["control_pass"] = str(benchmark["counts"]["controls"]["pass"])
                        benchmark_data_dict["control_fail"] = str(benchmark["counts"]["controls"]["fail"])
                        benchmark_data_dict["control_warn"] = str(benchmark["counts"]["controls"]["warn"])
                        if "kubernetes.cluster.name" in benchmark["labels"]:
                            benchmark_data_dict["cluster_name"] = str(benchmark["labels"]["kubernetes.cluster.name"])
                        else:
                            benchmark_data_dict["cluster_name"] = ""
                        if "kubernetes.node.name" in benchmark["labels"]:
                            benchmark_data_dict["node_name"] = str(benchmark["labels"]["kubernetes.node.name"])
                        else:
                            benchmark_data_dict["node_name"] = ""

                        benchmark_data_list.append(benchmark_data_dict.copy())
                        benchmark_data_dict.clear()
        else:
            logging.error("Received an error trying to get the response from: " + url)
            # logging.error("Error message: " + response.text)
            raise

        return benchmark_data_list