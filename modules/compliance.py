import logging
import json
import requests

class Compliance():
    def __init__(self, endpoint_url, token):
        self.secure_api_token = token
        self.secure_url = endpoint_url

    def compliance_prom_exporter(self):
        auth_string = "Bearer " + self.secure_api_token
        compliance_data_list = []
        compliance_data_dict = {}

        print("in compliance prom exporter")

        #global first_time_running
        global compliances
    #if first_time_running:
        url = self.secure_url + "/api/compliance/v2/tasks?light=true"
        try:
            response = requests.get(url, headers={"Authorization": auth_string})
        except Exception as ex:
            logging.error("Received an exception while invoking the url: " + url)
            logging.error(ex)
            raise
        if response.status_code == 200:
            compliances = json.loads(response.text)
        else:
            logging.error("Received an error trying to get the response from: " + url)
            logging.error("Error message: " + response.text)
            raise

        for compliance in compliances:

            if compliance["state"] == "Complete" and len(compliance["counts"]["controls"]) > 0:

                compliance_data_dict["name"] = compliance["name"]
                compliance_data_dict["type"] = compliance["type"]

                compliance_data_dict["schema"] = compliance["schema"]
                compliance_data_dict["framework"] = compliance["framework"]
                compliance_data_dict["version"] = compliance["version"]
                compliance_data_dict["platform"] = compliance["platform"]
                # compliance_data_dict["control_pass"] = str(compliance["counts"]["controls"]["pass"])
                # compliance_data_dict["control_fail"] = str(compliance["counts"]["controls"]["fail"])
                # compliance_data_dict["control_warn"] = str(compliance["counts"]["controls"]["warn"])
                # compliance_data_dict["control_pass_percent"] = str(compliance["counts"]["controls"]["passPercent"])
                # compliance_data_dict["control_total"] = str(compliance["counts"]["controls"]["pass"] + compliance["counts"]["controls"]["fail"] + compliance["counts"]["controls"]["warn"])

                # compliance_data_list.append(compliance_data_dict.copy())
                # compliance_data_dict.clear()

                url = self.secure_url + "/api/compliance/v2/tasks/" + str(compliance["id"]) + "/reports/" + compliance[
                    "lastRunCompletedId"]
                # url = secure_url + '/api/compliance/v1/report?detail=false&compliance=' + compliance + '&environment=Kubernetes&output=json'
                try:
                    response = requests.get(url, headers={"Authorization": auth_string})
                except Exception as ex:
                    logging.error("Received an exception while invoking the url: " + url)
                    logging.error(ex)
                    raise

                if response.status_code == 200:
                    compliance_report = json.loads(response.text)
                    for family in compliance_report["families"]:
                        compliance_data_dict["family"] = family["name"]
                        # compliance_data_dict["pass"] = family["counts"]["controls"]
                        compliance_data_dict["control_pass"] = str(family["counts"]["controls"]["pass"])
                        compliance_data_dict["control_fail"] = str(family["counts"]["controls"]["fail"])
                        compliance_data_dict["control_warn"] = str(family["counts"]["controls"]["warn"])
                        compliance_data_dict["control_pass_percent"] = str(family["counts"]["controls"]["passPercent"])
                        compliance_data_dict["control_total"] = str(
                            family["counts"]["controls"]["pass"] + family["counts"]["controls"]["fail"] +
                            family["counts"]["controls"]["warn"])
                        compliance_data_list.append(compliance_data_dict.copy())

                    # compliance_data_list.append(compliance_data_dict.copy())
                    compliance_data_dict.clear()
                elif response.reason == 'No Content':
                    compliance_data_dict.clear()
                # for testing purpose, I am ignoring the error and treating as no content
                # else:
                #     logging.error("Received an error trying to get the response from: " + url)
                #     logging.error("Error message: " + response.text)
                #     raise

        return compliance_data_list
