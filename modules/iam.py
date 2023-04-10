import logging
import json
import requests

customer_name = "C"
batch_limit = 100


class IAM():
    def __init__(self, endpoint_url, token):
        self.secure_api_token = token
        self.secure_url = endpoint_url

    def iam_prom_exporter(self):
        try:
            iam_policies = query_iam_policies_batch(self.secure_url, self.secure_api_token)
            iam_users = query_iam_users_roles_batch("user", self.secure_url, self.secure_api_token)
            iam_roles = query_iam_users_roles_batch("role", self.secure_url, self.secure_api_token)

        except:
            raise

        return iam_policies, iam_users, iam_roles


def query_iam_policies_batch(secure_url, secure_api_token):
    policy_list, next_cursor = query_iam_policies("", secure_url, secure_api_token)
    try:
        while next_cursor != "":
            policy_list_temp, next_cursor = query_iam_policies(next_cursor, secure_url, secure_api_token)
            policy_list = policy_list + policy_list_temp
    except:
        raise

    return policy_list


def query_iam_policies(next_cursor, secure_url, secure_api_token):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/cloud/v2/policies' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + '&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    policy_data_list = []
    policy_data_dict = {}

    if response.status_code == 200:
        all_policies_temp = json.loads(response.text)
        all_policies = all_policies_temp["data"]
        next_cursor = all_policies_temp["options"]["next"]

        for x in all_policies:
            policy_data_dict["policyName"] = x["policyName"]
            policy_data_dict["policyType"] = x["policyType"]
            policy_data_dict["actorsTotal"] = len(x['actors'])
            policy_data_dict["numPermissionsGiven"] = x["numPermissionsGiven"]
            policy_data_dict["numPermissionsUnused"] = x["numPermissionsUnused"]
            policy_data_dict["riskCategory"] = x["riskCategory"]
            policy_data_dict["riskyPermissions"] = x["riskyPermissions"]
            policy_data_dict["riskScore"] = x["riskScore"]
            policy_data_dict["excessiveRiskCategory"] = x["excessiveRiskCategory"]
            policy_data_dict["excessiveRiskyPermissions"] = x["excessiveRiskyPermissions"]
            policy_data_dict["excessiveRiskScore"] = x["excessiveRiskScore"]
            policy_data_dict["customerName"] = customer_name

            policy_data_list.append(policy_data_dict.copy())
            policy_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return policy_data_list, next_cursor


def query_iam_users_roles_batch(kind, secure_url, secure_api_token):
    user_list, next_cursor = query_iam_users_roles("", kind, secure_url, secure_api_token)
    try:
        while next_cursor != "":
            user_list_temp, next_cursor = query_iam_users_roles(next_cursor, kind, secure_url, secure_api_token)
            user_list = user_list + user_list_temp
    except:
        raise

    return user_list


def query_iam_users_roles(next_cursor, kind, secure_url, secure_api_token):
    global batch_limit

    auth_string = "Bearer " + secure_api_token

    url = secure_url + '/api/cloud/v2/users' \
                       '?cursor=' + next_cursor + \
          '&limit=' + str(batch_limit) + '&kind=' + kind + '&output=json'

    try:
        response = requests.get(url, headers={"Authorization": auth_string})
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise

    user_role_data_list = []
    user_role_data_dict = {}

    if response.status_code == 200:
        all_users_roles_temp = json.loads(response.text)
        all_users_roles = all_users_roles_temp["data"]
        next_cursor = all_users_roles_temp["options"]["next"]


        admin_risk = "Admin"
        inactive_risk = "Inactive"
        no_mfa_risk = "No MFA"
        key_1_not_rotated_risk = "Access Key 1 Not Rotated"
        key_2_not_rotated_risk = "Access Key 2 Not Rotated"
        multiple_keys_risk = "Multiple Access Keys Active"

        a = 0
        for x in all_users_roles:
            user_role_data_dict["actorName"] = x["actorName"]
            user_role_data_dict["policiesTotal"] = len(x['policies'])
            user_role_data_dict["numPermissionsGiven"] = x["numPermissionsGiven"]
            user_role_data_dict["effectivePermissionsCount"] = x["effectivePermissionsCount"]
            user_role_data_dict["numPermissionsUnused"] = x["numPermissionsUnused"]
            user_role_data_dict["numPermissionsUsed"] = x["numPermissionsUsed"]
            user_role_data_dict["riskCategory"] = x["riskCategory"]
            user_role_data_dict["riskyPermissions"] = x["riskyPermissions"]
            user_role_data_dict["riskScore"] = x["riskScore"]
            user_role_data_dict["excessiveRiskCategory"] = x["excessiveRiskCategory"]
            user_role_data_dict["excessiveRiskyPermissions"] = x["excessiveRiskyPermissions"]
            user_role_data_dict["excessiveRiskScore"] = x["excessiveRiskScore"]
            user_role_data_dict["customerName"] = customer_name

            risk_list = x["labels"]["risk"]

            user_role_data_dict["admin"] = "no"
            user_role_data_dict["inactive"] = "no"
            user_role_data_dict["no_mfa"] = "no"
            user_role_data_dict["key1_not_rotated"] = "no"
            user_role_data_dict["key2_not_rotated"] = "no"
            user_role_data_dict["multiple_keys"] = "no"

            if risk_list is not None:
                for risk in risk_list:
                    if risk == admin_risk:
                        user_role_data_dict["admin"] = "yes"
                    elif risk == inactive_risk:
                        user_role_data_dict["inactive"] = "yes"
                    elif risk == no_mfa_risk:
                        user_role_data_dict["no_mfa"] = "yes"
                    elif risk == key_1_not_rotated_risk:
                        user_role_data_dict["key1_not_rotated"] = "yes"
                    elif risk == key_2_not_rotated_risk:
                        user_role_data_dict["key2_not_rotated"] = "yes"
                    elif risk == multiple_keys_risk:
                        user_role_data_dict["multiple_keys"] = "yes"

            user_role_data_list.append(user_role_data_dict.copy())
            user_role_data_dict.clear()
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise

    return user_role_data_list, next_cursor

