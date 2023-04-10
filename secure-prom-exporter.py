import time
from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily
from prometheus_client import start_http_server
import json
import logging
import requests
import os
from datetime import datetime
from datetime import timedelta

from sdcclient import SdScanningClient

from modules.scanning_v2 import Scanning_v2 as scan_v2
from modules.scanning import Scanning as scan
from modules.compliance import Compliance as comp
from modules.benchmark import Benchmark as bench
from modules.iam import IAM as iam_pol




secure_api_token = os.getenv('SECURE_API_TOKEN').replace('\n', '')
secure_url = os.getenv('SECURE_URL')
scheduled_run_minutes = int(os.getenv('SCHEDULED_RUN_MINUTES'))
prom_exp_url_port = int(os.getenv('PROM_EXP_URL_PORT'))
batch_limit = int(os.getenv('BATCH_LIMIT'))
customer_name = os.getenv('CUSTOMER_NAME')
query_features_list = os.getenv('QUERY_FEATURES_LIST')
fetch_pipeline_data = os.getenv('QUERY_PIPELINE') # expects "yes" or "no"



# all - query all features
# if you want to test out a specific product area directly:
test_scanning = "scanning_v1"
test_scanning_v2 = "scanning_v2"
test_compliance = "compliance"
test_benchmark = "benchmark"
test_iam = "iam"


# if fetch_pipeline_data is None or len(fetch_pipeline_data) == 0:
#     fetch_pipeline_data = "yes"


test_area = [test_scanning]
if query_features_list == "all":
    test_area = [test_scanning, test_scanning_v2, test_compliance, test_benchmark, test_iam]
else:
    test_area = query_features_list

first_time_running = True

last_run_date = datetime.now()
last_run_date_str = last_run_date.strftime("%d/%m/%Y %H:%M")


posture_compliance_types = ["AWS", "AZURE", "GCP", "WORKLOAD"]

scanning_prom_exp_metrics = {}
all_compliances = []
all_benchmarks = []
all_scanning_v2 = []
iam_policies = []
iam_users = []
iam_roles = []
images_runtime_exploit_hasfix_inuse = []
total_requests = 0



from sdcclient import SdMonitorClient


# sdclient = SdMonitorClient(sdc_token)

# sdclient.get_connected_agents()

class SecureMetricsCollector(object):
    def __init__(self):
        pass

    def collect(self):

        # scanning - new
        prom_metric_scanning_v2_images_critical = GaugeMetricFamily("sysdig_secure_images_scanned_v2_critical",
                                                                    'critical vul using new scanning engine',
                                                                    labels=['sysdig_secure_image_id',
                                                                            'sysdig_secure_image_reg_name',
                                                                            'sysdig_secure_image_repo_name',
                                                                            'sysdig_secure_image_pull_string',
                                                                            'sysdig_secure_image_status',
                                                                            'sysdig_secure_image_running',
                                                                            'sysdig_secure_image_name',
                                                                            'sysdig_secure_asset_type',
                                                                            'sysdig_secure_cluster_name',
                                                                            'sysdig_secure_namespace_name',
                                                                            'sysdig_secure_workload_name',
                                                                            'sysdig_secure_workload_type',
                                                                            'sysdig_secure_customer_name'
                                                                            ])

        prom_metric_scanning_v2_images_high = GaugeMetricFamily("sysdig_secure_images_scanned_v2_high",
                                                                'high vul using new scanning engine',
                                                                labels=['sysdig_secure_image_id',
                                                                        'sysdig_secure_image_reg_name',
                                                                        'sysdig_secure_image_repo_name',
                                                                        'sysdig_secure_image_pull_string',
                                                                        'sysdig_secure_image_status',
                                                                        'sysdig_secure_image_running',
                                                                        'sysdig_secure_image_name',
                                                                        'sysdig_secure_asset_type',
                                                                        'sysdig_secure_cluster_name',
                                                                        'sysdig_secure_namespace_name',
                                                                        'sysdig_secure_workload_name',
                                                                        'sysdig_secure_workload_type',
                                                                        'sysdig_secure_customer_name'
                                                                        ])

        prom_metric_scanning_v2_images_medium = GaugeMetricFamily("sysdig_secure_images_scanned_v2_medium",
                                                                  'critical vul using new scanning engine',
                                                                  labels=['sysdig_secure_image_id',
                                                                          'sysdig_secure_image_reg_name',
                                                                          'sysdig_secure_image_repo_name',
                                                                          'sysdig_secure_image_pull_string',
                                                                          'sysdig_secure_image_status',
                                                                          'sysdig_secure_image_running',
                                                                          'sysdig_secure_image_name',
                                                                          'sysdig_secure_asset_type',
                                                                          'sysdig_secure_cluster_name',
                                                                          'sysdig_secure_namespace_name',
                                                                          'sysdig_secure_workload_name',
                                                                          'sysdig_secure_workload_type',
                                                                          'sysdig_secure_customer_name'
                                                                          ])

        prom_metric_scanning_v2_images_low = GaugeMetricFamily("sysdig_secure_images_scanned_v2_low",
                                                               'critical vul using new scanning engine',
                                                               labels=['sysdig_secure_image_id',
                                                                       'sysdig_secure_image_reg_name',
                                                                       'sysdig_secure_image_repo_name',
                                                                       'sysdig_secure_image_pull_string',
                                                                       'sysdig_secure_image_status',
                                                                       'sysdig_secure_image_running',
                                                                       'sysdig_secure_image_name',
                                                                       'sysdig_secure_asset_type',
                                                                       'sysdig_secure_cluster_name',
                                                                       'sysdig_secure_namespace_name',
                                                                       'sysdig_secure_workload_name',
                                                                       'sysdig_secure_workload_type',
                                                                       'sysdig_secure_customer_name'
                                                                       ])

        prom_metric_scanning_v2_images_in_use_critical = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_in_use_critical",
            'critical vul using new scanning engine',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_v2_images_in_use_high = GaugeMetricFamily("sysdig_secure_images_scanned_v2_in_use_high",
                                                                       'critical vul using new scanning engine',
                                                                       labels=['sysdig_secure_image_id',
                                                                               'sysdig_secure_image_reg_name',
                                                                               'sysdig_secure_image_repo_name',
                                                                               'sysdig_secure_image_pull_string',
                                                                               'sysdig_secure_image_status',
                                                                               'sysdig_secure_image_running',
                                                                               'sysdig_secure_image_name',
                                                                               'sysdig_secure_asset_type',
                                                                               'sysdig_secure_cluster_name',
                                                                               'sysdig_secure_namespace_name',
                                                                               'sysdig_secure_workload_name',
                                                                               'sysdig_secure_workload_type',
                                                                               'sysdig_secure_customer_name'
                                                                               ])

        prom_metric_scanning_v2_images_in_use_medium = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_in_use_medium",
            'critical vul using new scanning engine',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_v2_images_in_use_low = GaugeMetricFamily("sysdig_secure_images_scanned_v2_in_use_low",
                                                                      'critical vul using new scanning engine',
                                                                      labels=['sysdig_secure_image_id',
                                                                              'sysdig_secure_image_reg_name',
                                                                              'sysdig_secure_image_repo_name',
                                                                              'sysdig_secure_image_pull_string',
                                                                              'sysdig_secure_image_status',
                                                                              'sysdig_secure_image_running',
                                                                              'sysdig_secure_image_name',
                                                                              'sysdig_secure_asset_type',
                                                                              'sysdig_secure_cluster_name',
                                                                              'sysdig_secure_namespace_name',
                                                                              'sysdig_secure_workload_name',
                                                                              'sysdig_secure_workload_type',
                                                                              'sysdig_secure_customer_name'
                                                                              ])

        prom_metric_scanning_v2_images_exploit_count = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_exploit_count",
            'critical vul using new scanning engine',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_v2_images_exploit_fix_inuse_count = GaugeMetricFamily(
            "sysdig_secure_images_scanned_v2_exploit_fix_inuse_count",
            'critical vul using new scanning engine that has exploit, fix & inuse',
            labels=['sysdig_secure_image_id',
                    'sysdig_secure_image_reg_name',
                    'sysdig_secure_image_repo_name',
                    'sysdig_secure_image_pull_string',
                    'sysdig_secure_image_status',
                    'sysdig_secure_image_running',
                    'sysdig_secure_image_name',
                    'sysdig_secure_asset_type',
                    'sysdig_secure_cluster_name',
                    'sysdig_secure_namespace_name',
                    'sysdig_secure_workload_name',
                    'sysdig_secure_workload_type',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_scanning_images_v2 = GaugeMetricFamily("sysdig_secure_images_scanned_v2",
                                                        'All the images detected in your cluster with new scan engine.',
                                                        labels=['sysdig_secure_image_scan_origin',
                                                                'sysdig_secure_image_reg_name',
                                                                'sysdig_secure_image_repo_name',
                                                                'sysdig_secure_image_pull_string',
                                                                'sysdig_secure_image_status',
                                                                'sysdig_secure_image_running',
                                                                'sysdig_secure_image_name',
                                                                'sysdig_secure_asset_type',
                                                                'sysdig_secure_cluster_name',
                                                                'sysdig_secure_namespace_name',
                                                                'sysdig_secure_workload_name',
                                                                'sysdig_secure_workload_type',
                                                                'sysdig_secure_node_name',
                                                                'sysdig_secure_critical_vuln',
                                                                'sysdig_secure_high_vuln',
                                                                'sysdig_secure_medium_vuln',
                                                                'sysdig_secure_low_vuln',
                                                                'sysdig_secure_in_use_critical_vuln',
                                                                'sysdig_secure_in_use_high_vuln',
                                                                'sysdig_secure_in_use_medium_vuln',
                                                                'sysdig_secure_in_use_low_vuln',
                                                                'sysdig_secure_exploit_count',
                                                                'sysdig_secure_customer_name'
                                                                ])

        # Scanning - old
        prom_metric_scanning_images = GaugeMetricFamily("sysdig_secure_images_scanned",
                                                        'All the images detected in your cluster with scan result.',
                                                        labels=['sysdig_secure_image_distro',
                                                                'sysdig_secure_image_scan_origin',
                                                                'sysdig_secure_image_reg_name',
                                                                'sysdig_secure_image_repo_name',
                                                                'sysdig_secure_image_status',
                                                                'sysdig_secure_image_running',
                                                                'sysdig_secure_containers',
                                                                'sysdig_secure_cluster',
                                                                'sysdig_secure_customer_name'
                                                                ])

        # Compliance

        prom_metric_compliance_pass = GaugeMetricFamily("sysdig_secure_compliance_pass",
                                                        'How many controls passed against the compliance.',
                                                        labels=['sysdig_secure_compliance_name',
                                                                'sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_schema',
                                                                'sysdig_secure_compliance_framework',
                                                                'sysdig_secure_compliance_version',
                                                                'sysdig_secure_compliance_platform',
                                                                'sysdig_secure_compliance_family',
                                                                'sysdig_secure_customer_name'])

        prom_metric_compliance_fail = GaugeMetricFamily("sysdig_secure_compliance_fail",
                                                        'How many controls failed against the compliance.',
                                                        labels=['sysdig_secure_compliance_name',
                                                                'sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_schema',
                                                                'sysdig_secure_compliance_framework',
                                                                'sysdig_secure_compliance_version',
                                                                'sysdig_secure_compliance_platform',
                                                                'sysdig_secure_compliance_family',
                                                                'sysdig_secure_customer_name'])

        prom_metric_compliance_warn = GaugeMetricFamily("sysdig_secure_compliance_warn",
                                                        'How many controls warned against the compliance.',
                                                        labels=['sysdig_secure_compliance_name',
                                                                'sysdig_secure_compliance_type',
                                                                'sysdig_secure_compliance_schema',
                                                                'sysdig_secure_compliance_framework',
                                                                'sysdig_secure_compliance_version',
                                                                'sysdig_secure_compliance_platform',
                                                                'sysdig_secure_compliance_family',
                                                                'sysdig_secure_customer_name'])

        prom_metric_compliance_total = GaugeMetricFamily("sysdig_secure_compliance_total",
                                                         'How many total controls for the compliance.',
                                                         labels=['sysdig_secure_compliance_name',
                                                                 'sysdig_secure_compliance_type',
                                                                 'sysdig_secure_compliance_schema',
                                                                 'sysdig_secure_compliance_framework',
                                                                 'sysdig_secure_compliance_version',
                                                                 'sysdig_secure_compliance_platform',
                                                                 'sysdig_secure_compliance_family',
                                                                 'sysdig_secure_customer_name'])

        prom_metric_compliance_pass_perc = GaugeMetricFamily("sysdig_secure_compliance_pass_perc",
                                                             'How many % controls passed against the compliance.',
                                                             labels=['sysdig_secure_compliance_name',
                                                                     'sysdig_secure_compliance_type',
                                                                     'sysdig_secure_compliance_schema',
                                                                     'sysdig_secure_compliance_framework',
                                                                     'sysdig_secure_compliance_version',
                                                                     'sysdig_secure_compliance_platform',
                                                                     'sysdig_secure_compliance_family',
                                                                     'sysdig_secure_customer_name'])

        # prom_metric_compliance_pass = GaugeMetricFamily("sysdig_secure_compliance_pass",
        #                                                 'How many controls passed against the compliance.',
        #                                                 labels=['sysdig_secure_compliance_standard',
        #                                                         'sysdig_secure_compliance',
        #                                                         'sysdig_secure_compliance_type'])
        #
        # prom_metric_compliance_fail = GaugeMetricFamily("sysdig_secure_compliance_fail",
        #                                                 'How many controls failed against the compliance.',
        #                                                 labels=['sysdig_secure_compliance_standard',
        #                                                         'sysdig_secure_compliance',
        #                                                         'sysdig_secure_compliance_type'])
        #
        # prom_metric_compliance_checked = GaugeMetricFamily("sysdig_secure_compliance_checked",
        #                                                    'How many controls checked against the compliance.',
        #                                                    labels=['sysdig_secure_compliance_standard',
        #                                                            'sysdig_secure_compliance',
        #                                                            'sysdig_secure_compliance_type'])
        #
        # prom_metric_compliance_unchecked = GaugeMetricFamily("sysdig_secure_compliance_unchecked",
        #                                                      'How many controls unchecked against the compliance.',
        #                                                      labels=['sysdig_secure_compliance_standard',
        #                                                              'sysdig_secure_compliance',
        #                                                              'sysdig_secure_compliance_type'])

        # Benchmarks
        prom_metric_benchmark_resource_pass = GaugeMetricFamily("sysdig_secure_benchmark_resources_pass",
                                                                'How many resources passed against the benchmark.',
                                                                labels=['sysdig_secure_platform',
                                                                        'sysdig_secure_benchmark_name',
                                                                        'sysdig_secure_benchmark_schema',
                                                                        'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                        'sysdig_secure_customer_name'])

        prom_metric_benchmark_resource_fail = GaugeMetricFamily("sysdig_secure_benchmark_resources_fail",
                                                                'How many resources failed against the benchmark.',
                                                                labels=['sysdig_secure_platform',
                                                                        'sysdig_secure_benchmark_name',
                                                                        'sysdig_secure_benchmark_schema',
                                                                        'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                        'sysdig_secure_customer_name'])

        prom_metric_benchmark_resource_warn = GaugeMetricFamily("sysdig_secure_benchmark_resources_warn",
                                                                'How many resources warn against the benchmark.',
                                                                labels=['sysdig_secure_platform',
                                                                        'sysdig_secure_benchmark_name',
                                                                        'sysdig_secure_benchmark_schema',
                                                                        'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                        'sysdig_secure_customer_name'])

        prom_metric_benchmark_control_pass = GaugeMetricFamily("sysdig_secure_benchmark_control_pass",
                                                               'How many controls passed against the benchmark.',
                                                               labels=['sysdig_secure_platform',
                                                                       'sysdig_secure_benchmark_name',
                                                                       'sysdig_secure_benchmark_schema',
                                                                       'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                       'sysdig_secure_customer_name'])

        prom_metric_benchmark_control_fail = GaugeMetricFamily("sysdig_secure_benchmark_control_fail",
                                                               'How many controls failed against the benchmark.',
                                                               labels=['sysdig_secure_platform',
                                                                       'sysdig_secure_benchmark_name',
                                                                       'sysdig_secure_benchmark_schema',
                                                                       'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                       'sysdig_secure_customer_name'])

        prom_metric_benchmark_control_warn = GaugeMetricFamily("sysdig_secure_benchmark_control_warn",
                                                               'How many controls warn against the benchmark.',
                                                               labels=['sysdig_secure_platform',
                                                                       'sysdig_secure_benchmark_name',
                                                                       'sysdig_secure_benchmark_schema',
                                                                       'sysdig_secure_cluster', 'sysdig_secure_node',
                                                                       'sysdig_secure_customer_name'])

        # iam
        prom_metric_iam_policy = GaugeMetricFamily("sysdig_secure_iam_policy",
                                                     'IAM policies',
                                                     labels=['sysdig_secure_iam_policy_name',
                                                             'sysdig_secure_iam_actors_total',
                                                             'sysdig_secure_iam_permissions_given_total',
                                                             'sysdig_secure_iam_permissions_unused_total',
                                                             'sysdig_secure_iam_risk_category',
                                                             'sysdig_secure_iam_risky_permissions_total',
                                                             'sysdig_secure_iam_risk_score',
                                                             'sysdig_secure_iam_policy_type',
                                                             'sysdig_secure_iam_excessive_risk_category',
                                                             'sysdig_secure_iam_execssive_risky_permissions_total',
                                                             'sysdig_secure_iam_excessive_risk_score',
                                                             'sysdig_secure_customer_name'
                                                             ])

        prom_metric_iam_policy_perms_given_total = GaugeMetricFamily("sysdig_secure_iam_policy_perms_given_total",
                                                   'IAM policies permissions given total',
                                                   labels=['sysdig_secure_iam_policy_name',
                                                           'sysdig_secure_iam_actors_total',
                                                           'sysdig_secure_iam_risk_category',
                                                           'sysdig_secure_iam_policy_type',
                                                           'sysdig_secure_customer_name'
                                                           ])

        prom_metric_iam_policy_perms_unused_total = GaugeMetricFamily("sysdig_secure_iam_policy_perms_unused_total",
                                                                     'IAM policies permissions unused total',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_risky_perms_total = GaugeMetricFamily("sysdig_secure_iam_policy_risky_perms_total",
                                                                     'IAM policies risky permissions total',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_risk_score = GaugeMetricFamily("sysdig_secure_iam_policy_risk_score",
                                                                     'IAM policies risk score',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_excessive_risky_perms_total = GaugeMetricFamily("sysdig_secure_iam_policy_excessive_risky_perms_total",
                                                                     'IAM policies excessive risky permissions total',
                                                                     labels=['sysdig_secure_iam_policy_name',
                                                                             'sysdig_secure_iam_actors_total',
                                                                             'sysdig_secure_iam_risk_category',
                                                                             'sysdig_secure_iam_policy_type',
                                                                             'sysdig_secure_customer_name'
                                                                             ])

        prom_metric_iam_policy_excessive_risk_score = GaugeMetricFamily("sysdig_secure_iam_policy_excessive_risk_score",
                                                              'IAM policies excessive risk score',
                                                              labels=['sysdig_secure_iam_policy_name',
                                                                      'sysdig_secure_iam_actors_total',
                                                                      'sysdig_secure_iam_risk_category',
                                                                      'sysdig_secure_iam_policy_type',
                                                                      'sysdig_secure_customer_name'
                                                                      ])

        prom_metric_iam_user = GaugeMetricFamily("sysdig_secure_iam_user",
                                                     'IAM users',
                                                     labels=['sysdig_secure_iam_user_name',
                                                             'sysdig_secure_iam_user_policies_total',
                                                             'sysdig_secure_iam_permissions_given_total',
                                                             'sysdig_secure_iam_permissions_effective_total',
                                                             'sysdig_secure_iam_permissions_unused_total',
                                                             'sysdig_secure_iam_permissions_used_total',
                                                             'sysdig_secure_iam_risk_category',
                                                             'sysdig_secure_iam_risky_permissions_total',
                                                             'sysdig_secure_iam_risk_score',
                                                             'sysdig_secure_iam_excessive_risk_category',
                                                             'sysdig_secure_iam_execssive_risky_permissions_total',
                                                             'sysdig_secure_iam_excessive_risk_score',
                                                             'sysdig_secure_iam_user_risk_admin',
                                                             'sysdig_secure_iam_user_risk_inactive',
                                                             'sysdig_secure_iam_user_risk_no_mfa',
                                                             'sysdig_secure_iam_user_risk_key1_not_rotated',
                                                             'sysdig_secure_iam_user_risk_key2_not_rotated',
                                                             'sysdig_secure_iam_user_risk_multiple_keys',
                                                             'sysdig_secure_customer_name'
                                                             ])

        prom_metric_iam_user_permissions_given_total = GaugeMetricFamily("sysdig_secure_iam_user_permissions_given_total",
                                                 'IAM users permissions given',
                                                 labels=['sysdig_secure_iam_user_name',
                                                         'sysdig_secure_iam_user_policies_total',
                                                         'sysdig_secure_iam_risk_category',
                                                         'sysdig_secure_iam_excessive_risk_category',
                                                         'sysdig_secure_iam_user_risk_admin',
                                                         'sysdig_secure_iam_user_risk_inactive',
                                                         'sysdig_secure_iam_user_risk_no_mfa',
                                                         'sysdig_secure_iam_user_risk_key1_not_rotated',
                                                         'sysdig_secure_iam_user_risk_key2_not_rotated',
                                                         'sysdig_secure_iam_user_risk_multiple_keys',
                                                         'sysdig_secure_customer_name'
                                                         ])

        prom_metric_iam_user_permissions_unused_total = GaugeMetricFamily(
            "sysdig_secure_iam_user_permissions_unused_total",
            'IAM users permissions unused',
            labels=['sysdig_secure_iam_user_name',
                    'sysdig_secure_iam_user_policies_total',
                    'sysdig_secure_iam_risk_category',
                    'sysdig_secure_iam_excessive_risk_category',
                    'sysdig_secure_iam_user_risk_admin',
                    'sysdig_secure_iam_user_risk_inactive',
                    'sysdig_secure_iam_user_risk_no_mfa',
                    'sysdig_secure_iam_user_risk_key1_not_rotated',
                    'sysdig_secure_iam_user_risk_key2_not_rotated',
                    'sysdig_secure_iam_user_risk_multiple_keys',
                    'sysdig_secure_customer_name'
                    ])

        prom_metric_iam_role = GaugeMetricFamily("sysdig_secure_iam_role",
                                                 'IAM roles',
                                                 labels=['sysdig_secure_iam_role_name',
                                                         'sysdig_secure_iam_role_policies_total',
                                                         'sysdig_secure_iam_permissions_given_total',
                                                         'sysdig_secure_iam_permissions_effective_total',
                                                         'sysdig_secure_iam_permissions_unused_total',
                                                         'sysdig_secure_iam_permissions_used_total',
                                                         'sysdig_secure_iam_risk_category',
                                                         'sysdig_secure_iam_risky_permissions_total',
                                                         'sysdig_secure_iam_risk_score',
                                                         'sysdig_secure_iam_excessive_risk_category',
                                                         'sysdig_secure_iam_execssive_risky_permissions_total',
                                                         'sysdig_secure_iam_excessive_risk_score',
                                                         'sysdig_secure_iam_role_risk_admin',
                                                         'sysdig_secure_iam_role_risk_inactive',
                                                         'sysdig_secure_iam_role_risk_no_mfa',
                                                         'sysdig_secure_iam_role_risk_key1_not_rotated',
                                                         'sysdig_secure_iam_role_risk_key2_not_rotated',
                                                         'sysdig_secure_iam_role_risk_multiple_keys',
                                                         'sysdig_secure_customer_name'
                                                         ])

        prom_metric_iam_role_permissions_given_total = GaugeMetricFamily("sysdig_secure_iam_role_permissions_given_total",
                                                 'IAM roles permissions total',
                                                 labels=['sysdig_secure_iam_role_name',
                                                         'sysdig_secure_iam_role_policies_total',
                                                         'sysdig_secure_iam_risk_category',
                                                         'sysdig_secure_iam_excessive_risk_category',
                                                         'sysdig_secure_iam_role_risk_admin',
                                                         'sysdig_secure_iam_role_risk_inactive',
                                                         'sysdig_secure_iam_role_risk_no_mfa',
                                                         'sysdig_secure_iam_role_risk_key1_not_rotated',
                                                         'sysdig_secure_iam_role_risk_key2_not_rotated',
                                                         'sysdig_secure_iam_role_risk_multiple_keys',
                                                         'sysdig_secure_customer_name'
                                                         ])

        prom_metric_iam_role_permissions_unused_total = GaugeMetricFamily(
            "sysdig_secure_iam_role_permissions_unused_total",
            'IAM roles permissions unused',
            labels=['sysdig_secure_iam_role_name',
                    'sysdig_secure_iam_role_policies_total',
                    'sysdig_secure_iam_risk_category',
                    'sysdig_secure_iam_excessive_risk_category',
                    'sysdig_secure_iam_role_risk_admin',
                    'sysdig_secure_iam_role_risk_inactive',
                    'sysdig_secure_iam_role_risk_no_mfa',
                    'sysdig_secure_iam_role_risk_key1_not_rotated',
                    'sysdig_secure_iam_role_risk_key2_not_rotated',
                    'sysdig_secure_iam_role_risk_multiple_keys',
                    'sysdig_secure_customer_name'
                    ])

        curr_date = datetime.now()
        curr_date_str = curr_date.strftime("%d/%m/%Y %H:%M")

        global total_requests

        global last_run_date
        global last_run_date_str
        global first_time_running

        global scanning_prom_exp_metrics
        global all_compliances
        global all_benchmarks
        global all_scanning_v2
        global iam_policies
        global iam_users
        global iam_roles
        global images_runtime_exploit_hasfix_inuse
        global customer_name

        next_run_date = last_run_date + timedelta(minutes=scheduled_run_minutes)
        next_run_date_str = next_run_date.strftime("%d/%m/%Y %H:%M")

        if first_time_running:
            print_info()

        print("last_run_date_str - " + last_run_date_str)
        print("curr_date_str - " + curr_date_str)
        print("next_run_date_str - " + next_run_date_str)

        if next_run_date > curr_date and not first_time_running:
            print("Skipping querying......")
            print("Returning metrics from memory ")

            if test_scanning_v2 in test_area:
                print("Scanning v2 from memory - " + str(len(all_scanning_v2)))

                total_ts = 0
                for scanning in all_scanning_v2:
                    prom_metric_scanning_v2_images_critical.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["critical"]
                    )

                    prom_metric_scanning_v2_images_high.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["high"]
                    )

                    prom_metric_scanning_v2_images_medium.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["medium"]
                    )

                    prom_metric_scanning_v2_images_low.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["low"]
                    )

                    # in use
                    prom_metric_scanning_v2_images_in_use_critical.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_critical"]
                    )

                    prom_metric_scanning_v2_images_in_use_high.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_high"]
                    )

                    prom_metric_scanning_v2_images_in_use_medium.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_medium"]
                    )

                    prom_metric_scanning_v2_images_in_use_low.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["in_use_low"]
                    )

                    prom_metric_scanning_v2_images_exploit_count.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["exploitCount"]
                    )

                    prom_metric_scanning_images_v2.add_metric(
                        [scanning["origin"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"],  scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], scanning["node_name"], str(scanning["critical"]), str(scanning["high"]),
                         str(scanning["medium"]), str(scanning["low"]), str(scanning["in_use_critical"]), str(scanning["in_use_high"]),
                         str(scanning["in_use_medium"]), str(scanning["in_use_low"]), str(scanning["exploitCount"]), customer_name],
                        len(all_scanning_v2)
                    )

                    total_ts = total_ts + 6

                for scanning in images_runtime_exploit_hasfix_inuse:
                    prom_metric_scanning_v2_images_exploit_fix_inuse_count.add_metric(
                        [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                         scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                         scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                         scanning["workload_type"], customer_name],
                        scanning["fix_exploitable_running"]
                    )

                    total_ts = total_ts + 1

                yield prom_metric_scanning_v2_images_critical
                yield prom_metric_scanning_v2_images_high
                #yield prom_metric_scanning_v2_images_medium
                #yield prom_metric_scanning_v2_images_low
                yield prom_metric_scanning_v2_images_in_use_critical
                yield prom_metric_scanning_v2_images_in_use_high
                #yield prom_metric_scanning_v2_images_in_use_medium
                #yield prom_metric_scanning_v2_images_in_use_low
                yield prom_metric_scanning_v2_images_exploit_count
                yield prom_metric_scanning_images_v2
                yield prom_metric_scanning_v2_images_exploit_fix_inuse_count

                print("Total " + str(total_ts) + " TS yielded for new scanning engine")

            if test_scanning in test_area:
                print("Scanning v1 from memory - " + str(len(scanning_prom_exp_metrics)))

                total_ts = 0
                for x in scanning_prom_exp_metrics.keys():
                    temp_string = x.split("|")
                    prom_metric_scanning_images.add_metric(
                        [temp_string[0], temp_string[1], temp_string[2], temp_string[3], temp_string[4], temp_string[5],
                         temp_string[6], temp_string[7], customer_name],
                        scanning_prom_exp_metrics[x])

                    total_ts = total_ts + 1

                yield prom_metric_scanning_images

                print("Total " + str(total_ts) + " TS yielded for old scanning engine")

            if test_compliance in test_area:
                print("Compliance from memory - " + str(len(all_compliances)))
                total_ts = total_ts + 1
                for compliance in all_compliances:
                    prom_metric_compliance_pass.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_pass"])

                    prom_metric_compliance_fail.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_fail"])

                    prom_metric_compliance_warn.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_warn"])

                    prom_metric_compliance_pass_perc.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_pass_percent"])

                    prom_metric_compliance_total.add_metric(
                        [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                         compliance["version"], compliance["platform"], compliance["family"], customer_name],
                        compliance["control_total"])

                    total_ts = total_ts + 5

                    # prom_metric_compliance_pass.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                        compliance["pass"])
                    # prom_metric_compliance_fail.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                        compliance["fail"])
                    # prom_metric_compliance_checked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                           compliance["checked"])
                    # prom_metric_compliance_unchecked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                    #                                             compliance["unchecked"])

                yield prom_metric_compliance_pass
                yield prom_metric_compliance_fail
                yield prom_metric_compliance_warn
                # yield prom_metric_compliance_total
                yield prom_metric_compliance_pass_perc

                print("Total " + str(total_ts) + " TS yielded for compliance")

            if test_benchmark in test_area:
                print("Benchmarks from memory - " + str(len(all_benchmarks)))

                total_ts = 0

                for benchmark in all_benchmarks:
                    prom_metric_benchmark_resource_pass.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["resource_pass"])
                    prom_metric_benchmark_resource_fail.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["resource_fail"])
                    prom_metric_benchmark_resource_warn.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["resource_warn"])

                    prom_metric_benchmark_control_pass.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["control_pass"])
                    prom_metric_benchmark_control_fail.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["control_fail"])
                    prom_metric_benchmark_control_warn.add_metric(
                        [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                         benchmark["node_name"], customer_name],
                        benchmark["control_warn"])

                    total_ts = total_ts + 6

                yield prom_metric_benchmark_resource_pass
                yield prom_metric_benchmark_resource_fail
                yield prom_metric_benchmark_resource_warn

                yield prom_metric_benchmark_control_pass
                yield prom_metric_benchmark_control_fail
                yield prom_metric_benchmark_control_warn

                print("Total " + str(total_ts) + " TS yielded for benchmark")

            if test_iam in test_area:
                print("iam policies from memory - " + str(len(iam_policies)))

                total_ts = 0

                for policy in iam_policies:
                    prom_metric_iam_policy.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]), str(policy["numPermissionsGiven"]), str(policy["numPermissionsUnused"]),
                         policy["riskCategory"], str(policy["riskyPermissions"]), str(policy["riskScore"]), policy["policyType"], policy["excessiveRiskCategory"],
                         str(policy["excessiveRiskyPermissions"]), str(policy["excessiveRiskScore"]), policy["customerName"]],
                        len(iam_policies)
                    )

                    prom_metric_iam_policy_perms_given_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["numPermissionsGiven"]
                    )

                    prom_metric_iam_policy_perms_unused_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["numPermissionsUnused"]
                    )

                    prom_metric_iam_policy_risky_perms_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["riskyPermissions"]
                    )

                    prom_metric_iam_policy_risk_score.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["riskScore"]
                    )

                    prom_metric_iam_policy_excessive_risky_perms_total.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["excessiveRiskyPermissions"]
                    )

                    prom_metric_iam_policy_excessive_risk_score.add_metric(
                        [policy["policyName"], str(policy["actorsTotal"]),
                         policy["riskCategory"], policy["policyType"],
                         policy["customerName"]],
                        policy["excessiveRiskScore"]
                    )

                    total_ts = total_ts + 7

                print("iam users from memory - " + str(len(iam_users)))
                for user in iam_users:
                    prom_metric_iam_user.add_metric(
                        [user["actorName"], str(user["policiesTotal"]), str(user["numPermissionsGiven"]),
                         str(user["effectivePermissionsCount"]), str(user["numPermissionsUnused"]),
                         str(user["numPermissionsUsed"]),
                         user["riskCategory"], str(user["riskyPermissions"]), str(user["riskScore"]),
                         user["excessiveRiskCategory"],
                         str(user["excessiveRiskyPermissions"]), str(user["excessiveRiskScore"]),
                         user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                         user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                        len(iam_users)
                    )

                    prom_metric_iam_user_permissions_given_total.add_metric(
                        [user["actorName"], str(user["policiesTotal"]), user["riskCategory"],
                         user["excessiveRiskCategory"],
                         user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                         user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                        user["numPermissionsGiven"]
                    )

                    prom_metric_iam_user_permissions_unused_total.add_metric(
                        [user["actorName"], str(user["policiesTotal"]), user["riskCategory"],
                         user["excessiveRiskCategory"],
                         user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                         user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                        user["numPermissionsUnused"]
                    )

                    total_ts = total_ts + 3

                print("iam roles from memory - " + str(len(iam_roles)))
                for role in iam_roles:
                    prom_metric_iam_role.add_metric(
                        [role["actorName"], str(role["policiesTotal"]), str(role["numPermissionsGiven"]),
                         str(role["effectivePermissionsCount"]), str(role["numPermissionsUnused"]),
                         str(role["numPermissionsUsed"]),
                         role["riskCategory"], str(role["riskyPermissions"]), str(role["riskScore"]),
                         role["excessiveRiskCategory"],
                         str(role["excessiveRiskyPermissions"]), str(role["excessiveRiskScore"]),
                         role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                         role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                        len(iam_roles)
                    )

                    prom_metric_iam_role_permissions_given_total.add_metric(
                        [role["actorName"], str(role["policiesTotal"]), role["riskCategory"],
                         role["excessiveRiskCategory"],
                         role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                         role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                        role["numPermissionsGiven"]
                    )

                    prom_metric_iam_role_permissions_unused_total.add_metric(
                        [role["actorName"], str(role["policiesTotal"]), role["riskCategory"],
                         role["excessiveRiskCategory"],
                         role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                         role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                        role["numPermissionsUnused"]
                    )

                    total_ts = total_ts + 3


                yield prom_metric_iam_policy
                yield prom_metric_iam_policy_perms_given_total
                yield prom_metric_iam_policy_perms_unused_total
                yield prom_metric_iam_policy_risky_perms_total
                yield prom_metric_iam_policy_risk_score
                yield prom_metric_iam_policy_excessive_risky_perms_total
                yield prom_metric_iam_policy_excessive_risk_score

                yield prom_metric_iam_user
                yield prom_metric_iam_user_permissions_given_total
                yield prom_metric_iam_user_permissions_unused_total

                yield prom_metric_iam_role
                yield prom_metric_iam_role_permissions_given_total
                yield prom_metric_iam_role_permissions_unused_total

                print("Total " + str(total_ts) + " TS yielded for iam")

            return



        # **********************************************************************

        # Using API
        # ***********************************************************************




        print("still running... waiting for the first iteration to complete. Skipping querying...")

        print("Querying metrics from Sysdig Secure Backend using APIs....")
        # ------------------------------------------------------------------------------

        first_time_running = False

        last_run_date = curr_date
        next_run_date = curr_date + timedelta(minutes=scheduled_run_minutes)

        # scanning - new
        if test_scanning_v2 in test_area:
            try:
                s_v2 = scan_v2(secure_api_token, secure_url, "yes")
                all_scanning_v2, images_runtime_exploit_hasfix_inuse = s_v2.scanning_v2_prom_exporter()
                #all_scanning_v2, images_runtime_exploit_hasfix_inuse = scanning_v2_prom_exporter()
            except Exception as ex:
                logging.error(ex)
                return

            # print("scanning_v2_prom_exp_metrics count - " + str(len(all_scanning_v2)))

            total_requests += 1
            total_ts = 0
            for scanning in all_scanning_v2:
                prom_metric_scanning_v2_images_critical.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["critical"]
                )

                prom_metric_scanning_v2_images_high.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["high"]
                )

                prom_metric_scanning_v2_images_medium.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["medium"]
                )

                prom_metric_scanning_v2_images_low.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["low"]
                )

                # in use
                prom_metric_scanning_v2_images_in_use_critical.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_critical"]
                )

                prom_metric_scanning_v2_images_in_use_high.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_high"]
                )

                prom_metric_scanning_v2_images_in_use_medium.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_medium"]
                )

                prom_metric_scanning_v2_images_in_use_low.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["in_use_low"]
                )

                prom_metric_scanning_v2_images_exploit_count.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["exploitCount"]
                )



                prom_metric_scanning_images_v2.add_metric(
                    [scanning["origin"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], scanning["node_name"], str(scanning["critical"]), str(scanning["high"]),
                     str(scanning["medium"]), str(scanning["low"]), str(scanning["in_use_critical"]),
                     str(scanning["in_use_high"]),
                     str(scanning["in_use_medium"]), str(scanning["in_use_low"]), str(scanning["exploitCount"]),
                     customer_name],
                    len(all_scanning_v2)
                )

                total_ts = total_ts + 6

            for scanning in images_runtime_exploit_hasfix_inuse:
                prom_metric_scanning_v2_images_exploit_fix_inuse_count.add_metric(
                    [scanning["imageId"], scanning["reg"], scanning["repo"], scanning["imagePullString"],
                     scanning["policyStatus"], scanning["running"], scanning["image_name"], scanning["asset_type"],
                     scanning["cluster_name"], scanning["namespace_name"], scanning["workload_name"],
                     scanning["workload_type"], customer_name],
                    scanning["fix_exploitable_running"]
                )

                total_ts = total_ts + 1


            yield prom_metric_scanning_v2_images_critical
            yield prom_metric_scanning_v2_images_high
            #yield prom_metric_scanning_v2_images_medium
            #yield prom_metric_scanning_v2_images_low
            yield prom_metric_scanning_v2_images_in_use_critical
            yield prom_metric_scanning_v2_images_in_use_high
            #yield prom_metric_scanning_v2_images_in_use_medium
            #yield prom_metric_scanning_v2_images_in_use_low
            yield prom_metric_scanning_v2_images_exploit_count
            yield prom_metric_scanning_images_v2
            yield prom_metric_scanning_v2_images_exploit_fix_inuse_count

            print("Total " + str(total_ts) + " TS yielded for new scanning engine")

        # scanning - old
        if test_scanning in test_area:
            try:
                s = scan(secure_url, secure_api_token)
                scanning_prom_exp_metrics = s.scanning_prom_exporter()
            except Exception as ex:
                logging.error(ex)
                return

            print("scanning_prom_exp_metrics count - " + str(len(scanning_prom_exp_metrics)))

            total_requests += 1

            total_ts = 0
            for x in scanning_prom_exp_metrics.keys():
                temp_string = x.split("|")
                prom_metric_scanning_images.add_metric(
                    [temp_string[0], temp_string[1], temp_string[2], temp_string[3], temp_string[4], temp_string[5],
                     temp_string[6], temp_string[7], customer_name],
                    scanning_prom_exp_metrics[x])

                total_ts = total_ts + 1
            yield prom_metric_scanning_images


            print("Total " + str(total_ts) + " TS yielded for old scanning engine")

        # compliance
        if test_compliance in test_area:

            c = comp(secure_url, secure_api_token)
            all_compliances = c.compliance_prom_exporter()

            print("all compliance count - " + str(len(all_compliances)))

            total_ts = total_ts + 1

            for compliance in all_compliances:
                prom_metric_compliance_pass.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_pass"])

                prom_metric_compliance_fail.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_fail"])

                prom_metric_compliance_warn.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_warn"])

                prom_metric_compliance_pass_perc.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_pass_percent"])

                prom_metric_compliance_total.add_metric(
                    [compliance["name"], compliance["type"], compliance["schema"], compliance["framework"],
                     compliance["version"], compliance["platform"], compliance["family"], customer_name],
                    compliance["control_total"])

                total_ts = total_ts + 5

                # prom_metric_compliance_pass.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                        compliance["pass"])
                # prom_metric_compliance_fail.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                        compliance["fail"])
                # prom_metric_compliance_checked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                           compliance["checked"])
                # prom_metric_compliance_unchecked.add_metric([compliance["standard"], compliance["compliance"], compliance["compliance_type"]],
                #                                             compliance["unchecked"])

            yield prom_metric_compliance_pass
            yield prom_metric_compliance_fail
            yield prom_metric_compliance_warn
            # yield prom_metric_compliance_total
            yield prom_metric_compliance_pass_perc

            print("Total " + str(total_ts) + " TS yielded for compliance")

        # Benchmarks

        if test_benchmark in test_area:

            b = bench(secure_url, secure_api_token)
            all_benchmarks = b.benchmark_prom_exporter()

            print("all benchmark count - " + str(len(all_benchmarks)))

            total_ts = 0

            # adding control pass, clustername, node name
            # update the code....

            for benchmark in all_benchmarks:
                prom_metric_benchmark_resource_pass.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["resource_pass"])
                prom_metric_benchmark_resource_fail.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["resource_fail"])
                prom_metric_benchmark_resource_warn.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["resource_warn"])

                prom_metric_benchmark_control_pass.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["control_pass"])
                prom_metric_benchmark_control_fail.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["control_fail"])
                prom_metric_benchmark_control_warn.add_metric(
                    [benchmark["platform"], benchmark["name"], benchmark["schema"], benchmark["cluster_name"],
                     benchmark["node_name"], customer_name],
                    benchmark["control_warn"])

                total_ts = 6

            yield prom_metric_benchmark_resource_pass
            yield prom_metric_benchmark_resource_fail
            yield prom_metric_benchmark_resource_warn

            yield prom_metric_benchmark_control_pass
            yield prom_metric_benchmark_control_fail
            yield prom_metric_benchmark_control_warn

            print("Total " + str(total_ts) + " TS yielded for benchmark")


        # iam
        if test_iam in test_area:
            try:
                i = iam_pol(secure_url, secure_api_token)
                iam_policies, iam_users, iam_roles = i.iam_prom_exporter()

            except Exception as ex:
                logging.error(ex)
                return

            print("iam policies count - " + str(len(iam_policies)))
            print("iam users count - " + str(len(iam_users)))
            print("iam roles count - " + str(len(iam_roles)))

            total_requests += 1

            for policy in iam_policies:
                prom_metric_iam_policy.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]), str(policy["numPermissionsGiven"]),
                     str(policy["numPermissionsUnused"]),
                     policy["riskCategory"], str(policy["riskyPermissions"]), str(policy["riskScore"]),
                     policy["policyType"], policy["excessiveRiskCategory"],
                     str(policy["excessiveRiskyPermissions"]), str(policy["excessiveRiskScore"]),
                     policy["customerName"]],
                    len(iam_policies)
                )

                prom_metric_iam_policy_perms_given_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["numPermissionsGiven"]
                )

                prom_metric_iam_policy_perms_unused_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["numPermissionsUnused"]
                )

                prom_metric_iam_policy_risky_perms_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["riskyPermissions"]
                )

                prom_metric_iam_policy_risk_score.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["riskScore"]
                )

                prom_metric_iam_policy_excessive_risky_perms_total.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["excessiveRiskyPermissions"]
                )

                prom_metric_iam_policy_excessive_risk_score.add_metric(
                    [policy["policyName"], str(policy["actorsTotal"]),
                     policy["riskCategory"], policy["policyType"],
                     policy["customerName"]],
                    policy["excessiveRiskScore"]
                )

            for user in iam_users:
                prom_metric_iam_user.add_metric(
                    [user["actorName"], str(user["policiesTotal"]), str(user["numPermissionsGiven"]),
                     str(user["effectivePermissionsCount"]), str(user["numPermissionsUnused"]), str(user["numPermissionsUsed"]),
                     user["riskCategory"], str(user["riskyPermissions"]), str(user["riskScore"]),
                     user["excessiveRiskCategory"],
                     str(user["excessiveRiskyPermissions"]), str(user["excessiveRiskScore"]),
                     user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                     user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                    len(iam_users)
                )

                prom_metric_iam_user_permissions_given_total.add_metric(
                    [user["actorName"], str(user["policiesTotal"]),  user["riskCategory"], user["excessiveRiskCategory"],
                     user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                     user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                    user["numPermissionsGiven"]
                )

                prom_metric_iam_user_permissions_unused_total.add_metric(
                    [user["actorName"], str(user["policiesTotal"]), user["riskCategory"], user["excessiveRiskCategory"],
                     user["admin"], user["inactive"], user["no_mfa"], user["key1_not_rotated"],
                     user["key2_not_rotated"], user["multiple_keys"], user["customerName"]],
                    user["numPermissionsUnused"]
                )

            for role in iam_roles:
                prom_metric_iam_role.add_metric(
                    [role["actorName"], str(role["policiesTotal"]), str(role["numPermissionsGiven"]),
                     str(role["effectivePermissionsCount"]), str(role["numPermissionsUnused"]), str(role["numPermissionsUsed"]),
                     role["riskCategory"], str(role["riskyPermissions"]), str(role["riskScore"]),
                     role["excessiveRiskCategory"],
                     str(role["excessiveRiskyPermissions"]), str(role["excessiveRiskScore"]),
                     role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                     role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                    len(iam_roles)
                )

                prom_metric_iam_role_permissions_given_total.add_metric(
                    [role["actorName"], str(role["policiesTotal"]),  role["riskCategory"], role["excessiveRiskCategory"],
                     role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                     role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                    role["numPermissionsGiven"]
                )

                prom_metric_iam_role_permissions_unused_total.add_metric(
                    [role["actorName"], str(role["policiesTotal"]), role["riskCategory"], role["excessiveRiskCategory"],
                     role["admin"], role["inactive"], role["no_mfa"], role["key1_not_rotated"],
                     role["key2_not_rotated"], role["multiple_keys"], role["customerName"]],
                    role["numPermissionsUnused"]
                )

            yield prom_metric_iam_policy
            yield prom_metric_iam_policy_perms_given_total
            yield prom_metric_iam_policy_perms_unused_total
            yield prom_metric_iam_policy_risky_perms_total
            yield prom_metric_iam_policy_risk_score
            yield prom_metric_iam_policy_excessive_risky_perms_total
            yield prom_metric_iam_policy_excessive_risk_score

            yield prom_metric_iam_user
            yield prom_metric_iam_user_permissions_given_total
            yield prom_metric_iam_user_permissions_unused_total

            yield prom_metric_iam_role
            yield prom_metric_iam_role_permissions_given_total
            yield prom_metric_iam_role_permissions_unused_total

            #print("Total " + str(total_ts) + " TS yielded for iam")

        first_time_running = False





'''
def query_runtime_images():
    print ("in query_runtime_images")
    auth_string = "Bearer " + secure_api_token
    url = secure_url + "/api/scanning/v1/query/containers"
    payload = {}
    headers_dict = {'Content-Type': 'application/json', 'Authorization': auth_string}
    try:
        response = requests.request("POST", url, headers=headers_dict, data=payload)
    except Exception as ex:
        logging.error("Received an exception while invoking the url: " + url)
        logging.error(ex)
        raise
    if response.status_code == 200:
        all_runtime_images = json.loads(response.text)
        all_runtime_images = all_runtime_images["images"]
        print ("total runtime images found - " + str(len(all_runtime_images)))
    else:
        logging.error("Received an error trying to get the response from: " + url)
        logging.error("Error message: " + response.text)
        raise
    return all_runtime_images
'''


def print_info():
    print("-------------------------------------")
    print("Received request to scrape prometheus metrics from:")
    print("secure_url: " + secure_url)
    print("port: " + str(prom_exp_url_port))
    print("scheduled_run_minutes: " + str(scheduled_run_minutes))
    print("customer_name: " + customer_name)
    print("Querying for: " + str(query_features_list))
    #print("fetch pipeline data = " + str(fetch_pipeline_data))
    print("-------------------------------------")


if __name__ == '__main__':
    start_http_server(prom_exp_url_port)
    REGISTRY.register(SecureMetricsCollector())
    while True:
        time.sleep(600)