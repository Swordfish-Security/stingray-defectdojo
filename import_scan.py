import argparse
import json
import logging

import requests
import urllib3
from mdast_cli_core.api import mDastAPI as mDast

from helpers import check_dynamic, get_localization, get_scan_creation_date, severity


def parse_args():
    parser = argparse.ArgumentParser(
        description='get stingray scan results as generic DefectDojo json and import them.')
    parser.add_argument('--url', '-u', type=str, help='System url, should be with /rest,'
                                                      ' example: https://saas.stingray/rest', required=True)
    parser.add_argument('--login', '-l', type=str, help='System login', required=True)
    parser.add_argument('--password', '-p', type=str, help='System password', required=True)
    parser.add_argument('--scan_id', '-id', type=int, help='Scan id', required=True)
    parser.add_argument('--file_name', '-file', type=str, help='Custom file name', default='stingray_scan')
    parser.add_argument('--dojo_url', '-dojo', type=str, help='Url to DefectDojo', required=True)
    parser.add_argument('--dojo_key', '-key', type=str, help='DefectDojo api v2 key', required=True)
    parser.add_argument('--engagement_id', '-e', type=int, help='DefectDojo engagement id', required=True)
    parser.add_argument('--dojo_environment', '-env', type=str, help='DefectDojo environment', default='',
                        choices=['Default', 'Development', 'Lab', 'Pre-prod', 'Production', 'Staging', 'Test'])
    parser.add_argument('--dojo_min_severity', '-min', type=str, help='DefectDojo minimal severity', default='Info',
                        choices=['Info', 'Low', 'Medium', 'High', 'Critical'])

    arguments = parser.parse_args()

    return arguments


def get_scan(scan_id):
    logging.info('Collecting scan results..')
    dast_info = {'findings': []}
    dast_issues_resp = stingray.get_dast_issues(scan_id)
    dast_issues = dast_issues_resp.json()['results']
    logging.info(f'Found {len(dast_issues)} issues')
    for issue in dast_issues:
        get_issue_resp = stingray.get_issue_info(issue['id'])
        issue_info = get_issue_resp.json()
        rg = issue_info['project_issue']['type']['guide']
        try:
            issue_data_for_dojo = {
                "title": f"STG-{issue['id']}: {issue['title']}",
                "description": f"{issue_info['project_issue']['type']['description']}\n\nScan: "
                               f"{url.strip('/rest')}/scans/{scan_id}/defects\n\nLocalization: "
                               f"\n{get_localization(stingray, issue_info)}",
                "severity": f"{severity.get(issue_info['project_issue']['severity'])}",
                "mitigation": f"{issue_info['project_issue']['type']['requirement']}",
                "cve": f"{issue['id']}",
                "dynamic_finding": check_dynamic(stingray, issue_info['project_issue']['type']['module']),
                "references": f"{url.strip('/rest')}{rg}"
            }
            dast_info['findings'].append(issue_data_for_dojo)
        except ValueError:
            raise RuntimeError('Something goes wrong during parsing results')

    logging.info(f'{len(dast_issues)} issues was found')

    return dast_info


def import_scan_to_dojo(file_path):
    headers = {'Authorization': f'Token {dojo_api_key}'}
    data = {
        'engagement': engagement_id,
        'scan_type': 'Generic Findings Import',
        'environment': dojo_environment,
        'minimum_severity': dojo_min_severity,
        'scan_date': get_scan_creation_date(stingray, scan)

    }
    form_data = {
        'file': open(file_path, 'rb')
    }
    return requests.post(f'{dojo_url}/api/v2/import-scan/',
                         data=data, files=form_data, headers=headers, verify=False)


if __name__ == '__main__':
    # logger
    log_level = logging.INFO
    log_format = "[%(levelname)s] (%(asctime)s): %(message)s"
    logging.basicConfig(level=log_level, format=log_format)
    logging.info('Start importing Stingray scan to DefectDojo')
    urllib3.disable_warnings()

    # arguments
    args = parse_args()
    url = args.url
    login = args.login
    password = args.password
    scan = args.scan_id
    dojo_url = args.dojo_url
    dojo_api_key = args.dojo_key
    engagement_id = args.engagement_id
    dojo_environment = args.dojo_environment
    dojo_min_severity = args.dojo_min_severity
    file_name = f'{args.file_name}_{scan}_defectDojo_format.json'

    # get scan from sting
    logging.info('Logging in Stingray..')
    stingray = mDast(url, login, password)
    logging.info(f"Logged in as {stingray.current_context['username']}")
    scan_info = get_scan(scan)
    logging.info('Saving issues to json in generic DefectDojo format...')
    with open(file_name, 'w') as outfile:
        json.dump(scan_info, outfile, sort_keys=False, indent=4, ensure_ascii=False)
    logging.info(f'{file_name} with all issues for scan {scan} was successfully created')

    # import to dojo
    logging.info(f'Importing scan issues {scan} from {file_name} to engagement {engagement_id}')
    import_dojo_resp = import_scan_to_dojo(file_name)
    if import_dojo_resp.status_code == 201:
        logging.info('Success!')
    else:
        logging.info('Something went wrong')
        logging.info(f'Error - {import_dojo_resp.json()}')
