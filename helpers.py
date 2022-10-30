severity = {
    1: "Info",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical"
}


def check_dynamic(stingray, module_id):
    modules = stingray.get_modules().json()

    for m in modules:
        if module_id == m['id'] and m['tag'] == 'sast':
            return "False"
    return "True"


def get_scan_creation_date(stingray, scan_id):
    return stingray.get_scan_info(scan_id).json()['created_at'][0:10]


def get_localization(stingray, issue_info):
    issue_data_keys_resp = stingray.get_localization_issue_data_keys()
    issue_data_keys = issue_data_keys_resp.json()

    result_string = ""
    for k, v in issue_info['items'][0]['info'].items():
        if k in issue_data_keys:
            result_string += f"{issue_data_keys[k]}: {v}\n"
        else:
            result_string += f"{k}: {v}\n"

    return result_string
