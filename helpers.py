severity = {
    0: "Info",
    1: "Info",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical"
}


def get_scan_creation_date(stingray, scan_id):
    return stingray.get_scan_info(scan_id).json()['created_at'][0:10]


def get_localization(issue_data_keys, issue_info):
    result_string = ""
    for k, v in issue_info.items():
        if k in issue_data_keys:
            result_string += f"{issue_data_keys[k]}: {v}\n"
        else:
            result_string += f"{k}: {v}\n"

    return result_string
