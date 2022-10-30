<h1>stingray-defectdojo</h1>

**Stingray scan result to DefectDojo importer**

A small python tool for exporting [Stingray](https://stingray-mobile.ru/) scan result to [DefectDojo](https://www.defectdojo.org/) generic findings json format and then importing it to your DefectDojo project as findings import.

### Launch parameters

**Required parameters**:  
**Stingray**:
 * `--login` - Stingray login
 * `--password` - Stingray password
 * `--url` - network address for system (System url, should be with /rest, example: https://saas.stingray.ru/rest')
 * `--scan_id` - identifier of the scan to be exported
**Defect Dojo**:
 * `--dojo_url` - Url to DefectDojo server
 * `--dojo_key` - DefectDojo api v2 key
 * `--engagement_id` - DefectDojo engagement id (one project in stingray - one engagement in dojo)
  
**Optional parameters**:  
 * `--file_name` - custom name for json file to be saved locally, default: *stingray_scan*, file name will be *stingray_scan*_{scan_id}_defectDojo_format.json
 * `--dojo_environment` - DefectDojo environment for importing results. Default: ''  
Choices: Default/Development/Lab/Pre-prod/Production/Staging/Test
 * `--dojo_min_severity` - DefectDojo minimal severity. Default: 'Info'  
Choices: Info/Low/Medium/High/Critical


### Launch
Before first launch ypu should install pip packages:
```
pip install -r requirements.txt
```
Simple launch example:
```
python3 stingray-defectdojo/import_scan.py -u https://saas.stingray/rest -l admin -p P@ssw0rd -id 1337 --file_name buggen --dojo_url https://dojo.com --dojo_key D0j0S3cr3t --engagement_id 1 -env Staging
```