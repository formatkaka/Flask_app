import requests, base64
usrPass = "admin:pass"
b64Val = base64.b64encode(usrPass)
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
res = requests.get('http://127.0.0.1:5000/', auth=HTTPBasicAuth('admin','pass'), headers={'Authorization': 'Basic %s' % b64Val}, data={}, verify=False)
print res
