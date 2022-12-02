from flask import Flask, jsonify, request, abort, Response
from portScan import PortScan
from robustScan import tech_scanner, get_url
from zapScanner import zapScanner
from cve_search import find_cve_ref
from socket import gethostbyname
from cve_search import detail_cve_ref
import time
import json
from json2html import *

app = Flask(__name__)

def vul_report_convert(vul_report):
    results = list(vul_report.values())
    scan_report = []

    count = 0

    for vul in sorted(results, key=lambda x: x['severity'], reverse=False):
        count += 1
        name = vul['name']
        risk = vul['risk']
        severity = vul['severity']

        cve_id = vul.get('cweid') or vul.get('cveid', '')
        urls = list(vul.get('urls', []))
        description = vul['description']
        solution = vul['solution']
        reported_by = vul['reported_by']
        
        urls = f'({len(urls)} URLs) {urls[0]}' if urls else ''
        
        scan_report.append({
            "Count": count, 
            "NameVulnerable": name, 
            "Risk": risk, 
            "Serverity": severity, 
            "CVE-CWE ID": cve_id, 
            "URL Target": urls, 
            "Description": description, 
            "Solution": solution, 
            "Report By": reported_by
            })
    return scan_report

@app.route('/')
def home():
    data = "Welcome to API Robust_Scanner"
    return data

@app.route('/apiv1/robust_scanner/port_scan', methods=['GET'])
def port_scan_func():
    info = ""
    OPTION = request.args.get('option')
    DOMAIN = request.args.get('domain')
    PROTOCOL = request.args.get('protocol')
    PORT = request.args.get('port')
    START = request.args.get('start')
    END = request.args.get('end')

    if OPTION == 'default':
        try:            
            pScan_object = PortScan(DOMAIN, range(20, 10000, 1), PROTOCOL, re_state=True)
            info, port_report = pScan_object.port_scan_forrange()
            return jsonify({
                "Information of Host" : info,
                "Port report" : port_report  
            })
        except OSError:
            return jsonify({
                "Information of Host" : info,
                "Port report": 'NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper())
            })
        except:
            return jsonify({
                "Information of Host" : info,
                "Port report": 'ERROR ON THE PROCESSING! TRY AGAIN'
            })
    if OPTION == 'range':
        try:
            pScan_object = PortScan(DOMAIN, range(int(START), int(END),1), PROTOCOL, re_state=True)
            info, port_report = pScan_object.port_scan_forrange()
            return jsonify({
                "Information of Host" : info,
                "Port report" : port_report  
            })
        except OSError:
            return jsonify({
                "Information of Host" : info,
                "Port report": 'NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper())
            })
        except:
            return jsonify({
                "Information of Host" : info,
                "Port report": 'ERROR ON THE PROCESSING! TRY AGAIN'
            })
    if OPTION == 'particular':
        try:
            # PPORT = [eval(i) for i in PORT]
            pScan_object = PortScan(DOMAIN, int(PORT), PROTOCOL, re_state=True)
            info, port_report = pScan_object.port_scan()
            return jsonify({
                "Information of Host" : info,
                "Port report" : port_report  
            })
        except OSError:
            return jsonify({
                "Information of Host" : info,
                "Port report": 'NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper())
            })
        except:
            return jsonify({
                "Information of Host" : info,
                "Port report": 'ERROR ON THE PROCESSING! TRY AGAIN'
            })
            
@app.route('/apiv1/robust_scanner/tech_scan', methods=['GET'])
def tech_scan_func():
    DOMAIN = request.args.get('domain')
    HTTPS = request.args.get('https')
    WWW = request.args.get('www')
    DB = request.args.get('db')
    url = get_url(DOMAIN, HTTPS, WWW)
    tech_report = tech_scanner(DB, url, re_state=True)
    return jsonify({   
        "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',               
        "Tech Report" : tech_report
    })

@app.route('/apiv1/robust_scanner/cve_search', methods=['GET'])
def cve_search_func():
    DOMAIN = request.args.get('domain')
    HTTPS = request.args.get('https')
    WWW = request.args.get('www')
    DB = request.args.get('db')
    SAVE = request.args.get('save')
    sN = request.args.get('sN')
    url = get_url(DOMAIN, HTTPS, WWW)
    tech_report = tech_scanner(DB, url, re_state=True)
    cve_report = []
    for re in tech_report:
        cve_refs = find_cve_ref(re[0])
        for cve in cve_refs:
            PACKAGE = cve["__PACKAGE"]
            ID = cve["ID"]
            URL = cve["URL"]
            DESC = cve["DESC"]
            cve_report.append({
                "Package of Tech" : PACKAGE,
                "CVE_ID": ID,
                "URL of CVE": URL,
                "Description of CVE": DESC
            })
    data = {
        "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',
        "CVE report": cve_report
    }
    if SAVE != None:
        try:
            data['nameSave'] = sN + ".json" 
            json_object = json.dumps(data, indent=3)
            f = open("Data/" + sN + ".json", 'x')
            f.write(json_object)
        except:
            abort(500)
    return jsonify(data)

@app.route('/apiv1/robust_scanner/detail_cve', methods=['GET'])
def detail_cve_func():
    CVE_ID = request.args.get('id')
    return jsonify({
        f"Detail of {CVE_ID}": detail_cve_ref(CVE_ID)
    })
        
@app.route('/apiv1/robust_scanner/vul_scan', methods=['GET'])
def vul_scan_func():
    DOMAIN = request.args.get('domain')
    HTTPS = request.args.get('https')
    WWW = request.args.get('www')
    SAVE = request.args.get('save')
    sN = request.args.get('sN')
    sS = request.args.get('sS')
    
    url = get_url(DOMAIN, HTTPS, WWW)
    vul_scanner = zapScanner()
    
    vulnerable_report = {}
    scan_status_list = []
    
    if sS not in ['start', 'stop', 'resume', 'pause', 'status', 'result']:
        abort(500)
    
    if  sS == 'start':
        vul_scanner.start(scan_name=sN, target=url)
        time.sleep(1)
        return jsonify({
            "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',
            'vul_scanner_report': 'Vulnerability Scan Now'
        })

    if sS == 'pause':
        vul_scanner.pause(scan_name=sN)
        time.sleep(1)
        return jsonify({
            "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',
            'vul_scanner_report': 'Vulnerability Scan Paused' 
        })
        
    if sS == 'resume':
        vul_scanner.resume(scan_name=sN)
        time.sleep(1)
        return jsonify({
            "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',
            'vul_scanner_report': 'Vulnerability Scan Resumed'
        })  

    if sS == 'stop':
        vul_scanner.stop(scan_name=sN)
        time.sleep(1)
        return jsonify({
            "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',
            'vul_scanner_report': 'Vulnerability Scan Stopped'
        })

    if sS == 'status':
        vul_scanner.get_scan_status(scan_name=sN, scan_status_list=scan_status_list)
        time.sleep(1)
        return jsonify({
            "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',
            'vul_scanner_report': scan_status_list
        })
    
    if sS == 'result':
        vul_scanner.get_scan_results(scan_name=sN, scan_results=vulnerable_report)
        data = {
            "Information of Host" : f'Host: {DOMAIN} via IP address: {gethostbyname(DOMAIN)}',
            'vul_scanner_report': vul_report_convert(vulnerable_report)
        }
        if SAVE != None:
            try:
                data['nameSave'] = sN + ".json" 
                json_object = json.dumps(data, indent=3)
                f = open("Data/" + sN + ".json", 'x')
                f.write(json_object)
            except:
                abort(500)
        return jsonify(data)

@app.errorhandler(500)
def internal_error(error):
    return error

@app.errorhandler(404)
def notfound_error(error):
    return error

@app.route('/apiv1/robust_scanner/get_report', methods=['GET'])
def get_report():
    try:
        nameReport = request.args.get('name')
        file = open("Data/" + nameReport + '.json', 'r')
        # return json.dumps(file.read(), indent=3)
        visuallize = json2html.convert(json=file.read())
        return visuallize
    except:
        abort(500)
        
app.run(host='0.0.0.0', port=50000, debug=True)
