from flask import Flask, jsonify, request
from portScan import PortScan
from robustScan import tech_scanner, get_url
from zapScanner import zapScanner
from cve_search import find_cve_ref
import time

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
        
        scan_report.append([count, name, risk, severity, cve_id, urls, description, solution, reported_by])
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
                "Infomation of Host" : info,
                "Port report" : port_report  
            })
        except OSError:
            return jsonify({
                "Infomation of Host" : info,
                "Port report": 'NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper())
            })
        except:
            return jsonify({
                "Infomation of Host" : info,
                "Port report": 'ERROR ON THE PROCESSING! TRY AGAIN'
            })
    if OPTION == 'range':
        try:
            pScan_object = PortScan(DOMAIN, range(int(START), int(END),1), PROTOCOL, re_state=True)
            info, port_report = pScan_object.port_scan_forrange()
            return jsonify({
                "Infomation of Host" : info,
                "Port report" : port_report  
            })
        except OSError:
            return jsonify({
                "Infomation of Host" : info,
                "Port report": 'NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper())
            })
        except:
            return jsonify({
                "Infomation of Host" : info,
                "Port report": 'ERROR ON THE PROCESSING! TRY AGAIN'
            })
    if OPTION == 'particular':
        try:
            # PPORT = [eval(i) for i in PORT]
            pScan_object = PortScan(DOMAIN, int(PORT), PROTOCOL, re_state=True)
            info, port_report = pScan_object.port_scan()
            return jsonify({
                "Infomation of Host" : info,
                "Port report" : port_report  
            })
        except OSError:
            return jsonify({
                "Infomation of Host" : info,
                "Port report": 'NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper())
            })
        except:
            return jsonify({
                "Infomation of Host" : info,
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
        "Tech Report" : tech_report
    })

@app.route('/apiv1/robust_scanner/cve_search', methods=['GET'])
def cve_search_func():
    DOMAIN = request.args.get('domain')
    HTTPS = request.args.get('https')
    WWW = request.args.get('www')
    DB = request.args.get('db')
    url = get_url(DOMAIN, HTTPS, WWW)
    tech_report = tech_scanner(DB, url, re_state=True)
    cve_report = []
    for re in tech_report:
        cve_report.append(find_cve_ref(re[0]))
        
    return jsonify({
        "CVE report": cve_report
    })
        
@app.route('/apiv1/robust_scanner/vul_scan', methods=['GET'])
def vul_scan_func():
    DOMAIN = request.args.get('domain')
    HTTPS = request.args.get('https')
    WWW = request.args.get('www')
    sN = request.args.get('sN')
    sS = request.args.get('sS')
    
    url = get_url(DOMAIN, HTTPS, WWW)
    vul_scanner = zapScanner()
    
    vulnerable_report = {}
    scan_status_list = []
    
    if  sS == 'start':
        vul_scanner.start(scan_name=sN, target=url)
        time.sleep(1)
        return jsonify({
            'vul_scanner_report': 'Vulnerability Scan Now'
        })

    if sS == 'pause':
        vul_scanner.pause(scan_name=sN)
        time.sleep(1)
        return jsonify({
            'vul_scanner_report': 'Vulnerability Scan Paused' 
        })
        
    if sS == 'resume':
        vul_scanner.resume(scan_name=sN)
        time.sleep(1)
        return jsonify({
            'vul_scanner_report': 'Vulnerability Scan Resumed'
        })  

    if sS == 'stop':
        vul_scanner.stop(scan_name=sN)
        time.sleep(1)
        return jsonify({
            'vul_scanner_report': 'Vulnerability Scan Stopped'
        })

    if sS == 'status':
        vul_scanner.get_scan_status(scan_name=sN, scan_status_list=scan_status_list)
        time.sleep(1)
        return jsonify({
            'vul_scanner_report': scan_status_list
        })
    
    if sS == 'result':
        vul_scanner.get_scan_results(scan_name=sN, scan_results=vulnerable_report)
        return jsonify({
            'vul_scanner_report': vul_report_convert(vulnerable_report)
        })

        
app.run(host='127.0.0.1', port=50000, debug=True)
