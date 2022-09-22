from terminaltables import SingleTable, DoubleTable

'''
    Anything on that is really base on repo: https://github.com/vs4vijay/MultiScanner/blob/master/scanners/scanner.py
    Author: vs4vijay
'''

class Scanner:
    def __init__(self):
        pass
    
    def process_for_duplicate(self, scan_results):
        return scan_results
    
    def print_scan_status(self, scan_status_list):
        status = []
        status.append(['#', 'Scanner', 'Status'])
        count = 0
        
        for scan_status in scan_status_list:
            count += 1
            status.append([count, scan_status['scanner'], scan_status['status']])
        
        status_table = DoubleTable(status)
        status_table.title = 'Scan Status'
        print(status_table.table)
            
    def print_report(self, scan_results):
        if not scan_results:
            return False
        
        results = list(scan_results.values())
        scan_report = []
        scan_report.append([ '#', 'Vuln. Name', 'Risk', 'Severity', 'CVE/CWE ID', 'URLs', 'Desc.', 'Sol.', 'Scanner' ])
        
        count = 0
        
        for vul in sorted(results, key=lambda x: x['severity'], reverse=False):
        # for vul in results:
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
            
            # scan_report.append([count, name, risk, severity, cve_id, urls, description, solution, reported_by])
            scan_report.append([count, name, risk, severity, cve_id, 'urls', 'description', 'solution', reported_by])
            
        scan_report_table = SingleTable(scan_report)
        scan_report_table.title = 'Vuln. Alerts'
        print(scan_report_table.table)