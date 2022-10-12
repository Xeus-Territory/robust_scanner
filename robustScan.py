from sys import argv
from portScan import PortScan
import argparse
import pyfiglet
import time
from Wappalyzer import Wappalyzer, WebPage
import warnings
import requests
from terminaltables import SingleTable
from zapScanner import zapScanner
warnings.filterwarnings("ignore")
ascii_banner = pyfiglet.figlet_format('ROBUST SCAN')
ascii_banner_tech = pyfiglet.figlet_format('ROBUST TECH')
ascii_banner_vul_scan = pyfiglet.figlet_format('ROBUST VULN')


action_choice = ['tcp', 'udp', 'both']
port_choice = ['r', 'p']
tech_choice = ['y', 'n']
vul_scan_choice = ['y', 'n']
option_vul_scan = ['start', 'pause', 'resume', 'stop', 'status', 'result']
parser = argparse.ArgumentParser(description="Robust_Scan")
parser.add_argument('-d', '--domain', help='Domain name or ip address to scaning', required=True)
port_group = parser.add_argument_group('Range of ports to scan')
port_group.add_argument('-o', '--option', help='Option Port to scan #r: Range of ports to scan OR #p: particular port to scan', choices = port_choice, default='p')
port_group.add_argument('-p', '--port', help='Port number to scan', nargs='+',required= port_choice[1] in argv)
port_group.add_argument('-s', '--start', help='Starting of range port', required= port_choice[0] in argv)
port_group.add_argument('-e', '--end', help='End of range port', required= port_choice[0] in argv)
parser.add_argument('-pro','--protocol', help='Protocol to scan', choices = action_choice, default='tcp')
parser.add_argument('--tech', help ='Scan technology of web', required=False, choices=tech_choice)
tech_group = parser.add_argument_group('Tech Scan Options')
tech_group.add_argument('-db', help = 'Update database technology', action='store_true')
tech_group.add_argument('-https', action='store_true', help = 'Web protocol format')
tech_group.add_argument('-www', action='store_true', help = 'World Wide Web')
parser.add_argument('--vul_scan', help = 'Vulnerability Scanner with ZAP', choices = vul_scan_choice, required=False)
vul_group = parser.add_argument_group('Vuln Scan Option with ZAP')
vul_group.add_argument('-scan_name', help = 'Specify the name of the vulnerability scanner')
vul_group.add_argument('-aV', help = 'Vulnerability Scan Option with ZAP with', choices=option_vul_scan)
opt = parser.parse_args()

DOMAIN = opt.domain
PORT = opt.port
START = opt.start
END = opt.end
PROTOCOL = opt.protocol
TECH = opt.tech
VUL_SCAN_OPT = opt.vul_scan
SCAN_NAME = opt.scan_name

if (PORT != None):
    # try:
        PORT = [eval(i) for i in PORT]
        print(ascii_banner)
        start_time = time.time()
        scanner = PortScan(DOMAIN, PORT, PROTOCOL)
        scanner.port_scan()
        print('Time taken:', time.time() - start_time)
    # except OSError:
    #     print('NOT FOUND THAT PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper()))       
    #     print('Time taken:', time.time() - start_time) 
    # except:
    #     print('ERROR ON THE PROCESSING! TRY AGAIN')
    #     print('Time taken:', time.time() - start_time)
if (START != None and END != None):
    try:
        print(ascii_banner)
        start_time = time.time()
        scanner = PortScan(DOMAIN, range(int(START), int(END),1), PROTOCOL)
        scanner.port_scan_forrange()
        print('Time taken:', time.time() - start_time)
    except OSError:
        print('NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper()))
        print('Time taken:', time.time() - start_time)
    except:
        print('ERROR ON THE PROCESSING! TRY AGAIN')
        print('Time taken:', time.time() - start_time)
if (TECH == 'y'):
    try:
        print(ascii_banner_tech)
        if opt.db:
            lastest_technologies_file=requests.get('https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json')
            wappalyzer = Wappalyzer.latest(technologies_file=lastest_technologies_file)
        else:
            wappalyzer = Wappalyzer.latest()
        if opt.https and opt.www:
            url = 'https://www.' + DOMAIN
        if opt.https and not opt.www:
            url = 'https://' + DOMAIN
        if not opt.https and opt.www:
            url = 'http://www.' + DOMAIN
        if not opt.https and not opt.www:
            url = 'http://' + DOMAIN
        webpage = WebPage.new_from_url(url=url)
        report = wappalyzer.analyze_with_versions_and_categories(webpage)
        tech_report = []
        tech_report.append(['TECHNOLOGIES', 'CATEGORIES', 'VERSION'])
        # print('\t\tTECHNOLOGIES\t\t\t\tCATEGORIES\t\t\t\tVERSION')
        for i in report.keys():
            tech_report.append([i, list(report[i].values())[1][0], "" if len(list(report[i].values())[0]) == 0 else list(report[i].values())[0][0]])
            # print(f'\t\t{i:<20}\t\t\t{list(report[i].values())[1][0]:<20}\t\t\t{"" if len(list(report[i].values())[0]) == 0 else list(report[i].values())[0][0]:<20}')
        tech_report_table = SingleTable(tech_report)
        tech_report_table.title = 'Find Tech...'
        print(tech_report_table.table)
    except requests.exceptions.SSLError:
        print('REPLACE IP ADDRESS BY DNS INSTEAD !! SOME SSL CAUSE WITH IP')
if (VUL_SCAN_OPT == 'y'):
    print(ascii_banner_vul_scan)
    vul_scanner = zapScanner()
    start_time = time.time()
    
    scan_results = {}
    scan_status_list = []
    
    if opt.https and opt.www:
        url = 'https://www.' + DOMAIN
    if opt.https and not opt.www:
        url = 'https://' + DOMAIN
    if not opt.https and opt.www:
        url = 'http://www.' + DOMAIN
    if not opt.https and not opt.www:
        url = 'http://' + DOMAIN
    
    if  opt.aV == 'start':
        vul_scanner.start(scan_name=SCAN_NAME, target=url)
        time.sleep(1)
    
    if opt.aV == 'pause':
        vul_scanner.pause(scan_name=SCAN_NAME)
        time.sleep(1)
        
    if opt.aV == 'resume':
        vul_scanner.resume(scan_name=SCAN_NAME)
        time.sleep(1)  
    
    if opt.aV == 'stop':
        vul_scanner.stop(scan_name=SCAN_NAME)
        time.sleep(1)
    
    if opt.aV == 'status':
        vul_scanner.get_scan_status(scan_name=SCAN_NAME, scan_status_list=scan_status_list)
        time.sleep(1)
        vul_scanner.print_scan_status(scan_status_list)
        
    if opt.aV == 'result':
        vul_scanner.get_scan_results(scan_name=SCAN_NAME, scan_results=scan_results)
        time.sleep(1)
        vul_scanner.print_report(scan_results)

        


