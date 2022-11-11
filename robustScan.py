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

def commandline_Action(object=None):
    '''
        Do Active The Commandline Tools
    '''
    if object is None:
        PROTOCOL = ['tcp', 'udp', 'both']
        OPT_PORT = ['range', 'particular', 'default']
        OPT_VUL_SCAN = ['start', 'pause', 'resume', 'stop', 'status', 'result']
        PARSER = argparse.ArgumentParser(description="Robust_Scanner")

        ### PUBLIC PROPERTIES FOR SERVER RUN ON COMMANDS LINE ###
        ### 1. PORT_GROUP: For Port Scanner (TWICE OPTIONAL: 1. For Range 2. For Particular)

        PARSER.add_argument('-d', '--domain', help='Domain name or ip address to scaning', required=True)
        PARSER.add_argument('-pro','--protocol', help='Protocol to scan', choices = PROTOCOL, default='tcp')
        PORT_GROUP = PARSER.add_argument_group('Range of ports to scan')
        PORT_GROUP.add_argument('-o', '--option', help='option port to scan', choices = OPT_PORT)
        PORT_GROUP.add_argument('-p', '--port', help='Port number to scan', nargs='+',required= OPT_PORT[1] in argv)
        PORT_GROUP.add_argument('-s', '--start', help='Starting of range port', required= OPT_PORT[0] in argv)
        PORT_GROUP.add_argument('-e', '--end', help='End of range port', required= OPT_PORT[0] in argv)

        ### 2. TECH_GROUP: For Technical Informational On Target Domain  (OPTIONAL CHOICES)

        PARSER.add_argument('--tech', help ='Scan technology of web', required=False, action='store_true')
        TECH_GROUP = PARSER.add_argument_group('Tech Scan OPTions')
        TECH_GROUP.add_argument('-db', help = 'Update database technology', action='store_true')
        TECH_GROUP.add_argument('-https', action='store_true', help = 'HYPERTEXT TRANSFER PROTOCOL SECURE Addons')
        TECH_GROUP.add_argument('-www', action='store_true', help = 'WORLD WIDE WEB Addons')

        '''
        ### 3. VULNER_GROUP: Contains MANY OPTION (CHOOSE THE RIGHT FOR REDUCE TIME TO SCAN) 
                I. VUL_ZAP (Using Zed Attack Proxy to attack)
                II. CVE_SCAN (JUST TRY SOME KIND CVE BUT NOT USEFUL IF WE NOT SCAN ON SOURCE)
                III. SQLi_SCAN (SCAN ERROR SQLi - TOP 10 OWASP)
                IV. XSS_SCAN (SCAN ERROR XSS - TOP 10 OWASP)
                V. OPTIONAL (CUSTOM PAYLOADS SOURCE TO DO PARTICULARLY INJECTION LIKE XXE, CSRF, ...)
        '''
        PARSER.add_argument('-v', help = 'Vulnerability Scanner with ZAP', required=False, action='store_true')
        VULNER_GROUP = PARSER.add_argument_group('Vulnerability OPTion Choices Group')
        VULNER_GROUP.add_argument('-sN', help = 'Specify the name of the vulnerability scanner')
        VULNER_GROUP.add_argument('-sS', help = 'Interaction with the vulnerability scanner', choices=OPT_VUL_SCAN)
        OPT = PARSER.parse_args()
        if OPT.option != None:
            port_scanner(OPT.option, OPT.domain, OPT.protocol, OPT.port, OPT.start, OPT.end)
        if OPT.tech != False:
            tech_scanner(OPT.db, get_url(OPT.domain, OPT.https, OPT.www))
        if OPT.v != None:
            vul_scanner(get_url(OPT.domain, OPT.https, OPT.www), OPT.sN, OPT.sS)
    


def port_scanner(MODE_SCAN_PORT, DOMAIN, PROTOCOL, PORT, START, END):
    '''
        Process for scanning port of targets FT. Victims
    '''
    if MODE_SCAN_PORT == 'default':
        try:
            start_time = time.time()
            scanner = PortScan(DOMAIN, range(20, 10000, 1), PROTOCOL)
            scanner.port_scan_forrange()
            print('Time taken:', time.time() - start_time)
        except OSError:
            print('NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper()))
            print('Time taken:', time.time() - start_time)
        except:
            print('ERROR ON THE PROCESSING! TRY AGAIN')
            print('Time taken:', time.time() - start_time)
            
    if MODE_SCAN_PORT == 'range':
        try:
            # print(ascii_banner)
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
    if MODE_SCAN_PORT == 'particular':
        try:
            PPORT = [eval(i) for i in PORT]
            # print(ascii_banner)
            start_time = time.time()
            scanner = PortScan(DOMAIN, PPORT, PROTOCOL)
            scanner.port_scan()
            print('Time taken:', time.time() - start_time)
        except OSError:
            print('NOT FOUND THAT PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper()))       
            print('Time taken:', time.time() - start_time) 
        except:
            print('ERROR ON THE PROCESSING! TRY AGAIN')
            print('Time taken:', time.time() - start_time)
        
def get_url(DOMAIN,https, www):
    if https and www:
        url = 'https://www.' + DOMAIN
    if https and not www:
        url = 'https://' + DOMAIN
    if not https and www:
        url = 'http://www.' + DOMAIN
    if not https and not www:
        url = 'http://' + DOMAIN
    return url
    
def tech_scanner(DB, URL, re_state=False):
    '''
        Process for scanning technology of target FT. Victims
    '''
    if re_state == False:
        try:
            # print(ascii_banner_tech)
            if DB:
                lastest_technologies_file=requests.get('https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json')
                wappalyzer = Wappalyzer.latest(technologies_file=lastest_technologies_file)
            else:
                wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url=URL)
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
    if re_state == True:
        try:
            # print(ascii_banner_tech)
            if DB:
                lastest_technologies_file=requests.get('https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json')
                wappalyzer = Wappalyzer.latest(technologies_file=lastest_technologies_file)
            else:
                wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url=URL)
            report = wappalyzer.analyze_with_versions_and_categories(webpage)
            tech_report = []
            for i in report.keys():
                tech_report.append([i, list(report[i].values())[1][0], "" if len(list(report[i].values())[0]) == 0 else list(report[i].values())[0][0]])
            return tech_report
        except requests.exceptions.SSLError:
            return tech_report
 
        
            

def vul_scanner(URL, sN, sS):
    '''
        Process for scanning vulnerability of target FT. Victims
    '''
    # print(ascii_banner_vul_scan)        
    vul_scanner = zapScanner()

    scan_results = {}
    scan_status_list = []
        
    if  sS == 'start':
        vul_scanner.start(scan_name=sN, target=URL)
        time.sleep(1)

    if sS == 'pause':
        vul_scanner.pause(scan_name=sN)
        time.sleep(1)
        
    if sS == 'resume':
        vul_scanner.resume(scan_name=sN)
        time.sleep(1)  

    if sS == 'stop':
        vul_scanner.stop(scan_name=sN)
        time.sleep(1)

    if sS == 'status':
        vul_scanner.get_scan_status(scan_name=sN, scan_status_list=scan_status_list)
        time.sleep(1)
        vul_scanner.print_scan_status(scan_status_list)
        
    if sS == 'result':
        vul_scanner.get_scan_results(scan_name=sN, scan_results=scan_results)
        time.sleep(1)
        vul_scanner.print_report(scan_results)
        
# commandline_Action()
    
        

        


