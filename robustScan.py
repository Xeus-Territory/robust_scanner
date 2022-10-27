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
from flask import Flask, render_template, Response, redirect, request
warnings.filterwarnings("ignore")
ascii_banner = pyfiglet.figlet_format('ROBUST SCAN')
ascii_banner_tech = pyfiglet.figlet_format('ROBUST TECH')
ascii_banner_vul_scan = pyfiglet.figlet_format('ROBUST VULN')

app = Flask(__name__)

class Scan_Tool:
    def __init__(self, SCAN_INFO):
        '''
            Initialize the Obj Scanner
        '''
        if SCAN_INFO == None:
            self.DOMAIN, self.PROTOCOL, self.MODE_SCAN_PORT, self.PORT, self.START, self.END, self.TECH_SCAN, self.DB, self.HTTPS, self.www, self.VUL_MODE, self.sN, self.sS = self.commandline_Action()
        else:
            self.DOMAIN = SCAN_INFO[0]
            self.PROTOCOL = SCAN_INFO[1]
            self.MODE_SCAN_PORT = SCAN_INFO[2]
            self.PORT = SCAN_INFO[3]
            self.START = SCAN_INFO[4]
            self.END = SCAN_INFO[5]
            self.TECH_SCAN = SCAN_INFO[6]
            self.DB = SCAN_INFO[7]
            self.HTTPS  = SCAN_INFO[8]
            self.www = SCAN_INFO[9]
            self.VUL_MODE = SCAN_INFO[10]
            self.sN = SCAN_INFO[11]
            self.sS = SCAN_INFO[12]
            
    def commandline_Action(self):
        '''
            Do Active The Commandline Tools
        '''
        PROTOCOL = ['tcp', 'udp', 'both']
        OPT_PORT = ['range', 'particular']
        OPT_VUL_SCAN = ['start', 'pause', 'resume', 'stop', 'status', 'result']
        PARSER = argparse.ArgumentParser(description="Robust_Scanner")

        ### PUBLIC PROPERTIES FOR SERVER RUN ON COMMANDS LINE ###
        ### 1. PORT_GROUP: For Port Scanner (TWICE OPTIONAL: 1. For Range 2. For Particular)

        PARSER.add_argument('-d', '--domain', help='Domain name or ip address to scaning', required=True)
        PARSER.add_argument('-pro','--protocol', help='Protocol to scan', choices = PROTOCOL, default='tcp')
        PORT_GROUP = PARSER.add_argument_group('Range of ports to scan')
        PORT_GROUP.add_argument('-o', '--option', help='option port to scan', choices = OPT_PORT, default='p')
        PORT_GROUP.add_argument('-p', '--port', help='Port number to scan', nargs='+',required= OPT_PORT[1] in argv)
        PORT_GROUP.add_argument('-s', '--start', help='Starting of range port', required= OPT_PORT[0] in argv)
        PORT_GROUP.add_argument('-e', '--end', help='End of range port', required= OPT_PORT[0] in argv)

        ### 2. TECH_GROUP: For Technical Informational On Target Domain  (OPTIONAL CHOICES)

        PARSER.add_argument('--tech', help ='Scan technology of web', required=False)
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
        OPTIONAL_VUL_SCAN = ['VUL_ZAP', 'CVE_SCAN', 'SQLi_SCAN', 'XSS_SCAN', 'OPTIONAL']
        PARSER.add_argument('-v', help = 'Vulnerability Scanner with ZAP', choices = OPTIONAL_VUL_SCAN, required=False)
        VULNER_GROUP = PARSER.add_argument_group('Vulnerability OPTion Choices Group')
        VULNER_GROUP.add_argument('-sN', help = 'Specify the name of the vulnerability scanner')
        VULNER_GROUP.add_argument('-sS', help = 'Interaction with the vulnerability scanner', choices=OPT_VUL_SCAN)
        OPT = PARSER.parse_args()
        return OPT.domain, OPT.protocol, OPT.option, OPT.port, OPT.start, OPT.end, OPT.tech, OPT.db, OPT.https, OPT.www, OPT.v, OPT.sN, OPT.sS
    
    
    def port_scanner(self, mode):
        '''
            Process for scanning port of targets FT. Victims
        '''
        pass
    
    def tech_scanner(self):
        '''
            Process for scanning technology of target FT. Victims
        '''
        pass
    
    def vul_scanner(self):
        '''
            Process for scanning vulnerability of target FT. Victims
        '''
        pass
    
    def option_choice(self):
        if self.PORT != None:
            self.port_scanner(  )

class API: 
    def __init__(self):
        pass

# if (PORT != None):
#     try:
#         PORT = [eval(i) for i in PORT]
#         print(ascii_banner)
#         start_time = time.time()
#         scanner = PortScan(DOMAIN, PORT, PROTOCOL)
#         scanner.port_scan()
#         print('Time taken:', time.time() - start_time)
#     except OSError:
#         print('NOT FOUND THAT PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper()))       
#         print('Time taken:', time.time() - start_time) 
#     except:
#         print('ERROR ON THE PROCESSING! TRY AGAIN')
#         print('Time taken:', time.time() - start_time)
# if (START != None and END != None):
#     try:
#         print(ascii_banner)
#         start_time = time.time()
#         scanner = PortScan(DOMAIN, range(int(START), int(END),1), PROTOCOL)
#         scanner.port_scan_forrange()
#         print('Time taken:', time.time() - start_time)
#     except OSError:
#         print('NOT FOUND ANY PORT WITH PROTOCOL {protocol}'.format(protocol=PROTOCOL.upper()))
#         print('Time taken:', time.time() - start_time)
#     except:
#         print('ERROR ON THE PROCESSING! TRY AGAIN')
#         print('Time taken:', time.time() - start_time)
# if (TECH == 'y'):
#     try:
#         print(ascii_banner_tech)
#         if OPT.db:
#             lastest_technologies_file=requests.get('https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json')
#             wappalyzer = Wappalyzer.latest(technologies_file=lastest_technologies_file)
#         else:
#             wappalyzer = Wappalyzer.latest()
#         if OPT.https and OPT.www:
#             url = 'https://www.' + DOMAIN
#         if OPT.https and not OPT.www:
#             url = 'https://' + DOMAIN
#         if not OPT.https and OPT.www:
#             url = 'http://www.' + DOMAIN
#         if not OPT.https and not OPT.www:
#             url = 'http://' + DOMAIN
#         webpage = WebPage.new_from_url(url=url)
#         report = wappalyzer.analyze_with_versions_and_categories(webpage)
#         tech_report = []
#         tech_report.append(['TECHNOLOGIES', 'CATEGORIES', 'VERSION'])
#         # print('\t\tTECHNOLOGIES\t\t\t\tCATEGORIES\t\t\t\tVERSION')
#         for i in report.keys():
#             tech_report.append([i, list(report[i].values())[1][0], "" if len(list(report[i].values())[0]) == 0 else list(report[i].values())[0][0]])
#             # print(f'\t\t{i:<20}\t\t\t{list(report[i].values())[1][0]:<20}\t\t\t{"" if len(list(report[i].values())[0]) == 0 else list(report[i].values())[0][0]:<20}')
#         tech_report_table = SingleTable(tech_report)
#         tech_report_table.title = 'Find Tech...'
#         print(tech_report_table.table)
#     except requests.exceptions.SSLError:
#         print('REPLACE IP ADDRESS BY DNS INSTEAD !! SOME SSL CAUSE WITH IP')
# if (VUL_SCAN_OPT == 'y'):
#     print(ascii_banner_vul_scan)
#     vul_scanner = zapScanner()
#     start_time = time.time()
    
#     scan_results = {}
#     scan_status_list = []
    
#     if OPT.https and OPT.www:
#         url = 'https://www.' + DOMAIN
#     if OPT.https and not OPT.www:
#         url = 'https://' + DOMAIN
#     if not OPT.https and OPT.www:
#         url = 'http://www.' + DOMAIN
#     if not OPT.https and not OPT.www:
#         url = 'http://' + DOMAIN
    
#     if  OPT.aV == 'start':
#         vul_scanner.start(scan_name=SCAN_NAME, target=url)
#         time.sleep(1)
    
#     if OPT.aV == 'pause':
#         vul_scanner.pause(scan_name=SCAN_NAME)
#         time.sleep(1)
        
#     if OPT.aV == 'resume':
#         vul_scanner.resume(scan_name=SCAN_NAME)
#         time.sleep(1)  
    
#     if OPT.aV == 'stop':
#         vul_scanner.stop(scan_name=SCAN_NAME)
#         time.sleep(1)
    
#     if OPT.aV == 'status':
#         vul_scanner.get_scan_status(scan_name=SCAN_NAME, scan_status_list=scan_status_list)
#         time.sleep(1)
#         vul_scanner.print_scan_status(scan_status_list)
        
#     if OPT.aV == 'result':
#         vul_scanner.get_scan_results(scan_name=SCAN_NAME, scan_results=scan_results)
#         time.sleep(1)
#         vul_scanner.print_report(scan_results)

        


