# Robust Scanner - Tool for scanner (2 versions API and desktop)
*alert: Known what you do, pentesting need to be legally, responsibility depends on you*
## Table of contents
1.[Features of the scanner (desktop version)](#features-of-the-scanner-desktop-version-collision)<br>
2.[Features of the scanner (API version)](#features-of-the-scanner-api-version-stars)<br>
3.[Step by Step to install robust_scanner](#step-by-step-to-install-robust_scanner)<br>
4.[Contributors and Note Conclusion](#note)<br>
![Alt text](inkpx-word-art.png)

    usage: robustScan.py [-h] -d DOMAIN [-pro {tcp,udp,both}] [-o {range,particular,default}] [-p PORT [PORT ...]] [-s START] [-e END] [--tech] [-db] [-https] [-www] [-v] [-sN SN]
                     [-sS {start,pause,resume,stop,status,result}]
    Robust_Scanner

    options:
    -h, --help            show this help message and exit
    -d DOMAIN, --domain DOMAIN
                            Domain name or ip address to scaning
    -pro {tcp,udp,both}, --protocol {tcp,udp,both}
                            Protocol to scan
    --tech                Scan technology of web
    -v                    Vulnerability Scanner with ZAP

    Range of ports to scan:
    -o {range,particular,default}, --option {range,particular,default}
                            option port to scan
    -p PORT [PORT ...], --port PORT [PORT ...]
                            Port number to scan
    -s START, --start START
                            Starting of range port
    -e END, --end END     End of range port

    Tech Scan OPTions:
    -db                   Update database technology
    -https                HYPERTEXT TRANSFER PROTOCOL SECURE Addons
    -www                  WORLD WIDE WEB Addons

    Vulnerability OPTion Choices Group:
    -sN SN                Specify the name of the vulnerability scanner
    -sS {start,pause,resume,stop,status,result}
                            Interaction with the vulnerability scanner
## Features of the scanner (desktop version) :collision: 
- Port Scanner - Scan port on the target server
    - Mode Scan
        - *default*: Scan port on target from 20 to 10000
        - *range*: Scan port on target from start to end (Ex: 200-10000)
        - *particular*: Scan port on target for specific port (Ex: 80-HTTP)
    - Protocol Scan
        - *tcp*: Scan port on target with TCP
        - *udp*: Scan port on target with UDP
        - *both*: Scan port on target with both TCP and UDP
- Tech Scanner - Scan Technology on the target server
- Vulnerability Scanner - Scan vulnerability on the target server with ZAP proxy
- CVE Search - Reference to vulnerability (Ex: CVE) with Technology **(Not implemented for desktop version)**
- CVE Detailed - Detailed vulnerability information of specific CVE **(Not implemented for desktop version)**

## Features of the scanner (API version) :stars: 
Port Scanner - Scan port on the target server<br>
    *parameter: option, domain, protocol, port, start, end*

        OPTION = request.args.get('option') <Obligatory> //3 mode like desktop versionV
        DOMAIN = request.args.get('domain') <Obligatory>
        PROTOCOL = request.args.get('protocol') <Obligatory>
        PORT = request.args.get('port') <Option base on option: particular>
        START = request.args.get('start') <Option base on option: range>
        END = request.args.get('end') <Option base on option: range>
Instruction

        http://<IP Or Domain name>:<port>/apiv1/robust_scanner/port_scan?option=?&domain=?&protocol=?&port=?&start=?&end=?
Result

        {
            "Infomation of Host": "Host: <Domain target> via IP address: [Ip target]", 
            "Port report": [
                [
                "80/tcp", 
                "open", 
                "http"
                ], 
                [
                "443/tcp", 
                "open", 
                "https"
                ], 
                [
                "8080/tcp", 
                "open", 
                "---"
                ]
            ]
        }
---
Tech Scanner - Scan Technology on the target server<br>
    *parameter: domain, https, www, db*

        DOMAIN = request.args.get('domain') <Obligatory>
        HTTPS = request.args.get('https') <Option: addon>
        WWW = request.args.get('www') <Option: addon>
        DB = request.args.get('db') <Option: addon>

Instruction

        http://<IP Or Domain name>:<port>/apiv1/robust_scanner/tech_scan?domain=?&https=?&www=?&db=?
Result

        {
            "Tech Report": [
                [
                "Bootstrap", 
                "UI frameworks", 
                "Can't Detect"
                ], 
                [
                "Font Awesome", 
                "Font scripts", 
                "Can't Detect"
                ], 
                [
                "Apache Tomcat", 
                "Web servers", 
                "1.1"
                ], 
                [
                "jQuery", 
                "JavaScript libraries", 
                "1.8.2"
                ], 
                [
                "Java", 
                "Programming languages", 
                "Can't Detect"
                ]
            ]
        }
        
---
CVE Search - Reference to vulnerability (Ex: CVE) with Technology cve_search<br>
    *parameter: domain, https, www, db*
    
        DOMAIN = request.args.get('domain') <Obligatory>
        HTTPS = request.args.get('https') <Option: addon>
        WWW = request.args.get('www') <Option: addon>
        DB = request.args.get('db') <Option: addon>

Instruction

        http://<IP Or Domain name>:<port>/apiv1/robust_scanner/cve_search?domain=?&https=?&www=?&db=?
Result

        {
            "CVE report": [
                [
                [
                    0, 
                    {
                    "DESC": "Ecommerce-CodeIgniter-Bootstrap before commit 56465f was discovered to contain a cross-site scripting (XSS) vulnerability via the function base_url() at /blog/blogpublish.php.", 
                    "ID": "CVE-2022-35213", 
                    "URL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-35213", 
                    "__PACKAGE": "Bootstrap"
                    }
                ]
                ]
            ]
        }
        
---
Vulnerability Scanner - Scan vulnerability on the target server with ZAP proxy <br>
    *parameter: domain, https, www, sN, sS*

        DOMAIN = request.args.get('domain') <Obligatory>
        HTTPS = request.args.get('https') <Option: addon>
        WWW = request.args.get('www') <Option: addon>
        sN = request.args.get('sN') <Obligatory>
        sS = request.args.get('sS') <Obligatory>

Instruction

        http://<IP Or Domain name>:<port>/apiv1/robust_scanner/vul_scan?domain=?&https=?&www=?&sN=?&sS=?
Result

        {
            "vul_scanner_report": "Vulnerability Scan Now"
        }
---
        {
            "vul_scanner_report": [
                {
                "scanner": "ZAP (spider_scan)", 
                "status": "COMPLETE (100%)"
                }, 
                {
                "scanner": "ZAP (passive_scan)", 
                "status": "INPROGRESS (None)"
                }, 
                {
                "scanner": "ZAP (active_scan)", 
                "status": "INPROGRESS (44%)"
                }
            ]
        }
---
        {
            "vul_scanner_report": [
                [
                1, 
                "Modern Web Application", 
                "Informational", 
                0, 
                "-1", 
                "(5 URLs) http://zero.webappsecurity.com", 
                "The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.", 
                "This is an informational alert and so no changes are required.", 
                "ZAP"
                ], 
                [
                2, 
                "Information Disclosure - Suspicious Comments", 
                "Informational", 
                0, 
                "200", 
                "(3 URLs) http://zero.webappsecurity.com/resources/js/bootstrap.min.js", 
                "The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.", 
                "Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.", 
                "ZAP"
                ]
                ]
        }

## Step by Step to install robust_scanner
1.  Clone the repository
2.  Install ZAP (Zed Attack Proxy) with the [GUI Version](https://www.zaproxy.org/) or reference the repository for information [GitHub](https://github.com/zaproxy/zaproxy)
3.  Create a new .env file for configuration settings such as ZAP proxy API Key - Open it on the API tab on ZAP GUI<br>
    Ex: `ZAP_API_KEY='xxxxxxxxx'`
4. Create `scans.json` to store the results of ZAP scan
5.  Install all required for project from requirements.txt with the following command: `pip install -r requirements.txt` (Need to install [pip](https://pip.pypa.io/en/stable/installation/) before)
6.  Run this tool with the following command: `python api.py` or `python robust_scanner`

Note: Docker version can be released on soon as it will be available

## Note:
1. Take a private your ZAP API key
2. Configure for Proxy can be locally or Proxy on Remote Server like VPS ==> `default Proxy using : locahost:8080`
3. Make issue if you meet any problems on the process using one
4. You can help me improve this project by DM me :coffee:. Hopefully contribution from your ideas
5. ...



