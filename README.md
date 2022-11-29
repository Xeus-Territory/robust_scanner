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
CVE Detail - CVE details for get POC or reference to this one by using `https://cve.circl.lu/`
    *parameter: id --> (This is respective for cve_id. Example: id=CVE-2022-35213*

        CVE_ID = request.args.get('id')
    
Instruction

        http://<IP Or Domain name>:<port>/apiv1/robust_scanner/detail_cve?id=?
Result

        {
        "Detail of CVE-2022-35213": {
            "Modified": "2022-08-22T18:35:00", 
            "Published": "2022-08-18T20:15:00", 
            "access": {}, 
            "assigner": "cve@mitre.org", 
            "capec": [
            {
                "id": "591", 
                "name": "Reflected XSS", 
                "prerequisites": "An application that leverages a client-side web browser with scripting enabled. An application that fail to adequately sanitize or encode untrusted input.", 
                "related_weakness": [
                "79"
                ], 
                "solutions": "Use browser technologies that do not allow client-side scripting. Utilize strict type, character, and encoding enforcement. Ensure that all user-supplied input is validated before use.", 
                "summary": "This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is \"reflected\" off a vulnerable web application and then executed by a victim's browser. The process starts with an adversary delivering a malicious script to a victim and convincing the victim to send the script to the vulnerable web application. The most common method of this is through a phishing email where the adversary embeds the malicious script with a URL that the victim then clicks on. In processing the subsequent request, the vulnerable web application incorrectly considers the malicious script as valid input and uses it to creates a reposnse that is then sent back to the victim. To launch a successful Reflected XSS attack, an adversary looks for places where user-input is used directly in the generation of a response. This often involves elements that are not expected to host scripts such as image tags (<img>), or the addition of event attibutes such as onload and onmouseover. These elements are often not subject to the same input validation, output encoding, and other content filtering and checking routines."
            }, 
            {
                "id": "209", 
                "name": "XSS Using MIME Type Mismatch", 
                "prerequisites": "The victim must follow a crafted link that references a scripting file that is mis-typed as a non-executable file. The victim's browser must detect the true type of a mis-labeled scripting file and invoke the appropriate script interpreter without first performing filtering on the content.", 
                "related_weakness": [
                "20", 
                "646", 
                "79"
                ], 
                "solutions": "", 
                "summary": "An adversary creates a file with scripting content but where the specified MIME type of the file is such that scripting is not expected. The adversary tricks the victim into accessing a URL that responds with the script file. Some browsers will detect that the specified MIME type of the file does not match the actual type of its content and will automatically switch to using an interpreter for the real content type. If the browser does not invoke script filters before doing this, the adversary's script may run on the target unsanitized, possibly revealing the victim's cookies or executing arbitrary script in their browser."
            }, 
            {
                "id": "588", 
                "name": "DOM-Based XSS", 
                "prerequisites": "An application that leverages a client-side web browser with scripting enabled. An application that manipulates the DOM via client-side scripting. An application that failS to adequately sanitize or encode untrusted input.", 
                "related_weakness": [
                "20", 
                "79", 
                "83"
                ], 
                "solutions": "Use browser technologies that do not allow client-side scripting. Utilize proper character encoding for all output produced within client-site scripts manipulating the DOM. Ensure that all user-supplied input is validated before use.", 
                "summary": "This type of attack is a form of Cross-Site Scripting (XSS) where a malicious script is inserted into the client-side HTML being parsed by a web browser. Content served by a vulnerable web application includes script code used to manipulate the Document Object Model (DOM). This script code either does not properly validate input, or does not perform proper output encoding, thus creating an opportunity for an adversary to inject a malicious script launch a XSS attack. A key distinction between other XSS attacks and DOM-based attacks is that in other XSS attacks, the malicious script runs when the vulnerable web page is initially loaded, while a DOM-based attack executes sometime after the page loads. Another distinction of DOM-based attacks is that in some cases, the malicious script is never sent to the vulnerable web server at all. An attack like this is guaranteed to bypass any server-side filtering attempts to protect users."
            }, 
            {
                "id": "592", 
                "name": "Stored XSS", 
                "prerequisites": "An application that leverages a client-side web browser with scripting enabled. An application that fails to adequately sanitize or encode untrusted input. An application that stores information provided by the user in data storage of some kind.", 
                "related_weakness": [
                "79"
                ], 
                "solutions": "Use browser technologies that do not allow client-side scripting. Utilize strict type, character, and encoding enforcement. Ensure that all user-supplied input is validated before being stored.", 
                "summary": "This type of attack is a form of Cross-site Scripting (XSS) where a malicious script is persistenly \"stored\" within the data storage of a vulnerable web application. Initially presented by an adversary to the vulnerable web application, the malicious script is incorrectly considered valid input and is not properly encoded by the web application. A victim is then convinced to use the web application in a way that creates a response that includes the malicious script. This response is subsequently sent to the victim and the malicious script is executed by the victim's browser. To launch a successful Stored XSS attack, an adversary looks for places where stored input data is used in the generation of a response. This often involves elements that are not expected to host scripts such as image tags (<img>), or the addition of event attibutes such as onload and onmouseover. These elements are often not subject to the same input validation, output encoding, and other content filtering and checking routines."
            }, 
            {
                "id": "85", 
                "name": "AJAX Fingerprinting", 
                "prerequisites": "The user must allow JavaScript to execute in their browser", 
                "related_weakness": [
                "113", 
                "116", 
                "184", 
                "20", 
                "348", 
                "692", 
                "712", 
                "79", 
                "86", 
                "96"
                ], 
                "solutions": "Design: Use browser technologies that do not allow client side scripting. Design: Utilize strict type, character, and encoding enforcement Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification. Implementation: Perform input validation for all remote content. Implementation: Perform output validation for all remote content. Implementation: Disable scripting languages such as JavaScript in browser Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.", 
                "summary": "This attack utilizes the frequent client-server roundtrips in Ajax conversation to scan a system. While Ajax does not open up new vulnerabilities per se, it does optimize them from an attacker point of view. In many XSS attacks the attacker must get a \"hole in one\" and successfully exploit the vulnerability on the victim side the first time, once the client is redirected the attacker has many chances to engage in follow on probes, but there is only one first chance. In a widely used web application this is not a major problem because 1 in a 1,000 is good enough in a widely used application. A common first step for an attacker is to footprint the environment to understand what attacks will work. Since footprinting relies on enumeration, the conversational pattern of rapid, multiple requests and responses that are typical in Ajax applications enable an attacker to look for many vulnerabilities, well-known ports, network locations and so on."
            }, 
            {
                "id": "63", 
                "name": "Cross-Site Scripting (XSS)", 
                "prerequisites": "Target client software must be a client that allows scripting communication from remote hosts, such as a JavaScript-enabled Web Browser.", 
                "related_weakness": [
                "20", 
                "79"
                ], 
                "solutions": "Design: Use browser technologies that do not allow client side scripting. Design: Utilize strict type, character, and encoding enforcement Design: Server side developers should not proxy content via XHR or other means, if a http proxy for remote content is setup on the server side, the client's browser has no way of discerning where the data is originating from. Implementation: Ensure all content that is delivered to client is sanitized against an acceptable content specification. Implementation: Perform input validation for all remote content. Implementation: Perform output validation for all remote content. Implementation: Session tokens for specific host Implementation: Patching software. There are many attack vectors for XSS on the client side and the server side. Many vulnerabilities are fixed in service packs for browser, web servers, and plug in technologies, staying current on patch release that deal with XSS countermeasures mitigates this.", 
                "summary": "An adversary embeds malicious scripts in content that will be served to web browsers. The goal of the attack is for the target software, the client-side browser, to execute the script with the users' privilege level. An attack of this type exploits a programs' vulnerabilities that are brought on by allowing remote hosts to execute code and scripts. Web browsers, for example, have some simple security controls in place, but if a remote attacker is allowed to execute scripts (through injecting them in to user-generated content like bulletin boards) then these controls may be bypassed. Further, these attacks are very difficult for an end user to detect."
            }
            ], 
            "cvss": null, 
            "cwe": "CWE-79", 
            "id": "CVE-2022-35213", 
            "impact": {}, 
            "last-modified": "2022-08-22T18:35:00", 
            "references": [
            "https://github.com/kirilkirkov/Ecommerce-CodeIgniter-Bootstrap/issues/219", 
            "https://github.com/kirilkirkov/Ecommerce-CodeIgniter-Bootstrap/commit/56465fb6a83aaa934a76615a8579100938b790a1"
            ], 
            "summary": "Ecommerce-CodeIgniter-Bootstrap before commit 56465f was discovered to contain a cross-site scripting (XSS) vulnerability via the function base_url() at /blog/blogpublish.php.", 
            "vulnerable_configuration": [
            {
                "id": "cpe:2.3:a:ecommerce-codeigniter-bootstrap_project:ecommerce-codeigniter-bootstrap:2020-08-03:*:*:*:*:*:*:*", 
                "title": "cpe:2.3:a:ecommerce-codeigniter-bootstrap_project:ecommerce-codeigniter-bootstrap:2020-08-03:*:*:*:*:*:*:*"
            }
            ], 
            "vulnerable_configuration_cpe_2_2": [], 
            "vulnerable_product": [
            "cpe:2.3:a:ecommerce-codeigniter-bootstrap_project:ecommerce-codeigniter-bootstrap:2020-08-03:*:*:*:*:*:*:*"
            ]
        }
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



