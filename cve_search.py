from pycvesearch import CVESearch
from mitrecve import crawler

CVE_SEARCH = CVESearch('https://cve.circl.lu/')

def find_cve_ref(keyword):
    try:
        cve_simple = crawler.get_main_page(keyword)
        original = list(cve_simple.items())[:10]
        processData = []
        for obj in original:
            processData.append(obj[1])
        return processData
    except:
        return 'Not find CVE ref with keyword ' + keyword
    
def detail_cve_ref(cve_id):
    try:
        cve_detail = CVE_SEARCH.id(cve_id)
        return cve_detail
    except:
        return 'Not find detail of' + cve_id
    
def detail_cve_ref_V2(cve_mitre_url):
    try:
        cve_detail = crawler.get_detail(cve_mitre_url)
        return cve_detail
    except:
        return 'Not find detail of' + cve_mitre_url