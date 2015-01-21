import json
from xml.dom import minidom
import requests
from pythonwhois import get_whois
from tldextract import tldextract


class Scanner:
    def __init__(self, config_dir='config', domain_list_filename='domain_list.json', user_agent_filename='user_agents.json', domain_list=[], verbose_save=False):
        self.config_dir = config_dir
        self.user_agents = self.read_config(user_agent_filename)
        if domain_list_filename and not domain_list:
            self.domain_list = self.read_config(domain_list_filename)
        else:
            self.domain_list = domain_list
        self.results = {}
        self.verbose_save = verbose_save

    def get_config_path(self, filename):
        file_path = '/'.join([self.config_dir, filename])
        return file_path

    def read_config(self, filename):
        path = self.get_config_path(filename)
        fp = open(path)
        data = fp.read()
        fp.close()
        parsed_data = json.loads(data)
        return parsed_data

    def get_ua(self):
        return self.user_agents[0]

    def get_headers(self):
        user_agent = self.get_ua()
        headers = {
            'User-Agent': user_agent,
        }
        return headers

    def get_crossdomain_url(self, domain, protocol='http://'):
        CROSSDOMAIN_PAGE = 'crossdomain.xml'
        url = [protocol, domain]
        if domain[-1] != '/': url.append('/')
        url.append(CROSSDOMAIN_PAGE)
        url_str = ''.join(url)
        return url_str

    def get_crossdomain_file(self, domain):
        headers = self.get_headers()
        url = self.get_crossdomain_url(domain)
        response = requests.get(url, headers=headers)
        return response

    def scan_all(self, lookup_whois=True):
        results = {domain: self.scan_and_analyze(domain, lookup_whois=lookup_whois) for domain in self.domain_list}
        self.results = results
        return results

    def scan_and_analyze(self, domain, lookup_whois=True):
        crossdomain_str = self.scan_domain(domain)
        results = self.analyze_crossdomain(crossdomain_str, lookup_whois=lookup_whois)
        return results

    def analyze_allowed_domains(self, allowed_domains, lookup_whois=True):
        extracted_domains = [tldextract.extract(domain) for domain in allowed_domains]
        naked_domains = ['.'.join([extraction.domain, extraction.suffix]) if extraction.suffix else extraction.domain for extraction in extracted_domains]
        import ipdb; ipdb.set_trace()
        wide_open = '*' in allowed_domains
        wildcard_purchasable = [domain for domain in naked_domains if '*' in domain and domain != '*'] # find fuckups like '*expediacorporate.com'
        if lookup_whois:
            purchasable = [domain for domain in naked_domains if check_domain_unowned(domain)] # makes whois request
        else:
            purchasable = [] # if lookup_whois not set then we only know we can purchase wildcard screw ups
        purchasable.extend(wildcard_purchasable)
        return wide_open, purchasable


    def analyze_crossdomain(self, crossdomain_str, lookup_whois=True):
        allowed_domains = self.extract_allowed_domains(crossdomain_str)
        wide_open, purchasable = self.analyze_allowed_domains(allowed_domains, lookup_whois=lookup_whois)
        results = (wide_open, purchasable) if not self.verbose_save else (wide_open, purchasable, crossdomain_str)
        return results


    def scan_domain(self, domain):
        try:
            response = self.get_crossdomain_file(domain)
            if response.status_code >= 400:
                crossdomain_str = None
            else:
                crossdomain_str = str(response.text)
        except:
            crossdomain_str = None
        return crossdomain_str


    def extract_allowed_domains(self, crossdomain_str):
        domains = []
        dom = minidom.parseString(crossdomain_str)
        domain_elems = dom.getElementsByTagName('allow-access-from')
        for elem in domain_elems:
            domain = elem.getAttribute('domain')
            domains.append(domain)
        return domains


def check_domain_unowned(domain):
    try:
        whois_data = get_whois(domain)
    except:
        return None
    contacts =  whois_data['contacts']
    return not contacts['admin'] and not contacts['billing'] and not contacts['registrant'] and not contacts['tech'] # should be None for unowned domain


def scan_all():
    s = Scanner()
    domain_list = s.domain_list
    results = {domain: list(s.scan_domain(domain)) for domain in domain_list}
    return json.dumps(results)

def main():
    results = scan_all()
    print(results)
    return results

if __name__ == '__main__':
    main()
