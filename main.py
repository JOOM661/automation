#!/usr/bin/env python3
"""
OSINT MultiTool - Ferramenta completa para investigações OSINT
Otimizada para Replit
"""

import os
import sys
import re
import json
import socket
import requests
from datetime import datetime
import dns.resolver
import whois
from bs4 import BeautifulSoup
import hashlib
import base64
from urllib.parse import urlparse, quote
import time

class Colors:
    """Cores para terminal"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class OSINTMultiTool:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def banner(self):
        """Exibe o banner da ferramenta"""
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║        {Colors.BOLD}OSINT MultiTool v1.0{Colors.END}{Colors.CYAN}                        ║
║        Ferramenta Completa de Investigação OSINT         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Colors.END}
        """
        print(banner)
    
    def menu(self):
        """Exibe o menu principal"""
        print(f"\n{Colors.BOLD}=== MENU PRINCIPAL ==={Colors.END}\n")
        print(f"{Colors.GREEN}[1]{Colors.END}  Análise de Domínio (WHOIS + DNS)")
        print(f"{Colors.GREEN}[2]{Colors.END}  Verificação de Email")
        print(f"{Colors.GREEN}[3]{Colors.END}  Análise de IP")
        print(f"{Colors.GREEN}[4]{Colors.END}  Extração de Metadados de URL")
        print(f"{Colors.GREEN}[5]{Colors.END}  Username Search (Redes Sociais)")
        print(f"{Colors.GREEN}[6]{Colors.END}  Hash Analyzer")
        print(f"{Colors.GREEN}[7]{Colors.END}  Phone Number Lookup")
        print(f"{Colors.GREEN}[8]{Colors.END}  Breach Check (HaveIBeenPwned)")
        print(f"{Colors.GREEN}[9]{Colors.END}  Subdomain Finder")
        print(f"{Colors.GREEN}[10]{Colors.END} Reverse IP Lookup")
        print(f"{Colors.GREEN}[11]{Colors.END} GitHub User Analysis")
        print(f"{Colors.GREEN}[12]{Colors.END} Google Dorks Generator")
        print(f"{Colors.FAIL}[0]{Colors.END}  Sair\n")
    
    def domain_analysis(self, domain):
        """Análise completa de domínio"""
        print(f"\n{Colors.BOLD}[*] Analisando domínio: {domain}{Colors.END}\n")
        
        # WHOIS
        try:
            print(f"{Colors.CYAN}[+] Informações WHOIS:{Colors.END}")
            w = whois.whois(domain)
            print(f"    Registrador: {w.registrar}")
            print(f"    Data de Criação: {w.creation_date}")
            print(f"    Data de Expiração: {w.expiration_date}")
            print(f"    Name Servers: {w.name_servers}")
        except Exception as e:
            print(f"{Colors.FAIL}    Erro ao obter WHOIS: {e}{Colors.END}")
        
        # DNS Records
        print(f"\n{Colors.CYAN}[+] Registros DNS:{Colors.END}")
        dns_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        for record_type in dns_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                print(f"    {record_type}:")
                for rdata in answers:
                    print(f"      - {rdata}")
            except:
                pass
        
        # SSL Certificate
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    print(f"\n{Colors.CYAN}[+] Certificado SSL:{Colors.END}")
                    print(f"    Emitido para: {cert['subject']}")
                    print(f"    Emitido por: {cert['issuer']}")
                    print(f"    Válido até: {cert['notAfter']}")
        except Exception as e:
            print(f"{Colors.FAIL}    Erro ao obter certificado SSL: {e}{Colors.END}")
    
    def email_verification(self, email):
        """Verifica informações sobre um email"""
        print(f"\n{Colors.BOLD}[*] Verificando email: {email}{Colors.END}\n")
        
        # Validação básica
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            print(f"{Colors.FAIL}[!] Email inválido{Colors.END}")
            return
        
        domain = email.split('@')[1]
        print(f"{Colors.GREEN}[+] Email válido (formato){Colors.END}")
        print(f"    Domínio: {domain}")
        
        # Verificar MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print(f"\n{Colors.CYAN}[+] Servidores MX encontrados:{Colors.END}")
            for mx in mx_records:
                print(f"    - {mx.exchange} (prioridade: {mx.preference})")
        except:
            print(f"{Colors.FAIL}[!] Nenhum servidor MX encontrado{Colors.END}")
        
        # Verificar domínios conhecidos
        common_providers = {
            'gmail.com': 'Google Gmail',
            'outlook.com': 'Microsoft Outlook',
            'hotmail.com': 'Microsoft Hotmail',
            'yahoo.com': 'Yahoo Mail',
            'protonmail.com': 'ProtonMail'
        }
        
        if domain in common_providers:
            print(f"\n{Colors.GREEN}[+] Provedor: {common_providers[domain]}{Colors.END}")
    
    def ip_analysis(self, ip):
        """Análise de endereço IP"""
        print(f"\n{Colors.BOLD}[*] Analisando IP: {ip}{Colors.END}\n")
        
        try:
            # IP Geolocation usando ip-api.com (gratuito)
            response = self.session.get(f'http://ip-api.com/json/{ip}')
            data = response.json()
            
            if data['status'] == 'success':
                print(f"{Colors.CYAN}[+] Geolocalização:{Colors.END}")
                print(f"    País: {data.get('country', 'N/A')}")
                print(f"    Região: {data.get('regionName', 'N/A')}")
                print(f"    Cidade: {data.get('city', 'N/A')}")
                print(f"    CEP: {data.get('zip', 'N/A')}")
                print(f"    ISP: {data.get('isp', 'N/A')}")
                print(f"    Organização: {data.get('org', 'N/A')}")
                print(f"    AS: {data.get('as', 'N/A')}")
                print(f"    Latitude: {data.get('lat', 'N/A')}")
                print(f"    Longitude: {data.get('lon', 'N/A')}")
                print(f"    Timezone: {data.get('timezone', 'N/A')}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erro ao obter geolocalização: {e}{Colors.END}")
        
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"\n{Colors.CYAN}[+] Reverse DNS:{Colors.END}")
            print(f"    Hostname: {hostname}")
        except:
            print(f"\n{Colors.WARNING}[!] Reverse DNS não disponível{Colors.END}")
    
    def url_metadata(self, url):
        """Extrai metadados de uma URL"""
        print(f"\n{Colors.BOLD}[*] Extraindo metadados de: {url}{Colors.END}\n")
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            print(f"{Colors.CYAN}[+] Informações da Página:{Colors.END}")
            
            # Title
            title = soup.find('title')
            if title:
                print(f"    Título: {title.string}")
            
            # Meta tags
            meta_tags = soup.find_all('meta')
            print(f"\n{Colors.CYAN}[+] Meta Tags Importantes:{Colors.END}")
            for tag in meta_tags:
                if tag.get('name') in ['description', 'keywords', 'author']:
                    print(f"    {tag.get('name')}: {tag.get('content')}")
                elif tag.get('property'):
                    print(f"    {tag.get('property')}: {tag.get('content')}")
            
            # Headers HTTP
            print(f"\n{Colors.CYAN}[+] Headers HTTP:{Colors.END}")
            important_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Set-Cookie']
            for header in important_headers:
                if header in response.headers:
                    print(f"    {header}: {response.headers[header]}")
            
            # Links externos
            links = soup.find_all('a', href=True)
            external_links = [link['href'] for link in links if link['href'].startswith('http')]
            print(f"\n{Colors.CYAN}[+] Total de links externos: {len(set(external_links))}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erro ao extrair metadados: {e}{Colors.END}")
    
    def username_search(self, username):
        """Busca username em várias redes sociais"""
        print(f"\n{Colors.BOLD}[*] Buscando username: {username}{Colors.END}\n")
        
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter/X': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'Medium': f'https://medium.com/@{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Tumblr': f'https://{username}.tumblr.com',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Spotify': f'https://open.spotify.com/user/{username}',
            'Telegram': f'https://t.me/{username}',
        }
        
        found = []
        not_found = []
        
        print(f"{Colors.CYAN}[+] Verificando plataformas...{Colors.END}\n")
        
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}[✓]{Colors.END} {platform}: {url}")
                    found.append(platform)
                else:
                    print(f"{Colors.FAIL}[✗]{Colors.END} {platform}")
                    not_found.append(platform)
                time.sleep(0.5)  # Rate limiting
            except:
                print(f"{Colors.WARNING}[?]{Colors.END} {platform} (timeout/erro)")
        
        print(f"\n{Colors.BOLD}Resumo:{Colors.END}")
        print(f"  Encontrados: {len(found)}")
        print(f"  Não encontrados: {len(not_found)}")
    
    def hash_analyzer(self, hash_string):
        """Analisa e identifica tipo de hash"""
        print(f"\n{Colors.BOLD}[*] Analisando hash: {hash_string}{Colors.END}\n")
        
        hash_length = len(hash_string)
        hash_types = {
            32: ['MD5', 'NTLM'],
            40: ['SHA-1'],
            56: ['SHA-224'],
            64: ['SHA-256'],
            96: ['SHA-384'],
            128: ['SHA-512']
        }
        
        print(f"{Colors.CYAN}[+] Comprimento: {hash_length} caracteres{Colors.END}")
        
        if hash_length in hash_types:
            print(f"{Colors.GREEN}[+] Possíveis tipos: {', '.join(hash_types[hash_length])}{Colors.END}")
        else:
            print(f"{Colors.WARNING}[!] Tipo de hash não identificado{Colors.END}")
        
        # Verificar se é hexadecimal
        if all(c in '0123456789abcdefABCDEF' for c in hash_string):
            print(f"{Colors.GREEN}[+] Formato: Hexadecimal válido{Colors.END}")
        else:
            print(f"{Colors.WARNING}[!] Não é um hash hexadecimal válido{Colors.END}")
    
    def phone_lookup(self, phone):
        """Informações básicas sobre número de telefone"""
        print(f"\n{Colors.BOLD}[*] Analisando número: {phone}{Colors.END}\n")
        
        # Remove caracteres não numéricos
        clean_phone = re.sub(r'\D', '', phone)
        
        print(f"{Colors.CYAN}[+] Número limpo: {clean_phone}{Colors.END}")
        print(f"    Dígitos: {len(clean_phone)}")
        
        # Identificar DDI básico (simplificado)
        country_codes = {
            '55': 'Brasil',
            '1': 'EUA/Canadá',
            '44': 'Reino Unido',
            '351': 'Portugal',
            '34': 'Espanha',
            '33': 'França',
            '49': 'Alemanha'
        }
        
        for code, country in country_codes.items():
            if clean_phone.startswith(code):
                print(f"{Colors.GREEN}[+] Possível país: {country} (DDI +{code}){Colors.END}")
                break
    
    def breach_check(self, email):
        """Verifica se email está em vazamentos (HaveIBeenPwned)"""
        print(f"\n{Colors.BOLD}[*] Verificando vazamentos para: {email}{Colors.END}\n")
        
        try:
            # HaveIBeenPwned API v3
            headers = {
                'User-Agent': 'OSINT-MultiTool',
            }
            response = requests.get(
                f'https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                print(f"{Colors.FAIL}[!] Email encontrado em {len(breaches)} vazamento(s):{Colors.END}\n")
                for breach in breaches[:10]:  # Limita a 10
                    print(f"    - {breach['Name']} ({breach['BreachDate']})")
                    print(f"      {breach['Description'][:100]}...")
                    print()
            elif response.status_code == 404:
                print(f"{Colors.GREEN}[+] Email não encontrado em vazamentos conhecidos!{Colors.END}")
            else:
                print(f"{Colors.WARNING}[!] Não foi possível verificar (código: {response.status_code}){Colors.END}")
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erro ao verificar: {e}{Colors.END}")
            print(f"{Colors.WARNING}[!] Nota: API pública do HIBP pode ter limitações{Colors.END}")
    
    def subdomain_finder(self, domain):
        """Encontra subdomínios usando diferentes técnicas"""
        print(f"\n{Colors.BOLD}[*] Buscando subdomínios de: {domain}{Colors.END}\n")
        
        subdomains = []
        common_subs = ['www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 'webmail', 
                      'admin', 'dev', 'staging', 'api', 'blog', 'shop', 'store']
        
        print(f"{Colors.CYAN}[+] Testando subdomínios comuns...{Colors.END}\n")
        
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                print(f"{Colors.GREEN}[✓]{Colors.END} {subdomain}")
                subdomains.append(subdomain)
            except:
                pass
            time.sleep(0.1)
        
        print(f"\n{Colors.BOLD}[+] Total encontrados: {len(subdomains)}{Colors.END}")
    
    def reverse_ip(self, ip):
        """Busca outros domínios no mesmo IP"""
        print(f"\n{Colors.BOLD}[*] Reverse IP Lookup: {ip}{Colors.END}\n")
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"{Colors.GREEN}[+] Hostname principal: {hostname}{Colors.END}")
        except:
            print(f"{Colors.WARNING}[!] Nenhum hostname encontrado{Colors.END}")
        
        print(f"\n{Colors.WARNING}[!] Para resultados completos, use serviços como:{Colors.END}")
        print(f"    - viewdns.info")
        print(f"    - hackertarget.com")
        print(f"    - yougetsignal.com")
    
    def github_analysis(self, username):
        """Analisa perfil do GitHub"""
        print(f"\n{Colors.BOLD}[*] Analisando GitHub: {username}{Colors.END}\n")
        
        try:
            # API pública do GitHub
            response = self.session.get(f'https://api.github.com/users/{username}')
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.CYAN}[+] Informações do Perfil:{Colors.END}")
                print(f"    Nome: {data.get('name', 'N/A')}")
                print(f"    Bio: {data.get('bio', 'N/A')}")
                print(f"    Localização: {data.get('location', 'N/A')}")
                print(f"    Email: {data.get('email', 'N/A')}")
                print(f"    Blog: {data.get('blog', 'N/A')}")
                print(f"    Twitter: {data.get('twitter_username', 'N/A')}")
                print(f"    Empresa: {data.get('company', 'N/A')}")
                print(f"    Repositórios públicos: {data.get('public_repos', 0)}")
                print(f"    Seguidores: {data.get('followers', 0)}")
                print(f"    Seguindo: {data.get('following', 0)}")
                print(f"    Criado em: {data.get('created_at', 'N/A')}")
                
                # Buscar repositórios
                repos_response = self.session.get(f'https://api.github.com/users/{username}/repos?per_page=5&sort=updated')
                if repos_response.status_code == 200:
                    repos = repos_response.json()
                    print(f"\n{Colors.CYAN}[+] Últimos Repositórios:{Colors.END}")
                    for repo in repos:
                        print(f"    - {repo['name']} ⭐ {repo['stargazers_count']}")
                        print(f"      {repo.get('description', 'Sem descrição')}")
            else:
                print(f"{Colors.FAIL}[!] Usuário não encontrado{Colors.END}")
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Erro: {e}{Colors.END}")
    
    def google_dorks(self, target):
        """Gera Google Dorks úteis"""
        print(f"\n{Colors.BOLD}[*] Google Dorks para: {target}{Colors.END}\n")
        
        dorks = [
            f'site:{target}',
            f'site:{target} filetype:pdf',
            f'site:{target} filetype:doc',
            f'site:{target} filetype:xls',
            f'site:{target} inurl:admin',
            f'site:{target} inurl:login',
            f'site:{target} inurl:upload',
            f'site:{target} intitle:"index of"',
            f'site:{target} ext:sql | ext:db',
            f'site:{target} ext:conf | ext:config',
            f'site:{target} ext:log',
            f'inurl:{target} intext:"password"',
            f'inurl:{target} intext:"username"',
            f'site:{target} intext:"internal use only"',
        ]
        
        print(f"{Colors.CYAN}[+] Dorks Gerados:{Colors.END}\n")
        for i, dork in enumerate(dorks, 1):
            print(f"{Colors.GREEN}{i:2d}.{Colors.END} {dork}")
        
        print(f"\n{Colors.WARNING}[!] Use com responsabilidade e ética!{Colors.END}")
    
    def run(self):
        """Loop principal da ferramenta"""
        self.banner()
        
        while True:
            self.menu()
            choice = input(f"{Colors.BOLD}Escolha uma opção: {Colors.END}").strip()
            
            if choice == '0':
                print(f"\n{Colors.GREEN}[+] Encerrando... Até logo!{Colors.END}\n")
                break
            
            elif choice == '1':
                domain = input("\nDigite o domínio: ").strip()
                self.domain_analysis(domain)
            
            elif choice == '2':
                email = input("\nDigite o email: ").strip()
                self.email_verification(email)
            
            elif choice == '3':
                ip = input("\nDigite o IP: ").strip()
                self.ip_analysis(ip)
            
            elif choice == '4':
                url = input("\nDigite a URL: ").strip()
                self.url_metadata(url)
            
            elif choice == '5':
                username = input("\nDigite o username: ").strip()
                self.username_search(username)
            
            elif choice == '6':
                hash_str = input("\nDigite o hash: ").strip()
                self.hash_analyzer(hash_str)
            
            elif choice == '7':
                phone = input("\nDigite o telefone: ").strip()
                self.phone_lookup(phone)
            
            elif choice == '8':
                email = input("\nDigite o email: ").strip()
                self.breach_check(email)
            
            elif choice == '9':
                domain = input("\nDigite o domínio: ").strip()
                self.subdomain_finder(domain)
            
            elif choice == '10':
                ip = input("\nDigite o IP: ").strip()
                self.reverse_ip(ip)
            
            elif choice == '11':
                username = input("\nDigite o username do GitHub: ").strip()
                self.github_analysis(username)
            
            elif choice == '12':
                target = input("\nDigite o domínio/target: ").strip()
                self.google_dorks(target)
            
            else:
                print(f"\n{Colors.FAIL}[!] Opção inválida!{Colors.END}")
            
            input(f"\n{Colors.BOLD}Pressione ENTER para continuar...{Colors.END}")

if __name__ == "__main__":
    try:
        tool = OSINTMultiTool()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.FAIL}[!] Interrompido pelo usuário{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Erro fatal: {e}{Colors.END}\n")
        sys.exit(1)
