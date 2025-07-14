"""
OWASP IoT Security Testing Guide service
Provides automated testing capabilities for IoT security vulnerabilities
"""

import requests
import re
import json
import socket
import ssl
from urllib.parse import urlparse
import time
import subprocess

class IoTSecurityService:
    """Service for OWASP IoT Security Testing Guide testing"""
    
    @staticmethod
    def fetch_iot_security_data():
        """
        Fetch IoT Security Testing Guide from OWASP official sources
        Returns structured test data for IoT security testing
        """
        try:
            return IoTSecurityService._fetch_from_github()
        except Exception as e:
            print(f"GitHub fetch failed: {e}, using fallback data")
            return IoTSecurityService._get_fallback_data()
    
    @staticmethod
    def _fetch_from_github():
        """Fetch IoT Security testing data from OWASP GitHub repository"""
        import requests
        from app.utils.datetime_utils import utc_now
        from app.models import OWASPDataCache
        from app import db
        
        # OWASP IoT Top 10 and IoT Security Testing repositories
        urls = [
            "https://api.github.com/repos/OWASP/IoT-Top-10/contents/2018",
            "https://raw.githubusercontent.com/OWASP/IoT-Top-10/master/2018/OWASP-IoT-Top-10-2018-final.md",
            "https://api.github.com/repos/OWASP/IoT-Security-Testing-Guide/contents",
            "https://raw.githubusercontent.com/OWASP/www-project-iot-top-10/master/tab_2018.md"
        ]
        
        iot_tests = []
        
        # Try different sources
        for url in urls:
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    if 'api.github.com' in url:
                        # GitHub API response
                        files = response.json()
                        tests = IoTSecurityService._parse_github_iot_files(files)
                        if tests:
                            iot_tests = tests
                            break
                    else:
                        # Raw markdown content
                        content = response.text
                        tests = IoTSecurityService._parse_iot_markdown(content)
                        if tests:
                            iot_tests = tests
                            break
            except Exception as e:
                print(f"Failed to fetch from {url}: {e}")
                continue
        
        if iot_tests:
            # Update cache
            cache_entry = OWASPDataCache(
                data_type='iot_security',
                last_updated=utc_now(),
                data_source='github',
                test_count=len(iot_tests)
            )
            db.session.merge(cache_entry)
            db.session.commit()
            
            print(f"Successfully fetched {len(iot_tests)} IoT Security tests from GitHub")
            return iot_tests
        else:
            raise Exception("No data found in GitHub repositories")
    
    @staticmethod
    def _parse_iot_markdown(content):
        """Parse IoT security data from markdown content"""
        import re
        
        tests = []
        
        # Patterns to match IoT Top 10 entries
        patterns = [
            r'(?:^|\n)#+\s*(I\d+)\s*[-–:]\s*(.+?)(?:\n|$)',  # I1: Weak Passwords
            r'(?:^|\n)#+\s*(\d+)\.\s*(.+?)(?:\n|$)',         # 1. Weak Passwords
            r'(?:^|\n)#+\s*(IoT\d+)\s*[-–:]\s*(.+?)(?:\n|$)' # IoT1: Weak Passwords
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.MULTILINE)
            if matches:
                for i, match in enumerate(matches[:10]):
                    item_id = match[0].strip()
                    title = match[1].strip()
                    
                    # Extract description
                    desc_pattern = rf'{re.escape(title)}.*?\n\n(.*?)(?:\n#{1,6}|\Z)'
                    desc_match = re.search(desc_pattern, content, re.DOTALL)
                    description = desc_match.group(1).strip() if desc_match else f"IoT Security issue: {title}"
                    
                    # Clean up description
                    description = re.sub(r'\n+', ' ', description)
                    description = re.sub(r'\s+', ' ', description)
                    
                    category = IoTSecurityService._determine_iot_category(title, description)
                    risk_level = IoTSecurityService._determine_iot_risk_level(title, description)
                    
                    # Normalize ID format
                    if not item_id.startswith(('I', 'IoT')):
                        item_id = f"I{item_id}"
                    
                    tests.append({
                        'id': item_id,
                        'title': title,
                        'description': description[:500] + ('...' if len(description) > 500 else ''),
                        'category': category,
                        'risk_level': risk_level
                    })
                break
        
        return tests[:10]
    
    @staticmethod
    def _parse_github_iot_files(files):
        """Parse IoT security data from GitHub API file listing"""
        tests = []
        
        # Look for numbered files or IoT-related files
        iot_files = [f for f in files if f.get('name', '').endswith('.md') and 
                    any(keyword in f.get('name', '').lower() for keyword in ['iot', 'top', '01', '02', '03'])]
        
        for i, file_info in enumerate(iot_files[:10]):
            try:
                file_url = file_info.get('download_url')
                if file_url:
                    import requests
                    response = requests.get(file_url, timeout=15)
                    if response.status_code == 200:
                        content = response.text
                        
                        # Extract title from first heading
                        title_match = re.search(r'^#\s*(.+)', content, re.MULTILINE)
                        title = title_match.group(1).strip() if title_match else f"IoT Security Issue {i+1}"
                        
                        # Clean up title
                        title = re.sub(r'^I?\d+\s*[-:\.]\s*', '', title)
                        
                        # Extract first paragraph as description
                        desc_match = re.search(r'\n\n(.+?)(?:\n\n|\Z)', content, re.DOTALL)
                        description = desc_match.group(1).strip() if desc_match else "IoT Security vulnerability"
                        description = re.sub(r'\n+', ' ', description)[:400]
                        
                        tests.append({
                            'id': f'I{i+1}:2018',
                            'title': title,
                            'description': description,
                            'category': IoTSecurityService._determine_iot_category(title, description),
                            'risk_level': 'high' if i < 4 else 'medium'
                        })
            except Exception as e:
                print(f"Error processing IoT file {file_info.get('name', 'unknown')}: {e}")
                continue
        
        return tests
    
    @staticmethod
    def _determine_iot_category(title, description):
        """Determine category based on title and description"""
        title_lower = title.lower()
        desc_lower = description.lower()
        
        if any(word in title_lower for word in ['password', 'authentication', 'credential']):
            return 'Authentication'
        elif any(word in title_lower for word in ['network', 'communication', 'protocol']):
            return 'Network Security'
        elif any(word in title_lower for word in ['interface', 'web', 'ui', 'admin']):
            return 'Interface Security'
        elif any(word in title_lower for word in ['update', 'firmware', 'software']):
            return 'Update Management'
        elif any(word in title_lower for word in ['data', 'storage', 'encryption']):
            return 'Data Protection'
        elif any(word in title_lower for word in ['privacy', 'personal', 'information']):
            return 'Privacy'
        elif any(word in title_lower for word in ['config', 'setting', 'default']):
            return 'Configuration'
        else:
            return 'Device Security'
    
    @staticmethod
    def _determine_iot_risk_level(title, description):
        """Determine risk level based on title and description"""
        title_lower = title.lower()
        
        high_risk_keywords = ['weak', 'insecure', 'unencrypted', 'default', 'hardcoded']
        medium_risk_keywords = ['insufficient', 'lack of', 'poor', 'inadequate']
        
        if any(word in title_lower for word in high_risk_keywords):
            return 'high'
        elif any(word in title_lower for word in medium_risk_keywords):
            return 'medium'
        else:
            return 'medium'
    
    @staticmethod
    def _get_fallback_data():
        """Fallback data if GitHub fetch fails"""
        return [
            {
                'id': 'I1:2018',
                'title': 'Weak, Guessable, or Hardcoded Passwords',
                'description': 'Use of easily brute-forced, publicly available, or unchangeable credentials, including backdoors in firmware or client software.',
                'category': 'Authentication',
                'risk_level': 'high'
            },
            {
                'id': 'I2:2018',
                'title': 'Insecure Network Services',
                'description': 'Unneeded or insecure network services running on the device itself, especially those exposed to the internet.',
                'category': 'Network Security',
                'risk_level': 'high'
            },
            {
                'id': 'I3:2018',
                'title': 'Insecure Ecosystem Interfaces',
                'description': 'Insecure web, backend API, cloud, or mobile interfaces in the ecosystem outside of the device.',
                'category': 'Interface Security',
                'risk_level': 'high'
            },
            {
                'id': 'I4:2018',
                'title': 'Lack of Secure Update Mechanism',
                'description': 'Lack of ability to securely update the device, including lack of firmware validation.',
                'category': 'Update Management',
                'risk_level': 'high'
            },
            {
                'id': 'I5:2018',
                'title': 'Use of Insecure or Outdated Components',
                'description': 'Use of deprecated or insecure software components/libraries that may allow the device to be compromised.',
                'category': 'Component Security',
                'risk_level': 'medium'
            },
            {
                'id': 'I6:2018',
                'title': 'Insufficient Privacy Protection',
                'description': 'User personal information stored on the device or in the ecosystem that is used insecurely.',
                'category': 'Privacy',
                'risk_level': 'medium'
            },
            {
                'id': 'I7:2018',
                'title': 'Insecure Data Transfer and Storage',
                'description': 'Lack of encryption or access control of sensitive data anywhere within the ecosystem.',
                'category': 'Data Protection',
                'risk_level': 'high'
            },
            {
                'id': 'I8:2018',
                'title': 'Lack of Device Management',
                'description': 'Lack of security support on devices deployed in production, including asset management.',
                'category': 'Device Management',
                'risk_level': 'medium'
            },
            {
                'id': 'I9:2018',
                'title': 'Insecure Default Settings',
                'description': 'Devices or systems shipped with insecure default settings or lack the ability to make the system more secure.',
                'category': 'Configuration',
                'risk_level': 'high'
            },
            {
                'id': 'I10:2018',
                'title': 'Lack of Physical Hardening',
                'description': 'Lack of physical hardening measures, allowing potential attackers to gain sensitive information.',
                'category': 'Physical Security',
                'risk_level': 'medium'
            }
        ]

    # Testing methods
    @staticmethod
    def test_weak_passwords(device_url, credentials_list=None):
        """Test for weak, guessable, or hardcoded passwords"""
        if not credentials_list:
            credentials_list = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('root', 'root'),
                ('user', 'user'),
                ('admin', ''),
                ('', 'admin')
            ]
        
        try:
            evidence = []
            
            for username, password in credentials_list:
                try:
                    # Test basic HTTP auth
                    response = requests.get(
                        device_url,
                        auth=(username, password),
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        evidence.append(f"Weak credentials found: {username}:{password}")
                        
                except:
                    continue
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Weak credentials detected: {'; '.join(evidence)}",
                    'request': f'Credential testing on {device_url}',
                    'response': f'Found {len(evidence)} weak credential pairs'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No weak credentials found in common list',
                    'request': f'Credential testing on {device_url}',
                    'response': 'Credential brute force unsuccessful'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing credentials: {str(e)}',
                'request': f'Credential test of {device_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_network_services(device_ip):
        """Test for insecure network services"""
        try:
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 5432, 6379]
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((device_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            if open_ports:
                return {
                    'result': 'info',
                    'evidence': f"Open ports detected: {', '.join(map(str, open_ports))}",
                    'request': f'Port scan of {device_ip}',
                    'response': f'Found {len(open_ports)} open ports'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No common ports open',
                    'request': f'Port scan of {device_ip}',
                    'response': 'No services detected on common ports'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error scanning ports: {str(e)}',
                'request': f'Port scan of {device_ip}',
                'response': 'Scan failed - network error'
            }

    @staticmethod
    def test_encryption(device_url):
        """Test for insecure data transfer"""
        try:
            evidence = []
            
            # Test HTTP vs HTTPS
            if device_url.startswith('http://'):
                evidence.append("Using unencrypted HTTP protocol")
            
            # Test SSL/TLS configuration
            if device_url.startswith('https://'):
                parsed_url = urlparse(device_url)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                try:
                    with socket.create_connection((parsed_url.hostname, parsed_url.port or 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                            ssl_version = ssock.version()
                            if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                evidence.append(f"Weak SSL/TLS version: {ssl_version}")
                except:
                    evidence.append("SSL/TLS connection failed - possible weak configuration")
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Encryption issues: {'; '.join(evidence)}",
                    'request': f'Encryption test of {device_url}',
                    'response': f'Found {len(evidence)} encryption weaknesses'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'Encryption appears properly configured',
                    'request': f'Encryption test of {device_url}',
                    'response': 'Strong encryption detected'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing encryption: {str(e)}',
                'request': f'Encryption test of {device_url}',
                'response': 'Test failed - connection error'
            }
