"""
OWASP IoT Security Testing Guide service
Provides automated testing capabilities for IoT security vulnerabilities
"""

import requests
import re
import json

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
            {
                'id': 'ISTG-CONF-001',
                'title': 'Configuration Security',
                'description': 'Test device configuration security and default settings.',
                'category': 'Configuration',
                'risk_level': 'medium'
            },
            {
                'id': 'ISTG-PRIV-001',
                'title': 'Privacy Protection',
                'description': 'Assess privacy controls and data protection mechanisms.',
                'category': 'Privacy',
                'risk_level': 'medium'
            },
            {
                'id': 'ISTG-WEB-001',
                'title': 'Web Interface Security',
                'description': 'Test web interfaces exposed by IoT devices for common vulnerabilities.',
                'category': 'Web Interface',
                'risk_level': 'high'
            },
            {
                'id': 'ISTG-CLOUD-001',
                'title': 'Cloud Endpoint Security',
                'description': 'Evaluate security of cloud services and APIs used by the IoT device.',
                'category': 'Cloud Integration',
                'risk_level': 'high'
            },
            {
                'id': 'ISTG-UPDATE-001',
                'title': 'Update Mechanism Security',
                'description': 'Test firmware and software update mechanisms for security vulnerabilities.',
                'category': 'Update Security',
                'risk_level': 'high'
            },
            {
                'id': 'ISTG-NET-001',
                'title': 'Network Services Security',
                'description': 'Assess security of network services running on the IoT device.',
                'category': 'Network Security',
                'risk_level': 'medium'
            }
        ]
        
        return iot_security_tests

    @staticmethod
    def test_device_discovery(target_ip):
        """Test IoT device discovery and fingerprinting"""
        try:
            # Port scan for common IoT services
            common_iot_ports = [22, 23, 80, 443, 554, 8080, 8081, 1883, 5683, 8883]
            open_ports = []
            services = []
            
            for port in common_iot_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        open_ports.append(port)
                        
                        # Try to identify service
                        service_name = socket.getservbyport(port) if port < 1024 else f"port-{port}"
                        services.append(f"{port}/{service_name}")
                    sock.close()
                except:
                    continue
            
            if open_ports:
                evidence = f"Open ports discovered: {', '.join(map(str, open_ports))}. Services: {', '.join(services)}"
                return {
                    'result': 'informational',
                    'evidence': evidence,
                    'request': f'Port scan of {target_ip}',
                    'response': f'Found {len(open_ports)} open ports'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No common IoT ports found open',
                    'request': f'Port scan of {target_ip}',
                    'response': 'No services detected'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error during device discovery: {str(e)}',
                'request': f'Port scan of {target_ip}',
                'response': 'Scan failed - connection error'
            }

    @staticmethod
    def test_default_credentials(device_url):
        """Test for default or weak credentials"""
        try:
            # Common IoT default credentials
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '12345'),
                ('root', 'root'),
                ('user', 'user'),
                ('guest', 'guest'),
                ('admin', ''),
                ('', 'admin'),
                ('admin', 'admin123'),
                ('support', 'support')
            ]
            
            evidence = []
            
            for username, password in default_creds:
                try:
                    # Try HTTP Basic Auth
                    response = requests.get(
                        device_url,
                        auth=(username, password),
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        evidence.append(f"Default credentials work: {username}:{password}")
                        
                    # Try form-based login if there's a login page
                    if 'login' in response.text.lower() or 'password' in response.text.lower():
                        login_data = {
                            'username': username,
                            'password': password,
                            'user': username,
                            'pass': password
                        }
                        
                        post_response = requests.post(
                            device_url,
                            data=login_data,
                            timeout=10,
                            verify=False
                        )
                        
                        if post_response.status_code == 200 and 'welcome' in post_response.text.lower():
                            evidence.append(f"Form login successful with: {username}:{password}")
                            
                except:
                    continue
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Default credentials found: {'; '.join(evidence)}",
                    'request': f'Authentication attempts to {device_url}',
                    'response': f'Successfully authenticated with {len(evidence)} credential pairs'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No default credentials found',
                    'request': f'Authentication attempts to {device_url}',
                    'response': 'All default credential attempts failed'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing default credentials: {str(e)}',
                'request': f'Authentication test on {device_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_firmware_version_disclosure(device_url):
        """Test for firmware version and sensitive information disclosure"""
        try:
            response = requests.get(device_url, timeout=10, verify=False)
            
            # Look for firmware/version information
            version_patterns = [
                (r'firmware[:\s]+v?(\d+\.\d+[\.\d]*)', 'Firmware version'),
                (r'version[:\s]+v?(\d+\.\d+[\.\d]*)', 'Software version'),
                (r'build[:\s]+(\d+)', 'Build number'),
                (r'model[:\s]+([A-Z0-9\-]+)', 'Device model'),
                (r'serial[:\s]+([A-Z0-9]+)', 'Serial number'),
                (r'mac[:\s]+([0-9A-F:]{17})', 'MAC address')
            ]
            
            evidence = []
            response_text = response.text
            
            for pattern, description in version_patterns:
                import re
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                if matches:
                    evidence.append(f"{description}: {', '.join(matches)}")
            
            # Check response headers
            disclosure_headers = [
                'server', 'x-powered-by', 'x-firmware-version', 
                'x-device-model', 'x-hardware-version'
            ]
            
            for header in disclosure_headers:
                if header in response.headers:
                    evidence.append(f"Header disclosure - {header}: {response.headers[header]}")
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Information disclosure detected: {'; '.join(evidence)}",
                    'request': f'GET {device_url}',
                    'response': f'Status: {response.status_code}, Found {len(evidence)} disclosures'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No obvious information disclosure detected',
                    'request': f'GET {device_url}',
                    'response': f'Status: {response.status_code}, No version info found'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing information disclosure: {str(e)}',
                'request': f'GET {device_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_insecure_communication(device_url):
        """Test for insecure communication protocols"""
        try:
            parsed_url = urlparse(device_url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            evidence = []
            
            # Test HTTP vs HTTPS
            if parsed_url.scheme == 'http':
                evidence.append("Unencrypted HTTP communication detected")
                
                # Check if HTTPS is available
                try:
                    https_response = requests.get(
                        device_url.replace('http://', 'https://'),
                        timeout=10,
                        verify=False
                    )
                    if https_response.status_code == 200:
                        evidence.append("HTTPS is available but not enforced")
                except:
                    evidence.append("HTTPS not available - only HTTP supported")
            
            # Test SSL/TLS configuration if HTTPS
            if parsed_url.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((host, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            
                            # Check for weak ciphers
                            if cipher and cipher[1] < 128:
                                evidence.append(f"Weak cipher detected: {cipher[0]} ({cipher[1]} bits)")
                            
                            # Check certificate validity
                            if cert:
                                import datetime
                                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                                if not_after < datetime.datetime.now():
                                    evidence.append("SSL certificate has expired")
                                    
                except Exception as ssl_error:
                    evidence.append(f"SSL/TLS configuration issue: {str(ssl_error)}")
            
            # Test for common insecure protocols (Telnet, FTP, etc.)
            insecure_ports = {23: 'Telnet', 21: 'FTP', 69: 'TFTP', 161: 'SNMP'}
            
            for port, protocol in insecure_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    if sock.connect_ex((host, port)) == 0:
                        evidence.append(f"Insecure protocol {protocol} detected on port {port}")
                    sock.close()
                except:
                    continue
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Insecure communication detected: {'; '.join(evidence)}",
                    'request': f'Communication analysis of {device_url}',
                    'response': f'Found {len(evidence)} security issues'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'Communication appears to be properly secured',
                    'request': f'Communication analysis of {device_url}',
                    'response': 'No insecure communication protocols detected'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing communication security: {str(e)}',
                'request': f'Communication test of {device_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_debug_interfaces(device_url):
        """Test for exposed debug interfaces and development features"""
        try:
            debug_paths = [
                '/debug', '/test', '/admin', '/dev', '/developer',
                '/console', '/shell', '/cmd', '/system', '/config',
                '/api/debug', '/api/test', '/cgi-bin/test',
                '/.env', '/robots.txt', '/sitemap.xml'
            ]
            
            evidence = []
            base_url = device_url.rstrip('/')
            
            for path in debug_paths:
                try:
                    test_url = base_url + path
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        # Check for debug-related content
                        debug_keywords = [
                            'debug', 'test', 'development', 'console',
                            'shell', 'command', 'system', 'config'
                        ]
                        
                        response_text = response.text.lower()
                        for keyword in debug_keywords:
                            if keyword in response_text:
                                evidence.append(f"Debug interface found at {path}")
                                break
                        
                        # Check for configuration files
                        if path in ['/.env', '/config']:
                            if 'password' in response_text or 'secret' in response_text:
                                evidence.append(f"Configuration file with secrets at {path}")
                                
                except:
                    continue
            
            # Test for common debug headers
            debug_headers = {
                'X-Debug': '1',
                'X-Test': 'true',
                'Debug': 'true',
                'X-Developer': '1'
            }
            
            for header, value in debug_headers.items():
                try:
                    response = requests.get(
                        device_url,
                        headers={header: value},
                        timeout=10,
                        verify=False
                    )
                    
                    if 'debug' in response.text.lower() or response.headers.get(header):
                        evidence.append(f"Debug functionality triggered by header: {header}")
                        
                except:
                    continue
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Debug interfaces found: {'; '.join(evidence)}",
                    'request': f'Debug interface scan of {device_url}',
                    'response': f'Found {len(evidence)} debug features'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No debug interfaces detected',
                    'request': f'Debug interface scan of {device_url}',
                    'response': 'No debug features found'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing debug interfaces: {str(e)}',
                'request': f'Debug test of {device_url}',
                'response': 'Request failed - connection error'
            }
