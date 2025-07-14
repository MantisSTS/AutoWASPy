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
    def get_cached_iot_security_data():
        """Get IoT Security data from cache/fallback without fetching from GitHub"""
        print("Using cached/fallback IoT Security data for project creation...")
        return IoTSecurityService._get_fallback_data()
    
    @staticmethod
    def _fetch_from_github():
        """Fetch IoT Security testing data from OWASP ISTG GitHub repository"""
        import requests
        from app.utils.datetime_utils import utc_now
        from app.models import OWASPDataCache
        from app import db
        
        # Focus on the official ISTG checklist
        checklist_url = "https://raw.githubusercontent.com/OWASP/owasp-istg/main/checklists/checklist.md"
        
        iot_tests = []
        
        try:
            response = requests.get(checklist_url, timeout=30)
            if response.status_code == 200:
                content = response.text
                tests = IoTSecurityService._parse_istg_checklist(content)
                if tests:
                    iot_tests.extend(tests)
                    print(f"Successfully parsed {len(tests)} tests from ISTG checklist")
            else:
                print(f"Failed to fetch ISTG checklist: {response.status_code}")
        except Exception as e:
            print(f"Failed to fetch ISTG checklist: {e}")
        
        # If we didn't get enough tests from the checklist, try the fallback
        if len(iot_tests) < 10:
            print("Using fallback data - not enough tests from ISTG checklist")
            fallback_tests = IoTSecurityService._get_fallback_data()
            # Merge with any tests we did get from GitHub
            all_test_ids = {test['id'] for test in iot_tests}
            for fallback_test in fallback_tests:
                if fallback_test['id'] not in all_test_ids:
                    iot_tests.append(fallback_test)
        
        # Remove duplicates based on ID
        seen_ids = set()
        unique_tests = []
        for test in iot_tests:
            if test['id'] not in seen_ids:
                seen_ids.add(test['id'])
                unique_tests.append(test)
        
        if unique_tests:
            # Update cache - use merge to update existing or create new
            try:
                cache_entry = db.session.get(OWASPDataCache, 'iot_security')
                if cache_entry:
                    # Update existing entry
                    cache_entry.last_updated = utc_now()
                    cache_entry.data_source = 'github' if len(unique_tests) > 10 else 'static'
                    cache_entry.test_count = len(unique_tests)
                else:
                    # Create new entry
                    cache_entry = OWASPDataCache(
                        data_type='iot_security',
                        last_updated=utc_now(),
                        data_source='github' if len(unique_tests) > 10 else 'static',
                        test_count=len(unique_tests)
                    )
                    db.session.add(cache_entry)
                
                db.session.commit()
                print(f"Cache updated for IoT Security: {len(unique_tests)} tests")
            except Exception as e:
                print(f"Error updating IoT Security cache: {e}")
                db.session.rollback()
            
            print(f"Successfully fetched {len(unique_tests)} IoT Security tests from ISTG GitHub")
            return unique_tests
        else:
            raise Exception("No data found in ISTG GitHub repositories")
    
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
    
    @staticmethod
    def _parse_istg_test_categories(dirs):
        """Parse ISTG test case categories to create comprehensive test cases"""
        tests = []
        
        # Map directory names to test categories
        category_mapping = {
            'data_exchange_services': 'Data Exchange Services',
            'firmware': 'Firmware Security',
            'internal_interfaces': 'Internal Interfaces',
            'memory': 'Memory Security',
            'physical_interfaces': 'Physical Interfaces',
            'processing_units': 'Processing Units',
            'user_interfaces': 'User Interfaces',
            'wireless_interfaces': 'Wireless Interfaces'
        }
        
        counter = 1
        for dir_info in dirs:
            dir_name = dir_info.get('name', '')
            if dir_name in category_mapping and dir_info.get('type') == 'dir':
                category = category_mapping[dir_name]
                
                # Create test cases for this category
                test_cases = IoTSecurityService._generate_category_test_cases(category, dir_name, counter)
                tests.extend(test_cases)
                counter += len(test_cases)
        
        return tests
    
    @staticmethod
    def _generate_category_test_cases(category, dir_name, start_counter):
        """Generate specific test cases for each ISTG category"""
        test_cases = []
        
        # Define specific test cases for each category
        category_tests = {
            'Data Exchange Services': [
                ('Authentication & Authorization', 'Verify that data exchange services implement proper authentication and authorization mechanisms.'),
                ('Data Encryption', 'Verify that data transmitted through exchange services is properly encrypted in transit.'),
                ('API Security', 'Verify that APIs used for data exchange follow secure coding practices and input validation.'),
                ('Rate Limiting', 'Verify that data exchange services implement proper rate limiting to prevent abuse.')
            ],
            'Firmware Security': [
                ('Firmware Extraction', 'Verify the ability to extract and analyze device firmware for vulnerabilities.'),
                ('Firmware Integrity', 'Verify that firmware implements integrity checking mechanisms.'),
                ('Update Mechanism', 'Verify that firmware update mechanisms are secure and authenticated.'),
                ('Code Analysis', 'Verify firmware for hardcoded credentials, backdoors, and vulnerabilities.')
            ],
            'Internal Interfaces': [
                ('Debug Interfaces', 'Verify that debug interfaces are properly secured or disabled in production.'),
                ('Internal Communication', 'Verify that internal component communication is secure and authenticated.'),
                ('Access Controls', 'Verify that internal interfaces implement proper access controls.'),
                ('Privilege Escalation', 'Verify protection against privilege escalation through internal interfaces.')
            ],
            'Memory Security': [
                ('Buffer Overflow Protection', 'Verify that the device implements buffer overflow protection mechanisms.'),
                ('Memory Corruption', 'Verify protection against memory corruption attacks.'),
                ('Sensitive Data Storage', 'Verify that sensitive data is not stored unencrypted in memory.'),
                ('Memory Leakage', 'Verify that sensitive data does not leak through memory dumps or swap files.')
            ],
            'Physical Interfaces': [
                ('UART/Serial Interfaces', 'Verify that UART and serial interfaces are properly secured.'),
                ('JTAG Interface Security', 'Verify that JTAG interfaces are disabled or properly secured.'),
                ('SPI/I2C Security', 'Verify that SPI and I2C interfaces implement proper security controls.'),
                ('Physical Tampering', 'Verify that the device detects and responds to physical tampering attempts.')
            ],
            'Processing Units': [
                ('Secure Boot', 'Verify that the device implements secure boot mechanisms.'),
                ('Hardware Security Module', 'Verify proper implementation of hardware security modules if present.'),
                ('CPU Security Features', 'Verify that CPU security features are properly enabled and configured.'),
                ('Execution Environment', 'Verify that the execution environment is properly isolated and secured.')
            ],
            'User Interfaces': [
                ('Web Interface Security', 'Verify that web-based user interfaces follow secure coding practices.'),
                ('Mobile App Security', 'Verify that companion mobile applications are properly secured.'),
                ('Authentication UI', 'Verify that user authentication interfaces implement proper security measures.'),
                ('Session Management', 'Verify that user sessions are properly managed and secured.')
            ],
            'Wireless Interfaces': [
                ('WiFi Security', 'Verify that WiFi implementations use strong encryption and authentication.'),
                ('Bluetooth Security', 'Verify that Bluetooth implementations follow security best practices.'),
                ('Radio Frequency Security', 'Verify that RF communications are properly secured and encrypted.'),
                ('Protocol Security', 'Verify that wireless protocols implement proper security measures.')
            ]
        }
        
        tests_for_category = category_tests.get(category, [
            ('General Security Test', f'Verify security controls for {category.lower()} components.')
        ])
        
        for i, (test_name, description) in enumerate(tests_for_category):
            test_id = f"ISTG-{dir_name.upper()[:3]}-{start_counter + i:03d}"
            risk_level = IoTSecurityService._determine_istg_risk_level(test_name, description)
            
            test_cases.append({
                'id': test_id,
                'title': test_name,
                'description': description,
                'category': category,
                'risk_level': risk_level
            })
        
        return test_cases
    
    @staticmethod
    def _parse_istg_checklist(content):
        """Parse ISTG checklist markdown content with proper table parsing"""
        import re
        tests = []
        
        # Split content into sections by major headers
        sections = re.split(r'\n## (.+)', content)
        
        current_category = None
        current_subcategory = None
        
        for i in range(len(sections)):
            if i % 2 == 1:  # Odd indices are section headers
                current_category = sections[i].strip()
                continue
            elif i > 0:  # Even indices are section content (except first which is preamble)
                section_content = sections[i]
                
                # Parse subsections within this category
                subsections = re.split(r'\n### (.+)', section_content)
                
                for j in range(len(subsections)):
                    if j % 2 == 1:  # Subsection headers
                        current_subcategory = subsections[j].strip()
                        continue
                    elif j >= 0:  # Subsection content
                        subcontent = subsections[j]
                        
                        # Parse markdown tables in this subsection
                        table_tests = IoTSecurityService._parse_istg_table(subcontent, current_category, current_subcategory)
                        tests.extend(table_tests)
        
        return tests
    
    @staticmethod
    def _parse_istg_table(content, category, subcategory):
        """Parse ISTG markdown table format"""
        import re
        tests = []
        
        # Look for table rows with test IDs and names
        # Format: |ISTG-XXX-XXX-001|Test Name|Status|Notes|
        table_pattern = r'\|([^|]+)\|([^|]+)\|[^|]*\|[^|]*\|'
        matches = re.findall(table_pattern, content)
        
        for match in matches:
            test_id = match[0].strip()
            test_name = match[1].strip()
            
            # Skip header rows, separators, and bold category headers
            if (test_id.startswith('Test ID') or 
                test_id.startswith('-') or 
                test_id.startswith('**') or
                test_name.startswith('**') or
                not test_id.startswith('ISTG-') or
                len(test_name) <= 5):
                continue
                
            # Only process actual test case rows (those with ISTG- prefix and real names)
            if test_id.startswith('ISTG-') and len(test_name) > 5:
                # Determine primary category from the section
                main_category = IoTSecurityService._map_istg_category(test_id, category, subcategory)
                
                # Generate description based on test name and category
                description = IoTSecurityService._generate_istg_description(test_name, main_category, test_id)
                
                # Determine risk level
                risk_level = IoTSecurityService._determine_istg_risk_level(test_name, description)
                
                tests.append({
                    'id': test_id,
                    'title': test_name,
                    'description': description,
                    'category': main_category,
                    'risk_level': risk_level
                })
        
        return tests
    
    @staticmethod
    def _map_istg_category(test_id, category, subcategory):
        """Map ISTG test ID to readable category"""
        # Extract category code from test ID (e.g., ISTG-PROC-AUTHZ-001 -> PROC)
        id_parts = test_id.split('-')
        if len(id_parts) >= 2:
            category_code = id_parts[1]
            
            category_mapping = {
                'PROC': 'Processing Units',
                'MEM': 'Memory Security',
                'FW': 'Firmware Security',
                'DES': 'Data Exchange Services',
                'INT': 'Internal Interfaces',
                'PHY': 'Physical Interfaces',
                'WRLS': 'Wireless Interfaces',
                'UI': 'User Interfaces'
            }
            
            mapped_category = category_mapping.get(category_code, category or 'IoT Security')
            
            # Add subcategory info if available
            if subcategory and subcategory not in mapped_category:
                return f"{mapped_category} - {subcategory}"
            else:
                return mapped_category
        
        return category or 'IoT Security'
    
    @staticmethod
    def _generate_istg_description(test_name, category, test_id):
        """Generate comprehensive description for ISTG test cases"""
        
        # Base descriptions for common test patterns
        if 'Unauthorized Access' in test_name:
            return f"Verify that {category.lower()} components prevent unauthorized access through proper authentication and access controls."
        elif 'Privilege Escalation' in test_name:
            return f"Verify that {category.lower()} components prevent privilege escalation attacks and maintain proper permission boundaries."
        elif 'Information' in test_name or 'Disclosure' in test_name:
            return f"Verify that {category.lower()} components do not disclose sensitive information to unauthorized parties."
        elif 'Cryptograph' in test_name or 'Encryption' in test_name:
            return f"Verify that {category.lower()} components implement strong cryptographic algorithms and proper encryption practices."
        elif 'Configuration' in test_name or 'Patch' in test_name:
            return f"Verify that {category.lower()} components are properly configured and maintained with security updates."
        elif 'Secret' in test_name:
            return f"Verify that {category.lower()} components properly protect and manage sensitive secrets and credentials."
        elif 'Business Logic' in test_name:
            return f"Verify that {category.lower()} components implement proper business logic controls and cannot be circumvented."
        elif 'Input Validation' in test_name:
            return f"Verify that {category.lower()} components properly validate and sanitize all input data."
        elif 'Injection' in test_name:
            return f"Verify that {category.lower()} components are protected against code and command injection attacks."
        elif 'Side-Channel' in test_name:
            return f"Verify that {category.lower()} components are protected against side-channel attacks and information leakage."
        elif 'Firmware' in test_name and 'Update' in test_name:
            return f"Verify that firmware update mechanisms are secure, authenticated, and implement proper integrity checking."
        elif 'Signature' in test_name:
            return f"Verify that {category.lower()} components properly validate digital signatures and implement signature verification."
        elif 'Rollback' in test_name:
            return f"Verify that {category.lower()} components implement proper rollback protection to prevent downgrade attacks."
        else:
            return f"IoT Security test for {category.lower()}: {test_name}. Verify security controls and implementation best practices."
    
    @staticmethod
    def _determine_checklist_category(item):
        """Determine category for checklist items"""
        item_lower = item.lower()
        
        if any(word in item_lower for word in ['firmware', 'update', 'software']):
            return 'Firmware Security'
        elif any(word in item_lower for word in ['network', 'wifi', 'bluetooth', 'wireless']):
            return 'Wireless Interfaces'
        elif any(word in item_lower for word in ['authentication', 'password', 'credential']):
            return 'Authentication'
        elif any(word in item_lower for word in ['data', 'encryption', 'storage']):
            return 'Data Protection'
        elif any(word in item_lower for word in ['interface', 'ui', 'web', 'mobile']):
            return 'User Interfaces'
        elif any(word in item_lower for word in ['physical', 'hardware', 'tamper']):
            return 'Physical Interfaces'
        else:
            return 'General Security'
    
    @staticmethod
    def _determine_istg_risk_level(title, description):
        """Determine risk level for ISTG test cases"""
        content = f"{title} {description}".lower()
        
        high_risk_keywords = ['authentication', 'encryption', 'credential', 'privilege', 'firmware', 'buffer overflow']
        medium_risk_keywords = ['configuration', 'logging', 'session', 'interface', 'validation']
        
        if any(word in content for word in high_risk_keywords):
            return 'high'
        elif any(word in content for word in medium_risk_keywords):
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def _extract_test_title(item):
        """Extract a concise title from checklist item"""
        # Take first part as title, clean up
        title = item.split('.')[0].split(':')[0].strip()
        if len(title) > 60:
            title = title[:60] + '...'
        return title
    
    @staticmethod
    def _categorize_istg_test(test_id):
        """Categorize ISTG test based on ID prefix"""
        if 'PROC' in test_id:
            return 'Processing Units'
        elif 'MEM' in test_id:
            return 'Memory Security'
        elif 'FW' in test_id:
            return 'Firmware Security'
        elif 'DES' in test_id:
            return 'Data Exchange Services'
        elif 'INT' in test_id:
            return 'Internal Interfaces'
        elif 'PHY' in test_id:
            return 'Physical Interfaces'
        elif 'WRLS' in test_id:
            return 'Wireless Interfaces'
        elif 'UI' in test_id:
            return 'User Interfaces'
        else:
            return 'IoT Security'
    
    @staticmethod
    def _create_istg_test_description(test_id, description, test_type):
        """Create enhanced description for ISTG test cases"""
        category = IoTSecurityService._categorize_istg_test(test_id)
        
        base_desc = description.strip()
        if len(base_desc) < 50:
            # Enhance short descriptions
            if 'AUTHZ' in test_id:
                base_desc += f" - Verify proper authorization controls for {category.lower()}"
            elif 'AUTHN' in test_id:
                base_desc += f" - Verify authentication mechanisms for {category.lower()}"
            elif 'CRYPT' in test_id:
                base_desc += f" - Verify cryptographic implementation in {category.lower()}"
            elif 'INFO' in test_id:
                base_desc += f" - Verify information disclosure protection in {category.lower()}"
            elif 'CONF' in test_id:
                base_desc += f" - Verify configuration security for {category.lower()}"
            elif 'SCRT' in test_id:
                base_desc += f" - Verify secrets management in {category.lower()}"
            elif 'LOGIC' in test_id:
                base_desc += f" - Verify business logic security in {category.lower()}"
            elif 'INPV' in test_id:
                base_desc += f" - Verify input validation in {category.lower()}"
            elif 'SIDEC' in test_id:
                base_desc += f" - Verify side-channel attack protection in {category.lower()}"
        
        return f"{base_desc} (Test Type: {test_type})" if test_type else base_desc
