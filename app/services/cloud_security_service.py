"""
Cloud Security Testing Service
Fetches from OWASP Cloud Security sources when available, otherwise uses industry best practices
"""

import requests
import re
import json
from urllib.parse import urlparse
import time

class CloudSecurityService:
    """Service for Cloud Security Testing - fetches from OWASP sources when available"""
    
    @staticmethod
    def fetch_cloud_security_data():
        """
        Fetch Cloud Security testing data from OWASP sources when available
        Falls back to industry best practices if no official OWASP content found
        """
        try:
            return CloudSecurityService._fetch_from_sources()
        except Exception as e:
            print(f"Cloud security fetch failed: {e}, using fallback data")
            return CloudSecurityService._get_fallback_data()
    
    @staticmethod
    def _fetch_from_sources():
        """Fetch cloud security data from OWASP and industry sources"""
        from app.utils.datetime_utils import utc_now
        from app.models import OWASPDataCache
        from app import db
        
        cloud_tests = []
        
        # Try to fetch from official OWASP Cloud Security sources
        urls = [
            # OWASP Cloud Native Application Security Top 10
            "https://api.github.com/repos/OWASP/www-project-cloud-native-application-security-top-10/contents",
            "https://raw.githubusercontent.com/OWASP/www-project-cloud-native-application-security-top-10/main/README.md",
            
            # OWASP Cloud Security Project
            "https://api.github.com/repos/OWASP/www-project-cloud-security/contents",
            "https://raw.githubusercontent.com/OWASP/www-project-cloud-security/main/README.md",
            
            # OWASP DevSecOps Guideline - Cloud Security
            "https://api.github.com/repos/OWASP/DevSecOpsGuideline/contents",
            "https://raw.githubusercontent.com/OWASP/DevSecOpsGuideline/main/README.md",
            
            # OWASP Kubernetes Security Testing Guide
            "https://api.github.com/repos/OWASP/www-project-kubernetes-security-testing-guide/contents",
            "https://raw.githubusercontent.com/OWASP/www-project-kubernetes-security-testing-guide/main/README.md",
            
            # OWASP Application Security Verification Standard - Cloud sections
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x22-V13-Configuration.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x21-V12-Secure-Communication.md"
        ]
        
        github_success = False
        
        for url in urls:
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    print(f"Successfully connected to {url}")
                    
                    if 'api.github.com' in url and '/contents' in url:
                        # GitHub API response - get file listing
                        files = response.json()
                        tests = CloudSecurityService._parse_cloud_contents(files)
                        if tests:
                            cloud_tests.extend(tests)
                            github_success = True
                            break
                    elif 'raw.githubusercontent.com' in url:
                        # Raw markdown content
                        content = response.text
                        tests = CloudSecurityService._parse_cloud_markdown(content)
                        if tests:
                            cloud_tests.extend(tests)
                            github_success = True
                            break
                    else:
                        # GitHub API repo response
                        repo_data = response.json()
                        tests = CloudSecurityService._parse_cloud_repo(repo_data)
                        if tests:
                            cloud_tests.extend(tests)
                            github_success = True
                            break
            except Exception as e:
                print(f"Could not fetch from {url}: {e}")
                continue
        
        # If no official OWASP source found or insufficient data, supplement with industry best practices
        if not cloud_tests or len(cloud_tests) < 5:
            print("No comprehensive OWASP cloud security data found. Using industry best practices...")
            generated_tests = CloudSecurityService._generate_industry_best_practices()
            if not cloud_tests:
                cloud_tests = generated_tests
                data_source = 'industry_standards'
            else:
                # Merge OWASP content with industry standards
                existing_ids = {test['id'] for test in cloud_tests}
                for test in generated_tests:
                    if test['id'] not in existing_ids:
                        cloud_tests.append(test)
                data_source = 'mixed'  # OWASP + industry standards
        else:
            data_source = 'github'  # Pure OWASP content
        
        if cloud_tests:
            # Update cache with appropriate data source
            cache_entry = OWASPDataCache(
                data_type='cloud_security',
                last_updated=utc_now(),
                data_source=data_source,
                test_count=len(cloud_tests)
            )
            db.session.merge(cache_entry)
            db.session.commit()
            
            source_msg = {
                'github': 'from OWASP repositories',
                'industry_standards': 'from industry best practices (no OWASP cloud guide found)',
                'mixed': 'from OWASP repositories + industry standards'
            }.get(data_source, 'from unknown source')
            
            print(f"Successfully fetched {len(cloud_tests)} Cloud Security tests {source_msg}")
            return cloud_tests
        else:
            raise Exception("No Cloud Security test data available")
    
    @staticmethod
    def _parse_cloud_repo(repo_data):
        """Parse cloud security repository data"""
        tests = []
        # Implementation for parsing cloud security repo
        # This would be similar to other OWASP parsing methods
        return tests
    
    @staticmethod
    def _parse_cloud_contents(files):
        """Parse cloud security data from GitHub contents"""
        tests = []
        
        # Look for relevant files
        relevant_files = []
        for file_info in files:
            filename = file_info.get('name', '').lower()
            if any(keyword in filename for keyword in ['readme', 'top', 'security', 'checklist', 'guide']):
                relevant_files.append(file_info)
        
        # Process relevant files
        for file_info in relevant_files[:3]:  # Limit to first 3 files
            try:
                download_url = file_info.get('download_url')
                if download_url:
                    response = requests.get(download_url, timeout=15)
                    if response.status_code == 200:
                        content = response.text
                        file_tests = CloudSecurityService._parse_cloud_markdown(content)
                        if file_tests:
                            tests.extend(file_tests)
            except Exception as e:
                print(f"Error processing cloud file {file_info.get('name', 'unknown')}: {e}")
                continue
        
        return tests
    
    @staticmethod
    def _parse_cloud_markdown(content):
        """Parse cloud security requirements from OWASP markdown content"""
        tests = []
        
        # Enhanced patterns to match OWASP content formats
        patterns = [
            # OWASP Cloud Native Top 10 format: CNSA-1, CNSA-2, etc.
            r'(CNSA[-_]?\d+):?\s*([^.\n]{10,})',
            # OWASP standard format: C1:2023, C2:2023, etc.
            r'C(\d+):20\d\d[-:\s]*([^.\n]{10,})',
            # Kubernetes security format: K8S-SEC-01, etc.
            r'K8S[-_]?SEC[-_]?(\d+):?\s*([^.\n]{10,})',
            # General OWASP checklist format: ### Title or ## Title
            r'^#+\s*([^#\n]{10,})',
            # Numbered security requirements: 1. Requirement, 2. Requirement
            r'^(\d+)\.\s*([^.\n]{10,})',
            # Security control format: SC-01: Description
            r'SC[-_]?(\d+):?\s*([^.\n]{10,})',
            # Configuration security: CFG-01: Description  
            r'CFG[-_]?(\d+):?\s*([^.\n]{10,})'
        ]
        
        test_counter = 1
        found_items = set()  # Track to avoid duplicates
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    item_id = match[0] if not match[0].isdigit() else f"CLOUD-{match[0]}"
                    title = match[1].strip()
                    
                    # Clean and validate title
                    title = re.sub(r'[#*`\[\]()]', '', title).strip()
                    title = re.sub(r'\s+', ' ', title)  # Normalize whitespace
                    
                    # Skip if too short, too long, or duplicate
                    if len(title) < 10 or len(title) > 200 or title.lower() in found_items:
                        continue
                    
                    # Skip common non-security headings
                    skip_patterns = ['table of contents', 'introduction', 'overview', 'conclusion', 
                                   'references', 'about', 'license', 'contributing', 'changelog']
                    if any(skip in title.lower() for skip in skip_patterns):
                        continue
                    
                    found_items.add(title.lower())
                    
                    # Generate description and category based on OWASP content
                    description = CloudSecurityService._generate_owasp_description(title, content)
                    category = CloudSecurityService._categorize_cloud_security_item(title, description)
                    risk_level = CloudSecurityService._determine_cloud_risk_level(title, description, category)
                    
                    test_id = f"OWASP-CLOUD-{test_counter:03d}"
                    
                    tests.append({
                        'id': test_id,
                        'title': title,
                        'description': description,
                        'category': category,
                        'risk_level': risk_level,
                        'source': 'OWASP'
                    })
                    
                    test_counter += 1
                    
                    if len(tests) >= 20:  # Reasonable limit for OWASP content
                        break
            
            if len(tests) >= 5:  # If we found good OWASP content, don't try other patterns
                break
        
        return tests
    
    @staticmethod
    def _generate_description_from_title(title):
        """Generate a description based on the security item title"""
        title_lower = title.lower()
        
        description_templates = {
            'authentication': 'Verify that cloud authentication mechanisms are properly implemented and secured.',
            'authorization': 'Verify that cloud authorization controls follow principle of least privilege.',
            'encryption': 'Verify that data encryption is properly implemented in cloud environments.',
            'network': 'Verify that cloud network security controls are properly configured.',
            'monitoring': 'Verify that comprehensive monitoring and logging is implemented.',
            'configuration': 'Verify that cloud resources are securely configured.',
            'container': 'Verify that container security best practices are implemented.',
            'serverless': 'Verify that serverless security controls are properly configured.',
            'data': 'Verify that data protection controls are implemented in cloud environments.',
            'identity': 'Verify that cloud identity management follows security best practices.',
            'compliance': 'Verify that cloud compliance requirements are met.',
            'incident': 'Verify that incident response procedures are documented and tested.'
        }
        
        for keyword, template in description_templates.items():
            if keyword in title_lower:
                return template
        
        # Default description
        return f"Verify that {title.lower()} security controls are properly implemented in cloud environments."
    
    @staticmethod
    def _generate_owasp_description(title, content):
        """Generate enhanced description for OWASP cloud security items"""
        title_lower = title.lower()
        
        # Look for context around the title in the content
        title_context = ""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if title.lower() in line.lower():
                # Get surrounding context (3 lines after)
                context_lines = lines[i+1:i+4]
                title_context = ' '.join([l.strip() for l in context_lines if l.strip() and not l.startswith('#')])
                break
        
        # Use context if available, otherwise use template
        if title_context and len(title_context) > 20:
            description = title_context[:300] + "..." if len(title_context) > 300 else title_context
            # Clean up markdown formatting
            description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)  # Remove links
            description = re.sub(r'[*_`]', '', description)  # Remove formatting
            return f"Verify that {description}"
        
        # Fallback to template-based description
        return CloudSecurityService._generate_description_from_title(title)
    
    @staticmethod
    def _categorize_cloud_security_item(title, description):
        """Categorize cloud security items"""
        content = f"{title} {description}".lower()
        
        category_keywords = {
            'Identity and Access Management': ['identity', 'authentication', 'authorization', 'access', 'iam'],
            'Data Protection': ['data', 'encryption', 'privacy', 'protection', 'confidential'],
            'Network Security': ['network', 'firewall', 'vpc', 'subnet', 'traffic'],
            'Infrastructure Security': ['infrastructure', 'server', 'compute', 'resource', 'configuration'],
            'Monitoring and Logging': ['monitoring', 'logging', 'audit', 'detection', 'alerting'],
            'Application Security': ['application', 'app', 'software', 'code', 'development'],
            'Compliance and Governance': ['compliance', 'governance', 'policy', 'regulation', 'standard'],
            'Disaster Recovery': ['backup', 'recovery', 'disaster', 'continuity', 'resilience']
        }
        
        for category, keywords in category_keywords.items():
            if any(keyword in content for keyword in keywords):
                return category
        
        return 'General Security'

    @staticmethod
    def _generate_industry_best_practices():
        """Generate comprehensive cloud security tests based on industry standards (NOT OWASP)"""
        
        cloud_categories = {
            'Identity and Access Management': [
                ('Multi-Factor Authentication', 'Verify that cloud services enforce multi-factor authentication for administrative access based on industry standards.'),
                ('Privileged Access Management', 'Verify that privileged access to cloud resources is properly managed and monitored per industry best practices.'),
                ('Identity Federation', 'Verify that identity federation is securely configured and managed according to industry standards.'),
                ('Service Account Security', 'Verify that service accounts follow principle of least privilege per industry guidelines.')
            ],
            'Data Protection': [
                ('Data Encryption at Rest', 'Verify that sensitive data is encrypted when stored in cloud services per industry standards.'),
                ('Data Encryption in Transit', 'Verify that data is encrypted during transmission to and from cloud services per industry best practices.'),
                ('Key Management', 'Verify that encryption keys are properly managed using cloud key management services per industry standards.'),
                ('Data Loss Prevention', 'Verify that data loss prevention controls are implemented for sensitive data per industry guidelines.')
            ],
            'Network Security': [
                ('Network Segmentation', 'Verify that cloud networks are properly segmented and isolated per industry best practices.'),
                ('Firewall Configuration', 'Verify that cloud firewalls are properly configured with least privilege rules per industry standards.'),
                ('VPC Security', 'Verify that Virtual Private Cloud configurations follow industry security best practices.'),
                ('API Gateway Security', 'Verify that API gateways implement proper security controls per industry standards.')
            ],
            'Infrastructure Security': [
                ('Resource Configuration', 'Verify that cloud resources are configured according to industry security baselines.'),
                ('Patch Management', 'Verify that cloud infrastructure components are regularly updated per industry best practices.'),
                ('Container Security', 'Verify that containerized workloads implement industry security best practices.'),
                ('Serverless Security', 'Verify that serverless functions follow industry security guidelines.')
            ],
            'Monitoring and Logging': [
                ('Security Monitoring', 'Verify that comprehensive security monitoring is implemented across cloud services per industry standards.'),
                ('Log Management', 'Verify that security logs are properly collected, stored, and analyzed per industry best practices.'),
                ('Incident Response', 'Verify that cloud incident response procedures are documented and tested per industry standards.'),
                ('Compliance Monitoring', 'Verify that compliance monitoring tools are configured and operational per industry guidelines.')
            ],
            'Application Security': [
                ('Secure Development', 'Verify that cloud applications follow secure development practices per industry standards.'),
                ('Dependency Management', 'Verify that application dependencies are regularly scanned for vulnerabilities per industry best practices.'),
                ('Runtime Security', 'Verify that runtime application security controls are implemented per industry standards.'),
                ('API Security', 'Verify that cloud APIs implement proper authentication and authorization per industry guidelines.')
            ],
            'Compliance and Governance': [
                ('Policy Enforcement', 'Verify that cloud governance policies are properly enforced per industry best practices.'),
                ('Compliance Auditing', 'Verify that cloud environments meet relevant compliance requirements per industry standards.'),
                ('Resource Tagging', 'Verify that cloud resources are properly tagged for governance and cost management per industry practices.'),
                ('Change Management', 'Verify that changes to cloud infrastructure follow proper approval processes per industry standards.')
            ],
            'Disaster Recovery': [
                ('Backup Strategy', 'Verify that critical data and configurations are regularly backed up per industry best practices.'),
                ('Recovery Testing', 'Verify that disaster recovery procedures are regularly tested per industry standards.'),
                ('Business Continuity', 'Verify that business continuity plans account for cloud service dependencies per industry guidelines.'),
                ('Geographic Distribution', 'Verify that critical services are distributed across multiple regions per industry best practices.')
            ]
        }
        
        tests = []
        test_counter = 1
        
        for category, category_tests in cloud_categories.items():
            for test_name, description in category_tests:
                test_id = f"INDUSTRY-CLOUD-{test_counter:03d}"
                risk_level = CloudSecurityService._determine_cloud_risk_level(test_name, description, category)
                
                tests.append({
                    'id': test_id,
                    'title': test_name,
                    'description': description,
                    'category': category,
                    'risk_level': risk_level,
                    'source': 'Industry Standards'
                })
                test_counter += 1
        
        return tests
    
    @staticmethod
    def _determine_cloud_risk_level(test_name, description, category):
        """Determine risk level for cloud security tests"""
        high_risk_keywords = ['authentication', 'encryption', 'privileged', 'admin', 'key management']
        medium_risk_keywords = ['monitoring', 'logging', 'configuration', 'policy']
        
        content = f"{test_name} {description} {category}".lower()
        
        if any(keyword in content for keyword in high_risk_keywords):
            return 'high'
        elif any(keyword in content for keyword in medium_risk_keywords):
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def _get_fallback_data():
        """Fallback cloud security data (industry standards, not OWASP)"""
        return [
            {
                'id': 'FALLBACK-CLOUD-001',
                'title': 'Multi-Factor Authentication',
                'description': 'Verify that cloud services enforce multi-factor authentication for administrative access per industry standards.',
                'category': 'Identity and Access Management',
                'risk_level': 'high',
                'source': 'Industry Standards'
            },
            {
                'id': 'FALLBACK-CLOUD-002',
                'title': 'Data Encryption at Rest',
                'description': 'Verify that sensitive data is encrypted when stored in cloud services per industry best practices.',
                'category': 'Data Protection',
                'risk_level': 'high',
                'source': 'Industry Standards'
            },
            {
                'id': 'FALLBACK-CLOUD-003',
                'title': 'Network Segmentation',
                'description': 'Verify that cloud networks are properly segmented and isolated per industry standards.',
                'category': 'Network Security',
                'risk_level': 'high',
                'source': 'Industry Standards'
            },
            {
                'id': 'FALLBACK-CLOUD-004',
                'title': 'Security Monitoring',
                'description': 'Verify that comprehensive security monitoring is implemented across cloud services per industry practices.',
                'category': 'Monitoring and Logging',
                'risk_level': 'medium',
                'source': 'Industry Standards'
            },
            {
                'id': 'FALLBACK-CLOUD-005',
                'title': 'API Security',
                'description': 'Verify that cloud APIs implement proper authentication and authorization per industry guidelines.',
                'category': 'Application Security',
                'risk_level': 'high',
                'source': 'Industry Standards'
            }
        ]
    
    # Testing methods for cloud security
    @staticmethod
    def test_cloud_authentication(service_url, credentials):
        """Test cloud service authentication mechanisms"""
        try:
            # Test for weak authentication
            test_results = []
            
            # Test 1: Check if MFA is required
            response = requests.get(service_url, auth=credentials, timeout=10)
            if 'mfa' not in response.headers.get('www-authenticate', '').lower():
                test_results.append("MFA may not be enforced")
            
            # Test 2: Check for account lockout
            for _ in range(5):
                requests.get(service_url, auth=('invalid', 'invalid'), timeout=5)
            
            final_response = requests.get(service_url, auth=('invalid', 'invalid'), timeout=5)
            if final_response.status_code != 423:  # 423 = Locked
                test_results.append("Account lockout may not be implemented")
            
            if test_results:
                return {
                    'result': 'fail',
                    'evidence': f"Authentication issues: {'; '.join(test_results)}",
                    'request': f'Authentication test of {service_url}',
                    'response': f'Found {len(test_results)} authentication weaknesses'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'Authentication mechanisms appear secure',
                    'request': f'Authentication test of {service_url}',
                    'response': 'No authentication weaknesses detected'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing authentication: {str(e)}',
                'request': f'Authentication test of {service_url}',
                'response': 'Test failed - connection error'
            }
    
    @staticmethod
    def test_cloud_encryption(service_url):
        """Test cloud service encryption implementation"""
        try:
            import ssl
            import socket
            
            parsed_url = urlparse(service_url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            evidence = []
            
            if parsed_url.scheme != 'https':
                evidence.append("Service not using HTTPS")
                return {
                    'result': 'fail',
                    'evidence': f"Encryption issues: {'; '.join(evidence)}",
                    'request': f'Encryption test of {service_url}',
                    'response': 'Insecure protocol detected'
                }
            
            # Test SSL/TLS configuration
            context = ssl.create_default_context()
            
            try:
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssl_version = ssock.version()
                        cipher = ssock.cipher()
                        
                        if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            evidence.append(f"Weak SSL/TLS version: {ssl_version}")
                        
                        if cipher and len(cipher) > 0:
                            cipher_name = cipher[0]
                            if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5']):
                                evidence.append(f"Weak cipher: {cipher_name}")
                
                if evidence:
                    return {
                        'result': 'fail',
                        'evidence': f"Encryption issues: {'; '.join(evidence)}",
                        'request': f'Encryption test of {service_url}',
                        'response': f'Found {len(evidence)} encryption weaknesses'
                    }
                else:
                    return {
                        'result': 'pass',
                        'evidence': 'Strong encryption detected',
                        'request': f'Encryption test of {service_url}',
                        'response': 'Encryption appears properly configured'
                    }
                    
            except ssl.SSLError as ssl_error:
                return {
                    'result': 'fail',
                    'evidence': f'SSL/TLS error: {str(ssl_error)}',
                    'request': f'Encryption test of {service_url}',
                    'response': 'SSL/TLS configuration error'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing encryption: {str(e)}',
                'request': f'Encryption test of {service_url}',
                'response': 'Test failed - connection error'
            }
