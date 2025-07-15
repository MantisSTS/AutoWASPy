"""
OWASP API Security Top 10 2023 testing service
Provides automated testing capabilities for API security vulnerabilities
"""

import requests
import json
import re
from urllib.parse import urlparse, urljoin
from app.utils.datetime_utils import utc_now
import time

class APISecurityService:
    """Service for OWASP API Security Top 10 2023 testing"""
    
    @staticmethod
    def fetch_api_security_data():
        """
        Fetch API Security Top 10 test cases from OWASP official sources
        Returns structured test data for API security testing
        """
        try:
            return APISecurityService._fetch_from_github()
        except Exception as e:
            print(f"GitHub fetch failed: {e}, using fallback data")
            return APISecurityService._get_fallback_data()

    @staticmethod
    def get_cached_api_security_data():
        """Get API Security data from JSON cache file, fallback to hardcoded data if not available"""
        import os
        import json
        
        print("Getting cached API Security data for project creation...")
        
        # Try to load from cache file first
        cache_file = os.path.join(os.path.dirname(__file__), '..', '..', 'cache', 'api_security_cache.json')
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    if cached_data and len(cached_data) > 5:
                        print(f"Using cached API Security data: {len(cached_data)} tests")
                        return cached_data
        except Exception as e:
            print(f"Error loading API Security cache file: {e}")
        
        # Fall back to hardcoded data
        print("Using fallback API Security data")
        return APISecurityService._get_fallback_data()
    
    @staticmethod
    def _fetch_from_github():
        """Fetch API Security Top 10 from OWASP GitHub repository"""
        import requests
        from app.utils.datetime_utils import utc_now
        from app.models import OWASPDataCache
        from app import db
        
        # OWASP API Security Top 10 repository
        api_urls = [
            "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0x11-t10.md",
            "https://raw.githubusercontent.com/OWASP/API-Security/master/2019/en/0x11-t10.md",
            "https://api.github.com/repos/OWASP/API-Security/contents/editions/2023/en"
        ]
        
        api_security_tests = []
        
        # Try to fetch from the markdown file first
        for url in api_urls[:2]:
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    content = response.text
                    tests = APISecurityService._parse_api_security_markdown(content)
                    if tests:
                        api_security_tests = tests
                        break
            except:
                continue
        
        # If markdown parsing didn't work, try GitHub API
        if not api_security_tests:
            try:
                response = requests.get(api_urls[2], timeout=30)
                if response.status_code == 200:
                    files = response.json()
                    api_security_tests = APISecurityService._parse_github_api_files(files)
            except:
                pass
        
        if api_security_tests:
            # Save to cache file
            APISecurityService._save_to_cache(api_security_tests)
            
            # Update cache
            cache_entry = OWASPDataCache(
                data_type='api_security',
                last_updated=utc_now(),
                data_source='github',
                test_count=len(api_security_tests)
            )
            db.session.merge(cache_entry)
            db.session.commit()
            
            print(f"Successfully fetched {len(api_security_tests)} API Security tests from GitHub")
            return api_security_tests
        else:
            raise Exception("No data found in GitHub repository")
    
    @staticmethod
    def _parse_api_security_markdown(content):
        """Parse API Security Top 10 from markdown content"""
        import re
        
        tests = []
        
        # Pattern to match table rows with API Security items
        # Format: | [API1:2023 - Broken Object Level Authorization][api1] | Description text... |
        table_pattern = r'\|\s*\[?(API\d+:2023)\s*-\s*([^\]|]+)\]?[^\|]*\|\s*([^|]+)\s*\|'
        
        matches = re.findall(table_pattern, content, re.MULTILINE)
        
        for match in matches:
            api_id = match[0].strip()
            title = match[1].strip()
            description = match[2].strip()
            
            # Clean up description
            description = re.sub(r'\n+', ' ', description)
            description = re.sub(r'\s+', ' ', description)
            description = re.sub(r'\[([^\]]+)\]\[[^\]]+\]', r'\1', description)  # Convert [text][link] to text
            description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)   # Convert [text](url) to text
            
            # Skip if description is too short (likely a header)
            if len(description) < 50:
                continue
            
            # Determine category and risk level based on content
            category = APISecurityService._determine_category(title, description)
            risk_level = APISecurityService._determine_risk_level(title, description)
            
            tests.append({
                'id': api_id,
                'title': title,
                'description': description[:500] + ('...' if len(description) > 500 else ''),
                'category': category,
                'risk_level': risk_level
            })
        
        # If table parsing didn't work, try alternative pattern for simpler format
        if not tests:
            # Fallback pattern for different markdown formats
            alt_pattern = r'(?:^|\n)#+\s*(API\d+:2023)\s*[-–]\s*(.+?)(?:\n|$)'
            alt_matches = re.findall(alt_pattern, content, re.MULTILINE)
            
            for match in alt_matches:
                api_id = match[0].strip()
                title = match[1].strip()
                
                # Skip if title contains generic words that indicate it's not an actual API item
                if any(word in title.lower() for word in ['owasp', 'methodology', 'risks', 'top 10']):
                    continue
                
                # Extract description from content following the title
                desc_pattern = rf'{re.escape(title)}.*?\n\n(.*?)(?:\n#{1,6}|\Z)'
                desc_match = re.search(desc_pattern, content, re.DOTALL)
                description = desc_match.group(1).strip() if desc_match else f"API Security vulnerability: {title}"
                
                # Clean up description
                description = re.sub(r'\n+', ' ', description)
                description = re.sub(r'\s+', ' ', description)
                
                category = APISecurityService._determine_category(title, description)
                risk_level = APISecurityService._determine_risk_level(title, description)
                
                tests.append({
                    'id': api_id,
                    'title': title,
                    'description': description[:500] + ('...' if len(description) > 500 else ''),
                    'category': category,
                    'risk_level': risk_level
                })
        
        return tests[:10]  # Limit to top 10
    
    @staticmethod
    def _parse_github_api_files(files):
        """Parse API Security data from GitHub API file listing"""
        tests = []
        
        # Look for numbered files that might contain API security items
        api_files = [f for f in files if f.get('name', '').startswith('0x1') and f.get('name', '').endswith('.md')]
        
        for i, file_info in enumerate(api_files[:10]):
            try:
                file_url = file_info.get('download_url')
                if file_url:
                    response = requests.get(file_url, timeout=15)
                    if response.status_code == 200:
                        content = response.text
                        # Extract title from first heading
                        title_match = re.search(r'^#\s*(.+)', content, re.MULTILINE)
                        title = title_match.group(1).strip() if title_match else f"API Security Issue {i+1}"
                        
                        # Extract first paragraph as description
                        desc_match = re.search(r'\n\n(.+?)(?:\n\n|\Z)', content, re.DOTALL)
                        description = desc_match.group(1).strip() if desc_match else "API Security vulnerability"
                        description = re.sub(r'\n+', ' ', description)[:300]
                        
                        tests.append({
                            'id': f'API{i+1}:2023',
                            'title': title,
                            'description': description,
                            'category': 'API Security',
                            'risk_level': 'high' if i < 3 else 'medium'
                        })
            except:
                continue
        
        return tests
    
    @staticmethod
    def _determine_category(title, description):
        """Determine category based on title and description"""
        title_lower = title.lower()
        desc_lower = description.lower()
        
        if any(word in title_lower for word in ['authorization', 'access', 'permission']):
            return 'Authorization'
        elif any(word in title_lower for word in ['authentication', 'auth', 'token']):
            return 'Authentication'
        elif any(word in title_lower for word in ['input', 'validation', 'injection', 'ssrf']):
            return 'Input Validation'
        elif any(word in title_lower for word in ['resource', 'consumption', 'rate', 'limit']):
            return 'Resource Management'
        elif any(word in title_lower for word in ['business', 'flow', 'logic']):
            return 'Business Logic'
        elif any(word in title_lower for word in ['config', 'misconfiguration']):
            return 'Configuration'
        elif any(word in title_lower for word in ['inventory', 'management', 'asset']):
            return 'Asset Management'
        else:
            return 'API Security'
    
    @staticmethod
    def _determine_risk_level(title, description):
        """Determine risk level based on title and description"""
        title_lower = title.lower()
        
        high_risk_keywords = ['broken', 'bypass', 'injection', 'ssrf', 'authorization', 'authentication']
        medium_risk_keywords = ['misconfiguration', 'resource', 'consumption', 'exposure']
        
        if any(word in title_lower for word in high_risk_keywords):
            return 'high'
        elif any(word in title_lower for word in medium_risk_keywords):
            return 'medium'
        else:
            return 'medium'
    
    @staticmethod
    def _get_fallback_data():
        """Fallback data if GitHub fetch fails"""
        api_security_tests = [
            {
                'id': 'API1:2023',
                'title': 'Broken Object Level Authorization',
                'description': 'APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.',
                'category': 'Authorization',
                'risk_level': 'high'
            },
            {
                'id': 'API2:2023', 
                'title': 'Broken Authentication',
                'description': 'Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.',
                'category': 'Authentication',
                'risk_level': 'high'
            },
            {
                'id': 'API3:2023',
                'title': 'Broken Object Property Level Authorization', 
                'description': 'Lack of or improper authorization validation at the object property level leads to information exposure or manipulation.',
                'category': 'Authorization',
                'risk_level': 'medium'
            },
            {
                'id': 'API4:2023',
                'title': 'Unrestricted Resource Consumption',
                'description': 'API requests consume resources such as network bandwidth, CPU, memory, and storage without proper limits.',
                'category': 'Resource Management',
                'risk_level': 'medium'
            },
            {
                'id': 'API5:2023',
                'title': 'Broken Function Level Authorization',
                'description': 'Complex access control policies with different hierarchies tend to lead to authorization flaws.',
                'category': 'Authorization', 
                'risk_level': 'high'
            },
            {
                'id': 'API6:2023',
                'title': 'Unrestricted Access to Sensitive Business Flows',
                'description': 'APIs expose business flows without compensating for how the functionality could harm the business if used excessively.',
                'category': 'Business Logic',
                'risk_level': 'medium'
            },
            {
                'id': 'API7:2023',
                'title': 'Server Side Request Forgery',
                'description': 'SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URI.',
                'category': 'Input Validation',
                'risk_level': 'high'
            },
            {
                'id': 'API8:2023',
                'title': 'Security Misconfiguration',
                'description': 'APIs and supporting systems contain complex configurations that can be misconfigured, opening doors for attacks.',
                'category': 'Configuration',
                'risk_level': 'medium'
            },
            {
                'id': 'API9:2023',
                'title': 'Improper Inventory Management',
                'description': 'APIs expose more endpoints than traditional web applications, making proper documentation and inventory critical.',
                'category': 'Asset Management',
                'risk_level': 'low'
            },
            {
                'id': 'API10:2023',
                'title': 'Unsafe Consumption of APIs',
                'description': 'Developers trust data received from third-party APIs more than user input, adopting weaker security standards.',
                'category': 'Input Validation',
                'risk_level': 'medium'
            }
        ]
        
        # Update cache with fallback source
        from app.utils.datetime_utils import utc_now
        from app.models import OWASPDataCache
        from app import db
        
        cache_entry = OWASPDataCache(
            data_type='api_security',
            last_updated=utc_now(),
            data_source='fallback',
            test_count=len(api_security_tests)
        )
        db.session.merge(cache_entry)
        db.session.commit()
        
        print(f"Using fallback data: {len(api_security_tests)} API Security tests")
        return api_security_tests

    @staticmethod
    def _save_to_cache(data):
        """Save fetched API Security data to JSON cache file"""
        import os
        import json
        
        try:
            # Create cache directory if it doesn't exist
            cache_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'cache')
            os.makedirs(cache_dir, exist_ok=True)
            
            # Save to cache file
            cache_file = os.path.join(cache_dir, 'api_security_cache.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"Saved {len(data)} API Security tests to cache file: {cache_file}")
        except Exception as e:
            print(f"Error saving API Security data to cache: {e}")

    @staticmethod
    def test_api_authentication_bypass(api_url):
        """Test for authentication bypass vulnerabilities"""
        try:
            # Test 1: Access without authentication
            response = requests.get(api_url, timeout=10, verify=False)
            
            # Test 2: Try with common bypasses
            bypass_headers = [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Real-IP': '127.0.0.1'},
                {'X-Original-URL': '/admin'},
                {'Authorization': 'Bearer invalid_token'},
                {'Authorization': 'Basic YWRtaW46YWRtaW4='}  # admin:admin
            ]
            
            evidence = []
            for headers in bypass_headers:
                try:
                    bypass_response = requests.get(api_url, headers=headers, timeout=10, verify=False)
                    if bypass_response.status_code == 200:
                        evidence.append(f"Potential bypass with headers: {headers}")
                except:
                    continue
            
            if response.status_code == 200 or evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Authentication bypass detected. Status: {response.status_code}. " + "; ".join(evidence),
                    'request': f'GET {api_url}',
                    'response': f'Status: {response.status_code}, Headers: {dict(response.headers)}'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': f'API properly requires authentication. Status: {response.status_code}',
                    'request': f'GET {api_url}',
                    'response': f'Status: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing authentication: {str(e)}',
                'request': f'GET {api_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_object_level_authorization(api_url):
        """Test for Broken Object Level Authorization (BOLA/IDOR)"""
        try:
            # Look for endpoints with object IDs
            id_patterns = [
                r'/\d+',           # /123
                r'/[a-f0-9-]{36}', # UUID
                r'/\w+/\d+',       # /users/123
                r'id=\d+',         # ?id=123
                r'user_id=\d+'     # ?user_id=123
            ]
            
            evidence = []
            
            # Test different ID values
            test_ids = ['1', '2', '999', '0', '-1', 'admin', '../']
            
            for test_id in test_ids:
                try:
                    # Replace or append ID in URL
                    test_url = api_url
                    if '?' in api_url:
                        test_url += f'&id={test_id}'
                    else:
                        test_url += f'?id={test_id}'
                    
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        # Check if response contains different data
                        if len(response.text) > 0:
                            evidence.append(f"ID {test_id} returned data (Status: {response.status_code})")
                    
                except:
                    continue
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Potential BOLA/IDOR vulnerability detected: {'; '.join(evidence)}",
                    'request': f'GET {api_url} with various ID parameters',
                    'response': f'Multiple responses with different object IDs'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No obvious BOLA/IDOR vulnerabilities detected',
                    'request': f'GET {api_url}',
                    'response': 'Access control appears to be properly implemented'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing object level authorization: {str(e)}',
                'request': f'GET {api_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_rate_limiting(api_url):
        """Test for Unrestricted Resource Consumption (Rate Limiting)"""
        try:
            request_count = 50
            start_time = time.time()
            successful_requests = 0
            rate_limited = False
            
            for i in range(request_count):
                try:
                    response = requests.get(api_url, timeout=5, verify=False)
                    
                    if response.status_code == 429:  # Too Many Requests
                        rate_limited = True
                        break
                    elif response.status_code == 200:
                        successful_requests += 1
                        
                except:
                    continue
                    
                # Small delay to avoid overwhelming the server
                time.sleep(0.1)
            
            end_time = time.time()
            duration = end_time - start_time
            requests_per_second = successful_requests / duration if duration > 0 else 0
            
            if rate_limited:
                return {
                    'result': 'pass',
                    'evidence': f'Rate limiting detected after {successful_requests} requests. Received 429 status code.',
                    'request': f'GET {api_url} (x{request_count})',
                    'response': f'Rate limited after {successful_requests} requests'
                }
            elif requests_per_second > 10:  # Arbitrary threshold
                return {
                    'result': 'fail',
                    'evidence': f'No rate limiting detected. Made {successful_requests} requests in {duration:.2f} seconds ({requests_per_second:.2f} req/s)',
                    'request': f'GET {api_url} (x{request_count})',
                    'response': f'All requests successful, no rate limiting'
                }
            else:
                return {
                    'result': 'informational',
                    'evidence': f'Rate limiting test inconclusive. {successful_requests} successful requests in {duration:.2f} seconds',
                    'request': f'GET {api_url} (x{request_count})',
                    'response': f'Test completed with {successful_requests} successful requests'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing rate limiting: {str(e)}',
                'request': f'GET {api_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_api_versioning(api_url):
        """Test for Improper Inventory Management (API Versioning)"""
        try:
            # Common API version patterns
            version_patterns = [
                '/v1/', '/v2/', '/v3/', '/api/v1/', '/api/v2/',
                '?version=1', '?version=2', '?v=1', '?v=2'
            ]
            
            # Version headers
            version_headers = [
                {'Accept': 'application/vnd.api+json;version=1'},
                {'Accept': 'application/vnd.api+json;version=2'},
                {'API-Version': 'v1'},
                {'API-Version': 'v2'},
                {'Version': '1.0'},
                {'Version': '2.0'}
            ]
            
            evidence = []
            discovered_versions = set()
            
            # Test URL-based versioning
            base_url = api_url.rstrip('/')
            for pattern in version_patterns:
                try:
                    if '?' in pattern:
                        test_url = base_url + pattern
                    else:
                        test_url = base_url.replace('/api/', pattern).replace('/', pattern, 1)
                    
                    response = requests.get(test_url, timeout=10, verify=False)
                    if response.status_code == 200:
                        discovered_versions.add(pattern)
                        evidence.append(f"Version endpoint found: {pattern}")
                except:
                    continue
            
            # Test header-based versioning
            for headers in version_headers:
                try:
                    response = requests.get(api_url, headers=headers, timeout=10, verify=False)
                    if response.status_code == 200:
                        version_info = str(headers)
                        discovered_versions.add(version_info)
                        evidence.append(f"Version header accepted: {headers}")
                except:
                    continue
            
            if len(discovered_versions) > 1:
                return {
                    'result': 'informational',
                    'evidence': f"Multiple API versions discovered: {'; '.join(evidence)}. Ensure old versions are properly secured.",
                    'request': f'GET {api_url} with various version indicators',
                    'response': f'Found {len(discovered_versions)} potential versions'
                }
            elif discovered_versions:
                return {
                    'result': 'informational',
                    'evidence': f"API versioning detected: {'; '.join(evidence)}",
                    'request': f'GET {api_url}',
                    'response': 'Single version endpoint found'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No obvious API versioning issues detected',
                    'request': f'GET {api_url}',
                    'response': 'No multiple versions discovered'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing API versioning: {str(e)}',
                'request': f'GET {api_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_input_validation(api_url):
        """Test for injection vulnerabilities and input validation"""
        try:
            # SQL injection payloads
            sql_payloads = [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "1' UNION SELECT null,null,null--",
                "admin'--"
            ]
            
            # NoSQL injection payloads
            nosql_payloads = [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$where": "this.password.match(/.*/)"}',
                '[$ne]=1'
            ]
            
            # XSS payloads
            xss_payloads = [
                '<script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>',
                '"><script>alert("XSS")</script>'
            ]
            
            evidence = []
            
            # Test SQL injection
            for payload in sql_payloads:
                try:
                    test_url = f"{api_url}?search={payload}"
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Look for SQL error messages
                    error_patterns = ['sql', 'mysql', 'postgresql', 'oracle', 'sqlite', 'syntax error']
                    response_text = response.text.lower()
                    
                    for pattern in error_patterns:
                        if pattern in response_text:
                            evidence.append(f"Potential SQL injection with payload: {payload}")
                            break
                except:
                    continue
            
            # Test XSS
            for payload in xss_payloads:
                try:
                    test_url = f"{api_url}?input={payload}"
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    if payload in response.text:
                        evidence.append(f"Potential XSS with payload: {payload}")
                except:
                    continue
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Input validation vulnerabilities detected: {'; '.join(evidence)}",
                    'request': f'GET {api_url} with various injection payloads',
                    'response': f'Vulnerabilities found in {len(evidence)} tests'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No obvious input validation vulnerabilities detected',
                    'request': f'GET {api_url}',
                    'response': 'Input validation appears to be implemented'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing input validation: {str(e)}',
                'request': f'GET {api_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_sensitive_data_exposure(api_url):
        """Test for sensitive data exposure in API responses"""
        try:
            response = requests.get(api_url, timeout=10, verify=False)
            
            # Patterns for sensitive data
            sensitive_patterns = [
                (r'password', 'Password field'),
                (r'secret', 'Secret field'),
                (r'token', 'Token field'),
                (r'key', 'Key field'),
                (r'\d{16}', 'Credit card number'),
                (r'\d{3}-\d{2}-\d{4}', 'SSN pattern'),
                (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email address'),
                (r'api_key', 'API key field'),
                (r'private_key', 'Private key field')
            ]
            
            evidence = []
            response_text = response.text.lower()
            
            for pattern, description in sensitive_patterns:
                matches = re.findall(pattern, response_text)
                if matches:
                    evidence.append(f"{description} found: {len(matches)} matches")
            
            # Check response headers for sensitive information
            sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            for header in sensitive_headers:
                if header in response.headers:
                    evidence.append(f"Information disclosure in header: {header} = {response.headers[header]}")
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Sensitive data exposure detected: {'; '.join(evidence)}",
                    'request': f'GET {api_url}',
                    'response': f'Status: {response.status_code}, Found {len(evidence)} potential exposures'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No obvious sensitive data exposure detected',
                    'request': f'GET {api_url}',
                    'response': f'Status: {response.status_code}, Response appears clean'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing sensitive data exposure: {str(e)}',
                'request': f'GET {api_url}',
                'response': 'Request failed - connection error'
            }
