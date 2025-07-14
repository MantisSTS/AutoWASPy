"""
OWASP Application Security Verification Standard (ASVS) 5.0 testing service
Provides structured security verification requirements and testing capabilities
"""

import requests
import re
from urllib.parse import urlparse, urljoin
import json

class ASVSService:
    """Service for OWASP ASVS 5.0 verification requirements"""
    
    @staticmethod
    def fetch_asvs_data():
        """
        Fetch ASVS 5.0 verification requirements from OWASP official sources
        Returns structured verification requirements organized by categories
        """
        try:
            return ASVSService._fetch_from_github()
        except Exception as e:
            print(f"GitHub fetch failed: {e}, using fallback data")
            return ASVSService._get_fallback_data()
    
    @staticmethod
    def _fetch_from_github():
        """Fetch ASVS data from OWASP GitHub repository"""
        from app.utils.datetime_utils import utc_now
        from app.models import OWASPDataCache
        from app import db
        
        # OWASP ASVS 5.0 GitHub repositories - comprehensive verification requirements
        urls = [
            "https://api.github.com/repos/OWASP/ASVS/contents/5.0/en",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x11-V2-Validation-and-Business-Logic.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x12-V3-Web-Frontend-Security.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x13-V4-API-and-Web-Service.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x14-V5-File-Handling.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x15-V6-Authentication.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x16-V7-Session-Management.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x17-V8-Authorization.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x18-V9-Self-contained-Tokens.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x19-V10-OAuth-and-OIDC.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x20-V11-Cryptography.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x21-V12-Secure-Communication.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x22-V13-Configuration.md",
            "https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x23-V14-Data-Protection.md"
        ]
        
        asvs_requirements = []
        
        # Try different sources
        for url in urls:
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    if 'api.github.com' in url:
                        # GitHub API response
                        files = response.json()
                        requirements = ASVSService._parse_github_asvs_files(files)
                        if requirements:
                            asvs_requirements.extend(requirements)
                    else:
                        # Raw markdown content
                        content = response.text
                        requirements = ASVSService._parse_asvs_markdown(content, url)
                        if requirements:
                            asvs_requirements.extend(requirements)
            except Exception as e:
                print(f"Failed to fetch from {url}: {e}")
                continue
        
        # Remove duplicates based on ID
        seen_ids = set()
        unique_requirements = []
        for req in asvs_requirements:
            if req['id'] not in seen_ids:
                seen_ids.add(req['id'])
                unique_requirements.append(req)
        
        if unique_requirements:
            # Update cache
            cache_entry = OWASPDataCache(
                data_type='asvs',
                last_updated=utc_now(),
                data_source='github',
                test_count=len(unique_requirements)
            )
            db.session.merge(cache_entry)
            db.session.commit()
            
            print(f"Successfully fetched {len(unique_requirements)} ASVS requirements from GitHub")
            return unique_requirements
        else:
            raise Exception("No data found in GitHub repositories")
    
    @staticmethod
    def _parse_asvs_markdown(content, url):
        """Parse ASVS requirements from markdown content"""
        
        # Determine category from URL
        category = ASVSService._determine_category_from_url(url)
        
        # Use comprehensive parsing
        requirements = ASVSService._parse_comprehensive_asvs_requirements(content, category)
        
        return requirements
    
    @staticmethod
    def _parse_github_asvs_files(files):
        """Parse ASVS requirements from GitHub API file listing"""
        requirements = []
        
        # Look for verification chapter files
        asvs_files = [f for f in files if f.get('name', '').endswith('.md') and 
                     any(keyword in f.get('name', '').lower() for keyword in ['v1-', 'v2-', 'v3-', 'v4-', 'v5-'])]
        
        for file_info in asvs_files[:5]:  # Limit to first 5 files
            try:
                file_url = file_info.get('download_url')
                if file_url:
                    response = requests.get(file_url, timeout=15)
                    if response.status_code == 200:
                        content = response.text
                        file_requirements = ASVSService._parse_asvs_markdown(content, file_url)
                        requirements.extend(file_requirements)
            except Exception as e:
                print(f"Error processing ASVS file {file_info.get('name', 'unknown')}: {e}")
                continue
        
        return requirements
    
    @staticmethod
    def _determine_category_from_url(url):
        """Determine ASVS category from file URL"""
        if 'V1-Encoding' in url or 'V1-Architecture' in url:
            return 'Architecture & Design'
        elif 'V2-Validation' in url or 'V2-Authentication' in url:
            return 'Input Validation & Business Logic'
        elif 'V3-Web-Frontend' in url or 'V3-Session' in url:
            return 'Web Frontend Security'
        elif 'V4-API' in url or 'V4-Access-Control' in url:
            return 'API & Web Service Security'
        elif 'V5-File' in url:
            return 'File Handling'
        elif 'V6-Authentication' in url:
            return 'Authentication'
        elif 'V7-Session' in url:
            return 'Session Management'
        elif 'V8-Authorization' in url:
            return 'Authorization'
        elif 'V9-Self-contained' in url:
            return 'Self-contained Tokens'
        elif 'V10-OAuth' in url:
            return 'OAuth & OIDC'
        elif 'V11-Cryptography' in url:
            return 'Cryptography'
        elif 'V12-Secure-Communication' in url:
            return 'Secure Communication'
        elif 'V13-Configuration' in url:
            return 'Configuration'
        elif 'V14-Data-Protection' in url:
            return 'Data Protection'
        else:
            return 'General Security'
    
    @staticmethod
    def _parse_comprehensive_asvs_requirements(content, category):
        """Enhanced parsing for comprehensive ASVS requirements"""
        requirements = []
        
        # Multiple patterns to catch different ASVS requirement formats
        patterns = [
            # Current ASVS 5.0 format: | **6.1.1** | Verify that... | 1 |
            r'\|\s*\*\*(\d+\.\d+\.\d+)\*\*\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|',
            # Alternative format: | V1.1.1 | Verify that... | L1 | L2 | L3 | CWE |
            r'\|\s*(V\d+\.\d+\.\d+)\s*\|\s*([^|]+?)\s*\|(?:\s*[✓✗❌LX]?\s*\|){3}\s*(\d+)?\s*\|',
            # Simple format: V1.1.1 - Verify that...
            r'^(V\d+\.\d+\.\d+)\s*[-–]\s*(.+?)(?:\n|$)',
            # Numbered format: 1.1.1 - Verify that...
            r'^(\d+\.\d+\.\d+)\s*[-–]\s*(.+?)(?:\n|$)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.MULTILINE)
            if matches:
                for match in matches:
                    req_id = match[0].strip()
                    description = match[1].strip()
                    level = match[2].strip() if len(match) > 2 and match[2] else "1"
                    
                    # Clean and validate description
                    description = ASVSService._clean_description(description)
                    if not description or len(description) < 10:
                        continue
                    
                    # Ensure proper V prefix for ID
                    if not req_id.startswith('V'):
                        req_id = f"V{req_id}"
                    
                    # Determine risk level based on ASVS level
                    risk_level = 'medium'
                    if level in ['3', 'L3']:
                        risk_level = 'high'
                    elif level in ['1', 'L1']:
                        risk_level = 'low'
                    
                    # Extract verification levels from content
                    levels = ASVSService._extract_verification_levels(content, req_id)
                    
                    requirements.append({
                        'id': req_id,
                        'title': ASVSService._extract_title_from_description(description),
                        'description': description,
                        'category': category,
                        'levels': levels,
                        'risk_level': risk_level,
                        'level': level,
                        'testing_guidance': ASVSService._generate_testing_guidance(req_id, description, category)
                    })
                
                # If we found matches with this pattern, don't try others
                if requirements:
                    break
        
        return requirements[:15]  # Limit per category to keep manageable
    
    @staticmethod
    def _clean_description(description):
        """Clean and normalize ASVS requirement descriptions"""
        # Remove HTML tags
        description = re.sub(r'<[^>]+>', '', description)
        # Remove markdown formatting
        description = re.sub(r'\*\*(.+?)\*\*', r'\1', description)
        description = re.sub(r'\*(.+?)\*', r'\1', description)
        # Normalize whitespace
        description = re.sub(r'\s+', ' ', description)
        # Remove trailing punctuation if description is cut off
        description = description.strip().rstrip('.,;:')
        return description
    
    @staticmethod
    def _extract_verification_levels(content, req_id):
        """Extract verification levels (L1, L2, L3) for a requirement"""
        levels = []
        
        # Look for the requirement line and extract level indicators
        req_pattern = rf'{re.escape(req_id)}.*?\|(.*?)\|(.*?)\|(.*?)\|'
        match = re.search(req_pattern, content)
        
        if match:
            l1_indicator = match.group(1).strip()
            l2_indicator = match.group(2).strip()
            l3_indicator = match.group(3).strip()
            
            if '✓' in l1_indicator or 'L1' in l1_indicator:
                levels.append('L1')
            if '✓' in l2_indicator or 'L2' in l2_indicator:
                levels.append('L2')
            if '✓' in l3_indicator or 'L3' in l3_indicator:
                levels.append('L3')
        
        return levels if levels else ['L1']  # Default to L1 if unclear
    
    @staticmethod
    def _generate_testing_guidance(req_id, description, category):
        """Generate testing guidance for ASVS requirements"""
        guidance_templates = {
            'Authentication': 'Test authentication mechanisms by attempting various bypass techniques and verifying proper credential validation.',
            'Authorization': 'Test authorization controls by attempting to access resources with different privilege levels.',
            'Session Management': 'Test session handling by examining session tokens, timeout behavior, and session fixation vulnerabilities.',
            'Input Validation': 'Test input validation by submitting various malicious payloads and boundary values.',
            'Cryptography': 'Test cryptographic implementation by examining algorithms, key management, and random number generation.',
            'Data Protection': 'Test data protection by examining data storage, transmission, and access controls.',
            'Configuration': 'Test configuration security by examining default settings, error messages, and administrative interfaces.',
            'API & Web Service Security': 'Test API security by examining authentication, authorization, input validation, and rate limiting.',
            'File Handling': 'Test file handling by uploading various file types and examining file processing logic.',
            'Web Frontend Security': 'Test frontend security by examining client-side controls, DOM manipulation, and XSS vulnerabilities.'
        }
        
        base_guidance = guidance_templates.get(category, 'Test the security control through appropriate verification methods.')
        
        # Add specific guidance based on requirement content
        desc_lower = description.lower()
        specific_guidance = []
        
        if 'password' in desc_lower:
            specific_guidance.append('Test password policies, strength requirements, and storage mechanisms.')
        if 'token' in desc_lower:
            specific_guidance.append('Examine token generation, validation, and lifecycle management.')
        if 'encryption' in desc_lower:
            specific_guidance.append('Verify encryption algorithms, key sizes, and implementation correctness.')
        if 'sql' in desc_lower or 'injection' in desc_lower:
            specific_guidance.append('Test for SQL injection using various payload techniques.')
        if 'xss' in desc_lower or 'cross-site' in desc_lower:
            specific_guidance.append('Test for XSS vulnerabilities using reflected, stored, and DOM-based techniques.')
        
        if specific_guidance:
            return f"{base_guidance} {' '.join(specific_guidance)}"
        else:
            return base_guidance
    def _determine_verification_level(req_id, description):
        """Determine ASVS verification level (L1, L2, L3)"""
        # Basic heuristics based on requirement complexity
        desc_lower = description.lower()
        
        if any(word in desc_lower for word in ['advanced', 'cryptographic', 'hardware', 'sophisticated']):
            return 'L3'
        elif any(word in desc_lower for word in ['strong', 'robust', 'secure', 'validated']):
            return 'L2'
        else:
            return 'L1'
    
    @staticmethod
    def _determine_risk_level(description, cwe_id):
        """Determine risk level based on description and CWE ID"""
        desc_lower = description.lower()
        
        # High risk keywords
        if any(word in desc_lower for word in ['injection', 'authentication', 'authorization', 'cryptographic']):
            return 'high'
        elif any(word in desc_lower for word in ['validation', 'encoding', 'sanitization']):
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def _extract_title_from_description(description):
        """Extract a title from the verification requirement description"""
        # Take first part of description as title
        words = description.split()[:8]  # First 8 words
        title = ' '.join(words)
        
        # Clean up
        title = re.sub(r'^Verify that ', '', title, flags=re.IGNORECASE)
        title = re.sub(r'^Ensure that ', '', title, flags=re.IGNORECASE)
        
        if not title.endswith('.'):
            title += '...'
        
        return title
    
    @staticmethod
    def _get_fallback_data():
        """Fallback data if GitHub fetch fails"""
        return [
            # V1: Architecture, Design and Threat Modeling
            {
                'id': 'V1.1.1',
                'title': 'Secure Development Lifecycle',
                'description': 'Verify the use of a secure software development lifecycle that addresses security in all stages of development.',
                'category': 'Architecture',
                'level': 'L1',
                'risk_level': 'medium'
            },
            {
                'id': 'V1.2.1',
                'title': 'Authentication Architecture',
                'description': 'Verify that all authentication pathways and identity management APIs implement consistent security.',
                'category': 'Architecture',
                'level': 'L2',
                'risk_level': 'high'
            },
            
            # V2: Authentication
            {
                'id': 'V2.1.1',
                'title': 'Password Security',
                'description': 'Verify that user set passwords are at least 12 characters in length.',
                'category': 'Authentication',
                'level': 'L1',
                'risk_level': 'medium'
            },
            {
                'id': 'V2.2.1',
                'title': 'Multi-Factor Authentication',
                'description': 'Verify that multi-factor authentication is enforced for administrative accounts.',
                'category': 'Authentication',
                'level': 'L2',
                'risk_level': 'high'
            },
            {
                'id': 'V2.3.1',
                'title': 'Account Recovery',
                'description': 'Verify that secure account recovery mechanisms are implemented.',
                'category': 'Authentication',
                'level': 'L2',
                'risk_level': 'medium'
            },
            
            # V3: Session Management
            {
                'id': 'V3.1.1',
                'title': 'Session Token Generation',
                'description': 'Verify that the application generates a new session token on user authentication.',
                'category': 'Session Management',
                'level': 'L1',
                'risk_level': 'high'
            },
            {
                'id': 'V3.2.1',
                'title': 'Session Timeout',
                'description': 'Verify that sessions timeout after a defined period of inactivity.',
                'category': 'Session Management',
                'level': 'L1',
                'risk_level': 'medium'
            },
            
            # V4: Access Control
            {
                'id': 'V4.1.1',
                'title': 'Principle of Least Privilege',
                'description': 'Verify that the principle of least privilege exists for access control decisions.',
                'category': 'Access Control',
                'level': 'L1',
                'risk_level': 'high'
            },
            {
                'id': 'V4.2.1',
                'title': 'Resource-based Access Control',
                'description': 'Verify that the application enforces access control rules on the server side.',
                'category': 'Access Control',
                'level': 'L2',
                'risk_level': 'high'
            },
            
            # V5: Validation, Sanitization and Encoding
            {
                'id': 'V5.1.1',
                'title': 'Input Validation',
                'description': 'Verify that the application has defenses against HTTP parameter pollution attacks.',
                'category': 'Input Validation',
                'level': 'L1',
                'risk_level': 'high'
            },
            {
                'id': 'V5.2.1',
                'title': 'Injection Prevention',
                'description': 'Verify that all SQL queries use parameterized queries or prepared statements.',
                'category': 'Input Validation',
                'level': 'L1',
                'risk_level': 'high'
            },
            {
                'id': 'V5.3.1',
                'title': 'Output Encoding',
                'description': 'Verify that output encoding is relevant for the interpreter and context required.',
                'category': 'Input Validation',
                'level': 'L1',
                'risk_level': 'high'
            },
            
            # V6: Stored Cryptography
            {
                'id': 'V6.1.1',
                'title': 'Data Classification',
                'description': 'Verify that regulated private data is stored encrypted while at rest.',
                'category': 'Cryptography',
                'level': 'L2',
                'risk_level': 'high'
            },
            {
                'id': 'V6.2.1',
                'title': 'Algorithm Strength',
                'description': 'Verify that industry proven or government approved cryptographic algorithms are used.',
                'category': 'Cryptography',
                'level': 'L2',
                'risk_level': 'high'
            },
            
            # V7: Error Handling and Logging
            {
                'id': 'V7.1.1',
                'title': 'Error Handling',
                'description': 'Verify that the application does not log credentials or payment details.',
                'category': 'Error Handling',
                'level': 'L1',
                'risk_level': 'medium'
            },
            {
                'id': 'V7.2.1',
                'title': 'Security Logging',
                'description': 'Verify that security events are logged with sufficient detail.',
                'category': 'Error Handling',
                'level': 'L2',
                'risk_level': 'medium'
            },
            
            # V8: Data Protection
            {
                'id': 'V8.1.1',
                'title': 'Sensitive Data Protection',
                'description': 'Verify that the application protects sensitive data from being cached by browser components.',
                'category': 'Data Protection',
                'level': 'L1',
                'risk_level': 'medium'
            },
            {
                'id': 'V8.2.1',
                'title': 'Client-side Storage',
                'description': 'Verify that no sensitive data is stored in client-side storage mechanisms.',
                'category': 'Data Protection',
                'level': 'L1',
                'risk_level': 'high'
            },
            
            # V9: Communication
            {
                'id': 'V9.1.1',
                'title': 'TLS Implementation',
                'description': 'Verify that TLS is used for all connectivity that transmits sensitive data.',
                'category': 'Communication',
                'level': 'L1',
                'risk_level': 'high'
            },
            {
                'id': 'V9.2.1',
                'title': 'Certificate Validation',
                'description': 'Verify that certificate validation is properly implemented.',
                'category': 'Communication',
                'level': 'L2',
                'risk_level': 'high'
            },
            
            # V10: Malicious Code
            {
                'id': 'V10.1.1',
                'title': 'Code Integrity',
                'description': 'Verify that application source code and third party libraries do not contain malicious code.',
                'category': 'Malicious Code',
                'level': 'L2',
                'risk_level': 'high'
            },
            
            # V11: Business Logic
            {
                'id': 'V11.1.1',
                'title': 'Business Logic Flow',
                'description': 'Verify that the application enforces business logic requirements in the correct order.',
                'category': 'Business Logic',
                'level': 'L1',
                'risk_level': 'medium'
            },
            
            # V12: Files and Resources
            {
                'id': 'V12.1.1',
                'title': 'File Upload Security',
                'description': 'Verify that user-uploaded files are served from a separate domain or CDN.',
                'category': 'File Security',
                'level': 'L1',
                'risk_level': 'medium'
            },
            
            # V13: API and Web Service
            {
                'id': 'V13.1.1',
                'title': 'API Security',
                'description': 'Verify that all application components use the same encodings and parsers.',
                'category': 'API Security',
                'level': 'L1',
                'risk_level': 'medium'
            },
            
            # V14: Configuration
            {
                'id': 'V14.1.1',
                'title': 'Build Environment',
                'description': 'Verify that the build pipeline warns of out-of-date or insecure components.',
                'category': 'Configuration',
                'level': 'L2',
                'risk_level': 'medium'
            }
        ]

    # Testing methods
    @staticmethod
    def test_authentication_strength(app_url):
        """Test V2: Authentication requirements"""
        try:
            evidence = []
            
            # Test for login page
            response = requests.get(app_url, timeout=10, verify=False)
            
            # Look for authentication mechanisms
            auth_indicators = [
                'login', 'signin', 'password', 'username', 'email',
                'authentication', 'oauth', 'sso'
            ]
            
            response_text = response.text.lower()
            found_auth = any(indicator in response_text for indicator in auth_indicators)
            
            if found_auth:
                evidence.append("Authentication mechanism detected")
                
                # Test for multi-factor authentication indicators
                mfa_indicators = ['2fa', 'mfa', 'totp', 'authenticator', 'verification code']
                has_mfa = any(indicator in response_text for indicator in mfa_indicators)
                
                if has_mfa:
                    evidence.append("Multi-factor authentication appears to be implemented")
                else:
                    evidence.append("No multi-factor authentication detected")
                
                # Test for password policy hints
                policy_indicators = [
                    'password must', 'minimum length', 'at least', 'characters',
                    'uppercase', 'lowercase', 'number', 'special character'
                ]
                
                has_policy = any(indicator in response_text for indicator in policy_indicators)
                if has_policy:
                    evidence.append("Password policy requirements found")
                else:
                    evidence.append("No visible password policy requirements")
            
            # Check for secure authentication headers
            secure_headers = ['strict-transport-security', 'x-frame-options', 'x-content-type-options']
            present_headers = [h for h in secure_headers if h in response.headers]
            
            if present_headers:
                evidence.append(f"Security headers present: {', '.join(present_headers)}")
            else:
                evidence.append("Missing security headers")
            
            if evidence:
                return {
                    'result': 'informational',
                    'evidence': f"Authentication analysis: {'; '.join(evidence)}",
                    'request': f'GET {app_url}',
                    'response': f'Authentication mechanisms analyzed'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No authentication issues detected',
                    'request': f'GET {app_url}',
                    'response': 'Authentication appears properly implemented'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing authentication: {str(e)}',
                'request': f'GET {app_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_session_management(app_url):
        """Test V3: Session Management requirements"""
        try:
            evidence = []
            
            # Make initial request
            session = requests.Session()
            response = session.get(app_url, timeout=10, verify=False)
            
            # Check for session cookies
            cookies = session.cookies
            session_cookies = []
            
            for cookie in cookies:
                if any(name in cookie.name.lower() for name in ['session', 'sess', 'jsession', 'phpsession']):
                    session_cookies.append(cookie.name)
                    
                    # Check cookie security attributes
                    if not cookie.secure:
                        evidence.append(f"Session cookie {cookie.name} missing Secure flag")
                    
                    if not hasattr(cookie, 'httponly') or not cookie.httponly:
                        evidence.append(f"Session cookie {cookie.name} missing HttpOnly flag")
                    
                    if not hasattr(cookie, 'samesite') or not cookie.samesite:
                        evidence.append(f"Session cookie {cookie.name} missing SameSite attribute")
            
            if session_cookies:
                evidence.append(f"Session cookies found: {', '.join(session_cookies)}")
            else:
                evidence.append("No obvious session cookies detected")
            
            # Check for session-related headers
            session_headers = [
                'set-cookie', 'cache-control', 'pragma', 'expires'
            ]
            
            present_session_headers = [h for h in session_headers if h in response.headers]
            if present_session_headers:
                evidence.append(f"Session-related headers: {', '.join(present_session_headers)}")
            
            if evidence:
                return {
                    'result': 'informational',
                    'evidence': f"Session management analysis: {'; '.join(evidence)}",
                    'request': f'GET {app_url}',
                    'response': f'Session mechanisms analyzed'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'No session management issues detected',
                    'request': f'GET {app_url}',
                    'response': 'Session management appears properly implemented'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing session management: {str(e)}',
                'request': f'GET {app_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_input_validation_asvs(app_url):
        """Test V5: Validation, Sanitization and Encoding requirements"""
        try:
            evidence = []
            
            # Test for input validation on common parameters
            test_params = [
                ('search', '<script>alert("xss")</script>'),
                ('id', "'; DROP TABLE users; --"),
                ('name', '../../../etc/passwd'),
                ('email', 'test@<script>alert("xss")</script>.com'),
                ('url', 'javascript:alert("xss")')
            ]
            
            for param, payload in test_params:
                try:
                    test_url = f"{app_url}?{param}={payload}"
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Check if payload is reflected without encoding
                    if payload in response.text:
                        evidence.append(f"Unencoded input reflection for parameter: {param}")
                    
                    # Check for SQL error messages
                    sql_errors = ['sql', 'mysql', 'postgresql', 'oracle', 'sqlite']
                    response_lower = response.text.lower()
                    
                    for error_type in sql_errors:
                        if error_type in response_lower:
                            evidence.append(f"Potential SQL injection in parameter: {param}")
                            break
                            
                except:
                    continue
            
            # Check response headers for XSS protection
            xss_protection_headers = [
                'x-xss-protection', 'x-content-type-options', 
                'content-security-policy', 'x-frame-options'
            ]
            
            response = requests.get(app_url, timeout=10, verify=False)
            missing_headers = [h for h in xss_protection_headers if h not in response.headers]
            
            if missing_headers:
                evidence.append(f"Missing XSS protection headers: {', '.join(missing_headers)}")
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Input validation issues: {'; '.join(evidence)}",
                    'request': f'Input validation tests on {app_url}',
                    'response': f'Found {len(evidence)} potential issues'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'Input validation appears properly implemented',
                    'request': f'Input validation tests on {app_url}',
                    'response': 'No input validation issues detected'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing input validation: {str(e)}',
                'request': f'Input validation test on {app_url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_communication_security(app_url):
        """Test V9: Communication requirements"""
        try:
            evidence = []
            parsed_url = urlparse(app_url)
            
            # Test HTTPS enforcement
            if parsed_url.scheme == 'http':
                evidence.append("Application uses unencrypted HTTP")
                
                # Test if HTTPS is available
                https_url = app_url.replace('http://', 'https://')
                try:
                    https_response = requests.get(https_url, timeout=10, verify=False)
                    if https_response.status_code == 200:
                        evidence.append("HTTPS is available but not enforced")
                    else:
                        evidence.append("HTTPS not available")
                except:
                    evidence.append("HTTPS not available")
            
            # Test for HSTS header
            response = requests.get(app_url, timeout=10, verify=False)
            
            if 'strict-transport-security' not in response.headers:
                evidence.append("Missing Strict-Transport-Security header")
            else:
                hsts_value = response.headers['strict-transport-security']
                if 'max-age' not in hsts_value:
                    evidence.append("HSTS header missing max-age directive")
                if 'includeSubDomains' not in hsts_value:
                    evidence.append("HSTS header missing includeSubDomains directive")
            
            # Test for secure cookie transmission
            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure and parsed_url.scheme == 'https':
                    evidence.append(f"Cookie {cookie.name} missing Secure flag")
            
            # Test for mixed content issues
            if parsed_url.scheme == 'https':
                # Look for HTTP resources in HTTPS page
                http_resources = re.findall(r'http://[^"\s<>]+', response.text)
                if http_resources:
                    evidence.append(f"Mixed content detected: {len(http_resources)} HTTP resources in HTTPS page")
            
            if evidence:
                return {
                    'result': 'fail',
                    'evidence': f"Communication security issues: {'; '.join(evidence)}",
                    'request': f'Communication analysis of {app_url}',
                    'response': f'Found {len(evidence)} security issues'
                }
            else:
                return {
                    'result': 'pass',
                    'evidence': 'Communication security appears properly implemented',
                    'request': f'Communication analysis of {app_url}',
                    'response': 'No communication security issues detected'
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'Error testing communication security: {str(e)}',
                'request': f'Communication test of {app_url}',
                'response': 'Request failed - connection error'
            }
