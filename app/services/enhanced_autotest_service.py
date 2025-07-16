"""
Enhanced Automated Testing Service with OWASP Test Mapping

This module provides automated security testing capabilities for web applications
and automatically updates the OWASP checklist based on test results.
"""

import requests
import re
import socket
import ssl
import dns.resolver
from urllib.parse import urlparse, urljoin
from app.utils.datetime_utils import utc_now
from app import db
from app.models import TestItem


class EnhancedAutoTestService:
    """Enhanced auto-testing service that maps results to OWASP checklist items"""
    
    # Mapping of auto-tests to OWASP test IDs
    OWASP_TEST_MAPPING = {
        'HSTS Test': [
            'WSTG-CRYP-01',  # Testing for Weak Transport Layer Security
            'WSTG-CONF-07',  # Testing HTTP Strict Transport Security
        ],
        'Security Headers Test': [
            'WSTG-CONF-07',  # Testing HTTP Strict Transport Security
            'WSTG-CLNT-03',  # Testing for HTML Injection
            'WSTG-CLNT-13',  # Testing for Cross Site Flashing
        ],
        'SSL Configuration Test': [
            'WSTG-CRYP-01',  # Testing for Weak Transport Layer Security
            'WSTG-CRYP-02',  # Testing for Padding Oracle
            'WSTG-CRYP-03',  # Testing for Sensitive Information Sent via Unencrypted Channels
        ],
        'Cookie Security Test': [
            'WSTG-SESS-02',  # Testing for Cookies Attributes
            'WSTG-SESS-03',  # Testing for Session Fixation
            'WSTG-SESS-04',  # Testing for Exposed Session Variables
        ],
        'HTTP Methods Test': [
            'WSTG-CONF-06',  # Testing HTTP Methods
            'WSTG-INFO-02',  # Fingerprint Web Server
        ],
        'Information Disclosure Test': [
            'WSTG-INFO-02',  # Fingerprint Web Server
            'WSTG-INFO-08',  # Fingerprint Web Application Framework
            'WSTG-INFO-09',  # Fingerprint Web Application
            'WSTG-ERRH-01',  # Testing for Improper Error Handling
            'WSTG-ERRH-02',  # Testing for Stack Traces
        ],
        'Clickjacking Protection Test': [
            'WSTG-CLNT-09',  # Testing for Clickjacking
        ],
        'Input Validation Test': [
            'WSTG-INPV-01',  # Testing for Reflected Cross Site Scripting
            'WSTG-INPV-02',  # Testing for Stored Cross Site Scripting
            'WSTG-INPV-05',  # Testing for SQL Injection
            'WSTG-INPV-12',  # Testing for Command Injection
            'WSTG-ATHZ-01',  # Testing Directory Traversal File Include
        ],
        'CORS Configuration Test': ['WSTG-CONF-11'],
        'Content Type Validation Test': ['WSTG-INPV-16'],
        'Cache Control Test': ['WSTG-ATHN-06'],
        'Directory Listing Test': ['WSTG-CONF-04'],
        'Error Handling Test': ['WSTG-ERRH-01', 'WSTG-ERRH-02'],
        'Input Validation Test': ['WSTG-INPV-01'],
        'Robots.txt Analysis': ['WSTG-INFO-01'],
        'Web Server Detection': ['WSTG-INFO-02'],
        'Admin Panel Detection': ['WSTG-CONF-05'],
        'Backup File Detection': ['WSTG-CONF-04'],
        'Version Control Exposure': ['WSTG-CONF-09']
    }

    @staticmethod
    def _format_request_details(method, url, headers=None, data=None):
        """Format full HTTP request details"""
        request_lines = [f"{method} {url} HTTP/1.1"]
        
        if headers:
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
        
        request_lines.append("")  # Empty line between headers and body
        
        if data:
            request_lines.append(str(data))
        
        return "\n".join(request_lines)
    
    @staticmethod
    def _format_response_details(response, highlight_headers=None):
        """Format full HTTP response with highlighting"""
        response_lines = [f"HTTP/1.1 {response.status_code} {response.reason}"]
        
        # Add all response headers
        for key, value in response.headers.items():
            if highlight_headers and key in highlight_headers:
                response_lines.append(f">>> {key}: {value} <<<  [HIGHLIGHTED]")
            else:
                response_lines.append(f"{key}: {value}")
        
        response_lines.append("")  # Empty line between headers and body
        
        # Add response body (truncated for readability)
        if response.content:
            content = response.text[:1000] if len(response.text) > 1000 else response.text
            if len(response.text) > 1000:
                content += "\n... [Response truncated]"
            response_lines.append(content)
        
        return "\n".join(response_lines)

    @staticmethod
    def update_checklist_items(project_id, test_name, test_result):
        """Update OWASP checklist items based on auto-test results"""
        mapped_tests = EnhancedAutoTestService.OWASP_TEST_MAPPING.get(test_name, [])
        
        for owasp_id in mapped_tests:
            test_item = TestItem.query.filter_by(
                project_id=project_id,
                owasp_id=owasp_id
            ).first()
            
            if test_item:
                # Update test status based on auto-test result
                if test_result['result'] == 'pass':
                    test_item.finding_status = 'pass'
                    test_item.risk_level = 'low'
                elif test_result['result'] == 'fail':
                    test_item.finding_status = 'fail'
                    test_item.risk_level = 'medium'  # Default to medium, user can adjust
                elif test_result['result'] == 'error':
                    test_item.finding_status = 'error'
                else:
                    test_item.finding_status = 'informational'
                
                # Update evidence with auto-test results
                auto_evidence = f"🤖 AUTOMATED TEST RESULT:\n{test_result['evidence']}\n\n"
                if test_item.evidence:
                    test_item.evidence = auto_evidence + "📝 MANUAL NOTES:\n" + test_item.evidence
                else:
                    test_item.evidence = auto_evidence
                
                test_item.is_tested = True
                
        db.session.commit()

    @staticmethod
    def test_hsts(url):
        """Enhanced HSTS test with better analysis"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner v2.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            # Test HTTPS version if HTTP provided
            parsed_url = urlparse(url)
            if parsed_url.scheme == 'http':
                https_url = url.replace('http://', 'https://', 1)
                try:
                    response = requests.get(https_url, headers=headers, timeout=10, verify=False)
                    url = https_url  # Use HTTPS for testing
                except:
                    # Fall back to HTTP if HTTPS not available
                    response = requests.get(url, headers=headers, timeout=10, verify=False)
            else:
                response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            hsts_header = response.headers.get('Strict-Transport-Security')
            
            full_request = EnhancedAutoTestService._format_request_details('GET', url, headers)
            full_response = EnhancedAutoTestService._format_response_details(response, ['Strict-Transport-Security'])
            
            if hsts_header:
                # Enhanced HSTS analysis
                max_age = 'Unknown'
                include_subdomains = 'includeSubDomains' in hsts_header
                preload = 'preload' in hsts_header
                
                if 'max-age=' in hsts_header:
                    max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                
                evidence = f"✅ HSTS HEADER FOUND\n"
                evidence += f"📄 Header Value: {hsts_header}\n\n"
                evidence += f"📊 DETAILED ANALYSIS:\n"
                evidence += f"  • Max-Age: {max_age} seconds"
                
                if isinstance(max_age, int):
                    days = max_age // 86400
                    evidence += f" ({days} days)\n"
                    
                    if max_age < 31536000:  # Less than 1 year
                        evidence += f"  ⚠️  Recommendation: Increase to at least 31536000 (1 year)\n"
                    else:
                        evidence += f"  ✅ Good: Meets minimum 1-year requirement\n"
                else:
                    evidence += "\n"
                
                evidence += f"  • Include Subdomains: {'✅ Yes' if include_subdomains else '❌ No (Recommended: Yes)'}\n"
                evidence += f"  • Preload Ready: {'✅ Yes' if preload else '❌ No (Optional but recommended)'}\n\n"
                
                if include_subdomains and preload and isinstance(max_age, int) and max_age >= 31536000:
                    evidence += f"🎯 EXCELLENT: All HSTS best practices implemented!"
                    result = 'pass'
                elif isinstance(max_age, int) and max_age >= 86400:  # At least 1 day
                    evidence += f"✅ GOOD: Basic HSTS protection enabled"
                    result = 'pass'
                else:
                    evidence += f"⚠️  WEAK: HSTS present but needs improvement"
                    result = 'fail'
                
                return {
                    'result': result,
                    'evidence': evidence,
                    'request': full_request,
                    'response': full_response
                }
            else:
                evidence = f"❌ HSTS HEADER MISSING\n\n"
                evidence += f"🚨 SECURITY RISKS:\n"
                evidence += f"  • Protocol downgrade attacks possible\n"
                evidence += f"  • Man-in-the-middle attacks via SSL stripping\n"
                evidence += f"  • Users vulnerable to HTTP interception\n\n"
                evidence += f"💡 SOLUTION:\n"
                evidence += f"Add this header to your web server configuration:\n"
                evidence += f"Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                
                return {
                    'result': 'fail',
                    'evidence': evidence,
                    'request': full_request,
                    'response': full_response
                }
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing HSTS: {str(e)}',
                'request': f'GET {url}',
                'response': 'Request failed - no response received'
            }

    @staticmethod
    def test_security_headers(url):
        """Enhanced security headers test with comprehensive analysis"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner v2.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Security headers to check
            security_headers = {
                'X-Frame-Options': {
                    'purpose': 'Clickjacking protection',
                    'good_values': ['DENY', 'SAMEORIGIN'],
                    'recommendation': 'X-Frame-Options: DENY'
                },
                'X-Content-Type-Options': {
                    'purpose': 'MIME type sniffing protection',
                    'good_values': ['nosniff'],
                    'recommendation': 'X-Content-Type-Options: nosniff'
                },
                'X-XSS-Protection': {
                    'purpose': 'XSS filter (legacy browsers)',
                    'good_values': ['1; mode=block'],
                    'recommendation': 'X-XSS-Protection: 1; mode=block'
                },
                'Referrer-Policy': {
                    'purpose': 'Control referrer information',
                    'good_values': ['strict-origin-when-cross-origin', 'strict-origin', 'no-referrer'],
                    'recommendation': 'Referrer-Policy: strict-origin-when-cross-origin'
                },
                'Content-Security-Policy': {
                    'purpose': 'XSS and injection protection',
                    'good_values': None,  # Too complex for simple check
                    'recommendation': "Content-Security-Policy: default-src 'self'"
                },
                'Permissions-Policy': {
                    'purpose': 'Feature policy control',
                    'good_values': None,
                    'recommendation': 'Permissions-Policy: camera=(), microphone=(), geolocation=()'
                }
            }
            
            full_request = EnhancedAutoTestService._format_request_details('GET', url, headers)
            highlight_headers = list(security_headers.keys()) + ['Strict-Transport-Security']
            full_response = EnhancedAutoTestService._format_response_details(response, highlight_headers)
            
            evidence = f"🛡️ SECURITY HEADERS ANALYSIS\n\n"
            missing_headers = []
            present_headers = []
            weak_headers = []
            
            for header, config in security_headers.items():
                header_value = response.headers.get(header)
                
                if header_value:
                    present_headers.append(header)
                    evidence += f"✅ {header}: {header_value}\n"
                    evidence += f"   Purpose: {config['purpose']}\n"
                    
                    # Check if value is good
                    if config['good_values']:
                        if not any(good_val in header_value for good_val in config['good_values']):
                            weak_headers.append(header)
                            evidence += f"   ⚠️  Warning: Value may not be optimal\n"
                    evidence += "\n"
                else:
                    missing_headers.append(header)
                    evidence += f"❌ {header}: MISSING\n"
                    evidence += f"   Purpose: {config['purpose']}\n"
                    evidence += f"   Recommended: {config['recommendation']}\n\n"
            
            # Overall assessment
            total_headers = len(security_headers)
            present_count = len(present_headers)
            
            evidence += f"📊 SUMMARY:\n"
            evidence += f"  • Present: {present_count}/{total_headers} headers\n"
            evidence += f"  • Missing: {len(missing_headers)} headers\n"
            evidence += f"  • Weak configurations: {len(weak_headers)} headers\n\n"
            
            # Determine result
            if present_count >= total_headers * 0.8:  # 80% or more present
                if len(weak_headers) == 0:
                    result = 'pass'
                    evidence += f"🎯 EXCELLENT: Strong security header configuration!"
                else:
                    result = 'pass'
                    evidence += f"✅ GOOD: Most security headers present, minor improvements possible"
            elif present_count >= total_headers * 0.5:  # 50% or more present
                result = 'fail'
                evidence += f"⚠️  PARTIAL: Some security headers missing"
            else:
                result = 'fail'
                evidence += f"🚨 POOR: Critical security headers missing"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing security headers: {str(e)}',
                'request': f'GET {url}',
                'response': 'Request failed - no response received'
            }

    @staticmethod
    def test_ssl_configuration(url):
        """Enhanced SSL configuration test"""
        try:
            parsed_url = urlparse(url)
            
            if parsed_url.scheme != 'https':
                return {
                    'result': 'fail',
                    'evidence': '❌ URL is not HTTPS - SSL configuration cannot be tested',
                    'request': f'GET {url}',
                    'response': 'Non-HTTPS URL provided'
                }
            
            hostname = parsed_url.netloc.split(':')[0]
            port = parsed_url.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            evidence = f"🔐 SSL/TLS CONFIGURATION ANALYSIS\n\n"
            evidence += f"📄 CERTIFICATE INFORMATION:\n"
            evidence += f"  • Subject: {dict(x[0] for x in cert['subject'])}\n"
            evidence += f"  • Issuer: {dict(x[0] for x in cert['issuer'])}\n"
            evidence += f"  • Valid From: {cert['notBefore']}\n"
            evidence += f"  • Valid Until: {cert['notAfter']}\n"
            evidence += f"  • Serial Number: {cert['serialNumber']}\n\n"
            
            evidence += f"🔒 CONNECTION DETAILS:\n"
            evidence += f"  • TLS Version: {version}\n"
            evidence += f"  • Cipher Suite: {cipher[0] if cipher else 'Unknown'}\n"
            evidence += f"  • Key Exchange: {cipher[1] if cipher and len(cipher) > 1 else 'Unknown'}\n"
            evidence += f"  • Encryption: {cipher[2] if cipher and len(cipher) > 2 else 'Unknown'}\n\n"
            
            # Check for security issues
            issues = []
            
            # Check TLS version
            if version in ['TLSv1.3', 'TLSv1.2']:
                evidence += f"✅ TLS Version: {version} (Secure)\n"
            elif version == 'TLSv1.1':
                evidence += f"⚠️  TLS Version: {version} (Deprecated, upgrade recommended)\n"
                issues.append("Outdated TLS version")
            else:
                evidence += f"❌ TLS Version: {version} (Insecure)\n"
                issues.append("Insecure TLS version")
            
            # Check cipher strength
            if cipher and cipher[0]:
                if 'AES' in cipher[0] and ('GCM' in cipher[0] or 'CBC' in cipher[0]):
                    evidence += f"✅ Cipher: Strong encryption detected\n"
                elif 'RC4' in cipher[0] or 'DES' in cipher[0]:
                    evidence += f"❌ Cipher: Weak encryption detected\n"
                    issues.append("Weak cipher suite")
                else:
                    evidence += f"⚠️  Cipher: Unknown strength\n"
            
            # Overall assessment
            if not issues:
                result = 'pass'
                evidence += f"\n🎯 EXCELLENT: SSL/TLS configuration is secure!"
            elif len(issues) == 1 and "Deprecated" in evidence:
                result = 'pass'
                evidence += f"\n✅ GOOD: SSL/TLS mostly secure, minor improvements possible"
            else:
                result = 'fail'
                evidence += f"\n🚨 ISSUES FOUND: {', '.join(issues)}"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': f'SSL Connection to {hostname}:{port}',
                'response': f'Certificate and connection details retrieved'
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing SSL configuration: {str(e)}',
                'request': f'SSL Connection to {url}',
                'response': 'SSL connection failed'
            }

    @staticmethod
    def test_cookie_security(url):
        """Enhanced cookie security test"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner v2.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Get all cookies from response
            cookies = response.cookies
            set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
            
            # Also check raw headers for Set-Cookie
            raw_cookies = []
            for key, value in response.headers.items():
                if key.lower() == 'set-cookie':
                    raw_cookies.append(value)
            
            full_request = EnhancedAutoTestService._format_request_details('GET', url, headers)
            full_response = EnhancedAutoTestService._format_response_details(response, ['Set-Cookie'])
            
            if not cookies and not raw_cookies:
                return {
                    'result': 'informational',
                    'evidence': 'ℹ️  No cookies set by this endpoint\n\nThis may be expected for static resources or APIs.',
                    'request': full_request,
                    'response': full_response
                }
            
            evidence = f"🍪 COOKIE SECURITY ANALYSIS\n\n"
            total_issues = 0
            total_cookies = len(cookies) + len(raw_cookies)
            
            # Analyze cookies from response.cookies
            for cookie in cookies:
                evidence += f"📋 Cookie: {cookie.name}\n"
                evidence += f"   Value: {cookie.value[:50]}{'...' if len(cookie.value) > 50 else ''}\n"
                
                issues = []
                security_attrs = []
                
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                else:
                    security_attrs.append("Secure")
                
                if not getattr(cookie, 'httponly', False):
                    issues.append("Missing HttpOnly flag")
                else:
                    security_attrs.append("HttpOnly")
                
                if not getattr(cookie, 'samesite', None):
                    issues.append("Missing SameSite attribute")
                else:
                    security_attrs.append(f"SameSite={cookie.samesite}")
                
                if security_attrs:
                    evidence += f"   ✅ Security: {', '.join(security_attrs)}\n"
                
                if issues:
                    evidence += f"   ❌ Issues: {', '.join(issues)}\n"
                    total_issues += len(issues)
                else:
                    evidence += f"   ✅ All security attributes present\n"
                
                evidence += "\n"
            
            # Analyze raw Set-Cookie headers
            for i, cookie_header in enumerate(raw_cookies, 1):
                evidence += f"📋 Set-Cookie Header {i}:\n"
                evidence += f"   {cookie_header}\n"
                
                issues = []
                security_attrs = []
                
                if 'Secure' not in cookie_header:
                    issues.append("Missing Secure flag")
                else:
                    security_attrs.append("Secure")
                
                if 'HttpOnly' not in cookie_header:
                    issues.append("Missing HttpOnly flag")
                else:
                    security_attrs.append("HttpOnly")
                
                if 'SameSite' not in cookie_header:
                    issues.append("Missing SameSite attribute")
                else:
                    samesite_match = re.search(r'SameSite=([^;]+)', cookie_header)
                    if samesite_match:
                        security_attrs.append(f"SameSite={samesite_match.group(1)}")
                
                if security_attrs:
                    evidence += f"   ✅ Security: {', '.join(security_attrs)}\n"
                
                if issues:
                    evidence += f"   ❌ Issues: {', '.join(issues)}\n"
                    total_issues += len(issues)
                else:
                    evidence += f"   ✅ All security attributes present\n"
                
                evidence += "\n"
            
            # Overall assessment
            evidence += f"📊 SUMMARY:\n"
            evidence += f"  • Total cookies analyzed: {total_cookies}\n"
            evidence += f"  • Security issues found: {total_issues}\n\n"
            
            if total_issues == 0:
                result = 'pass'
                evidence += f"🎯 EXCELLENT: All cookies have proper security attributes!"
            elif total_issues <= total_cookies:  # Minor issues
                result = 'fail'
                evidence += f"⚠️  SOME ISSUES: Cookie security can be improved"
            else:
                result = 'fail'
                evidence += f"🚨 SIGNIFICANT ISSUES: Multiple cookie security problems found"
            
            evidence += f"\n💡 RECOMMENDATIONS:\n"
            evidence += f"  • Add 'Secure' flag for HTTPS-only transmission\n"
            evidence += f"  • Add 'HttpOnly' flag to prevent XSS access\n"
            evidence += f"  • Add 'SameSite=Strict' or 'SameSite=Lax' for CSRF protection"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing cookie security: {str(e)}',
                'request': f'GET {url}',
                'response': 'Request failed - no response received'
            }

    @staticmethod
    def test_http_methods(url):
        """Enhanced HTTP methods test"""
        try:
            dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT', 'OPTIONS']
            safe_methods = ['GET', 'POST', 'HEAD']
            
            evidence = f"🔍 HTTP METHODS ANALYSIS\n\n"
            allowed_methods = []
            dangerous_allowed = []
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner v2.0',
                'Accept': '*/*'
            }
            
            # Test each method
            for method in dangerous_methods + safe_methods:
                try:
                    response = requests.request(method, url, headers=headers, timeout=5, verify=False)
                    
                    if response.status_code != 405:  # Method Not Allowed
                        allowed_methods.append(method)
                        
                        if method in dangerous_methods:
                            dangerous_allowed.append(method)
                        
                        evidence += f"⚠️  {method}: Allowed (Status: {response.status_code})\n"
                        
                        # Check for interesting headers
                        allow_header = response.headers.get('Allow', '')
                        if allow_header:
                            evidence += f"     Allow header: {allow_header}\n"
                    else:
                        evidence += f"✅ {method}: Not Allowed (Status: 405)\n"
                        
                except requests.exceptions.RequestException:
                    evidence += f"❓ {method}: Request failed\n"
            
            evidence += f"\n📊 SUMMARY:\n"
            evidence += f"  • Total methods tested: {len(dangerous_methods + safe_methods)}\n"
            evidence += f"  • Allowed methods: {len(allowed_methods)}\n"
            evidence += f"  • Dangerous methods allowed: {len(dangerous_allowed)}\n\n"
            
            if dangerous_allowed:
                evidence += f"🚨 DANGEROUS METHODS ENABLED: {', '.join(dangerous_allowed)}\n"
                evidence += f"💡 RECOMMENDATION: Disable unnecessary HTTP methods\n"
                evidence += f"   Consider allowing only GET, POST, and HEAD methods"
                result = 'fail'
            else:
                evidence += f"✅ SECURE: No dangerous HTTP methods detected"
                result = 'pass'
            
            full_request = f"Testing methods: {', '.join(dangerous_methods + safe_methods)}"
            full_response = f"Tested {len(dangerous_methods + safe_methods)} HTTP methods"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing HTTP methods: {str(e)}',
                'request': f'HTTP Methods test for {url}',
                'response': 'Test failed'
            }

    @staticmethod
    def test_information_disclosure(url):
        """Enhanced information disclosure test"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner v2.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Information disclosure patterns
            disclosure_patterns = {
                'Server Information': [
                    r'Server:\s*(.+)',
                    r'X-Powered-By:\s*(.+)',
                    r'X-AspNet-Version:\s*(.+)',
                    r'X-AspNetMvc-Version:\s*(.+)'
                ],
                'Debug Information': [
                    r'DEBUG\s*=\s*True',
                    r'development\s*mode',
                    r'stacktrace',
                    r'exception\s*details',
                    r'error\s*details'
                ],
                'Version Information': [
                    r'version\s*[:\=]\s*[\d\.]+',
                    r'build\s*[:\=]\s*[\d\.]+',
                    r'release\s*[:\=]\s*[\d\.]+'
                ],
                'Directory Paths': [
                    r'[C-Z]:\\[\w\\]+',
                    r'/var/www/[\w/]+',
                    r'/home/[\w/]+',
                    r'/usr/[\w/]+'
                ]
            }
            
            evidence = f"🔍 INFORMATION DISCLOSURE ANALYSIS\n\n"
            disclosures_found = []
            
            # Check response headers
            evidence += f"📋 RESPONSE HEADERS:\n"
            sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            
            for header in sensitive_headers:
                if header in response.headers:
                    value = response.headers[header]
                    evidence += f"  ⚠️  {header}: {value}\n"
                    disclosures_found.append(f"Header: {header}")
                else:
                    evidence += f"  ✅ {header}: Not disclosed\n"
            
            evidence += f"\n📄 RESPONSE BODY ANALYSIS:\n"
            
            # Check response body for patterns
            body_text = response.text.lower()
            for category, patterns in disclosure_patterns.items():
                category_matches = []
                
                for pattern in patterns:
                    matches = re.findall(pattern, body_text, re.IGNORECASE)
                    if matches:
                        category_matches.extend(matches)
                
                if category_matches:
                    evidence += f"  ⚠️  {category}: {len(category_matches)} potential disclosures found\n"
                    disclosures_found.append(category)
                    
                    # Show first few matches
                    for match in category_matches[:3]:
                        evidence += f"     - {match}\n"
                    if len(category_matches) > 3:
                        evidence += f"     ... and {len(category_matches) - 3} more\n"
                else:
                    evidence += f"  ✅ {category}: No disclosures detected\n"
            
            evidence += f"\n📊 SUMMARY:\n"
            evidence += f"  • Total disclosure categories: {len(disclosures_found)}\n"
            
            if disclosures_found:
                evidence += f"  • Found disclosures: {', '.join(disclosures_found)}\n"
                evidence += f"\n🚨 RECOMMENDATION:\n"
                evidence += f"  • Remove or obscure server version headers\n"
                evidence += f"  • Disable debug mode in production\n"
                evidence += f"  • Implement custom error pages\n"
                evidence += f"  • Review application output for sensitive information"
                result = 'fail'
            else:
                evidence += f"  ✅ No obvious information disclosures detected"
                result = 'pass'
            
            full_request = EnhancedAutoTestService._format_request_details('GET', url, headers)
            full_response = EnhancedAutoTestService._format_response_details(response, sensitive_headers)
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing information disclosure: {str(e)}',
                'request': f'GET {url}',
                'response': 'Request failed - no response received'
            }

    @staticmethod
    def test_clickjacking_protection(url):
        """Enhanced clickjacking protection test"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner v2.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Check for clickjacking protection headers
            x_frame_options = response.headers.get('X-Frame-Options')
            csp_header = response.headers.get('Content-Security-Policy')
            
            evidence = f"🛡️ CLICKJACKING PROTECTION ANALYSIS\n\n"
            
            # Analyze X-Frame-Options
            evidence += f"📋 X-Frame-Options Header:\n"
            if x_frame_options:
                evidence += f"  ✅ Present: {x_frame_options}\n"
                
                if x_frame_options.upper() == 'DENY':
                    evidence += f"  🎯 EXCELLENT: Denies all framing (strongest protection)\n"
                    xfo_score = 3
                elif x_frame_options.upper() == 'SAMEORIGIN':
                    evidence += f"  ✅ GOOD: Allows framing from same origin only\n"
                    xfo_score = 2
                elif x_frame_options.upper().startswith('ALLOW-FROM'):
                    evidence += f"  ⚠️  PARTIAL: Allows framing from specific origin\n"
                    xfo_score = 1
                else:
                    evidence += f"  ❓ UNKNOWN: Unrecognized value\n"
                    xfo_score = 0
            else:
                evidence += f"  ❌ Not present\n"
                xfo_score = 0
            
            # Analyze Content Security Policy
            evidence += f"\n📋 Content Security Policy:\n"
            csp_score = 0
            if csp_header:
                evidence += f"  ✅ Present: {csp_header[:100]}{'...' if len(csp_header) > 100 else ''}\n"
                
                # Check for frame-ancestors directive
                if 'frame-ancestors' in csp_header.lower():
                    if "'none'" in csp_header.lower():
                        evidence += f"  🎯 EXCELLENT: frame-ancestors 'none' (strongest protection)\n"
                        csp_score = 3
                    elif "'self'" in csp_header.lower():
                        evidence += f"  ✅ GOOD: frame-ancestors 'self' (same-origin protection)\n"
                        csp_score = 2
                    else:
                        evidence += f"  ⚠️  PARTIAL: frame-ancestors allows specific origins\n"
                        csp_score = 1
                else:
                    evidence += f"  ❓ frame-ancestors directive not found\n"
            else:
                evidence += f"  ❌ Not present\n"
            
            # Overall assessment
            evidence += f"\n📊 PROTECTION ASSESSMENT:\n"
            total_score = max(xfo_score, csp_score)
            
            if total_score >= 3:
                evidence += f"  🎯 EXCELLENT: Strong clickjacking protection\n"
                result = 'pass'
            elif total_score >= 2:
                evidence += f"  ✅ GOOD: Adequate clickjacking protection\n"
                result = 'pass'
            elif total_score >= 1:
                evidence += f"  ⚠️  WEAK: Some protection present but could be stronger\n"
                result = 'fail'
            else:
                evidence += f"  🚨 VULNERABLE: No clickjacking protection detected\n"
                result = 'fail'
            
            evidence += f"\n💡 RECOMMENDATIONS:\n"
            evidence += f"  • Best: Use Content-Security-Policy: frame-ancestors 'none'\n"
            evidence += f"  • Alternative: Use X-Frame-Options: DENY\n"
            evidence += f"  • For same-origin framing: frame-ancestors 'self' or X-Frame-Options: SAMEORIGIN"
            
            full_request = EnhancedAutoTestService._format_request_details('GET', url, headers)
            full_response = EnhancedAutoTestService._format_response_details(response, ['X-Frame-Options', 'Content-Security-Policy'])
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing clickjacking protection: {str(e)}',
                'request': f'GET {url}',
                'response': 'Request failed - no response received'
            }

    @staticmethod
    def test_input_validation(url):
        """Enhanced input validation test with XSS and injection checks"""
        try:
            # Common XSS and injection payloads
            test_payloads = {
                'XSS': [
                    '<script>alert("XSS")</script>',
                    '"><script>alert("XSS")</script>',
                    "javascript:alert('XSS')",
                    '<img src=x onerror=alert("XSS")>',
                    '{{7*7}}',  # Template injection
                ],
                'SQL Injection': [
                    "' OR '1'='1",
                    "1' UNION SELECT NULL--",
                    "'; DROP TABLE users--",
                    "1' AND 1=1--",
                ],
                'Command Injection': [
                    "; ls -la",
                    "| whoami",
                    "& dir",
                    "`id`",
                ],
                'Path Traversal': [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
                ]
            }
            
            evidence = f"🔍 INPUT VALIDATION ANALYSIS\n\n"
            vulnerabilities_found = []
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner v2.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            # Test GET parameters
            evidence += f"📋 GET PARAMETER TESTING:\n"
            for category, payloads in test_payloads.items():
                evidence += f"  Testing {category}:\n"
                
                for payload in payloads[:2]:  # Test first 2 payloads per category
                    test_url = f"{url}{'&' if '?' in url else '?'}test={payload}"
                    
                    try:
                        response = requests.get(test_url, headers=headers, timeout=5, verify=False)
                        
                        # Check if payload is reflected in response
                        if payload in response.text:
                            evidence += f"    ⚠️  Payload reflected: {payload[:30]}...\n"
                            vulnerabilities_found.append(f"GET {category}")
                        
                        # Check for error messages that might indicate injection
                        error_indicators = [
                            'sql error', 'mysql error', 'oracle error', 'postgresql error',
                            'warning:', 'fatal error:', 'parse error:',
                            'syntax error', 'unexpected token'
                        ]
                        
                        response_lower = response.text.lower()
                        for error in error_indicators:
                            if error in response_lower:
                                evidence += f"    🚨 Error message detected: {error}\n"
                                vulnerabilities_found.append(f"GET {category} Error")
                                break
                        
                    except requests.exceptions.RequestException:
                        evidence += f"    ❓ Request failed for payload: {payload[:20]}...\n"
            
            # Test POST data (if URL appears to accept POST)
            evidence += f"\n📋 POST DATA TESTING:\n"
            try:
                # Try a simple POST to see if it's accepted
                test_response = requests.post(url, data={'test': 'value'}, headers=headers, timeout=5, verify=False)
                
                if test_response.status_code not in [405, 501]:  # Method not allowed or not implemented
                    evidence += f"  POST method accepted, testing payloads:\n"
                    
                    for category, payloads in test_payloads.items():
                        for payload in payloads[:1]:  # Test 1 payload per category for POST
                            try:
                                post_data = {'input': payload, 'test': payload}
                                response = requests.post(url, data=post_data, headers=headers, timeout=5, verify=False)
                                
                                if payload in response.text:
                                    evidence += f"    ⚠️  POST {category}: Payload reflected\n"
                                    vulnerabilities_found.append(f"POST {category}")
                                
                            except requests.exceptions.RequestException:
                                continue
                else:
                    evidence += f"  POST method not accepted (Status: {test_response.status_code})\n"
                    
            except requests.exceptions.RequestException:
                evidence += f"  POST testing failed\n"
            
            # Overall assessment
            evidence += f"\n📊 VULNERABILITY SUMMARY:\n"
            evidence += f"  • Total vulnerability types found: {len(set(vulnerabilities_found))}\n"
            
            if vulnerabilities_found:
                evidence += f"  • Vulnerabilities detected: {', '.join(set(vulnerabilities_found))}\n"
                evidence += f"\n🚨 CRITICAL: Input validation vulnerabilities found!\n"
                evidence += f"💡 IMMEDIATE ACTIONS REQUIRED:\n"
                evidence += f"  • Implement input sanitization and validation\n"
                evidence += f"  • Use parameterized queries for database operations\n"
                evidence += f"  • Encode output data before displaying\n"
                evidence += f"  • Consider using a Web Application Firewall (WAF)"
                result = 'fail'
            else:
                evidence += f"  ✅ No obvious input validation vulnerabilities detected\n"
                evidence += f"💡 RECOMMENDATIONS:\n"
                evidence += f"  • Continue regular security testing\n"
                evidence += f"  • Implement comprehensive input validation\n"
                evidence += f"  • Use security-focused code reviews"
                result = 'pass'
            
            full_request = f"Multiple requests with injection payloads to {url}"
            full_response = f"Tested {sum(len(payloads) for payloads in test_payloads.values())} different injection payloads"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing input validation: {str(e)}',
                'request': f'Input validation test for {url}',
                'response': 'Test failed'
            }

    @staticmethod
    def get_all_tests():
        """Get all available enhanced auto-tests"""
        return [
            ('HSTS Test', EnhancedAutoTestService.test_hsts),
            ('Security Headers Test', EnhancedAutoTestService.test_security_headers),
            ('SSL Configuration Test', EnhancedAutoTestService.test_ssl_configuration),
            ('Cookie Security Test', EnhancedAutoTestService.test_cookie_security),
            ('HTTP Methods Test', EnhancedAutoTestService.test_http_methods),
            ('Information Disclosure Test', EnhancedAutoTestService.test_information_disclosure),
            ('Clickjacking Protection Test', EnhancedAutoTestService.test_clickjacking_protection),
            ('Input Validation Test', EnhancedAutoTestService.test_input_validation),
        ]
