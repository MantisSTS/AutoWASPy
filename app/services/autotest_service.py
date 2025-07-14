"""
Automated Testing Service Module

This module provides automated security testing capabilities for web applications.
"""

import requests
import re
import socket
import dns.resolver
from urllib.parse import urlparse, urljoin
from app.utils.datetime_utils import utc_now


class AutoTestService:
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
    def test_hsts(url):
        """Test for HTTP Strict Transport Security"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            hsts_header = response.headers.get('Strict-Transport-Security')
            
            # Format full request and response
            full_request = AutoTestService._format_request_details('GET', url, headers)
            full_response = AutoTestService._format_response_details(response, ['Strict-Transport-Security'])
            
            if hsts_header:
                # Parse HSTS header for better analysis
                max_age = 'Unknown'
                include_subdomains = 'includeSubDomains' in hsts_header
                preload = 'preload' in hsts_header
                
                if 'max-age=' in hsts_header:
                    max_age = hsts_header.split('max-age=')[1].split(';')[0]
                
                evidence = f"✅ HSTS header found: {hsts_header}\n\n"
                evidence += f"📊 Analysis:\n"
                evidence += f"  • Max-Age: {max_age} seconds\n"
                evidence += f"  • Include Subdomains: {'✅ Yes' if include_subdomains else '❌ No'}\n"
                evidence += f"  • Preload: {'✅ Yes' if preload else '❌ No'}\n\n"
                
                if int(max_age) < 31536000:  # Less than 1 year
                    evidence += f"⚠️  Warning: max-age is less than 1 year (31536000 seconds)\n"
                
                return {
                    'result': 'pass',
                    'evidence': evidence,
                    'request': full_request,
                    'response': full_response
                }
            else:
                evidence = f"❌ HSTS header not found\n\n"
                evidence += f"🚨 Security Impact:\n"
                evidence += f"  • Allows protocol downgrade attacks\n"
                evidence += f"  • Man-in-the-middle attacks possible\n"
                evidence += f"  • Users vulnerable to SSL stripping\n\n"
                evidence += f"💡 Recommendation: Add Strict-Transport-Security header"
                
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
    def test_cookie_security(url):
        """Test for secure cookie attributes"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Get all Set-Cookie headers
            set_cookie_headers = []
            if 'Set-Cookie' in response.headers:
                # Handle multiple Set-Cookie headers
                for key, value in response.headers.items():
                    if key.lower() == 'set-cookie':
                        set_cookie_headers.append(value)
            
            full_request = AutoTestService._format_request_details('GET', url, headers)
            full_response = AutoTestService._format_response_details(response, ['Set-Cookie'])
            
            if not set_cookie_headers:
                return {
                    'result': 'informational',
                    'evidence': 'ℹ️  No cookies set by this endpoint\n\nThis may be expected for static resources or APIs.',
                    'request': full_request,
                    'response': full_response
                }
            
            cookies_analysis = []
            overall_issues = []
            
            for cookie_header in set_cookie_headers:
                if cookie_header:
                    cookie_name = cookie_header.split('=')[0] if '=' in cookie_header else 'Unknown'
                    issues = []
                    security_flags = []
                    
                    if 'HttpOnly' not in cookie_header:
                        issues.append('❌ Missing HttpOnly flag (XSS protection)')
                    else:
                        security_flags.append('✅ HttpOnly')
                        
                    if 'Secure' not in cookie_header:
                        issues.append('❌ Missing Secure flag (HTTPS only)')
                    else:
                        security_flags.append('✅ Secure')
                        
                    if 'SameSite' not in cookie_header:
                        issues.append('❌ Missing SameSite attribute (CSRF protection)')
                    else:
                        # Extract SameSite value
                        samesite_match = re.search(r'SameSite=([^;]+)', cookie_header)
                        samesite_value = samesite_match.group(1) if samesite_match else 'Unknown'
                        security_flags.append(f'✅ SameSite={samesite_value}')
                    
                    cookies_analysis.append({
                        'name': cookie_name,
                        'header': cookie_header,
                        'issues': issues,
                        'security_flags': security_flags
                    })
                    overall_issues.extend(issues)
            
            evidence = f"🍪 Cookie Security Analysis\n\n"
            
            for i, cookie in enumerate(cookies_analysis, 1):
                evidence += f"Cookie {i}: {cookie['name']}\n"
                evidence += f"  Full Header: {cookie['header']}\n"
                
                if cookie['security_flags']:
                    evidence += f"  Security Flags: {', '.join(cookie['security_flags'])}\n"
                
                if cookie['issues']:
                    evidence += f"  Issues Found: {', '.join(cookie['issues'])}\n"
                else:
                    evidence += f"  ✅ All security attributes present\n"
                
                evidence += "\n"
            
            if overall_issues:
                evidence += f"🚨 Summary: {len(overall_issues)} security issues found\n"
                evidence += f"💡 Recommendation: Implement missing cookie security attributes"
                
                return {
                    'result': 'fail',
                    'evidence': evidence,
                    'request': full_request,
                    'response': full_response
                }
            else:
                evidence += f"✅ Summary: All cookies have proper security attributes"
                
                return {
                    'result': 'pass',
                    'evidence': evidence,
                    'request': full_request,
                    'response': full_response
                }
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing cookies: {str(e)}',
                'request': f'GET {url}',
                'response': 'Request failed - no response received'
            }

    @staticmethod
    def test_security_headers(url):
        """Test for common security headers"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'X-XSS-Protection': 'Enables XSS filtering',
                'Content-Security-Policy': 'Prevents XSS and data injection',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features',
                'Cross-Origin-Embedder-Policy': 'Controls cross-origin embedding',
                'Cross-Origin-Opener-Policy': 'Controls cross-origin window opening'
            }
            
            missing_headers = []
            present_headers = []
            highlight_headers = []
            
            for header, description in security_headers.items():
                if header in response.headers:
                    present_headers.append(f'✅ {header}: {response.headers[header]}')
                    highlight_headers.append(header)
                else:
                    missing_headers.append(f'❌ {header} ({description})')
            
            # Format full request and response with highlighting
            full_request = AutoTestService._format_request_details('GET', url, headers)
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            evidence = "🛡️  Security Headers Analysis\n\n"
            
            if present_headers:
                evidence += f"Present security headers ({len(present_headers)}):\n"
                for header in present_headers:
                    evidence += f"  {header}\n"
                evidence += "\n"
            
            if missing_headers:
                evidence += f"🚨 Missing security headers ({len(missing_headers)}):\n"
                for header in missing_headers:
                    evidence += f"  {header}\n"
                evidence += "\n"
                evidence += f"💡 Recommendation: Implement missing security headers to improve protection\n"
                evidence += f"   against common web attacks (XSS, clickjacking, MIME sniffing, etc.)"
            else:
                evidence += f"✅ All recommended security headers are present!"
            
            result = 'fail' if missing_headers else 'pass'
            
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
        """Test SSL/TLS configuration"""
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return {
                    'result': 'fail',
                    'evidence': '🚨 URL does not use HTTPS\n\nHTTP connections are vulnerable to:\n  • Man-in-the-middle attacks\n  • Data eavesdropping\n  • Content tampering\n\n💡 Recommendation: Use HTTPS for all web communications',
                    'request': f'SSL test for {url}',
                    'response': 'Non-HTTPS URL detected - SSL test skipped'
                }
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            # Test SSL connection with verification
            response = requests.get(url, headers=headers, timeout=10, verify=True)
            
            # Format request and response
            full_request = AutoTestService._format_request_details('GET', url, headers)
            full_response = AutoTestService._format_response_details(response)
            
            # If we get here, SSL is valid
            evidence = "✅ SSL/TLS Certificate Validation\n\n"
            evidence += f"🔒 Certificate Status: Valid and Trusted\n"
            evidence += f"🌐 URL: {url}\n"
            evidence += f"📊 Response Code: {response.status_code}\n\n"
            evidence += f"🛡️  Security Benefits:\n"
            evidence += f"  • Data encrypted in transit\n"
            evidence += f"  • Certificate authority verified\n"
            evidence += f"  • Protection against MITM attacks"
            
            return {
                'result': 'pass',
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except requests.exceptions.SSLError as e:
            ssl_error = str(e)
            evidence = f"🚨 SSL/TLS Certificate Error\n\n"
            evidence += f"❌ Error Details: {ssl_error}\n\n"
            evidence += f"🔍 Common SSL Issues:\n"
            evidence += f"  • Self-signed certificate\n"
            evidence += f"  • Expired certificate\n"
            evidence += f"  • Invalid certificate chain\n"
            evidence += f"  • Hostname mismatch\n\n"
            evidence += f"💡 Recommendation: Fix SSL certificate issues before production deployment"
            
            return {
                'result': 'fail',
                'evidence': evidence,
                'request': f'SSL verification for {url}',
                'response': f'SSL Error: {ssl_error}'
            }
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing SSL: {str(e)}',
                'request': f'SSL test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_http_methods(url):
        """Test for allowed HTTP methods"""
        try:
            methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
            allowed_methods = []
            risky_methods = []
            method_details = []
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            for method in methods_to_test:
                try:
                    response = requests.request(method, url, headers=headers, timeout=5, verify=False)
                    if response.status_code not in [405, 501]:  # Method not allowed or not implemented
                        allowed_methods.append(method)
                        method_details.append(f"  • {method}: {response.status_code} {response.reason}")
                        
                        if method in ['TRACE', 'DELETE', 'PUT', 'PATCH']:
                            risky_methods.append(method)
                except:
                    method_details.append(f"  • {method}: Connection failed")
            
            # Create a sample request for documentation
            full_request = AutoTestService._format_request_details('OPTIONS', url, headers)
            
            evidence = f"🔍 HTTP Methods Analysis\n\n"
            evidence += f"📊 Methods Tested: {', '.join(methods_to_test)}\n"
            evidence += f"✅ Allowed Methods: {', '.join(allowed_methods) if allowed_methods else 'None detected'}\n\n"
            
            evidence += f"📋 Detailed Results:\n"
            for detail in method_details:
                evidence += detail + "\n"
            evidence += "\n"
            
            if risky_methods:
                evidence += f"⚠️  Potentially Risky Methods Found: {', '.join(risky_methods)}\n\n"
                evidence += f"🚨 Security Implications:\n"
                for method in risky_methods:
                    if method == 'TRACE':
                        evidence += f"  • TRACE: Can reveal proxy information and enable XST attacks\n"
                    elif method == 'DELETE':
                        evidence += f"  • DELETE: Can be used to delete resources if not properly protected\n"
                    elif method in ['PUT', 'PATCH']:
                        evidence += f"  • {method}: Can modify resources if not properly protected\n"
                
                evidence += f"\n💡 Recommendation: Review if these methods are necessary and properly secured"
                result = 'fail'
            else:
                evidence += f"✅ No risky HTTP methods detected - only safe methods are allowed"
                result = 'pass'
            
            response_summary = f"HTTP Methods Test Results:\nAllowed: {', '.join(allowed_methods)}\nRisky: {', '.join(risky_methods) if risky_methods else 'None'}"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': response_summary
            }
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing HTTP methods: {str(e)}',
                'request': f'HTTP method test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_information_disclosure(url):
        """Test for information disclosure through various means"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            full_request = AutoTestService._format_request_details('GET', url, headers)
            
            # Check for information disclosure in headers
            disclosure_headers = {
                'Server': 'Web server information',
                'X-Powered-By': 'Technology stack information',
                'X-AspNet-Version': 'ASP.NET version',
                'X-AspNetMvc-Version': 'ASP.NET MVC version',
                'X-Generator': 'Content management system',
                'X-Drupal-Cache': 'Drupal CMS detection',
                'X-Varnish': 'Varnish cache information'
            }
            
            found_disclosures = []
            highlight_headers = []
            
            for header, description in disclosure_headers.items():
                if header in response.headers:
                    found_disclosures.append(f"• {header}: {response.headers[header]} ({description})")
                    highlight_headers.append(header)
            
            # Check for common debug/error information in response body
            debug_patterns = [
                r'(?i)(debug|trace|error|exception|stack\s*trace)',
                r'(?i)(mysql|postgresql|oracle|sql\s*server).*error',
                r'(?i)php\s*(warning|error|notice|fatal)',
                r'(?i)(apache|nginx|iis).*error',
                r'(?i)application\s*error'
            ]
            
            body_issues = []
            for pattern in debug_patterns:
                if re.search(pattern, response.text):
                    body_issues.append(f"• Debug/error information detected in response body")
                    break
            
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            evidence = "🔍 Information Disclosure Analysis\n\n"
            
            if found_disclosures:
                evidence += f"⚠️  Information Disclosure Found ({len(found_disclosures)} issues):\n"
                for disclosure in found_disclosures:
                    evidence += f"  {disclosure}\n"
                evidence += "\n"
            
            if body_issues:
                evidence += f"🚨 Response Body Issues:\n"
                for issue in body_issues:
                    evidence += f"  {issue}\n"
                evidence += "\n"
            
            if found_disclosures or body_issues:
                evidence += f"💡 Recommendation: Remove or minimize information disclosure\n"
                evidence += f"   • Configure server to hide version information\n"
                evidence += f"   • Implement custom error pages\n"
                evidence += f"   • Review debug settings for production"
                result = 'fail'
            else:
                evidence += f"✅ No obvious information disclosure detected\n"
                evidence += f"   • Server headers appear to be properly configured\n"
                evidence += f"   • No debug information found in response"
                result = 'pass'
            
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
                'request': f'Information disclosure test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_clickjacking_protection(url):
        """Test for clickjacking protection mechanisms"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            full_request = AutoTestService._format_request_details('GET', url, headers)
            
            # Check for clickjacking protection headers
            x_frame_options = response.headers.get('X-Frame-Options')
            csp_header = response.headers.get('Content-Security-Policy')
            
            highlight_headers = []
            protection_methods = []
            issues = []
            
            if x_frame_options:
                highlight_headers.append('X-Frame-Options')
                if x_frame_options.upper() in ['DENY', 'SAMEORIGIN']:
                    protection_methods.append(f"✅ X-Frame-Options: {x_frame_options}")
                else:
                    issues.append(f"⚠️  X-Frame-Options has weak setting: {x_frame_options}")
            else:
                issues.append("❌ Missing X-Frame-Options header")
            
            if csp_header:
                highlight_headers.append('Content-Security-Policy')
                if 'frame-ancestors' in csp_header:
                    protection_methods.append(f"✅ CSP frame-ancestors directive present")
                else:
                    issues.append(f"⚠️  CSP header present but no frame-ancestors directive")
            
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            evidence = "🛡️  Clickjacking Protection Analysis\n\n"
            
            if protection_methods:
                evidence += f"Protection Methods Found:\n"
                for method in protection_methods:
                    evidence += f"  {method}\n"
                evidence += "\n"
            
            if issues:
                evidence += f"🚨 Issues Found ({len(issues)}):\n"
                for issue in issues:
                    evidence += f"  {issue}\n"
                evidence += "\n"
                evidence += f"💡 Recommendation: Implement clickjacking protection\n"
                evidence += f"   • Add X-Frame-Options: DENY or SAMEORIGIN\n"
                evidence += f"   • Or use CSP frame-ancestors directive\n"
                evidence += f"   • Test embedded content functionality"
                result = 'fail'
            else:
                evidence += f"✅ Clickjacking protection is properly configured"
                result = 'pass'
            
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
                'request': f'Clickjacking protection test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_cors_configuration(url):
        """Test CORS configuration for potential security issues"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Origin': 'https://evil.example.com'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            full_request = AutoTestService._format_request_details('GET', url, headers)
            
            # Check CORS headers
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Max-Age': response.headers.get('Access-Control-Max-Age')
            }
            
            highlight_headers = [h for h in cors_headers.keys() if cors_headers[h]]
            issues = []
            configurations = []
            
            if cors_headers['Access-Control-Allow-Origin']:
                acao = cors_headers['Access-Control-Allow-Origin']
                if acao == '*':
                    if cors_headers['Access-Control-Allow-Credentials'] == 'true':
                        issues.append("🚨 CRITICAL: Wildcard CORS with credentials enabled")
                    else:
                        issues.append("⚠️  Wildcard CORS origin (allows all domains)")
                elif acao == headers['Origin']:
                    issues.append("⚠️  CORS reflects any origin (potential security risk)")
                else:
                    configurations.append(f"✅ CORS origin restricted to: {acao}")
            
            if cors_headers['Access-Control-Allow-Methods']:
                methods = cors_headers['Access-Control-Allow-Methods']
                if any(method in methods for method in ['PUT', 'DELETE', 'PATCH']):
                    issues.append(f"⚠️  Potentially dangerous methods allowed: {methods}")
                else:
                    configurations.append(f"✅ CORS methods: {methods}")
            
            if cors_headers['Access-Control-Allow-Credentials'] == 'true':
                configurations.append("⚠️  Credentials allowed in CORS requests")
            
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            evidence = "🌐 CORS Configuration Analysis\n\n"
            
            if not any(cors_headers.values()):
                evidence += "ℹ️  No CORS headers detected\n"
                evidence += "   • This may be expected for same-origin applications\n"
                evidence += "   • Consider if cross-origin requests are needed"
                result = 'informational'
            else:
                if configurations:
                    evidence += f"CORS Configuration:\n"
                    for config in configurations:
                        evidence += f"  {config}\n"
                    evidence += "\n"
                
                if issues:
                    evidence += f"🚨 Security Issues Found ({len(issues)}):\n"
                    for issue in issues:
                        evidence += f"  {issue}\n"
                    evidence += "\n"
                    evidence += f"💡 Recommendation: Review CORS configuration\n"
                    evidence += f"   • Avoid wildcard origins with credentials\n"
                    evidence += f"   • Restrict origins to trusted domains\n"
                    evidence += f"   • Limit allowed methods and headers"
                    result = 'fail'
                else:
                    evidence += f"✅ CORS configuration appears secure"
                    result = 'pass'
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing CORS configuration: {str(e)}',
                'request': f'CORS configuration test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_content_type_validation(url):
        """Test for content type validation and MIME sniffing protection"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            full_request = AutoTestService._format_request_details('GET', url, headers)
            
            # Check content type headers
            content_type = response.headers.get('Content-Type', '')
            x_content_type_options = response.headers.get('X-Content-Type-Options')
            
            highlight_headers = []
            issues = []
            protections = []
            
            if content_type:
                highlight_headers.append('Content-Type')
                if 'charset' not in content_type.lower() and 'text/' in content_type:
                    issues.append(f"⚠️  Missing charset in Content-Type: {content_type}")
                else:
                    protections.append(f"✅ Content-Type properly set: {content_type}")
            else:
                issues.append("❌ Missing Content-Type header")
            
            if x_content_type_options:
                highlight_headers.append('X-Content-Type-Options')
                if x_content_type_options.lower() == 'nosniff':
                    protections.append(f"✅ MIME sniffing protection: {x_content_type_options}")
                else:
                    issues.append(f"⚠️  Weak X-Content-Type-Options: {x_content_type_options}")
            else:
                issues.append("❌ Missing X-Content-Type-Options header")
            
            # Check for potential MIME confusion
            parsed_url = urlparse(url)
            if parsed_url.path.endswith(('.jpg', '.png', '.gif', '.css', '.js')):
                if not content_type or not any(ext in content_type for ext in ['image/', 'text/css', 'javascript']):
                    issues.append("⚠️  Content-Type mismatch with file extension")
            
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            evidence = "📋 Content Type Validation Analysis\n\n"
            
            if protections:
                evidence += f"Protection Mechanisms:\n"
                for protection in protections:
                    evidence += f"  {protection}\n"
                evidence += "\n"
            
            if issues:
                evidence += f"🚨 Issues Found ({len(issues)}):\n"
                for issue in issues:
                    evidence += f"  {issue}\n"
                evidence += "\n"
                evidence += f"💡 Recommendation: Improve content type handling\n"
                evidence += f"   • Always specify Content-Type with charset\n"
                evidence += f"   • Add X-Content-Type-Options: nosniff\n"
                evidence += f"   • Ensure content types match file extensions"
                result = 'fail'
            else:
                evidence += f"✅ Content type validation is properly configured"
                result = 'pass'
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing content type validation: {str(e)}',
                'request': f'Content type validation test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_input_validation(url):
        """Test basic input validation and injection protections"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            evidence = "🔍 Input Validation & Injection Protection Test\n\n"
            
            # Basic injection test payloads (for detection, not exploitation)
            test_payloads = {
                'XSS': ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
                'SQL': ["'", "1' OR '1'='1", "'; DROP TABLE users; --"],
                'Command': ['$(whoami)', '$(id)', '; ls -la'],
                'LDAP': ['*)(uid=*', '*)(&(objectClass=*)'],
                'NoSQL': ['{"$gt":""}', '{"$ne":null}']
            }
            
            vulnerabilities = []
            tested_vectors = 0
            
            # Test common parameters
            for injection_type, payloads in test_payloads.items():
                for payload in payloads[:2]:  # Limit to 2 payloads per type
                    try:
                        # Test as URL parameter
                        test_url = f"{url}?test={requests.utils.quote(payload)}"
                        response = requests.get(test_url, headers=headers, timeout=5, verify=False)
                        tested_vectors += 1
                        
                        # Check if payload is reflected unescaped
                        if payload in response.text and response.status_code == 200:
                            if injection_type == 'XSS' and '<script>' in response.text:
                                vulnerabilities.append(f"🚨 Potential {injection_type}: Payload reflected unescaped")
                            elif injection_type == 'SQL' and any(error in response.text.lower() for error in 
                                                               ['sql', 'mysql', 'postgresql', 'sqlite']):
                                vulnerabilities.append(f"🚨 Potential {injection_type}: SQL error triggered")
                            elif len(payload) > 5:  # Avoid false positives for simple payloads
                                vulnerabilities.append(f"⚠️  Potential {injection_type}: Payload reflected")
                        
                        # Test as POST data if it's a form
                        if 'form' in response.text.lower() and injection_type == 'XSS':
                            try:
                                post_response = requests.post(url, data={'input': payload}, 
                                                            headers=headers, timeout=5, verify=False)
                                if payload in post_response.text:
                                    vulnerabilities.append(f"⚠️  Potential POST {injection_type}: Payload reflected")
                            except:
                                pass
                        
                    except requests.exceptions.RequestException:
                        continue
            
            # Check for basic protections
            protections = []
            
            # Test for WAF/filtering (basic detection)
            waf_test_payload = "<script>alert('xss')</script>"
            try:
                waf_response = requests.get(f"{url}?test={waf_test_payload}", 
                                          headers=headers, timeout=5, verify=False)
                if waf_response.status_code in [403, 406, 418, 429]:
                    protections.append(f"✅ WAF/Filtering detected (Status: {waf_response.status_code})")
                elif 'blocked' in waf_response.text.lower() or 'forbidden' in waf_response.text.lower():
                    protections.append(f"✅ Request filtering detected")
            except:
                pass
            
            if protections:
                evidence += f"Protection Mechanisms:\n"
                for protection in protections:
                    evidence += f"  {protection}\n"
                evidence += "\n"
            
            if vulnerabilities:
                evidence += f"🚨 Potential Vulnerabilities Found ({len(vulnerabilities)}):\n"
                for vuln in vulnerabilities:
                    evidence += f"  {vuln}\n"
                evidence += "\n"
                evidence += f"💡 Critical Recommendations:\n"
                evidence += f"   • Implement input validation and sanitization\n"
                evidence += f"   • Use parameterized queries for SQL\n"
                evidence += f"   • Escape output for XSS prevention\n"
                evidence += f"   • Deploy Web Application Firewall (WAF)\n"
                evidence += f"   • Conduct thorough penetration testing"
                result = 'fail'
            else:
                evidence += f"✅ Basic input validation appears functional\n"
                evidence += f"   • Tested {tested_vectors} injection vectors\n"
                evidence += f"   • No obvious injection vulnerabilities detected\n"
                evidence += f"   • Note: This is basic testing - comprehensive testing recommended"
                result = 'pass'
            
            request_summary = f"Input Validation Test for {url}\nTested {tested_vectors} injection vectors"
            response_summary = f"Found {len(vulnerabilities)} potential issues, {len(protections)} protections"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': request_summary,
                'response': response_summary
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing input validation: {str(e)}',
                'request': f'Input validation test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_robots_txt_analysis(url):
        """Test robots.txt for sensitive information disclosure"""
        try:
            # Parse the base URL and construct robots.txt path
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            robots_url = urljoin(base_url, '/robots.txt')
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/plain'
            }
            
            response = requests.get(robots_url, headers=headers, timeout=10, verify=False)
            
            full_request = AutoTestService._format_request_details('GET', robots_url, headers)
            full_response = AutoTestService._format_response_details(response)
            
            if response.status_code == 200:
                content = response.text.lower()
                sensitive_patterns = [
                    'admin', 'wp-admin', 'administrator', 'login', 'auth',
                    'api', 'backup', 'config', 'database', 'db', 'secret',
                    'private', 'internal', 'dev', 'test', 'staging'
                ]
                
                found_patterns = []
                disallowed_paths = []
                
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        disallowed_paths.append(path)
                        
                        for pattern in sensitive_patterns:
                            if pattern in path.lower():
                                found_patterns.append((pattern, path))
                
                evidence = f"🤖 Robots.txt Analysis\n\n"
                evidence += f"📍 Found robots.txt at: {robots_url}\n"
                evidence += f"📝 Total paths found: {len(disallowed_paths)}\n\n"
                
                if found_patterns:
                    evidence += f"🚨 Potentially sensitive paths discovered:\n"
                    for pattern, path in found_patterns:
                        evidence += f"  • {path} (contains '{pattern}')\n"
                    evidence += f"\n💡 Recommendation: Review these paths for sensitive exposure\n"
                    result = 'fail'
                else:
                    evidence += f"✅ No obviously sensitive paths found in robots.txt\n"
                    if disallowed_paths:
                        evidence += f"📋 Sample paths:\n"
                        for path in disallowed_paths[:5]:
                            evidence += f"  • {path}\n"
                        if len(disallowed_paths) > 5:
                            evidence += f"  ... and {len(disallowed_paths) - 5} more\n"
                    result = 'pass'
                
                return {
                    'result': result,
                    'evidence': evidence,
                    'request': full_request,
                    'response': full_response
                }
            else:
                return {
                    'result': 'informational',
                    'evidence': f"ℹ️  No robots.txt found (HTTP {response.status_code})\n\nThis is common and not necessarily a security issue.",
                    'request': full_request,
                    'response': full_response
                }
                
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error analyzing robots.txt: {str(e)}',
                'request': f'GET {url}/robots.txt',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_web_server_detection(url):
        """Detect web server type and version"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            full_request = AutoTestService._format_request_details('GET', url, headers)
            
            # Server identification headers to check
            server_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            highlight_headers = [h for h in server_headers if h in response.headers]
            
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            detected_info = []
            version_info = []
            
            for header in server_headers:
                if header in response.headers:
                    value = response.headers[header]
                    detected_info.append(f"{header}: {value}")
                    
                    # Check for version numbers
                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', value)
                    if version_match:
                        version_info.append(f"{header}: {version_match.group(1)}")
            
            evidence = f"🖥️  Web Server Detection\n\n"
            
            if detected_info:
                evidence += f"📋 Server information discovered:\n"
                for info in detected_info:
                    evidence += f"  • {info}\n"
                evidence += f"\n"
                
                if version_info:
                    evidence += f"🔢 Version information found:\n"
                    for version in version_info:
                        evidence += f"  • {version}\n"
                    evidence += f"\n⚠️  Recommendation: Version disclosure may help attackers\n"
                    evidence += f"   identify known vulnerabilities. Consider hiding version info.\n"
                    result = 'fail'
                else:
                    evidence += f"✅ No detailed version information disclosed\n"
                    result = 'pass'
            else:
                evidence += f"✅ Server information is properly hidden\n"
                evidence += f"🛡️  Good security practice: No server headers disclosed\n"
                result = 'pass'
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error detecting web server: {str(e)}',
                'request': f'GET {url}',
                'response': 'Request failed - connection error'
            }
