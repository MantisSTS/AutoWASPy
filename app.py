import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import requests
import json
import sqlite3
import ssl
import urllib3
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
import re
from bs4 import BeautifulSoup
import yaml
from typing import List, Dict
import socket
import base64
import hashlib
import time
import dns.resolver
from email.utils import parseaddr

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///autowaspy.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Suppress SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

db = SQLAlchemy(app)

# Database Models
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    client_name = db.Column(db.String(100), nullable=False)
    job_type = db.Column(db.String(20), nullable=False)  # 'web', 'mobile_ios', 'mobile_android'
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    urls = db.Column(db.Text)  # JSON string of URLs for web tests
    status = db.Column(db.String(20), default='active')  # 'active', 'completed', 'archived'
    
    # Relationships
    test_items = db.relationship('TestItem', backref='project', lazy=True, cascade='all, delete-orphan')

class TestItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    owasp_id = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    test_type = db.Column(db.String(20), nullable=False)  # 'wstg', 'mstg'
    is_tested = db.Column(db.Boolean, default=False)
    evidence = db.Column(db.Text)
    risk_level = db.Column(db.String(20))  # 'low', 'medium', 'high', 'critical'
    finding_status = db.Column(db.String(20), default='not_tested')  # 'not_tested', 'pass', 'fail', 'informational'
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    updated_date = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AutoTestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    test_name = db.Column(db.String(100), nullable=False)
    url_tested = db.Column(db.String(500))
    result = db.Column(db.String(20))  # 'pass', 'fail', 'error'
    evidence = db.Column(db.Text)
    request_data = db.Column(db.Text)
    response_data = db.Column(db.Text)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

# Add a simple cache table for OWASP data updates
class OWASPDataCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_type = db.Column(db.String(10), nullable=False)  # 'wstg' or 'mstg'
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    data_source = db.Column(db.String(50), default='github')  # 'github' or 'fallback'
    test_count = db.Column(db.Integer, default=0)

# OWASP Data Service
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
                    OWASPService._update_cache('wstg', 'github', len(wstg_tests))
                    print(f"Successfully fetched {len(wstg_tests)} WSTG tests from GitHub (original method)")
                    return sorted(wstg_tests, key=lambda x: x['id'])
            
            # Original method failed or insufficient data, try checklist fallback
            print("Original method failed or insufficient data, trying checklist fallback...")
            checklist_data = OWASPService._fetch_wstg_from_checklist()
            if len(checklist_data) >= 10:
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
            
            description = description_match.group(1).strip() if description_match else "Security testing as per OWASP WSTG guidelines."
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
        """Fetch OWASP MSTG checklist data from GitHub repository"""
        try:
            print("Fetching MSTG data from GitHub...")
            # OWASP MSTG GitHub API endpoint
            api_url = "https://api.github.com/repos/OWASP/owasp-mstg/contents/Document/0x90-Appendix-B_References.md"
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            # Try to fetch the main MSTG checklist file
            response = requests.get(api_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                file_info = response.json()
                content_response = requests.get(file_info['download_url'], timeout=15)
                
                if content_response.status_code == 200:
                    content = content_response.text
                    mstg_tests = OWASPService._parse_mstg_content(content)
                    
                    if len(mstg_tests) >= 5:
                        OWASPService._update_cache('mstg', 'github', len(mstg_tests))
                        print(f"Successfully fetched {len(mstg_tests)} MSTG tests from GitHub")
                        return mstg_tests
            
            # Fallback: try alternative approach
            print("Trying alternative MSTG fetch method...")
            alternative_data = OWASPService._fetch_mstg_alternative()
            if len(alternative_data) >= 5:
                OWASPService._update_cache('mstg', 'github', len(alternative_data))
                print(f"Successfully fetched {len(alternative_data)} MSTG tests via alternative method")
                return alternative_data
            
            # Use fallback data
            print("GitHub fetch returned insufficient data, using fallback MSTG data")
            fallback_data = OWASPService._get_fallback_mstg_data()
            OWASPService._update_cache('mstg', 'fallback', len(fallback_data))
            return fallback_data
            
        except Exception as e:
            print(f"Error fetching MSTG data from GitHub: {e}")
            fallback_data = OWASPService._get_fallback_mstg_data()
            OWASPService._update_cache('mstg', 'fallback', len(fallback_data))
            return fallback_data

    @staticmethod
    def _fetch_mstg_alternative():
        """Alternative method to fetch MSTG data"""
        try:
            # Try to fetch from the checklist in the main documentation
            api_url = "https://api.github.com/repos/OWASP/owasp-mstg/contents/Document"
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            response = requests.get(api_url, headers=headers, timeout=30)
            if response.status_code != 200:
                return OWASPService._get_fallback_mstg_data()
            
            contents = response.json()
            mstg_tests = []
            
            # Look for checklist or requirement files
            for item in contents:
                if item['type'] == 'file' and any(keyword in item['name'].lower() for keyword in ['checklist', 'requirement', 'mstg']):
                    file_response = requests.get(item['download_url'], timeout=15)
                    if file_response.status_code == 200:
                        content = file_response.text
                        parsed_tests = OWASPService._parse_mstg_content(content)
                        mstg_tests.extend(parsed_tests)
            
            if len(mstg_tests) >= 5:
                return sorted(mstg_tests, key=lambda x: x['id'])
            
            return OWASPService._get_fallback_mstg_data()
            
        except Exception:
            return OWASPService._get_fallback_mstg_data()

    @staticmethod
    def _parse_mstg_content(content):
        """Parse MSTG content for test requirements"""
        mstg_tests = []
        
        # Look for MSTG patterns
        mstg_patterns = [
            r'MSTG-([A-Z]+)-(\d+)[:\s]*(.+)',
            r'(\d+\.\d+)\s+(.+?)(?=\n\d+\.\d+|\Z)',
            r'-\s*(MSTG-[A-Z]+-\d+)[:\s]*(.+)'
        ]
        
        for pattern in mstg_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                if 'MSTG-' in pattern:
                    if len(match.groups()) >= 3:
                        category_code = match.group(1)
                        test_num = match.group(2)
                        description = match.group(3).strip()
                        
                        mstg_id = f"MSTG-{category_code}-{test_num}"
                        category = OWASPService._get_mstg_category(category_code)
                        
                        mstg_tests.append({
                            'id': mstg_id,
                            'title': description[:100] + "..." if len(description) > 100 else description,
                            'category': category,
                            'description': description
                        })
        
        # If no patterns matched, create based on common MSTG requirements
        if len(mstg_tests) < 5:
            return OWASPService._get_fallback_mstg_data()
        
        return mstg_tests[:20]  # Limit to reasonable number

    @staticmethod
    def _get_mstg_category(category_code):
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
    def _get_fallback_wstg_data():
        """Enhanced fallback WSTG data as backup"""
        return [
            {
                'id': 'WSTG-INFO-01',
                'title': 'Conduct Search Engine Discovery Reconnaissance for Information Leakage',
                'category': 'Information Gathering',
                'description': 'Use search engines to discover sensitive information about the application that may be inadvertently exposed.'
            },
            {
                'id': 'WSTG-INFO-02',
                'title': 'Fingerprint Web Server',
                'category': 'Information Gathering',
                'description': 'Identify the web server software, version, and configuration to understand potential attack vectors.'
            },
            {
                'id': 'WSTG-INFO-03',
                'title': 'Review Webserver Metafiles for Information Leakage',
                'category': 'Information Gathering',
                'description': 'Analyze robots.txt, sitemap.xml and other metafiles for sensitive information disclosure.'
            },
            {
                'id': 'WSTG-INFO-04',
                'title': 'Enumerate Applications on Webserver',
                'category': 'Information Gathering',
                'description': 'Identify all applications and services running on the web server.'
            },
            {
                'id': 'WSTG-INFO-05',
                'title': 'Review Webpage Content for Information Leakage',
                'category': 'Information Gathering',
                'description': 'Examine webpage source code and content for sensitive information exposure.'
            },
            {
                'id': 'WSTG-CONF-01',
                'title': 'Test Network Infrastructure Configuration',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Test the network infrastructure configuration for security misconfigurations and vulnerabilities.'
            },
            {
                'id': 'WSTG-CONF-02',
                'title': 'Test Application Platform Configuration',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Verify that the application platform is securely configured according to best practices.'
            },
            {
                'id': 'WSTG-CONF-03',
                'title': 'Test File Extensions Handling for Sensitive Information',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Test how the web server handles different file extensions and potential information disclosure.'
            },
            {
                'id': 'WSTG-CONF-04',
                'title': 'Review Old Backup and Unreferenced Files for Sensitive Information',
                'category': 'Configuration and Deployment Management Testing',
                'description': 'Search for backup files, old versions, and unreferenced files that may contain sensitive information.'
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
                'description': 'Verify that user credentials are transmitted securely over encrypted channels.'
            },
            {
                'id': 'WSTG-ATHN-02',
                'title': 'Testing for Default Credentials',
                'category': 'Authentication Testing',
                'description': 'Test for the presence of default or easily guessable credentials in the application.'
            },
            {
                'id': 'WSTG-ATHN-03',
                'title': 'Testing for Weak Lock Out Mechanism',
                'category': 'Authentication Testing',
                'description': 'Verify that account lockout mechanisms are properly implemented and cannot be bypassed.'
            },
            {
                'id': 'WSTG-SESS-01',
                'title': 'Testing for Session Management Schema',
                'category': 'Session Management Testing',
                'description': 'Analyze the session management implementation for security vulnerabilities.'
            },
            {
                'id': 'WSTG-SESS-02',
                'title': 'Testing for Cookies Attributes',
                'category': 'Session Management Testing',
                'description': 'Verify that session cookies have proper security attributes (HttpOnly, Secure, SameSite).'
            },
            {
                'id': 'WSTG-SESS-03',
                'title': 'Testing for Session Fixation',
                'category': 'Session Management Testing',
                'description': 'Test for session fixation vulnerabilities in the authentication process.'
            },
            {
                'id': 'WSTG-INPV-01',
                'title': 'Testing for Reflected Cross Site Scripting',
                'category': 'Input Validation Testing',
                'description': 'Test for reflected Cross-Site Scripting (XSS) vulnerabilities in user input fields.'
            },
            {
                'id': 'WSTG-INPV-02',
                'title': 'Testing for Stored Cross Site Scripting',
                'category': 'Input Validation Testing',
                'description': 'Test for stored Cross-Site Scripting (XSS) vulnerabilities that persist in the application.'
            },
            {
                'id': 'WSTG-INPV-05',
                'title': 'Testing for SQL Injection',
                'category': 'Input Validation Testing',
                'description': 'Test for SQL injection vulnerabilities in database query parameters.'
            },
            {
                'id': 'WSTG-ERRH-01',
                'title': 'Testing for Improper Error Handling',
                'category': 'Error Handling',
                'description': 'Verify that error messages do not disclose sensitive information about the application.'
            },
            {
                'id': 'WSTG-CRYP-01',
                'title': 'Testing for Weak SSL/TLS Ciphers',
                'category': 'Cryptography',
                'description': 'Test for weak cryptographic implementations and insecure SSL/TLS configurations.'
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
                'title': 'The app uses proven implementations of cryptographic primitives',
                'category': 'Cryptography Requirements',
                'description': 'Verify that the app uses proven implementations of cryptographic primitives.'
            },
            {
                'id': 'MSTG-AUTH-1',
                'title': 'Authentication is performed at the remote endpoint',
                'category': 'Authentication and Session Management Requirements',
                'description': 'If the app provides users access to a remote service, authentication is performed at the remote endpoint.'
            },
            {
                'id': 'MSTG-AUTH-2',
                'title': 'Remote endpoint maintains stateful session management',
                'category': 'Authentication and Session Management Requirements',
                'description': 'Verify that the remote endpoint uses randomly generated access tokens to authenticate client requests.'
            },
            {
                'id': 'MSTG-NETWORK-1',
                'title': 'Data is encrypted on the network using TLS',
                'category': 'Network Communication Requirements',
                'description': 'Verify that data is encrypted on the network using TLS with secure cipher suites.'
            },
            {
                'id': 'MSTG-NETWORK-2',
                'title': 'The TLS certificate is properly verified',
                'category': 'Network Communication Requirements',
                'description': 'Ensure that TLS certificates are properly verified and certificate pinning is implemented where appropriate.'
            },
            {
                'id': 'MSTG-PLATFORM-1',
                'title': 'App only uses software components without known vulnerabilities',
                'category': 'Platform Interaction Requirements',
                'description': 'Verify that the app only uses software components without known security vulnerabilities.'
            },
            {
                'id': 'MSTG-PLATFORM-2',
                'title': 'All app components from third parties are identified and checked',
                'category': 'Platform Interaction Requirements',
                'description': 'Ensure that all third-party components are identified and checked for known security vulnerabilities.'
            },
            {
                'id': 'MSTG-CODE-1',
                'title': 'The app is signed and provisioned with a valid certificate',
                'category': 'Code Quality and Build Setting Requirements',
                'description': 'Verify that the app is signed and provisioned with a valid certificate.'
            },
            {
                'id': 'MSTG-CODE-2',
                'title': 'The app has been built in release mode',
                'category': 'Code Quality and Build Setting Requirements',
                'description': 'Ensure that the app has been built in release mode with appropriate compiler optimizations.'
            },
            {
                'id': 'MSTG-RESILIENCE-1',
                'title': 'The app detects and responds to jailbroken or rooted devices',
                'category': 'Resilience Against Reverse Engineering Requirements',
                'description': 'Verify that the app detects and responds appropriately to jailbroken or rooted devices.'
            },
            {
                'id': 'MSTG-RESILIENCE-2',
                'title': 'The app prevents debugging and/or detects being debugged',
                'category': 'Resilience Against Reverse Engineering Requirements',
                'description': 'Ensure that the app implements anti-debugging techniques or detects when it is being debugged.'
            }
        ]

    @staticmethod
    def _update_cache(data_type, source, count):
        """Update the cache information"""
        cache_entry = OWASPDataCache.query.filter_by(data_type=data_type).first()
        if cache_entry:
            cache_entry.last_updated = datetime.utcnow()
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
        """Get cache information for display"""
        wstg_cache = OWASPDataCache.query.filter_by(data_type='wstg').first()
        mstg_cache = OWASPDataCache.query.filter_by(data_type='mstg').first()
        
        return {
            'wstg': {
                'last_updated': wstg_cache.last_updated if wstg_cache else None,
                'source': wstg_cache.data_source if wstg_cache else 'unknown',
                'count': wstg_cache.test_count if wstg_cache else 0
            },
            'mstg': {
                'last_updated': mstg_cache.last_updated if mstg_cache else None,
                'source': mstg_cache.data_source if mstg_cache else 'unknown',
                'count': mstg_cache.test_count if mstg_cache else 0
            }
        }

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
                            description = f"Security testing as per OWASP WSTG guidelines for {test_name.lower()}."
                            
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

# Automated Testing Service
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
    def test_cache_control(url):
        """Test cache control headers for sensitive content"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            full_request = AutoTestService._format_request_details('GET', url, headers)
            
            # Check cache control headers
            cache_control = response.headers.get('Cache-Control')
            pragma = response.headers.get('Pragma')
            expires = response.headers.get('Expires')
            etag = response.headers.get('ETag')
            last_modified = response.headers.get('Last-Modified')
            
            highlight_headers = []
            cache_directives = []
            recommendations = []
            
            if cache_control:
                highlight_headers.append('Cache-Control')
                directives = [d.strip() for d in cache_control.split(',')]
                
                security_directives = ['no-cache', 'no-store', 'must-revalidate', 'private']
                found_security = [d for d in directives if d in security_directives]
                
                if found_security:
                    cache_directives.append(f"✅ Security directives found: {', '.join(found_security)}")
                else:
                    if 'public' in directives:
                        recommendations.append("⚠️  Public caching enabled - review for sensitive content")
                    cache_directives.append(f"ℹ️  Cache directives: {', '.join(directives)}")
            else:
                recommendations.append("❌ Missing Cache-Control header")
            
            if pragma:
                highlight_headers.append('Pragma')
                if pragma.lower() == 'no-cache':
                    cache_directives.append(f"✅ Pragma no-cache directive present")
                else:
                    cache_directives.append(f"ℹ️  Pragma: {pragma}")
            
            if expires:
                highlight_headers.append('Expires')
                cache_directives.append(f"ℹ️  Expires header: {expires}")
            
            if etag:
                highlight_headers.append('ETag')
                cache_directives.append(f"ℹ️  ETag present for cache validation")
            
            if last_modified:
                highlight_headers.append('Last-Modified')
                cache_directives.append(f"ℹ️  Last-Modified: {last_modified}")
            
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            evidence = "🗂️  Cache Control Analysis\n\n"
            
            if cache_directives:
                evidence += f"Cache Configuration:\n"
                for directive in cache_directives:
                    evidence += f"  {directive}\n"
                evidence += "\n"
            
            # Determine if content might be sensitive
            is_sensitive = any(keyword in url.lower() for keyword in 
                             ['login', 'admin', 'profile', 'account', 'secure', 'private'])
            
            if is_sensitive and not any(directive in (cache_control or '') for directive in 
                                      ['no-cache', 'no-store', 'private']):
                recommendations.append("🚨 Potentially sensitive content without proper cache control")
            
            if recommendations:
                evidence += f"🚨 Recommendations ({len(recommendations)}):\n"
                for rec in recommendations:
                    evidence += f"  {rec}\n"
                evidence += "\n"
                evidence += f"💡 Best Practices:\n"
                evidence += f"   • Use 'no-store' for sensitive data\n"
                evidence += f"   • Use 'private' for user-specific content\n"
                evidence += f"   • Set appropriate max-age for static resources"
                result = 'fail' if is_sensitive else 'informational'
            else:
                evidence += f"✅ Cache control appears appropriate for this content"
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
                'evidence': f'❌ Error testing cache control: {str(e)}',
                'request': f'Cache control test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_subdomain_takeover(url):
        """Test for potential subdomain takeover vulnerabilities"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Skip if not a subdomain
            if domain.count('.') < 2:
                return {
                    'result': 'informational',
                    'evidence': f'ℹ️  Not a subdomain: {domain}\n\nSubdomain takeover tests only apply to subdomains.',
                    'request': f'Subdomain takeover test for {url}',
                    'response': 'Test skipped - not a subdomain'
                }
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            evidence = f"🔍 Subdomain Takeover Analysis for {domain}\n\n"
            
            # Test 1: Try to resolve the domain
            try:
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                evidence += f"✅ Domain resolves and responds (Status: {response.status_code})\n"
                
                # Check for common takeover indicators in response
                takeover_indicators = {
                    'github.io': 'There isn\'t a GitHub Pages site here',
                    'herokuapp.com': 'No such app',
                    'azurewebsites.net': 'Web App - Unavailable',
                    'cloudfront.net': 'Bad Request',
                    's3.amazonaws.com': 'NoSuchBucket',
                    'wordpress.com': 'Do you want to register'
                }
                
                response_text = response.text.lower()
                for service, indicator in takeover_indicators.items():
                    if indicator.lower() in response_text:
                        evidence += f"🚨 POTENTIAL TAKEOVER: {service} indicator found!\n"
                        evidence += f"   Indicator: '{indicator}'\n"
                        
                        return {
                            'result': 'fail',
                            'evidence': evidence + f"\n💡 Recommendation: Immediately investigate and secure this subdomain!",
                            'request': f'GET {url}',
                            'response': f'Potential takeover indicator found: {indicator}'
                        }
                
                evidence += f"✅ No obvious takeover indicators in response content\n"
                
            except requests.exceptions.RequestException as e:
                evidence += f"⚠️  Request failed: {str(e)}\n"
                evidence += f"   This could indicate a dangling DNS record\n"
                
                # Try DNS resolution
                try:
                    import socket
                    ip = socket.gethostbyname(domain)
                    evidence += f"   DNS resolves to: {ip}\n"
                except socket.gaierror:
                    evidence += f"🚨 DNS resolution failed - possible dangling record!\n"
                    return {
                        'result': 'fail',
                        'evidence': evidence + f"\n💡 Recommendation: Check DNS records for this subdomain",
                        'request': f'DNS resolution for {domain}',
                        'response': 'DNS resolution failed'
                    }
            
            # Test 2: Check CNAME records if possible
            try:
                import dns.resolver
                cname_records = dns.resolver.resolve(domain, 'CNAME')
                for cname in cname_records:
                    cname_target = str(cname.target)
                    evidence += f"📋 CNAME record found: {cname_target}\n"
                    
                    # Check if CNAME points to common services
                    risky_services = ['github.io', 'herokuapp.com', 'azurewebsites.net', 
                                    'cloudfront.net', 's3.amazonaws.com', 'wordpress.com']
                    
                    for service in risky_services:
                        if service in cname_target:
                            evidence += f"⚠️  CNAME points to {service} - verify service is still active\n"
                            
            except Exception as dns_error:
                evidence += f"ℹ️  DNS CNAME check failed: {str(dns_error)}\n"
            
            evidence += f"\n✅ No immediate subdomain takeover vulnerability detected"
            
            return {
                'result': 'pass',
                'evidence': evidence,
                'request': f'Subdomain takeover test for {url}',
                'response': 'Subdomain appears secure'
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing subdomain takeover: {str(e)}',
                'request': f'Subdomain takeover test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_directory_listing(url):
        """Test for directory listing vulnerabilities"""
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Common directories to test
            test_paths = [
                '/admin/',
                '/backup/',
                '/config/',
                '/uploads/',
                '/files/',
                '/tmp/',
                '/logs/',
                '/assets/',
                '/css/',
                '/js/',
                '/images/',
                '/.git/',
                '/.svn/',
                '/web.config',
                '/.env'
            ]
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            evidence = "📂 Directory Listing & Sensitive Files Test\n\n"
            findings = []
            accessible_dirs = []
            
            for path in test_paths:
                try:
                    test_url = urljoin(base_url, path)
                    response = requests.get(test_url, headers=headers, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        # Check for directory listing patterns
                        listing_patterns = [
                            r'Index of /',
                            r'Directory listing for',
                            r'<title>Index of',
                            r'Parent Directory',
                            r'<a href="\.\."',
                            r'Last modified'
                        ]
                        
                        is_directory_listing = any(re.search(pattern, response.text, re.IGNORECASE) 
                                                 for pattern in listing_patterns)
                        
                        if is_directory_listing:
                            findings.append(f"🚨 Directory listing: {test_url}")
                            accessible_dirs.append(test_url)
                        elif len(response.text) > 100:  # Non-empty response
                            findings.append(f"⚠️  Accessible path: {test_url} (Status: {response.status_code})")
                    
                except requests.exceptions.RequestException:
                    continue  # Path not accessible or error occurred
            
            if findings:
                evidence += f"🚨 Issues Found ({len(findings)}):\n"
                for finding in findings:
                    evidence += f"  {finding}\n"
                evidence += "\n"
                
                if accessible_dirs:
                    evidence += f"💥 CRITICAL: Directory listings expose file structure!\n"
                    evidence += f"💡 Immediate Actions Required:\n"
                    evidence += f"   • Disable directory browsing on web server\n"
                    evidence += f"   • Add index files to directories\n"
                    evidence += f"   • Review file permissions\n"
                    evidence += f"   • Remove sensitive files from web root"
                    result = 'fail'
                else:
                    evidence += f"💡 Recommendations:\n"
                    evidence += f"   • Review accessible paths\n"
                    evidence += f"   • Ensure sensitive files are not web-accessible\n"
                    evidence += f"   • Implement proper access controls"
                    result = 'fail'
            else:
                evidence += f"✅ No directory listings or obvious sensitive files found\n"
                evidence += f"   • Common administrative paths appear protected\n"
                evidence += f"   • No obvious file exposure detected"
                result = 'pass'
            
            # Create request summary
            request_summary = f"Directory Listing Test for {base_url}\nTested {len(test_paths)} common paths"
            response_summary = f"Found {len(findings)} issues" + (f", {len(accessible_dirs)} directory listings" if accessible_dirs else "")
            
            return {
                'result': result,
                'evidence': evidence,
                'request': request_summary,
                'response': response_summary
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing directory listing: {str(e)}',
                'request': f'Directory listing test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_error_handling(url):
        """Test error handling and information disclosure through error messages"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            evidence = "🚨 Error Handling & Information Disclosure Test\n\n"
            error_tests = []
            
            # Test 1: Invalid parameter
            try:
                invalid_url = url + "?id=999999999999999999999"
                response = requests.get(invalid_url, headers=headers, timeout=10, verify=False)
                error_tests.append(('Invalid Parameter', response))
            except:
                pass
            
            # Test 2: SQL injection attempt (for error detection only)
            try:
                sql_url = url + "?id=1'"
                response = requests.get(sql_url, headers=headers, timeout=10, verify=False)
                error_tests.append(('SQL Injection Test', response))
            except:
                pass
            
            # Test 3: Directory traversal attempt
            try:
                traversal_url = url + "/../../../etc/passwd"
                response = requests.get(traversal_url, headers=headers, timeout=10, verify=False)
                error_tests.append(('Directory Traversal', response))
            except:
                pass
            
            # Test 4: Non-existent page
            try:
                nonexistent_url = urljoin(url, "/this-page-does-not-exist-12345")
                response = requests.get(nonexistent_url, headers=headers, timeout=10, verify=False)
                error_tests.append(('404 Error Page', response))
            except:
                pass
            
            # Analyze error responses
            error_patterns = {
                'SQL Errors': [
                    r'mysql.*error', r'postgresql.*error', r'oracle.*error',
                    r'sql.*syntax.*error', r'sqlite.*error', r'sqlserver.*error'
                ],
                'Stack Traces': [
                    r'stack\s*trace', r'exception.*at\s+line', r'traceback',
                    r'\.java:\d+', r'\.php:\d+', r'\.asp:\d+', r'\.py:\d+'
                ],
                'Path Disclosure': [
                    r'[a-z]:\\[^<>"|]+', r'/var/www/', r'/home/', r'/usr/',
                    r'c:\\inetpub\\', r'c:\\windows\\'
                ],
                'Version Info': [
                    r'php/\d+\.\d+', r'apache/\d+\.\d+', r'nginx/\d+\.\d+',
                    r'microsoft-iis/\d+\.\d+', r'\.net\s+framework'
                ]
            }
            
            issues_found = []
            detailed_findings = []
            
            for test_name, response in error_tests:
                if response and hasattr(response, 'text'):
                    response_text = response.text.lower()
                    
                    for category, patterns in error_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                issues_found.append(f"⚠️  {category} in {test_name}")
                                detailed_findings.append(f"   Pattern: {pattern}")
                                break
            
            if issues_found:
                evidence += f"🚨 Information Disclosure Found ({len(issues_found)} issues):\n"
                for i, issue in enumerate(issues_found):
                    evidence += f"  {issue}\n"
                    if i < len(detailed_findings):
                        evidence += f"  {detailed_findings[i]}\n"
                evidence += "\n"
                evidence += f"💡 Recommendations:\n"
                evidence += f"   • Implement custom error pages\n"
                evidence += f"   • Disable debug mode in production\n"
                evidence += f"   • Configure proper error logging\n"
                evidence += f"   • Remove stack traces from responses"
                result = 'fail'
            else:
                evidence += f"✅ Error handling appears secure\n"
                evidence += f"   • No obvious information disclosure in error responses\n"
                evidence += f"   • Error pages do not reveal sensitive details"
                result = 'pass'
            
            request_summary = f"Error Handling Test for {url}\nTested {len(error_tests)} error conditions"
            response_summary = f"Analyzed error responses for information disclosure"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': request_summary,
                'response': response_summary
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing error handling: {str(e)}',
                'request': f'Error handling test for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_http_security_features(url):
        """Test for modern HTTP security features and best practices"""
        try:
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            full_request = AutoTestService._format_request_details('GET', url, headers)
            
            # Modern security headers to check
            modern_headers = {
                'Expect-CT': 'Certificate Transparency monitoring',
                'Feature-Policy': 'Browser feature controls (deprecated, use Permissions-Policy)',
                'Permissions-Policy': 'Browser feature controls',
                'Cross-Origin-Embedder-Policy': 'Cross-origin isolation',
                'Cross-Origin-Opener-Policy': 'Cross-origin window opening',
                'Cross-Origin-Resource-Policy': 'Cross-origin resource access',
                'Clear-Site-Data': 'Browser data clearing',
                'Report-To': 'Security reporting endpoint',
                'Nel': 'Network Error Logging'
            }
            
            security_features = []
            missing_features = []
            highlight_headers = []
            
            for header, description in modern_headers.items():
                if header in response.headers:
                    security_features.append(f"✅ {header}: {response.headers[header]}")
                    highlight_headers.append(header)
                else:
                    missing_features.append(f"❌ {header} ({description})")
            
            # Check HTTP/2 or HTTP/3 usage
            if hasattr(response.raw, 'version') and response.raw.version == 20:
                security_features.append("✅ HTTP/2 in use")
            elif hasattr(response.raw, 'version') and response.raw.version == 30:
                security_features.append("✅ HTTP/3 in use")
            
            # Check TLS version in headers (if revealed)
            if 'Strict-Transport-Security' in response.headers:
                security_features.append("✅ HTTPS with HSTS")
            
            full_response = AutoTestService._format_response_details(response, highlight_headers)
            
            evidence = "🔒 Modern HTTP Security Features Analysis\n\n"
            
            if security_features:
                evidence += f"Implemented Security Features ({len(security_features)}):\n"
                for feature in security_features:
                    evidence += f"  {feature}\n"
                evidence += "\n"
            
            if missing_features:
                evidence += f"⚠️  Missing Modern Security Features ({len(missing_features)}):\n"
                for feature in missing_features[:5]:  # Show top 5 to avoid clutter
                    evidence += f"  {feature}\n"
                if len(missing_features) > 5:
                    evidence += f"  ... and {len(missing_features) - 5} more\n"
                evidence += "\n"
                evidence += f"💡 Recommendations for Enhanced Security:\n"
                evidence += f"   • Implement Permissions-Policy for feature control\n"
                evidence += f"   • Add Cross-Origin-* headers for isolation\n"
                evidence += f"   • Consider Expect-CT for certificate monitoring\n"
                evidence += f"   • Set up security reporting with Report-To"
            
            # Determine result based on critical vs nice-to-have features
            critical_missing = [f for f in missing_features if any(crit in f for crit in 
                              ['Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy', 'Permissions-Policy'])]
            
            if critical_missing:
                evidence += f"\n🚨 Critical modern security features missing"
                result = 'fail'
            elif len(security_features) >= 3:
                evidence += f"\n✅ Good implementation of modern security features"
                result = 'pass'
            else:
                evidence += f"\n⚠️  Some modern security features could be improved"
                result = 'informational'
            
            return {
                'result': result,
                'evidence': evidence,
                'request': full_request,
                'response': full_response
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing HTTP security features: {str(e)}',
                'request': f'HTTP security features test for {url}',
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
            from urllib.parse import urljoin, urlparse
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
                    import re
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

    @staticmethod
    def test_admin_panel_detection(url):
        """Test for common admin panel paths"""
        try:
            from urllib.parse import urljoin, urlparse
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Common admin paths to test
            admin_paths = [
                '/admin', '/administrator', '/wp-admin', '/wp-login.php',
                '/admin.php', '/admin/', '/admin/login', '/admin/index.php',
                '/administrator/', '/administrator/index.php', '/control-panel',
                '/cpanel', '/plesk', '/webmin', '/phpmyadmin', '/adminer',
                '/manager/html', '/login', '/signin', '/auth'
            ]
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            found_panels = []
            redirect_panels = []
            tested_paths = []
            
            for path in admin_paths:
                try:
                    test_url = urljoin(base_url, path)
                    tested_paths.append(path)
                    
                    response = requests.get(test_url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                    
                    if response.status_code == 200:
                        # Check for admin-like content
                        content_lower = response.text.lower()
                        admin_indicators = ['login', 'password', 'admin', 'dashboard', 'control panel']
                        
                        if any(indicator in content_lower for indicator in admin_indicators):
                            found_panels.append((path, response.status_code, 'Login page detected'))
                    
                    elif response.status_code in [301, 302, 303, 307, 308]:
                        redirect_panels.append((path, response.status_code, response.headers.get('Location', 'Unknown')))
                        
                except:
                    continue  # Skip failed requests
            
            evidence = f"🔐 Admin Panel Detection\n\n"
            evidence += f"📊 Tested {len(tested_paths)} common admin paths\n\n"
            
            if found_panels or redirect_panels:
                if found_panels:
                    evidence += f"🚨 Accessible admin panels found:\n"
                    for path, status, desc in found_panels:
                        evidence += f"  • {path} (HTTP {status}) - {desc}\n"
                
                if redirect_panels:
                    evidence += f"\n↩️  Admin panel redirects found:\n"
                    for path, status, location in redirect_panels:
                        evidence += f"  • {path} → {location} (HTTP {status})\n"
                
                evidence += f"\n🚨 Security Risk: Admin panels are discoverable\n"
                evidence += f"💡 Recommendations:\n"
                evidence += f"   • Move admin panels to non-standard paths\n"
                evidence += f"   • Implement IP-based access restrictions\n"
                evidence += f"   • Use strong authentication and MFA\n"
                evidence += f"   • Monitor for unauthorized access attempts\n"
                result = 'fail'
            else:
                evidence += f"✅ No common admin panels found on standard paths\n"
                evidence += f"🛡️  Good security practice: Admin interfaces are not easily discoverable\n"
                result = 'pass'
            
            request_summary = f"Admin Panel Detection for {base_url}\nTested {len(tested_paths)} paths"
            response_summary = f"Found {len(found_panels)} panels, {len(redirect_panels)} redirects"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': request_summary,
                'response': response_summary
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing admin panel detection: {str(e)}',
                'request': f'Admin panel detection for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_backup_file_detection(url):
        """Test for exposed backup files"""
        try:
            from urllib.parse import urljoin, urlparse
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Common backup file extensions and patterns
            backup_patterns = [
                'index.html.bak', 'index.php.bak', 'index.asp.bak',
                'backup.zip', 'backup.tar.gz', 'backup.sql', 'database.sql',
                'config.php.bak', 'config.php.old', 'config.php~',
                'web.config.bak', '.env.bak', '.env.old',
                'site.zip', 'www.zip', 'backup.tar', 'dump.sql'
            ]
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': '*/*'
            }
            
            found_backups = []
            tested_files = []
            
            for pattern in backup_patterns:
                try:
                    test_url = urljoin(base_url, '/' + pattern)
                    tested_files.append(pattern)
                    
                    response = requests.head(test_url, headers=headers, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        content_length = response.headers.get('Content-Length', 'Unknown')
                        content_type = response.headers.get('Content-Type', 'Unknown')
                        found_backups.append((pattern, content_length, content_type))
                        
                except:
                    continue  # Skip failed requests
            
            evidence = f"📦 Backup File Detection\n\n"
            evidence += f"📊 Tested {len(tested_files)} backup file patterns\n\n"
            
            if found_backups:
                evidence += f"🚨 Exposed backup files found:\n"
                for filename, size, content_type in found_backups:
                    evidence += f"  • {filename}\n"
                    evidence += f"    Size: {size} bytes, Type: {content_type}\n"
                
                evidence += f"\n🚨 Security Risk: Backup files may contain sensitive data\n"
                evidence += f"💡 Recommendations:\n"
                evidence += f"   • Remove all backup files from web-accessible directories\n"
                evidence += f"   • Use .htaccess or web server rules to block backup file access\n"
                evidence += f"   • Store backups outside the document root\n"
                evidence += f"   • Implement automated cleanup procedures\n"
                result = 'fail'
            else:
                evidence += f"✅ No common backup files found in web root\n"
                evidence += f"🛡️  Good security practice: Backup files are not web-accessible\n"
                result = 'pass'
            
            request_summary = f"Backup File Detection for {base_url}\nTested {len(tested_files)} patterns"
            response_summary = f"Found {len(found_backups)} exposed backup files"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': request_summary,
                'response': response_summary
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing backup file detection: {str(e)}',
                'request': f'Backup file detection for {url}',
                'response': 'Request failed - connection error'
            }

    @staticmethod
    def test_version_control_exposure(url):
        """Test for exposed version control directories"""
        try:
            from urllib.parse import urljoin, urlparse
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Version control paths to test
            vc_paths = [
                '.git/', '.git/config', '.git/HEAD', '.git/logs/HEAD',
                '.svn/', '.svn/entries', '.svn/wc.db',
                '.hg/', '.hg/requires', '.bzr/', 'CVS/', 'CVS/Root'
            ]
            
            headers = {
                'User-Agent': 'AutoWASPy Security Scanner',
                'Accept': 'text/plain,*/*'
            }
            
            found_vc = []
            tested_paths = []
            
            for path in vc_paths:
                try:
                    test_url = urljoin(base_url, '/' + path)
                    tested_paths.append(path)
                    
                    response = requests.get(test_url, headers=headers, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        # Check for version control indicators
                        content = response.text[:200].lower()  # First 200 chars
                        
                        vc_indicators = {
                            '.git': ['ref:', 'refs/', 'repository', 'gitdir'],
                            '.svn': ['svn', 'entries', 'repository'],
                            '.hg': ['mercurial', 'repository'],
                            'CVS': ['cvs', 'repository']
                        }
                        
                        for vc_type, indicators in vc_indicators.items():
                            if vc_type in path and any(indicator in content for indicator in indicators):
                                found_vc.append((path, vc_type, len(response.content)))
                                break
                        else:
                            # Generic detection for accessible VC paths
                            if len(response.content) > 0:
                                found_vc.append((path, 'Unknown VCS', len(response.content)))
                                
                except:
                    continue  # Skip failed requests
            
            evidence = f"📂 Version Control Exposure Test\n\n"
            evidence += f"📊 Tested {len(tested_paths)} version control paths\n\n"
            
            if found_vc:
                evidence += f"🚨 Exposed version control data found:\n"
                for path, vc_type, size in found_vc:
                    evidence += f"  • {path} ({vc_type}) - {size} bytes\n"
                
                evidence += f"\n🚨 Critical Security Risk: Source code and history may be exposed\n"
                evidence += f"💥 Attackers can download entire source code repositories!\n\n"
                evidence += f"💡 Immediate Actions Required:\n"
                evidence += f"   • Block access to all .git, .svn, .hg, CVS directories\n"
                evidence += f"   • Remove version control data from production servers\n"
                evidence += f"   • Use .htaccess or web server rules to deny access\n"
                evidence += f"   • Audit for other sensitive development files\n"
                result = 'fail'
            else:
                evidence += f"✅ No version control directories exposed\n"
                evidence += f"🛡️  Good security practice: Development files are not accessible\n"
                result = 'pass'
            
            request_summary = f"Version Control Exposure Test for {base_url}\nTested {len(tested_paths)} paths"
            response_summary = f"Found {len(found_vc)} exposed version control paths"
            
            return {
                'result': result,
                'evidence': evidence,
                'request': request_summary,
                'response': response_summary
            }
            
        except Exception as e:
            return {
                'result': 'error',
                'evidence': f'❌ Error testing version control exposure: {str(e)}',
                'request': f'Version control exposure test for {url}',
                'response': 'Request failed - connection error'
            }

# Routes
@app.route('/')
def index():
    projects = Project.query.order_by(Project.created_date.desc()).all()
    return render_template('index.html', projects=projects)

@app.route('/project/new', methods=['GET', 'POST'])
def new_project():
    if request.method == 'POST':
        project = Project(
            name=request.form['name'],
            client_name=request.form['client_name'],
            job_type=request.form['job_type'],
            description=request.form.get('description', ''),
            urls=request.form.get('urls', '')
        )
        
        db.session.add(project)
        db.session.commit()
        
        # Initialize test items based on job type
        if project.job_type == 'web':
            tests = OWASPService.fetch_wstg_data()
            test_type = 'wstg'
        else:  # mobile
            tests = OWASPService.fetch_mstg_data()
            test_type = 'mstg'
        
        for test_data in tests:
            test_item = TestItem(
                project_id=project.id,
                owasp_id=test_data['id'],
                title=test_data['title'],
                description=test_data['description'],
                category=test_data['category'],
                test_type=test_type
            )
            db.session.add(test_item)
        
        db.session.commit()
        flash(f'Project "{project.name}" created successfully!', 'success')
        return redirect(url_for('project_detail', project_id=project.id))
    
    return render_template('new_project.html')

@app.route('/project/<int:project_id>')
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    test_items = TestItem.query.filter_by(project_id=project_id).order_by(TestItem.category, TestItem.owasp_id).all()
    
    # Group test items by category
    categories = {}
    for item in test_items:
        if item.category not in categories:
            categories[item.category] = []
        categories[item.category].append(item)
    
    return render_template('project_detail.html', project=project, categories=categories)

@app.route('/project/<int:project_id>/test/<int:test_id>/update', methods=['POST'])
def update_test_item(project_id, test_id):
    test_item = TestItem.query.get_or_404(test_id)
    
    test_item.is_tested = request.form.get('is_tested') == 'on'
    test_item.evidence = request.form.get('evidence', '')
    test_item.finding_status = request.form.get('finding_status', 'not_tested')
    test_item.risk_level = request.form.get('risk_level', '')
    test_item.updated_date = datetime.utcnow()
    
    db.session.commit()
    flash('Test item updated successfully!', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/autotest', methods=['POST'])
def run_auto_tests(project_id):
    project = Project.query.get_or_404(project_id)
    
    if not project.urls:
        flash('No URLs configured for automatic testing', 'error')
        return redirect(url_for('project_detail', project_id=project_id))
    
    urls = [url.strip() for url in project.urls.split('\n') if url.strip()]
    
    # List of all available auto tests
    auto_tests = [
        ('HSTS Test', AutoTestService.test_hsts),
        ('Cookie Security Test', AutoTestService.test_cookie_security),
        ('Security Headers Test', AutoTestService.test_security_headers),
        ('SSL Configuration Test', AutoTestService.test_ssl_configuration),
        ('HTTP Methods Test', AutoTestService.test_http_methods),
        ('Information Disclosure Test', AutoTestService.test_information_disclosure),
        ('Clickjacking Protection Test', AutoTestService.test_clickjacking_protection),
        ('CORS Configuration Test', AutoTestService.test_cors_configuration),
        ('Content Type Validation Test', AutoTestService.test_content_type_validation),
        ('Cache Control Test', AutoTestService.test_cache_control),
        ('Subdomain Takeover Test', AutoTestService.test_subdomain_takeover),
        ('Directory Listing Test', AutoTestService.test_directory_listing),
        ('Error Handling Test', AutoTestService.test_error_handling),
        ('HTTP Security Features Test', AutoTestService.test_http_security_features),
        ('Input Validation Test', AutoTestService.test_input_validation),
        ('Robots.txt Analysis', AutoTestService.test_robots_txt_analysis),
        ('Web Server Detection', AutoTestService.test_web_server_detection),
        ('Admin Panel Detection', AutoTestService.test_admin_panel_detection),
        ('Backup File Detection', AutoTestService.test_backup_file_detection),
        ('Version Control Exposure', AutoTestService.test_version_control_exposure)
    ]
    
    total_tests = 0
    successful_tests = 0
    
    for url in urls:
        flash(f'Running automated tests for: {url}', 'info')
        
        for test_name, test_function in auto_tests:
            try:
                print(f"Running {test_name} for {url}")
                test_result = test_function(url)
                
                auto_result = AutoTestResult(
                    project_id=project_id,
                    test_name=test_name,
                    url_tested=url,
                    result=test_result['result'],
                    evidence=test_result['evidence'],
                    request_data=test_result['request'],
                    response_data=test_result['response']
                )
                db.session.add(auto_result)
                
                total_tests += 1
                if test_result['result'] == 'pass':
                    successful_tests += 1
                    
            except Exception as e:
                print(f"Error running {test_name} for {url}: {e}")
                # Log the error but continue with other tests
                error_result = AutoTestResult(
                    project_id=project_id,
                    test_name=test_name,
                    url_tested=url,
                    result='error',
                    evidence=f'Test failed with error: {str(e)}',
                    request_data='N/A - Test Error',
                    response_data='N/A - Test Error'
                )
                db.session.add(error_result)
                total_tests += 1
    
    db.session.commit()
    flash(f'Automated tests completed! {successful_tests}/{total_tests} tests passed.', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<int:project_id>/autotest-results')
def autotest_results(project_id):
    project = Project.query.get_or_404(project_id)
    results = AutoTestResult.query.filter_by(project_id=project_id).order_by(AutoTestResult.created_date.desc()).all()
    return render_template('autotest_results.html', project=project, results=results)

@app.route('/admin/refresh-owasp', methods=['GET', 'POST'])
def refresh_owasp_data():
    if request.method == 'POST':
        try:
            # Clear cache to force fresh fetch
            OWASPDataCache.query.delete()
            db.session.commit()
            
            # Fetch latest OWASP data
            flash('Fetching latest OWASP WSTG data from GitHub...', 'info')
            wstg_data = OWASPService.fetch_wstg_data()
            
            flash('Fetching latest OWASP MSTG data from GitHub...', 'info')
            mstg_data = OWASPService.fetch_mstg_data()
            
            flash('OWASP data refreshed successfully!', 'success')
            
        except Exception as e:
            flash(f'Error refreshing OWASP data: {str(e)}', 'error')
        
        return redirect(url_for('index'))
    
    # Get cache information for display
    cache_info = OWASPService.get_cache_info()
    return render_template('refresh_owasp.html', cache_info=cache_info)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.getenv('PORT', 5001))
    app.run(debug=True, host='0.0.0.0', port=port)
