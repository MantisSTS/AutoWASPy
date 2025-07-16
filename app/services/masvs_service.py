"""
MASVS (Mobile Application Security Verification Standard) Service
Provides MASVS checklists for both iOS and Android platforms
"""
import os
import json
import requests
import re
from app.utils.datetime_utils import utc_now


class MASVSService:
    """Service for handling MASVS verification requirements"""
    
    @staticmethod
    def fetch_masvs_data():
        """Fetch OWASP MASVS verification requirements from GitHub repository"""
        try:
            print("Fetching MASVS data from GitHub...")
            
            # Try to fetch from the official MASVS repository
            masvs_requirements = []
            
            # Fetch MASVS requirements from different sources
            sources = [
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x03-Using_the_MASVS.md",
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x07-V2-Data_Storage_and_Privacy_Requirements.md",
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x08-V3-Cryptography_Requirements.md",
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x09-V4-Authentication_and_Session_Management_Requirements.md",
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x10-V5-Network_Communication_Requirements.md",
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x11-V6-Environmental_Interaction_Requirements.md",
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x12-V7-Code_Quality_and_Build_Setting_Requirements.md",
                "https://raw.githubusercontent.com/OWASP/owasp-masvs/master/Document/0x13-V8-Resilience_Against_Reverse_Engineering_Requirements.md"
            ]
            
            for source_url in sources:
                try:
                    response = requests.get(source_url, timeout=30)
                    if response.status_code == 200:
                        content = response.text
                        requirements = MASVSService._parse_masvs_content(content)
                        masvs_requirements.extend(requirements)
                except Exception as e:
                    print(f"Error fetching from {source_url}: {e}")
                    continue
            
            # Remove duplicates
            unique_requirements = []
            seen_ids = set()
            for req in masvs_requirements:
                if req['id'] not in seen_ids:
                    seen_ids.add(req['id'])
                    unique_requirements.append(req)
            
            if len(unique_requirements) >= 30:  # MASVS typically has around 50-60 requirements
                print(f"Successfully fetched {len(unique_requirements)} MASVS requirements")
                MASVSService._save_to_cache('masvs', unique_requirements)
                return sorted(unique_requirements, key=lambda x: x['id'])
            else:
                print("GitHub fetch returned insufficient data, using enhanced MASVS fallback data")
                fallback_data = MASVSService._get_enhanced_masvs_data()
                return fallback_data
                
        except Exception as e:
            print(f"Error fetching MASVS data from GitHub: {e}")
            fallback_data = MASVSService._get_enhanced_masvs_data()
            return fallback_data
    
    @staticmethod
    def _parse_masvs_content(content):
        """Parse MASVS content for verification requirements"""
        requirements = []
        
        # Pattern to match MASVS requirements: V<NUMBER>.<NUMBER>
        # Example: V2.1, V3.7, etc.
        pattern = r'\*?\*?\s*(V\d+\.\d+)\s*[:\-\|]\s*(.*?)(?=\n|$)'
        
        for match in re.finditer(pattern, content, re.MULTILINE):
            requirement_id = match.group(1).strip()
            description = match.group(2).strip()
            
            # Clean up the description
            description = re.sub(r'\*\*([^*]+)\*\*', r'\1', description)  # Remove bold markdown
            description = re.sub(r'\*([^*]+)\*', r'\1', description)      # Remove italic markdown
            description = description.replace('|', '').strip()            # Remove table separators
            
            if len(description) > 10:  # Filter out very short descriptions
                category = MASVSService._get_masvs_category(requirement_id)
                
                requirements.append({
                    'id': requirement_id,
                    'title': f"MASVS {requirement_id}",
                    'category': category,
                    'description': description,
                    'full_description': f"MASVS Verification Requirement {requirement_id}: {description}"
                })
        
        return requirements
    
    @staticmethod
    def _get_masvs_category(requirement_id):
        """Get category based on MASVS requirement ID"""
        if requirement_id.startswith('V1.'):
            return "Architecture, Design and Threat Modeling"
        elif requirement_id.startswith('V2.'):
            return "Data Storage and Privacy"
        elif requirement_id.startswith('V3.'):
            return "Cryptography"
        elif requirement_id.startswith('V4.'):
            return "Authentication and Session Management"
        elif requirement_id.startswith('V5.'):
            return "Network Communication"
        elif requirement_id.startswith('V6.'):
            return "Environmental Interaction"
        elif requirement_id.startswith('V7.'):
            return "Code Quality and Build Settings"
        elif requirement_id.startswith('V8.'):
            return "Resilience Against Reverse Engineering"
        else:
            return "General Requirements"
    
    @staticmethod
    def get_masvs_requirements(platform='both'):
        """Return MASVS requirements for the given platform ('android', 'ios', or 'both')"""
        return MASVSService.get_cached_masvs_data_for_platform(platform)
    
    @staticmethod
    def get_cached_masvs_data():
        """Get MASVS data from cache or fallback"""
        try:
            cache_data = MASVSService._load_from_cache('masvs')
            if cache_data:
                return cache_data
            else:
                return MASVSService._get_enhanced_masvs_data()
        except Exception as e:
            print(f"Error loading MASVS cache: {e}")
            return MASVSService._get_enhanced_masvs_data()
    
    @staticmethod
    def get_cached_masvs_data_for_platform(platform):
        """Get platform-specific MASVS data (ios or android)"""
        # For now, MASVS requirements are platform-agnostic
        # Both iOS and Android projects get the same requirements
        # In the future, we could add platform-specific filtering
        all_requirements = MASVSService.get_cached_masvs_data()
        
        # Add platform indicator to titles for clarity
        platform_requirements = []
        for req in all_requirements:
            req_copy = req.copy()
            req_copy['title'] = f"MASVS {req['id']} ({platform.upper()})"
            platform_requirements.append(req_copy)
        
        print(f"Returning {len(platform_requirements)} MASVS requirements for {platform} platform")
        return platform_requirements
    
    @staticmethod
    def _get_enhanced_masvs_data():
        """Enhanced fallback MASVS data with comprehensive requirements"""
        return [
            # V1: Architecture, Design and Threat Modeling Requirements
            {
                'id': 'V1.1',
                'title': 'MASVS V1.1',
                'category': 'Architecture, Design and Threat Modeling',
                'description': 'All app components are identified and are known to be needed.',
                'full_description': 'MASVS Verification Requirement V1.1: All app components are identified and are known to be needed.'
            },
            {
                'id': 'V1.2',
                'title': 'MASVS V1.2',
                'category': 'Architecture, Design and Threat Modeling',
                'description': 'Security controls are never enforced only on the client side, but on the respective remote endpoints.',
                'full_description': 'MASVS Verification Requirement V1.2: Security controls are never enforced only on the client side, but on the respective remote endpoints.'
            },
            {
                'id': 'V1.3',
                'title': 'MASVS V1.3',
                'category': 'Architecture, Design and Threat Modeling',
                'description': 'A high-level architecture has been defined for the mobile app and all connected remote services and those components have been identified.',
                'full_description': 'MASVS Verification Requirement V1.3: A high-level architecture has been defined for the mobile app and all connected remote services and those components have been identified.'
            },
            {
                'id': 'V1.4',
                'title': 'MASVS V1.4',
                'category': 'Architecture, Design and Threat Modeling',
                'description': 'Data considered sensitive in the context of the mobile app is clearly identified.',
                'full_description': 'MASVS Verification Requirement V1.4: Data considered sensitive in the context of the mobile app is clearly identified.'
            },
            {
                'id': 'V1.5',
                'title': 'MASVS V1.5',
                'category': 'Architecture, Design and Threat Modeling',
                'description': 'All app components are defined in terms of the business functions and/or security functions they provide.',
                'full_description': 'MASVS Verification Requirement V1.5: All app components are defined in terms of the business functions and/or security functions they provide.'
            },
            
            # V2: Data Storage and Privacy Requirements
            {
                'id': 'V2.1',
                'title': 'MASVS V2.1',
                'category': 'Data Storage and Privacy',
                'description': 'System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys.',
                'full_description': 'MASVS Verification Requirement V2.1: System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys.'
            },
            {
                'id': 'V2.2',
                'title': 'MASVS V2.2',
                'category': 'Data Storage and Privacy',
                'description': 'No sensitive data should be stored outside of the app container or system credential storage facilities.',
                'full_description': 'MASVS Verification Requirement V2.2: No sensitive data should be stored outside of the app container or system credential storage facilities.'
            },
            {
                'id': 'V2.3',
                'title': 'MASVS V2.3',
                'category': 'Data Storage and Privacy',
                'description': 'No sensitive data is written to application logs.',
                'full_description': 'MASVS Verification Requirement V2.3: No sensitive data is written to application logs.'
            },
            {
                'id': 'V2.4',
                'title': 'MASVS V2.4',
                'category': 'Data Storage and Privacy',
                'description': 'No sensitive data is shared with third parties unless it is a necessary part of the architecture.',
                'full_description': 'MASVS Verification Requirement V2.4: No sensitive data is shared with third parties unless it is a necessary part of the architecture.'
            },
            {
                'id': 'V2.5',
                'title': 'MASVS V2.5',
                'category': 'Data Storage and Privacy',
                'description': 'The keyboard cache is disabled on text inputs that process sensitive data.',
                'full_description': 'MASVS Verification Requirement V2.5: The keyboard cache is disabled on text inputs that process sensitive data.'
            },
            {
                'id': 'V2.6',
                'title': 'MASVS V2.6',
                'category': 'Data Storage and Privacy',
                'description': 'No sensitive data is exposed via IPC mechanisms.',
                'full_description': 'MASVS Verification Requirement V2.6: No sensitive data is exposed via IPC mechanisms.'
            },
            {
                'id': 'V2.7',
                'title': 'MASVS V2.7',
                'category': 'Data Storage and Privacy',
                'description': 'No sensitive data, such as passwords or pins, is exposed through the user interface.',
                'full_description': 'MASVS Verification Requirement V2.7: No sensitive data, such as passwords or pins, is exposed through the user interface.'
            },
            {
                'id': 'V2.8',
                'title': 'MASVS V2.8',
                'category': 'Data Storage and Privacy',
                'description': 'No sensitive data is included in backups generated by the mobile operating system.',
                'full_description': 'MASVS Verification Requirement V2.8: No sensitive data is included in backups generated by the mobile operating system.'
            },
            
            # V3: Cryptography Requirements
            {
                'id': 'V3.1',
                'title': 'MASVS V3.1',
                'category': 'Cryptography',
                'description': 'The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.',
                'full_description': 'MASVS Verification Requirement V3.1: The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.'
            },
            {
                'id': 'V3.2',
                'title': 'MASVS V3.2',
                'category': 'Cryptography',
                'description': 'The app uses proven implementations of cryptographic primitives.',
                'full_description': 'MASVS Verification Requirement V3.2: The app uses proven implementations of cryptographic primitives.'
            },
            {
                'id': 'V3.3',
                'title': 'MASVS V3.3',
                'category': 'Cryptography',
                'description': 'The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices.',
                'full_description': 'MASVS Verification Requirement V3.3: The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices.'
            },
            {
                'id': 'V3.4',
                'title': 'MASVS V3.4',
                'category': 'Cryptography',
                'description': 'The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes.',
                'full_description': 'MASVS Verification Requirement V3.4: The app does not use cryptographic protocols or algorithms that are widely considered depreciated for security purposes.'
            },
            {
                'id': 'V3.5',
                'title': 'MASVS V3.5',
                'category': 'Cryptography',
                'description': 'The app doesn\'t re-use the same cryptographic key for multiple purposes.',
                'full_description': 'MASVS Verification Requirement V3.5: The app doesn\'t re-use the same cryptographic key for multiple purposes.'
            },
            {
                'id': 'V3.6',
                'title': 'MASVS V3.6',
                'category': 'Cryptography',
                'description': 'All random values are generated using a sufficiently secure random number generator.',
                'full_description': 'MASVS Verification Requirement V3.6: All random values are generated using a sufficiently secure random number generator.'
            },
            
            # V4: Authentication and Session Management Requirements
            {
                'id': 'V4.1',
                'title': 'MASVS V4.1',
                'category': 'Authentication and Session Management',
                'description': 'If the app provides users access to a remote service, some form of authentication, such as username/password authentication, is performed at the remote endpoint.',
                'full_description': 'MASVS Verification Requirement V4.1: If the app provides users access to a remote service, some form of authentication, such as username/password authentication, is performed at the remote endpoint.'
            },
            {
                'id': 'V4.2',
                'title': 'MASVS V4.2',
                'category': 'Authentication and Session Management',
                'description': 'If stateful session management is used, the remote endpoint uses randomly generated session identifiers to authenticate client requests without sending the user\'s credentials.',
                'full_description': 'MASVS Verification Requirement V4.2: If stateful session management is used, the remote endpoint uses randomly generated session identifiers to authenticate client requests without sending the user\'s credentials.'
            },
            {
                'id': 'V4.3',
                'title': 'MASVS V4.3',
                'category': 'Authentication and Session Management',
                'description': 'If stateless token-based authentication is used, the server provides a token that has been signed using a secure algorithm.',
                'full_description': 'MASVS Verification Requirement V4.3: If stateless token-based authentication is used, the server provides a token that has been signed using a secure algorithm.'
            },
            {
                'id': 'V4.4',
                'title': 'MASVS V4.4',
                'category': 'Authentication and Session Management',
                'description': 'The remote endpoint terminates the existing session when the user logs out.',
                'full_description': 'MASVS Verification Requirement V4.4: The remote endpoint terminates the existing session when the user logs out.'
            },
            {
                'id': 'V4.5',
                'title': 'MASVS V4.5',
                'category': 'Authentication and Session Management',
                'description': 'A password policy exists and is enforced at the remote endpoint.',
                'full_description': 'MASVS Verification Requirement V4.5: A password policy exists and is enforced at the remote endpoint.'
            },
            
            # V5: Network Communication Requirements
            {
                'id': 'V5.1',
                'title': 'MASVS V5.1',
                'category': 'Network Communication',
                'description': 'Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app.',
                'full_description': 'MASVS Verification Requirement V5.1: Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app.'
            },
            {
                'id': 'V5.2',
                'title': 'MASVS V5.2',
                'category': 'Network Communication',
                'description': 'The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards.',
                'full_description': 'MASVS Verification Requirement V5.2: The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards.'
            },
            {
                'id': 'V5.3',
                'title': 'MASVS V5.3',
                'category': 'Network Communication',
                'description': 'The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted.',
                'full_description': 'MASVS Verification Requirement V5.3: The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted.'
            },
            {
                'id': 'V5.4',
                'title': 'MASVS V5.4',
                'category': 'Network Communication',
                'description': 'The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA.',
                'full_description': 'MASVS Verification Requirement V5.4: The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA.'
            },
            {
                'id': 'V5.5',
                'title': 'MASVS V5.5',
                'category': 'Network Communication',
                'description': 'The app doesn\'t rely on a single insecure communication channel (email or SMS) for critical operations, such as enrollments and account recovery.',
                'full_description': 'MASVS Verification Requirement V5.5: The app doesn\'t rely on a single insecure communication channel (email or SMS) for critical operations, such as enrollments and account recovery.'
            },
            
            # V6: Environmental Interaction Requirements
            {
                'id': 'V6.1',
                'title': 'MASVS V6.1',
                'category': 'Environmental Interaction',
                'description': 'The app only requires the minimum set of permissions that are necessary.',
                'full_description': 'MASVS Verification Requirement V6.1: The app only requires the minimum set of permissions that are necessary.'
            },
            {
                'id': 'V6.2',
                'title': 'MASVS V6.2',
                'category': 'Environmental Interaction',
                'description': 'All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources.',
                'full_description': 'MASVS Verification Requirement V6.2: All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources.'
            },
            {
                'id': 'V6.3',
                'title': 'MASVS V6.3',
                'category': 'Environmental Interaction',
                'description': 'The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected.',
                'full_description': 'MASVS Verification Requirement V6.3: The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected.'
            },
            {
                'id': 'V6.4',
                'title': 'MASVS V6.4',
                'category': 'Environmental Interaction',
                'description': 'The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected.',
                'full_description': 'MASVS Verification Requirement V6.4: The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected.'
            },
            {
                'id': 'V6.5',
                'title': 'MASVS V6.5',
                'category': 'Environmental Interaction',
                'description': 'JavaScript is disabled in WebViews unless explicitly required.',
                'full_description': 'MASVS Verification Requirement V6.5: JavaScript is disabled in WebViews unless explicitly required.'
            },
            
            # V7: Code Quality and Build Settings Requirements
            {
                'id': 'V7.1',
                'title': 'MASVS V7.1',
                'category': 'Code Quality and Build Settings',
                'description': 'The app is signed and provisioned with a valid certificate, of which the private key is properly protected.',
                'full_description': 'MASVS Verification Requirement V7.1: The app is signed and provisioned with a valid certificate, of which the private key is properly protected.'
            },
            {
                'id': 'V7.2',
                'title': 'MASVS V7.2',
                'category': 'Code Quality and Build Settings',
                'description': 'The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable).',
                'full_description': 'MASVS Verification Requirement V7.2: The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable).'
            },
            {
                'id': 'V7.3',
                'title': 'MASVS V7.3',
                'category': 'Code Quality and Build Settings',
                'description': 'Debugging symbols have been removed from native binaries.',
                'full_description': 'MASVS Verification Requirement V7.3: Debugging symbols have been removed from native binaries.'
            },
            {
                'id': 'V7.4',
                'title': 'MASVS V7.4',
                'category': 'Code Quality and Build Settings',
                'description': 'Debugging code and developer assistance code (e.g. test code, backdoors, hidden settings) have been removed. The app does not log verbose errors or debugging messages.',
                'full_description': 'MASVS Verification Requirement V7.4: Debugging code and developer assistance code (e.g. test code, backdoors, hidden settings) have been removed. The app does not log verbose errors or debugging messages.'
            },
            {
                'id': 'V7.5',
                'title': 'MASVS V7.5',
                'category': 'Code Quality and Build Settings',
                'description': 'All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities.',
                'full_description': 'MASVS Verification Requirement V7.5: All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities.'
            },
            {
                'id': 'V7.6',
                'title': 'MASVS V7.6',
                'category': 'Code Quality and Build Settings',
                'description': 'The app catches and handles possible exceptions.',
                'full_description': 'MASVS Verification Requirement V7.6: The app catches and handles possible exceptions.'
            },
            {
                'id': 'V7.7',
                'title': 'MASVS V7.7',
                'category': 'Code Quality and Build Settings',
                'description': 'Error handling logic in security controls denies access by default.',
                'full_description': 'MASVS Verification Requirement V7.7: Error handling logic in security controls denies access by default.'
            },
            {
                'id': 'V7.8',
                'title': 'MASVS V7.8',
                'category': 'Code Quality and Build Settings',
                'description': 'In unmanaged code, memory is allocated, freed and used securely.',
                'full_description': 'MASVS Verification Requirement V7.8: In unmanaged code, memory is allocated, freed and used securely.'
            },
            
            # V8: Resilience Against Reverse Engineering Requirements
            {
                'id': 'V8.1',
                'title': 'MASVS V8.1',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The app detects, and responds to, the presence of a rooted or jailbroken device either by alerting the user or terminating the app.',
                'full_description': 'MASVS Verification Requirement V8.1: The app detects, and responds to, the presence of a rooted or jailbroken device either by alerting the user or terminating the app.'
            },
            {
                'id': 'V8.2',
                'title': 'MASVS V8.2',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The app prevents debugging and/or detects, and responds to, a debugger being attached. All available debugging protocols must be covered.',
                'full_description': 'MASVS Verification Requirement V8.2: The app prevents debugging and/or detects, and responds to, a debugger being attached. All available debugging protocols must be covered.'
            },
            {
                'id': 'V8.3',
                'title': 'MASVS V8.3',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The app detects, and responds to, tampering with executable files and critical data within its own sandbox.',
                'full_description': 'MASVS Verification Requirement V8.3: The app detects, and responds to, tampering with executable files and critical data within its own sandbox.'
            },
            {
                'id': 'V8.4',
                'title': 'MASVS V8.4',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The app detects, and responds to, the presence of widely used reverse engineering tools and frameworks on the device.',
                'full_description': 'MASVS Verification Requirement V8.4: The app detects, and responds to, the presence of widely used reverse engineering tools and frameworks on the device.'
            },
            {
                'id': 'V8.5',
                'title': 'MASVS V8.5',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The app detects, and responds to, being run in an emulator.',
                'full_description': 'MASVS Verification Requirement V8.5: The app detects, and responds to, being run in an emulator.'
            },
            {
                'id': 'V8.6',
                'title': 'MASVS V8.6',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The app detects, and responds to, tampering the code and data in its own memory space.',
                'full_description': 'MASVS Verification Requirement V8.6: The app detects, and responds to, tampering the code and data in its own memory space.'
            },
            {
                'id': 'V8.7',
                'title': 'MASVS V8.7',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The app implements multiple mechanisms in each defense category (8.1 to 8.6). Note that resiliency scales with the amount, diversity of the originality of the mechanisms used.',
                'full_description': 'MASVS Verification Requirement V8.7: The app implements multiple mechanisms in each defense category (8.1 to 8.6). Note that resiliency scales with the amount, diversity of the originality of the mechanisms used.'
            },
            {
                'id': 'V8.8',
                'title': 'MASVS V8.8',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'The detection mechanisms trigger responses of different types, including delayed and stealthy responses.',
                'full_description': 'MASVS Verification Requirement V8.8: The detection mechanisms trigger responses of different types, including delayed and stealthy responses.'
            },
            {
                'id': 'V8.9',
                'title': 'MASVS V8.9',
                'category': 'Resilience Against Reverse Engineering',
                'description': 'Obfuscation is applied to programmatic defenses, which in turn impede de-obfuscation via dynamic analysis.',
                'full_description': 'MASVS Verification Requirement V8.9: Obfuscation is applied to programmatic defenses, which in turn impede de-obfuscation via dynamic analysis.'
            }
        ]
    
    @staticmethod
    def _save_to_cache(cache_type, data):
        """Save data to cache file"""
        try:
            cache_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'cache')
            os.makedirs(cache_dir, exist_ok=True)
            
            cache_file = os.path.join(cache_dir, f'{cache_type}_cache.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"Saved {len(data)} items to {cache_type} cache")
        except Exception as e:
            print(f"Error saving {cache_type} cache: {e}")
    
    @staticmethod
    def _load_from_cache(cache_type):
        """Load data from cache file"""
        try:
            cache_file = os.path.join(os.path.dirname(__file__), '..', '..', 'cache', f'{cache_type}_cache.json')
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading {cache_type} cache: {e}")
        return None
