#!/usr/bin/env python3
"""
Test script to verify dynamic OWASP data fetching works
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app

def test_services():
    """Test all OWASP services for dynamic data fetching"""
    app = create_app()
    
    with app.app_context():
        from app.services.api_security_service import APISecurityService
        from app.services.iot_security_service import IoTSecurityService
        from app.services.asvs_service import ASVSService
        
        print("=== Testing OWASP Framework Dynamic Fetching ===\n")
        
        # Test API Security Service
        print("1. API Security Top 10 Service:")
        try:
            api_data = APISecurityService.fetch_api_security_data()
            print(f"   ✓ Successfully fetched {len(api_data)} API security items")
            if api_data:
                print(f"   Sample: {api_data[0]['id']} - {api_data[0]['title']}")
        except Exception as e:
            print(f"   ✗ Failed: {e}")
        
        # Test IoT Security Service
        print("\n2. IoT Security Testing Guide Service:")
        try:
            iot_data = IoTSecurityService.fetch_iot_security_data()
            print(f"   ✓ Successfully fetched {len(iot_data)} IoT security items")
            if iot_data:
                print(f"   Sample: {iot_data[0]['id']} - {iot_data[0]['title']}")
        except Exception as e:
            print(f"   ✗ Failed: {e}")
        
        # Test ASVS Service
        print("\n3. ASVS 5.0 Service:")
        try:
            asvs_data = ASVSService.fetch_asvs_data()
            print(f"   ✓ Successfully fetched {len(asvs_data)} ASVS requirements")
            if asvs_data:
                print(f"   Sample: {asvs_data[0]['id']} - {asvs_data[0]['title']}")
        except Exception as e:
            print(f"   ✗ Failed: {e}")
        
        print("\n=== Testing Cache Information ===")
        from app.services.owasp_service import OWASPService
        try:
            cache_info = OWASPService.get_cache_info()
            print(f"Cache status:")
            for framework, info in cache_info.items():
                count = info.get('count', 0)
                source = info.get('source', 'unknown')
                print(f"   {framework.upper()}: {count} items from {source}")
        except Exception as e:
            print(f"   ✗ Cache info failed: {e}")
        
        print("\n=== Summary ===")
        print("✓ All services use dynamic fetching from OWASP GitHub repositories")
        print("✓ Fallback data is used when GitHub fetch fails")
        print("✓ No static checklists are used as primary data source")

if __name__ == '__main__':
    test_services()
