#!/usr/bin/env python3
"""
Test direct ISTG checklist parsing
"""

import requests
import re

def test_istg_checklist_parsing():
    """Test parsing of ISTG checklist directly"""
    
    url = "https://raw.githubusercontent.com/OWASP/owasp-istg/main/checklists/checklist.md"
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            content = response.text
            
            print("Raw ISTG checklist content sample:")
            print("=" * 50)
            print(content[:1000])
            print("..." if len(content) > 1000 else "")
            print("\n" + "=" * 50 + "\n")
            
            # Look for table rows with test IDs and names
            # Format: |ISTG-XXX-XXX-001|Test Name|Status|Notes|
            table_pattern = r'\|([^|]+)\|([^|]+)\|[^|]*\|[^|]*\|'
            matches = re.findall(table_pattern, content)
            
            print(f"Found {len(matches)} table entries")
            print("\nFirst 20 entries:")
            print("-" * 40)
            
            valid_tests = []
            for i, match in enumerate(matches[:20]):
                test_id = match[0].strip()
                test_name = match[1].strip()
                
                print(f"{i+1:2d}. ID: '{test_id}' | Name: '{test_name}'")
                
                # Check if this is a valid test case
                if (test_id.startswith('ISTG-') and 
                    not test_id.startswith('Test ID') and 
                    not test_id.startswith('-') and 
                    not test_name.startswith('**') and
                    len(test_name) > 5):
                    valid_tests.append((test_id, test_name))
            
            print(f"\nValid test cases found: {len(valid_tests)}")
            print("-" * 30)
            
            for i, (test_id, test_name) in enumerate(valid_tests[:15]):
                print(f"{i+1:2d}. {test_id} - {test_name}")
            
            # Parse sections
            print(f"\nParsing sections...")
            print("-" * 20)
            
            sections = re.split(r'\n## (.+)', content)
            print(f"Found {len(sections)} sections")
            
            for i in range(min(len(sections), 10)):
                if i % 2 == 1:  # Section headers
                    print(f"Section: {sections[i].strip()}")
                    
                    # Look at content in this section
                    if i + 1 < len(sections):
                        section_content = sections[i + 1]
                        section_tests = re.findall(table_pattern, section_content)
                        section_valid = [
                            (t[0].strip(), t[1].strip()) for t in section_tests 
                            if t[0].strip().startswith('ISTG-') and len(t[1].strip()) > 5
                        ]
                        print(f"  - {len(section_valid)} test cases")
        
        else:
            print(f"Failed to fetch checklist: {response.status_code}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_istg_checklist_parsing()
