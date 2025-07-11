# Contributing to AutoWASPy

We love contributions! AutoWASPy is an open-source penetration testing tool, and we welcome contributions from the cybersecurity community.

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- Basic knowledge of Flask and web security testing

### Development Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/yourusername/AutoWASPy.git
   cd AutoWASPy
   ```

2. **Set up development environment**
   ```bash
   # Create virtual environment
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Install development dependencies (if available)
   pip install -r requirements-dev.txt
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 💡 Ways to Contribute

### 🔧 Code Contributions
- **New Security Tests**: Add automated security tests following OWASP guidelines
- **Bug Fixes**: Fix reported issues or improve existing functionality
- **Performance Improvements**: Optimize database queries, HTTP requests, or UI responsiveness
- **UI/UX Enhancements**: Improve the user interface with better Tailwind CSS styling

### 📝 Documentation
- **README Improvements**: Enhance installation guides, usage examples
- **Code Comments**: Add clear docstrings and inline comments
- **Wiki Content**: Create guides for specific testing scenarios
- **Security Best Practices**: Document security considerations for deployment

### 🧪 Testing
- **Unit Tests**: Add tests for new automated security tests
- **Integration Tests**: Test OWASP data fetching and caching
- **Security Testing**: Help test the application's own security
- **Bug Reports**: Report issues with detailed reproduction steps

## 🛡️ Adding New Security Tests

Adding new automated security tests is one of the most valuable contributions. Here's how:

### 1. Create the Test Method
```python
@staticmethod
def test_your_security_check(url):
    """Test description following OWASP guidelines"""
    try:
        # Your security test implementation
        headers = {
            'User-Agent': 'AutoWASPy Security Scanner',
            'Accept': 'text/html,application/xhtml+xml'
        }
        
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Analysis logic here
        evidence = "Your analysis and recommendations"
        
        full_request = AutoTestService._format_request_details('GET', url, headers)
        full_response = AutoTestService._format_response_details(response, highlight_headers)
        
        return {
            'result': 'pass|fail|informational|error',
            'evidence': evidence,
            'request': full_request,
            'response': full_response
        }
        
    except Exception as e:
        return {
            'result': 'error',
            'evidence': f'❌ Error in test: {str(e)}',
            'request': f'Test request for {url}',
            'response': 'Request failed - connection error'
        }
```

### 2. Add to Auto-Test Route
Update the `auto_tests` list in the `run_auto_tests` route:
```python
auto_tests = [
    # ... existing tests ...
    ('Your New Test', AutoTestService.test_your_security_check),
]
```

### 3. Test Guidelines
- **OWASP Aligned**: Follow OWASP WSTG/MSTG methodology
- **Conservative Detection**: Prefer false negatives over false positives
- **Detailed Evidence**: Provide clear explanations and recommendations
- **Safe Testing**: Never modify target data or cause disruption
- **Error Handling**: Gracefully handle network failures and edge cases

## 📋 Contribution Process

### 1. Issue First (for major changes)
For significant features or changes:
1. Open an issue describing your proposed contribution
2. Discuss the approach with maintainers
3. Get approval before starting work

### 2. Code Standards
- **Python Style**: Follow PEP 8 guidelines
- **Flask Best Practices**: Use proper route organization and error handling
- **Security Focus**: Always consider security implications
- **Documentation**: Include docstrings and comments for complex logic

### 3. Testing Your Changes
```bash
# Test the application manually
python3 app.py

# Run automated test verification
python3 test_automated_security_tests.py

# Test specific security functions
python3 -c "from app import AutoTestService; print(AutoTestService.test_your_new_test('https://httpbin.org'))"
```

### 4. Commit Guidelines
- **Clear Messages**: Use descriptive commit messages
- **Atomic Commits**: One logical change per commit
- **Reference Issues**: Include issue numbers when applicable

```bash
git commit -m "Add SQL injection detection test (fixes #123)"
```

### 5. Pull Request Process
1. **Update Documentation**: Ensure README and comments are updated
2. **Test Thoroughly**: Verify all existing functionality still works
3. **Detailed Description**: Explain what your changes do and why
4. **Screenshots**: Include UI changes screenshots if applicable

## 🐛 Bug Reports

When reporting bugs, please include:

### Essential Information
- **AutoWASPy Version**: Include git commit hash if using development version
- **Python Version**: Output of `python3 --version`
- **Operating System**: OS and version
- **Target URL**: Example URL that demonstrates the issue (if safe to share)

### Reproduction Steps
1. Clear step-by-step instructions to reproduce the bug
2. Expected behavior vs. actual behavior
3. Error messages or logs (if any)
4. Screenshots (if UI-related)

### Example Bug Report
```markdown
**Bug**: HSTS test fails with SSL verification error

**Environment**:
- AutoWASPy: commit abc123
- Python: 3.9.7
- OS: Ubuntu 22.04

**Steps to Reproduce**:
1. Create new project with URL: https://self-signed.example.com
2. Run automated tests
3. HSTS test fails with SSL verification error

**Expected**: Test should handle self-signed certificates gracefully
**Actual**: Test crashes with SSLError exception

**Error Message**:
```
SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
```
```

## 💬 Getting Help

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Security Issues**: Email security vulnerabilities privately to rclifford at cybershade dot org.

## 📄 License

By contributing to AutoWASPy, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

All contributors will be recognized in:
- README.md contributors section
- Release notes for significant contributions
- GitHub contributors list

Thank you for helping make AutoWASPy better! 🚀
