# AutoWASPy 🛡️

**Professional Penetration Testing Tool for UK CHECK Team Leaders**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![OWASP](https://img.shields.io/badge/OWASP-WSTG%20%26%20MSTG-red.svg)](https://owasp.org)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

AutoWASPy is a comprehensive Flask web application designed specifically for UK CHECK Team Leaders to manage penetration testing projects using OWASP WSTG (Web Security Testing Guide) and MSTG (Mobile Security Testing Guide) methodologies.

## 🚀 Key Features

### 📋 Project Management
- **Client Tracking**: Organize penetration tests by client and project
- **OWASP Integration**: Automatic WSTG/MSTG checklist generation
- **Progress Tracking**: Monitor test completion status across projects
- **Evidence Management**: Centralized evidence collection and storage

### 🔧 Automated Security Testing
- **20 Comprehensive Tests**: Automated security vulnerability detection
- **Real-time Analysis**: Live security assessment with detailed reporting
- **Professional Evidence**: Detailed request/response logging for reports
- **Multi-URL Support**: Test multiple endpoints simultaneously

### 🎯 OWASP Methodology Compliance
- **WSTG Integration**: Complete Web Security Testing Guide checklist
- **MSTG Support**: Mobile Security Testing Guide for iOS/Android
- **Fallback Systems**: Robust data fetching with GitHub API fallbacks
- **Dynamic Updates**: Refresh OWASP data from official repositories

## 📊 Automated Security Tests

AutoWASPy includes 20 automated security tests covering:

### Core Security Assessment (15 tests)
- **Transport Security**: HSTS, SSL/TLS configuration
- **Authentication & Session**: Cookie security, session management
- **Input Validation**: Basic injection vulnerability testing
- **Information Disclosure**: Server information leakage detection
- **Access Control**: Directory listing, clickjacking protection
- **HTTP Security**: Security headers, CORS, content type validation

### Reconnaissance & Discovery (5 tests)
- **robots.txt Analysis**: Sensitive path disclosure detection
- **Web Server Detection**: Technology stack identification
- **Admin Panel Discovery**: Common administrative interface detection
- **Backup File Scanning**: Exposed backup and temporary file detection
- **Version Control Exposure**: Git, SVN, and other VCS directory detection

## 🛠️ Technology Stack

- **Backend**: Python Flask with SQLAlchemy ORM
- **Frontend**: HTML templates with Tailwind CSS
- **Database**: SQLite (production-ready, portable)
- **Security**: Automated HTTP security testing
- **APIs**: GitHub API integration for OWASP data

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Git

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/AutoWASPy.git
cd AutoWASPy

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python3 app.py
```

### Dependencies
```txt
Flask==2.3.3
Flask-SQLAlchemy==3.0.5
requests==2.31.0
urllib3==2.0.7
```

## 🚀 Usage

### Starting the Application
```bash
python3 app.py
```
Access the application at `http://localhost:5001`

### Basic Workflow

1. **Create Project**: Set up a new penetration testing project
2. **Configure URLs**: Add target URLs for automated testing
3. **Run Auto Tests**: Execute comprehensive security analysis
4. **Review Results**: Analyze detailed evidence and recommendations
5. **Manual Testing**: Use OWASP checklists for comprehensive assessment
6. **Evidence Collection**: Document findings with built-in evidence management

### Example: Running Automated Tests

```python
# The application provides a web interface, but tests can also be run programmatically
from app import AutoTestService

# Run individual security tests
hsts_result = AutoTestService.test_hsts('https://example.com')
headers_result = AutoTestService.test_security_headers('https://example.com')
```

## 📋 OWASP Integration

AutoWASPy automatically fetches and integrates the latest OWASP testing guidelines:

### Web Application Testing (WSTG)
- **109+ Test Cases**: Complete WSTG checklist coverage
- **Category Organization**: Tests organized by OWASP categories
- **Dynamic Updates**: Fetch latest tests from OWASP repository

### Mobile Application Testing (MSTG)
- **Comprehensive Coverage**: iOS and Android security testing
- **Platform-Specific**: Tailored tests for mobile platforms
- **Industry Standards**: Aligned with OWASP mobile security guidelines

## 🔧 Configuration

### Environment Variables
```bash
# Optional: Set custom port
export PORT=5001

# Optional: Database configuration
export DATABASE_URL=sqlite:///autowaspy.db
```

### Security Considerations
- Run on internal networks only
- Use HTTPS in production environments
- Implement proper authentication for multi-user deployments
- Regular OWASP data updates recommended

## 📈 Sample Test Results

```
📊 Automated Test Results for https://example.com:
✅ 12 Tests Passed
❌ 6 Tests Failed  
ℹ️ 2 Informational
💥 0 Errors

Key Findings:
- Missing HSTS header
- Insecure cookie configuration
- Server version disclosure
- No admin panels discovered
- SSL/TLS properly configured
```

## 🛡️ Security Features

### Test Safety
- **Read-Only Testing**: No data modification during automated tests
- **Rate Limiting**: Respectful testing to avoid service disruption
- **SSL Verification**: Proper certificate validation (with warnings for self-signed)
- **Error Handling**: Graceful failure handling for robust operation

### Professional Evidence Collection
- **Request/Response Logging**: Complete HTTP transaction details
- **Categorized Results**: Pass/Fail/Informational/Error classification
- **Detailed Analysis**: Comprehensive explanations and recommendations
- **Export Ready**: Evidence formatted for professional reports

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python3 -m pytest tests/

# Run linting
flake8 app.py
```

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [OWASP WSTG](https://github.com/OWASP/wstg) - Web Security Testing Guide
- [OWASP MSTG](https://github.com/OWASP/owasp-mstg) - Mobile Security Testing Guide
- [OWASP Top 10](https://owasp.org/Top10/) - Most Critical Web Application Security Risks

## 📞 Support

- 📧 Email: [Your Contact Email]
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/AutoWASPy/issues)
- 📖 Wiki: [Project Wiki](https://github.com/yourusername/AutoWASPy/wiki)

## 🎯 Roadmap

### Upcoming Features
- [ ] **API Security Testing**
- [ ] **Docker Containerization**
- [ ] **Multi-user Authentication**
- [ ] **PDF Report Generation**
- [ ] **CI/CD Integration**

### Version History
- **v2.0** - 20 Automated Security Tests, Enhanced OWASP Integration
- **v1.5** - OWASP MSTG Support, Evidence Management
- **v1.0** - Initial Release, Basic WSTG Integration

---

**Made with ❤️ for the cybersecurity community**

*AutoWASPy - Empowering penetration testers with automated security analysis and OWASP methodology integration.*
- **WSTG (Web Security Testing Guide)**: Complete checklist for web application security testing
- **MSTG (Mobile Security Testing Guide)**: Comprehensive mobile application security testing for iOS and Android
- Categorized test items with detailed descriptions
- Evidence collection for each test case

### Automated Testing
- **HTTP Security Headers**: Automatically test for HSTS, security headers, and cookie attributes
- **SSL/TLS Configuration**: Validate encryption and certificate settings
- **Request/Response Analysis**: Capture and analyze HTTP traffic
- **Evidence Auto-Population**: Automated test results populate evidence fields

### Evidence Management
- Rich text evidence collection
- Request/response capture and highlighting
- Risk level assignment (Low, Medium, High, Critical)
- Test status tracking (Pass, Fail, Informational)
- Screenshot and artifact storage

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

1. **Clone or download the project**
   ```bash
   cd AutoWASPy
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the application**
   Open your browser and navigate to `http://localhost:5000`

## 📱 Usage Guide

### Creating a New Project

1. Click "New Project" from the dashboard
2. Enter project details:
   - **Project Name**: Descriptive name for your test
   - **Client Name**: Organization being tested
   - **Testing Type**: 
     - Web Application (OWASP WSTG)
     - Mobile iOS (OWASP MSTG)
     - Mobile Android (OWASP MSTG)
3. For web applications, add target URLs for automated testing
4. Click "Create Project"

### Managing Test Cases

Each project includes relevant OWASP test cases:

- **View by Category**: Tests are organized by OWASP categories
- **Evidence Collection**: Add detailed evidence for each test
- **Status Tracking**: Mark tests as Pass/Fail/Informational
- **Risk Assessment**: Assign risk levels to findings
- **Progress Tracking**: Visual progress indicators

### Automated Testing (Web Applications)

For web application projects:

1. Configure target URLs during project creation
2. Click "Run Auto Tests" from the project page
3. Automated tests include:
   - HSTS header validation
   - Cookie security attributes
   - Security header analysis
   - SSL/TLS configuration checks

Results are automatically populated into relevant OWASP test cases.

### Updating OWASP Checklists

Keep your test cases current with the latest OWASP guidelines:

1. **Access Refresh Function**
   - Click "Refresh OWASP" in the main navigation
   - View current cache status and data sources

2. **Refresh Process**
   - Fetches latest WSTG tests from official OWASP GitHub repository
   - Retrieves current MSTG requirements from official sources
   - Automatically adds new test cases to existing projects
   - Preserves existing evidence and test results

3. **Smart Caching**
   - 24-hour cache prevents excessive API calls
   - Shows data source (GitHub vs Fallback)
   - Displays last update timestamp
   - Fallback data ensures continuity when GitHub is unavailable

## 🔧 Technical Architecture

### Backend
- **Flask**: Web framework
- **SQLAlchemy**: Database ORM
- **SQLite**: Local database storage
- **Requests**: HTTP client for automated testing

### Frontend
- **Tailwind CSS**: Modern styling framework
- **Responsive Design**: Mobile-friendly interface
- **JavaScript**: Interactive features and auto-save

### Database Schema
- **Projects**: Client and project information
- **TestItems**: OWASP test cases with evidence
- **AutoTestResults**: Automated testing results

## 🔍 Automated Test Capabilities

### Current Tests
- **HSTS (HTTP Strict Transport Security)**: Validates presence and configuration
- **Cookie Security**: Checks HttpOnly, Secure, and SameSite attributes
- **Security Headers**: Validates X-Frame-Options, CSP, X-XSS-Protection, etc.

### Planned Enhancements
- SQL injection detection
- XSS vulnerability scanning
- Directory traversal testing
- Authentication bypass checks
- Session management analysis

## 📊 OWASP Test Coverage

### WSTG Categories
- Information Gathering
- Configuration and Deployment Management
- Identity Management
- Authentication Testing
- Session Management
- Input Validation
- Error Handling
- Cryptography

### MSTG Categories
- Architecture, Design and Threat Modeling
- Data Storage and Privacy
- Cryptography
- Authentication and Session Management
- Network Communication
- Platform Interaction
- Code Quality and Build Settings
- Resilience Against Reverse Engineering

## 🛠️ Development

### Project Structure
```
AutoWASPy/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Project dashboard
│   ├── new_project.html  # Project creation
│   ├── project_detail.html # Test case management
│   └── autotest_results.html # Automated test results
├── .github/
│   └── copilot-instructions.md # Development guidelines
└── README.md             # This file
```

### Adding New Automated Tests

1. Extend the `AutoTestService` class in `app.py`
2. Add new test methods following the existing pattern
3. Update the `run_auto_tests` route to include new tests
4. Map results to appropriate OWASP test cases

### Database Migrations

The application automatically creates the database on first run. For schema changes:

1. Update model definitions in `app.py`
2. Delete `autowaspy.db` to recreate (development only)
3. Implement proper migrations for production use

## 🔒 Security Considerations

- **SSL Verification**: Configurable for testing environments
- **Input Validation**: All user inputs are validated and sanitized
- **SQL Injection Protection**: SQLAlchemy ORM prevents SQL injection
- **XSS Protection**: Template escaping enabled by default

## 📝 License

This tool is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any systems.

## 🤝 Contributing

This tool is designed for CHECK Team Leaders. Contributions should focus on:
- Additional OWASP test case coverage
- Enhanced automated testing capabilities
- Better evidence management features
- Export/reporting functionality


---

**Disclaimer**: This tool is intended for authorized security testing only. Always ensure you have explicit permission before testing any systems or applications.
