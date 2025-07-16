import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import html
import markdown
from markupsafe import Markup
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()

def create_app():
    """Application factory pattern"""
    # Get the template folder relative to the parent directory
    template_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    app = Flask(__name__, template_folder=template_folder)
    
    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{os.path.abspath("instance/autowaspy.db")}')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions with app
    db.init_app(app)
    
    # Import and configure models after db is available
    with app.app_context():
        from app import models
        models.init_models(db)
        
        # Register custom Jinja2 filters
        register_filters(app)
        
        # Register blueprints
        register_blueprints(app)
        
        # Create database tables
        db.create_all()
    
    return app

def register_filters(app):
    """Register custom Jinja2 filters"""
    
    @app.template_filter('safe_format_description')
    def safe_format_description(description):
        """Safely format test descriptions while preventing XSS"""
        if not description:
            return ""
        
        # Escape all HTML to prevent XSS
        escaped = html.escape(description)
        
        # Replace line breaks with HTML breaks (safe since we escaped everything)
        formatted = escaped.replace('\n', '<br>')
        
        # Return as Markup object so it's treated as safe HTML
        return Markup(formatted)

    @app.template_filter('markdown')
    def markdown_filter(text):
        """Convert markdown text to HTML"""
        if not text:
            return ""
        
        # Configure markdown with safe extensions
        md = markdown.Markdown(extensions=['nl2br', 'tables', 'fenced_code'])
        html_content = md.convert(text)
        
        # Return as safe markup
        return Markup(html_content)

    @app.template_filter('safe_escape')
    def safe_escape(content):
        """Safely escape content to prevent XSS"""
        if not content:
            return ""
        return html.escape(str(content))
    
    @app.template_filter('summarize_description')
    def summarize_description(content):
        """Extract only the first block before 'What to Review' or similar sections with markdown support"""
        if not content:
            return ""
        
        # Common section headers that indicate the start of detailed instructions
        section_markers = [
            "▼ What to Test",
            "What to Test",
            "## What to Test",
            "### What to Test",
            "▼ What to test",
            "What to test",
            "## What to test",
            "### What to test",
            "▼ What to Review",
            "What to Review",
            "## What to Review",
            "### What to Review", 
            "▼ What to review",
            "What to review",
            "## What to review",
            "### What to review",
            "▼ How to Test",
            "How to Test",
            "## How to Test",
            "### How to Test",
            "▼ How to test",
            "How to test",
            "## How to test", 
            "### How to test",
            "▼ Testing Procedure",
            "Testing Procedure",
            "## Testing Procedure",
            "### Testing Procedure",
            "▼ Testing procedure",
            "Testing procedure",
            "## Testing procedure",
            "### Testing procedure",
            "▼ Test Steps",
            "Test Steps",
            "## Test Steps",
            "### Test Steps",
            "▼ Procedure",
            "Procedure",
            "## Procedure",
            "### Procedure",
            "▼ Steps",
            "Steps",
            "## Steps",
            "### Steps"
        ]
        
        # Find the first occurrence of any section marker
        first_marker_pos = len(content)  # Default to end of content
        
        for marker in section_markers:
            pos = content.find(marker)
            if pos != -1 and pos < first_marker_pos:
                first_marker_pos = pos
        
        # Extract content before the first marker
        summary = content[:first_marker_pos].strip()
        
        # Clean up any trailing symbols like ▼
        summary = summary.rstrip('▼ \t\n')
        
        # If no marker found or summary is very short, take first few sentences
        if first_marker_pos == len(content) or len(summary) < 50:
            sentences = content.split('.')
            if len(sentences) >= 2:
                summary = '. '.join(sentences[:2]) + '.'
            else:
                # Fallback: take first 200 characters
                summary = content[:200] + '...' if len(content) > 200 else content
        
        # Limit summary length for better display
        if len(summary) > 300:
            summary = summary[:297] + "..."
        
        # Convert markdown to HTML for links and basic formatting
        md = markdown.Markdown(extensions=['nl2br'])
        html_content = md.convert(summary)
        
        return Markup(html_content)

def register_blueprints(app):
    """Register all route blueprints"""
    from app.routes.main import bp as main_bp
    from app.routes.projects import bp as projects_bp
    from app.routes.testing import bp as testing_bp
    from app.routes.exports import bp as exports_bp
    from app.routes.admin import bp as admin_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(testing_bp)
    app.register_blueprint(exports_bp)
    app.register_blueprint(admin_bp)

# Helper function for timezone-aware UTC datetime
def utc_now():
    """Return current UTC time in timezone-aware format"""
    return datetime.now(timezone.utc)
