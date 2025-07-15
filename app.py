"""
Modular Flask app using the new structure.
This is the main entry point for the refactored AutoWASPy application.
"""
import os
from app import create_app

def create_modular_app():
    """Create and configure the modular Flask application"""
    return create_app()

# Create the app instance
app = create_modular_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(debug=True, host='0.0.0.0', port=port)
