"""
Route blueprints for AutoWASPy application
"""
from .main import bp as main_bp
from .projects import bp as projects_bp
from .testing import bp as testing_bp
from .exports import bp as exports_bp
from .admin import bp as admin_bp

__all__ = ['main_bp', 'projects_bp', 'testing_bp', 'exports_bp', 'admin_bp']
