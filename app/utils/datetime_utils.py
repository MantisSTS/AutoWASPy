"""
Datetime Utilities Module

Provides datetime utility functions for the AutoWASPy application.
"""

from datetime import datetime, timezone


def utc_now():
    """
    Get current UTC datetime.
    
    Returns:
        datetime: Current datetime in UTC timezone
    """
    return datetime.now(timezone.utc)


def format_datetime(dt, format_string="%Y-%m-%d %H:%M:%S UTC"):
    """
    Format a datetime object to string.
    
    Args:
        dt (datetime): The datetime object to format
        format_string (str): The format string to use
        
    Returns:
        str: Formatted datetime string
    """
    if dt is None:
        return "Never"
    return dt.strftime(format_string)


def parse_datetime(dt_string, format_string="%Y-%m-%d %H:%M:%S"):
    """
    Parse a datetime string to datetime object.
    
    Args:
        dt_string (str): The datetime string to parse
        format_string (str): The format string to use
        
    Returns:
        datetime: Parsed datetime object in UTC
    """
    dt = datetime.strptime(dt_string, format_string)
    return dt.replace(tzinfo=timezone.utc)
