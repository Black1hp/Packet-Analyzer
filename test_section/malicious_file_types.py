"""
This module defines file types commonly associated with malware that should be monitored
when scanning network traffic.
"""

# List of file extensions commonly associated with malware
MALICIOUS_EXTENSIONS = {
    # Executable files
    '.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.pif', '.msi', '.ps1', '.vbs', '.vbe',
    
    # Script files
    '.js', '.jse', '.wsf', '.wsh', '.hta', '.jar', '.py', '.pyc', '.pyw',
    
    # Document files that may contain macros or exploits
    '.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx', '.ppt', '.pptm', '.pptx', '.rtf', '.pdf',
    
    # Archive files that may contain malware
    '.zip', '.rar', '.7z', '.tar', '.gz', '.cab', '.iso',
    
    # Other potentially dangerous file types
    '.reg', '.inf', '.cpl', '.sys', '.bin', '.sh', '.pl', '.php'
}

# File types to explicitly ignore (safe types)
SAFE_EXTENSIONS = {
    # Web content
    '.html', '.htm', '.css', '.svg',
    
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.ico', '.tiff',
    
    # Media
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv', '.flac', '.ogg', '.webm',
    
    # Text and data
    '.txt', '.csv', '.json', '.xml',
    
    # Other common safe types
    '.ttf', '.otf', '.woff', '.woff2'
}

def is_potentially_malicious(filename):
    """
    Check if a file might be potentially malicious based on its extension.
    
    Args:
        filename (str): The filename to check
        
    Returns:
        bool: True if the file extension is in the list of potentially malicious extensions
    """
    if not filename:
        return False
        
    # Convert to lowercase for case-insensitive comparison
    filename = filename.lower()
    
    # Extract extension (handle cases with no extension)
    extension = ''
    if '.' in filename:
        extension = '.' + filename.split('.')[-1]
    
    return extension in MALICIOUS_EXTENSIONS
