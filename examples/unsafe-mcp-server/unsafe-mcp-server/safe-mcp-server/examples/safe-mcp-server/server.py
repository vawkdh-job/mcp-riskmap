import os

def read_file_safe(filename):
    # Define the secure base directory (where this script is located)
    base_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Get the absolute path of the requested file
    target_path = os.path.abspath(os.path.join(base_dir, filename))
    
    # Check if the target path stays within the base directory
    if not target_path.startswith(base_dir):
        return "Access denied: Attempted directory traversal!"
        
    try:
        with open(target_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"
