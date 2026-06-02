import re

def remove_comments(code, language):
    """
    Remove comments from Solidity or Move code using regex.
    - Solidity supports // and /* comments
    - Move supports // and /* comments
    """
    if language == 'solidity':
        # Remove single-line and multi-line comments for Solidity
        code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.DOTALL | re.MULTILINE)
    elif language == 'move':
        # Remove single-line and multi-line comments for Move
        code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.DOTALL | re.MULTILINE)
    return code

def count_total_lines(code):
    """Count the total number of lines including comments and blank lines."""
    return len(code.splitlines())

def count_loc(code):
    """Count the number of lines of code (non-empty lines)."""
    lines = [line for line in code.splitlines() if line.strip()]
    return len(lines)

def count_comments(original_code, language):
    """
    Count the number of comment lines before removing them from the code.
    """
    if language == 'solidity':
        # Find single-line and multi-line comments
        comments = re.findall(r'//.*?$|/\*.*?\*/', original_code, flags=re.DOTALL | re.MULTILINE)
    elif language == 'move':
        # Find single-line and multi-line comments
        comments = re.findall(r'//.*?$|/\*.*?\*/', original_code, flags=re.DOTALL | re.MULTILINE)
    
    # Split the comments into lines and count
    comment_lines = sum([len(comment.splitlines()) for comment in comments])
    return comment_lines

def count_function_definitions(code, language):
    """
    Count function definitions using regex based on the language.
    """
    if language == 'solidity':
        return len(re.findall(r'\bfunction\b', code))
    elif language == 'move':
        return len(re.findall(r'\bfun\b', code))

def count_complexity_indicators(code):
    """
    Count complexity indicators like conditional statements and loops.
    """
    # Count conditionals and loops using regex
    conditionals = len(re.findall(r'\bif\b|\belse\b|\bswitch\b', code))
    loops = len(re.findall(r'\bwhile\b|\bfor\b|\bloop\b', code))
    return conditionals + loops

def analyze_code(original_code, language):
    """
    Analyze the code for all metrics: Total Lines, LOC, comments, functions, dependencies, and complexity.
    """
    # Step 1: Remove comments to avoid false matches inside comments
    clean_code = remove_comments(original_code, language)

    # Step 2: Analyze the code
    analysis = {
        'Total Lines': count_total_lines(original_code),
        'LOC': count_loc(clean_code),
        'Lines of Comments': count_comments(original_code, language),
        'Function Definitions': count_function_definitions(clean_code, language),
        'Complexity Indicators': count_complexity_indicators(clean_code),
    }

    return analysis

def read_file(file_path):
    """
    Read the content of a file from the given path.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None

def compare_contracts(solidity_path, move_path):
    """
    Compare a Solidity contract with a Move contract by reading from the provided file paths.
    """
    # Read the Solidity contract
    solidity_code = read_file(solidity_path)
    if solidity_code is None:
        return
    
    # Read the Move contract
    move_code = read_file(move_path)
    if move_code is None:
        return
    
    # Analyze Solidity code
    solidity_analysis = analyze_code(solidity_code, 'solidity')
    
    # Analyze Move code
    move_analysis = analyze_code(move_code, 'move')
    
    # Print comparison
    print("Comparison of Solidity and Move Contracts:")
    print("-" * 60)
    print(f"{'Metric':<30}{'Solidity':<15}{'Move'}")
    print("-" * 60)
    for metric in solidity_analysis:
        print(f"{metric:<30}{solidity_analysis[metric]:<15}{move_analysis[metric]}")
    print("-" * 60)

# Example usage with file paths
solidity_file_path = ''
move_file_path = ''

# Compare the contracts
compare_contracts(solidity_file_path, move_file_path)