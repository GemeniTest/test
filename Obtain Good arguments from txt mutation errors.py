import os
import re
import json
import requests
from pathlib import Path
from datetime import datetime

# Configuration
GRAPHQL_ENDPOINT = "https://graph.linktr.ee/graphql"
HEADERS = {
    "Content-Type": "application/json",
}
INPUT_FOLDER = "Mutation"
OUTPUT_FOLDER = "Mutation_Fixed"

def extract_mutation_name(file_path):
    """Extract the mutation name from the GQL file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    mutation_name_match = re.search(r'MUTATION:\s*(\w+)', content)
    if mutation_name_match:
        return mutation_name_match.group(1)
    return None

def test_mutation(mutation, variables=None):
    """Send GraphQL mutation to endpoint and return response."""
    payload = {
        "query": mutation,
        "variables": variables or {}
    }
    
    try:
        response = requests.post(GRAPHQL_ENDPOINT, json=payload, headers=HEADERS, timeout=10)
        return response.json()
    except Exception as e:
        return {"errors": [{"message": f"Request failed: {str(e)}"}]}

def extract_required_argument(error_message):
    """Extract required argument from error message."""
    pattern = r'argument "(\w+)" of type "([^"]+)" is required'
    match = re.search(pattern, error_message)
    
    if match:
        return {
            'name': match.group(1),
            'type': match.group(2),
            'required': '!' in match.group(2)
        }
    return None

def extract_type_mismatch(error_message):
    """Extract type mismatch to fix the argument type."""
    pattern = r'Variable "\$(\w+)" of type "([^"]+)" used in position expecting type "([^"]+)"'
    match = re.search(pattern, error_message)
    
    if match:
        return {
            'name': match.group(1),
            'type': match.group(3),
            'required': '!' in match.group(3)
        }
    return None

def extract_nested_field_requirement(error_message):
    """Extract nested field requirements from complex input types."""
    pattern = r'Field "(\w+)" of required type "([^"]+)" was not provided'
    match = re.search(pattern, error_message)
    
    if match:
        return {
            'name': match.group(1),
            'type': match.group(2)
        }
    return None

def get_placeholder_value(arg_type, nested_fields=None):
    """Generate placeholder values for different argument types."""
    base_type = arg_type.replace('!', '').strip()
    
    if base_type.startswith('['):
        return []
    elif 'String' in base_type or 'ID' in base_type:
        return "test_value"
    elif 'Int' in base_type:
        return 1
    elif 'Float' in base_type:
        return 1.0
    elif 'Boolean' in base_type:
        return True
    else:
        # For complex types, build object from nested fields
        if nested_fields:
            obj = {}
            for field in nested_fields:
                obj[field['name']] = get_placeholder_value(field['type'])
            return obj
        return {}

def build_simple_mutation(mutation_name, is_scalar=False):
    """Build a simple mutation with no arguments."""
    if is_scalar:
        return f"mutation {{ {mutation_name} }}"
    else:
        return f"mutation {{ {mutation_name} {{ __typename }} }}"

def build_mutation_with_args(mutation_name, arguments, is_scalar=False):
    """Build a mutation with the discovered arguments."""
    arg_definitions = ", ".join([f"${arg['name']}: {arg['type']}" for arg in arguments])
    arg_usage = ", ".join([f"{arg['name']}: ${arg['name']}" for arg in arguments])
    
    if is_scalar:
        return f"mutation({arg_definitions}) {{ {mutation_name}({arg_usage}) }}"
    else:
        return f"mutation({arg_definitions}) {{ {mutation_name}({arg_usage}) {{ __typename }} }}"

def is_valid_response(response):
    """Check if response indicates a valid mutation."""
    if "data" in response and response["data"] is not None:
        return True, "VALID_DATA"
    
    if "errors" in response:
        error_codes = [err.get("extensions", {}).get("code", "") for err in response["errors"]]
        error_messages = [err.get("message", "") for err in response["errors"]]
        
        if any("UNAUTHENTICATED" in code for code in error_codes):
            return True, "VALID_AUTH_REQUIRED"
        
        if any(word in msg.lower() for msg in error_messages for word in ["forbidden", "unauthorized"]):
            return True, "VALID_FORBIDDEN"
    
    return False, None

def format_mutation_as_json(mutation_name, arguments, is_scalar=False):
    """Format the mutation as a JSON payload with variables."""
    if arguments:
        # Build the GraphQL mutation string with proper formatting
        arg_definitions = ", ".join([f"${arg['name']}: {arg['type']}" for arg in arguments])
        arg_usage = ", ".join([f"{arg['name']}: ${arg['name']}" for arg in arguments])
        
        if is_scalar:
            mutation_str = f"mutation {mutation_name}({arg_definitions}) {{\n    {mutation_name}({arg_usage})\n}}"
        else:
            mutation_str = f"mutation {mutation_name}({arg_definitions}) {{\n    {mutation_name}({arg_usage}) {{\n        __typename\n    }}\n}}"
        
        # Build variables object with nested fields
        variables = {}
        for arg in arguments:
            if 'nested_fields' in arg and arg['nested_fields']:
                # Build nested object
                nested_obj = {}
                for field in arg['nested_fields']:
                    field_value = get_placeholder_value(field['type'])
                    nested_obj[field['name']] = field_value
                variables[arg['name']] = nested_obj
            else:
                variables[arg['name']] = get_placeholder_value(arg['type'])
    else:
        # No arguments
        if is_scalar:
            mutation_str = f"mutation {mutation_name} {{\n    {mutation_name}\n}}"
        else:
            mutation_str = f"mutation {mutation_name} {{\n    {mutation_name} {{\n        __typename\n    }}\n}}"
        variables = {}
    
    payload = {
        "query": mutation_str,
        "variables": variables
    }
    
    return json.dumps(payload, separators=(',', ':'))

def discover_mutation_signature(mutation_name, verbose=False):
    """Discover the full signature of a mutation by testing it."""
    max_iterations = 20
    
    # Track nested fields for complex input types
    nested_fields = {}
    
    # Try both the original name and lowercase first letter
    mutation_names_to_try = [mutation_name]
    if mutation_name[0].isupper():
        lowercase_first = mutation_name[0].lower() + mutation_name[1:]
        mutation_names_to_try.append(lowercase_first)
    
    for attempt_name in mutation_names_to_try:
        if verbose:
            print(f"    Trying: {attempt_name}")
        
        arguments = []
        nested_fields = {}
        is_scalar = False
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            
            # Build mutation
            if arguments:
                mutation = build_mutation_with_args(attempt_name, arguments, is_scalar)
                variables = {}
                for arg in arguments:
                    if arg['name'] in nested_fields and nested_fields[arg['name']]:
                        variables[arg['name']] = get_placeholder_value(arg['type'], nested_fields[arg['name']])
                    else:
                        variables[arg['name']] = get_placeholder_value(arg['type'])
            else:
                mutation = build_simple_mutation(attempt_name, is_scalar)
                variables = {}
            
            # Test mutation
            response = test_mutation(mutation, variables)
            
            if verbose and "errors" in response:
                errors = [err.get("message", "") for err in response["errors"]]
                for err in errors[:3]:
                    print(f"    Error: {err[:150]}")
            
            # Check if valid
            valid, status = is_valid_response(response)
            if valid:
                for arg in arguments:
                    if arg['name'] in nested_fields and nested_fields[arg['name']]:
                        arg['nested_fields'] = nested_fields[arg['name']]
                return attempt_name, arguments, status, is_scalar
            
            # Parse errors
            if "errors" not in response:
                if verbose:
                    print(f"    No errors in response")
                break
            
            error_messages = [err.get("message", "") for err in response["errors"]]
            
            # Check for invalid field
            if any("Cannot query field" in msg for msg in error_messages):
                if verbose:
                    print(f"    Invalid field, trying next name variation...")
                break
            
            # Check if it's a scalar field
            if any("must not have a selection" in msg for msg in error_messages):
                is_scalar = True
                if verbose:
                    print(f"    Detected scalar field")
                continue
            
            # Check for required arguments and nested fields
            found_new_arg = False
            
            for msg in error_messages:
                # Try to find required top-level argument
                new_arg = extract_required_argument(msg)
                if new_arg and not any(arg['name'] == new_arg['name'] for arg in arguments):
                    arguments.append(new_arg)
                    found_new_arg = True
                    if verbose:
                        print(f"    Added argument: {new_arg['name']} ({new_arg['type']})")
                    break
                
                # Try to fix type mismatch
                type_fix = extract_type_mismatch(msg)
                if type_fix:
                    for arg in arguments:
                        if arg['name'] == type_fix['name']:
                            arg['type'] = type_fix['type']
                            arg['required'] = type_fix['required']
                            found_new_arg = True
                            if verbose:
                                print(f"    Fixed type for {arg['name']}: {type_fix['type']}")
                            break
                    if found_new_arg:
                        break
            
            # If no top-level arg found, check for nested fields
            if not found_new_arg:
                for msg in error_messages:
                    nested_req = extract_nested_field_requirement(msg)
                    if nested_req:
                        # Find which argument this field belongs to
                        for arg in reversed(arguments):
                            base_type = arg['type'].replace('!', '').strip()
                            if base_type not in ['String', 'Int', 'Float', 'Boolean', 'ID'] and not base_type.startswith('['):
                                if arg['name'] not in nested_fields:
                                    nested_fields[arg['name']] = []
                                if not any(f['name'] == nested_req['name'] for f in nested_fields[arg['name']]):
                                    nested_fields[arg['name']].append(nested_req)
                                    found_new_arg = True
                                    if verbose:
                                        print(f"    Added nested field to {arg['name']}: {nested_req['name']} ({nested_req['type']})")
                                    break
                        if found_new_arg:
                            break
            
            if not found_new_arg:
                if verbose:
                    print(f"    No new arguments or fields found")
                for arg in arguments:
                    if arg['name'] in nested_fields and nested_fields[arg['name']]:
                        arg['nested_fields'] = nested_fields[arg['name']]
                return attempt_name, arguments, "ERROR", is_scalar
        
    return mutation_name, arguments, "INVALID_FIELD", False

def save_result(file_name, mutation_name, arguments, status, output_path, is_scalar=False):
    """Save the result in the original format."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if status.startswith("VALID"):
        description = "Valid mutation - Authentication or permissions may be required."
    elif status == "INVALID_FIELD":
        description = "Mutation field does not exist in schema."
    else:
        description = "No description available."
    
    content = f"""================================================================================
MUTATION: {mutation_name}
================================================================================
Generated at: {timestamp}
Description: {description}
ARGUMENTS:
----------------------------------------
"""
    
    if arguments:
        for arg in arguments:
            req_status = "required" if arg.get('required', False) else "optional"
            content += f"• {arg['name']} ({arg['type']}) - {req_status}\n"
            
            if 'nested_fields' in arg and arg['nested_fields']:
                for field in arg['nested_fields']:
                    content += f"  - {field['name']} ({field['type']})\n"
    else:
        content += "No arguments required.\n"
    
    content += "RETURN TYPE:\n"
    content += "----------------------------------------\n"
    content += "See return fields\n"
    
    # Add formatted JSON mutation
    if status.startswith("VALID") or (status == "ERROR" and arguments):
        content += "\nFORMATTED MUTATION:\n"
        content += "----------------------------------------\n"
        content += format_mutation_as_json(mutation_name, arguments, is_scalar) + "\n"
    
    output_file = output_path / file_name
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    script_dir = Path(__file__).parent
    
    input_path = script_dir / INPUT_FOLDER
    output_path = script_dir / OUTPUT_FOLDER
    
    os.makedirs(output_path, exist_ok=True)
    
    if not input_path.exists():
        print(f"Error: Folder '{INPUT_FOLDER}' not found in {script_dir}!")
        print(f"Looking for: {input_path}")
        return
    
    mutation_files = list(input_path.glob("*.txt"))
    
    if not mutation_files:
        print(f"No .txt files found in '{input_path}'")
        return
    
    print(f"Found {len(mutation_files)} mutation files to test\n")
    print("=" * 80)
    
    results = {
        'valid': 0,
        'invalid_field': 0,
        'error': 0
    }
    
    verbose = True
    
    for idx, file_path in enumerate(mutation_files, 1):
        print(f"\n[{idx}/{len(mutation_files)}] Testing: {file_path.name}")
        
        mutation_name = extract_mutation_name(file_path)
        
        if not mutation_name:
            print(f"  ⚠️  Could not extract mutation name")
            results['error'] += 1
            continue
        
        print(f"  Mutation: {mutation_name}")
        
        actual_name, arguments, status, is_scalar = discover_mutation_signature(mutation_name, verbose=verbose)
        
        if status.startswith("VALID"):
            print(f"  ✅ Valid - {len(arguments)} argument(s)")
            if actual_name != mutation_name:
                print(f"  🔄 Corrected name: {actual_name}")
            results['valid'] += 1
        elif status == "INVALID_FIELD":
            print(f"  ❌ Invalid field name")
            results['invalid_field'] += 1
        else:
            print(f"  ⚠️  Error - {len(arguments)} argument(s) discovered")
            results['error'] += 1
        
        save_result(file_path.name, actual_name, arguments, status, output_path, is_scalar)
        print(f"  💾 Saved to: {output_path}/{file_path.name}")
    
    print("\n" + "=" * 80)
    print("\nSUMMARY:")
    print(f"  ✅ Valid Mutations: {results['valid']}")
    print(f"  ❌ Invalid Field Names: {results['invalid_field']}")
    print(f"  ⚠️  Errors: {results['error']}")
    print(f"  📊 Total Processed: {len(mutation_files)}")
    print(f"\n💾 All results saved to: {output_path}/")

if __name__ == "__main__":
    main()
