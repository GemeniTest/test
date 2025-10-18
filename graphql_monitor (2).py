import re
import os
import glob
import json
import threading
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    print("Error: 'requests' library not installed. Run: pip install requests")
    exit()

OUTPUT_DIR = 'graphql_monitor'
TS_DIR = os.path.join(OUTPUT_DIR, 'ts_files')
MAP_CACHE_DIR = os.path.join(OUTPUT_DIR, '.maps_cache')
GRAPHQL_API_DIR = os.path.join(OUTPUT_DIR, 'GraphQL_API')
GRAPHQL_NEW_DIR = os.path.join(OUTPUT_DIR, 'GraphQL_NEW')
HISTORY_FILE = os.path.join(OUTPUT_DIR, 'operations_history.json')
MAX_WORKERS = 10

class Stats:
    def __init__(self):
        self.js_total_count = 0
        self.sourcemap_found_count = 0
        self.ts_in_maps_count = 0
        self.ts_downloaded_count = 0
        self.ts_extracted_count = 0
        self.lock = threading.Lock()

    def increment_sourcemap_found(self):
        with self.lock:
            self.sourcemap_found_count += 1
    
    def add_ts_in_map(self, count):
        with self.lock:
            self.ts_in_maps_count += count

    def increment_ts_downloaded(self):
        with self.lock:
            self.ts_downloaded_count += 1
            
    def increment_ts_extracted(self):
        with self.lock:
            self.ts_extracted_count += 1

stats = Stats()
print_lock = threading.Lock()

def safe_print(message):
    with print_lock:
        print(message)

def load_config():
    config_file = 'config.json'
    if not os.path.exists(config_file):
        print(f"Error: '{config_file}' not found. Creating template...")
        template = {
            "hosts": [
                "mfe-admin-shell.production.linktr.ee",
                "assets.production.linktr.ee",
                "linktree-federation-host.production.linktr.ee"
            ],
            "cookies": "YOUR_COOKIES_HERE"
        }
        with open(config_file, 'w') as f:
            json.dump(template, f, indent=2)
        print(f"Template created. Please edit '{config_file}' with your cookies.")
        exit()
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    if config.get('cookies') == 'YOUR_COOKIES_HERE':
        print(f"Error: Please update cookies in '{config_file}'")
        exit()
    
    return config

def sanitize_filename(path):
    path = re.sub(r'^\.\.?[/\\]webpack:[/\\_]+', '', path)
    path = re.sub(r'^\.\.?[/\\]', '', path)
    path = re.sub(r'[<>:"|?*]', '_', path)
    return path.replace('/', '_').replace('\\', '_')

def download_file(url, headers):
    try:
        response = requests.get(url, timeout=20, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        reason = f" (Status: {e.response.status_code})" if e.response else f" ({type(e).__name__})"
        safe_print(f"Download failed: {url}{reason}")
        return None

def extract_ts_from_map(source_content, save_path):
    try:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(source_content)
        stats.increment_ts_extracted()
        safe_print(f"Extracted: {os.path.basename(save_path)}")
    except Exception as e:
        safe_print(f"Error writing: {save_path}: {e}")

def download_and_save_ts(ts_url, save_path, headers):
    response = download_file(ts_url, headers)
    if response:
        try:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            stats.increment_ts_downloaded()
            safe_print(f"Downloaded: {os.path.basename(save_path)}")
        except Exception as e:
            safe_print(f"Error writing: {save_path}: {e}")

def process_js_file(js_filename, executor, output_dir, map_cache_dir, headers, hosts):
    safe_print(f"Processing: {js_filename}")
    try:
        with open(js_filename, 'rb') as f:
            js_content = f.read().decode('utf-8', errors='ignore')

        match = re.search(r'//# sourceMappingURL=(.+\.map)', js_content)
        if not match:
            safe_print(f"No source map in {js_filename}")
            return

        stats.increment_sourcemap_found()
        map_filename = match.group(1).strip()
        
        map_data = None
        cached_map_path = os.path.join(map_cache_dir, sanitize_filename(map_filename))
        
        if os.path.exists(cached_map_path):
            safe_print(f"Using cached map: {os.path.basename(cached_map_path)}")
            with open(cached_map_path, 'r', encoding='utf-8') as f:
                map_data = json.load(f)
        else:
            map_downloaded = False
            for host in hosts:
                base_url = f"https://{host}/"
                map_url = urljoin(base_url, map_filename)
                safe_print(f"Trying: {map_url}")
                
                response = download_file(map_url, headers)
                if response:
                    map_data = response.json()
                    with open(cached_map_path, 'w', encoding='utf-8') as f:
                        json.dump(map_data, f)
                    safe_print(f"Map cached: {os.path.basename(cached_map_path)}")
                    map_downloaded = True
                    break
            
            if not map_downloaded:
                safe_print(f"Failed to download map from all hosts for {js_filename}")
                return

        if 'sources' not in map_data:
            return

        has_embedded_content = ('sourcesContent' in map_data and 
                                map_data['sourcesContent'] and
                                len(map_data['sourcesContent']) == len(map_data['sources']))
        
        ts_files = [s for s in map_data['sources'] if s.endswith(('.ts', '.tsx'))]
        stats.add_ts_in_map(len(ts_files))

        if has_embedded_content:
            safe_print(f"Extracting embedded TS code...")
            for i, source_path in enumerate(map_data['sources']):
                if source_path.endswith(('.ts', '.tsx')) and map_data['sourcesContent'][i]:
                    save_path = os.path.join(output_dir, sanitize_filename(source_path))
                    executor.submit(extract_ts_from_map, map_data['sourcesContent'][i], save_path)
        else:
            safe_print(f"Downloading TS files individually...")
            for source_path in ts_files:
                ts_downloaded = False
                for host in hosts:
                    base_url = f"https://{host}/"
                    ts_url = urljoin(base_url, source_path)
                    save_path = os.path.join(output_dir, sanitize_filename(source_path))
                    
                    response = download_file(ts_url, headers)
                    if response:
                        executor.submit(lambda r=response, p=save_path: save_ts_content(r.text, p))
                        ts_downloaded = True
                        break
                
                if not ts_downloaded:
                    safe_print(f"Failed to download: {source_path}")
                
    except Exception as e:
        safe_print(f"Fatal error processing {js_filename}: {e}")

def save_ts_content(content, save_path):
    try:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(content)
        stats.increment_ts_downloaded()
        safe_print(f"Downloaded: {os.path.basename(save_path)}")
    except Exception as e:
        safe_print(f"Error writing: {save_path}: {e}")

def clean_description(desc):
    if not desc:
        return "No description available.", []
    
    lines = desc.strip().split('\n')
    cleaned_lines = []
    tags = []
    
    for line in lines:
        tag_match = re.search(r'@(\w+)(?:\s+(.+?))?$', line)
        if tag_match:
            tags.append((tag_match.group(1), tag_match.group(2) or ''))
            continue
        
        cleaned_line = re.sub(r'^\s*\*\s?', '', line).strip()
        if cleaned_line and not cleaned_line.startswith('@'):
            cleaned_lines.append(cleaned_line)
    
    full_desc = ' '.join(cleaned_lines)
    return (full_desc if full_desc else "No description available."), tags

def format_argument_line(arg_name, arg_type, is_optional, description=""):
    status = "optional" if is_optional else "required"
    simple_type = re.sub(r'Scalars\[\'(.*?)\'\]\[\'(input|output)\'\]', r'\1', arg_type)
    simple_type = re.sub(r'Array<(\w+)>', r'\1[]', simple_type)
    simple_type = re.sub(r'\s*[|]\s*', ' | ', simple_type)
    
    line = f"• {arg_name} ({simple_type}) - {status}"
    if description and description != "No description available.":
        line += f"\n  {description}"
    return line

def extract_return_fields(return_type_str, content, depth=0, max_depth=2):
    fields = []
    
    if depth > max_depth:
        return []
    
    base_type = re.sub(r'Maybe<(.+?)>', r'\1', return_type_str)
    base_type = re.sub(r'Array<(.+?)>', r'\1', base_type)
    base_type = re.sub(r'[\[\]!?]', '', base_type).strip()
    
    scalars = ['String', 'Int', 'Float', 'Boolean', 'ID', 'Any', 'void', 'unknown', 'Date', 'DateTime']
    if base_type in scalars:
        return []
    
    type_pattern = re.compile(
        rf"export\s+(?:type|interface)\s+{re.escape(base_type)}\s*=\s*{{([\s\S]*?)^}};",
        re.MULTILINE | re.DOTALL
    )
    type_match = type_pattern.search(content)
    
    if type_match:
        type_content = type_match.group(1)
        field_pattern = re.compile(r'(?:/\*\*.*?\*/\s*)?(?:readonly\s+)?(\w+)(\??):\s*([\w\[\]<>|&\s]+);', re.DOTALL)
        
        for field_match in field_pattern.finditer(type_content):
            field_name = field_match.group(1)
            optional = field_match.group(2) == '?'
            field_type = field_match.group(3).strip()
            
            if field_name != '__typename':
                field_type_clean = re.sub(r'Scalars\[\'(.*?)\'\]\[\'(input|output)\'\]', r'\1', field_type)
                field_type_clean = re.sub(r'Array<(\w+)>', r'\1[]', field_type_clean)
                field_type_clean = re.sub(r'\s*[|]\s*', ' | ', field_type_clean)
                
                nested_fields = extract_return_fields(field_type, content, depth + 1, max_depth)
                
                fields.append({
                    'name': field_name,
                    'type': field_type_clean,
                    'optional': optional,
                    'nested': nested_fields,
                    'depth': depth
                })
    
    return fields

def extract_from_ts_types(content, op_type):
    operations = []
    op_block_pattern = re.compile(
        rf"export type {op_type}\s*=\s*{{([\s\S]*?)}};", re.DOTALL
    )
    op_block_match = op_block_pattern.search(content)
    if not op_block_match:
        return []

    op_block_content = op_block_match.group(1)
    op_pattern = re.compile(r"(?:/\*\*(.*?)\*/\s*)?(?:readonly\s+)?(\w+)\??\s*:\s*([\s\S]*?);", re.DOTALL)

    for match in op_pattern.finditer(op_block_content):
        description_raw, op_name, return_type_raw = match.groups()
        if op_name == '__typename':
            continue

        description, tags = clean_description(description_raw)
        
        operation_details = {
            "name": op_name,
            "description": description,
            "tags": tags,
            "return_type": return_type_raw.strip(),
            "return_fields": [],
            "arguments": [],
            "fragments": []
        }
        
        operation_details["return_fields"] = extract_return_fields(return_type_raw, content)
        
        args_type_name = f"{op_type}{op_name[0].upper() + op_name[1:]}Args"
        args_block_pattern = re.compile(rf"export type {args_type_name}\s*=\s*{{([\s\S]*?)}};", re.DOTALL)
        args_match = args_block_pattern.search(content)

        if args_match:
            args_content = args_match.group(1).strip()
            arg_pattern = re.compile(r'(?:/\*\*(.*?)\*/\s*)?(\w+)(\??):\s*([\s\S]*?);', re.DOTALL)
            for arg_match in arg_pattern.finditer(args_content):
                arg_desc_raw, arg_name, optional_marker, full_type = arg_match.groups()
                arg_desc, _ = clean_description(arg_desc_raw)
                
                operation_details["arguments"].append({
                    "name": arg_name,
                    "type": full_type.strip(),
                    "optional": (optional_marker == '?'),
                    "description": arg_desc
                })
        operations.append(operation_details)
    return operations

def extract_from_gql_blocks(content):
    operations = []
    gql_blocks = re.findall(r'gql\s*`([\s\S]+?)`', content)
    
    for block in gql_blocks:
        op_match = re.search(r'^\s*(query|mutation|subscription)\s+([_A-Za-z]\w*)', block.strip())
        if not op_match:
            continue
        
        op_type, op_name = op_match.groups()
        op_type = op_type.capitalize()

        fragments = re.findall(r'\.\.\.\s*(\w+)', block)
        
        return_fields = []
        selection_match = re.search(r'{([\s\S]*)}', block)
        if selection_match:
            selection_content = selection_match.group(1)
            field_matches = re.findall(r'\b([a-zA-Z_]\w*)\s*(?:\{|$|\n)', selection_content)
            for field in field_matches:
                if field not in ['query', 'mutation', 'subscription', 'fragment'] and not field.startswith('...'):
                    return_fields.append({
                        'name': field,
                        'type': 'Unknown',
                        'optional': False,
                        'nested': [],
                        'depth': 0
                    })

        operation_details = {
            "name": op_name,
            "description": "Extracted from gql template literal.",
            "tags": [],
            "return_type": "See return fields",
            "return_fields": return_fields,
            "arguments": [],
            "fragments": fragments
        }

        args_block_match = re.search(r'\(([\s\S]*?)\)', block)
        if args_block_match:
            args_string = args_block_match.group(1)
            arg_matches = re.findall(r'\$([_A-Za-z]\w*)\s*:\s*([\[\]\w!]+)', args_string)
            for arg_name, arg_type_full in arg_matches:
                is_required = arg_type_full.endswith('!')
                arg_type_clean = re.sub(r'[!\[\]]', '', arg_type_full)
                operation_details["arguments"].append({
                    "name": arg_name,
                    "type": arg_type_clean,
                    "optional": not is_required,
                    "description": ""
                })
        operations.append((op_type, operation_details))
    return operations

def extract_from_graphql_schema(content):
    operations = []
    
    type_block_pattern = re.compile(
        r'type\s+(Query|Mutation|Subscription)\s*\{([\s\S]*?)\n\}',
        re.MULTILINE
    )
    
    for type_match in type_block_pattern.finditer(content):
        op_type = type_match.group(1)
        block_content = type_match.group(2)
        
        op_pattern = re.compile(
            r'(?:"""([\s\S]*?)"""\s*)?(\w+)\s*(?:\(([\s\S]*?)\))?\s*:\s*([\w\[\]!]+)',
            re.MULTILINE
        )
        
        for op_match in op_pattern.finditer(block_content):
            description_raw, op_name, args_str, return_type = op_match.groups()
            description, tags = clean_description(description_raw)
            
            operation_details = {
                "name": op_name,
                "description": description,
                "tags": tags,
                "return_type": return_type,
                "return_fields": extract_return_fields(return_type, content),
                "arguments": [],
                "fragments": []
            }
            
            if args_str:
                arg_pattern = re.findall(r'(\w+)\s*:\s*([\w\[\]!]+)', args_str)
                for arg_name, arg_type in arg_pattern:
                    is_required = arg_type.endswith('!')
                    arg_type_clean = re.sub(r'[!\[\]]', '', arg_type)
                    operation_details["arguments"].append({
                        "name": arg_name,
                        "type": arg_type_clean,
                        "optional": not is_required,
                        "description": ""
                    })
            
            operations.append((op_type, operation_details))
    
    return operations

def write_fields_tree(f, fields, is_last_sibling=True, prefix=""):
    for i, field in enumerate(fields):
        is_last = (i == len(fields) - 1)
        
        if field['depth'] == 0:
            connector = "└─" if is_last else "├─"
            extension = "  " if is_last else "│ "
        else:
            connector = "└─" if is_last else "├─"
            extension = "  " if is_last else "│ "
        
        nullable = "nullable" if field['optional'] else "non-null"
        f.write(f"{prefix}{connector} {field['name']} ({field['type']}) - {nullable}\n")
        
        if field.get('nested'):
            new_prefix = prefix + extension
            write_fields_tree(f, field['nested'], is_last, new_prefix)

def write_op_to_file(operation, op_type, base_dir):
    try:
        folder_path = os.path.join(base_dir, op_type)
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, f"{operation['name']}.txt")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"{op_type.upper()}: {operation['name']}\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"Description: {operation['description']}\n")
            
            if operation.get('tags'):
                f.write("\nTags:\n")
                for tag_name, tag_value in operation['tags']:
                    f.write(f"  @{tag_name}")
                    if tag_value:
                        f.write(f": {tag_value}")
                    f.write("\n")
            
            f.write("\n")
            f.write("ARGUMENTS:\n")
            f.write("-" * 40 + "\n")
            
            if operation['arguments']:
                sorted_args = sorted(operation['arguments'], key=lambda x: x['optional'])
                for arg in sorted_args:
                    line = format_argument_line(
                        arg['name'], 
                        arg['type'], 
                        arg['optional'],
                        arg.get('description', '')
                    )
                    f.write(f"{line}\n")
            else:
                f.write("No arguments required.\n")
            
            f.write("\n")
            f.write("RETURN TYPE:\n")
            f.write("-" * 40 + "\n")
            f.write(f"{operation.get('return_type', 'Unknown')}\n\n")
            
            if operation.get('return_fields'):
                f.write("AVAILABLE FIELDS TO RETURN:\n")
                f.write("-" * 40 + "\n")
                try:
                    write_fields_tree(f, operation['return_fields'])
                except Exception as tree_error:
                    print(f"Error writing fields tree for {operation['name']}: {tree_error}")
                    for field in operation['return_fields']:
                        nullable = "nullable" if field.get('optional', False) else "non-null"
                        f.write(f"• {field['name']} ({field['type']}) - {nullable}\n")
                f.write("\n")
            
            if operation.get('fragments'):
                f.write("FRAGMENTS USED:\n")
                f.write("-" * 40 + "\n")
                for fragment in operation['fragments']:
                    f.write(f"• {fragment}\n")
                f.write("\n")
            
            f.write("\n")
        return True
    except Exception as e:
        print(f"Error writing {op_type} '{operation['name']}': {e}")
        return False

def extract_graphql_operations(ts_dir):
    input_files = (
        glob.glob(os.path.join(ts_dir, '**/*.ts'), recursive=True) + 
        glob.glob(os.path.join(ts_dir, '**/*.tsx'), recursive=True) +
        glob.glob(os.path.join(ts_dir, '**/*.graphql'), recursive=True) +
        glob.glob(os.path.join(ts_dir, '**/*.gql'), recursive=True)
    )

    if not input_files:
        print("No TS/GraphQL files found for extraction")
        return {}

    print(f"\nExtracting GraphQL operations from {len(input_files)} files...")

    all_operations = {}
    
    for filename in input_files:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if filename.endswith(('.graphql', '.gql')):
                for op_type, op in extract_from_graphql_schema(content):
                    all_operations[(op_type, op['name'])] = op
            else:
                for op_type, op in extract_from_gql_blocks(content):
                    all_operations[(op_type, op['name'])] = op
                
                for op in extract_from_ts_types(content, "Mutation"):
                    all_operations[("Mutation", op['name'])] = op

                for op in extract_from_ts_types(content, "Query"):
                    all_operations[("Query", op['name'])] = op
                
                for op in extract_from_ts_types(content, "Subscription"):
                    all_operations[("Subscription", op['name'])] = op

        except Exception as e:
            print(f"Error processing {filename}: {e}")

    return all_operations

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_history(operations):
    history = {}
    for (op_type, op_name), op_data in operations.items():
        key = f"{op_type}:{op_name}"
        history[key] = {
            "name": op_name,
            "type": op_type,
            "description": op_data.get('description', ''),
            "arguments": op_data.get('arguments', []),
            "return_type": op_data.get('return_type', '')
        }
    
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def compare_and_save_operations(current_operations):
    old_history = load_history()
    
    unique_mutations = {k[1]: v for k, v in current_operations.items() if k[0] == 'Mutation'}
    unique_queries = {k[1]: v for k, v in current_operations.items() if k[0] == 'Query'}
    unique_subscriptions = {k[1]: v for k, v in current_operations.items() if k[0] == 'Subscription'}

    new_operations = {}
    
    for op_type, ops_dict in [("Mutation", unique_mutations), ("Query", unique_queries), ("Subscription", unique_subscriptions)]:
        for op_name, op_data in ops_dict.items():
            key = f"{op_type}:{op_name}"
            if key not in old_history:
                new_operations[(op_type, op_name)] = op_data

    if os.path.exists(GRAPHQL_NEW_DIR):
        print(f"\nMerging previous NEW operations into main API...")
        for op_type in ['Mutation', 'Query', 'Subscription']:
            new_type_dir = os.path.join(GRAPHQL_NEW_DIR, op_type)
            api_type_dir = os.path.join(GRAPHQL_API_DIR, op_type)
            
            if os.path.exists(new_type_dir):
                os.makedirs(api_type_dir, exist_ok=True)
                for filename in os.listdir(new_type_dir):
                    if filename.endswith('.txt'):
                        src = os.path.join(new_type_dir, filename)
                        dst = os.path.join(api_type_dir, filename)
                        os.rename(src, dst)
                        print(f"Merged: {op_type}/{filename}")
        
        import shutil
        shutil.rmtree(GRAPHQL_NEW_DIR)
        print("Removed old NEW directory")

    print(f"\nWriting operations to {GRAPHQL_API_DIR}...")
    for op in unique_mutations.values():
        write_op_to_file(op, "Mutation", GRAPHQL_API_DIR)
    for op in unique_queries.values():
        write_op_to_file(op, "Query", GRAPHQL_API_DIR)
    for op in unique_subscriptions.values():
        write_op_to_file(op, "Subscription", GRAPHQL_API_DIR)

    if new_operations:
        print(f"\nFound {len(new_operations)} NEW operations!")
        print(f"Writing to {GRAPHQL_NEW_DIR}...")
        
        new_mutations = {k[1]: v for k, v in new_operations.items() if k[0] == 'Mutation'}
        new_queries = {k[1]: v for k, v in new_operations.items() if k[0] == 'Query'}
        new_subscriptions = {k[1]: v for k, v in new_operations.items() if k[0] == 'Subscription'}
        
        for op in new_mutations.values():
            write_op_to_file(op, "Mutation", GRAPHQL_NEW_DIR)
        for op in new_queries.values():
            write_op_to_file(op, "Query", GRAPHQL_NEW_DIR)
        for op in new_subscriptions.values():
            write_op_to_file(op, "Subscription", GRAPHQL_NEW_DIR)
        
        print("\nNEW operations:")
        for (op_type, op_name) in new_operations.keys():
            print(f"  - {op_type}: {op_name}")
    else:
        print("\nNo new operations found.")

    save_history(current_operations)
    
    print(f"\nSummary:")
    print(f"Total Mutations: {len(unique_mutations)}")
    print(f"Total Queries: {len(unique_queries)}")
    print(f"Total Subscriptions: {len(unique_subscriptions)}")
    print(f"New operations: {len(new_operations)}")

def main():
    print("GraphQL Monitor - Starting...\n")
    
    config = load_config()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
        "Cookie": config['cookies']
    }
    
    hosts = config.get('hosts', [])
    if not hosts:
        print("Error: No hosts defined in config.json")
        return
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(TS_DIR, exist_ok=True)
    os.makedirs(MAP_CACHE_DIR, exist_ok=True)
    
    print(f"Step 1: Downloading TypeScript files from source maps")
    print(f"Hosts: {', '.join(hosts)}\n")

    js_folder = 'JS'
    if not os.path.exists(js_folder):
        print(f"Error: '{js_folder}' folder not found. Please create it and add your JS files.")
        return
    
    local_js_files = [f for f in glob.glob(os.path.join(js_folder, '*.js*')) if not f.endswith('.map')]
    
    stats.js_total_count = len(local_js_files)
    if not local_js_files:
        print("No JS files found. Skipping download step.")
    else:
        print(f"Found {stats.js_total_count} JS files")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for js_file in local_js_files:
                process_js_file(js_file, executor, TS_DIR, MAP_CACHE_DIR, headers, hosts)
        
        print(f"\nDownload Summary:")
        print(f"JS files processed: {stats.js_total_count}")
        print(f"Source maps found: {stats.sourcemap_found_count}")
        print(f"TS files in maps: {stats.ts_in_maps_count}")
        print(f"TS extracted: {stats.ts_extracted_count}")
        print(f"TS downloaded: {stats.ts_downloaded_count}")

    print(f"\nStep 2: Extracting GraphQL operations from TypeScript files")
    all_operations = extract_graphql_operations(TS_DIR)
    
    if not all_operations:
        print("No GraphQL operations found")
        return
    
    print(f"\nStep 3: Comparing with history and saving operations")
    compare_and_save_operations(all_operations)
    
    print("\nMonitoring complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()