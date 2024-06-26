import os
import yaml
import re
import shutil

def str_presenter(dumper, data):
    if len(data.splitlines()) > 1 or '\n' in data:  
        text_list = [line.rstrip() for line in data.splitlines()]
        fixed_data = "\n".join(text_list)
        return dumper.represent_scalar('tag:yaml.org,2002:str', fixed_data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


yaml.add_representer(str, str_presenter)


script_dir=os.path.dirname(os.path.realpath(__file__))

ORIG_RULE_DIRS = 'detection-rules'

NEW_RULE_DIR = "mimecast-detection-rules"

new_rule_path = os.path.join(script_dir,"../..",NEW_RULE_DIR)

orig_rule_path = os.path.join(script_dir,"../..",ORIG_RULE_DIRS)

if not os.path.exists(new_rule_path):
    os.makedirs(new_rule_path)

with open(os.path.join(script_dir,"replacements.yml"), 'r') as f:
    url_replacement_string = yaml.safe_load(f.read())

def change_urls_to_mimecast():

    def check_hard_to_fix(text_to_check):
        difficult_markups = [".href_url.url",".href_url.path",".href_url.query_params",".href_url.domain.subdomain",".href_url.domain.punycode",".href_url.domain.valid","beta.whois","strings.ilevenshtein(.href_url.domain.root_domain",".href_url.rewrite.encoders"]

        for x in difficult_markups:
            if x in text_to_check:
                return(True)
        return(False)


    for root, dirs, files in os.walk(orig_rule_path):
        for file in files:
            # CI validates that no .YAML files exist
            if file.endswith('.yml'):
                changed_file = False

                # Read the file contents
                orig_full_file_path = os.path.join(root, file)
                with open(orig_full_file_path, 'r') as f:
                    contents = f.read()

                    # load the YAML and check if it already has an ID
                    parsed = yaml.safe_load(contents)
                    source = parsed.get('source')
                    tags = []

                    if "body.links" in source:
                        for replace_item in url_replacement_string.values():
                            stripped_orig=replace_item['orig'].strip()
                            if stripped_orig in source:
                                source = source.replace(stripped_orig," " + replace_item['replace'].strip() + " ")
                                changed_file=True
                            else:
                                temp_source=source
                                if "$$" in stripped_orig:
                                    orig_string_regex=stripped_orig.replace("$$","\$([\w_\-]+)")
                                    strings_to_be_replaced=re.finditer(orig_string_regex,source)
                                if "[]" in stripped_orig:
                                    orig_string_regex=stripped_orig.replace("[]","\[([\w\.\-\\\",'\s]+)\]")
                                    strings_to_be_replaced=re.finditer(orig_string_regex,source)
                                if "()" in stripped_orig:
                                    orig_string_regex=stripped_orig.replace("()","\(([\w\.\-\\\",'\s]+)\)")
                                    strings_to_be_replaced=re.finditer(orig_string_regex,source)
                                if "\"\"" in stripped_orig:
                                    orig_string_regex=stripped_orig.replace("\"\"","\"([\w\.\-]+)\"")
                                    strings_to_be_replaced=re.finditer(orig_string_regex,source)
                                if "''" in stripped_orig:
                                    orig_string_regex=stripped_orig.replace("''","'([\w\.\-]+)'")
                                    strings_to_be_replaced=re.finditer(orig_string_regex,source)

                                for string_to_be_replaced in strings_to_be_replaced:
                                    if "$$" in replace_item['replace']:
                                        replacement_string = replace_item['replace'].strip().replace("$$","$" + string_to_be_replaced.group(1))
                                    if "[]" in replace_item['replace']:
                                        replacement_string = replace_item['replace'].strip().replace("[]","[" + string_to_be_replaced.group(1) + "]")
                                    if "()" in replace_item['replace']:
                                        replacement_string = replace_item['replace'].strip().replace("()","(" + string_to_be_replaced.group(1) + ")")
                                    if "\"\"" in replace_item['replace']:
                                        replacement_string = replace_item['replace'].strip().replace("\"\"","\"" + string_to_be_replaced.group(1) + "\"")
                                    if "''" in replace_item['replace']:
                                        replacement_string = replace_item['replace'].strip().replace("''","'" + string_to_be_replaced.group(1) + "'")
                                    if "##" in replace_item['replace']:
                                        replacement_string = replace_item['replace'].strip().replace("##", string_to_be_replaced.group(1))                                      
                                    source = source.replace(string_to_be_replaced.group(0)," " + replacement_string + " ")
                                    changed_file=True

                        if "beta.linkanalysis" in parsed['source']:
                            tags.append('Link Analysis Present')

                        if check_hard_to_fix(parsed['source']):
                            tags.append('Mimecast Hard to Fix')

                        elif ".href_url.domain" in source:
                            tags.append('Mimecast Needs Fix')

                        elif changed_file:
                            tags.append('Mimecast Changes Complete')

                        parsed['source'] = source

                        if 'tags' in parsed:
                            parsed['tags'].extend(tags)
                        else:
                            parsed['tags']=tags
                            
                        with open(os.path.join(new_rule_path, file), 'w') as f:
                            yaml.dump(parsed, f)
                    else:
                        shutil.copy(orig_full_file_path, os.path.join(new_rule_path, file))

                        

if __name__ == '__main__':
    change_urls_to_mimecast()
