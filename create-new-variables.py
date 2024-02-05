# create-new-variables.py
import re
import os

variable_regex = re.compile('^variable[\s]*"(.*)"[\s]*\{$')
description_regex = re.compile('^description[\s]*=[\s]*(".*")$')
type_regex = re.compile('^type[\s]*=[\s]*(.*)$')
default_regex = re.compile('^default[\s]*=[\s]*(.*)$')
validation_regex = re.compile('^validation[\s]*\{[\s]*$')
end_regex = re.compile('^.*\}$')

module_source = 'terraform-aws-modules/eks/aws'
module_version = '20.0.0'

files_to_process = [
    {
        'source_var_file': 'variables.tf',
        'destination_path': 'modules/mu/aws-eks',
        'destination_var_file': 'variables.tf',
        'destination_main_file': 'main.tf',
        'variable_name': 'cluster',
        'description': 'AWS EKS cluster resources to be created',
        'module_name': 'eks',
        'module_source': module_source,
        'module_version': module_version,
        'add_for_each': False,
        'add_count': True
    },
    {
        'source_var_file': 'modules/eks-managed-node-group/variables.tf',
        'destination_path': 'modules/mu/eks-managed-node-group',
        'destination_var_file': 'variables.tf',
        'destination_main_file': 'main.tf',
        'variable_name': 'eks_managed_node_groups',
        'description': 'AWS EKS managed node group to be created',
        'module_name': 'eks_managed_node_group',
        'module_source': f'{module_source}//modules/eks-managed-node-group',
        'module_version': module_version,
        'add_for_each': True
    },
    {
        'source_var_file': 'modules/self-managed-node-group/variables.tf',
        'destination_path': 'modules/mu/self-managed-node-group',
        'destination_var_file': 'variables.tf',
        'destination_main_file': 'main.tf',
        'variable_name': 'self_managed_node_groups',
        'description': 'AWS EKS self managed node group to be created',
        'module_name': 'self_managed_node_group',
        'module_source': f'{module_source}//modules/self-managed-node-group',
        'module_version': module_version,
        'add_for_each': True
    },
    {
        'source_var_file': 'modules/karpenter/variables.tf',
        'destination_path': 'modules/mu/karpenter',
        'destination_var_file': 'variables.tf',
        'destination_main_file': 'main.tf',
        'variable_name': 'karpenter',
        'description': 'Node provisioning for Kubernetes',
        'module_name': 'eks_karpenter',
        'module_source': module_source,
        'module_version': module_version,
        'add_for_each': False
    }
]

def main():

    for file in files_to_process:
        print('=========================')
        print(file['variable_name'])
        print(file)
        print('-------------------------')
        os.makedirs(file['destination_path'], exist_ok=True)
        source_var_file = file['source_var_file']
        dest_var_file = os.path.join(file['destination_path'], file['destination_var_file'])
        dest_main_file = os.path.join(file['destination_path'], file['destination_main_file'])

        new_lines = {}

        with open(source_var_file, encoding="utf-8") as read_f:
            new_line = {
                "variable_name": None,
                "description": None,
                "type": None,
                "default": None
            }
            isMultiLineDefault = False
            isOpenSquareBracket = False
            isOpenCurlyBracket = False
            isValidationBlock = False
            isTypeObject = False
            for line in read_f:
                variable_match = variable_regex.match(line.strip())
                description_match = description_regex.match(line.strip())
                type_match = type_regex.match(line.strip())
                default_match = default_regex.match(line.strip())
                validation_match = validation_regex.match(line.strip())
                end_match = end_regex.match(line.strip())

                if variable_match:
                    new_line['variable_name'] = variable_match.group(1).strip()
                elif description_match:
                    new_line['description'] = description_match.group(1).strip()
                elif type_match:
                    new_line['type'] = type_match.group(1).strip()
                    if 'object(' in new_line['type']:
                        new_line['type'] += '\n'
                        isTypeObject = True
                elif default_match:
                    new_line['default'] = default_match.group(1).strip()
                    if new_line['default'] == '[':
                        new_line['default'] += '\n'
                        isMultiLineDefault = True
                        isOpenSquareBracket = True
                    elif new_line['default'] == '{':
                        new_line['default'] += '\n'
                        isMultiLineDefault = True
                        isOpenCurlyBracket = True
                elif isMultiLineDefault:
                    new_line['default'] += f'  {line}'
                    if line.strip() == ']' and isOpenSquareBracket:
                        isMultiLineDefault = False
                        isOpenSquareBracket = False
                    elif line.strip() == '}' and isOpenCurlyBracket:
                        isMultiLineDefault = False
                        isOpenSquareBracket = False
                elif isTypeObject:
                    if '}' in line.strip():
                        new_line['type'] += f'    {line.strip()}'
                        isTypeObject = False
                    else:
                        new_line['type'] += f'  {line}'
                elif validation_match:
                    isValidationBlock = True
                elif isValidationBlock:
                    if line.strip() == '}':
                        isValidationBlock = False
                elif end_match:
                    if new_line["variable_name"] is not None:
                        new_lines[new_line["variable_name"]] = new_line
                    new_line = {
                        "variable_name": None,
                        "description": None,
                        "type": None,
                        "default": None
                    }

        keys = list(new_lines)
        keys.sort()
        with open(dest_main_file, 'w') as write_main_f:
            write_main_f.write(f'module "{file["module_name"]}" {{\n')
            write_main_f.write(f'  source = "{file["module_source"]}"\n')
            write_main_f.write(f'  version = "{file["module_version"]}"\n\n')
            if file.get('add_count', False): write_main_f.write(f'  count = try(local.{file["variable_name"]}.create, false) ? 1 : 0\n\n')
            if file["add_for_each"]:
                write_main_f.write(f'  for_each = local.{file["variable_name"]}\n\n')
            for k in keys:
                l = new_lines[k]
                write_main_f.write(f'  # {l["description"]}\n')
                if file["add_for_each"]:
                    write_main_f.write(f'  {l["variable_name"]} = try(each.value.{l["variable_name"]}, {l["default"].rstrip()})\n\n')
                else:
                    write_main_f.write(f'  {l["variable_name"]} = try(local.{file["variable_name"]}.{l["variable_name"]}, {l["default"].rstrip()})\n\n')
            write_main_f.write('}')

        with open(dest_var_file, 'w') as write_f:
            write_f.write(f'variable "{file["variable_name"]}" {{\n')
            write_f.write(f'  description = "{file["description"]}"\n')
            write_f.write(f'  default = null\n')
            write_f.write('  type = object({\n')

            for k in keys:
                l = new_lines[k]
                write_f.write(f'    # {l["description"]}\n')
                if l["default"] is None:
                    write_f.write(f'    {l["variable_name"]} = {l["type"]}\n')
                else:
                    write_f.write(f'    {l["variable_name"]} = optional({l["type"]}, {l["default"].rstrip()})\n')
                write_f.write('\n')
            write_f.write('  })\n')
            write_f.write('}\n')

if __name__ == '__main__':
    main()