import re
import os

output_name_regex = re.compile('^output[\s]*"(.*)"[\s]*\{$')
description_regex = re.compile('^description[\s]*=[\s]*(".*")$')
value_regex = re.compile('^value[\s]*=.*$')
end_regex = re.compile('^.*\}$')

def main():
    src_file = 'outputs.tf'
    dest_file = 'wrapper/eks-outputs.tf'
    output_name = None
    description = None

    with open(dest_file, 'w') as write_f:
        with open(src_file, encoding="utf-8") as read_f:
            for line in read_f:
                output_name_variable_match = output_name_regex.match(line.strip())
                if output_name_variable_match:
                    output_name = output_name_variable_match.group(1).strip()
                    continue
                description_match = description_regex.match(line.strip())
                if description_match:
                    description = description_match.group(1).strip()
                    continue
                end_match = end_regex.match(line.strip())
                if end_match:
                    if output_name is None:
                        continue
                    write_f.write(f'output "{output_name}" {{\n')
                    if description is not None:
                        write_f.write(f'  description = {description}\n')
                    write_f.write(f'  value = module.eks.{output_name}\n')
                    write_f.write('}\n\n')
                    output_name = None
                    description = None


if __name__ == '__main__':
    main()
