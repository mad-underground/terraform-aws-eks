import re
import os

variable_regex = re.compile('var.([a-zA-Z_0-9]*)[\W|\s]*')

files_to_process = [
    {
        'file_name': 'main.tf',
        'variable_name': 'eks'
    },
    {
        'file_name': 'locals.tf',
        'variable_name': 'eks'
    },
    {
        'file_name': 'outputs.tf',
        'variable_name': 'eks'
    },
    {
        'file_name': 'data.tf',
        'variable_name': 'eks'
    },
    {
        'file_name': 'aws-auth-configmap.tf',
        'variable_name': 'eks'
    },
    {
        'file_name': 'eks-worker.tf',
        'variable_name': 'eks'
    }
]

def test():
    for file in files_to_process:
        orig_file = f'{file["file_name"]}.orig'
        generated_file = f'generated_{file["file_name"]}'

        if os.path.isfile(file["file_name"]):
            os.replace(file["file_name"], orig_file)

def main():
    for file in files_to_process:
        orig_file = f'{file["file_name"]}.orig'
        generated_file = f'generated_{file["file_name"]}'
        variable_name = file["variable_name"]

        if os.path.isfile(file["file_name"]):
            os.replace(file["file_name"], orig_file)

        with open(generated_file, 'w') as write_f:
            with open(orig_file, encoding="utf-8") as read_f:
                for line in read_f:
                    new_line = line
                    variable_matches = variable_regex.findall(line.strip())
                    if variable_matches is not None and len(variable_matches) > 0:
                        for v in variable_matches:
                            new_line = new_line.replace(f'var.{v}', f'var.{variable_name}.{v}')
                    write_f.write(f'{new_line}')


if __name__ == '__main__':
    main()
