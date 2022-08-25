import argparse
import json


def check_esc1(template):

    def has_domain_users_in_enrollment_rights(template):
        for enrollment_right in template['Permissions']['Enrollment Permissions']['Enrollment Rights']:
            if enrollment_right.split('\\')[1] == 'Domain Users':
                return True
    
        return False

    assert(template['Enabled'] == True)
    assert(template['Client Authentication'] == True)
    assert(template['Enrollee Supplies Subject'] == True)
    assert(template['Requires Manager Approval'] == False)
    assert(template['Authorized Signatures Required'] == 0)
    assert(has_domain_users_in_enrollment_rights(template))


def check_esc4(template):

    def check_objet_control_permissions_write_owners(template):
        for write_owner in template['Permissions']['Object Control Permissions']['Write Owner Principals']:
            if write_owner.split('\\')[1] == 'Authenticated Users':
                return True
        
        return False
    

    def check_object_control_permissions_write_dacl(template):
        for write_owner in template['Permissions']['Object Control Permissions']['Write Dacl Principals']:
            if write_owner.split('\\')[1] == 'Authenticated Users':
                return True
        
        return False
    

    assert(check_objet_control_permissions_write_owners(template))
    assert(check_object_control_permissions_write_dacl(template))


CHECKS = {
    'esc1': check_esc1,
    'esc4': check_esc4
}


def parse_args():
    parser = argparse.ArgumentParser(description='')

    parser.add_argument('input_file', type=str, help='A JSON file containing the Certipy output')
    parser.add_argument('checks', choices=CHECKS.keys(), nargs='+', help='The checks to run against the templates')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    with open(args.input_file, 'r') as input_file:
        data = json.loads(input_file.read())
    
    vulnerabilities = {}

    for certificate_template in data['Certificate Templates'].values():
        name = certificate_template['Template Name']
        display_name = certificate_template['Display Name']
        vulnerabilities[name] = {
            'display_name': display_name
        }

        for check_name in args.checks:
            check_function = CHECKS[check_name]

            try:
                check_function(certificate_template)
                vulnerabilities[name][check_name] = True
            except AssertionError:
                vulnerabilities[name][check_name] = False
    
    print(json.dumps(vulnerabilities, indent=4))
