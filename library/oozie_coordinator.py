# Copyright (c) 2017 LAYER4
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: oozie_coordinator
short_description: Sets attributes of files stored in HDFS.
description:
    - Sets attributes of files and directories, or removes files/directories.
author: "Vincent Devillers (@treydone)"
options:
    state:
        description:
          - Desired state of the target
        choices: ['present', 'absent']
    other_param:
        description:
          - What does this do?
notes:
    - TODO
requirements:
  - "python >= 2.6"
'''

EXAMPLES = '''
# ensure coordinator is deployed
- oozie_coordinator:
    path=files/worflow.xml.j2 state=present
'''

#
# python core, ansible imports
#
from ansible.module_utils.basic import *

#
# custom imports
#
from io import StringIO

DEPENDENCIES_OK = True  # use flag as we want to use module.fail_json for errors
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError, e:
    DEPENDENCIES_OK = False


def kill(baseurl, auth, id):
    url = '{}/job/{}?action=kill'.format(baseurl, id)
    req = requests.put(
        url,
        auth=auth,
        verify=strict)
    if req.status_code == 200:
        module.exit_json(changed=True, msg='Job {} killed'.format(id), id=req.json()['id'])
    else:
        module.fail_json(msg='Error while killing job'.format(id))

def write_property(xml,name,value):
    xml.write('<property>\n')
    xml.write('<name>')
    xml.write(name)
    xml.write('</name>\n')
    xml.write('<value>')
    xml.write(str(value))
    xml.write('</value>\n')
    xml.write('</property>\n')

def write_properties(xml, properties):
    xml.write('<?xml version="1.0" encoding="UTF-8"?>\n<configuration>\n')
    if properties is not None:
        for name in properties:
            value = properties[name]
            write_property(xml,name,value)
    xml.write('</configuration>\n')

def run(module):
    baseurl = module.params['url'] + '/oozie/v1'
    user = module.params['user']
    password = module.params['password']
    strict = module.params['strict']

    file = module.params['file']
    #state = module.params['state']

    properties=dict(line.strip().split('=') for line in open(file))

    auth = HTTPBasicAuth(user, password)

    url = '{}/jobs?filter=jobtype%3Dcoordinator%3Bname={}'.format(baseurl, name)
    req = requests.get(
        url,
        auth=auth,
        verify=strict)
    if req.status_code == 200:
        # Kill all the coordinators found
        for job in req.json()['jobs']:
            kill(baseurl, auth, job['id'])

        xml = StringIO()
        write_properties(xml, properties)
        req = requests.post(
            url,
            data=xml.getvalue(),
            auth=auth,
            verify=strict)

        if req.status_code == 201:
            module.exit_json(changed=True, msg='Job deployed', id=req.json()['id'])
        else:
            module.fail_json(msg='Error while deploying the job'.format(id))
    else:
        module.fail_json(msg='Error while finding info about coordinators')


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(required=True, type='str', choices=['present', 'absent']),
            url=dict(required=True, type='str'),
            user=dict(required=True, type='str'),
            file=dict(required=True, type='str'),
            strict=dict(required=False, type='bool'),
            password=dict(required=True, type='str', no_log=True)
        ),
        required_together=(),
        mutually_exclusive=(),
        required_one_of=(),
        supports_check_mode=True
    )

    if not DEPENDENCIES_OK:
        module.fail_json(msg='`requests` library required for this module (`pip install requests`)')

    # Run logic, manage errors
    try:
        run(module)
    except Exception as e:
        import traceback
        module.fail_json(msg=str(e) + str(traceback.format_exc()))


if __name__ == '__main__':
    main()
