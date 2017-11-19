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
import xml.etree.ElementTree as ET
from ansible.module_utils.basic import *
from io import BytesIO

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


def write_property(xml, name, value):
    xml.write('<property>')
    xml.write('<name>')
    xml.write(name)
    xml.write('</name>')
    xml.write('<value>')
    xml.write(str(value))
    xml.write('</value>')
    xml.write('</property>')


def write_properties(xml, properties):
    xml.write('<?xml version="1.0" encoding="UTF-8" standalone="no"?><configuration>')
    if properties is not None:
        for name in properties:
            value = properties[name]
            write_property(xml, name, value)
    xml.write('</configuration>')


def download(module, webdhdfsurl, auth, strict, coordinatorPath):
    url = '{}{}?op=OPEN'.format(webdhdfsurl, coordinatorPath)
    open_req = requests.get(url, auth=auth, allow_redirects=False, verify=strict)
    if open_req.status_code == 307:
        location = open_req.headers['Location'];
        read_req = requests.get(location, auth=auth, verify=strict)  # , allow_redirects=False, stream=True)
        if read_req.status_code == 200:
            return BytesIO(read_req.content)
        else:
            module.fail_json(msg='Cannot open datanode location {}, got {}'.format(location, open_req.status_code))
    else:
        module.fail_json(msg='Cannot open path {}, got {}'.format(coordinatorPath, open_req.status_code))


def run(module):
    baseurl = module.params['url']
    ooziebaseurl = baseurl + '/oozie/v1'
    webdhdfsurl = baseurl + '/webhdfs/v1'
    user = module.params['user']
    password = module.params['password']
    strict = module.params['strict']

    file = module.params['file']
    # state = module.params['state']

    auth = HTTPBasicAuth(user, password)

    # Read properties
    properties = dict(line.strip().split('=') for line in open(file))
    coordinatorPath = properties.get('oozie.coord.application.path')

    # Coordinator is already deployed?
    url = '{}{}?op=GETFILESTATUS'.format(webdhdfsurl, coordinatorPath)
    req = requests.get(
        url,
        auth=auth,
        verify=strict)
    if req.status_code == 404:
        # Coordinator file is missing -> error
        module.fail_json(msg='Cannot find coordinator at {}'.format(coordinatorPath))
    if req.status_code == 200:
        # Coordinator file exist, check if already deployed

        # Download remote coordinator file
        content = download(module, webdhdfsurl, auth, strict, coordinatorPath)

        # Find coordinator name
        content_as_string = content.getvalue()
        try:
            coordinatorName = ET.parse(content).find(".").get('name')
        except:
            module.fail_json(msg='Cannot parse content {}, got {}'.format(content_as_string, sys.exc_info()[0]))

        # Find coordinator from name
        url = '{}/jobs?jobtype=coordinator&filter=name={}'.format(ooziebaseurl, coordinatorName)
        req = requests.get(
            url,
            auth=auth,
            verify=strict)
        if req.status_code == 200:
            # Kill all the coordinators found
            for job in req.json()['coordinatorjobs']:
                kill(ooziebaseurl, auth, job['id'])

            # Deploy coordinator
            xml = BytesIO()
            write_properties(xml, properties)
            url = '{}/jobs'.format(ooziebaseurl)
            headers = {'Content-Type': 'application/xml;charset=UTF-8'}

            content = xml.getvalue()

            req = requests.post(
                url,
                data=content,
                headers=headers,
                auth=auth,
                verify=strict)

            if req.status_code == 201:
                module.exit_json(changed=True, msg='Job deployed', id=req.json()['id'])
            else:
                module.fail_json(msg='Error while deploying the job, got {}: {} while sending coordinator: {}'.format(
                    req.status_code, req.text, content))
        else:
            module.fail_json(
                msg='Error while finding info about coordinators, got {}: {}'.format(req.status_code, req.text))
    module.fail_json(msg='Cannot get file status for path {}, got {}'.format(coordinatorPath, req.status_code))


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
