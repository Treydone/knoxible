# Copyright (c) 2017 LAYER4
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: hdfs_file
short_description: Sets attributes of files stored in HDFS.
description:
    - Sets attributes of files and directories, or removes files/directories.
author: "Vincent Devillers (@treydone)"
options:
    state:
        description:
          - Desired state of the target. If directory, all immediate subdirectories will be created if they do not exist. If absent, directories will be recursively deleted, and files or symlinks will be deleted.
        choices: ['directory', 'absent']
    path:
        description:
          - path to the file being managed.
    url:
        description:
          - url of Knox Gateway
    user:
        description:
          - user
    password:
        description:
          - password
    strict:
        description:
          - enforce strict for https connection
notes:
    - TODO
requirements:
  - "python >= 2.6"
'''

EXAMPLES = '''
# create a directory if it doesn't exist
- hdfs_file:
    path: /src/www
    state: directory
    url: "{{ knox_url }}"
    user: "{{ knox_user }}"
    password: "{{ knox_password }}"
'''

#
# python core, ansible imports
#
from ansible.module_utils.basic import *
from pathlib import Path

DEPENDENCIES_OK = True  # use flag as we want to use module.fail_json for errors
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError, e:
    DEPENDENCIES_OK = False


def absolute_path(path):
    if len(path) > 0 and path[0] != '/':
        path = '/' + path
    return path


def parent_path(path):
    return Path(path).parent


def run(module):
    url = module.params['url'] + '/webhdfs/v1'
    user = module.params['user']
    password = module.params['password']
    strict = module.params['strict']

    path = module.params['path']
    state = module.params['state']

    auth = HTTPBasicAuth(user, password)

    if path is not None and state is not None:
        update_state_if_needed(module, url, auth, strict, path, state)
        module.exit_json(changed=False, msg='Well...')

    module.fail_json(changed=False)


def update_state_if_needed(module, url, auth, strict, path, state):
    if "directory" == state:
        create_directory_if_needed(auth, module, path, strict, url)
    elif "absent" == state:
        delete_path_if_needed(auth, module, path, strict, url)
    module.fail_json(msg='?')


def delete_path_if_needed(auth, module, path, strict, baseurl):
    url = '{}{}?op=GETFILESTATUS'.format(baseurl, path)
    req = requests.get(
        url,
        auth=auth,
        verify=strict)
    if req.status_code == 200:
        # File exists...
        url = '{}{}?op=DELETE&recursive=true'.format(baseurl, path)
        req = requests.delete(
            url,
            verify=strict,
            auth=auth)
        if req.status_code == 200:
            module.exit_json(changed=True, msg='Path {} deleted'.format(path))
        else:
            module.fail_json(msg='Cannot delete path {}, got {}'.format(path, req.status_code))
    elif req.status_code == 404:
        module.exit_json(changed=False, msg='Path is already {} missing'.format(path))
    else:
        module.fail_json(msg='Error while getting info about {}, got a file'.format(path))


def create_directory_if_needed(auth, module, path, strict, baseurl):
    url = '{}{}?op=GETFILESTATUS'.format(baseurl, path)
    req = requests.get(
        url,
        auth=auth,
        verify=strict)
    if req.status_code == 200:
        # File exists...
        if 'DIRECTORY' == req.json()['FileStatus']['type']:
            module.exit_json(changed=False, msg='Dir already {} created'.format(path))
        else:
            module.fail_json(msg='Expecting a dir at {}, got a file'.format(path))
    if req.status_code == 404:
        url = '{}{}?op=MKDIRS'.format(baseurl, path)
        req = requests.put(
            url,
            verify=strict,
            auth=auth)
        if req.status_code == 200:
            module.exit_json(changed=True, msg='Dir {} created'.format(path))
        else:
            module.fail_json(msg='Cannot create dir {}, got {}: {}'.format(path, req.status_code, req.text))
    else:
        module.fail_json(msg='Error while getting info about {}, got a file'.format(path))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(required=False, type='str'),
            state=dict(required=False, type='str', choices=['directory', 'absent']),
            url=dict(required=True, type='str'),
            strict=dict(required=False, type='bool'),
            user=dict(required=True, type='str'),
            password=dict(required=True, type='str', no_log=True)
        ),
        required_one_of=(),
        supports_check_mode=True
    )

    # validations and checks
    # note: module.fail_json stops execution of the module
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
