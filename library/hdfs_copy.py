# Copyright (c) 2017 LAYER4
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: hdfs_copy
short_description: Copies files to HDFS.
description:
    - The hdfs_copy module copies a file from the local machine to HDFS. If the file already exists, copy happens only if the size or the checksum of the remote and local files are different.
author: "Vincent Devillers (@treydone)"
options:
    dest:
        description:
          - path where the file should be copied to.
    src:
        description:
          - Local path to a file to copy to the remote server; can be absolute or relative.
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
requirements:
  - "python >= 2.6"
'''

EXAMPLES = '''
- hdfs_file:
    src: /file/to/link/to
    dest: /path/to/symlink
    url: "{{ knox_url }}"
    user: "{{ knox_user }}"
    password: "{{ knox_password }}"
    strict: "{{ knox_strict }}"
'''

#
# python core, ansible imports
#
import hashlib
import os
from ansible.module_utils.basic import *
from io import BytesIO
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

    src = module.params['src']
    dest = module.params['dest']

    auth = HTTPBasicAuth(user, password)

    if src is not None and dest is not None:
        copy_if_not_exists(module, url, auth, strict, src, dest)

    module.fail_json(changed=False)


def copy(module, baseurl, auth, strict, src, path, msg):
    if module.check_mode:
        module.exit_json(changed=False)

    # Ok, copy...
    url = '{}{}?op=CREATE&overwrite=true'.format(baseurl, path)
    open_req = requests.put(
        url,
        auth=auth,
        verify=strict,
        allow_redirects=False)
    if open_req.status_code == 307:
        location = open_req.headers['Location'];
        with open(src, 'rb') as fh:
            mydata = fh.read()
            req = requests.put(
                location,
                data=mydata,
                auth=auth,
                verify=strict)
        if req.status_code != 201:
            module.fail_json(msg='Cannot copy to path {}, got {}'.format(path, req.status_code))
    else:
        module.fail_json(msg='Cannot open path {}, got {}'.format(path, open_req.status_code))
    module.exit_json(changed=True, msg=msg)


def copy_if_not_exists(module, baseurl, auth, strict, src, path):
    path = absolute_path(path)

    # Parent exists?
    url = '{}{}?op=GETFILESTATUS'.format(baseurl, parent_path(path))
    req = requests.get(
        url,
        auth=auth,
        verify=strict)
    if req.status_code == 404:
        # No -> failed
        module.fail_json(changed=False, msg='Path {} doesn\'t exists'.format(parent_path(path)))
    if req.status_code == 200:
        # Parent exists!
        # Path exists?
        url = '{}{}?op=GETFILESTATUS'.format(baseurl, path)
        req = requests.get(
            url,
            auth=auth,
            verify=strict)
        if req.status_code == 404:
            # No -> copy
            copy(module, baseurl, auth, strict, src, path, 'Path {} doesn\'t exit, copying...'.format(path))
        if req.status_code == 200:
            # File exists...
            # Size if the same?
            if os.path.getsize(src) != req.json()['FileStatus']['length']:
                # No -> copy
                copy(module, baseurl, auth, strict, src, path,
                     'Local and remote file {} do not have the same size, copying...'.format(path))
            else:
                # Same checksum?

                # TODO !!! Use instead GETFILECHECKSUM and compare the remote checksum to a MD5 of MD5 of 512CRC32C
                url = '{}{}?op=OPEN'.format(baseurl, path)
                open_req = requests.get(url, auth=auth, allow_redirects=False, verify=strict)
                if open_req.status_code == 307:
                    location = open_req.headers['Location'];
                    read_req = requests.get(location, auth=auth, verify=strict)  # , allow_redirects=False, stream=True)
                    if read_req.status_code == 200:
                        content = BytesIO(read_req.content)
                    else:
                        module.fail_json(
                            msg='Cannot open datanode location {}, got {}'.format(location, open_req.status_code))
                else:
                    module.fail_json(msg='Cannot open path {}, got {}'.format(path, open_req.status_code))

                remote_md5 = hashlib.md5()
                remote_md5.update(content.getvalue())

                with open(src, 'rb') as fh:
                    mydata = fh.read()
                    local_md5 = hashlib.md5()
                    local_md5.update(mydata)

                if local_md5.hexdigest() != remote_md5.hexdigest():
                    # No -> copy
                    copy(module, baseurl, auth, strict, src, path,
                         'Local and remote file {} do not have the same checksum, copying...'.format(path))

                # Alright, file is already in hdfs, and it's the same, go away!
                module.exit_json(changed=False)
        else:
            module.fail_json(msg='Cannot get file status for path {}, got {}'.format(path, req.status_code))
    else:
        module.fail_json(msg='Cannot get file status for path {}, got {}'.format(parent_path(path), req.status_code))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            src=dict(required=False, type='str'),
            dest=dict(required=False, type='str'),
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
