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
# create a directory if it doesn't exist
- hdfs_file:
    path: /src/www
    state: directory
    url: "{{ knox_url }}"
    user: "{{ knox_user }}"
    password: "{{ knox_password }}"

- hdfs_file:
    src: /file/to/link/to
    dest: /path/to/symlink
    url: "{{ knox_url }}"
    user: "{{ knox_user }}"
    password: "{{ knox_password }}"

# change file ownership, group and mode. When specifying mode using octal numbers, first digit should always be 0.
- hdfs_file:
    path: /etc/foo.conf
    owner: foo
    group: foo
    mode: 0644
    url: "{{ knox_url }}"
    user: "{{ knox_user }}"
    password: "{{ knox_password }}"
'''

#
# python core, ansible imports
#
import os
from ansible.module_utils.basic import *


#
# custom imports
#

DEPENDENCIES_OK = True  # use flag as we want to use module.fail_json for errors
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError, e:
    DEPENDENCIES_OK = False

def absolute_path(path):
   if len(path)>0 and path[0]!='/':
      path = '/'+path
   return path

def parent_path(path):
  return path

def run(module):
  url = module.params['url']
  user = module.params['user']
  password = module.params['password']

  path = module.params['path']
  state = module.params['state']
  src = module.params['src']
  dest = module.params['dest']
  
  if(src is not None and dest is not None):
    copyIfNotExists(url,user,password,src,dest)
  if(path is not None and state is not None):
    # TODO
    module.exit_json(changed=False,msg='Well...')

  module.fail_json(changed=False)

def copy(url,auth,data,path,msg):

  if module.check_mode:
     module.exit_json(changed=False)

  # Ok, copy...
  url = '{}{}?op=CREATE&overwrite=true'.format(url,path)
  headers = {}
  headers['Content-Type'] = 'application/octet-stream'
  #headers['Authorization'] = HTTPBasicAuth(user,password)
  #headers['Content-Length'] = ...
  open_req = requests.put(
     url,
     auth=auth,
     allow_redirects=False,
     headers=headers)
  if open_req.status_code==307:
     location = open_req.headers['Location'];
     req = requests.put(
        location,
        auth=auth,
        data=data,
        headers=headers)
     if req.status_code!=201:
       module.fail_json(msg='Cannot copy to path {}, got {}'.format(path, req.status_code))
  else:
     module.fail_json(msg='Cannot open path {}, got {}'.format(path, req.status_code))
  module.exit_json(changed=True,msg=msg)

def copyIfNotExists(url,user,password,data,path):
   path = absolute_path(path)
   headers = {}
   #headers['Authorization'] = HTTPBasicAuth(user,password)
   auth=HTTPBasicAuth(user,password)

   # Parent exists?
   url = '{}{}?op=GETFILESTATUS'.format(url,path)
   req = requests.get(
     parent_path(url),
     auth=auth,
     data=data,
     headers=headers)
   if req.status_code==404:
     # No -> failed
     module.exit_json(changed=False,msg='Path {} doesn\'t exists'.format(parent_path(path)))
   if req.status_code==200:
     # Parent exists!
     # Path exists?
     url = '{}{}?op=GETFILESTATUS'.format(url,path)
     req = requests.get(
      url,
      auth=auth,
      headers=headers)
     if req.status_code==404:
       # No -> copy
       copy(url,auth,data,path,'Path {} doesn\'t exit, copying...'.format(path))
     if req.status_code==200:
       # File exists...
       # Size if the same?
       if(len(data)!=req.json()['FileStatus']['length']):
         # No -> copy
         copy(url,auth,data,path, 'Local and remote file {} do not have the same size, copying...'.format(path))
       else:
         # Same checksum?
         url = '{}{}?op=GETFILECHECKSUM'.format(url,path)
         req = requests.get(
            url,
            auth=auth,
            data=data,
            headers=headers)

         #MD5-of-1MD5-of-512CRC32C
         #md5(md5(crc32))
         #{
         #  "FileChecksum":
         #  {
         #    "algorithm": "MD5-of-1MD5-of-512CRC32",
         #    "bytes"    : "eadb10de24aa315748930df6e185c0d ...",
         #    "length"   : 28
         #  }
         #}
         # No -> copy
         copy(url,auth,data,path, 'Local and remote file {} do not have the same checksum, copying...'.format(path))

         # Alright, file is here, go away!
         module.exit_json(changed=False)
     else:
       module.fail_json(msg='Cannot get file status for path {}, got {}'.format(path, req.status_code))
   else:
     module.fail_json(msg='Cannot get file status for path {}, got {}'.format(parent_path(path), req.status_code))

def main():
  module = AnsibleModule(
      argument_spec = dict(
        path=dict(required=False, type='str'),
        state = dict(required=False, type='str', choices=['directory', 'absent']),
        owner=dict(required=False, type='str'),
        group=dict(required=False, type='str'),
        src=dict(required=False, type='str'),
        dest=dict(required=False, type='str'),
        url=dict(required=True, type='str'),
        user=dict(required=True, type='str'),
        password=dict(required=True, type='str')
      ),
      required_together = (
          ['state', 'path'],
          ['src', 'dest']
      ),
      mutually_exclusive = (
          ['dest', 'path'],
          ['src', 'path']
      ),
      required_one_of = (),
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
