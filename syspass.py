#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# python 3 headers, required if submitting to Ansible
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = """
      DISCLAIMER: This module has been heavily inspired by https://github.com/ansible/ansible/blob/devel/lib/ansible/plugins/lookup/password.py for password generation and term handling and thus is under GPL.

      lookup: syspass
        author: Gousseaud Gaëtan <gousseaud.gaetan.pro@gmail.com>, Pierre-Henry Muller <pierre-henry.muller@digdeo.fr>
        short_description: get syspass user password and syspass API client
        description:
            - This lookup returns the contents from Syspass database, a user's password more specificly. Other functions are also implemented for further use.
        ansible_version: ansible 2.6.2 with mitogen
        python_version: 2.7.9
        syspass_version: 3.0 Beta (300.18082701)
        params:
           -term: the account name (required and must be unique)
             -login: login given to created account
             -category: category given to created account
             -customer: client given to created account
             -state: like in Ansible absent to remove the password, present in default to create (Optional)
             -pass_length: generated password length (Optional)
             -chars: type of chars used in generated (Optional)
             -url: url given to created account (Optional)
             -notes: notes given to created account (Optional)
             -private: is this password private for users who have access or public for all users in acl (default false)
             -privategroup: is private only for users in same group (default false)
             -expirationDate: expiration date given to created account (Optional) and not tested (no entry in webui)

        notes:
          - debug is only debug and has no return value (new or existing account)
          - Account is only created if exact name has no match.
          - A different field passed to an already existing account wont modify it.
          - Utility of tokenPass: https://github.com/nuxsmin/sysPass/issues/994#issuecomment-409050974
          - Rudimentary list of API accesses (Deprecated): https://github.com/nuxsmin/sysPass/blob/d0056d74a8a2845fb3841b02f4af5eac3e4975ed/lib/SP/Services/Api/ApiService.php#L175
          - Usage of ansible vars: https://github.com/ansible/ansible/issues/33738#issuecomment-350819222

        syspass function list:
          SyspassClient:
            Account:
              -AccountSearch
              -AccountViewpass
              -AccountCreate
              -AccountDelete
              -AccountView
            Category:
              -CategorySearch
              -CategoryCreate
              -CategoryDelete
            Client:
              -ClientSearch
              -ClientCreate
              -ClientDelete
            Tag:
              -TagCreate
              -TagSearch
              -TagDelete
            Others:
              -Backup
"""

EXAMPLES = """
### IN HOST VARS ###

syspass_API_URL: http://syspass-server.net/api.php
syspass_API_KEY: 'API_KEY' #Found in Users & Accesses -> API AUTHORIZATION -> User token
syspass_API_ACC_TOKPWD: Password for API_KEY for Account create / view / delete password account permission in API

### IN PLAYBOOK ###

NOTE: Default values are handled 

##### USAGE 1 #####

- name: Minimum declaration to get / create password
  local_action: debug msg="{{ lookup('syspass', 'Server 1 test account', login=test, category='MySQL', customer='Customer 1') }}"

- name: All details for password declaration
  local_action: debug msg="{{ lookup('syspass', 'Server 1 test account', login=test, category='MySQL', customer='Customer 1', 
    url='https://exemp.le', notes='Additionnal infos', private=True, privategroupe=True) }}"

- name: Minimum declaration to delete password
  local_action: debug msg="{{ lookup('syspass', 'Server 1 test account', state=absent) }}"


"""

import json
import requests
import random
import string
import urllib3
import re
from ansible.errors import AnsibleError, AnsibleAssertionError
from ansible.module_utils._text import to_native, to_text
from ansible.plugins.lookup import LookupBase
from ansible.utils.encrypt import do_encrypt, random_password

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

    
ERR_NEEDED='Empty arg needed'
# default password length
DEFAULT_LENGTH = 20

def _gen_candidate_chars(characters):
    '''Generate a string containing all valid chars as defined by ``characters``
    :arg characters: A list of character specs. The character specs are
        shorthand names for sets of characters like 'digits', 'ascii_letters',
        or 'punctuation' or a string to be included verbatim.
    The values of each char spec can be:
    * a name of an attribute in the 'strings' module ('digits' for example).
      The value of the attribute will be added to the candidate chars.
    * a string of characters. If the string isn't an attribute in 'string'
      module, the string will be directly added to the candidate chars.
    For example::
        characters=['digits', '?|']``
    will match ``string.digits`` and add all ascii digits.  ``'?|'`` will add
    the question mark and pipe characters directly. Return will be the string::
        u'0123456789?|'
    '''
    chars = []
    for chars_spec in characters:
        # getattr from string expands things like "ascii_letters" and "digits"
        # into a set of characters.
        chars.append(to_text(getattr(string, to_native(chars_spec), chars_spec),
                     errors='strict'))
    chars = u''.join(chars).replace(u'"', u'').replace(u"'", u'')
    return chars


class SyspassClient:
    def __init__(self, API_KEY, API_URL, API_ACC_TOKPWD):
        self.API_KEY = API_KEY
        self.API_URL = API_URL
        self.API_ACC_TOKPWD = API_ACC_TOKPWD
        self.rId = 1

    def AccountSearch(self, text,
                           count = None,
                           categoryId = None,
                           clientId = None):
        """
        Search account in syspass using text as keyword,
        can apply categoryId of clientId as a filter.
        """
        data = {   "jsonrpc": "2.0",
                   "method": "account/search",
                   "params": {
                       "authToken": self.API_KEY,
		       "text": text,
                       "count": count,
                       "categoryId": categoryId,
                       "clientId": clientId},
                   "id": self.rId }

        self.rId+=1
        req = requests.post(self.API_URL, json = data)
        return req.json()['result']['result'][0]
    
    def AccountViewpass(self, uId):
        """
        Returns account's password. 
        uId identifies account.
        tokenPass is used to decrypt encrypted data.
        """
        data = {"jsonrpc": "2.0",
                "method": "account/viewPass",
                "params":{
                    "authToken": self.API_KEY,
                    "id": uId,
                    "tokenPass": self.API_ACC_TOKPWD
                },
                "id": self.rId 
        }

        self.rId+=1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']['result']['password']
    
    def AccountCreate(self,
                      name,
                      categoryId,
                      clientId,
                      password,
                      login,
                      url = None,
                      notes = None,
                      private = None,
                      privateGroup = None,
                      expireDate = None,
                      parentId = None):
        """
        Creates account for syspass.
        """
        data = {"jsonrpc": "2.0",
                "method": "account/create",
                "params":{
                    "authToken": self.API_KEY,
                    "tokenPass": self.API_ACC_TOKPWD,
                    "name": name,
                    "categoryId": categoryId,
                    "clientId": clientId,
                    "pass": password,
                    "login": login,
                    "url": url,
                    "notes": notes,
                    "private": private,
                    "privateGroup": privateGroup,
                    "expireDate": expireDate,
                    "parentId": parentId
		},
		"id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']

    def AccountDelete(self, uId):
        """
        Delete syspass account.
        """
        data = {"jsonrpc": "2.0",
                "method": "account/delete",
		"params":{
	            "authToken": self.API_KEY,
                    "id": uId,
                    "tokenPass": self.API_ACC_TOKPWD
                },
                "id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()

    def AccountView(self, uId):
        """
        View syspass account.
        """
        data = {"jsonrpc": "2.0",
                "method": "account/view",
                "params":{
                    "authToken": self.API_KEY,
                    "id": uId
                },
                "id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']['result']
    
    def CategorySearch(self,text, count = None):
        """
        Searches syspass category.
        text is the keyword.
        count is the number of results.
        """

        data = {"jsonrpc": "2.0",
                "method": "category/search",
                "params":{
                    "authToken": self.API_KEY,
                    "text": text,
                    "count": count
		},
		"id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']['result'][0]

    def CategoryCreate(self, name, description = None):
        """
        Creates syspass category.
        """
        data = {"jsonrpc": "2.0",
                "method": "category/create",
                "params":{
                    "authToken": self.API_KEY,
                    "name": name,
                    "description": description
		},
                "id": self.rId
	}

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']

    def CategoryDelete(self, Id):
        """
        Deletes syspass category.
        """
        data = {"jsonrpc": "2.0",
                "method": "category/delete",
                "params":{
                    "authToken": self.API_KEY,
                    "id": Id
		},
                "id": self.rId
	}

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()
    
    def ClientSearch(self, text, count = None):
        """
        Searches syspass client.
        """
        data = {"jsonrpc": "2.0",
                "method": "client/search",
                "params":{
                    "authToken": self.API_KEY,
                    "text": text,
                    "count": count
		},
		"id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']['result'][0]

    def ClientCreate(self, name, description = None, Global = False):
        """
        Creates a syspass client.
        """
        data = {"jsonrpc": "2.0",
                "method": "client/create",
                "params":{
                    "authToken": self.API_KEY,
                    "name": name,
                    "description": description,
                    "global": Global
		},
		"id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']

    def ClientDelete(self, cId):
        """
        Deletes a syspass client.
        """
        data = {"jsonrpc": "2.0",
                "method": "client/delete",
                "params":{
                    "authToken": self.API_KEY,
                    "id": cId
		},
		"id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()

    def TagCreate(self,name):
        """
        Creates a syspass tag.
        """
        data = {"jsonrpc": "2.0",
                "method": "tag/create",
                "params":{
                    "authToken": self.API_KEY,
                    "name": name
                },
                "id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']
    
    def TagSearch(self, text, count = None):
        """
        Searches a syspass tag using text as keyword.
        """
        data = {"jsonrpc": "2.0",
                "method": "tag/search",
                "params":{
                    "authToken": self.API_KEY,
                    "text": text,
                    "count": count
		},
		"id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()

    def TagDelete(self,tId):
        """
        Deletes syspass tag using id.
        """
        data = {"jsonrpc": "2.0",
                "method": "tag/delete",
                "params":{
                    "authToken": self.API_KEY,
                    "id" : tId
                },
                "id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()

    def Backup(self):
        """
        https://github.com/nuxsmin/sysPass/issues/1004#issuecomment-411487284
        """
        data = {"jsonrpc": "2.0",
                "method": "backup",
                "params":{
                    "authToken": self.API_KEY,
                },
                "id": self.rId
        }

        self.rId += 1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()

class LookupModule(LookupBase):
    """
    Execution of Ansible Lookup
    """
    def run(self, terms, variables=None, **kwargs):
        # disables https warnings in python2
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if variables is not None:
            self._templar.set_available_variables(variables)
        myvars = getattr(self._templar, '_available_variables', {})

        sp = SyspassClient(API_URL= str(myvars['syspass_API_URL']),
                           API_KEY = str(myvars['syspass_API_KEY']),
                           API_ACC_TOKPWD = str(myvars['syspass_API_ACC_TOKPWD']))

        chars = kwargs.get('chars', 'default')
        psswd_length = kwargs.get('psswd_length', DEFAULT_LENGTH)
        login = kwargs.get('login', ERR_NEEDED)
        category = kwargs.get('category', ERR_NEEDED)
        customer = kwargs.get('customer', ERR_NEEDED)
        url = kwargs.get('url', '')
        notes = kwargs.get('notes', '')
        state = kwargs.get('state', 'present')
        private = kwargs.get('state', False)
        privategroup = kwargs.get('state', False)
        expirationDate = kwargs.get('expirationDate', '')

        values = []

        for term in terms:
            try:
                account = sp.AccountSearch(text = term, count = 1)
                if term == account['name']:
                    exists = True
                    debug = "Existing account, retrieved password"
                else:
                    exists = False
                    debug = "Missing account, created account and retrieved password"
            except IndexError:
                exists = False
                debug = "Missing account, created account and retrieved password"
                
            if exists:
                if state == 'absent':
                    sp.AccountDelete(uId = account["id"])
                    psswd = 'Deleted Account'
                else:
                    psswd = sp.AccountViewpass(uId = account["id"])
            elif not exists:
                chars = _gen_candidate_chars(chars)
                psswd = random_password(psswd_length, chars)

                # Following handlers verify existence of fields
                # creating them in case of absence.
                try:
                    categoryId = sp.CategorySearch(text = category, count = 1 )["id"]
                except IndexError:
                    categoryId = sp.CategoryCreate(name = category)['itemId']
                try:
                    customerId = sp.ClientSearch(text = customer)['id']

                except IndexError:
                    customerId = sp.ClientCreate(name = customer)['itemId']
                sp.AccountCreate(name = term,
                                 categoryId = int(categoryId),
                                 clientId = int(customerId),
                                 password = psswd,
                                 login = login,
                                 url = url,
                                 notes = notes,
                                 private = private,
                                 privateGroup = privategroup,
                                 expireDate = expirationDate,
                                 parentId = None)

            # Note: Plugins and modules always have list as output
            values.append(psswd)
        return values
