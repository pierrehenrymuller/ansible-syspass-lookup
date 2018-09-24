#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# python 3 headers, required if submitting to Ansible
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = """
      DISCLAIMER: This module has been heavily inspired by https://github.com/ansible/ansible/blob/devel/lib/ansible/plugins/lookup/password.py for password generation and term handling and thus is under GPL.

      lookup: syspass
        author: Gousseaud Gaëtan <gousseaud.gaetan.pro@gmail.com>
        short_description: get syspass user password and syspass API client
        description:
            - This lookup returns the contents from Syspass database, a user's password more specificly. Other functions are also implemented for further use.
        ansible_version: ansible 2.6.2
        python_version: 2.7.9
        syspass_version: 3.0 Beta (300.18082701)
        params:
           terms: Parameters passed to the lookup plugin
             -pass_length: generated password length (Optional)
             -chars: type of chars used in generated (Optional)
             -psswd_tokenPass: tokenPass field for account/viewPass
             -account_tokenPass: tokenPass field for account/create
             -name: name searched for existing or to be created account
             -login: login given to created account
             -category: category given to created account
             -customer: client given to created account
             -url: url given to created account (Optional)
             -notes: notes given to created account (Optional)
             -expirationDate: expiration date given to created account (Optional)

        notes:
          - Current state is only debug and has no return value (new or existing account)
          - Account is only created if exact name has no match.
          - A different field passed to an already existing account wont modify it.
          - Utility of tokenPass: https://github.com/nuxsmin/sysPass/issues/994#issuecomment-409050974
          - Rudimentary list of API accesses (Deprecated): https://github.com/nuxsmin/sysPass/blob/d0056d74a8a2845fb3841b02f4af5eac3e4975ed/lib/SP/Services/Api/ApiService.php#L175
          - Lookup args are a string of keywords separated by a space and are parsed by parse_kv such as:
            "{{ lookup('syspass','insidelookuptermname1=' + arg1 + ' insidelookuptermname2=' + arg2}}"
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

### IN PLAYBOOK ###

NOTE: Default values are handled 

##### USAGE 1 #####

- name: Using formatted string
  vars:
    sysargs: >-
      psswd_length={{ psswd_length | default(16) }}
      psswd_tokenPass={{ psswd_tokenPass | default('ERR_NEEDED') }}
      chars={{ chars | default('default') }}
      account_tokenPass={{ account_tokenPass | default('ERR_NEEDED') }}
      acc_name={{ acc_name | default('ERR_NEEDED') }}
      login={{ login | default('ERR_NEEDED') }}
      category={{ category | default('ERR_NEEDED') }}
      customer={{ customer | default('ERR_NEEDED') }}
      url={{ url | default('') }}
      notes={{ notes | default('') }}
                                       
  local_action: debug msg="{{lookup('syspass',sysargs)}}"

##### USAGE 2 ######

- name: Using direct string
    local_action: debug msg="{{ lookup('syspass','psswd_length=' + (psswd_length | default('16'))  + ' psswd_tokenPass=' + (psswd_tokenPass | default('ERR_NEEDED')) + ' chars=' + (chars | default('default')) + ' account_tokenPass=' + (account_tokenPass | default('ERR_NEEDED')) + ' acc_name=' + (acc_name | default('ERR_NEEDED')) + ' login=' + (login | default('ERR_NEEDED')) + ' category=' + (category | default('ERR_NEEDED')) + ' customer=' + (customer | default('ERR_NEEDED')) + ' url=' + (url | default('')) + ' notes=' + (notes | default('')) ) }}"

### COMMAND LINE ###

host@ansible-server:~/ansible_root$ ansible-playbook playbooks/syspass.yml -e "psswd_tokenPass='YOUR_VIEWPASS_PASSWORD' account_tokenPass='YOUR_ACCOUNTCREATE_PASSWORD'' acc_name='extra_vared_dynamic_len' login='dd_user_dyn' category='dd_cat_dyn' customer='dd_new_cust' url='dd_url' notes='dd_notes' chars='.,:-_@',digits,hexdigits"


"""

import json
import requests
import random
import string
import urllib3
import re
from ansible.errors import AnsibleError, AnsibleAssertionError
from ansible.module_utils._text import to_native, to_text
from ansible.parsing.splitter import parse_kv
from ansible.plugins.lookup import LookupBase
from ansible.utils.encrypt import do_encrypt, random_password

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


DEFAULT_LENGTH = 20
VALID_PARAMS = frozenset(('psswd_length',
                          'chars',
                          'psswd_tokenPass',
                          'account_tokenPass',
                          'acc_name',
                          'login',
                          'category',
                          'customer',
                          'url',
                          'notes',
                          'expirationDate',
                          'state'))

#Value of needed fields if missing
ERR_NEEDED = 'ERR_NEEDED' 

def _parse_parameters(term):
    """Hacky parsing of params
    See https://github.com/ansible/ansible-modules-core/issues/1968#issuecomment-136842156
    and the first_found lookup For how we want to fix this later
    """
    
    params = parse_kv(term)

    if '_raw_params' in params:
        # Spaces in the path?
        del params['_raw_params']
    
    # Check for invalid parameters.  Probably a user typo
    invalid_params = frozenset(params.keys()).difference(VALID_PARAMS)
    if invalid_params:
        raise AnsibleError('Unrecognized parameter(s) given to password lookup: %s' % ', '.join(invalid_params))

    # Set defaults
    params['chars'] = str(params.get('chars', 'default').encode('utf-8'))
    params['psswd_length'] = int(params.get('psswd_length', DEFAULT_LENGTH))
    params['account_tokenPass'] = str(params.get('account_tokenPass', ERR_NEEDED).encode('utf-8'))
    params['psswd_tokenPass'] = str(params.get('psswd_tokenPass', ERR_NEEDED).encode('utf-8'))
    params['acc_name'] = str(params.get('acc_name', ERR_NEEDED).encode('utf-8'))
    params['login'] = str(params.get('login', ERR_NEEDED).encode('utf-8'))
    params['category'] = str(params.get('category', ERR_NEEDED).encode('utf-8'))
    params['customer'] = str(params.get('customer', ERR_NEEDED).encode('utf-8'))
    params['url'] = str(params.get('url', '').encode('utf-8'))
    params['notes'] = str(params.get('notes', '').encode('utf-8'))
    params['state'] = str(params.get('state', '').encode('utf-8'))
    params['expirationDate'] = str(params.get('expirationDate', None)).encode('utf-8')\
                               if params.get('expirationDate', None) else None  
    
    # Minimal use params
    NEEDED = [params['psswd_tokenPass'],
              params['account_tokenPass'],
              params['acc_name'],
              params['login'],
              params['category'],
              params['customer']]

    # Raising error for minimal use
    if ERR_NEEDED in set(NEEDED):
        raise AnsibleError('Missing needed parameter(s) for minimal syspass lookup usage: %s' % ', '.join({key: param for key, param in params.iteritems() if param == ERR_NEEDED}.keys()))
        
                         
    if params['chars'] != "default":
        tmp_chars = []
        if u',,' in params['chars']:
            tmp_chars.append(u',')
        tmp_chars.extend(c for c in params['chars'].replace(u',,', u',').split(u',') if c)
        params['chars'] = tmp_chars
    else:
        # Default chars for password
        params['chars'] = [u'ascii_letters', u'digits', u".,:-_"]

    return params


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


    def __init__(self, API_KEY, API_URL):
        self.API_KEY = API_KEY
        self.API_URL = API_URL
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

    
    def AccountViewpass(self, uId, tokenPass):
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
                    "tokenPass": tokenPass
                },
                "id": self.rId 
        }

        self.rId+=1
        req = requests.post(self.API_URL, json = data, verify = False)
        return req.json()['result']['result']['password']

    
    def AccountCreate(self,tokenPass,
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
                    "tokenPass": tokenPass,
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


    def AccountDelete(self, uId, tokenPass):
        """
        Delete syspass account.
        """
        data = {"jsonrpc": "2.0",
                "method": "account/delete",
		"params":{
	            "authToken": self.API_KEY,
                    "id": uId,
                    "tokenPass": tokenPass                    
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
    

    def CategorySearch(self,text,
                          count = None):
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


    def CategoryCreate(self, name,
                       description = None):
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

    
    def ClientSearch(self, text,
                        count = None):
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


    def ClientCreate(self, name,
                     description = None,
                     Global = False):
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

    
    def TagSearch(self, text,
                  count = None):
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
    Execution when called by lookup('syspass',"terms")
    """
    def run(self, terms, variables = None, **kwargs):

        # disables https warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        if variables is not None:
            self._templar.set_available_variables(variables)
        myvars = getattr(self._templar, '_available_variables', {})
        
        sysClient = SyspassClient(API_URL= str(myvars['syspass_API_URL']),
                                  API_KEY = str(myvars['syspass_API_KEY']))
        ret = []
        for term in terms:
            display.debug("Syspass lookup term: %s" % term)
            params = _parse_parameters(term)

            try:
                # Verifies account's existence
                account = sysClient.AccountSearch(text = params['acc_name'],
                                                  count = 1)
                # Makes sure it matched by name and not any other fields
                if params['acc_name'] == account['name']:
                    exists = True
                    state = "Existing account, retrieved password"
                else:
                    exists = False
                    state = "Missing account, created account and retrieved password"
            except IndexError: # No search match
                exists = False
                state = "Missing account, created account and retrieved password"

                
            if exists: # Views password
                if params['state'] == 'absent':
                    sysClient.AccountDelete(tokenPass = params["psswd_tokenPass"],
                                            uId = account["id"])
                    psswd = 'Deleted Account'
                else:
                    psswd = sysClient.AccountViewpass(tokenPass = params["psswd_tokenPass"],
                                                      uId = account["id"])
            elif not exists:
                # Password generation
                chars = _gen_candidate_chars(params['chars'])
                psswd = random_password(params['psswd_length'], chars)

                # Following handlers verify existence of fields
                # creating them in case of absence.
                try:
                    categoryId = sysClient.CategorySearch(text = params["category"],
                                                          count = 1 )["id"]
                except IndexError:
                    categoryId = sysClient.CategoryCreate(name = params["category"])['itemId']
                try:
                    customerId = sysClient.ClientSearch(text = params["customer"])['id']

                except IndexError:
                    customerId = sysClient.ClientCreate(name = params["customer"])['itemId']
                # Creates syspass account
                sysClient.AccountCreate(tokenPass = params['account_tokenPass'],
                                        name = params['acc_name'],
                                        categoryId = int(categoryId),
                                        clientId = int(customerId),
                                        password = psswd,
                                        login = params['login'],
                                        url = params['url'],
                                        notes = params['notes'],
                                        private = False,
                                        privateGroup = False,
                                        expireDate = params["expirationDate"],
                                        parentId = None)

            # Note: Plugins and modules always have list as output
            print("Syspass lookup state: " + state)
            ret = [psswd]
        return ret

