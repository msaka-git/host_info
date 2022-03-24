#!/usr/bin/env python2

## Mandatory imports
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

## Optional imports
from __future__ import print_function,unicode_literals
import subprocess,sys,csv,time,argparse,os,re,shutil,tempfile
from secops_linux.utils.subprocess_helper import subprocess_command
from secops_linux.leavers import query
from sudo_manager.objects import SudoRecord
sys.path.append('/secbin/security/Scripts/get_passwd_tools_2/libs')
from lib_passlist_file import PasslistManager
from datetime import datetime

## Variables
fa_header = ['access_action','source_user','target_user','target_server','commands']
# Build the Leaver dump object. We run the Leavers queries against that object
dump = query.LeaversDump("{}".format("/secbin/security/Scripts/Unix/Prod_host_information"  if os.uname()[1] == 'vmhokki' else "/secbin/security/Scripts/Unix/LEAVERS/local_accesses/all"))
env_passlist = "local_bat" if os.uname()[1] == 'vmhokki' else "lux_prod"
# temp directory path
path = '/tmp/{}/'.format(os.path.basename(__file__).split('.')[0])

'''
Script checks sudo rules, get_password objects and netgroups for a given server.
Run the script: ./scriptname.py --hostname server
CSV files are generated inside a directory in /tmp. Full path of the directory 
will be printed at the end of its execution.
'''

def get_arguments():
    parser = argparse.ArgumentParser(description="Retrieve netgroup,sudo,get password information.\n", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hostname", type=str.lower, help="Give a hostname")

    if len(sys.argv) <= 2:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = parser.parse_args()
    return args

def temp_dir():
    '''
    Create a temp directory to place files.
    '''
    if os.path.exists(path):
    #    shutil.rmtree(path)
         pass
    else:
        os.makedirs(path)
    #tempdir=tempfile.mkdtemp(prefix='.',dir='/tmp')
    #print(tempdir) # shows tempdir name

def check_host_indump(hostname):
    '''
    Return True or False
    '''
    server_name = hostname
    server = dump.host_exists(server_name)
    return server

def write_csv(func):
    def wrapper(host):
        '''
        Key value will be sudo,get_paaswd or netgroup.
        according to 'key', we'll build csv headers.
        '''
        f_timestamp=datetime.now().strftime('%Y%m%d-%H%M%S')
        output=func(host)
        key = output[1]
        hostname = host
        header = output[2]
        f_name='{}{}_{}_{}.csv'.format(path,key,hostname,f_timestamp)
        with open(f_name,'w') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(output[0])
        print(f_name)
        return f_name
    return wrapper

@write_csv
def list_netgroups(host):
    '''
    Return all netgroups.
    key = default value of function type.
    '''
    key = 'all_netgroup'
    csv_headers = ['netgroup','target_server']
    netgroups = dump.get_netgroups(host)
    ng_output = []
    for ng in netgroups:
        ng_dict = {}
        ng_dict['target_server'] = host
        ng_dict['netgroup'] = ng
        ng_output.append(ng_dict)
    
    return ng_output,key,csv_headers

def list_fa_netgroups():
    '''
    Return only FA netgroups
    '''
    exclude=['sysadmin','secops']
    netgroups=list_netgroups(args.hostname,dump)
    regex = re.compile(r"^\w.*_|admin|bau|dev|ro|DEV|RO")
    fa_netgroups = []
    for netgroup in netgroups:
        if regex.match(netgroup):
            fa_netgroups.append(netgroup)
            if any(x in netgroup for x in exclude):
                fa_netgroups.remove(netgroup)

    return fa_netgroups

@write_csv
def get_sudo_data(hostname):
    '''
    Returns sudo rules.
    key = default value of function type.
    hostname : server name
    '''
    key='sudo'
    csv_headers = ['source_user','target_user','target_group','target_server','commands']
    no_all = True

    list_record_=[]
    try:
        records = SudoRecord.list_records_2(target_host=hostname,no_all=no_all)
        for record in records:
            record_={}
            record_['source_user']=str(record.sudo_source) if record.sudo_source else ''
            record_['target_user']=str(record.runas_user) if record.runas_user else ''
            record_['target_group']=str(record.runas_group) if record.runas_group else ''
            record_['target_server']=str(record.sudo_host_meta) if record.sudo_host_meta else ''
            record_['commands']=str(record.sudo_target) if record.sudo_target else ''
            list_record_.append(record_)
            
    except ValueError:
        pass
    return list_record_,key,csv_headers

@write_csv
def get_getpasswd_data(hostname):
    '''
    key = default value of function type.
    hostname : server name
    Inside this function we convert hostname to a list element (get_passwd library requirement).
    '''
    hostname=[hostname]
    key='get_passwd'
    csv_headers = ['safe','requestor','account','environment','domain','password']
    # lock_passlist = False for 'export-flatfile'
    passlist = PasslistManager(env_passlist, lock_passlist=False)
    passlist.parse_passlist()

    filter_data = [f.lower() for f in hostname]
    lines = passlist.get_passlist_flat()

    password_map = []
    result = []
    for line in lines:
        # Apply filter
        if line['hostname'] in filter_data:
            # Hide the password but show which ones are the same
            if line['password'] not in password_map:
                password_map.append(line['password'])
            hashed_password = 'passwd_{}'.format(
                              password_map.index(line['password']) + 1)
            # Split Account+Environment
            account_env = line['account'].split('+')
            try:
                # check if there are missing environments
                if len(account_env) < 2:
                    result.append({'safe': line['safe'], 'requestor': line['user'], 'account': account_env[0], 'environment': None,
                                   'password': hashed_password, 'domain': line['hostname']})
                else:
                    result.append({'safe': line['safe'], 'requestor': line['user'], 'account': account_env[0], 'environment': account_env[1],
                                   'password': hashed_password, 'domain': line['hostname']})
            except Exception as e:
                pass            
    
    return result,key,csv_headers

if __name__=='__main__':
    args=get_arguments()
    if args.hostname:
        temp_dir()
        list_netgroups(args.hostname)
        get_sudo_data(args.hostname)
        get_getpasswd_data(args.hostname)
