#!/usr/bin/env python3

__title__ = 'Script to add hosts to a Host Group based on IP'
__version__ = '2.0'
__author__ = 'mp@vectra.ai'
__copyright__ = 'Vectra AI, Inc.'
__status__ = 'Production'

'''
Opens a list of IPs or subnets formatted one per line, collects Cognito hosts with those IPs, adds the hosts
in turn to the group specified.  See ip_list.txt for sample syntax.
Written for Python 3.5+
'''

try:
    import sys
    import requests
    import argparse
    import logging
    import json
    import datetime
    import logging.handlers
    import ipaddress
    import re
    import string
except ImportError as error:
    stringerror = "\nMissing import requirements: %s\n" % str(error)
    sys.exit(stringerror)


#  Logging setup
logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)
fh = logging.FileHandler('ip_to_host_group.log')
fh.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

fh.setFormatter(formatter)

logger.addHandler(fh)


requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='Import a list of IPs or subnets from a file specified, poll '
                                             'Cognito for the host containers with the specified IPs and '
                                             'add those hosts to the group specified.  Script will create'
                                             'the group if necessary.  See ip_list.txt for sample syntax.',
                                 prefix_chars='-', formatter_class=argparse.RawTextHelpFormatter,
                                 epilog='')
parser.add_argument('cognito_url', type=str, help='Cognito\'s brain url, eg https://brain.vectra.local')
parser.add_argument('cognito_token', type=str, help='Cognito\'s auth token')
parser.add_argument('input_file', type=str, help='Text file containing list of IPs and subnets')
parser.add_argument('group', type=str, help='Name of group to add hosts to')
args = parser.parse_args()

vectra_header = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'Authorization': 'Token ' + args.cognito_token
}

cognito_api = '/api/v2/'

#  Lines begging with comment characters are ignored
comment_chars_re = '^[#;\'A-Za-z].*'


def test_creds(url, headers):
    try:
        response = requests.request("GET", url, headers=headers, verify=False)
        if response.status_code in [200, 201]:
            return
        else:
            logger.info('Error code: {}, Credential errors: {}'.format(response.status_code, response.content))
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        logger.info('\nUnable to establish connection with brain: {}\n\n'.format(args.cognito_url))
        sys.exit(1)


def add_host_to_group(group, host_dict):
    host_id_l = []
    logger.info('Preparing host list for group: [{}]'.format(group))
    for hid, values in host_dict.items():
        #  add_host_to_group(args.group, hid, values[0], values[1])
        host_id, hostname, ip = hid, values[0], values[1]

        #  Adds a list of hosts to a group, creating the group if needed
        host_id_l.append(str(host_id))
        logger.info('Adding host_id: {}, hostname: {}, ip: {} to list to be pushed'.format(host_id, hostname, ip))

    body_dict = {
        "name": group,
        "description": "Created by ip_to_host_group script",
        "type": "host",
        "members": host_id_l
    }
    logger.debug('Group Body:\n{}'.format(body_dict))
    body = json.dumps(body_dict)

    #  Check to see if group already exists
    cognito_group_check_url = args.cognito_url + cognito_api + 'groups/?name=' + group
    group_results = requests.request("GET", url=cognito_group_check_url, headers=vectra_header, verify=False).json()
    logger.debug('Checking if group {} exists.'.format(group))
    logger.debug('Group results:{}'.format(group_results))

    if not group_results:
        #  Group does not exist
        logger.info('Creating group: [{}], adding host_ids: {}'.format(group, host_id_l))
        cognito_group_url = args.cognito_url + cognito_api + 'groups/'
        response = requests.request("POST", url=cognito_group_url, headers=vectra_header, data=body, verify=False)
        logger.debug('Group create body: {}'.format(body))
        logger.debug('Group create url: {}'.format(response.url))
        logger.info('Group Create Response Reason: {}'.format(response.reason))
        logger.debug('Group Create Response Content: {}'.format(response.content))
        logger.info('New group {} has {} members'.format(group, len(host_id_l)))
    else:
        logger.debug('Group like: [{}] exists'.format(group))
        #  Group exists, possible fuzzy match
        for item in group_results:
            if item['name'] == group:
                group_id = item['id']
                #  Handle pre-existing members of group
                pre_exist_members = []
                for member in item['members']:
                    pre_exist_members.append(member['id'])
                logger.debug('Pre-existing members: {}'.format(pre_exist_members))
                #  Combine existing hosts with updated hosts and remove duplicates
                logger.info('Adding host_ids {} to group: [{}]'.format(host_id_l, group))
                pre_exist_members_len = len(pre_exist_members)
                pre_exist_members += host_id_l
                host_id_list = list(set(pre_exist_members))
                cognito_group_url = args.cognito_url + cognito_api + 'groups/' + str(group_id)
                logger.debug('group URL:{}'.format(cognito_group_url))

                body_dict = {
                    "members": host_id_list
                }
                body = json.dumps(body_dict)
                response = requests.request("PATCH", url=cognito_group_url, headers=vectra_header,
                                            data=body, verify=False)

                logger.debug('Group: {} exists, response:{}'.format(group, response))
                logger.debug('Group create body: {}'.format(body))
                logger.debug('Group create url: {}'.format(response.url))
                logger.info('Group Update Response: {}'.format(response.reason))
                logger.info('Existing group {} original member count {}, new member count {}'.format(
                    group, pre_exist_members_len, len(host_id_list)))
            else:
                cognito_group_url = args.cognito_url + cognito_api + 'groups/'
                logger.info('Creating group: [{}], adding host_ids: {}'.format(group, host_id_l))
                response = requests.request("POST", url=cognito_group_url, headers=vectra_header, data=body,
                                            verify=False)
                logger.debug('Group like: {} does not exist creating, response:{}'.format(group, response))
                logger.debug('Group create url: {}'.format(response.url))
                logger.info('Group Create Response: {}'.format(response.reason))
                logger.info('New group {} now has {} members'.format(group, len(host_id_l)))


def pull_hosts(ip):
    #  Returns a dictionary {'host_id': ['hostname', 'ip']}
    host_dict = {}
    hosts = requests.request("GET", args.cognito_url + cognito_api +
                             '/search/hosts?field=id,name&&query_string=host.last_source:"' +
                             ip + '"', headers=vectra_header, verify=False)
    logging.debug('Pull hosts status: {}, url: {}'.format(hosts.status_code, hosts.url))
    if len(hosts.json()['results']):
        for host in hosts.json()['results']:
            host_dict[host['id']] = list([host['name'], ip])
        logger.debug('pull hosts host_dict: {}'.format(host_dict))
        return host_dict
    else:
        return host_dict


def process_ips():
    #  Returns a list of host dictionaries
    #  Initialize host dictionary
    host_dict = {}
    with open(args.input_file, 'r') as infile:
        for line in infile:
            #  Skip commented lines
            m_comment = re.search(comment_chars_re, line.strip())
            if m_comment:
                logger.info('Ignoring {}'.format(line.strip()))
                pass
            else:
                #  Handle IP ranges
                iprange = re.search('(.*)-(.*)', line.strip())
                ipsubnet = re.search('(.*)/(.*)', line.strip())
                if iprange:
                    logger.debug('IP range: {}'.format(line.strip()))
                    #  IP range
                    ip_1 = str.rsplit(iprange.group(1), '.', 1)
                    ip_2 = str.rsplit(iprange.group(2), '.', 1)
                    if ip_1[0] == ip_2[0]:
                        #  IP range within same /24 subnet
                        ip_1i = int(ip_1[1])
                        ip_2i = int(ip_2[1])
                        while ip_1i <= ip_2i:
                            #  Retrieve list of host containers with IP
                            host = pull_hosts(ip_1[0] + '.' + str(ip_1i))

                            if len(host):
                                for hid, values in host.items():
                                    logger.info('Found container for host: {} ID: {} with IP: {}'.format(
                                        values[0], hid, values[1]))
                                    #  add_host_to_group(args.group, id, values[0], values[1])
                                    host_dict.update(host)
                            else:
                                logger.info('No host container found for IP: {}'.format(ip_1[0] + '.' + str(ip_1i)))
                            ip_1i += 1
                    else:
                        logger.info('IP range not within same class C, ignoring:', line)

                elif ipsubnet:
                    logger.debug('IP subnet: {}'.format(line.strip()))
                    #  Handle IP subnet
                    subnet = ipaddress.IPv4Network(line.strip()).hosts()
                    #  Iterate through IP in subnet
                    for ipv4 in subnet:
                        ip = str(ipaddress.IPv4Address(ipv4))
                        host = pull_hosts(ip)

                        if len(host):
                            for hid, values in host.items():
                                logger.info('Found container for host: {} ID: {} with IP: {}'.format(
                                    values[0], hid, values[1]))
                                #  add_host_to_group(args.group, id, values[0], values[1])
                                host_dict.update(host)
                        else:
                            logger.info('No host container found for IP: {}'.format(ip))

                else:
                    logger.debug('Single IP: {}'.format(line.strip()))
                    host = pull_hosts(line.strip())

                    if len(host):
                        for hid, values in host.items():
                            logger.info('Found container for host: {} ID: {} with IP: {}'.format(
                                values[0], hid, values[1]))
                            #  add_host_to_group(, id, values[0], values[1])
                            host_dict.update(host)
                    else:
                        logger.info('No host container found for IP: {}'.format(line.strip()))
    return host_dict


def main():
    test_creds(args.cognito_url + cognito_api, vectra_header)

    logger.info('Processing IPs in file {}'.format(args.input_file))
    dict_host_dict = process_ips()
    if len(dict_host_dict):
        logger.info('\n\nStarting add hosts to group\n')
        add_host_to_group(args.group, dict_host_dict)
        logger.info('Process complete, exiting.')
    else:
        logger.info('No host containers found, exiting.')


if __name__ == '__main__':
    main()


