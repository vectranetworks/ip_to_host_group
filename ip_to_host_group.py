#!/usr/bin/env python3

__title__ = 'Script to add hosts to a Host Group based on IP'
__version__ = '0.9'
__author__ = 'mp@vectra.ai'
__copyright__ = 'Vectra AI, Inc.'
__status__ = 'Development'

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

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

ch.setFormatter(formatter)
fh.setFormatter(formatter)

logger.addHandler(ch)
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
print('Type args.group: {}'.format(type(args.group)))

vectra_header = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'Authorization': 'Token ' + args.cognito_token
}

cognito_api = '/api/v2/'

#  Lines begging with comment characters are ignored
comment_chars_re = '^[#;\'].*'


def add_host_to_group(group, host_id, hostname, ip):
    #  Adds a list of hosts to a group, creating the group if needed
    host_id_l = [str(host_id)]
    logger.debug('add_host_to_group Group: {}, host_id: {}, hostname: {}, ip: {}'.format(group, host_id_l, hostname, ip))
    body_dict = {
        "name": group,
        "description": "Created by ip_to_host_group script",
        "type": "host",
        "members": host_id_l
    }
    body = json.dumps(body_dict)

    #  Check to see if group already exists
    cognito_group_check_url = args.cognito_url + cognito_api + 'groups/?name=' + group
    group_results = requests.request("GET", url=cognito_group_check_url, headers=vectra_header, verify=False).json()
    logger.debug('Checking if group {} exists.'.format(group))
    logger.debug('Group results:{}'.format(group_results))
    if not group_results:
        #  Group does not exist
        cognito_group_url = args.cognito_url + cognito_api + 'groups/'
        response = requests.request("POST", url=cognito_group_url, headers=vectra_header, data=body, verify=False)
        logger.debug('Group create body: {}'.format(body))
        logger.debug('Group create url: {}'.format(response.url))
        logger.debug('Response: {}'.format(response.reason))
        logger.info('Creating group: [{}], adding host: {} with IP: {}'.format(group, hostname, ip))
        logger.debug('Group: {} does not exist, creating.  Response: {}'.format(group, response))
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
                logger.info('Adding host {} to group: [{}] with IP: {}'.format(hostname, group, ip))
                pre_exist_members.append(host_id)
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
                logger.debug('Response: {}'.format(response.reason))
            else:
                cognito_group_url = args.cognito_url + cognito_api + 'groups/'
                response = requests.request("POST", url=cognito_group_url, headers=vectra_header, data=body,
                                            verify=False)
                logger.debug('Group like: {} does not exist creating, response:{}'.format(group, response))
                logger.debug('Group create url: {}'.format(response.url))
                #  hostnames = poll_vectra_host_names(host_ids)
                logger.info('Creating group: [{}], adding host: {} with IP: {}'.format(group, hostname, ip))


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


def main():
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
                            host_dict = pull_hosts(ip_1[0] + '.' + str(ip_1i))

                            if len(host_dict):
                                for id, values in host_dict.items():
                                    logger.debug('Adding host: {} ID: {} to group: {} with IP: {}'.format(
                                        values[0], id, args.group, values[1]))
                                    add_host_to_group(args.group, id, values[0], values[1])
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
                        host_dict = pull_hosts(ip)

                        if len(host_dict):
                            for id, values in host_dict.items():
                                logger.debug('Adding host: {} ID: {} to group: {} with IP: {}'.format(
                                    values[0], id, args.group, values[1]))
                                add_host_to_group(args.group, id, values[0], values[1])
                        else:
                            logger.info('No host container found for IP: {}'.format(ip))

                else:
                    logger.debug('Single IP: {}'.format(line.strip()))
                    host_dict = pull_hosts(line.strip())

                    if len(host_dict):
                        for id, values in host_dict.items():
                            logger.debug('##Adding host: {} ID: {} to group: {} with IP: {}'.format(
                                values[0], id, args.group, values[1]))
                            add_host_to_group(args.group, id, values[0], values[1])
                    else:
                        logger.info('No host container found for IP: {}'.format(line.strip()))


if __name__ == '__main__':
    main()


