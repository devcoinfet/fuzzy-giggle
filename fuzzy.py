from ipaddress import ip_network, ip_address
import socket
import json
import sys
import re

cloudflare_cidrs = [
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/12',
    '172.64.0.0/13',
    '131.0.72.0/22']


incapsula_cidrs = [
    '199.83.128.0/21',
    '198.143.32.0/19',
    '149.126.72.0/21',
    '103.28.248.0/22',
    '45.64.64.0/22',
    '185.11.124.0/22',
    '192.230.64.0/18',
    '107.154.0.0/16',
    '45.60.0.0/16',
    '45.223.0.0/16']
    
    
def check_flairs(flairs_in):
    detected_flares = []
    for cidr in cloudflare_cidrs:
        net = ip_network(cidr)
        for flair in flairs_in:
            is_cloudflare = ip_address(flair['ip']) in net
            if is_cloudflare:
                print("Cloudflare Ip Detected: " + str(net) + "({},{})".format(flair['ip'], flair['host']))
                detected_flares.append(flair['host'])

    return detected_flares




def check_impervas(incaps_in):
    detected_incaps = []
    for cidr in incapsula_cidrs:
        net = ip_network(cidr)
        for incap in incaps_in:
            is_inapsula = ip_address(incap['ip']) in net
            if is_inapsula:
                print("Incapsula Ip Detected: " + str(net) + "({},{})".format(incap['ip'], incap['host']))
                detected_incaps.append(incap['host'])

    return detected_incaps
    
    
    
def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]

    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)




def detect_cloudflare(hosts_in):
    responding = []
    single_ips = []
    flairs_found = []
    lineList = [line.rstrip('\n') for line in open(hosts_in)]
    print(lineList)
    matching = []
    valid_hosts = []
    for hosts in lineList:
        try:
            host_result = is_valid_hostname(hosts)
            if host_result:
                print(host_result)
                valid_hosts.append(hosts)
            else:
                print("Invalid Hostname")
        except:
            pass

    try:
        for line in valid_hosts:
            try:

                socket.setdefaulttimeout(1.0)
                addr1 = socket.gethostbyname(line)
                print(addr1)
                if addr1:
                    # store info as ip and host
                    ip_info = {}
                    ip_info['ip'] = addr1
                    ip_info['host'] = line
                    print(ip_info)
                    responding.append(ip_info)
                    '''
                    for hosts in responding:
                        known_hosts = hosts
                        contains_dupe_ip = addr1 in known_hosts.values()
                        print("Dupe Ip Detected: "+contains_dupe_ip)
                        if contains_dupe_ip:
                            pass
                        else:
                            responding.append(ip_info)
                    '''
            except Exception as ex:
                pass

    except Exception as ex1:
        print(ex1)
        pass

    try:

        flairs_found = check_flairs(responding)


    except:
        pass

    return flairs_found, responding




       
def flare_fun(hosts_in):
    cloudflares_found, matching = detect_cloudflare(hosts_in)
    matched_hosts = []
    for items in matching:
        tmp = items['host']
        print(tmp)
        matched_hosts.append(tmp)

    unmatched = set(cloudflares_found) ^ set(matched_hosts)
    print("*" * 50)
    print("Not Protected By Cloudflare")
    print("*" * 50)
    print(str(unmatched) + '\n')
    print("*" * 50)
    print("Protected By Cloudflare")
    print("*" * 50)
    print(str(cloudflares_found) + '\n')
    print("*" * 50)
    return unmatched, matched_hosts  # return unmatched and matched cloudflare hosts
    
    
yahoo_hosts = sys.argv[1]
unmatched,matched = flare_fun(yahoo_hosts)
if unmatched:
   discovered_out = open("foundyahoos.txt","a")
   for hosts in unmatched:
       discovered_out.write(str(hosts)+"\n")
   discovered_out.close()
   
