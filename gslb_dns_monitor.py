#!/usr/bin/env python3

from time import sleep
import datetime,logging,dns.resolver

class bcolors:
  WARNING = '\033[91m'
  OK = '\033[92m'
  ENDC = '\033[0m'

############
# Variables
############

# The number of seconds between batches of queries
cycledelay=15

# Enable Logging and set filename
loggingEnabled = True
loggingFilename = "/var/log/gslb_mon.log"

# the root domain name to monitor for NS records
rootDomain = 'example.com'

# the expected list of NS records
expectedNSlist_raw = sorted(['a.iana-servers.net.','b.iana-servers.net.'])

# the list of GSLBs to query for specific records
gslbs = [
    {'name': 'gslb.west.example.net.', 'address': '192.0.9.35'},
    {'name': 'gslb.east.example.net.', 'address': '192.0.9.36'}
]

# generic FQDNs to verify each GSLB is responding
gslb_test_records = ['www.example.com.','example.com.']

# root server A record verification
rootNSServers = [
    {'name': 'a.iana-servers.net.', 'address': '199.43.135.53'},
    {'name': 'b.iana-servers.net.', 'address': '199.43.133.53'}
]

# FQDNs/Wide IPs to poll against each GSLB and expected responses
records = [
    {'hostname': 'www.example.com', 'recordType': 'A', 'expectedResponse': ['93.184.216.34'],'type':'static'},
    {'hostname': 'www.example.com', 'recordType': 'AAAA','expectedResponse': ['2606:2800:220:1:248:1893:25c8:1946'], 'type': 'static'},
]

# Logging file 
if loggingEnabled:
  logging.basicConfig(filename=loggingFilename,level=logging.DEBUG)

def monitoring_sequence():
    print('Starting monitoring sequence at ' + str(datetime.datetime.now()))
    if loggingEnabled:
      logging.info('Starting monitoring sequence at ' + str(datetime.datetime.now()))
    #
    # Set per cycle variables
    #
    sequence_error_count = 0
    #
    # Test each GLB for response
    #
    for current_gslb in gslbs:
        for current_test_record in gslb_test_records:
            dns_query = dns.resolver.Resolver()
            dns_query.timeout = 3.0
            dns_query.lifetime = 3.0
            dns_query.nameservers = [current_gslb['address']]
            if loggingEnabled:
              logging.info(str(datetime.datetime.now()) + ':QUERY: ' + current_test_record + ' @' + current_gslb['name'] + ' (' + current_gslb['address'] + ')')
              logging.info(str(datetime.datetime.now()) + ':QUERY: ' + current_test_record + ' @' + current_gslb['name'] + ' (' + current_gslb['address'] + ')')
            try:
                query_response = dns_query.query(current_test_record)
            except BaseException as response_error:
                print(bcolors.WARNING + str(datetime.datetime.now()) + 'ERROR: Failure ' + current_test_record + ' @' + current_gslb['name'] + ' (' + current_gslb['address'] + ') ' + str(response_error) + ' ' + bcolors.ENDC)
                if loggingEnabled:
                  logging.error(str(datetime.datetime.now()) + 'ERROR: Failure ' + current_test_record + ' @' + current_gslb['name'] + ' (' + current_gslb['address'] + ') ' + str(response_error))
                sequence_error_count += 1

    #
    # Confirm root server resolution hasn't changed
    #
    dns_query = dns.resolver.Resolver()
    dns_query.timeout = 3.0
    dns_query.lifetime = 3.0
    if loggingEnabled:
      logging.info(str(datetime.datetime.now()) + ':QUERY: example.com NS records')
    try:
        query_response = dns_query.query('example.com','NS')
    except dns.exception as response_error:
        print(bcolors.WARNING + str(datetime.datetime.now()) + ':ERROR: Failure ' + str(response_error) + bcolors.ENDC)
        if loggingEnabled:
          logging.error(str(datetime.datetime.now()) + ':ERROR: Failure ' + str(response_error))
        sequence_error_count += 1
    receivedNSlist_raw = []
    for current_response in query_response:
        receivedNSlist_raw.append(str(query_response))
    if sorted(expectedNSlist_raw) == sorted(receivedNSlist_raw):
        if loggingEnabled:
          logging.info(str(datetime.datetime.now()) + ':REPLY: Expected NS list matches received NS list')
    query_response = None
    response_error = None
    current_response = None
    dns_query = dns.resolver.Resolver()
    dns_query.timeout = 3.0
    dns_query.lifetime = 3.0
    if loggingEnabled:
      logging.info(str(datetime.datetime.now()) + ':QUERY: ' + rootDomain + ' type=NS')
    try:
        query_response = dns_query.query(rootDomain,'NS')
    except dns.exception as response_error:
        print(bcolors.WARNING + str(datetime.datetime.now()) + ':ERROR: Failure ' + str(response_error) + ' ' + bcolors.ENDC)
        if loggingEnabled:
          logging.error(str(datetime.datetime.now()) + ':ERROR: Failure ' + str(response_error))
        sequence_error_count += 1
    receivedNSlist_raw = []
    for current_response in query_response:
        receivedNSlist_raw.append(str(query_response))
    if sorted(expectedNSlist_raw) == sorted(receivedNSlist_raw):
        if loggingEnabled:
          logging.info(str(datetime.datetime.now()) + ':REPLY: Successful')
    query_response = None
    response_error = None
    current_response = None
    #
    # Confirm root server records haven't changed
    #
    for current_NS_server in rootNSServers:
        logging.info(str(datetime.datetime.now()) + ':QUERY: ' + current_NS_server['name'] + ' (' + current_NS_server['address'] + ')')
        dns_query = dns.resolver.Resolver()
        dns_query.timeout = 3.0
        dns_query.lifetime = 3.0
        try:
            query_response = dns_query.query(current_NS_server['name'])
        except dns.exception.DNSException as response_error:
            print(bcolors.WARNING + str(datetime.datetime.now()) + 'ERROR: Failure ' + str(response_error) + bcolors.ENDC)
            logging.error(str(datetime.datetime.now()) + 'ERROR: Failure ' + str(response_error))
            sequence_error_count += 1
        if str(query_response[0]) == current_NS_server['address']:
            logging.info(str(datetime.datetime.now()) + ':REPLY: Successful ')
        else:
            print(bcolors.WARNING + str(datetime.datetime.now()) + ':ERROR:' + current_NS_server['name'] + ' no longer resolves to expected IP of ' + current_NS_server['address'] + bcolors.ENDC)
            logging.error(str(datetime.datetime.now()) + ':REPLY: Failure ' + current_NS_server['name'] + ' no longer resolves to expected IP of ' + current_NS_server['address'])
            sequence_error_count += 1
    query_response = None
    response_error = None
    #
    # Check existing public URLs
    #
    for current_record in records:
        query_response = None
        response_error = None
        dns_query = dns.resolver.Resolver()
        dns_query.timeout = 3.0
        dns_query.lifetime = 3.0
        logging.info(str(datetime.datetime.now()) + ':QUERY: ' + current_record['hostname'] + ' ' + current_record['recordType'])
        try:
            query_response = dns_query.query(current_record['hostname'],current_record['recordType'])
        except dns.exception.DNSException as response_error:
            print(bcolors.WARNING + str(datetime.datetime.now()) + ':ERROR: Failure ' + str(response_error) + bcolors.ENDC)
            logging.error(str(datetime.datetime.now()) + ':ERROR: Failure ' + str(response_error))
            sequence_error_count += 1
        receivedAlist = []
        for current_response in query_response:
            receivedAlist.append(str(current_response))
        if sorted(receivedAlist) == sorted(current_record['expectedResponse']):
            logging.info(str(datetime.datetime.now()) + ':REPLY: Successful ' + current_record['hostname'] + ' resolved to ' + str(query_response))
        else:
            print(bcolors.WARNING + str(datetime.datetime.now()) + ':ERROR: Failure for ' + current_record['hostname'] + ' - expected ' + str(current_record['expectedResponse']) + ' and received ' + str(receivedAlist) + bcolors.ENDC)
            logging.error(str(datetime.datetime.now()) + ':ERROR: Failure for ' + current_record['hostname'] + ' - expected ' + str(current_record['expectedResponse']) + ' and received ' + str(receivedAlist))
            sequence_error_count += 1
    #
    #   End the test cycle
    #
    return(sequence_error_count)

while 1 != 0:
    error_count=0
    error_count = monitoring_sequence()
    if error_count == 0:
        print(bcolors.OK + '***********************************\n' + 'Errors during last cycle: ' + str(error_count) + '\n***********************************' + bcolors.ENDC)
    else:
        print(bcolors.WARNING + '***********************************\n' + 'Errors during last cycle: ' + str(error_count) + '\n***********************************' + bcolors.ENDC)
    logging.info('***********************************')
    logging.info('Errors during last cycle: ' + str(error_count))
    logging.info('***********************************')
    print('Sleeping for ' + str(cycledelay) + ' seconds before next cycle')
    sleep(cycledelay)