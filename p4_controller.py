import sys
import argparse
import grpc
import os
import random
import time
import datetime
import json
from scapy.all import sr1, IP, ICMP, sniff, Ether, UDP, send, sendp, RandLong, bind_layers, BitField, Packet, Raw, IEEEDoubleField, TCP
from collections import Counter
import socket
import select
import threading
import crcmod
import ipaddress
import math
import logging
from pathlib import Path

import importlib
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol


sys.path.append('/home/nickjan')

from utils.Event import Event
import utils.p4runtime_lib.bmv2
from utils.p4runtime_lib.error_utils import printGrpcError
from utils.p4runtime_lib.switch import ShutdownAllSwitchConnections
import utils.p4runtime_lib.helper


sys.path.append('/opt/bf-sde-9.7.0/install/lib/python3.6/site-packages/tofino/')

from conn_mgr_pd_rpc.ttypes import *





EID_INACTIVE = 0
EID_ACTIVE = 1
MAX_TTL = 0xffffffff
UDP_PROTO = 17
MAPPING_SYSTEM_UDP_PORT = 4342
SOCKET_BUFFER_SIZE = 196608
LOCALHOST_IP = "127.0.0.1"
CONTROL_PLANE_ACTIVE = False

MAP_REQUEST_EIDS = {}
MAP_CACHE_ENTRIES = {}

CACHED_PACKETS = {}

TOFINO_PORTS = {}


# Use arg parse to set lisp site
parser = argparse.ArgumentParser(description='LISP P4Runtime Controller')
parser.add_argument('-c', '--config', help='Path to Config File', type=str, default="config/s1.json", action="store")
parser.add_argument('-l', '--log_path', help='Filepath to logile', type=str, default="", action="store")
args = parser.parse_args()


NODE_BEHIND_NAT_UDP_SRC_PORT = random.randint(0, 65535)

with open(args.config) as config_json:
    configuration = json.load(config_json)

    xTR_NAME = configuration["switch_name"]
    CONTROLLER_INTERFACE = configuration["controller_interface"]
    KOWN_SRC_EIDS = configuration["known_src_eids"]
    SWITCH_ENCAPSULATED_IP = configuration["encapsulation_ip"]
    gRPC_PORT = configuration["port"]
    DEVICE_ID = configuration["device_id"]
    LISPERS_CONNECTION = configuration["lispers_connection"].lower()
    if LISPERS_CONNECTION == "unix":
        LISPERS_PATH = configuration["lispers_path"]
    elif LISPERS_CONNECTION == "udp":
        LISPERS_CONTAINER_IP = configuration["lispers_container_ip"]
        LISPERS_CONTAINER_PORT = configuration["lispers_container_port"]
        LISPERS_DATAPLANE_PORT = configuration["lispers_dataplane_port"]
    INSTANCE_ID = configuration["instance_id"]
    HOME_DIRECTORY = configuration["home_directory"]
    P4INFO_FILE_PATH = configuration["p4info_file_path"]
    BMV2_JSON_FILE_PATH = configuration["bmv2_file_path"]
    CHANNEL = configuration["channel_tofino"]
    USED_PORTS = configuration["used_ports"]
    TABLE_ENTRIES = configuration["table_entries"]
    TOFINO_CONFIG = configuration["tofino_config"]
    PROGRAM_NAME = configuration["program_name"]
    BIN_FILE_PATH = configuration["bin_file_path"]
    LISP_NODE_TYPE = configuration["lisp_node_type"].lower()
    STANDARD_PETR = configuration["standard_petr"]
    NATIVELY_FORWARD_PORT = configuration["natively_forward_port"]
    INNER_PORTS = configuration["inner_ports"]
    PIPELINES = configuration["pipelines"]
    LISP_ADDRESS_SPACES = []
    LISP_ADDRESS_SPACES_JSON_ARRAY = configuration["LISP_address_spaces"]

    STANDARD_LOOPBACK_PORT = configuration["standard_loopback_port"]
        

    # LISP-NAT
    LISP_NAT = configuration["LISP-NAT"]
    PREFIXES_LISP_R = configuration["prefixes_LISP-R"]
    CURRENT_LISP_R_PREFIX = ""
    if LISP_NAT and len(PREFIXES_LISP_R > 0):
        CURRENT_LISP_R_PREFIX = PREFIXES_LISP_R[0]
    NEXT_LISP_R = ""
    CURRENT_LISP_R_PREFIX_NETWORK = None
    CURRENT_LISP_R_HOSTS = []
    PREFIXES_LISP_R_INDEX = 0
    LISP_NAT_EIDS = {}
    
    print("config loaded")

path_to_logfile = args.log_path
current_log_directory = path_to_logfile.replace("\\", "/").rsplit("/", 1)[0] + "/" # Remove file name from path

if path_to_logfile == "":

    # Use start time to organize log files
    start_time = datetime.datetime.now()
    formated_start_time_string = start_time.strftime("%Y-%m-%d_%H-%M-%S")

    # Get config file name
    # Split filepath along slashes, continue with last item (filename) - then remove file extension
    config_name_with_file_extension = (args.config).replace("\\", "/").split("/")[-1]
    config_name = config_name_with_file_extension.split(".", 1)[0]

    current_log_directory = HOME_DIRECTORY + "evaluation/logs/p4_controller/" + config_name + "/"
    path_to_logfile =  current_log_directory + formated_start_time_string + ".log"
    
print("Logfile: " + path_to_logfile)
Path(current_log_directory).mkdir(parents=True, exist_ok=True)
logging.basicConfig(filename=path_to_logfile, filemode='w', level=logging.DEBUG, format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',datefmt='%Y-%m-%d,%H:%M:%S')


class ThriftConnection:
    def __init__(self):
        self.transport = TTransport.TBufferedTransport(TSocket.TSocket("localhost", 9090))
        self.protocol = TBinaryProtocol.TBinaryProtocol(self.transport)
        self.conn_mgr_client_module = importlib.import_module(".".join(["conn_mgr_pd_rpc", "conn_mgr"]))
        self.conn_mgr_protocol = self.conn_mgr_protocol = TMultiplexedProtocol.TMultiplexedProtocol(self.protocol, "conn_mgr")
        self.conn_mgr = self.conn_mgr_client_module.Client(self.conn_mgr_protocol)

        self.transport.open()

        self.hdl = self.conn_mgr.client_init()

    def end(self):
        self.conn_mgr.client_cleanup(self.hdl)

class PortConfig():

    def __init__(self, thrift_con=None):
        self.pal_protocol = TMultiplexedProtocol.TMultiplexedProtocol(thrift_con.protocol, "pal")
        self.pal_client_module = importlib.import_module(".".join(["pal_rpc", "pal"]))
        self.pal = self.pal_client_module.Client(self.pal_protocol)


    # speed 7 for 100G and speed 3 for 25G, 2 for 10G
    def setPorts(self, data=None):
        for config in data:
            p_id = self.pal.pal_port_front_panel_port_to_dev_port_get(0, config['port'], config['channel'])
            self.pal.pal_port_add(0, p_id, config['speed'], 0)
            self.pal.pal_port_an_set(0, p_id, 2)
            self.pal.pal_port_enable(0, p_id)
            
            if 'loopback' in config and config['loopback']:
                self.pal.pal_port_loopback_mode_set(0, p_id, 1)



# Link Map Request to UDP source port of mapping system
class CPU(Packet):
    name = "CPU Header"
    fields_desc = [
        BitField("relevant_port", 0, 9), 
        # BitField("padding", 0, 7) # use one bit for recirculation info
        BitField("already_recirculated", 0, 1), 
        BitField("padding", 0, 6)
    ]

    def guess_payload_class(self, payload):
        return Ether

class Timestamp_header(Packet):
    name = "Timestamp"
    fields_desc=[ IEEEDoubleField("timestamp_field", 0) ]


bind_layers(CPU, Ether)
bind_layers(TCP, Timestamp_header, dport=22222)
bind_layers(Timestamp_header, Raw)


class MessageInHandler:

    @staticmethod
    def message_in(*args, **kwargs):
        print("\n\n-- is it ethernet? --")
        logging.debug("-- is it ethernet? --")

        packet = kwargs.get('packet')
        sw = kwargs.get('switch')

        current_time = time.time()
        time_str = datetime.datetime.fromtimestamp(current_time).strftime("%Y-%m-%d %H:%M:%S.%f")
        print("current time: " + str(current_time) + " -> " + time_str)
        logging.debug("current time: " + str(current_time) + " -> " + time_str)

        try:
            pkt = CPU(packet.packet.payload[:2]) # Read first two bytes from packet
            eth = Ether(packet.packet.payload[2:])

            # For latency testing: Check if a timestamp is in packet, if so log it
            if Timestamp_header in eth:
                float_timestamp = float(eth[Timestamp_header].timestamp_field)
                date_time = datetime.datetime.fromtimestamp(float_timestamp)
                readable_time_str = date_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                print("float: " + str(float_timestamp))
                logging.debug("float: " + str(float_timestamp))
                print("Timestamp in packet: " + str(date_time))
                logging.debug("Timestamp in packet: " + str(date_time))

            process_packet_from_switch(eth, pkt)
            print("-- end ethernet (port was " + str(int(pkt.relevant_port)) + ") --\n\n")
            logging.debug("-- end ethernet (port was " + str(int(pkt.relevant_port)) + ") --")

        except Exception as e:  # it's not an ethernet frame
            print("\n-- wasn't ethernet --\n\n")
            logging.debug("-- wasn't ethernet --")
            print(str(e))
            logging.debug("exception: " + str(e))
            print(str(packet))
            logging.debug(str(packet))
            pass


Event.activate()
Event.on("packet_in", MessageInHandler.message_in)

# Instantiate a P4Runtime helper from the p4info file
P4INFO_HELPER = utils.p4runtime_lib.helper.P4InfoHelper(P4INFO_FILE_PATH)


# Create a switch connection object for switch;
# this is backed by a P4Runtime gRPC connection.
# Also, dump all P4Runtime messages sent to switch to given txt files.
switch = utils.p4runtime_lib.switch.SwitchConnection(
    name=xTR_NAME,
    address='127.0.0.1:' + str(gRPC_PORT),
    device_id=DEVICE_ID,
    proto_dump_file='logs/' + xTR_NAME + '-ctr-p4runtime-requests.txt')

switch.start_thread()

PENDING_MAP_REQUESTS = {}
ENTRIES = {}
RLOC_WEIGHT_RANGES = {}
LLOC_MAP_REQUEST = {}

def get_field_bytes(pkt, name):
     fld, val = pkt.getfield_and_val(name)
     return fld.i2m(pkt, val)

def writeInitialEntries(entries):

    for entry in entries:

        match_field_types = entry['match_field_type']
        match_fields = {}
        priority = entry.get("priority", None)

        range_array = []
        range_key = ""

        # Iterate over keys in match dictionary while getting the current index for the match_field_types array
        for index, key in enumerate(entry['match'].keys()):
          
            match_field_value = entry['match'][key]

            if match_field_types[index] == "prefix":
                match_fields[key] = (match_field_value["eid"], match_field_value["mask"])
                range_key = match_field_value["eid"] + "/" + str(match_field_value["mask"])
            elif match_field_types[index] == "ipv4":
                match_fields[key] = match_field_value["ipv4"]
            
            elif match_field_types[index] == "ternary":
                match_fields[key] = (match_field_value["value"], match_field_value["mask"])
                range_array.insert(0, match_fields[key])

            elif match_field_types[index] == "range":
                match_fields[key] = (match_field_value["low"], match_field_value["high"])
                range_array.insert(0, match_fields[key])
            
            elif match_field_types[index] == "port":
                # Convert normal ports into tofino ports
                match_fields[key] = TOFINO_PORTS[match_field_value["port"]]
    
        
        action_params = {}

        for key in entry['action_params'].keys():

            value = entry['action_params'][key]

            # Convert normal ports into tofino ports
            if key == "port":
                value = TOFINO_PORTS[value]

            action_params[key] = value

        # If we have multiple destinations (weighted) for one destination eid prefix, we have to store the used ranges
        # Else we would need to iterate through all Entries to find all to remove them after their ttl
        if len(range_array) > 0:
            RLOC_WEIGHT_RANGES[range_key] = range_array

        add_table_entry(table_name=entry['table'], match_field_types=match_field_types, match_fields=match_fields, action_name=entry['action_name'], action_params=action_params, priority=priority, print_debug=False)

    print("Initial entries written")
    logging.info("Initial entries written")


def adaptSwitchForNodeType(node_type):
    if node_type == "pxtr":
        change_default_action(table_name="SwitchIngress.allowed_prefixes_lpm", action_name="NoAction")
        change_default_action(table_name="SwitchIngress.valid_lisp_destinations_lpm", action_name="NoAction")

    # PITR checks destination address if EID for an advertised prefix
    elif node_type == "pitr":
        change_default_action(table_name="SwitchIngress.allowed_prefixes_lpm", action_name="NoAction")

    # PETR checks inner source EID if it comes from a configured LISP site
    # RTR checks if it knows either src or dst (allowed prefix with drop, valid dst can use pick_up action)
    elif node_type == "petr" or node_type == "rtr":
        change_default_action(table_name="SwitchIngress.valid_lisp_destinations_lpm", action_name="NoAction")
    
    print("LISP node: " + node_type)
    logging.info("LISP node: " + node_type)


def process_packet_from_switch(packet, cpu_packet):

    src_eid = packet[0][1].src
    dst_eid = packet[0][1].dst
    ingress_port = cpu_packet.relevant_port
    lloc = dst_eid in LLOC_MAP_REQUEST

    print("from " + src_eid + " to " + dst_eid)
    logging.info("from " + src_eid + " to " + dst_eid)


    dst_eid_dictionary_value = KOWN_SRC_EIDS.get(dst_eid)
    dst_eid_is_not_registered = dst_eid_dictionary_value is None or dst_eid_dictionary_value == EID_INACTIVE

    if dst_eid_is_not_registered and LISP_NODE_TYPE != "petr" :
        print("dst not in known_src -> outside of lisp site -> map request")
        logging.info("dst not in known_src -> outside of lisp site -> map request")
        send_map_request(src_eid, dst_eid, ingress_port, lloc)
    elif LISP_NODE_TYPE != "petr":
        print("dst is known -> map cache timed out -> map request")
        logging.info("dst is known -> map cache timed out -> map request")
        send_map_request(src_eid, dst_eid, ingress_port, lloc)
    else:
        print("interesting else case")
        logging.info("interesting else case")

    sys.stdout.flush()


    # Create tuple of Src/Dst in sorted order
    key = tuple(sorted([src_eid, dst_eid]))
    packet_counts.update([key])

    packet_description = "Packet " + str(sum(packet_counts.values())) + ": " + str(src_eid) + " ==> " + str(dst_eid)
    return packet_description

   
def send_map_request(src_eid, dst_eid, ingress_port, lloc=False):

    #print("Send Map Request")
    #logging.debug("Send Map Request")
    global CONTROL_PLANE_ACTIVE

    if str(dst_eid) not in MAP_REQUEST_EIDS:

        eid_discovery_message = '{ "type" : "discovery", "source-eid" : "' + str(src_eid) + '", "dest-eid": "' + str(dst_eid) + '", "interface" : "' + str(ingress_port) + '", "instance-id" : "' + str(INSTANCE_ID) + '"}'

        bytesToSend = str.encode(eid_discovery_message)

        # Send to socket on container (which gets forwarded there to the unix socket)
        # Or directly to unix socket
        if LISPERS_CONNECTION == "unix":
            send_to_Lispers_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            server_address = LISPERS_PATH + "/lispers.net-itr"
        else:
            send_to_Lispers_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_address = (LISPERS_CONTAINER_IP, LISPERS_DATAPLANE_PORT)

        timestamp = str(time.time())
        print("Write to socket at " + timestamp)
        logging.debug("Write to socket at " + timestamp)
        if CONTROL_PLANE_ACTIVE:
            send_to_Lispers_socket.sendto(bytesToSend, server_address)
        elif os.path.exists(server_address):
            CONTROL_PLANE_ACTIVE = True
            send_to_Lispers_socket.sendto(bytesToSend, server_address)

        # Add map request for dst_eid with deadline in one second and not already answered
        MAP_REQUEST_EIDS[str(dst_eid)] = {"deadline": time.time()+1, "already_answered": False, "src_eid": str(src_eid), "ingress_port": ingress_port, "lloc": lloc, "pipeline_loopback_port": get_lb_for_pipeline(ingress_port)}
    

    else:
        print("Map Request for " + str(dst_eid) + " not sent since it has already one running from " + str(MAP_REQUEST_EIDS[str(dst_eid)]))
        logging.info("Map Request for " + str(dst_eid) + " not sent since it has already one running from " + str(MAP_REQUEST_EIDS[str(dst_eid)]))




def delete_table_entry(table_name, match_field_types, match_fields, priority=None, remove_from_dict=True):

    try:

        table_entry = P4INFO_HELPER.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            priority=priority
        )

        switch.DeleteTableEntry(table_entry)

        # Delete linked entries (e.g. ipv4 for encapsulation)
        linked_entries = ENTRIES[table_name+";"+str(match_fields)]["linked_entries"]

        for entry_name in linked_entries:
            entry = ENTRIES[entry_name]
            table_entry = P4INFO_HELPER.buildTableEntry(
                table_name=entry["table_name"],
                match_fields=entry["match_fields"],
                priority=entry.get("priority", None))
            switch.DeleteTableEntry(table_entry)

            if remove_from_dict:
                del ENTRIES[entry_name]

        if remove_from_dict:
            del ENTRIES[table_name+";"+str(match_fields)]

        print("Delete rule on %s" % switch.name)
        logging.info("Delete rule on %s" % switch.name)

    except grpc.RpcError as e:
        printGrpcError(e)
        print("Entry: " + str(table_name) + ", " + str(match_field_types) + ", " + str(match_fields))
        logging.info("Entry: " + str(table_name) + ", " + str(match_field_types) + ", " + str(match_fields))


# Expects a P4INFO_HELPER match_fields and action dictionary and writes it to the switch
def add_table_entry(table_name, match_field_types, match_fields, action_name, action_params, priority=None, action_type="add", print_debug=True, linked_entries=""):

    match_fields_str = str(match_fields)

    try:

        table_entry = P4INFO_HELPER.buildTableEntry(
            table_name=table_name,
            match_fields=match_fields,
            action_name=action_name,
            action_params=action_params,
            priority=priority
        )
        
        if action_type=="modify":
            switch.ModifyTableEntry(table_entry)
        else:
            switch.WriteTableEntry(table_entry)

        # A table entry is identified by match fields and priority
        entry_key = table_name+";"+match_fields_str
        ENTRIES[entry_key] = {
            "table_name": table_name, "match_field_types": match_field_types, 
            "match_fields": match_fields, "action_name": action_name, 
            "action_params": action_params, "priority": priority, "linked_entries": linked_entries
        }
        
        if print_debug:
            timestring = "Wrote entry on " + switch.name + " at " + str(time.time())
            print(timestring)
            logging.debug(timestring)

        return entry_key

    except grpc.RpcError as e:
        printGrpcError(e)
        logging.info(str(e))
        print("Entry: " + str(table_name) + ", " + match_fields_str)
        logging.info("Entry: " + str(table_name) + ", " + match_fields_str)

        return ""


# Change the default action of a table to the passed action
def change_default_action(table_name, action_name):

    table_entry = ""

    table_entry = P4INFO_HELPER.buildTableEntry(
                table_name=table_name,
                match_fields={},
                action_name=action_name,
                default_action=True
            )

    switch.ModifyTableEntry(table_entry)

    
# Initiate the map cache based on the entire-map-cache message from control plane
# E.g. {'type': 'entire-map-cache', 'entries': [{'opcode': 'add', 'type': 'map-cache', 'instance-id': '0', 
# #        'rlocs': [{'priority': '0', 'rloc': '15.15.1.4', 'port': '55735', 'weight': '0'}], 'eid-prefix': '10.1.0.0/16'}]}
def initiate_entire_map_cache(json_message):
    for entry in json_message["entries"]:
        if entry["opcode"] == "add":
            add_map_cache_entry(entry)

# Get the next LISP-R EID for LISP-NAT
def get_next_lisp_r():
    global PREFIXES_LISP_R
    global PREFIXES_LISP_R_INDEX
    global CURRENT_LISP_R_PREFIX_NETWORK
    global CURRENT_LISP_R_HOSTS
    global NEXT_LISP_R

    next_eid = next(CURRENT_LISP_R_HOSTS, "")

    if next_eid == "":
        PREFIXES_LISP_R_INDEX = PREFIXES_LISP_R_INDEX + 1
        if PREFIXES_LISP_R_INDEX < len(PREFIXES_LISP_R):
            CURRENT_LISP_R_PREFIX = PREFIXES_LISP_R[PREFIXES_LISP_R_INDEX]
            CURRENT_LISP_R_PREFIX_NETWORK = ipaddress.ip_network(CURRENT_LISP_R_PREFIX)
            CURRENT_LISP_R_HOSTS = CURRENT_LISP_R_PREFIX_NETWORK.hosts()

            next_eid = next(CURRENT_LISP_R_HOSTS, "")
        else:
            print("All LISP-NAT EIDs are exhausted")
            logging.info("All LISP-NAT EIDs are exhausted")
            PREFIXES_LISP_R_INDEX = 0
            LISP_NAT_EIDS = {}
            return get_next_lisp_r()

    return next_eid



# Add a new map cache entry to the switch
def add_map_cache_entry(json_message):

    eid_prefix_mask = json_message["eid-prefix"]
    prefix_array = eid_prefix_mask.split("/")

    locator_array = []

    # Check if eid is ipv4
    if "." not in prefix_array[0]:
        print(eid_prefix_mask + " is ipv6 -> skip")
        return

    # Convert multicast rles to a rloc array with identical weights
    if prefix_array[0].startswith("224."):
        print("map-reply for multicast destination")
        logging.info("map-reply for multicast destination")
        rle_array = json_message["rles"]

        if len(rle_array) == 0:
            print("rle array empty -> skip")
            logging.info("rle array empty -> skip")
            return
            
        rle_weight = 100/len(rle_array)
        for rle_entry in rle_array:
            locator_array.append({"rloc": rle_entry["rle"], "priority": 1, "weight": rle_weight})

    else:
        locator_array = json_message["rlocs"]

    range_array = []

    action_type="add"
    entry_key = ""
    
    # If the current entry already exists, go to next entry
    if eid_prefix_mask in RLOC_WEIGHT_RANGES:
        print("Entry already exists - use modify")
        logging.info("Entry already exists - use modify")
        action_type="modify"


    # If the LISP node has sth to do with nat traversal, either the source or destiantion udp port have to be changed
    port_type = 0
    udp_port = 0 # Is ignored in P4 program for port type 0


    # If more then one RLOC is in routing info, add multiple entries with a range according to the weights
    if len(locator_array) > 0:

        # Use only entries with relevant priority
        
        control_priority = locator_array[0]["priority"]
        relevant_entry_counter = 0

         # Look for smallest priority in entries and count simultaniously the relevant entries with the smalles priority
        for rloc_entry in locator_array:

            current_priority = rloc_entry["priority"]

            # If the current priority is smaller than the stored one, overwrite it and reset the counter to one
            if control_priority > current_priority:
                control_priority = current_priority
                relevant_entry_counter = 1
            # If the current priority is the same as the stored one, add entry to counter
            elif control_priority == current_priority:
                relevant_entry_counter += 1


        range_low = 0
        range_high = -1

        for current_index, rloc_entry in enumerate(locator_array):

            # Only look at entries with highest priority -> lowest value for priority
            if rloc_entry["priority"] != control_priority:
                continue

            if "port" in rloc_entry:
                # Change the udp source port if it is a xTR behind a NAT
                if LISP_NODE_TYPE != "rtr":
                    port_type = 1
                    udp_port = NODE_BEHIND_NAT_UDP_SRC_PORT
                # Change the udp destination port if lisp node is a RTR which wants to send to a ETR behind a NAT
                else:
                    # if dst port is 4341, no NAT to destination -> random src port, 4341 as destination port
                    if int(rloc_entry["port"]) != 4341: 
                        port_type = 2
                        udp_port = int(rloc_entry["port"])

            
            rloc = rloc_entry["rloc"]
            weight = float(rloc_entry["weight"])

            # For RTRs the "default" entry should be changed to an encapsulation to the RTRs
            # In these cases the priority is set to 254 (very small priority -> only gets match if no better entry)
            # and the weight is set to 0 for all rloc entries
            if weight == 0:
                weight = 100.0/relevant_entry_counter 

            # Since the weight range on P4 switch is 0-127, weights have to be modified slightly
            # For now: Just round down all weights and add rest of the range to last entry
            range_low = range_high + 1
            range_high = int(range_low + math.floor(weight*1.28)) - 1

            # Priority in p4 entry is for us irrelevant, we don't use overlapping ranges [-> just use first entry gets highest priority] 
            priority = 254 - current_index  


            # Add rest of range (resulting from rounding down) to last rloc
            if current_index == len(locator_array) - 1:
                range_high = 127        

            match_fields = {
                "hdr.ipv4.dstAddr": (prefix_array[0], int(prefix_array[1])),
                "ig_md.rnd_load_balance_group": (range_low, range_high)
            }

            # If destination doesn't matter, omit field for "don't care" representation
            if int(prefix_array[1]) == 0:
                del match_fields["hdr.ipv4.dstAddr"]

            range_array.insert(0, match_fields["ig_md.rnd_load_balance_group"])

            action_params={
                "switch_src": SWITCH_ENCAPSULATED_IP,
                "switch_dst": rloc,
                "udp_port_type": port_type, 
                "udp_port": udp_port
            }

            
            timestamp_str = "Knowing what entry to add at " + str(time.time())
            print(timestamp_str)
            logging.debug(timestamp_str)

            entry_key = add_table_entry(table_name="SwitchIngress.encapsulate_lpm", match_field_types=["prefix", "range"], 
                                    match_fields=match_fields, priority = priority,
                                    action_name="SwitchIngress.encapsulate_packet", action_params=action_params, action_type=action_type)

            print("Installed rule on %s" % switch.name)
            logging.debug("Installed rule on %s" % switch.name)

            
            # detect if answer is a LLOC (LISP address)
            # if so, add ipv4 entry with recirculation port in map-reply function
            ipv4_address_eid = ipaddress.IPv4Address(rloc)
            for current_address_space in LISP_ADDRESS_SPACES:
                if ipv4_address_eid in current_address_space:

                    LLOC_MAP_REQUEST[rloc] = prefix_array[0]
                    print("RLOC is an LLOC")
                    logging.debug("RLOC is an LLOC")
                    break

    else:
        print("locator array empty - send to petr or natively forward")
        logging.info("locator array empty - send to petr or natively forward")

        # If no standard PETR is configured, natively forward the packet through a port
        if STANDARD_PETR == "" and not LISP_NAT:
            table_name = "SwitchIngress.ipv4_lpm"
            match_field_types = ["prefix"],
            match_fields = {"hdr.ipv4.dstAddr": (prefix_array[0], int(prefix_array[1]))}
            action_name = "SwitchIngress.forward_natively"
            action_params = {
              "port": TOFINO_PORTS[NATIVELY_FORWARD_PORT]
            }
            priority = None
            
            timestamp_str = "locator array empty - natively forward at " + str(time.time())
            print(timestamp_str)
            logging.debug(timestamp_str)

            entry_key = add_table_entry(table_name=table_name, match_field_types=match_field_types, match_fields=match_fields, priority = priority, 
                action_name=action_name, action_params=action_params, action_type=action_type)

        # If LISP-NAT functionality should be used  
        elif LISP_NAT:
            # Get EID which issued Map-Request
            src_eid = MAP_REQUEST_EIDS[prefix_array[0]]["src_eid"]

            # If source EID doesn't have already a
            if src_eid not in LISP_NAT_EIDS:
    
                # Get next LISP-R EID
                lisp_r_eid = get_next_lisp_r()

                add_table_entry(table_name="SwitchIngress.replace_source_address_exact", match_field_types=["ipv4"], match_fields={"hdr.ipv4.srcAddr": src_eid}, priority = None, 
                    action_name="SwitchIngress.replace_source_address", action_params={"new_source": lisp_r_eid}, action_type=action_type)
                entry_key = add_table_entry(table_name="SwitchIngress.replace_destination_address_exact", match_field_types=["ipv4"], match_fields={"hdr.ipv4.dstAddr": lisp_r_eid}, priority = None, 
                    action_name="SwitchIngress.replace_destination_address", action_params={"new_destination": src_eid}, action_type=action_type)

                LISP_NAT_EIDS[lisp_r_eid] = src_eid
                LISP_NAT_EIDS[src_eid] = lisp_r_eid


        # Else a PETR is configured and we send packets to this destination through it
        else:
            table_name = "SwitchIngress.encapsulate_lpm"
            match_field_types=["prefix", "range"]
            match_fields = {
                "hdr.ipv4.dstAddr": (prefix_array[0], int(prefix_array[1])),
                "ig_md.rnd_load_balance_group": (0, 127)
            }
            action_name = "SwitchIngress.set_outgoing_port"
            action_params={
                "switch_src": SWITCH_ENCAPSULATED_IP,
                "switch_dst": STANDARD_PETR
            }
            priority = 1
        
            entry_key = add_table_entry(table_name=table_name, match_field_types=match_field_types, match_fields=match_fields, priority = priority, 
                action_name=action_name, action_params=action_params, action_type=action_type)


    # If we have multiple destinations (weighted) for one destination eid prefix, we have to store the used ranges
    # Else we would need to iterate through all Entries to find all to remove them after their ttl
    if len(range_array) > 0:
        RLOC_WEIGHT_RANGES[eid_prefix_mask] = range_array

    return entry_key
        


# Return the loobpack port for the pipeline on which the map-request was triggered
def get_lb_for_pipeline(ingress_port):
    global PIPELINES

    #print("pipelines - ingress port: " + str(ingress_port))
    return 0 #TOFINO_PORTS[29]
    #for key in PIPELINES:
    #    #print("key: " + str(key))
    #    #print("port range: " + str(PIPELINES[key]["port_range"][0]) + str(PIPELINES[key]["port_range"][1]))
    #    if PIPELINES[key]["port_range"][0] <= ingress_port and PIPELINES[key]["port_range"][1] >= ingress_port:
    #        print("loopback port: " + str(PIPELINES[key]["loopback_ports"][0]))
    #        return PIPELINES[key]["loopback_ports"][0]



# Delete a table entry if the ttl expired and the control plane has sent the corresponding message
def delete_map_cache_entry(json_message):

    global ENTRIES
    global RLOC_WEIGHT_RANGES
    table_name = "SwitchIngress.encapsulate_lpm"
    match_field_types = ["prefix", "range"]

    eid_prefix_mask = json_message["eid-prefix"]
    prefix_array = eid_prefix_mask.split("/")

    # Get all used ranges for this entry which correspond to the different RLOCs for load balancing
    used_ranges_for_rloc = RLOC_WEIGHT_RANGES.get(eid_prefix_mask, None)

    if used_ranges_for_rloc == None:
        print("entry doesn't exist, return")
        logging.info("entry doesn't exist, return")
        return

    match_fields = {
        "hdr.ipv4.dstAddr": (prefix_array[0], int(prefix_array[1])),
        "ig_md.rnd_load_balance_group": ()
    }

    # Iterate over all different ranges and remove them
    # Change load balance group in Dictionary according to current entry and remove it
    for range_weight_tuple in used_ranges_for_rloc:
        
        match_fields["ig_md.rnd_load_balance_group"] = range_weight_tuple
        entry = ENTRIES[table_name+";"+str(match_fields)]
        priority = entry.get("priority", None)

        delete_table_entry(table_name=table_name, match_field_types=match_field_types, match_fields=match_fields, priority=priority, remove_from_dict=True)

    del RLOC_WEIGHT_RANGES[eid_prefix_mask]
    
    print("Map Cache entry for " + eid_prefix_mask + " deleted")
    logging.info("Map Cache entry for " + eid_prefix_mask + " deleted")
    sys.stdout.flush()
    

# Check for which eids map requests are reallowed
def check_reallowance_of_map_requests():

    current_thread = threading.currentThread()
    
    while getattr(current_thread, "do_run", True): #True:
        
        # In seconds (could use time_ns for nanoseconds, but 10^9 is one second -- maybe too precise)
        start_timestamp = time.time() 
        
        # List of keys which should be removed from dictionary
        to_delete_keys = []

        # Iterate every half second over all map request entries (only requests from one second 
        # --> mass should't be a problem
        keys = list(MAP_REQUEST_EIDS.keys()) # get a list, not a reference
        for key in keys:

            request_entry = MAP_REQUEST_EIDS[key]

            # Deadline of one second and if a map reply has been received stored as tuple in dictionary
            prefix_str = key
            deadline = request_entry["deadline"]
            map_request_answered = request_entry["already_answered"]
            src_eid = request_entry["src_eid"]
            ingress_port = request_entry["ingress_port"]
            lloc = request_entry["lloc"]
            pipeline_loopback_port =  request_entry["pipeline_loopback_port"]

            # If the map request wasn't already answered and the deadline is exceeded:
            # Reallow Map-Requests for this destination eid
            if deadline <= time.time() and not map_request_answered:
                reallow_map_request(prefix_str, pipeline_loopback_port)
                to_delete_keys.append(prefix_str)
            
            # Delete entries which got map replies
            if map_request_answered:
                to_delete_keys.append(prefix_str)

        # Not allowed to change dictionary length while iterating over it
        # --> Remove entries in second loop
        for key in to_delete_keys:
            del MAP_REQUEST_EIDS[key]

        # Reset list of keys which should be removed
        to_delete_keys = []

        # Check evey tenth of a second if some entries have to change
        time.sleep(0.2)

    print("Map Request thread ended")


def reallow_map_request(eid, pipeline_port=0):

    print("Reallow map request for " + str(eid))

    src_eid = "0.0.0.0" # Doesn't matter, gets ignored in p4 program
    dst_eid = eid # Which eid should be reallowed to be issued in a map request
    mac_src = "b8:59:9f:e2:0b:46" # Doesn't matter, gets ignored  
    mac_dst = "b8:59:9f:e2:0b:46" # Doesn't matter, gets ignored 

    # If no pipeline port is specified, use directly pipeline of cpu port
    use_cpu_pipeline = (pipeline_port == 0)

    register_control_packet = CPU(relevant_port=pipeline_port, already_recirculated=use_cpu_pipeline)/Ether(src=mac_src, dst=mac_dst)/IP(src=src_eid, dst=dst_eid)/ICMP(type=8, code=0)
    # relevant_port=TOFINO_PORTS[1] to send packet out of tofino

    switch.send_packet_out(payload=bytes(register_control_packet))

    # Set boolean answered to true
    entry = MAP_REQUEST_EIDS[eid]
    entry["already_answered"] = True
    MAP_REQUEST_EIDS[eid] = entry 



# Go through pending map requests and check if they were answered with the current reply
def replied_map_requests_with_prefix(eid_prefix, entry_key=""):

    keys = list(MAP_REQUEST_EIDS.keys())
    for eid_str in keys:
        try:
            request_entry = MAP_REQUEST_EIDS[eid_str]
        except Exception as e:
            print("entry was deleted")
            continue
        if ipaddress.IPv4Address(eid_str) in ipaddress.IPv4Network(eid_prefix):
            # Reallow map request in case map cache entry times out and the entry in the register has not been overwritten by another entry.
            # This would prevent a new map request.
            pipeline_loopback_port = get_lb_for_pipeline(request_entry["ingress_port"])
            reallow_map_request(eid_str, pipeline_loopback_port)  

            # If reply was for LLOC, add it in forwarding table with recirculation port as exit (second encapsulation on recirculation)
            if request_entry["lloc"]:
                eid_prefix_mask = eid_str
                prefix_array = eid_prefix_mask.split("/")

                ipv4_entry_key = add_table_entry(
                            table_name="SwitchIngress.ipv4_lpm", match_field_types=["prefix"], 
                            match_fields={"hdr.ipv4.dstAddr": (prefix_array[0], int(prefix_array[1]))}, priority = 1,
                            action_name="SwitchIngress.set_outgoing_port", 
                            action_params={"port": STANDARD_LOOPBACK_PORT}, action_type="add")

                ENTRIES[entry_key]["linked_entries"] = ipv4_entry_key

            # Set boolean answered to true
            request_entry["already_answered"] = True
            MAP_REQUEST_EIDS[eid_str] = request_entry



def read_lispers_messages(lispers_connection="", address="", container_port="", container_ip="", dataplane_port=""):

    
    current_thread = threading.currentThread()

    # cache for map cache message (only execute on message after etr nat port is known)
    entire_map_cache_message = ""

    ## Sockets for communicating with Lispers.net
    if lispers_connection == "unix":
        lispers_path = address
        receive_from_Lispers_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        send_to_Lispers_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server_address_rec = lispers_path + "/lisp-ipc-data-plane"
        server_address_send = lispers_path + "/lispers.net-itr"
    else:
        # Listen to the UDP socket on localhost for messages from Lispers.net
        localhost_ip = address
        receive_from_Lispers_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_to_Lispers_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address_rec = (localhost_ip, container_port)
        server_address_send = (container_ip, dataplane_port)

    try:
        print("server_address_receive: " + str(server_address_rec))
        logging.debug("server_address_receive: " + str(server_address_rec))


        if lispers_connection == "unix" and os.path.exists(server_address_rec):
            os.unlink(server_address_rec)

        receive_from_Lispers_socket.bind(server_address_rec)
        
    except Exception as e:
        print(str(e))
        logging.info(str(e))
    

    msgFromClient       = '{ "type" : "restart" }'
    bytesToSend         = str.encode(msgFromClient)
    
    # Send to socket on container (which gets forwarded there to the unix socket)
    #### here if condition for unix socket of lispers.net
    #### change socket receive_from_lispers_socket necessary to unix
    send_to_Lispers_socket.sendto(bytesToSend, server_address_send)


    while getattr(current_thread, "do_run", True): #True:

        data, addr = receive_from_Lispers_socket.recvfrom(SOCKET_BUFFER_SIZE)
            
        current_time = time.time()
        time_str = datetime.datetime.fromtimestamp(current_time).strftime("%Y-%m-%d %H:%M:%S.%f")
        print("socket message - current time: " + str(current_time) + " -> " + time_str)
        logging.debug("socket message - current time: " + str(current_time) + " -> " + time_str)
        sys.stdout.flush()

        json_message_unicode = json.loads(data)
        json_message = json_message_unicode

        print(str(json_message))
        logging.info(str(json_message))

        if "type" in json_message and "opcode" in json_message:
            if json_message["opcode"] == "add":
                entry_key = add_map_cache_entry(json_message)
                replied_map_requests_with_prefix(json_message["eid-prefix"], entry_key)
            if json_message["opcode"] == "delete":
                delete_map_cache_entry(json_message)

        # If lisp node is behind a NAT, the etr-nat-port from the control plane should be used as udp src port.
        # Since the entire-map-cache message comes before the nat port, cache it if node has an ETR
        if "type" in json_message and json_message["type"] == "entire-map-cache":
            # Only lisp nodes with an ETR get a etr nat port message
            if LISP_NODE_TYPE == "rtr" or LISP_NODE_TYPE == "itr":
                initiate_entire_map_cache(json_message)
            else:
                entire_map_cache_message = json_message

        if "type" in json_message and json_message["type"] == "database-mappings":

            for mapping in json_message["database-mappings"]:

                eid_prefix_mask = mapping["eid-prefix"]
                prefix_array = eid_prefix_mask.split("/")

                # If the current entry already exists, go to next entry
                if eid_prefix_mask in RLOC_WEIGHT_RANGES:
                    print("Entry already exists")
                    logging.info("Entry already exists")
                    continue
                
                # For "don't care" matches, the P4Runtime client must omit the field's entire FieldMatch entry when building the match repeated field of the TableEntry message.
                if prefix_array[0] == "0.0.0.0" and prefix_array[1] == 0:
                    change_default_action(table_name="SwitchIngress.allowed_prefixes_lpm", action_name="NoAction")

                else:
                    for inner_port in INNER_PORTS:
                        match_fields = {"hdr.ipv4.srcAddr": (prefix_array[0], int(prefix_array[1])), "ig_intr_md.ingress_port": TOFINO_PORTS[inner_port]}
                        add_table_entry(table_name="SwitchIngress.allowed_prefixes_lpm", match_field_types=["prefix", "port"], 
                                        match_fields=match_fields,
                                        action_name="NoAction", action_params={})
                        str_match_fields = str(match_fields)
                        print("Match fields for Lisp site with ports: " + str_match_fields)
                        logging.info("Match fields for Lisp site with ports: " + str_match_fields)

                    # If lisp node is behind a NAT, the encapsulation table will have a RTR as default match.
                    # To prevent encapsulation of packets with the destination in the LISP domain, add a match entry with NoAction.
                    add_table_entry(table_name="SwitchIngress.encapsulate_lpm", match_field_types=["prefix", "range"], 
                                        match_fields={"hdr.ipv4.dstAddr": (prefix_array[0], int(prefix_array[1])), "ig_md.rnd_load_balance_group": (0, 127)}, priority = 254,
                                    action_name="NoAction", action_params={})

                    RLOC_WEIGHT_RANGES[eid_prefix_mask] = {"type": "lisp-site"}

                
                print("New Lisp Site Prefix: " + mapping["eid-prefix"])
                logging.info("New Lisp Site Prefix: " + mapping["eid-prefix"])
                sys.stdout.flush()
        
        if "type" in json_message and json_message["type"] == "etr-nat-port":
            # Change the udp source port if it is a xTR behind a NAT
            global NODE_BEHIND_NAT_UDP_SRC_PORT
            NODE_BEHIND_NAT_UDP_SRC_PORT = json_message["port"]

            # Now that the etr nat port of lispers is known, process map cache
            if LISP_NODE_TYPE != "rtr" and LISP_NODE_TYPE != "itr":
                initiate_entire_map_cache(entire_map_cache_message)
                entire_map_cache_message["entries"] = [] # Delete cached message
            
    receive_from_Lispers_socket.close()
    print("Lispers.net listener stopped")
    logging.debug("Lispers.net listener stopped")




if __name__ == "__main__":

    
    #logging.debug('This is a debug message')
    #logging.info('This is an info message')
    
    try:
        switch.MasterArbitrationUpdate()
        switch.SetForwardingPipelineConfig(p4info=P4INFO_HELPER.p4info, prog_name=PROGRAM_NAME, bin_path=BIN_FILE_PATH, cxt_json_path=BMV2_JSON_FILE_PATH)
    except grpc.RpcError as e:
        printGrpcError(e)

    thrift_con = ThriftConnection()
    pal_protocol = TMultiplexedProtocol.TMultiplexedProtocol(thrift_con.protocol, "pal")
    pal_client_module = importlib.import_module(".".join(["pal_rpc", "pal"]))
    pal = pal_client_module.Client(pal_protocol)
    
    port_config = PortConfig(thrift_con=thrift_con)
    port_config.setPorts(TOFINO_CONFIG)


    # Translate the real ports into tofino program addressable ports
    for p in USED_PORTS:
        TOFINO_PORTS[p] = int(pal.pal_port_front_panel_port_to_dev_port_get(0, p, CHANNEL))
        print("Port " + str(p) + ": " + str(TOFINO_PORTS[p]))
        logging.debug("Port " + str(p) + ": " + str(TOFINO_PORTS[p]))

    
    for address_space in LISP_ADDRESS_SPACES_JSON_ARRAY: 
        LISP_ADDRESS_SPACES.append(ipaddress.ip_network(address_space))

    # Create a Packet Counter
    packet_counts = Counter()

    NODE_BEHIND_NAT_UDP_SRC_PORT = random.randint(0, 65535)

    print("Adapt switch to configured LISP node")
    logging.info("Adapt switch to configured LISP node")
    adaptSwitchForNodeType(LISP_NODE_TYPE)

    print("Write initial table entries")
    logging.info("Write initial table entries")
    writeInitialEntries(TABLE_ENTRIES)

    if LISP_NAT:
        print("LISP NAT should be enabled")
        logging.info("LISP NAT should be enabled")
        #PREFIXES_LISP_R
        CURRENT_LISP_R_PREFIX_NETWORK = ipaddress.ip_network(CURRENT_LISP_R_PREFIX)
        CURRENT_LISP_R_HOSTS = CURRENT_LISP_R_PREFIX_NETWORK.hosts()
        NEXT_LISP_R = next(CURRENT_LISP_R_HOSTS, "")

    #readTableRules(P4INFO_HELPER, switch)

    # Start thread to reallow map replies after one second
    map_request_timeout_thread = threading.Thread(target=check_reallowance_of_map_requests)
    map_request_timeout_thread.start()
    print("Thread for map request timeouts")
    logging.debug("Thread for map request timeouts")


    # Listen to control plane (Lispers.net)
    args_list = ()
    if LISPERS_CONNECTION == "unix":
        args_list = (LISPERS_CONNECTION, LISPERS_PATH)
    elif LISPERS_CONNECTION == "udp":
        args_list = (LISPERS_CONNECTION, LOCALHOST_IP, LISPERS_CONTAINER_PORT, LISPERS_CONTAINER_IP, LISPERS_DATAPLANE_PORT)

    if LISPERS_CONNECTION != "none":
        control_plane_thread = threading.Thread(target=read_lispers_messages, args=args_list)
        control_plane_thread.start()
        print("Thread that listens to Lispers.net")
        logging.debug("Thread that listens to Lispers.net")
    else:
        print("No connection to Lispers.net should be established")
        logging.debug("No connection to Lispers.net should be established")
    

    input("\n\n\nPress Enter to exit controller\n\n\n")

    # Delete all table entries on switch if controller is exited
    for entry_key in ENTRIES: 
        entry = ENTRIES[entry_key]
        priority = entry.get("priority", None)
        delete_table_entry( table_name = entry["table_name"], 
                            match_field_types = entry["match_field_types"], 
                            match_fields = entry["match_fields"],
                            priority = priority,
                            remove_from_dict = False)  # Removing entries from dictionary while in for each loop results in error

    ENTRIES = {}

    print("Flushed all written table entries")
    logging.debug("Flushed all written table entries")

    
    ## Code for ending the threads after user ended program

    # Stop threads in endless loops
    if LISPERS_CONNECTION != "none":
        control_plane_thread.do_run = False
        # Send message to socket of control plane thread, so the attribute do_run gets checked
        if LISPERS_CONNECTION == "unix":
            receive_from_Lispers_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receive_from_Lispers_socket.sendto(str.encode("{ }"), LISPERS_PATH + "/lisp-ipc-data-plane")
        else:
            receive_from_Lispers_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receive_from_Lispers_socket.sendto(str.encode("{ }"), (LOCALHOST_IP, LISPERS_CONTAINER_PORT))

    time.sleep(1) # Wait one second so all destinations with pending map requests are unblocked
    map_request_timeout_thread.do_run = False

    print("All blocked map requests are reallowed")
    logging.debug("All blocked map requests are reallowed")

    ShutdownAllSwitchConnections()
    thrift_con.end()




