# Original experiment collector; configure ports, pipe selection and thresholds for your testbed.
#!/usr/bin/python3

from __future__ import print_function

import os
import sys
import pdb

SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON2   = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
sys.path.append(SDE_PYTHON2)
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))

PYTHON3_VER   = '{}.{}'.format(
                    sys.version_info.major,
                    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER, 'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as bfrt_client
import pandas as pd

import time
import socket, struct

#
# Connect to the BF Runtime Server
#
interface = bfrt_client.ClientInterface(
    grpc_addr = 'localhost:50052',
    client_id = 1,
    device_id = 0)
print('Connected to BF Runtime Server')

#
# Get the information about the running program
#
bfrt_info = interface.bfrt_info_get()
print('The target runs the program ', bfrt_info.p4_name_get())
#
# Establish that you are using this program on the given connection
#
interface.bind_pipeline_config(bfrt_info.p4_name_get())

learn_filter = bfrt_info.learn_get("digest")

# List of registers
registers = []

# Target pipe_id=0xffff
target = bfrt_client.Target(device_id=0, pipe_id=0xffff)

count = 0

# with open(filename_out, "w") as text_file:
#     text_file.write(header)
#     text_file.write("\n")
count_digest = 0
count_refresh = 0
result_df = pd.DataFrame()

while True:

    try:
        digest = interface.digest_get(timeout=50)
        recv_target = digest.target
        digest_type = 1
        data_list = learn_filter.make_data_list(digest)
    except:
        digest_type = 0
        persistence_list = []
        src_id_list = []
        dst_id_list = []

        table_persistence = bfrt_info.table_get('Ingress.reg_persistence_count')
        table_persistence_snd = bfrt_info.table_get('Ingress.reg_persistence_count_snd')
        table_time = bfrt_info.table_get('Ingress.reg_current_time_window')
        table_recirc = bfrt_info.table_get('Ingress.reg_count_recirc')
        resp_persistence = table_persistence.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())

        resp_persistence_snd = table_persistence_snd.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())

        resp_time = table_time.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())

        resp_recirc = table_recirc.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())


        for data, x in resp_persistence:
            x_dict = x.to_dict()
            data_dict = data.to_dict()
            persistence_list.append(data_dict['Ingress.reg_persistence_count.f1'][1])

        for data, x in resp_persistence_snd:
            x_dict = x.to_dict()
            data_dict = data.to_dict()
            persistence_list.append(data_dict['Ingress.reg_persistence_count_snd.f1'][1])

        print('persistence values so far: ', persistence_list, len(persistence_list))

        result_df['persistence'] = persistence_list
        # result_df['src_ID'] = src_id_list
        # result_df['dst_ID'] = dst_id_list

        thr = 1500*0.4
        print(len(result_df[result_df['persistence'] >= thr]))
        print('WINDOW: ', count_refresh)

        for data, x in resp_time:
            x_dict = x.to_dict()
            data_dict = data.to_dict()
            print('TIME WINDOW: ', data_dict['Ingress.reg_current_time_window.f1'][1])
            current_time_w =  data_dict['Ingress.reg_current_time_window.f1'][1]

        for data, x in resp_recirc:
            x_dict = x.to_dict()
            data_dict = data.to_dict()
            print('RECIRC COUNT: ', data_dict['Ingress.reg_count_recirc.f1'][1])

        print('MISTAKEN: ', len(result_df[result_df['persistence'] > current_time_w]))

        break


    if digest_type == 1:
        for dd in data_list:
            count_digest = count_digest + 1
            data_dict = dd.to_dict()
            # convert ip address into normal format
            source_addr = socket.inet_ntoa(struct.pack('!L', data_dict['source_addr']))
            destin_addr = socket.inet_ntoa(struct.pack('!L', data_dict['destin_addr']))
            pkt_count = data_dict['pkt_count']

            count_refresh = count_refresh + 1
            current_time_w = 0
            # print('FIRST persistence: ', data_dict['persistence_count_fst'], '  SECOND: ', data_dict['persistence_count_snd'], ' ROW:   ', data_dict['minRow'] )
            if (count_digest%500 == 0):
            # if (1):
                persistence_list = []
                item_id_list = []
                last_t_wind_list = []
                table = bfrt_info.table_get('Ingress.reg_persistence_count')
                resp = table.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                        key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())
                for data, x in resp:
                    x_dict = x.to_dict()
                    data_dict = data.to_dict()
                    # print(data_dict['Ingress.reg_persistence_count.f1'])
                    persistence_list.append(data_dict['Ingress.reg_persistence_count.f1'][1])
                # print(persistence_list)
                #
                table_snd = bfrt_info.table_get('Ingress.reg_persistence_count_snd')
                resp_snd = table_snd.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                        key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())
                for data, x in resp_snd:
                    x_dict = x.to_dict()
                    data_dict = data.to_dict()
                    persistence_list.append(data_dict['Ingress.reg_persistence_count_snd.f1'][1])
                print(persistence_list)
                ###################################
                table = bfrt_info.table_get('Ingress.reg_current_time_window')
                resp = table.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                        key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())

                for data, x in resp:
                    x_dict = x.to_dict()
                    data_dict = data.to_dict()
                    print(data_dict['Ingress.reg_current_time_window.f1'][1])
                    current_time_w = data_dict['Ingress.reg_current_time_window.f1'][1]
                #####################################
                table = bfrt_info.table_get('Ingress.reg_count_recirc')
                resp = table.entry_get(bfrt_client.Target(device_id=0, pipe_id=0xffff), required_data=None,
                                        key_list=None, flags={"from_hw":True}, p4_name=bfrt_info.p4_name_get())

                for data, x in resp:
                    x_dict = x.to_dict()
                    data_dict = data.to_dict()
                    print('------ RECIRC', data_dict['Ingress.reg_count_recirc.f1'][1])

                count_thr = 0
                count_mist = 0
                for p in persistence_list:
                    if p >= 0.4*count_refresh:
                        count_thr = count_thr + 1
                    if p>current_time_w:
                        count_mist = count_mist + 1
                print('RESULT' ,count_thr)
                print('COUNT: ', count_refresh + 1)
                print('MISTAKEN: ', count_mist)

result_df.to_csv('pontus_results_switch_8192_W2000_Random11.csv')
