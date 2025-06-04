import os
import time
import json
import config
import socket
import base64
import hashlib
import threading
import select
import random
import subprocess as sp
from sympy import mod_inverse


class Master():
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.server_socket.setblocking(False)

        self.sockets_list = [self.server_socket]
        self.client_data = {}
        self.secret_key = {}
        self.ts1 = {}
        self.rn1 = {}
        self.port_name = {}

        self.public_key, self.private_key = config.generate_keys()
        self.patient_key = {}
        self.session_keys = {}
        self.ids = {}
        self.clients = {}
        self.blocked_list = {}
        with open('blocked_id.txt', 'r') as f:
            for line in f:
                id = line.strip()
                l = id.split(':')
                if len(l) >= 2 and abs(int(time.time())-int(l[1])) <= 86400:
                    self.blocked_list[l[0]] = 1
    


    def send_response(self, client_socket, response):
        response = json.dumps(response).encode('utf-8')
        response += b' ' * (config.MESSAGE_SIZE - len(response))
        client_socket.sendall(response)



    def make_connection(self, client):
        message = client.recv(config.MESSAGE_SIZE)
        message = json.loads(message.decode('utf-8'))

        name = message['sender_type']
        print(f"{name} : {message['data']}")
        response = {
            'data': 'Connected to Server!',
        }
        self.send_response(client_socket=client, response=response)


    def exchange_keys(self, client_socket, message):
        name = message['sender_type']
        self.patient_key[name] = message['public']
        self.ids[name] = message['id']

        response = {
            'data': 'Key Exchange Successful!',
            'public': self.public_key,
            'id': 101,
            'Opcode': 10,
        }
        self.send_response(client_socket, response)


    def digitalsigverify(self, client_socket, message):
        # receive
        name = message['sender_type']
        curr_ts = int(time.time())
        ts1 = message['ts']
        rn1 = message['rn']
        id1 = message['id']
        c1_bytes = base64.b64decode(message['c1'])
        c2_bytes = base64.b64decode(message['c2'])
        c1 = int.from_bytes(c1_bytes, 'big')
        c2 = int.from_bytes(c2_bytes, 'big')
        signData1 = message['signData']
        enc_key1 = (c1, c2)

        ip, port = client_socket.getpeername()
        if abs(curr_ts - ts1) > config.DELTA_TS:
            response = {
                'status': 'Time Delay!',
                'Opcode': 20,
            }
            self.send_response(client_socket=client_socket, response=message)
            return False
        else:
            data = f"{ts1}|{rn1}|{id1}|{enc_key1}"
            if not config.verify(data, self.patient_key[name], signData1):
                response = {
                    'status': 'Signature not valid!',
                    'Opcode': 20,
                }
                self.send_response(client_socket=client_socket, response=response)
                return False
        
        secret_key = config.decrypt(enc_key1, self.public_key, self.private_key)
        # send
        ts2 = int(time.time())
        rn2 = str(random.randint(512, 1024))
        id2 = self.ids[name]
        enc_key2 = config.encrypt(secret_key, self.patient_key[name])
        data = f"{ts2}|{rn2}|{id2}|{enc_key2}"
        signData2 = config.sign(data, self.public_key, self.private_key)

        response = {
            'status': 'OK',
            'ts': ts2,
            'rn': rn2,
            'id': id2,
            'secret_key': enc_key2,
            'signData': signData2,
        }
        print("Signature Verification done")

        ip, port = client_socket.getpeername()
        self.secret_key[port] = str(secret_key)
        self.ts1[port] = str(ts1)
        self.ts2 = ts2
        self.rn1[port] = str(rn1)
        self.rn2 = rn2
        self.id1 = id1
        self.id2 = id2
        self.send_response(client_socket=client_socket, response=response)



    
    def broadcast(self):
        string = ""
        print(self.session_keys)
        for key, value in self.session_keys.items():
            string += value
        string += str(self.private_key)
        self.shared_group_key = hashlib.sha256(string.encode()).hexdigest()


        # encryption using AES. Send group key to all patients
        ciphertexts = {}
        for key, value in self.session_keys.items():
            aes = config.AESFunctions(key=value.encode(encoding='utf-8'))
            ciphertexts[key] = aes.encrypt_to_base64(self.shared_group_key)
        

        print("Ciphertexts made", self.clients)
        for client in self.clients:
            _, port = client.getpeername()
            response = {
                'message': 'broadcast',
                'status': 'OK',
                'key': ciphertexts[port],
                'Opcode': 40
            }
            self.send_response(client, response=response)
        print("Group key sent to all clients")

        # encryption using AES. Send broadcast message finally
        message = input("Enter the Emergency message: ")
        # message = "I am not free from 9-10AM in the mornings and 5-6PM in the evenings. Apart from that, come anytime between 8AM-7PM on Sunday and Monday."
        start_time=time.time()
        
        aes = config.AESFunctions(key=self.shared_group_key.encode(encoding='utf-8'))
        ciphertext = aes.encrypt_to_base64(message)

        end_time = time.time()
        elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
        print('Time taken for AES encryption :',elapsed_time)
        
        for client in self.clients:
            _, port = client.getpeername()
            response = {
                'message': message,
                'status': 'OK',
                'data': ciphertext,
                'Opcode': 50
            }
            self.send_response(client, response=response)
        return

    
    def authenticate(self, client_socket, message):
        # receive
        if message['status'] != 'OK':
            print(message['status'])
            return False

        curr_ts = int(time.time())
        ts3 = message['ts']
        hash_verifier = message['key_verifier']
        ip, port = client_socket.getpeername()


        if abs(curr_ts - ts3) > config.DELTA_TS:
            response = {
                'status': 'Time Delay!',
                'Opcode': 20
            }
            self.send_response(client_socket=client_socket, response=response)
            return False

        start_time = time.time()
        session_key = f"{self.secret_key[port]}|{self.ts1[port]}|{self.ts2}|{self.rn1[port]}|{self.rn2}|{self.id1}|{self.id2}"
        hash_session = hashlib.sha256(session_key.encode()).hexdigest()

        end_time = time.time()
        elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
        print('Time taken for hashing session key :',elapsed_time)

        start_time = time.time()

        key_verifier1 = f"{hash_session}|{ts3}"
        hash_verifier1 = hashlib.sha256(key_verifier1.encode()).hexdigest()
        end_time = time.time()
        elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
        print('Time taken for hashing key verifier :',elapsed_time)

        # send
        if hash_verifier != hash_verifier1:
            response = {
                'status': 'Final Verification failed!',
                'Opcode': 20
            }
            self.send_response(client_socket=client_socket, response=response)
            return False
        
        response = {
            'status': 'OK',
            'Opcode': 20
        }
        self.session_keys[port] = session_key
        self.clients[client_socket] = 1
        print(f"Client {ip}: {port} authenticated successfully")
        self.send_response(client_socket=client_socket, response=response)

        if len(self.patient_key) == 3:                  # we can change this value of n, broadcast the keys to everyone.
            self.broadcast()
        return True


    def handle_message(self, client_socket, message):
        sender_type = message.get('sender_type')
        data = message.get('data')
        id = message.get('id')
        key_verifier = message.get('key_verifier')
        opcode = message.get("Opcode")
        ip, port = client_socket.getpeername()
        if not self.port_name.__contains__(port):
            self.port_name[port] = sender_type

        if opcode == 60:
            ip, port = client_socket.getpeername()
            print(f"{port = }")
            self.secret_key.pop(port, None)
            self.session_keys.pop(port, None)
            self.clients.pop(port, None)
            self.patient_key.pop(sender_type, None)
            self.client_data.pop(client_socket, None)
            self.ts1.pop(port, None)
            self.rn1.pop(port, None)
            self.ids.pop(sender_type, None)
            self.sockets_list.remove(client_socket)

            obj = None
            for client in self.clients:
                ip1, port1 = client.getpeername()
                if port == port1:
                    obj = client
                    break
            self.clients.pop(obj, None)
            x = self.clients.get(port)
            print(f"{message['sender_type']} Opcode: {message['Opcode']}, Disconnected!!")
            message = {
                'status': 'OK'
            }
            self.send_response(client_socket=client_socket, response=message)

            # command = f"lsof -i tcp:{port} -t"
            print(self.clients, int(sender_type[-1]))
            l = ["lsof", "-i", f"tcp:{port}", "-t"]
            process = sp.run(l, capture_output=True, text=True)
            print(process, type(process))
            stdout = process.stdout
            if stdout:
                pids = stdout.strip().splitlines()
                print(pids)
                try:
                    sp.run(f"kill -9 {pids[1]}", shell=True, check=True)
                except sp.CalledProcessError as e:
                    print(f"Error killing process with PID {pids[1]}: {e}")
            else:
                print(f"No process found listening on port {port}.")


        if data == 'Public key received':
            print(f"{message['sender_type']} : {message['data']} Opcode: {message['Opcode']}")
            self.exchange_keys(client_socket, message)
        elif id is not None:
            self.digitalsigverify(client_socket, message)
        elif key_verifier is not None:
            self.authenticate(client_socket=client_socket, message=message)
        elif data is None:
            return
        else:
            if self.blocked_list.__contains__(sender_type):
                print("Connection with port disabled for 24 hours.")
                response = {
                    'data': 'Connection refused!',
                }
                self.send_response(client_socket=client_socket, response=response)
                self.sockets_list.remove(client_socket)
                del self.client_data[client_socket]
            else:
                print(f"{sender_type}: {data}")



    def listen(self):
        while True:
            read_sockets, _, exception_sockets = select.select(self.sockets_list, [], self.sockets_list)

            for notified_socket in read_sockets:
                if notified_socket == self.server_socket:
                    client_socket, client_address = self.server_socket.accept()
                    client_socket.setblocking(False)
                    self.sockets_list.append(client_socket)
                    self.client_data[client_socket] = {'address': client_address}
                    ip, port = client_socket.getpeername()
                    
                    response = {
                        'data': 'Connected to Server!',
                    }
                    self.send_response(client_socket=client_socket, response=response)
                else:
                    try:
                        message = notified_socket.recv(config.MESSAGE_SIZE)
                        message = json.loads(message.decode('utf-8'))
                        self.handle_message(notified_socket, message)

                    except Exception as e:
                        print(f"Error: {e}")
                        ip, port = notified_socket.getpeername()
                        with open('blocked_id.txt', 'a+') as f:
                            t = int(time.time())
                            f.write(self.port_name[port])
                            f.write(":")
                            f.write(str(t))
                            f.write("\n")
                        self.sockets_list.remove(notified_socket)
                        del self.client_data[notified_socket]

            for notified_socket in exception_sockets:
                self.sockets_list.remove(notified_socket)
                del self.client_data[notified_socket]



if __name__ == '__main__':
    ms = Master(config.HOST, config.MASTER_PORT)
    print('Master Server Running')
    ms.listen()