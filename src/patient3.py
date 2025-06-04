import os
import time
import json
import socket
import config
import base64
import random
import hashlib


class Client():
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((socket.gethostbyname('localhost'), config.MASTER_PORT))
        self.public_key, self.private_key = config.generate_keys()
        self.group_key = None

        message = {
            'sender_type': name,
            'data': 'Connected!',
        }
        encoded = json.dumps(message).encode('utf-8')
        encoded += b' ' * (config.MESSAGE_SIZE - len(encoded))
        self.sock.sendall(encoded)

        response = self.sock.recv(config.MESSAGE_SIZE)
        if not response:
            raise Exception('Server not responding!')
        response = json.loads(response.decode('utf-8'))
        print(response['data'])
        if response['data'] == 'Connection refused!':
            exit(0)


    def exchange_keys(self):
        message = {
            'sender_type': name,
            'data': 'Public key received',
            'public': self.public_key,
            'id': num,
            'Opcode': 10,
        }
        encoded = json.dumps(message).encode('utf-8')
        encoded += b' ' * (config.MESSAGE_SIZE - len(encoded))
        self.sock.sendall(encoded)

        response = self.sock.recv(config.MESSAGE_SIZE)
        if not response:
            raise Exception('Server not responding!')
        response = json.loads(response.decode('utf-8'))
        self.master_public_key = response['public']
        self.master_id = response['id']
        print(response['data'], " Opcode: ", response['Opcode'])

    
    def authenticate(self):
        # send
        ts1 = int(time.time())
        rn1 = str(random.randint(512, 1024))
        id1 = self.master_id
        secret_key = random.randint(512, 1024)
        p, g, y = self.master_public_key
        secret_key = (secret_key%p)

        enc_key1 = config.encrypt(secret_key, self.master_public_key)
        data = f"{ts1}|{rn1}|{id1}|{enc_key1}"
        signData1 = config.sign(data, self.public_key, self.private_key)

        c1, c2 = enc_key1
        c1_bytes = c1.to_bytes((c1.bit_length() + 7) // 8, 'big')
        c2_bytes = c2.to_bytes((c2.bit_length() + 7) // 8, 'big')

        message = {
            'sender_type': name,
            'ts': ts1,
            'rn': rn1,
            'id': id1,
            'c1': base64.b64encode(c1_bytes).decode('utf-8'),
            'c2': base64.b64encode(c2_bytes).decode('utf-8'),
            'signData': signData1,
            'data': "Authentication request",
            'Opcode': 20
        }
        encoded = json.dumps(message).encode('utf-8')
        encoded += b' ' * (config.MESSAGE_SIZE - len(encoded))
        self.sock.sendall(encoded)

        # receive
        response = self.sock.recv(config.MESSAGE_SIZE)
        if not response:
            raise Exception('Server not responding!')
        response = json.loads(response.decode('utf-8'))
        if response['status'] != 'OK':
            print(response['status'], " Opcode:", response['Opcode'])
            return False
        
        curr_ts = int(time.time())
        ts2 = response['ts']
        rn2 = response['rn']
        id2 = response['id']
        enc_key2 = tuple(response['secret_key'])
        signData2 = response['signData']

        if abs(curr_ts - ts2) > config.DELTA_TS:
            message = {
                'sender_type': name,
                'status': 'Time Delay!',
                'Opcode': 20
            }
            message = json.dumps(message).encode('utf-8')
            message += b' ' * (config.MESSAGE_SIZE - len(message))
            self.sock.sendall(message)
            return False
        else:
            data = f"{ts2}|{rn2}|{id2}|{enc_key2}"
            if not config.verify(data, self.master_public_key, signData2):
                message = {
                    'sender_type': name,
                    'status': 'Signature not valid!',
                    'Opcode': 20
                }
                message = json.dumps(message).encode('utf-8')
                message += b' ' * (config.MESSAGE_SIZE - len(message))
                self.sock.sendall(message)
                return False
            
        self.session_key = f"{secret_key}|{ts1}|{ts2}|{rn1}|{rn2}|{id1}|{id2}"
        hash_session = hashlib.sha256(self.session_key.encode()).hexdigest()

        # send
        ts3 = int(time.time())
        key_verifier = f"{hash_session}|{ts3}"
        hash_verifier = hashlib.sha256(key_verifier.encode()).hexdigest()
        
        message = {
            'sender_type': name,
            'status': 'OK',
            'ts': ts3,
            'key_verifier': hash_verifier,
            'Opcode': 30,
        }
        encoded = json.dumps(message).encode('utf-8')
        encoded += b' ' * (config.MESSAGE_SIZE - len(encoded))
        self.sock.sendall(encoded)

        # receive
        response = self.sock.recv(config.MESSAGE_SIZE)
        if not response:
            raise Exception('Server not responding!')
        response = json.loads(response.decode('utf-8'))
        if response['status'] != 'OK':
            print(response['status'], " Opcode:", response['Opcode'])
            return False
        else:
            print('Authentication Successful! Opcode: ', response['Opcode'])
        return True


num = 2
name = config.NAMES[num]
port = config.PORTS[num]


if __name__ == '__main__':
    cs = Client(config.HOST, port)
    cs.exchange_keys()
    ret = cs.authenticate()
    if ret:
        while True:
            print("Welcome to the Doctor Service!!!!")
            response = cs.sock.recv(config.MESSAGE_SIZE)
            if not response:
                raise Exception('Server not responding!')
            response = json.loads(response.decode('utf-8'))
            
            # decryption using AES
            aes = config.AESFunctions(key=cs.session_key.encode('utf-8'))
            cs.group_key = aes.decrypt_from_base64(response['key'])
            print('Group key = ', cs.group_key, " Opcode:", response['Opcode'])

            response = cs.sock.recv(config.MESSAGE_SIZE)
            if not response:
                raise Exception('Server not responding!')
            response = json.loads(response.decode('utf-8'))
            # decryption using AES
            start_time = time.time()
            aes = config.AESFunctions(key=cs.group_key)
            message = aes.decrypt_from_base64(response['data'])
            end_time = time.time()
            elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
            print('Time taken for AES decryption :',elapsed_time)          
            print('Message = ', message, " Opcode:", response['Opcode'])

            while True:
                x = input("Do you want to Exit Now (Y/N): ")
                if x != "Y" and x != "N":
                    print("Please Enter either Y or N")
                elif x == "Y":
                    message = {
                        'sender_type': name,
                        'status': 'OK',
                        'Opcode': 60,
                    }
                    encoded = json.dumps(message).encode('utf-8')
                    encoded += b' ' * (config.MESSAGE_SIZE - len(encoded))
                    cs.sock.sendall(encoded)
                    response = cs.sock.recv(config.MESSAGE_SIZE)
                else:
                    break