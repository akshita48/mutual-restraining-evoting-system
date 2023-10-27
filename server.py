import json
import socket 
import threading
import time
import sys

HEADER = 64
PORT = 50505
SERVER = "127.0.0.1" #loopback IP address
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'

class Election:
    def __init__(self, num_candidates, num_voters):
        self.num_candidates = num_candidates
        self.num_voters = num_voters
        self.collectors = []
        self.voters = []
        self.S = {}
    
    def handle_clients(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")

        while True:
            try:
                msg_length = conn.recv(HEADER).decode(FORMAT)
            except ConnectionResetError:
                print(f"Connection closed by client: {addr}")
                break

            if msg_length:
                msg_length = int(msg_length)
                msg = conn.recv(msg_length).decode(FORMAT)

                print(f"[{addr}] {msg}")
                msg = json.loads(msg)

                if msg["message_type"] == "COLLECTOR_REGISTRATION":
                    resp = {"message_type": "REGISTERED",
                            "addr": addr, 
                            "id": len(self.collectors),
                            "num_candidates": self.num_candidates}
                    
                    self.collectors.append((conn, addr))
                    conn.send(json.dumps(resp).encode(FORMAT))

                    if len(self.collectors) == 2:
                        print("Collectors registered:", self.collectors)

                elif msg["message_type"] == "VOTER_REGISTRATION" and len(self.voters) < self.num_voters:
                    resp = {"message_type": "REGISTERED",
                            "addr": addr, 
                            "id": len(self.voters), 
                            "num_candidates": self.num_candidates,
                            "collector1": self.collectors[0][1],
                            "collector2": self.collectors[1][1]}
                    
                    self.voters.append((conn, addr))
                    conn.send(json.dumps(resp).encode(FORMAT))
                    
                    if len(self.voters) == self.num_voters:
                        print("Voters registered:", self.voters)

                        for v in self.voters:
                            msg = {"message_type": "NUM_VOTERS", "num_voters": len(self.voters)}
                            v[0].send(json.dumps(msg).encode(FORMAT))

                        resp = {"message_type": "NUM_VOTERS", "num_voters": len(self.voters)}
                        self.collectors[0][0].send(json.dumps(resp).encode(FORMAT))
                        self.collectors[1][0].send(json.dumps(resp).encode(FORMAT))
                        
                        print("Sent voters addresses to collectors")
                
                elif msg["message_type"] == "LAS_C1toC2" or msg["message_type"] == "STPM_C1toC2": 
                    msg_length = len(json.dumps(msg))
                    send_length = str(msg_length).encode(FORMAT)
                    send_length += b' ' * (HEADER - len(send_length))
                    self.collectors[1][0].send(send_length)
                    self.collectors[1][0].send(json.dumps(msg).encode(FORMAT))
                
                elif msg["message_type"] == "LAS_C2toC1" or msg["message_type"] == "STPM_C2toC1":
                    msg_length = len(json.dumps(msg))
                    send_length = str(msg_length).encode(FORMAT)
                    send_length += b' ' * (HEADER - len(send_length))
                    self.collectors[0][0].send(send_length)
                    self.collectors[0][0].send(json.dumps(msg).encode(FORMAT))

                elif msg["message_type"] == "COLLECTOR_RECONNECT":
                    self.collectors[msg["id"]] = (conn, addr)
                    print("Collector", msg["id"], "reconnected")
                
                elif msg["message_type"] == "SECRETS_SUM":
                    self.S[msg["id"]] = msg["S"]
                    if len(self.S) == 2:
                        print("Received both secrets sum, sending sum of them to both collectors...")
                        S_sum = [self.S[0][i]+self.S[1][i] for i in range(self.num_voters)]
                        resp = {"message_type": "SECRETS_SUM_BOTH", "S_sum": S_sum}
                        resp_length = len(json.dumps(resp))
                        send_length = str(resp_length).encode(FORMAT)
                        send_length += b' ' * (HEADER - len(send_length))
                        self.collectors[0][0].send(send_length)
                        self.collectors[1][0].send(send_length)
                        self.collectors[0][0].send(json.dumps(resp).encode(FORMAT))
                        self.collectors[1][0].send(json.dumps(resp).encode(FORMAT))
                        print("Sent secrets sums to both the collectors.")

                        print("Election completed successfully, closing server.")
                        sys.exit()

    def handle_collector_registration(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")

        while True:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                msg = conn.recv(msg_length).decode(FORMAT)

                print(f"[{addr}] {msg}")
                msg = json.loads(msg)
                if msg["message_type"] == "COLLECTOR_REGISTRATION":
                    resp = {"message_type": "REGISTERED",
                            "addr": addr, 
                            "id": len(self.collectors),
                            "num_candidates": self.num_candidates}
                    
                    self.collectors.append((conn, addr))
                    conn.send(json.dumps(resp).encode(FORMAT))
                    break

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(ADDR)
        self.server.listen()
        print(f"[LISTENING] Server is listening on {SERVER}")
        self.start_time = time.time()
        
        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_clients, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
            time.sleep(1)

    def register_collectors(self):
        while len(self.collectors) < 2:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_collector_registration, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
            time.sleep(1)
      
        print("Collectors registered:", len(self.collectors))

    def handle_voter_registeration(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")

        while True:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                msg = conn.recv(msg_length).decode(FORMAT)

                print(f"[{addr}] {msg}")
                msg = json.loads(msg)
                if msg["message_type"] == "VOTER_REGISTRATION":
                    resp = {"message_type": "REGISTERED",
                            "addr": addr, 
                            "id": len(self.voters), 
                            "num_candidates": self.num_candidates,
                            "collector1": self.collectors[0][1],
                            "collector2": self.collectors[1][1]}
                    
                    self.voters.append((conn, addr))
                    conn.send(json.dumps(resp).encode(FORMAT))
                    break

    def register_voters(self):
        while len(self.voters) < self.num_voters:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_voter_registeration, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
            time.sleep(1)
            
        for v in self.voters:
            msg = {"message_type": "NUM_VOTERS", "num_voters": len(self.voters)}
            v[0].send(json.dumps(msg).encode(FORMAT))
            
        print("Voters registered:", len(self.voters))

    def send_voters_to_collectors(self):
        voters_addr_list = [i[1] for i in self.voters]
        resp = {"message_type": "VOTERS", "voters_addr_list": voters_addr_list}
        conn = self.collectors[0][0]
        conn.send(json.dumps(resp).encode(FORMAT))
        conn = self.collectors[1][0]
        conn.send(json.dumps(resp).encode(FORMAT))
        
        print("Sent voters addresses to collectors")

    def handle_collector(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")

        while True:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                msg = conn.recv(msg_length).decode(FORMAT)

                print(f"[{addr}] {msg}")
                msg = json.loads(msg)
                if msg["message_type"] == "LAS_C1toC2":
                    resp = {"message_type": "LAS_C1",
                            "addr": addr, 
                            "id": len(self.collectors),
                            "num_candidates": self.num_candidates}
                    
                    conn.send(json.dumps(resp).encode(FORMAT))
                    break    
    
    def start_election(self):
        print("[STARTING] server is starting...")
        self.start_server()
        print("Starting Collector Registeration...")
        self.register_collectors()
        print("Starting voter registeration...")
        self.register_voters()
        print("Sending voter addresses to collectors...")
        self.send_voters_to_collectors()

Election1 = Election(3, 3)

try:
    Election1.start_election()
    print("Server job complete.")
except KeyboardInterrupt:
    print("Server closed.")