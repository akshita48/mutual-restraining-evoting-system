import random
import socket
import json

HEADER = 64
PORT = 50505 #server port
FORMAT = 'utf-8'
SERVER = "127.0.0.1" #loopback IP address
ADDR = (SERVER, PORT)

class Voter:
    def __init__(self, server_addr):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_addr = server_addr
        self.client.connect(server_addr)
        self.collectors = []
        self.collector_shares = dict()
        self.collector_shares_pri = dict()
        self.location = 0

    def send(self, msg, client):
        message = msg.encode(FORMAT)
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.send(send_length)
        client.send(message)
        return client.recv(2048).decode(FORMAT)
    
    def register(self):
        msg = {"message_type": "VOTER_REGISTRATION"}
        resp = self.send(json.dumps(msg), self.client)
        resp = json.loads(resp)
        if resp["message_type"] == "REGISTERED":
            self.addr = tuple(resp["addr"])
            self.id = resp["id"]
            self.num_candidates = resp["num_candidates"]
            self.M = self.num_candidates
            self.collectors.append(tuple(resp["collector1"]))
            self.collectors.append(tuple(resp["collector2"]))
            print("Registered")
        else:
            print(resp)
        
        resp = self.client.recv(2048).decode(FORMAT)
        resp = json.loads(resp)
        if resp["message_type"] == "NUM_VOTERS":
            self.N = resp["num_voters"]
            print("Received number of voters")
        else:
            print(resp)
    
    def connect_to_collectors(self):
        self.coll_clients = []
        for coll in self.collectors:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(coll)
            self.coll_clients.append(client)

    def get_collector_shares(self):
        for client in self.coll_clients:
            msg = {"message_type": "LOCATION_SHARES_REQUEST", "id": self.id}
            resp = self.send(json.dumps(msg), client)
            resp = json.loads(resp)
            if resp["message_type"] == "LOCATION_SHARES":
                self.location += resp["location"]
                self.collector_shares[self.coll_clients.index(client)] = resp["share"]
                self.collector_shares_pri[self.coll_clients.index(client)] = resp["share_pri"]
                print("Received collector shares")
            else:
                print(resp)
        print("My location:", self.location)
    
    def vote(self):
        self.cand_num = random.randrange(self.M)
        self.vi = "0"*self.M*self.location + "0"*self.cand_num + "1" + "0"*(self.M - self.cand_num - 1) + "0"*self.M*(self.N - self.location - 1)
        print("vi =", self.vi, ", vi length =", len(self.vi), ", L (M x N) =", self.N * self.M)
        self.vi_pri = self.vi[::-1]
        print("Voter", self.id, "voted for", self.cand_num)

        self.pi = int(self.vi, 2)
        for coll in self.collector_shares:
            self.pi += self.collector_shares[coll]
        self.pi_pri = int(self.vi_pri, 2)
        for coll in self.collector_shares_pri:
            self.pi_pri += self.collector_shares_pri[coll]

        print("Created pi, sending to collectors...")

        for client in self.coll_clients:
            msg = {"message_type": "Pi", "id": self.id, "pi": self.pi, "pi_pri": self.pi_pri}
            resp = self.send(json.dumps(msg), client)
            print("Response from collector", self.coll_clients.index(client), resp)
            
    def start_election(self):
        print("Start registeration...")
        self.register()
        input()
        print("Requesting collector shares...")
        self.connect_to_collectors()
        self.get_collector_shares()
        print("Voting...")
        self.vote()

voter1 = Voter(ADDR)

try:
    voter1.start_election()
except KeyboardInterrupt:
    print("Voter closed.")