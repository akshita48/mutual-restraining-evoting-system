import random
import socket
import threading
import json
import time
from phe import paillier

HEADER = 64
PORT = 50505 #server port
FORMAT = 'utf-8'
SERVER = "127.0.0.1" #loopback IP address
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def DEC_to_BIN(num, num_bits):
    b = bin(num)[2:].zfill(num_bits)
    return b

class Collector:
    def __init__(self, server_addr):
        self.server_addr = server_addr
        self.pi = dict()
        self.pi_pri = dict()
        client.connect(server_addr)

    def send(self, msg):
        message = msg.encode(FORMAT)
        msg_length = len(message)
        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))
        client.send(send_length)
        client.send(message)
    
    def register(self):
        msg = {"message_type": "COLLECTOR_REGISTRATION"}
        self.send(json.dumps(msg))
        resp = client.recv(2048).decode(FORMAT)
        resp = json.loads(resp)
        if resp["message_type"] == "REGISTERED":
            self.addr = tuple(resp["addr"])
            self.id = resp["id"]
            self.num_candidates = resp["num_candidates"]
            self.M = self.num_candidates
            print("Registered")
        else:
            print(resp)
    
    def get_voters(self):
        resp = client.recv(2048).decode(FORMAT)
        resp = json.loads(resp)
        if resp["message_type"] == "NUM_VOTERS":
            self.num_voters = resp["num_voters"]
            self.L = self.num_voters * self.num_candidates
            print("Recieved voters")
        else:
            print(resp)

    def create_shares(self):
        self.shares = random.sample(range(-2**self.L, 2**self.L), k=(self.num_voters - 1))
        self.shares.append(-sum(self.shares))
        print("Shares sum:", sum(self.shares))
        self.shares_pri = random.sample(range(-2**self.L, 2**self.L), k=(self.num_voters - 1))
        self.shares_pri.append(-sum(self.shares_pri))
        print("Created shares")
    
    def LAS(self):
        if self.id == 0:
            self.public_key, self.private_key = paillier.generate_paillier_keypair()

            las_r1 = random.sample(range(self.num_voters), k=self.num_voters)
            Er1 = [self.public_key.encrypt(i).ciphertext(False) for i in las_r1]
            msg = {"message_type": "LAS_C1toC2", "public_key": self.public_key.n, "E(r1)": Er1}
            self.send(json.dumps(msg))
            resp = client.recv(HEADER).decode(FORMAT)
            resp = client.recv(int(resp)).decode(FORMAT)
            resp = json.loads(resp)
            if resp["message_type"] == "LAS_C2toC1":
                from_C2 = resp["E(r1)pi2*E(r2)-1"]
            else:
                print(resp)
            to_dec = [paillier.EncryptedNumber(self.public_key, i) for i in from_C2]
            
            self.las = [self.private_key.decrypt(i) for i in to_dec]     

        else:
            resp = client.recv(HEADER).decode(FORMAT)
            resp = client.recv(int(resp)).decode(FORMAT)
            resp = json.loads(resp)
            if resp["message_type"] == "LAS_C1toC2":
                self.public_key = paillier.PaillierPublicKey(resp["public_key"])
                Er1 = resp["E(r1)"]
            else:
                print(resp)
            
            random.shuffle(Er1)
            self.las = random.sample(range(self.num_voters), k=self.num_voters)
            Er2 = [self.public_key.encrypt(i).ciphertext(False) for i in self.las]
            Er2_inv = [pow(i, -1, self.public_key.nsquare) for i in Er2]
            to_C1 = [Er1[i] * Er2_inv[i] for i in range(self.num_voters)]
            
            msg = {"message_type": "LAS_C2toC1", "E(r1)pi2*E(r2)-1": to_C1}
            self.send(json.dumps(msg))
        
        print("Location Anonymization Scheme completed.")
    
    def handle_voter(self, conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")

        while True:
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                msg = conn.recv(msg_length).decode(FORMAT)

                print(f"[{addr}] {msg}")
                msg = json.loads(msg)
                if msg["message_type"] == "LOCATION_SHARES_REQUEST":
                    resp = {"message_type": "LOCATION_SHARES", 
                            "location": self.las[msg["id"]],
                            "share": self.shares[msg["id"]],
                            "share_pri": self.shares_pri[msg["id"]]}
                    
                    conn.send(json.dumps(resp).encode(FORMAT))
                elif msg["message_type"] == "Pi":
                    self.pi[msg["id"]] = msg["pi"]
                    self.pi_pri[msg["id"]] = msg["pi_pri"]
                    conn.send("Recieved pi".encode(FORMAT))
                    break

    def start_server(self):
        client.close()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(self.addr)
        self.server.listen()
        print(f"[LISTENING] Server is listening on {SERVER}")

        while len(self.pi) != self.num_voters:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_voter, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
            time.sleep(1)
        
        print("Received all pi from voters")

    def tally_votes(self):
        # Compute final voting vector
        pi_total = 0
        for key in self.pi:
            pi_total += self.pi[key]
        self.Vi = DEC_to_BIN(pi_total, self.L)
        print("Final voting vector Vi =", self.Vi)

        pi_pri_total = 0
        for key in self.pi_pri:
            pi_pri_total += self.pi_pri[key]
        self.Vi_pri = DEC_to_BIN(pi_pri_total, self.L)
        print("Final voting vector Vi' =", self.Vi_pri)

        print("Vi = reverse(Vi')?", self.Vi[::-1] == self.Vi_pri)

        self.cand_votes = [0 for i in range(self.M)]
        self.ballots = {}

        for i in range(0, self.L, self.M):
            for j in range(self.M):
                if self.Vi[i:i+self.M][j] == "1":
                    self.cand_votes[j] += 1
                    self.ballots[int(i/self.M)] = j
        
        print("Location wise ballots:")
        print("Voter location : Candidated voted")
        for k in self.ballots:
            print(k, ":", self.ballots[k])

        print("Candidate votes tally:", end=" ")
        print(self.cand_votes)
        print("Candidate", self.cand_votes.index(max(self.cand_votes)), "wins!!!")
        print()
    
    def validate(self):
        print("Closing collection server and reconnecting to admin server...")
        self.server.close()
        global client
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.connect(self.server_addr)
        msg = {"message_type": "COLLECTOR_RECONNECT", "id": self.id}
        self.send(json.dumps(msg))

        if self.id == 0:
            #STPM1
            print("Start STPM 1...")
            Ex1 = [self.public_key.encrypt(i).ciphertext(False) for i in self.shares]
            msg = {"message_type": "STPM_C1toC2", "E(x1)": Ex1}
            self.send(json.dumps(msg))

            resp = client.recv(HEADER).decode(FORMAT)
            resp = client.recv(int(resp)).decode(FORMAT)
            resp = json.loads(resp)
            if resp["message_type"] == "STPM_C2toC1":
                from_C2 = resp["E(x1)x2*E(r2)-1"]
            
            to_dec = [paillier.EncryptedNumber(self.public_key, i) for i in from_C2]
            self.s1 = [self.private_key.decrypt(i) for i in to_dec]
            print("STPM 1 successful, got s1")

            #STPM2
            resp = client.recv(HEADER).decode(FORMAT)
            resp = client.recv(int(resp)).decode(FORMAT)
            resp = json.loads(resp)
            if resp["message_type"] == "STPM_C2toC1":
                self.public_key2 = paillier.PaillierPublicKey(resp["public_key"])
                Ex2 = resp["E(x2)"]
            
            self.s1_pri = random.sample(range(-2**(self.L-1), 2**(self.L-1)), k=(self.num_voters-1))
            self.s1_pri.append(-sum(self.s1_pri))
            print("STPM 2: made s1'")

            Ex2x1 = [pow(Ex2[i], self.shares_pri[i], self.public_key2.nsquare) for i in range(self.num_voters)]
            Er1 = [self.public_key2.encrypt(i).ciphertext(False) for i in self.s1_pri]
            to_C2 = [Ex2x1[i] * pow(Er1[i], -1, self.public_key2.nsquare) for i in range(self.num_voters)]

            msg = {"message_type": "STPM_C1toC2", "E(x2)x1*E(r1)-1": to_C2}
            self.send(json.dumps(msg))
        
        else:
            #STPM1
            resp = client.recv(HEADER).decode(FORMAT)
            resp = client.recv(int(resp)).decode(FORMAT)
            resp = json.loads(resp)
            if resp["message_type"] == "STPM_C1toC2":
                Ex1 = resp["E(x1)"]
            
            self.s2_pri = random.sample(range(-2**(self.L-1), 2**(self.L-1)), k=(self.num_voters-1))
            self.s2_pri.append(-sum(self.s2_pri))
            print("STPM 1: made s2'")

            Ex1x2 = [pow(Ex1[i], self.shares_pri[i], self.public_key.nsquare) for i in range(self.num_voters)]
            Er2 = [self.public_key.encrypt(i).ciphertext(False) for i in self.s2_pri]
            to_C1 = [Ex1x2[i] * pow(Er2[i], -1, self.public_key.nsquare) for i in range(self.num_voters)]

            msg = {"message_type": "STPM_C2toC1", "E(x1)x2*E(r2)-1": to_C1}
            self.send(json.dumps(msg))

            #STPM2
            print("Start STPM 2...")
            self.public_key2, self.private_key2 = paillier.generate_paillier_keypair()

            Ex2 = [self.public_key2.encrypt(i).ciphertext(False) for i in self.shares]
            msg = {"message_type": "STPM_C2toC1", "public_key": self.public_key2.n, "E(x2)": Ex2}
            self.send(json.dumps(msg))

            resp = client.recv(HEADER).decode(FORMAT)
            resp = client.recv(int(resp)).decode(FORMAT)
            resp = json.loads(resp)
            if resp["message_type"] == "STPM_C1toC2":
                from_C1 = resp["E(x2)x1*E(r1)-1"]
            
            to_dec = [paillier.EncryptedNumber(self.public_key2, i) for i in from_C1]
            self.s2 = [self.private_key2.decrypt(i) for i in to_dec]
            print("STPM 2 successful, got s2")
        
        print("Both applications of STPM completed successfully, creating sum of secret terms...")

        if self.id == 0:
            self.sum_secrets = [(-self.pi[i]*self.shares_pri[i]-self.pi_pri[i]*self.shares[i]+self.shares[i]*self.shares_pri[i]+self.s1[i]+self.s1_pri[i])%self.public_key.nsquare for i in range(self.num_voters)]
        else:
            self.sum_secrets = [(-self.pi[i]*self.shares_pri[i]-self.pi_pri[i]*self.shares[i]+self.shares[i]*self.shares_pri[i]+self.s2[i]+self.s2_pri[i])%self.public_key2.nsquare for i in range(self.num_voters)]
        
        msg = {"message_type": "SECRETS_SUM", "id": self.id, "S": self.sum_secrets}
        self.send(json.dumps(msg))

        resp = client.recv(HEADER).decode(FORMAT)
        resp = client.recv(int(resp)).decode(FORMAT)
        resp = json.loads(resp)
        if resp["message_type"] == "SECRETS_SUM_BOTH":
            self.S_sum = resp["S_sum"]
        
        print("Verifying ballots...")
        print("2^(L-1) =", 2**(self.L-1))
        self.S_sum_plus_pipi_pri = [self.pi[i]*self.pi_pri[i]+self.S_sum[i] for i in range(self.num_voters)]
        print("Checking if pi.pi'+S1+S2 = 2^(L-1) for each voter...")
        for i in range(self.num_voters):
            print("Voter", i, end=": ")
            print(self.S_sum_plus_pipi_pri[i]%self.public_key.nsquare == 2**(self.L-1) or self.S_sum_plus_pipi_pri[i]%self.public_key2.nsquare == 2**(self.L-1))
    
    def start_election(self):
        print("Start registeration...")
        self.register()
        print("Receive voters...")
        self.get_voters()
        print("Location Anonymization Scheme...")
        self.LAS()
        print("Create shares...")
        self.create_shares()
        print("Starting server...")
        self.start_server()
        print("Tallying votes...")
        self.tally_votes()
        print("Ballots validation...")
        self.validate()

collector1 = Collector(ADDR)

try:
    collector1.start_election()
except KeyboardInterrupt:
    print("Collector closed.")