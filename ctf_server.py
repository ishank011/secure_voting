# Secure voting protocol with multiple Central Tabulating Facilities (CTFs)
# CS-530 Information Security, Group: 5
# CTF Server

import threading
import socket
import argparse
import pickle
import os
from phe import paillier
from time import sleep

SERVER_HOST = '127.0.0.1'
VOTES_RECEIVED, VOTE_COUNT, HAS_VOTED, RESULTS_DEC = 0, {}, {}, False 		# Store the votes received till now and count of votes for each candidate 


def voter_conn(ctf_id, conn, addr, public_key, private_key):
	print('>> Voter ID: {0} connected to CTF ID: {1}'.format(addr[1], ctf_id))

	if addr[1] in HAS_VOTED:							# Check if the voter has already voted or not
		print('>> Voter ID: {0} has already voted.'.format(addr[1]))
		conn.sendall(pickle.dumps(-1, -1))
		return

	conn.sendall(pickle.dumps(CANDIDATES, -1))			# Send the choice of candidates to the voter
	conn.sendall(pickle.dumps(public_key, -1))			# Send the public key to the voter

	print('>> Waiting for Voter ID: {0} to cast vote.\n'.format(addr[1]))
	encrypted_vote = pickle.loads(conn.recv(4096))			# Receive the encrypted choice of vote from the voter
	actual_vote  = private_key.decrypt(encrypted_vote)		# Decrypt the vote
	print('>> Vote received from Voter ID: {0}\n'.format(addr[1]))

	global VOTES_RECEIVED, VOTE_COUNT, RESULTS_DEC
	VOTES_RECEIVED += 1
	VOTE_COUNT[actual_vote] += 1
	HAS_VOTED[addr[1]] = True

	while(VOTES_RECEIVED != NO_VOTERS):
		pass

	conn.sendall(pickle.dumps(VOTE_COUNT, -1))				# Send the final results to the voter

	if not RESULTS_DEC:
		RESULTS_DEC = True
		winner = max(VOTE_COUNT, key=VOTE_COUNT.get)			# Determine the winner of the election
		print('\nResults\n-------\n')
		if len([k for k, v in VOTE_COUNT.items() if v == VOTE_COUNT[winner]]) > 1:
			print('>> No winner as more than one candidates received the maximum votes.\n')
		else:
			print('>> Winner of the election: Candidate: {0} with {1} votes.\n'.format(winner, VOTE_COUNT[winner]))
		for contes in VOTE_COUNT:							# Print the votes received by each candidate
			print('Candidate: {0}, Votes: {1}\n'.format(contes, VOTE_COUNT[contes]))
		sleep(1)
		os._exit(1)

def start_ctf(id, port):
	ctf_port = port + id
	ctf_sock = socket.socket()				# Start a new server for each CTF
	ctf_sock.bind((SERVER_HOST, ctf_port))
	ctf_sock.listen(3)
	public_key, private_key = paillier.generate_paillier_keypair()
	while True:
		# Accept each voter client who wants to connect to the given CTF in a separate thread
		conn, addr = ctf_sock.accept()
		v = threading.Thread(target = voter_conn, args = (id, conn, addr, public_key, private_key))
		v.start()

def main():
	parser = argparse.ArgumentParser()			# Optional arguments
	parser.add_argument("--ctf", help="Number of Central Tabulating Facilities.", type=int, default=2)
	parser.add_argument("-v", "--voters", help="Number of eligible voters.", type=int, default=3)
	parser.add_argument("--candidates", help="Number of people contesting the election.", type=int, default=5)
	parser.add_argument("-p", "--port", help="The port number of the CTF server to connect to.", type=int, default=8000)
	args = parser.parse_args()
	global NO_VOTERS, NO_CTFS, CANDIDATES, VOTE_COUNT
	NO_VOTERS, NO_CTFS, CANDIDATES = args.voters, args.ctf, args.candidates
	VOTE_COUNT = dict.fromkeys(range(1, CANDIDATES + 1), 0)

	print('\nSecure voting protocol with multiple Central Tabulating Facilities (CTFs)\n')
	print('Number of CTFs: {0}'.format(NO_CTFS))
	print('Number of candidates: {0}'.format(CANDIDATES))
	print('Number of voters: {0}\n'.format(NO_VOTERS))

	for ctf in range(NO_CTFS):					# Create a new thread for each CTF
		t = threading.Thread(target=start_ctf, args=(ctf + 1, args.port))
		t.start()

if __name__ == '__main__':
	main()
