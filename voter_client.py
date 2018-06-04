# Secure voting protocol with multiple Central Tabulating Facilities (CTFs)
# CS-530 Information Security, Group: 5
# Voter Client

import socket
import pickle
import argparse

SERVER_HOST = "127.0.0.1"

def main():
	parser = argparse.ArgumentParser()					# Optional arguments
	parser.add_argument("--ctfid", help="The CTF to which send the vote to.", type=int, default=1)
	parser.add_argument("-p", "--port", help="The port number of the CTF server to connect to.", type=int, default=8000)
	args = parser.parse_args()
	PORT = args.port + args.ctfid
	voter_sock = socket.socket()						# Establish connection to the specified CTF server
	voter_sock.connect((SERVER_HOST, PORT))
	print('\n>> Connected to CTF ID: {0}'.format(args.ctfid))
	CANDIDATES = pickle.loads(voter_sock.recv(4096))		# Receive the number of candidates and the public key 
	if CANDIDATES == -1:									# Return if the voter has already voted
		return

	public_key = pickle.loads(voter_sock.recv(4096))
	print('>> Public key received from CTF: {0}\n'.format(str(public_key)))

	print('>> Number of Candidates in the election: {0}\n'.format(CANDIDATES))
	vote_choice = int(input('Select candidate to vote for: '))			# Input the choice of vote
	encrypted_vote = public_key.encrypt(vote_choice)					# Encrypt the vote and send to the CTF
	voter_sock.sendall(pickle.dumps(encrypted_vote, -1))

	print('\n>> Waiting for result..\n')
	vote_result = pickle.loads(voter_sock.recv(4096))
	winner = max(vote_result, key=vote_result.get)
	print('\nResults\n-------\n')								# Print the results received
	if len([k for k, v in vote_result.items() if v == vote_result[winner]]) > 1:
		print('>> No winner as more than one candidates received the maximum votes.\n')
	else:
		print('>> Winner of election: Candidate: {0} with {1} votes.\n'.format(winner, vote_result[winner]))
	for contes in vote_result:
		print('Candidate: {0}, Votes: {1}\n'.format(contes, vote_result[contes]))

if __name__ == '__main__':
	main()
