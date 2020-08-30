#!/usr/bin/env python3 

import argparse
import json
import socket
import os

TCP_IP = 'twistwislittlestar.fword.wtf'
TCP_PORT = 4445
BUFFER_SIZE = 1024


def create_socket(timeout:int=2) -> socket.socket:
    """
    Parameters
    ----------
    timeout: int
        The number of seconds to wait before timing out.
    Returns
    -------
    socket.socket
        The socket to be used for communication.
    """
    # Set up the socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.settimeout(timeout)
    return s



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="""Randomness is power, apparently!""",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-s", "--save_file", default="save_file",
            help="Path to the json file of saved random numbers..")
    args = parser.parse_args()

    # Load previous saves
    if not os.path.isfile(args.save_file):
        saved_data = {"random_numbers": []}
    else:
        with open(args.save_file, "r") as fin:
            saved_data = json.load(fin)

    # Create the socket
    soc = create_socket()
    # Ask for starting information
    soc.send(b"")
    intro = soc.recv(BUFFER_SIZE).decode('utf-8')
    print(intro)
    first_numbers = soc.recv(BUFFER_SIZE).decode('utf-8')
    print(first_numbers)
    # Extract the first numbers, through hard coding
    mess = first_numbers.split()
    random_numbers = []
    random_numbers.append(int(mess[4]))
    random_numbers.append(int(mess[9]))
    random_numbers.append(int(mess[14]))

    # Collect the other 20
    for i in range(20):
        # Make a guess
        guess = 1
        soc.send(f"{guess}\n".encode('utf-8'))
        # Get response
        laughter = soc.recv(BUFFER_SIZE).decode('utf-8')
        print(laughter)
        soc.send(b"")
        info = soc.recv(BUFFER_SIZE).decode('utf-8')
        print(info)
        # Collect random number
        random_numbers.append(int(info.split()[4]))

    # Clean up
    soc.close()

    saved_data["random_numbers"].append(random_numbers)
    
    # Save new data
    with open(args.save_file, "w") as fout:
        json.dump(saved_data, fout)

    print("We have no idea what we're doing :)")

