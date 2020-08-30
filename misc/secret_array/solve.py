#!/usr/bin/env python3 

import argparse
import itertools
import random
import socket
import sys
# The target CTF requires at least a recursion of 1337
sys.setrecursionlimit(2000)


TCP_IP = 'secretarray.fword.wtf'
TCP_PORT = 1337
BUFFER_SIZE = 1024

def print_spacer(number_of_dashes:int=10) -> None:
    """Print some dashes as a spacer
    Parameters
    ----------
    number_of_dashes: int
        The number of dashes to print on the line.
    """
    print("-"*number_of_dashes)


def bounds_correct(i:int, array_size:int) -> int:
    """Convert a value to the bounds of [0,array_size]
    Note, this will fail if you go array_size+1 out of the
        bounds.
    Parameters
    ---------- i: int The value to bound within the array.
    array_size: int
        The size of the array
    Returns
    -------
    int
        The value within the bounds of the array
    """
    if i >= array_size:
        return i - array_size
    elif i < 0:
        return i + array_size
    else:
        return i

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


def submit_information(s: socket.socket, solutions:list) -> str:
    """
    Parameters
    ----------
    s: socket.socket
        The socket to communicate with.
    solutions: list
        The secret array
    Returns
    -------
    str
        The flag!
    """
    # Format the solutions
    formatted_solution = " ".join((str(s) for s in solutions))
    # Send it off!
    s.send(f"DONE {formatted_solution}\n".encode('utf-8'))
    # Receive the flag (if we're correct)!
    congratulations = s.recv(BUFFER_SIZE).decode('utf-8')
    print(congratulations)
    s.send(b"")
    flag = s.recv(BUFFER_SIZE).decode('utf-8')
    return flag


# Equation Solving
def query_pair(s, i:int, j:int) -> int:
    """Query the value of arr[i]+arr[j]
    Parameters
    ----------
    s: socket.socket or list
        The socket to communicate with.
        OR, the array itself. Useful in the testing phase.
    i: int
        The i-th index to query information fromk
    j: int
        The j-th index to query information fromk
    Returns
    -------
    int
        The value arr[i]+arr[j]
    """
    if isinstance(s, list):
        return s[i] + s[j]
    else:
        # Request the pair of information
        s.send(f"{i} {j}\n".encode('utf-8'))
        # Receive the value
        received_info = s.recv(BUFFER_SIZE).decode('utf-8')
        # Clear up communications for next request
        s.send(b"")
        s.recv(BUFFER_SIZE)
        # Cast and return the value
        return int(received_info.split()[0])


def calulate_while_querying(s, n:int) -> list:
    """Calculate while querying the information.
    Parameters
    ----------
    s: socket.socket or list
        The socket to communicate with.
        OR, the array itself. Useful in the testing phase.
    n: int
        The number of numbers
    Returns
    -------
    list
        The solutions
    """
    # info is built as [0]+[1], [1]+[2], ..., [n-2]+[n-1] [n-1]+[0]
    info = []
    # calculations is built as [0], [1], ..., [n-2], [n-1]
    calculations = []

    # Calculate as we query
    for i, k_start in zip(
            range(0,n), itertools.chain([0], range(n))):
        # Calculate i value
        j = bounds_correct(i+1, n)
        # Print status
        print(f"i:{i}, j:{j}", end="\r")
        # Query new information
        info.append(query_pair(s, i, j))
        # Append new info as start of new calculation
        calculations.append(info[-1])
        # Calculate as far as we can
        for k in range(0, len(info)-1):
            calculations[k] = info[-1] - calculations[k]
    print("Finishing up equations")

    # Finishing touches with collected info
    for l in range(1, n):
        for k in range(l, len(info)):
            k = bounds_correct(k, n)
            calculations[k] = info[l-1] - calculations[k]

    # Finish calculations
    for i in range(n):
        calculations[i] = calculations[i] // 2

    return calculations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="""
    The equations in the form of 'array[n]+array[n+1]', and the given
        array is actually the values of these equations.
    The solution is to subtract every other value from the target value.
    This cancels out every other value, except the target, thus solving it.
    Note, this will fail if the number of values/equations is even, as the
    result will be 0 every time.
    Thankfully the CTF is 1337, which is odd.""",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-t", "--test", help="Run on test input.",
            default=False, action="store_true")
    parser.add_argument("-n", "--number", 
            help="Number of numbers. This obviously has to be positive, "\
                    "but it also has to be an odd number.",
            default=1337, type=int)
    args = parser.parse_args()

    if args.number % 2 == 0:
        print("The number of numbers must be odd!")
        exit(1)

    if args.test:
        # Create test array for random integers
        test_array = []
        for i in range(args.number):
            test_array.append(random.randint(0,pow(10,25)))
        print(f"Test Array: {test_array}")
        print_spacer()
        # Solve for the integers
        solutions = calulate_while_querying(test_array, len(test_array))
        print(f"Test Array: {test_array}")
        print(f"Solutions:  {solutions}")
        print_spacer()
        print(f"Correct?: {test_array == solutions}")
    else:
        # Create the socket
        s = create_socket()
        # Ask for starting information
        s.send(b"")
        print(s.recv(BUFFER_SIZE))
        s.send(b"")
        # Get the equation information
        print("Querying information, and solving equations")
        solutions = calulate_while_querying(s, args.number)
        # Submit information to receive the flag
        print("Submitting solution")
        flag = submit_information(s, solutions)
        # Celebrate (probably)
        print(flag)
        # Clean up
        s.close()

