#!/usr/bin/env python3 

import argparse
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
    ----------
    i: int
        The value to bound within the array.
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

def create_socket(timeout:int=60) -> socket.socket:
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


def collect_equations(s: socket.socket, n:int=1337) -> list:
    """
    Parameters
    ----------
    s: socket.socket
        The socket to communicate with.
    n: int
        The number of equations to gather.
    Returns
    -------
    list
        The list of equation values.
    """
    equations = []
    for i in range(n):
        # Equations values are requested in pairs.
        i_p1 = bounds_correct(i+1, n)
        # Request the pair of information
        s.send(f"{i} {i_p1}\n".encode('utf-8'))
        # Receive the value
        received_info = s.recv(BUFFER_SIZE).decode('utf-8')
        # Cast and store the value
        equations.append(int(received_info.split()[0]))
        # Print out equation, for prettiness?
        print(f"[{i}] + [{i_p1}] = {equations[-1]}")
        # Clear up communications for next request
        s.send(b"")
        s.recv(BUFFER_SIZE)
    return equations


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
    print(formatted_solution)
    # Send it off!
    s.send(f"DONE {formatted_solution}".encode('utf-8'))
    # Receive the flag (if we're correct)!
    flag = s.recv(BUFFER_SIZE).decode('utf-8')
    return flag


# Equation Solving
def solve_for_one(target:int, equations:list) -> int:
    """Solve for one of the equations
    The equations in the form of 'array[n]+array[n+1]', and the given
        array is actually the values of these equations.
    The solution is to subtract every other value from the target value.
    This cancels out every other value, except the target, thus solving it.
    Note, this will fail if the number of values/equations is even, as the
    result will be 0 every time.
    Thankfully the CTF is 1337, which is odd.
    Parameters
    ----------
    target: int
        The value to solve for
    equations: list
        List of value results for the equations in the form of 'array[n]+array[n+1]'
    Returns
    -------
    int
        The solution to index 'target'
    """
    def bounds_loop():
        for i in range(len(equations)):
            yield bounds_correct(target + i, len(equations))

    def equation_parts():
        for i in bounds_loop():
            yield equations[i]

    # Solve the equation, which is subtracting everything in reverse.
    def subtract(eq_parts, pretty_internal=""):
        if len(eq_parts) == 2:
            num = eq_parts[0] - eq_parts[1]
            pretty_internal += f"{eq_parts[0]}-{eq_parts[1]})"
            return num, pretty_internal
        else:
            num, pretty_internal = subtract(eq_parts[1:], pretty_internal)
            num = eq_parts[0] - num
            pretty_internal = f"{eq_parts[0]}-({pretty_internal}"
            return num, pretty_internal

    parts = list(equation_parts())
    partial_solution, partial_pretty = subtract(parts)
    # Use floor division to not induce floating point errors
    solution = partial_solution // 2
    pretty = f"[{target}] = {solution} = "\
            f"0.5*({partial_pretty}{')'*(len(equations)-2)}"
    print(pretty)
    return solution


def solve_for_all(equations:list) -> list:
    """Solve for all of the equations
    Parameters
    ----------
    equations: list
        List of value results for the equations
    Returns
    -------
    list
        The solutions
    """
    solutions = []
    for i in range(len(equations)):
        solutions.append(solve_for_one(i, equations))
        print_spacer()
    return solutions


def create_test_equations(test_array: list) -> list:
    """Generate the values for equations for the given array
    The values are in the form of 'array[n]+array[n+1]'
    Parameters
    ----------
    test_array: list
        The test array to create the test equation results for.
    Returns
    ----------
    list
        The equations created from the given array
    """
    test_equations = []
    for i in range(len(test_array)):
        # Equations values are requested in pairs.
        i_p1 = i +1
        # Take care of an out of bounds value
        if i_p1 >= len(test_array):
            i_p1 -= len(test_array)
        test_equations.append(test_array[i] + test_array[i_p1])
        print(f"[{i}] + [{i_p1}] = {test_equations[-1]}")
    return test_equations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Solve the CTF",
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
        test_array = []
        for i in range(args.number):
            test_array.append(random.randint(0,pow(10,25)))
        print(f"Test Array: {test_array}")
        print_spacer()
        test_equations = create_test_equations(test_array)
        print_spacer()
        solutions = solve_for_all(test_equations)
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
        print("Gathering equations")
        equations = collect_equations(s)
        # Solve equations
        print("Solving equations")
        solutions = solve_for_all(equations)
        # Submit information to receive the flag
        print("Submitting solution")
        flag = submit_information(s, solutions)
        # Celebrate (probably)
        print(flag)
        # Clean up
        s.close()

