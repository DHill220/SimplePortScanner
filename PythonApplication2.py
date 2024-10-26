

"""
Basic Port Scanner 
"""

from ast import Num
import socket
from argparse import ArgumentParser
import threading
from   queue import Queue as q
from token import STAR


def scan_port(ip,port,open_ports,lock):
    try:
        #Create a new socket using IPv4 (AF_INET) and TCP (SOCK_STREAM)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        results = s.connect_ex((ip,port))

        if results == 0:
            with lock:
                open_ports.append(port)
        s.close()
    except socket.error:
        #ignore any sockets errors and move on 
        pass

    def worker(ip,queue,open_ports,lock):
        #run by each threads to process to ports from the queue.


        while True:
            try:
                #Get a prot number from the q without blocking
                port = q.get_nowait()
                #Scan the port
                scan_port(ip,port,open_ports,lock)
                #signal that the task is done
                q.task_done()
            except Queue.Empty:
                #if the queue is empty, exit the loop
                break


def  scan_ports(ip, start_point, end_point, num_threads=100):
    
    open_ports = []             #shared list to store open ports
    lock = threading.lock()     #lock to sync access to oen_ports
    q = q()                     #Queue to hold the ports to be scanned 

    # add all porst in the specified range to the queue

    for port in range(start_point, end_point + 1):
        q.put:(port)

    thread_list = []
    actual_threads = min(num_threads, end_point - start_point +1)

    for _ in range(actual_threads):
        thread = worker,
        args =(ip,q,open_ports,lock)


        thread.daemon = True
        thread.start()
        thread_list.append(thread)

        q.join()

        for thread in thread_list:
            thread.join()

        return sorted(open_ports)


def print_results(ip,open_ports,duration):

    print("\nScan Complete")
    print("Duration: {duration:.2f} seconds")
    print("\nResults:")

    if open_ports:
        print("\nOpen ports:")
        for port in open_ports:
            try:
                service = socket.getservbyname(port)
            except OSError:
                service = "unknown"

            print("  Port {port}: {service}")

    else:
        print("\n No open ports found")


def main():
    
    #Set up command line arg parsing

    parser = ArgumentParser(description='Basic Port Scanning')
    parser.add_argument('target', help='target IP address or hostname')
    parser.add_argument(
        '-s', '--start',
        type=int,
        default=1,
        help='Starting port (default: 1)'
    )

    parser.add_argument(
        '-e', '--end',
        type=int,
        default=1024,
        help='Ending port (default: 1024)'
    )

    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=100,
        help='Number of threads to use (default:100)'
    )

    args = parser.parse_args()

    try:
        #resulve the hostname to an IP address
        target_ip = socket.gethostbyname(args.target)

        print("\nStarting Scan {args.target} ({target_ip})")
        print("Port range: {args.start}-{args.end}")
        print("using {args.threads} threads")
        print("\nScanning")
        
        start_time = time.time()

        open_ports = scan_ports(
            target_ip,
            args.start,
            args.end,
            args.threads
        )

        duration = time.time() - start_time
        
        print_results(target_ip,open_ports,duration)

    except socket.socket.gaierror:
            print("Error: Could not resolve hostname")

    except KeyboardInterrupt:
            print("\nScan interupted by user")

    except Exception as e:
        print("An error occurred: {e}")

if __name__ == "__main__":
    main()

        