# ip_scanner
Playing with local IP addresses through a CLI made with Python.

This small program emphasizes the use of multithreading.

*The program works only on windows 10.

## To run the program:
From the command line (at the script's path) type `ip_scanner.py help` and follow the instructions.

# Examples:

## scan the local ip addresses with 256 threads:

`ip_scanner.py scan -t 256`

## spamming specific address:

`ip_scanner.py 192.168.1.15 -t 2000 -n 4`
