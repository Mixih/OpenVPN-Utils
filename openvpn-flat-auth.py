#!/usr/bin/python3
from abc import ABC, abstractmethod
import base64
from getpass import getpass
from hashlib import sha384
from os import environ
from sys import argv,  exit

import bcrypt

filestore = '/etc/openvpn/server/store.txt'

# abstract out implementation backends
class PassStore(ABC):

    @abstractmethod
    def checkPass(self, user: str, pw: str) -> bool:
        pass

    @abstractmethod
    def checkUser(self, user):
        pass

    @abstractmethod
    def addUser(self, user: str, pw: str):
        pass

class FlatfileStore(PassStore):

    def __init__(self, passfile):
        self.passfile = passfile

    def checkPass(self, user: str, pw: str):
        with open(self.passfile, 'r') as f:
            for line in f.readlines():
                parts = line[:-1].split(':')
                if(user == parts[0]):
                    if(bcrypt.checkpw(base64.b64encode(sha384(pw.encode()).digest()), parts[1].encode())):
                        return True
                    else:
                        return False
            return False

    def checkUser(self, user: str):
        with open(self.passfile, 'r') as f:
            for line in f.readlines():
                if user == line.split(':')[0]:
                    return true
            return false

    def addUser(self, user, pw):
        with open(self.passfile, 'a') as f:
            f.write(user + ':' + bcrypt.hashpw(base64.b64encode(sha384(pw.encode()).digest()),
                                               bcrypt.gensalt()).decode() + '\n')

def main():
    ffs = FlatfileStore(filestore)
    user = ''
    pw = ''
    with open(argv[1], 'r') as f:
        user = f.readline()[:-1]
        pw = f.readline()[:-1]
    if (ffs.checkPass(user, pw) == True):
        exit(0)
    else:
        exit(1)

def enrollUser():
    ffs = FlatfileStore(filestore)
    print('Enter user: ', end='')
    user = input()
    pw = getpass()
    ffs.addUser(user, pw)

if __name__ == '__main__':
    main()

