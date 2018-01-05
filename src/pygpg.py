import sys, os, os.path
import sqlite3
from pathlib import Path

from src.NTRUCrypt.EncryptionParameters import Parameters


def generateKey(keyid):
    from src.NTRUCrypt.NTRUCrypt import NTRUCrypt

    c = conn.cursor()
    keytable = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys';")
    result = keytable.fetchone()
    if result is None:
        c.execute("CREATE TABLE keys (email text, path_to_key text)")
        conn.commit()

    keyRecord = c.execute("SELECT * FROM keys WHERE email=?", [keyid]).fetchone()
    if not (keyRecord is None):
        print("There is already a key in the database for that id")
        sys.exit(0)

    while True:
        security = input("How secure should the keypair be? (112, 128, 192, or 256 bit security level)\n")
        try:
            security = int(security)
            if security == 112 or security == 128 or security == 192 or security == 256:
                break
            print("Please enter a valid number (112, 128, 192, 256)")
        except ValueError:
            print("Please enter a valid number (112, 128, 192, 256)")

    if security == 112:
        security = "ees659ep1"
    elif security == 128:
        security = "ees791ep1"
    elif security == 192:
        security = "ees1087ep1"
    elif security == 256:
        security = "ees1499ep1"

    while True:
        pw = input("Please enter a password to protect your keypair. \n"
                   "Please remember the security of the keypair is only as good \n"
                   "as the security of your chosen password\n")
        if pw != "":
            break

    crypt = NTRUCrypt(security)
    kp = crypt.keygen()
    keypath = kp.save(pw, configFolder)
    c.execute("INSERT INTO keys VALUES (?, ?)", (keyid, keypath))
    conn.commit()


def encryptFile(keyid, fileLoc):
    from src.NTRUCrypt.NTRUCrypt import NTRUCrypt, KeyPair
    from cryptography.fernet import Fernet
    import hashlib

    c = conn.cursor()
    keytable = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys';")
    result = keytable.fetchone()
    if result is None:
        c.execute("CREATE TABLE keys (email text, path_to_key text)")
        conn.commit()

    keyRecord = c.execute("SELECT * FROM keys WHERE email=?", [keyid]).fetchone()
    if keyRecord is None:
        print("There is no public key for that id!")
        sys.exit(0)

    fileLoc = Path(fileLoc)
    if not fileLoc.is_file():
        print("Cannot find a file at location: {}".format(fileLoc.absolute()))
        sys.exit(0)

    symkey = Fernet.generate_key()
    fernet = Fernet(symkey)
    pubkey = KeyPair.load(keyRecord[1], "", publicOnly=True).h

    with open(fileLoc, 'rb') as toEnc:
        dataBytes = toEnc.read()
        encryptedData = fernet.encrypt(dataBytes)
        dataHash = hashlib.sha256(dataBytes).digest()

    crypt = NTRUCrypt(Parameters.pset)
    encrypted_symkey = crypt.encrypt(symkey, pubkey)

    toWrite = {
        'for': keyid,
        'symkey': [x for x in encrypted_symkey],
        'symdata': [x for x in encryptedData],
        'dataHash': [x for x in dataHash],
    }
    writeLoc = str(fileLoc.absolute()) + ".pygpg"

    with open(writeLoc, 'w') as fp:
        import json
        json.dump(toWrite, fp)


def decryptFile(fileLoc):
    from src.NTRUCrypt.NTRUCrypt import NTRUCrypt, KeyPair
    from cryptography.fernet import Fernet, InvalidToken
    import hashlib

    c = conn.cursor()
    keytable = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys';")
    result = keytable.fetchone()
    if result is None:
        c.execute("CREATE TABLE keys (email text, path_to_key text)")
        conn.commit()

    fileLoc = Path(fileLoc)
    if not fileLoc.is_file():
        print("Cannot find a file at location: {}".format(fileLoc.absolute()))
        sys.exit(0)

    with open(fileLoc, 'rb') as fp:
        import json
        contents = json.load(fp)

    keyid = contents['for']
    symkey = bytes(contents['symkey'])
    symdata = bytes(contents['symdata'])
    dataHash = bytes(contents['dataHash'])

    keyRecord = c.execute("SELECT * FROM keys WHERE email=?", [keyid]).fetchone()
    if keyRecord is None:
        print("There is no public key for that id!")
        sys.exit(0)

    for i in range(3):
        pw = input("[{}/3] Please enter the password to unlock the keyfile:\n".format(i+1))
        try:
            kp = KeyPair.load(keyRecord[1], pw)
            break
        except InvalidToken:
            print("wrong password!")
            if i == 2:
                print("Too many wrong tries!")
                sys.exit(0)

    crypt = NTRUCrypt(Parameters.pset)
    key = crypt.decrypt(symkey, kp.f, kp.h)
    fernet = Fernet(key)
    try:
        fileData = fernet.decrypt(symdata)
    except InvalidToken:
        print("provided symmetric key does not decrypt the file!")
        sys.exit(0)

    if hashlib.sha256(fileData).digest() != dataHash:
        print("hash of the decrypted data does not match provided data hash!")
        sys.exit(0)

    writeLoc = fileLoc.parent.joinpath(os.path.splitext(os.path.basename(fileLoc))[0])
    with open(writeLoc, 'wb') as fp:
        fp.write(fileData)



help = "usage: \n" \
       "pygpg -e [id] [file] \n" \
       "pygpg -d [file]\n" \
       "pygpg -g [id]"

configFolder = ""

if len(sys.argv) < 3 or \
        (sys.argv[1] == "-e" and len(sys.argv) < 4):
    print(help)
    sys.exit()

if os.name == "posix":
    configFolder = os.path.join(os.path.expanduser("~"), ".pygpg")
else:
    configFolder = os.path.join(os.getenv('APPDATA'), "pygpg")


keyDb = os.path.join(configFolder, "key.db")

configFolder = Path(configFolder)
keyDb = Path(keyDb)

if not configFolder.is_dir():
    os.makedirs(configFolder.absolute())

conn = sqlite3.connect(str(keyDb.absolute()))

if sys.argv[1] == "-g":
    generateKey(sys.argv[2])
elif sys.argv[1] == "-e":
    encryptFile(sys.argv[2], sys.argv[3])
elif sys.argv[1] == "-d":
    decryptFile(sys.argv[2])

