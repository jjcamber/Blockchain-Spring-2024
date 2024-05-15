import copy
import struct
import sys
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from datetime import datetime
from collections import namedtuple
import os
import struct
import hashlib

# Josh Camberg
# Group 999
# Blockchain Project
# CSE 469

key =  b"R0chLi4uLi4uLi4="

def bite(byte_data):
    # Convert bytes to a byte string notation
    return repr(byte_data)

def encrypt_case(ID):
    global key
    ID = ID.replace('-', '')
    data_as_bytes = bytes.fromhex(ID)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(data_as_bytes)
    hex_data = encrypted_data.hex()
    return hex_data
def encrypt_item(ID):
    global key
    ID = int(ID)
    data_as_bytes = ID.to_bytes(16, byteorder='big', signed=False)  
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(data_as_bytes)
    hex_data = encrypted_data.hex()
    return hex_data
def decrypt_case(encrypted_hex):
    global key
    encrypted_data = bytes.fromhex(encrypted_hex.decode())
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_data = cipher.decrypt(encrypted_data)
    decrypted_data = decrypted_padded_data.hex()
    #decrypted_data = f"{decrypted_data[:8]}-{decrypted_data[8:12]}-{decrypted_data[12:16]}-{decrypted_data[16:20]}-{decrypted_data[20:]}"
    return decrypted_data
def decrypt_item(encrypted_hex):
    global key
    print(encrypted_hex)
    encrypted_data = bytes.fromhex(encrypted_hex.decode())
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    decrypted_int = int.from_bytes(decrypted_data, byteorder='big', signed=False)
    return str(decrypted_int)

init_block = {
    'prev_hash' : (0).to_bytes(32, byteorder = 'little'),
    'time' : (0).to_bytes(8, byteorder = 'little'),
    'case_id' : b'0' * 32,
    'item_id': b'0' * 32,
    'state': b"INITIAL".ljust(5,b"\0"),
    'creator': b"\0".ljust(12,b'\x00'),
    'owner': b"\0".ljust(12,b'\x00'),
    'data_len' : (14).to_bytes(4, byteorder = 'little'),
    'data' : b"Initial block\0"
}

blocks = []
prev_hash = ''
owner = ''

#file_chain = 'blockchain.bin'
file_chain = os.environ.get('BCHOC_FILE_PATH')

os.environ["BCHOC_PASSWORD_POLICE"] = "P80P"
os.environ["BCHOC_PASSWORD_LAWYER"] = "L76L"
os.environ["BCHOC_PASSWORD_ANALYST"] = "A65A"
os.environ["BCHOC_PASSWORD_EXECUTIVE"] = "E69E"
os.environ["BCHOC_PASSWORD_CREATOR"] = "C67C"


block_head_form = struct.Struct('32s d 32s 32s 12s 12s 12s I')
head_form = '>32s26s36s36s12s12s12s4s100s'


######################################################################################################################## Helpers

# helper function for displaying case id and items inside the cases
def load_blocks(filename):
    block_size = struct.calcsize('>32s26s36s36s12s12s12s4s100s')  # Correct block size based on serialization format
    with open(filename, 'rb') as file:
        while True:
            block_data = file.read(block_size)
            if not block_data:
                break
            block = deserialize(block_data)
            if block:
                yield block
            else:
                break  # Stop if a block fails to deserialize properly

def serialize(block):
    try:
        # Pack data: Ensure all fields are correctly formatted as bytes
        # Example assumes fields are already in appropriate formats or converted as such
        block_string = struct.pack(
            head_form,
            block
        )
        with open(file_chain, 'wb') as file:
            file.write(block_string)
        print("Serialized block for case_id:", block['case_id'])
        return block_string
    except KeyError as e:
        print(f"Failed to serialize block: Missing key {e}")
    except Exception as e:
        print(f"Failed to serialize block: {e}")
    return None
    
def deserialize(binary_data):
    try:
        fmt = '>32s26s36s36s12s12s12s4s100s'  # Ensure this matches serialization format
        unpacked_data = struct.unpack(fmt, binary_data)
        block = {
            'prev_hash': unpacked_data[0].decode().strip('\x00'),
            'time': unpacked_data[1].decode().strip('\x00'),
            'case_id': unpacked_data[2].decode().strip('\x00'),
            'item_id': unpacked_data[3].decode().strip('\x00'),
            'state': unpacked_data[4].decode().strip('\x00'),
            'creator': unpacked_data[5].decode().strip('\x00'),
            'owner': unpacked_data[6].decode().strip('\x00'),
            'data_len': int(unpacked_data[7].decode().strip('\x00')),
            'data': unpacked_data[8].decode().strip('\x00')
        }
        return block
    except Exception as e:
        print(f"Error during deserialization: {e}")
        return None

def get_item_ids():
    pass

# helper function to verify if a given password is a recognized one
def verify_pass(password):
    global owner
    if password == os.environ.get('BCHOC_PASSWORD_POLICE'):
        owner = "Police"
        return True
    if password == os.environ.get('BCHOC_PASSWORD_LAWYER'):
        owner = "Lawyer"
        return True
    if password == os.environ.get('BCHOC_PASSWORD_ANALYST'):
        owner = "Analyst"
        return True
    if password == os.environ.get('BCHOC_PASSWORD_EXECUTIVE'):
        owner = "Executive"
        return True
    if password == os.environ.get('BCHOC_PASSWORD_CREATOR'):
        owner = ""
        return True
    return False

def unpack_all():
    global blocks, file_chain, block_head_form

    print('unpacking')
    for i, block in enumerate(blocks):
        print(f"Block {i + 1}:")
        for key, value in block.items():
            print(f"  {key}: {repr(value)}")
        print()

    with open(file_chain, 'rb') as blockchain:
        while True:
            # Read and unpack the block header
            block_header = blockchain.read(block_head_form.size)
            if not block_header:
                break  # Exit if no more data to read
            block_content = struct.unpack(block_head_form.format, block_header)
            
            # Read the data part of the block
            data = blockchain.read(block_content[7])  # Read data_len bytes
            # Create current block dictionary
            curr_block = {
                'prev_hash': block_content[0].decode('utf-8'),
                'time': block_content[1],
                'case_id': block_content[2],
                'item_id': block_content[3],
                'state': block_content[4].decode('utf-8'),
                'creator': block_content[5].decode('utf-8'),
                'owner': block_content[6].decode('utf-8'),
                'data_len': block_content[7],
                'data': data.decode('utf-8')
            }
            if curr_block['state'] != 'INITIAL\x00\x00\x00\x00\x00':
                print(curr_block['case_id'])
                decrypted_item = decrypt_item(curr_block['item_id'])
                decrypted_case = decrypt_case(curr_block['case_id'])
                decrypted_item = decrypt_item(curr_block['item_id'])
                curr_block['case_id'] = decrypted_case
                curr_block['item_id'] = decrypted_item
            blocks.append(curr_block)
    blockchain.close()
    
def pack_all():
    global blocks, file_chain

    print('packing')
    for i, block in enumerate(blocks):
        print(f"Block {i + 1}:")
        for key, value in block.items():
            print(f"  {key}: {repr(value)}")
        print()

    timestamp = datetime.timestamp(datetime.now())
    blockchain = open(file_chain, 'wb')
    for block in blocks:
        block_hash_val = struct.pack('32s', str.encode(block['prev_hash']))
        blockchain.write(block_hash_val)
        block_timestamp_val = struct.pack('d', timestamp)
        blockchain.write(block_timestamp_val)
        print('before')
        if block['state'] == 'INITIAL\x00\x00\x00\x00\x00':
            blockchain.write(block['case_id'])
            blockchain.write(block['item_id'])
        else:
            print(block['case_id'])
            block_case_id = encrypt_case(block['case_id'])
            print(block_case_id)
            blockchain.write(block_case_id.encode('utf-8'))
            block_item_id = encrypt_item(block['item_id'])
            print(block_item_id)
            blockchain.write(block_item_id.encode('utf-8'))
        block_state_val = struct.pack('12s', str.encode(block['state']))
        blockchain.write(block_state_val)
        block_creator_val = struct.pack('12s', str.encode(block['creator']))
        blockchain.write(block_creator_val)
        block_owner_val = struct.pack('12s', str.encode(block['owner']))
        blockchain.write(block_owner_val)
        print('middle')
        block_data_len_val = struct.pack('<I', block['data_len'])
        blockchain.write(block_data_len_val)
        print('middle 2')
        block_data_val = struct.pack(f'{len(block["data"])}s', str.encode(block['data']))
        print('after')
        print(block_data_val)
        blockchain.write(block_data_val)
        print('after2')
    blockchain.close
    

############################################################################################################################ Functions

def display_case_ids(filename):
    print("Available Cases:")
    cases = set()
    for block in load_blocks(filename):
        # Skip genesis block for display
        if block['case_id'] != 'None':
            cases.add(block['case_id'])
    for case in cases:
        print("Case ID:", case)

def display_items_in_case(filename, case_id):
    print(f"Displaying Items for Case ID {case_id}:")
    for block in load_blocks(filename):
        # Filter out blocks that do not match the input case ID and genesis block
        if block['case_id'].upper() == case_id.upper() and block['case_id'] != 'None':
            print(f"Item ID: {block['item_id']}, State: {block['state']}, Creator: {block['creator']}, Owner: {block['owner']}, Description: {block['data']}")

def add(case_id, item_ids, creator, password):
    global prev_hash
    print_case_num = 0
    if verify_pass(password) == False:
        sys.exit(1)

    try:
        block = open(file_chain, 'rb')
        block.close()
    except:
        timestamp = datetime.timestamp(datetime.now())

        block_head_form_1 = struct.Struct('32s d I I 12s 12s 12s')

        block_head_vals = (str.encode(""), timestamp, 0, 0, str.encode("INITIAL"), str.encode(""), str.encode(""))
        
        block_hash_val = struct.pack('32s', str.encode(""))
        block_timestamp_val = struct.pack('d', timestamp)
        block_case_id_val = b'0'*32
        block_item_id_val = b'0'*32
        block_state_val = struct.pack('12s', str.encode("INITIAL"))
        block_creator_val = struct.pack('12s', str.encode(""))
        block_owner_val = struct.pack('12s', str.encode(""))
        
        block_data_val = str.encode("Initial block")
        block_data_len_val = struct.pack('<I', 14)
        block_data_form = struct.Struct('14s')
        packed_head_vals = block_head_form_1.pack(*block_head_vals)
        packed_data_val = block_data_form.pack(block_data_val)

        # Pack the data according to the format
        block = open(file_chain, 'wb')
        block.write(block_hash_val)
        block.write(block_timestamp_val)
        block.write(block_case_id_val)
        block.write(block_item_id_val)
        block.write(block_state_val)
        block.write(block_creator_val)
        block.write(block_owner_val)
        block.write(block_data_len_val)
        block.write(packed_data_val)
        block.close()
        sys.exit(0)
    
    unpack_all()

    for item_id in item_ids:
        for block in blocks:
            if block['item_id'] == item_id:
                print(f'\n{item_id} was skipped because it is already present')
                sys.exit(1)
            if not print_case_num:
                print("Case: ", case_id)
                print_case_num += 1

        new_block = copy.deepcopy(blocks[0])
        new_block['case_id'] = case_id
        new_block['item_id'] = item_id
        new_block['state'] = 'CHECKEDIN\x00\x00'
        new_block['creator'] = creator
        new_block['data_len'] = 0
        new_block['data'] = ''
        blocks.append(new_block)
        print(new_block['case_id'])
        print(new_block['item_id'])
        print("Added item:", )
        print("\tStatus: CHECKEDIN")
        print("\tTime of action:", datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')
        
        

    # Pack the data according to the format
    pack_all()


    sys.exit(0)


            

def checkout(item_id, password):
    found_item = False
    # read in binary file

    # populate struct array

    # find item in struct array

    # change status

    # encrpyt

    # store to binary file (in BINARY)

    
    # check password before anything else 
    # basically need to ensure that the item exists within the blockchain
    # once we know that it exists in the blockchain, we can create the checkin entry

    # if password doesn't match anything in records, deny access.
    if verify_pass(password) == False:
        #idk do some exit function here and tell user da pass is wrongggg
        return



    # else password matches and function gives the info

    # read binary file
    block = open(file_chain, 'rb')

    # use a while true loop to iterate through all blocks within data file.
    # while loop breaks off of the try except statement which triggers when any
    # statement within the try fails (indicating no more blocks and end of data file)
    while True:

        try:
            block_head_content = block.read(head_form.size)
            curr_block_head = block_head._make(head_form.unpack(block_head_content))
            data_content = block.read(curr_block_head.length)
            
            prev_hash = hashlib.sha256(block_head_content+data_content).digest()

            # we have current block's info. check for item id hit. if hit, store some data
            if int(item_id[0]) == curr_block_head.item_id:
                case_id = curr_block_head.count
                state = curr_block_head.state
                found_item = True

        except:
            break

    # done reading from file
    block.close()

    # if we found a match in blockchain, change state and print da info
    if found_item:
        if state.decode('utf-8').rstrip('\x00') == "CHECKEDIN":
            timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
            head_vals = (prev_hash, timestamp, case_id, int(item_id[0]), str.encode("CHECKEDIN"), 0)
            data_val = b''
            block_data_form = struct.Struct('0s')
            packed_head_vals = head_form.pack(*head_vals)
            packed_data_vals = block_data_form.pack(data_val)
            curr_block_head = block_head._make(head_form.unpack(packed_head_vals))
            

            # write data to binary file
            block = open(file_chain, 'ab')
            block.write(packed_head_vals)
            block.write(packed_data_vals)
            block.close()

            # relay info to user via cmd line
            print("Case: ", str(uuid.UUID(bytes=case_id)))
            print("Checked out Item: ", item_id[0])
            print("Status: CHECKEDOUT")
            print("Time of action: ", datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')

def checkin(item_id, password):
    found_item = False
    # read in binary file

    # populate struct array

    # find item in struct array

    # change status

    # encrpyt

    # store to binary file (in BINARY)

    
    # check password before anything else 
    # basically need to ensure that the item exists within the blockchain
    # once we know that it exists in the blockchain, we can create the checkin entry

    # if password doesn't match anything in records, deny access.
    if verify_pass(password) == False:
        #idk do some exit function here and tell user da pass is wrongggg
        return

    # else password matches and function gives the info

    # read binary file
    block = open(file_chain, 'rb')

    # use a while true loop to iterate through all blocks within data file.
    # while loop breaks off of the try except statement which triggers when any
    # statement within the try fails (indicating no more blocks and end of data file)
    while True:

        try:
            block_head_content = block.read(head_form.size)
            curr_block_head = block_head._make(head_form.unpack(block_head_content))
            data_content = block.read(curr_block_head.length)

            prev_hash = hashlib.sha256(block_head_content+data_content).digest()

            # we have current block's info. check for item id hit. if hit, store some data
            if int(item_id[0]) == curr_block_head.item_id:
                case_id = curr_block_head.count
                state = curr_block_head.state
                found_item = True

        except:
            break

    # done reading from file
    block.close()

    # if we found a match in blockchain, change state and print da info
    if found_item:
        if state.decode('utf-8').rstrip('\x00') == "CHECKEDOUT":
            timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
            head_vals = (prev_hash, timestamp, case_id, int(item_id[0]), str.encode("CHECKEDIN"), 0)
            data_val = b''
            block_data_form = struct.Struct('0s')
            packed_head_vals = head_form.pack(*head_vals)
            packed_data_vals = block_data_form.pack(data_val)
            curr_block_head = block_head._make(head_form.unpack(packed_head_vals))


            # write data to binary file
            block = open(file_chain, 'ab')
            block.write(packed_head_vals)
            block.write(packed_data_vals)
            block.close()

            # relay info to user via cmd line
            print("Case: ", str(uuid.UUID(bytes=case_id)))
            print("Checked in Item: ", item_id[0])
            print("Status: CHECKEDIN")
            print("Time of action: ", datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')

def show_cases(password):
    pass

def show_items(case_id, password):
    pass

def show_history(case_id, item_id, num_entries, reverse, password):
    pass

def removal(item_id, reason, password):
    pass

# Validate all entries
def verify_chain(self):
    badBlock = ""
        # Open the file
    with open(self.path, 'rb') as f:
            actual_prev_hash = b'\x00' * 32  # Initial block has no previous hash
            count = 0

            # Loop through the file
            while True:
                count += 1

                # Analyze the block
                block = f.read(0x90)

                # If there is no block detected, break the loop
                if not block:
                    break
                
                # Read the itemID, state
                itemID = block[0x48:0x68]
                state = block[0x68:0x74].strip(b'\x00').decode('utf-8')

                # Obtain the previous hash saved in the block alongside the data
                previous_hash = block[0x00:0x20]
                dataLength = block[0x8c:0x90]
                targetData = f.read(int.from_bytes(dataLength, 'little'))
                
                validPreviousHash = previous_hash == actual_prev_hash

                # Retrieve the hash value of the current block
                actual_prev_hash = hashlib.sha256(block + targetData).digest()

                # Find a duplicate block
                duplicateBlock = self.duplicateBlockCheck(hashlib.sha256(block + targetData).digest())
                if (duplicateBlock):
                    badBlock = f"Bad block: {actual_prev_hash.hex()}\nTwo duplicate blocks were found"
                    break

                # Find a duplicate parent block
                duplicateParent = self.duplicateParentCheck(previous_hash)
                if (duplicateParent):
                    badBlock = f"Bad block: {actual_prev_hash.hex()}\nTwo blocks were found with the same parent"
                    break

                # Verify transition 
                invalidTransitionString = self.validTransitionCheck(itemID, state, count)
                if (invalidTransitionString != None):
                    badBlock = f"Bad block: {actual_prev_hash.hex()}\n{invalidTransitionString}"
                    break

                # Verify hash values
                if (not validPreviousHash):
                    badBlock = f"Bad block: {actual_prev_hash.hex()}\nBlock Contents do not match block checksum"
                    break
    # No bad block chain detected
    return badBlock


# function that initializes a block only if a blockchain file is already found within the intial block
def init():
    # if we try to open the file and it fails, we need to create the file, reflected
    # in the except phase of the except block. Else, we just open and close file
    try: 
        block = open(file_chain, 'rb')
        block.close()
    except:
        # open, write to and close file
        print("Blockchain file not found. Created INITIAL block")

        timestamp = datetime.timestamp(datetime.now())

        block_head_form_1 = struct.Struct('32s d I I 12s 12s 12s')

        block_head_vals = (str.encode(""), timestamp, 0, 0, str.encode("INITIAL"), str.encode(""), str.encode(""))
        
        block_hash_val = struct.pack('32s', str.encode(""))
        block_timestamp_val = struct.pack('d', timestamp)
        block_case_id_val = b'0' * 32
        block_item_id_val = b'0' * 32
        block_state_val = struct.pack('12s', str.encode("INITIAL"))
        block_creator_val = struct.pack('12s', str.encode(""))
        block_owner_val = struct.pack('12s', str.encode(""))
        
        block_data_val = str.encode("Initial block")
        block_data_len_val = struct.pack('<I', 14)
        block_data_form = struct.Struct('14s')
        packed_head_vals = block_head_form_1.pack(*block_head_vals)
        packed_data_val = block_data_form.pack(block_data_val)

        # Pack the data according to the format
        block = open(file_chain, 'wb')
        block.write(block_hash_val)
        block.write(block_timestamp_val)
        block.write(block_case_id_val)
        block.write(block_item_id_val)
        block.write(block_state_val)
        block.write(block_creator_val)
        block.write(block_owner_val)
        block.write(block_data_len_val)
        block.write(packed_data_val)
        block.close()
        sys.exit(0)
    
    # atp we know file exists, so we read from file


    try:
        block = open(file_chain, 'rb')
        block_content = block.read(block_head_form.size)
        block_content = struct.unpack(block_head_form.format, block_content)

        curr_block = {
                'prev_hash': block_content[0],
                'time': block_content[1],
                'case_id': block_content[2],
                'item_id': block_content[3],
                'state': block_content[4],
                'creator': block_content[5],
                'owner': block_content[6],
                'data_len': block_content[7],
            }
    
        block.close()
    except:
        print("Invalid Block Format")
        sys.exit(1)


    if "INITIAL" == curr_block['state'].decode('utf-8').strip('\x00'):
        print("Blockchain file found with INITIAL block")
        sys.exit(0)
    else:
        print("Blockchain file not found. Created INITIAL block")
        timestamp = datetime.timestamp(datetime.now())

        block_head_form_1 = struct.Struct('32s d I I 12s 12s 12s')

        block_head_vals = (str.encode(""), timestamp, 0, 0, str.encode("INITIAL"), str.encode(""), str.encode(""))
        
        block_hash_val = struct.pack('32s', str.encode(""))
        block_timestamp_val = struct.pack('d', timestamp)
        block_case_id_val = b'0' * 32
        block_item_id_val = b'0' * 32
        block_state_val = struct.pack('12s', str.encode("INITIAL"))
        block_creator_val = struct.pack('12s', str.encode(""))
        block_owner_val = struct.pack('12s', str.encode(""))
        
        block_data_val = str.encode("Initial block")
        block_data_len_val = struct.pack('<I', 14)
        block_data_form = struct.Struct('14s')
        packed_head_vals = block_head_form_1.pack(*block_head_vals)
        packed_data_val = block_data_form.pack(block_data_val)

        # Pack the data according to the format
        block = open(file_chain, 'wb')
        block.write(block_hash_val)
        block.write(block_timestamp_val)
        block.write(block_case_id_val)
        block.write(block_item_id_val)
        block.write(block_state_val)
        block.write(block_creator_val)
        block.write(block_owner_val)
        block.write(block_data_len_val)
        block.write(packed_data_val)
        block.close()

        sys.exit(0)

##################################################################################################################################### Parsers
def parse_add(user_input):
    # Split the input string into parts based on spaces
    parts = user_input.split()
    
    case_id = None
    item_ids = []
    creator = None
    password = None
    last_flag = None

    for part in parts:
        if part == '-c':
            last_flag = 'case_id'
        elif part == '-i':
            last_flag = 'item_id'
        elif part == '-p':
            last_flag = 'password'
        elif part == '-g':
            last_flag = 'creator'
        else:
            if last_flag == 'case_id':
                case_id = part
            elif last_flag == 'item_id':
                item_ids.append(part)
            elif last_flag == 'creator':
                creator = part
            elif last_flag == 'password':
                password = part
                break

    return case_id, item_ids, creator, password
def parse_check(user_input):
    parts = user_input.split()
    item_id = None
    password = None
    
    for i, part in enumerate(parts):
        if part == '-i':
            item_id = parts[i + 1]
        elif part == '-p':
            password = parts[i + 1]
            break
    
    return item_id, password
def parse_show_cases(user_input):
    parts = user_input.split()
    password = None
    
    for i, part in enumerate(parts):
        if part == '-p':
            password = parts[i + 1]
            break
    
    return password
def parse_show_items(user_input):
    parts = user_input.split()
    case_id = None
    password = None
    
    for i, part in enumerate(parts):
        if part == '-c':
            case_id = parts[i + 1]
        elif part == '-p':
            password = parts[i + 1]
            break
    
    return case_id, password
def parse_show_history(user_input):
    parts = user_input.split()
    case_id = None
    item_id = None
    num_entries = None
    reverse = False
    password = None
    
    for i, part in enumerate(parts):
        if part == '-c':
            case_id = parts[i + 1]
        elif part == '-i':
            item_id = parts[i + 1]
        elif part == '-n':
            num_entries = parts[i + 1]
        elif part == '-r':
            reverse = True
        elif part == '-p':
            password = parts[i + 1]
            break
    
    return case_id, item_id, num_entries, reverse, password
def parse_remove(user_input):
    parts = user_input.split()
    item_id = None
    reason = None
    password = None
    
    for i, part in enumerate(parts):
        if part == '-i':
            item_id = parts[i + 1]
        elif part == '-y':
            reason = parts[i + 1]
        elif part == '-p':
            password = parts[i + 1]
            break
    
    return item_id, reason, password
def get_input():
    # Check if any command is passed, else print an error message.
    if len(sys.argv) < 2:
        print("Usage: ./bchoc <command> [options]")
        sys.exit(1)
    
    # Fetch the command from the first argument.
    command = sys.argv[1]
    
    # Process the command using the rest of the arguments.
    if command == 'add':
        try:
            case_id, item_ids, creator, password = parse_add(' '.join(sys.argv[2:]))
            add(case_id, item_ids, creator, password)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif command == 'checkout':
        try:
            item_id, password = parse_check(' '.join(sys.argv[2:]))
            checkout(item_id, password)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif command == 'checkin':
        try:
            item_id, password = parse_check(' '.join(sys.argv[2:]))
            checkin(item_id, password)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif command == 'show cases':
        try:
            password = parse_show_cases(' '.join(sys.argv[2:]))
            show_cases(password)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif command == 'show items':
        try:
            case_id, password = parse_show_items(' '.join(sys.argv[2:]))
            show_items(case_id, password)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif command == 'show history':
        try:
            case_id, item_id, num_entries, reverse, password = parse_show_history(' '.join(sys.argv[2:]))
            show_history(case_id, item_id, num_entries, reverse, password)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif command == 'remove':
        try:
            item_id, reason, password = parse_remove(' '.join(sys.argv[2:]))
            removal(item_id, reason, password)
        except Exception as e:
            print(f"Error: {str(e)}")
    elif command == 'init':
        if len(sys.argv) > 2:
            exit(1)
        init()
    elif command == 'verify':
        verify_chain()
    else:
        print(f"Unknown command: {command}")

def main():
    global init_block 
    get_input()
    #init()
    # itemx = []
    # itemx.append('808859859')
    # add('9082d7bf-0331-4c50-8eaa-157d0eba193a', itemx, 'U8alD7McuLHx', 'C67C')
    # unpack_all()
    # pack_all()

if __name__ == "__main__":
    main()