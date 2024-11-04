import hashlib
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import time

# Blockchain class to store file hashes and log block info
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(file_hash='0', previous_hash='0')  # Create the genesis block

    def create_block(self, file_hash, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'file_hash': file_hash,
            'previous_hash': previous_hash or self.get_last_block()['hash'],
            'hash': self.hash_block(file_hash, previous_hash)
        }
        self.chain.append(block)
        
        # Log the block information to blockchain_log.txt
        
        self.log_block_info(block)
        
        return block

    def get_last_block(self):
        return self.chain[-1] if self.chain else None

    def hash_block(self, file_hash, previous_hash):
        # Combine the file hash and previous hash to create the current block hash
        block_string = f"{file_hash}{previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def is_chain_valid(self):
        # Check the validity of the entire blockchain
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if the current block's hash is correct
            if current_block['hash'] != self.hash_block(current_block['file_hash'], current_block['previous_hash']):
                return False
            
            # Check if the previous block's hash matches
            if current_block['previous_hash'] != previous_block['hash']:
                return False
        return True

    # Function to log block info into blockchain_log.txt
    def log_block_info(self, block):
        with open("blockchain_log.txt", "a") as log_file:
            log_file.write(f"Block Index: {block['index']}\n")
            log_file.write(f"Timestamp: {time.ctime(block['timestamp'])}\n")
            log_file.write(f"File Hash: {block['file_hash']}\n")
            log_file.write(f"Previous Hash: {block['previous_hash']}\n")
            log_file.write(f"Current Block Hash: {block['hash']}\n")
            log_file.write("\n" + "="*50 + "\n\n")

# Function to compute SHA-256 hash of a file
def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Global blockchain instance
blockchain = Blockchain()

# Function to browse and select a CAD file
def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("CAD files", "*.dwg")])
    if file_path:
        selected_file_label.config(text=file_path)
        file_hash = compute_sha256(file_path)
        hash_result_var.set(f"SHA-256 Hash: {file_hash}")
        
        # Store the file hash in the blockchain
        store_hash_in_blockchain(file_hash)
        save_secure_file(file_path, file_hash)

# Function to store the file hash in the blockchain
def store_hash_in_blockchain(file_hash):
    last_block = blockchain.get_last_block()
    new_block = blockchain.create_block(file_hash, last_block['hash'])
    messagebox.showinfo("Blockchain", f"File hash stored in blockchain! Block index: {new_block['index']}")

# Function to save a secured version of the file and its hash
def save_secure_file(original_file_path, file_hash):
    secure_file_path = original_file_path.replace(".dwg", "_secured.dwg")
    
    shutil.copy(original_file_path, secure_file_path)
    messagebox.showinfo("Success", f"Original CAD file securely saved as: {secure_file_path}")
    
    hash_file_path = secure_file_path.replace(".dwg", "_hash.txt")
    
    with open(hash_file_path, 'w') as f:
        f.write(f"File: {secure_file_path}\nSHA-256 Hash: {file_hash}\n")
    
    messagebox.showinfo("Success", f"Hash saved to: {hash_file_path}")

# Function to verify the file's integrity against the blockchain
def verify_hash():
    file_path = filedialog.askopenfilename(filetypes=[("CAD files", "*_secured.dwg")])
    if file_path:
        current_hash = compute_sha256(file_path)
        
        # Get the last block from the blockchain
        last_block = blockchain.get_last_block()
        stored_hash = last_block['file_hash']
        
        if current_hash == stored_hash:
            messagebox.showinfo("Integrity Check", "Integrity check passed: The file has not been modified.")
        else:
            messagebox.showwarning("Integrity Check", "Integrity check failed: The file has been altered.")
    else:
        messagebox.showwarning("Error", "No secured CAD file selected for verification.")

# Function to simulate file modification, save it as *_modified_R.dwg, and compare with secured file
def simulate_modification():
    file_path = filedialog.askopenfilename(filetypes=[("CAD files", "*_secured.dwg")])
    if file_path:
        # Save the modified file as *_modified_R.dwg
        modified_file_path = file_path.replace("_secured.dwg", "_modified_R.dwg")
        
        # Copy the secured file to the new modified file
        shutil.copy(file_path, modified_file_path)
        
        # Simulate modification by appending data to the modified file
        with open(modified_file_path, 'a') as f:
            f.write('x')  # Simulate modification by appending 'x' to the file
        
        # Notify the user about the modified file
        messagebox.showinfo("Modification", f"Modified file saved as: {modified_file_path}")
        
        # Compute the hash of the modified file and the original secured file
        modified_file_hash = compute_sha256(modified_file_path)
        secure_file_hash = compute_sha256(file_path)
        
        # Compare the hashes and notify the user of the result
        if secure_file_hash == modified_file_hash:
            messagebox.showinfo("Modification Check", "No changes detected: The modified file is identical to the secure file.")
        else:
            messagebox.showwarning("Modification Check", "Changes detected: The modified file is different from the secure file.")

# Setting up the GUI window
root = tk.Tk()
root.title("CAD File Integrity Checker")
hash_result_var = tk.StringVar()

title_label = tk.Label(root, text="CAD File Integrity Checker", font=("Helvetica", 16))
title_label.pack(pady=10)

browse_button = tk.Button(root, text="Browse CAD File", command=browse_file)
browse_button.pack(pady=5)

selected_file_label = tk.Label(root, text="No file selected")
selected_file_label.pack(pady=5)

hash_label = tk.Label(root, textvariable=hash_result_var, font=("Helvetica", 12), wraplength=400)
hash_label.pack(pady=10)

verify_button = tk.Button(root, text="Verify Hash", command=verify_hash)
verify_button.pack(pady=5)

simulate_button = tk.Button(root, text="Simulate Modification", command=simulate_modification)
simulate_button.pack(pady=5)

root.mainloop()
