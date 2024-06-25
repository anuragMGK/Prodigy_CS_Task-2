import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np

def encrypt_image(input_path, output_path, key):
    try:
        with Image.open(input_path) as img:
            img_array = np.array(img)
            encrypted_array = (img_array + key) % 256
            encrypted_array = encrypted_array[::-1, ::-1]
            encrypted_img = Image.fromarray(encrypted_array.astype('uint8'))
            encrypted_img.save(output_path)
            messagebox.showinfo("Success", f"Image encrypted and saved to {output_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def decrypt_image(input_path, output_path, key):
    try:
        with Image.open(input_path) as img:
            img_array = np.array(img)
            decrypted_array = img_array[::-1, ::-1]
            decrypted_array = (decrypted_array - key) % 256
            decrypted_img = Image.fromarray(decrypted_array.astype('uint8'))
            decrypted_img.save(output_path)
            messagebox.showinfo("Success", f"Image decrypted and saved to {output_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def select_input_file():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
    input_entry.delete(0, tk.END)
    input_entry.insert(0, file_path)

def select_output_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
    output_entry.delete(0, tk.END)
    output_entry.insert(0, file_path)

def start_process(operation):
    input_path = input_entry.get().strip()
    output_path = output_entry.get().strip()
    key = key_entry.get().strip()

    if not input_path or not output_path or not key:
        messagebox.showerror("Error", "All fields must be filled out")
        return
    
    try:
        key = int(key)
    except ValueError:
        messagebox.showerror("Error", "Key must be an integer")
        return
    
    if operation == 'encrypt':
        encrypt_image(input_path, output_path, key)
    elif operation == 'decrypt':
        decrypt_image(input_path, output_path, key)

# Create the main window
root = tk.Tk()
root.title("Image Encryptor/Decryptor")

# Create and place the input file selection widgets
tk.Label(root, text="Input Image Path:").grid(row=0, column=0, padx=10, pady=5, sticky='e')
input_entry = tk.Entry(root, width=50)
input_entry.grid(row=0, column=1, padx=10, pady=5)
tk.Button(root, text="Browse...", command=select_input_file).grid(row=0, column=2, padx=10, pady=5)

# Create and place the output file selection widgets
tk.Label(root, text="Output Image Path:").grid(row=1, column=0, padx=10, pady=5, sticky='e')
output_entry = tk.Entry(root, width=50)
output_entry.grid(row=1, column=1, padx=10, pady=5)
tk.Button(root, text="Browse...", command=select_output_file).grid(row=1, column=2, padx=10, pady=5)

# Create and place the key entry widget
tk.Label(root, text="Encryption/Decryption Key:").grid(row=2, column=0, padx=10, pady=5, sticky='e')
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=2, column=1, padx=10, pady=5)

# Create and place the encrypt and decrypt buttons
tk.Button(root, text="Encrypt", command=lambda: start_process('encrypt')).grid(row=3, column=0, padx=10, pady=20)
tk.Button(root, text="Decrypt", command=lambda: start_process('decrypt')).grid(row=3, column=1, padx=10, pady=20)

# Run the main event loop
root.mainloop()
