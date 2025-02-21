import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, Menu
import cv2
import os

# Global variables to hold file paths.
cover_image_path = ""
encrypted_image_path = ""

def load_cover_image():
    global cover_image_path
    cover_image_path = filedialog.askopenfilename(
        title="Select Cover Image",
        filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp")]
    )
    if cover_image_path:
        cover_label.config(text=cover_image_path)
    else:
        cover_label.config(text="No file selected")

def load_encrypted_image():
    global encrypted_image_path
    encrypted_image_path = filedialog.askopenfilename(
        title="Select Encrypted Image",
        filetypes=[("PNG Files", "*.png"), ("All Files", "*.*")]
    )
    if encrypted_image_path:
        encrypted_label.config(text=encrypted_image_path)
    else:
        encrypted_label.config(text="No file selected")

def encrypt_message():
    if not cover_image_path:
        messagebox.showerror("Error", "Please load a cover image!")
        return
    msg = enc_message_entry.get()
    password = enc_password_entry.get()
    if not msg:
        messagebox.showerror("Error", "Please enter a secret message!")
        return
    if not password:
        messagebox.showerror("Error", "Please enter an encryption passcode!")
        return

    # Load the cover image.
    img = cv2.imread(cover_image_path)
    if img is None:
        messagebox.showerror("Error", "Failed to load the cover image!")
        return

    # Save the encryption passcode to a file (for decryption purposes).
    try:
        with open("pass.txt", "w") as f:
            f.write(password)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save password: {e}")
        return

    # Embed the secret message into the image using LSB steganography.
    try:
        # Convert message to binary
        binary_msg = ''.join(format(ord(char), '08b') for char in msg)
        binary_msg += '1111111111111110'  # Add a delimiter to mark the end of the message

        data_idx = 0
        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(3):  # Iterate over B, G, R channels
                    if data_idx < len(binary_msg):
                        img[i, j, k] = img[i, j, k] & ~1 | int(binary_msg[data_idx])
                        data_idx += 1
                    else:
                        break
                else:
                    continue
                break
            else:
                continue
            break

        # Save the modified image as a PNG (lossless) to preserve pixel data.
        cv2.imwrite("encryptedImage.png", img)
        messagebox.showinfo("Success", "Secret message embedded into image and saved as 'encryptedImage.png'.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to embed message: {e}")

def decrypt_message():
    if not encrypted_image_path:
        messagebox.showerror("Error", "Please load an encrypted image!")
        return
    password_input = dec_password_entry.get()
    try:
        with open("pass.txt", "r") as f:
            correct_pass = f.read().strip()
    except Exception as e:
        messagebox.showerror("Error", "Password file not found!")
        return

    if password_input != correct_pass:
        messagebox.showerror("Error", "Incorrect passcode. Access denied!")
        return

    # Load the encrypted image.
    img = cv2.imread(encrypted_image_path)
    if img is None:
        messagebox.showerror("Error", "Failed to load the encrypted image!")
        return

    # Extract the message from the image using LSB steganography.
    try:
        binary_msg = ""
        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(3):  # Iterate over B, G, R channels
                    binary_msg += str(img[i, j, k] & 1)
                    if binary_msg[-16:] == '1111111111111110':  # Check for delimiter
                        break
                else:
                    continue
                break
            else:
                continue
            break

        # Convert binary message to string
        message = ""
        for i in range(0, len(binary_msg)-16, 8):
            message += chr(int(binary_msg[i:i+8], 2))

        # Display the decrypted message.
        dec_text.delete(1.0, tk.END)
        dec_text.insert(tk.END, message)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to extract message: {e}")

def clear_fields():
    cover_label.config(text="No file selected")
    encrypted_label.config(text="No file selected")
    enc_message_entry.delete(0, tk.END)
    enc_password_entry.delete(0, tk.END)
    dec_password_entry.delete(0, tk.END)
    dec_length_entry.delete(0, tk.END)
    dec_text.delete(1.0, tk.END)

def save_decrypted_message():
    decrypted_message = dec_text.get(1.0, tk.END).strip()
    if not decrypted_message:
        messagebox.showerror("Error", "No decrypted message to save!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "w") as f:
                f.write(decrypted_message)
            messagebox.showinfo("Success", "Decrypted message saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save decrypted message: {e}")

def toggle_password_visibility():
    if enc_password_entry.cget('show') == '*':
        enc_password_entry.config(show='')
        dec_password_entry.config(show='')
    else:
        enc_password_entry.config(show='*')
        dec_password_entry.config(show='*')

def about():
    messagebox.showinfo("About", "Image Steganography Tool\nVersion 1.0\n\nA simple tool to hide and extract secret messages in images.")

# Create the main application window.
root = tk.Tk()
root.title("Image Steganography")

# Create a menu bar
menubar = Menu(root)
root.config(menu=menubar)

# File menu
file_menu = Menu(menubar, tearoff=0)
file_menu.add_command(label="Clear All", command=clear_fields)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=file_menu)

# Help menu
help_menu = Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=about)
menubar.add_cascade(label="Help", menu=help_menu)

# Create a container frame.
main_frame = tk.Frame(root)
main_frame.pack(padx=10, pady=10)

# --- Cover Image Section (For Encryption) ---
cover_frame = tk.LabelFrame(main_frame, text="Cover Image (For Encryption)")
cover_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
btn_load_cover = tk.Button(cover_frame, text="Load Cover Image", command=load_cover_image)
btn_load_cover.grid(row=0, column=0, padx=5, pady=5)
cover_label = tk.Label(cover_frame, text="No file selected")
cover_label.grid(row=0, column=1, padx=5, pady=5)

# --- Encryption Section ---
enc_frame = tk.LabelFrame(main_frame, text="Encryption")
enc_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
tk.Label(enc_frame, text="Secret Message:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
enc_message_entry = tk.Entry(enc_frame, width=40)
enc_message_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Label(enc_frame, text="Passcode:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
enc_password_entry = tk.Entry(enc_frame, width=40, show="*")
enc_password_entry.grid(row=1, column=1, padx=5, pady=5)
btn_encrypt = tk.Button(enc_frame, text="Encrypt", command=encrypt_message)
btn_encrypt.grid(row=2, column=0, columnspan=2, pady=5)

# --- Encrypted Image Section (For Decryption) ---
encrypted_frame = tk.LabelFrame(main_frame, text="Encrypted Image (For Decryption)")
encrypted_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
btn_load_encrypted = tk.Button(encrypted_frame, text="Load Encrypted Image", command=load_encrypted_image)
btn_load_encrypted.grid(row=0, column=0, padx=5, pady=5)
encrypted_label = tk.Label(encrypted_frame, text="No file selected")
encrypted_label.grid(row=0, column=1, padx=5, pady=5)

# --- Decryption Section ---
dec_frame = tk.LabelFrame(main_frame, text="Decryption")
dec_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
tk.Label(dec_frame, text="Passcode:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
dec_password_entry = tk.Entry(dec_frame, width=40, show="*")
dec_password_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Label(dec_frame, text="Message Length:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
dec_length_entry = tk.Entry(dec_frame, width=40)
dec_length_entry.grid(row=1, column=1, padx=5, pady=5)
btn_decrypt = tk.Button(dec_frame, text="Decrypt", command=decrypt_message)
btn_decrypt.grid(row=2, column=0, columnspan=2, pady=5)
tk.Label(dec_frame, text="Decrypted Message:").grid(row=3, column=0, padx=5, pady=5, sticky="ne")
dec_text = scrolledtext.ScrolledText(dec_frame, width=40, height=5)
dec_text.grid(row=3, column=1, padx=5, pady=5)

# --- Additional Buttons ---
btn_clear = tk.Button(main_frame, text="Clear All", command=clear_fields)
btn_clear.grid(row=4, column=0, pady=10)

btn_save = tk.Button(main_frame, text="Save Decrypted Message", command=save_decrypted_message)
btn_save.grid(row=5, column=0, pady=10)

btn_toggle_password = tk.Button(main_frame, text="Show/Hide Password", command=toggle_password_visibility)
btn_toggle_password.grid(row=6, column=0, pady=10)

root.mainloop()