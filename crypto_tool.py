import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
from PIL import Image
import numpy as np

class EncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Lab Tool")
        self.root.geometry("550x450")
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Algorithm selection
        ttk.Label(main_frame, text="Encryption Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.algo_var = tk.StringVar(value="AES")
        algo_frame = ttk.Frame(main_frame)
        algo_frame.grid(row=0, column=1, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        ttk.Radiobutton(algo_frame, text="AES (128-bit)", variable=self.algo_var, value="AES").pack(side=tk.LEFT)
        ttk.Radiobutton(algo_frame, text="DES (64-bit)", variable=self.algo_var, value="DES").pack(side=tk.LEFT)
        
        # Mode selection
        ttk.Label(main_frame, text="Cipher Mode:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.mode_var = tk.StringVar(value="CBC")
        mode_frame = ttk.Frame(main_frame)
        mode_frame.grid(row=1, column=1, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        for mode in ["ECB", "CBC", "CTR"]:
            ttk.Radiobutton(mode_frame, text=mode, variable=self.mode_var, value=mode).pack(side=tk.LEFT)
        
        # Key input
        ttk.Label(main_frame, text="Encryption Key (hex):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.key_entry = ttk.Entry(main_frame, width=60)
        self.key_entry.grid(row=2, column=1, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # IV input
        ttk.Label(main_frame, text="IV/Nonce (hex):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.iv_entry = ttk.Entry(main_frame, width=60)
        self.iv_entry.grid(row=3, column=1, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # File selection
        ttk.Button(main_frame, text="Select File", command=self.select_file).grid(row=4, column=0, pady=10)
        self.file_label = ttk.Label(main_frame, text="No file selected", foreground="gray")
        self.file_label.grid(row=4, column=1, columnspan=2, sticky=tk.W, pady=10)
        
        # Operation buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=4, pady=15)
        
        ttk.Button(button_frame, text="Generate Random Key/IV", 
                  command=self.generate_random).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Encrypt File", 
                  command=self.encrypt_file, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt File", 
                  command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
        
        # Visualization section
        viz_frame = ttk.LabelFrame(main_frame, text="Pattern Visualization", padding="5")
        viz_frame.grid(row=6, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Button(viz_frame, text="Create Test Image & Encrypt", 
                  command=self.create_and_visualize).pack(side=tk.LEFT, padx=5)
        ttk.Button(viz_frame, text="Encrypt Selected Image", 
                  command=self.visualize_image).pack(side=tk.LEFT, padx=5)
        
        # Status
        self.status_var = tk.StringVar(value="Ready to encrypt/decrypt files")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, relief="sunken", padding="5")
        status_label.grid(row=7, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Set initial key/IV
        self.generate_random()
        self.algo_var.trace('w', self.on_algo_change)
    
    def on_algo_change(self, *args):
        self.generate_random()
    
    def select_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.file_label.config(text=os.path.basename(filename))
            self.current_file = filename
            self.status_var.set(f"Selected: {os.path.basename(filename)}")
    
    def generate_random(self):
        if self.algo_var.get() == "AES":
            key = get_random_bytes(16)  # 128-bit
            iv = get_random_bytes(16)   # 128-bit
        else:  # DES
            key = get_random_bytes(8)   # 64-bit
            iv = get_random_bytes(8)    # 64-bit
            
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())
        
        self.iv_entry.delete(0, tk.END)
        self.iv_entry.insert(0, iv.hex())
    
    def hex_to_bytes(self, hex_str):
        try:
            return bytes.fromhex(hex_str.strip())
        except ValueError:
            messagebox.showerror("Error", "Invalid hex string in key or IV")
            return None
    
    def encrypt_file(self):
        if not hasattr(self, 'current_file'):
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        key = self.hex_to_bytes(self.key_entry.get())
        iv = self.hex_to_bytes(self.iv_entry.get())
        if not key or not iv:
            return
        
        try:
            with open(self.current_file, 'rb') as f:
                plaintext = f.read()
            
            ciphertext = self.encrypt_data(plaintext, key, iv)
            
            output_file = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
                title="Save encrypted file as..."
            )
            
            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(ciphertext)
                self.status_var.set(f"Encrypted: {os.path.basename(output_file)}")
                messagebox.showinfo("Success", "File encrypted successfully!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_file(self):
        if not hasattr(self, 'current_file'):
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        key = self.hex_to_bytes(self.key_entry.get())
        iv = self.hex_to_bytes(self.iv_entry.get())
        if not key or not iv:
            return
        
        try:
            with open(self.current_file, 'rb') as f:
                ciphertext = f.read()
            
            plaintext = self.decrypt_data(ciphertext, key, iv)
            
            output_file = filedialog.asksaveasfilename(
                defaultextension=".dec",
                filetypes=[("All files", "*.*")],
                title="Save decrypted file as..."
            )
            
            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(plaintext)
                self.status_var.set(f"Decrypted: {os.path.basename(output_file)}")
                messagebox.showinfo("Success", "File decrypted successfully!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def encrypt_data(self, data, key, iv):
        algo = self.algo_var.get()
        mode = self.mode_var.get()
        
        if algo == "AES":
            if mode == "ECB":
                cipher = AES.new(key, AES.MODE_ECB)
                return cipher.encrypt(pad(data, AES.block_size))
            elif mode == "CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv)
                return cipher.encrypt(pad(data, AES.block_size))
            elif mode == "CTR":
                cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
                return cipher.encrypt(data)
        else:  # DES
            if mode == "ECB":
                cipher = DES.new(key, DES.MODE_ECB)
                return cipher.encrypt(pad(data, DES.block_size))
            elif mode == "CBC":
                cipher = DES.new(key, DES.MODE_CBC, iv)
                return cipher.encrypt(pad(data, DES.block_size))
            elif mode == "CTR":
                # Custom CTR implementation for DES
                return self.des_ctr_mode(data, key, iv)
    
    def decrypt_data(self, data, key, iv):
        algo = self.algo_var.get()
        mode = self.mode_var.get()
        
        try:
            if algo == "AES":
                if mode == "ECB":
                    cipher = AES.new(key, AES.MODE_ECB)
                    return unpad(cipher.decrypt(data), AES.block_size)
                elif mode == "CBC":
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    return unpad(cipher.decrypt(data), AES.block_size)
                elif mode == "CTR":
                    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
                    return cipher.decrypt(data)
            else:  # DES
                if mode == "ECB":
                    cipher = DES.new(key, DES.MODE_ECB)
                    return unpad(cipher.decrypt(data), DES.block_size)
                elif mode == "CBC":
                    cipher = DES.new(key, DES.MODE_CBC, iv)
                    return unpad(cipher.decrypt(data), DES.block_size)
                elif mode == "CTR":
                    return self.des_ctr_mode(data, key, iv)
        except Exception as e:
            raise Exception(f"Check your key and IV: {str(e)}")
    
    def des_ctr_mode(self, data, key, iv):
        """Custom CTR mode implementation for DES"""
        cipher = DES.new(key, DES.MODE_ECB)
        result = bytearray()
        counter = int.from_bytes(iv[:8], 'big')
        
        for i in range(0, len(data), 8):
            counter_bytes = counter.to_bytes(8, 'big')
            keystream = cipher.encrypt(counter_bytes)
            chunk = data[i:i+8]
            result.extend(a ^ b for a, b in zip(chunk, keystream[:len(chunk)]))
            counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF  # 64-bit counter
        
        return bytes(result)
    
    def create_test_image(self):
        """Create a test image with visible patterns"""
        width, height = 300, 200
        img = Image.new('L', (width, height), color=128)
        pixels = img.load()
        
        # Create striped pattern
        for x in range(width):
            for y in range(height):
                if (x // 30) % 2 == 0:
                    pixels[x, y] = 200  # Light stripes
                else:
                    pixels[x, y] = 50   # Dark stripes
        
        # Add some blocks
        for x in range(50, 150):
            for y in range(50, 100):
                pixels[x, y] = 255  # White block
        
        test_image_path = "test_pattern.png"
        img.save(test_image_path)
        return test_image_path
    
    def create_and_visualize(self):
        """Create test image and show encryption patterns"""
        try:
            test_image_path = self.create_test_image()
            self.current_file = test_image_path
            self.file_label.config(text="test_pattern.png")
            self.visualize_image()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create visualization: {str(e)}")
    
    def visualize_image(self):
        """Encrypt an image and show pattern differences between modes"""
        if not hasattr(self, 'current_file'):
            messagebox.showwarning("Warning", "Please select an image file first")
            return
        
        try:
            # Load image
            img = Image.open(self.current_file).convert('L')
            img_array = np.array(img)
            original_bytes = img.tobytes()
            
            # Get encryption parameters
            key = self.hex_to_bytes(self.key_entry.get())
            iv = self.hex_to_bytes(self.iv_entry.get())
            if not key or not iv:
                return
            
            # Encrypt with different modes to show patterns
            original_modes = ["ECB", "CBC", "CTR"]
            encrypted_images = []
            
            for mode in original_modes:
                self.mode_var.set(mode)
                encrypted = self.encrypt_data(original_bytes, key, iv)
                # Truncate to original length for display
                encrypted_truncated = encrypted[:len(original_bytes)]
                encrypted_array = np.frombuffer(encrypted_truncated, dtype=np.uint8)
                encrypted_array = encrypted_array.reshape(img_array.shape)
                encrypted_images.append(encrypted_array)
            
            # Create visualization
            fig, axes = plt.subplots(2, 2, figsize=(12, 8))
            fig.suptitle('Encryption Mode Comparison - Pattern Visibility', fontsize=16)
            
            images = [
                (img_array, 'Original Image'),
                (encrypted_images[0], 'ECB Mode - Patterns Visible'),
                (encrypted_images[1], 'CBC Mode - Patterns Hidden'), 
                (encrypted_images[2], 'CTR Mode - Patterns Hidden')
            ]
            
            for idx, (image_data, title) in enumerate(images):
                ax = axes[idx // 2, idx % 2]
                ax.imshow(image_data, cmap='gray', aspect='auto')
                ax.set_title(title, fontweight='bold')
                ax.axis('off')
                
                # Highlight ECB vulnerability
                if 'ECB' in title:
                    ax.title.set_color('red')
            
            plt.tight_layout()
            plt.show()
            
            self.status_var.set("Visualization completed - Observe ECB pattern leakage")
            
        except Exception as e:
            messagebox.showerror("Error", f"Visualization failed: {str(e)}")

def main():
    root = tk.Tk()
    app = EncryptionTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()