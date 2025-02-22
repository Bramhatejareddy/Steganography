# Image Steganography Tool

A Python-based tool for hiding and extracting secret messages in images using steganography. This tool allows users to encrypt a message into an image and later decrypt it using a passcode.

## Features
- **Encryption**: Embed a secret message into a cover image.
- **Decryption**: Extract the hidden message from an encrypted image.
- **LSB Steganography**: Uses the Least Significant Bit (LSB) method for robust message embedding.
- **User-Friendly Interface**: Built with `tkinter` for easy interaction.
- **Password Protection**: Secures the encrypted message with a passcode.

## Files in the Repository
1. **`main.py`**: The main script containing the GUI and core functionality.
2. **`encryption.py`**: Contains the logic for embedding a message into an image.
3. **`decryption.py`**: Contains the logic for extracting a message from an image.
4. **`README.md`**: This file, providing an overview of the project.
5. **`requirements.txt`**: Lists the dependencies required to run the project.

## Installation

### Prerequisites
- Python 3.x
- `tkinter` (usually comes pre-installed with Python)
- `opencv-python` (for image processing)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/image-steganography-tool.git
   cd image-steganography-tool
