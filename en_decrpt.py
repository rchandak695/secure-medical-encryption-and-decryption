import pydicom
from cryptography.fernet import Fernet
import os
import numpy as np
from skimage.metrics import structural_similarity as ssim
from skimage.metrics import peak_signal_noise_ratio as psnr
from skimage.measure import shannon_entropy
import base64

# Function to encrypt a single DICOM file using AES encryption
def encrypt_dicom_file(file_path, encryption_key):
    try:
        # Read the DICOM file as binary data
        with open(file_path, 'rb') as file:
            dicom_data = file.read()

        # Encrypt the DICOM data
        f = Fernet(encryption_key)
        encrypted_data = f.encrypt(dicom_data)

        # Write the encrypted data back to the same file
        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        print("DICOM file encrypted successfully.")

    except Exception as e:
        print(f"Error encrypting DICOM file: {str(e)}")


# Function to decrypt a single DICOM file using AES decryption
def decrypt_dicom_file(file_path, decryption_key):
    try:

        # Read the encrypted DICOM file as binary data
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Decrypt the encrypted data
        f = Fernet(decryption_key)
        decrypted_data = f.decrypt(encrypted_data)

        # Write the decrypted data back to the same file
        with open(file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print("DICOM file decrypted successfully.")

        decrypted_pixels = pydicom.dcmread(file_path).pixel_array

        return decrypted_pixels

    except Exception as e:
        print(f"Error decrypting DICOM file: {str(e)}")

        return None


# Function to encrypt all DICOM files in a directory and store keys in a text file
def encrypt_dicom_files_in_directory(directory_path, key_file_path):
    key_file = open(key_file_path, "a")

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith('.dcm'):
                encryption_key = Fernet.generate_key()
                file_path = os.path.join(root, file)

                # Encrypt the DICOM file
                encrypt_dicom_file(file_path, encryption_key)

                # Store the key in the text file
                key_file.write(f"{file_path}:{encryption_key.hex()}\n")

    key_file.close()
    print("All DICOM files in the directory encrypted and keys stored in text file.")


# Function to decrypt DICOM files using keys from a text file
def decrypt_dicom_files_using_key_file(key_file_path):
    with open(key_file_path, 'r') as key_file:
        lines = key_file.readlines()
        for line in lines:
            file_path, key_hex = line.strip().split(":")
            decryption_key = bytes.fromhex(key_hex)
            decrypt_dicom_file(file_path, decryption_key)

    # Delete the key file after decrypting all images
    os.remove(key_file_path)
    print("All DICOM files decrypted using keys from the text file.")


# Function to perform security analysis between original and decrypted data
def perform_security_analysis(original_data, decrypted_data):
    try:
        # Calculate NPCR and UACI
        npcr = np.mean(np.abs(original_data != decrypted_data))
        uaci = np.mean(np.abs(original_data - decrypted_data))

        # Calculate PSNR
        psnr_value = psnr(original_data, decrypted_data, data_range=original_data.max())

        # Calculate Entropy
        entropy_value = shannon_entropy(decrypted_data)

        print("\nSecurity Analysis Report: ")
        print(f"NPCR: {npcr}")
        print(f"UACI: {uaci}")
        print(f"PSNR: {psnr_value}")
        print(f"Entropy: {entropy_value}")

    except Exception as e:
        print(f"Error performing security analysis: {str(e)}")

# Function to analyze avalanche effect
def analyze_avalanche_effect(encryption_key, file_path):
    try:

        original_data = pydicom.dcmread(file_path)

        # Modify a small part of the data
        modified_data = original_data.pixel_array.copy()
        modified_data[0, 0] = 0

        # Create a new DICOM object for the modified data
        modified_dicom = pydicom.dcmread(file_path)

        # Assign the modified data to the DICOM file's pixel data attribute
        modified_dicom.PixelData = modified_data.tobytes()

        # Save the modified DICOM file as a new file
        modified_file_path = 'temp.dcm'
        modified_dicom.save_as(modified_file_path)

        # Compare the original and decrypted data
        print("\nAvalanche Effect Analysis:")

        # Encrypt the modified DICOM file
        encrypt_dicom_file(modified_file_path, encryption_key) # Encrypt with the modified data

        # Decrypt the modified file for comparison
        decrypted_data = decrypt_dicom_file(modified_file_path, encryption_key) # Decrypt

        # Remove the temporary modified DICOM file
        os.remove(modified_file_path)


        if np.array_equal(original_data, decrypted_data):
            print("Avalanche effect not observed, the decrypted image is similar to original image.")
        else:
            print("Avalanche effect observed, the decrypted image differ from the original image. ")

    except Exception as e:
        print(f"Error performing security analysis: {str(e)}")


# Function to analyze key sensitivity
def analyze_key_sensitivity(original_data, encryption_key, file_path):
    try:
        # Convert the base64-encoded key to bytes
        original_key_bytes = base64.urlsafe_b64decode(encryption_key)

        modified_array = bytearray(original_key_bytes)

        # Modify a small part of the key
        modified_array[0] = 0

        # Convert the modified key back to URL-safe base64 encoding
        modified_key_base64 = base64.urlsafe_b64encode(modified_array)

        # Compare the original data with the modified data
        print("\nKey Sensitivity Analysis:")

        # Encrypt with the modified key
        encrypt_dicom_file(file_path, modified_key_base64)
        decrypted_data = decrypt_dicom_file(file_path, encryption_key)  # Decrypt with the original key

        if np.array_equal(original_data, decrypted_data):
            print("Key sensitivity not observed, changes to the enrypted key does not affect the encryption process.")
            print("Hence, the decrypted image is similar to original image")
        else:
            print("Key sensitivity observed, even a minor change to the enrypted key affects decryption process.")
            print("Hence, the decrypted image differs from the original image")

    except Exception as e:
        print(f"Error performing security analysis: {str(e)}")

# Main loop
while True:
    print("\nDICOM Image Encryption/Decryption Menu:")
    print("1. Encrypt DICOM File")
    print("2. Decrypt DICOM File")
    print("3. Encrypt DICOM Files in Directory and Store Keys")
    print("4. Decrypt DICOM Files using Keys from File")
    print("5. Perform Security Analysis")
    print("6. Exit")

    choice = input("Enter your choice (1/2/3/4/5/6): ")

    original_data = None
    decrypted_data = None

    if choice == "1":
        file_path = input("Enter the path of the DICOM file to encrypt: ")

        # Read the DICOM file as binary data
        with open(file_path, 'rb') as file:
            original_data = file.read()

        encryption_key = Fernet.generate_key()
        encrypt_dicom_file(file_path, encryption_key)
        print(f"Encryption Key: {encryption_key.hex()}")

    elif choice == "2":
        file_path = input("Enter the path of the encrypted DICOM file to decrypt: ")
        decryption_key = input("Enter the decryption key (hexadecimal): ")
        decryption_key = bytes.fromhex(decryption_key)
        decrypted_data = decrypt_dicom_file(file_path, decryption_key)

    elif choice == "3":
        directory_path = input("Enter the path of the directory containing DICOM files: ")
        key_file_path = input("Enter the path to create the key file: ")
        encrypt_dicom_files_in_directory(directory_path, key_file_path)

    elif choice == "4":
        key_file_path = input("Enter the path of the key file containing decryption keys: ")
        decrypt_dicom_files_using_key_file(key_file_path)


    elif choice == "5":
        file_path = input("Enter the path of a DICOM file to perform security analysis: ")

        original_data = pydicom.dcmread(file_path).pixel_array

        encryption_key = Fernet.generate_key()
        encrypt_dicom_file(file_path, encryption_key)

        decrypted_data = decrypt_dicom_file(file_path, encryption_key)

        try:

            perform_security_analysis(original_data, decrypted_data)

            # Analyze Avalanche Effect
            analyze_avalanche_effect(encryption_key, file_path)

            # Analyze Key Sensitivity
            analyze_key_sensitivity(original_data, encryption_key, file_path)

        except Exception as e:
            print(f"Error performing security analysis: {str(e)}")


    elif choice == "6":
        print("Exiting the program.")
        break

    else:
        print("Invalid choice. Please select a valid option (1/2/3/4/5/6).")