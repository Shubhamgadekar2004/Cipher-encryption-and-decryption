import streamlit as st
import string
import base64
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter

# Set page configuration
st.set_page_config(
    page_title="Cipher Encryption/Decryption Tool",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Define cipher algorithms
class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift % 26
        
    def encrypt(self, text):
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + self.shift) % 26 + ascii_offset
                result += chr(shifted)
            else:
                result += char
        return result
    
    def decrypt(self, text):
        return CaesarCipher(26 - self.shift).encrypt(text)
    
    @staticmethod
    def visualization_data(plaintext, ciphertext):
        # Prepare data for visualization
        alphabet = string.ascii_lowercase
        shift_map = {}
        for i, letter in enumerate(alphabet):
            shifted_idx = (i + int(st.session_state.key)) % 26
            shift_map[letter] = alphabet[shifted_idx]
            shift_map[letter.upper()] = alphabet[shifted_idx].upper()
        
        return {
            "type": "mapping",
            "data": shift_map,
            "title": f"Caesar Cipher with Shift {st.session_state.key}"
        }


class VigenereCipher:
    def __init__(self, key):
        self.key = key.lower()
        
    def _extend_key(self, length):
        return (self.key * (length // len(self.key) + 1))[:length]
    
    def encrypt(self, text):
        if not self.key:
            return text
            
        result = ""
        key_idx = 0
        extended_key = self._extend_key(len(''.join(c for c in text if c.isalpha())))
        
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                key_char = extended_key[key_idx]
                key_shift = ord(key_char) - ord('a')
                
                shifted = (ord(char) - ascii_offset + key_shift) % 26 + ascii_offset
                result += chr(shifted)
                key_idx += 1
            else:
                result += char
        return result
    
    def decrypt(self, text):
        if not self.key:
            return text
            
        result = ""
        key_idx = 0
        extended_key = self._extend_key(len(''.join(c for c in text if c.isalpha())))
        
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                key_char = extended_key[key_idx]
                key_shift = ord(key_char) - ord('a')
                
                shifted = (ord(char) - ascii_offset - key_shift) % 26 + ascii_offset
                result += chr(shifted)
                key_idx += 1
            else:
                result += char
        return result
    
    @staticmethod
    def visualization_data(plaintext, ciphertext):
        # Visualization for Vigenère - show extended key and alignment
        key = st.session_state.key.lower()
        if not key:
            return None
            
        plain_filtered = ''.join(c.lower() for c in plaintext if c.isalpha())
        cipher_filtered = ''.join(c.lower() for c in ciphertext if c.isalpha())
        
        if not plain_filtered:
            return None
            
        extended_key = (key * (len(plain_filtered) // len(key) + 1))[:len(plain_filtered)]
        
        return {
            "type": "vigenere_table",
            "plaintext": plain_filtered[:20],  # Show first 20 chars
            "key": extended_key[:20],
            "ciphertext": cipher_filtered[:20],
            "title": f"Vigenère Cipher with Key '{key}'"
        }


class PlayfairCipher:
    def __init__(self, key):
        self.key = key.upper().replace('J', 'I')
        self.matrix = self._generate_matrix()
    
    def _generate_matrix(self):
        # Create 5x5 Playfair matrix
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
        key = ''.join(dict.fromkeys(self.key.upper().replace('J', 'I')))
        key_and_alphabet = key + ''.join([a for a in alphabet if a not in key])
        
        matrix = []
        for i in range(0, 25, 5):
            matrix.append(list(key_and_alphabet[i:i+5]))
        return matrix
    
    def _find_position(self, char):
        char = char.upper()
        if char == 'J':
            char = 'I'
        
        for row in range(5):
            for col in range(5):
                if self.matrix[row][col] == char:
                    return row, col
        return -1, -1
    
    def _process_pairs(self, text, mode):
        result = ""
        text = text.upper().replace('J', 'I')
        
        # Prepare pairs
        i = 0
        pairs = []
        while i < len(text):
            if i == len(text) - 1:
                pairs.append(text[i] + 'X')
                break
            
            if text[i] == text[i+1]:
                pairs.append(text[i] + 'X')
                i += 1
            else:
                pairs.append(text[i] + text[i+1])
                i += 2
                
        for pair in pairs:
            if len(pair) == 1:
                pair += 'X'
                
            r1, c1 = self._find_position(pair[0])
            r2, c2 = self._find_position(pair[1])
            
            if r1 == r2:  # Same row
                shift = 1 if mode == "encrypt" else -1
                c1 = (c1 + shift) % 5
                c2 = (c2 + shift) % 5
            elif c1 == c2:  # Same column
                shift = 1 if mode == "encrypt" else -1
                r1 = (r1 + shift) % 5
                r2 = (r2 + shift) % 5
            else:  # Rectangle
                c1, c2 = c2, c1
                
            result += self.matrix[r1][c1] + self.matrix[r2][c2]
            
        return result
    
    def encrypt(self, text):
        # Remove non-alpha chars
        clean_text = ''.join(c for c in text if c.isalpha())
        return self._process_pairs(clean_text, "encrypt")
    
    def decrypt(self, text):
        # Remove non-alpha chars
        clean_text = ''.join(c for c in text if c.isalpha())
        return self._process_pairs(clean_text, "decrypt")
    
    @staticmethod
    def visualization_data(plaintext, ciphertext):
        key = st.session_state.key.upper().replace('J', 'I')
        
        # Create the Playfair matrix for visualization
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
        key = ''.join(dict.fromkeys(key))
        key_and_alphabet = key + ''.join([a for a in alphabet if a not in key])
        
        matrix = []
        for i in range(0, 25, 5):
            matrix.append(list(key_and_alphabet[i:i+5]))
            
        # Prepare clean text for visualization
        clean_text = ''.join(c for c in plaintext if c.isalpha()).upper().replace('J', 'I')
        
        # Format pairs for visualization
        i = 0
        pairs = []
        while i < len(clean_text):
            if i == len(clean_text) - 1:
                pairs.append(clean_text[i] + 'X')
                break
                
            if clean_text[i] == clean_text[i+1]:
                pairs.append(clean_text[i] + 'X')
                i += 1
            else:
                pairs.append(clean_text[i] + clean_text[i+1])
                i += 2
                
        return {
            "type": "playfair_matrix",
            "matrix": matrix,
            "pairs": pairs[:5],  # Show first 5 pairs
            "title": "Playfair Cipher Matrix"
        }


class Base64Cipher:
    def __init__(self):
        pass
        
    def encrypt(self, text):
        encoded_bytes = base64.b64encode(text.encode('utf-8'))
        return encoded_bytes.decode('utf-8')
    
    def decrypt(self, text):
        try:
            decoded_bytes = base64.b64decode(text)
            return decoded_bytes.decode('utf-8')
        except:
            return "Error: Invalid Base64 encoding"
    
    @staticmethod
    def visualization_data(plaintext, ciphertext):
        return {
            "type": "info",
            "title": "Base64 Encoding",
            "description": "Base64 encoding converts binary data to ASCII strings using 64 characters (A-Z, a-z, 0-9, +, /). It's commonly used to safely transmit binary data across text-based systems."
        }


class MorseCipher:
    def __init__(self):
        self.morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 
            'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', 
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', 
            '9': '----.', '0': '-----', ' ': '/'
        }
        self.inverse_dict = {v: k for k, v in self.morse_dict.items()}
    
    def encrypt(self, text):
        result = []
        for char in text.upper():
            if char in self.morse_dict:
                result.append(self.morse_dict[char])
        return ' '.join(result)
    
    def decrypt(self, text):
        result = []
        for code in text.split():
            if code in self.inverse_dict:
                result.append(self.inverse_dict[code])
            elif code == '/':
                result.append(' ')
        return ''.join(result)
    
    @staticmethod
    def visualization_data(plaintext, ciphertext):
        # Show Morse code mapping for the first few characters
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 
            'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', 
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', 
            '9': '----.', '0': '-----', ' ': '/'
        }
        
        sample_text = plaintext.upper()[:10]
        morse_map = {}
        for char in sample_text:
            if char in morse_dict:
                morse_map[char] = morse_dict[char]
                
        return {
            "type": "mapping",
            "data": morse_map,
            "title": "Morse Code Mapping"
        }


# Function to create frequency analysis
def create_frequency_chart(text):
    if not text:
        return None
        
    # Count only alphabetic characters
    text = ''.join(c.lower() for c in text if c.isalpha())
    if not text:
        return None
    
    # Count character frequencies
    counter = Counter(text)
    labels = sorted(counter.keys())
    values = [counter[label] for label in labels]
    
    # Create bar chart using plotly
    fig = px.bar(
        x=labels, 
        y=values, 
        labels={'x': 'Character', 'y': 'Frequency'},
        title="Character Frequency Analysis"
    )
    
    # Customize appearance
    fig.update_layout(
        xaxis_title="Character",
        yaxis_title="Frequency",
        plot_bgcolor='rgba(0,0,0,0.05)',
        height=300,
    )
    
    return fig


# Function to render visualizations based on cipher type
def render_visualization(viz_data):
    if not viz_data:
        return
        
    if viz_data["type"] == "mapping":
        # Display character mapping
        st.subheader(viz_data["title"])
        
        # Create two columns
        cols = st.columns(len(viz_data["data"]) // 4 + 1)
        items = list(viz_data["data"].items())
        
        # Distribute items across columns
        items_per_col = len(items) // len(cols) + 1
        for i, (char, mapped) in enumerate(items):
            col_idx = i // items_per_col
            if col_idx < len(cols):
                cols[col_idx].write(f"{char} → {mapped}")
    
    elif viz_data["type"] == "vigenere_table":
        st.subheader(viz_data["title"])
        
        # Create a table showing plaintext, key, and ciphertext alignment
        df_data = {
            "Plaintext": list(viz_data["plaintext"]),
            "Key": list(viz_data["key"]),
            "Ciphertext": list(viz_data["ciphertext"])
        }
        
        # Create table as HTML
        html = "<div style='background-color: rgba(0,0,0,0.05); padding: 10px; border-radius: 5px;'>"
        html += "<table style='width: 100%;'>"
        
        # Headers
        html += "<tr>"
        for header in df_data.keys():
            html += f"<th style='text-align: center; padding: 5px;'>{header}</th>"
        html += "</tr>"
        
        # Data
        for i in range(len(df_data["Plaintext"])):
            html += "<tr>"
            for key in df_data.keys():
                html += f"<td style='text-align: center; padding: 5px;'>{df_data[key][i]}</td>"
            html += "</tr>"
        
        html += "</table></div>"
        
        st.markdown(html, unsafe_allow_html=True)
        
        # Add explanation
        st.markdown("""
        **How Vigenère works:**
        1. Each letter of the key shifts the corresponding plaintext letter
        2. The key repeats to match the length of the plaintext
        3. The shift follows the Caesar cipher principle for each letter pair
        """)
    
    elif viz_data["type"] == "playfair_matrix":
        st.subheader(viz_data["title"])
        
        # Display the 5x5 matrix
        matrix = viz_data["matrix"]
        
        # Create table as HTML
        html = "<div style='background-color: rgba(0,0,0,0.05); padding: 10px; border-radius: 5px;'>"
        html += "<table style='width: 250px; margin: 0 auto;'>"
        
        for row in matrix:
            html += "<tr>"
            for cell in row:
                html += f"<td style='text-align: center; padding: 10px; font-weight: bold; width: 40px; height: 40px; border: 1px solid #ddd;'>{cell}</td>"
            html += "</tr>"
            
        html += "</table></div>"
        st.markdown(html, unsafe_allow_html=True)
        
        # Display the pairs
        if viz_data["pairs"]:
            st.markdown("### First few plaintext pairs:")
            pairs_text = " ".join(viz_data["pairs"])
            st.markdown(f"<div style='font-family: monospace; font-size: 16px; padding: 10px;'>{pairs_text}</div>", unsafe_allow_html=True)
            
            # Add explanation
            st.markdown("""
            **How Playfair works:**
            1. Text is split into pairs of letters
            2. If a pair has the same letter, 'X' is inserted
            3. For each pair, apply the rules:
               - If in the same row, shift right (encrypt) or left (decrypt)
               - If in the same column, shift down (encrypt) or up (decrypt)
               - If in different rows/columns, swap the columns
            """)
    
    elif viz_data["type"] == "info":
        st.subheader(viz_data["title"])
        st.markdown(viz_data["description"])


# Initialize session state variables
if 'input_text' not in st.session_state:
    st.session_state.input_text = ""
if 'output_text' not in st.session_state:
    st.session_state.output_text = ""
if 'key' not in st.session_state:
    st.session_state.key = ""
if 'mode' not in st.session_state:
    st.session_state.mode = "Encrypt"
if 'cipher' not in st.session_state:
    st.session_state.cipher = "Caesar"


# Main app layout
st.title("🔐 Cipher Encryption and Decryption Tool")
st.markdown("Encrypt and decrypt messages using various classical cryptography methods.")

# Sidebar for controls
with st.sidebar:
    st.subheader("Cipher Settings")
    
    # Cipher selection
    cipher_options = ["Caesar", "Vigenère", "Playfair", "Base64", "Morse Code"]
    selected_cipher = st.selectbox("Select Cipher Algorithm", 
                                 cipher_options, 
                                 index=cipher_options.index(st.session_state.cipher))
    st.session_state.cipher = selected_cipher
    
    # Operation mode
    mode_options = ["Encrypt", "Decrypt"]
    selected_mode = st.selectbox("Select Mode", 
                               mode_options, 
                               index=mode_options.index(st.session_state.mode))
    st.session_state.mode = selected_mode
    
    # Key input (for ciphers that need it)
    if selected_cipher == "Caesar":
        key_input = st.number_input("Enter Shift Value (0-25)", 
                                  min_value=0, 
                                  max_value=25, 
                                  value=int(st.session_state.key) if st.session_state.key.isdigit() else 3)
        st.session_state.key = str(key_input)
        
    elif selected_cipher in ["Vigenère", "Playfair"]:
        key_input = st.text_input("Enter Key", 
                                value=st.session_state.key,
                                placeholder="Enter encryption key...")
        # Validate key (only alphabetic characters)
        key_input = ''.join(c for c in key_input if c.isalpha())
        st.session_state.key = key_input
        
        if not key_input:
            st.warning("Please enter a valid alphabetic key")
            
    # Base64 and Morse Code don't need keys
    
    st.divider()
    
    # About section
    st.markdown("### About this App")
    st.markdown("""
    This app demonstrates various encryption and decryption techniques used throughout history.
    
    **Available Ciphers:**
    - **Caesar**: Simple substitution with fixed shift
    - **Vigenère**: Polyalphabetic substitution with key
    - **Playfair**: Digraph substitution with key matrix
    - **Base64**: Binary-to-text encoding scheme
    - **Morse Code**: Represents characters as sequences of dots and dashes
    
    Created by Shubham_Gadekar
    """)

# Main panel with input/output
col1, col2 = st.columns(2)

with col1:
    st.subheader("Input")
    input_text = st.text_area("Enter text to process", 
                           value=st.session_state.input_text,
                           height=150,
                           placeholder="Type or paste your text here...")
    st.session_state.input_text = input_text

# Process on button click
process_button = st.button("Process", type="primary", use_container_width=True)

if process_button or st.session_state.output_text:
    # Initialize the selected cipher object
    if selected_cipher == "Caesar":
        try:
            shift = int(st.session_state.key)
            cipher = CaesarCipher(shift)
        except ValueError:
            st.error("Caesar cipher requires a numeric shift value")
            cipher = None
    elif selected_cipher == "Vigenère":
        cipher = VigenereCipher(st.session_state.key)
    elif selected_cipher == "Playfair":
        cipher = PlayfairCipher(st.session_state.key)
    elif selected_cipher == "Base64":
        cipher = Base64Cipher()
    elif selected_cipher == "Morse Code":
        cipher = MorseCipher()
    
    # Process text if cipher is initialized
    if cipher and input_text:
        if selected_mode == "Encrypt":
            output_text = cipher.encrypt(input_text)
        else:  # Decrypt
            output_text = cipher.decrypt(input_text)
        
        st.session_state.output_text = output_text
    
    # Display output
    with col2:
        st.subheader("Output")
        st.text_area("Processed text", 
                   value=st.session_state.output_text,
                   height=150)
    
    # Show visualizations
    st.divider()
    st.subheader("Visualizations")
    
    # Create tabs for different visualizations
    tab1, tab2 = st.tabs(["Cipher Visualization", "Frequency Analysis"])
    
    with tab1:
        # Get visualization data based on cipher type
        if cipher:
            viz_data = None
            if hasattr(cipher, 'visualization_data'):
                if selected_mode == "Encrypt":
                    plaintext = input_text
                    ciphertext = st.session_state.output_text
                else:
                    plaintext = st.session_state.output_text
                    ciphertext = input_text
                
                viz_data = cipher.visualization_data(plaintext, ciphertext)
            
            # Render visualization
            if viz_data:
                render_visualization(viz_data)
            else:
                st.info("No visualization available for the current configuration")
    
    with tab2:
        # Show frequency analysis for both input and output
        freq_tabs = st.tabs(["Input Text", "Output Text"])
        
        with freq_tabs[0]:
            if input_text:
                freq_chart = create_frequency_chart(input_text)
                if freq_chart:
                    st.plotly_chart(freq_chart, use_container_width=True)
                else:
                    st.info("Not enough alphabetic characters for analysis")
            else:
                st.info("Enter text to see frequency analysis")
                
        with freq_tabs[1]:
            if st.session_state.output_text:
                freq_chart = create_frequency_chart(st.session_state.output_text)
                if freq_chart:
                    st.plotly_chart(freq_chart, use_container_width=True)
                else:
                    st.info("Not enough alphabetic characters for analysis")
            else:
                st.info("Process text to see frequency analysis")

# Footer
st.markdown("---")
st.markdown("📚 Learn more about classical cryptography and its historical significance")