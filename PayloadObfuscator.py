import random

def safe_arithmetic(byte: int) -> str:
    operations = [
        # Basic XOR
        f"(0x{byte:02x}^0)",
        f"(0x{byte:02x}^0xFF^0xFF)",
        
        # Basic mafs 
        f"(0x{byte:02x}+0)",
        f"(0x{byte:02x}-0)",
        f"(0x{byte:02x}*1)",
        
        # Basic XOR w/ small number
        f"(0x{byte:02x}^0x1^0x1)",
        f"(0x{byte:02x}^0x2^0x2)",
        f"(0x{byte:02x}^0x3^0x3)",
    ]
    return random.choice(operations)

def safe_xor(byte: int) -> str:
    key = random.randint(1, 255)
    return f"(0x{(byte ^ key):02x}^0x{key:02x})"

def obfuscate_byte(byte: int) -> str:
    return random.choice([safe_arithmetic, safe_xor])(byte)

def obfuscate_bytes(bytes_list, bytes_per_line=8) -> str:
    obfuscated = [obfuscate_byte(b) for b in bytes_list]
    
    lines = []
    for i in range(0, len(obfuscated), bytes_per_line):
        line = obfuscated[i:i + bytes_per_line]
        lines.append('    ' + ', '.join(line))
    
    return "static const unsigned char bytearray[] = {\n" + ",\n".join(lines) + "\n};"

def main():
    print("Paste your byte array (with curly brace).")
    print("Ex: { 0xfc, 0x48, 0x81, .. }")
    print("Press Enter twice when done:")
    
    lines = []
    while True:
        line = input()
        if not line.strip():
            break
        lines.append(line)
    
    text = ' '.join(lines)
    start = text.find('{') + 1
    end = text.rfind('}')
    
    if start <= 0 or end <= 0:
        print("Error: Missing curly braces.")
        return
        
    content = text[start:end].strip()
    bytes_list = []
    
    for val in content.split(','):
        val = val.strip()
        if not val:
            continue
            
        try:
            if val.startswith('0x'):
                bytes_list.append(int(val, 16))
            else:
                bytes_list.append(int(val))
        except ValueError:
            print(f"Error parsing: {val}")
            return

    if not bytes_list:
        print("Error: No bytes found@")
        return

    print("\nObfuscated array:")
    print(obfuscate_bytes(bytes_list))

if __name__ == "__main__":
    main()
