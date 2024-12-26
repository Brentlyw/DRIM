import random

def generate_complex_arithmetic(target):
    def create_nested_expr(value, depth=0):
        if depth >= 3:
            return str(value)
            
        ops = [
            ('*', lambda x,y: x*y),
            ('/', lambda x,y: x/y),
            ('+', lambda x,y: x+y),
            ('-', lambda x,y: x-y),
            ('<<', lambda x,y: x<<y),
            ('>>', lambda x,y: x>>y),
            ('&', lambda x,y: x&y),
            ('|', lambda x,y: x|y),
            ('^', lambda x,y: x^y)
        ]
        
        op, func = random.choice(ops)
        
        if op in ['*', '/']:
            factor = random.choice([2,3,4,5])
            if op == '*':
                value //= factor
            else:
                value *= factor
            inner = create_nested_expr(value, depth+1)
            return f"({inner}{op}{factor})"
            
        elif op in ['<<', '>>']:
            shift = random.randint(1,3)
            if op == '<<':
                value >>= shift
            else:
                value <<= shift
            inner = create_nested_expr(value, depth+1)
            return f"({inner}{op}{shift})"
            
        elif op in ['&', '|', '^']:
            mask = random.randint(64, 255)
            if op == '&':
                value = value | (~mask & 0xFF)
            elif op == '|':
                value = value & ~mask
            else:
                value ^= mask
            inner = create_nested_expr(value, depth+1)
            return f"({inner}{op}{mask})"
            
        else:  # + or -
            offset = random.randint(1,15)
            if op == '+':
                value -= offset
            else:
                value += offset
            inner = create_nested_expr(value, depth+1)
            return f"({inner}{op}{offset})"
    
    return create_nested_expr(target)

def validate_expression(expr, target):
    try:
        result = eval(expr)
        return int(result) == target and 0 <= target <= 127
    except:
        return False

def obfuscate_string(input_str):
    chars = []
    for c in input_str:
        while True:
            expr = generate_complex_arithmetic(ord(c))
            if validate_expression(expr, ord(c)):
                chars.append(expr)
                break
    return f"char arr[] = {{{', '.join(chars)}, 0}};"

def main():
    while True:
        text = input("Enter string to obfuscate ( 'q' to quit ): ")
        if text.lower() == 'q':
            break
        print("\nObfuscated:")
        print(obfuscate_string(text))
        print()

if __name__ == "__main__":
    main()
