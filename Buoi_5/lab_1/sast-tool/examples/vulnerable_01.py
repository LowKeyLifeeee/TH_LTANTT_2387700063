password = "123456"  # Fake password for the lab, not a real credential.

import pickle  # Có thể gây nguy hiểm

def unsafe_func(data):
    return eval(data)  # Rất nguy hiểm, eval dùng tùy ý

def safe_func():
    print("Hello world!")

if __name__ == "__main__":
    unsafe_func("2 + 2")
    safe_func()
