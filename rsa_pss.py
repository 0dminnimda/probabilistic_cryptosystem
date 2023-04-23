import ast

from src.rsa import rsa_generate_keypair_of_sizes, rsa_encode, rsa_decode, Key
from src.pss import OctetString, pss_sign, MAX_SIGN_LEN, pss_verify


def send(message: bytes) -> tuple[bytes, int, Key]:
    print("=" * 15 + " Sender " + "=" * 15)

    oct_msg = OctetString.from_bytes(message)
    print(message)
    print(oct_msg.diagnostic())

    pss_signature = pss_sign(oct_msg, MAX_SIGN_LEN)
    print(pss_signature.diagnostic())

    numeric_repr = pss_signature.to_int()
    print(numeric_repr)

    prime_size = numeric_repr.bit_length() // 2 + 1
    public, private = rsa_generate_keypair_of_sizes(prime_size, prime_size)
    print(public)
    print(private)

    rsa_signature = rsa_encode(numeric_repr, private)
    print(rsa_signature)

    return message, rsa_signature, public


def recieve(message: bytes, rsa_signature: int, public: Key) -> bool:
    print("=" * 15 + " Reciever " + "=" * 15)

    numeric_repr = rsa_decode(rsa_signature, public)
    print(numeric_repr)

    oct_msg = OctetString.from_bytes(message)
    print(oct_msg.diagnostic())

    pss_signature = OctetString.from_int(numeric_repr)
    print(pss_signature.diagnostic())

    is_valid = pss_verify(oct_msg, MAX_SIGN_LEN, pss_signature)
    print("Valid" if is_valid else "Invalid")
    try:
        print(message.decode("utf-8"))
    except UnicodeDecodeError:
        print(message)

    return is_valid


def error_test(message: bytes) -> None:
    print("=" * 15 + " Error tests " + "=" * 15)
    inp = OctetString.from_bytes(message)
    pss_signature = pss_sign(inp, MAX_SIGN_LEN)

    is_valid = pss_verify(
        OctetString([inp[0] + 1, *inp[1:]]), MAX_SIGN_LEN, pss_signature
    )
    print("Valid" if is_valid else "Invalid")

    is_valid = pss_verify(
        inp, MAX_SIGN_LEN, OctetString([pss_signature[0] + 1, *pss_signature[1:]])
    )
    print("Valid" if is_valid else "Invalid")

    is_valid = pss_verify(
        inp, MAX_SIGN_LEN, OctetString([*pss_signature[:-1], pss_signature[-1] + 1])
    )
    print("Valid" if is_valid else "Invalid")


operation = input("Send message/Recieve message/Both? (s/r/b) [b]: ") or "b"

if "b" in operation:
    operation = "sr"

data: tuple[bytes, int, Key]
if "s" in operation:
    if int(input("Do you want to use random message? (0/1) [1]: ") or "1"):
        message = OctetString.random(69).to_bytes()
    else:
        message = input("Then input the message: ").encode("utf-8")

    data = send(message)
    print("Sending:", data)
else:
    data = ast.literal_eval(input("Then input the sent data: "))
    assert type(data) is tuple
    assert len(data) == 3

if "r" in operation:
    assert recieve(*data)

error_test(data[0])
