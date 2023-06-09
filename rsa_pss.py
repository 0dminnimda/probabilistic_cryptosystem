import ast

from src import rsa, pss
from src.octet_string import OctetString
from src.pss import MAX_SIGN_LEN


VERBOSE = False


def verbose_print(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)


def send(message: bytes) -> tuple[bytes, int, rsa.Key]:
    print("=" * 15 + " Sender " + "=" * 15)

    oct_msg = OctetString.from_bytes(message)
    verbose_print("raw message:", message)
    verbose_print("octate message:", oct_msg.diagnostic())

    pss_signature = pss.sign(oct_msg, MAX_SIGN_LEN)
    verbose_print("octate pss signature:", pss_signature.diagnostic())

    numeric_repr = pss_signature.to_int()
    verbose_print("number pss signature:", numeric_repr)

    public, private = rsa.generate_keypair(numeric_repr.bit_length())
    verbose_print("public rsa key:", public)
    verbose_print("private rsa key:", private)

    rsa_signature = rsa.encode(numeric_repr, private)
    verbose_print("rsa signature:", rsa_signature)

    return message, rsa_signature, public


def recieve(message: bytes, rsa_signature: int, public: rsa.Key) -> bool:
    print("=" * 15 + " Reciever " + "=" * 15)

    numeric_repr = rsa.decode(rsa_signature, public)
    verbose_print("rsa signature:", numeric_repr)

    oct_msg = OctetString.from_bytes(message)
    verbose_print("octate message:", oct_msg.diagnostic())

    pss_signature = OctetString.from_int(numeric_repr)
    verbose_print("number pss signature:", pss_signature.diagnostic())

    is_valid = pss.verify(oct_msg, MAX_SIGN_LEN, pss_signature)
    print("Valid" if is_valid else "Invalid")
    try:
        print(message.decode("utf-8"))
    except UnicodeDecodeError:
        print(message)

    return is_valid


def error_test(message: bytes) -> None:
    print("=" * 15 + " Error tests " + "=" * 15)
    inp = OctetString.from_bytes(message)
    pss_signature = pss.sign(inp, MAX_SIGN_LEN)

    is_valid = pss.verify(
        OctetString([inp[0] + 1, *inp[1:]]), MAX_SIGN_LEN, pss_signature
    )
    print("Valid" if is_valid else "Invalid")

    is_valid = pss.verify(
        inp, MAX_SIGN_LEN, OctetString([pss_signature[0] + 1, *pss_signature[1:]])
    )
    print("Valid" if is_valid else "Invalid")

    is_valid = pss.verify(
        inp, MAX_SIGN_LEN, OctetString([*pss_signature[:-1], pss_signature[-1] + 1])
    )
    print("Valid" if is_valid else "Invalid")


verbose = input("Make output verbose? (0/1) [0]: ") or "0"
VERBOSE = bool(int(verbose))
operation = input("Send message/Recieve message/Both? (s/r/b) [b]: ") or "b"

if "b" in operation:
    operation = "sr"

data: tuple[bytes, int, rsa.Key]
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
    assert recieve(*data), "Message is invalid"

# since it works no need to run it every time
# error_test(data[0])
