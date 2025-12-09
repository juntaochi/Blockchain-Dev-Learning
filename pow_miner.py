import hashlib
import time


def find_pow(nickname: str, zero_count: int, start_nonce: int = 0):
    """Brute-force a nonce so sha256(nickname + nonce) has the desired leading zeros."""
    target = "0" * zero_count
    nonce = start_nonce
    start = time.perf_counter()

    while True:
        payload = f"{nickname}{nonce}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if digest.startswith(target):
            elapsed = time.perf_counter() - start
            return nonce, payload, digest, elapsed
        nonce += 1


def main():
    nickname = "JackFrost"

    nonce4, payload4, hash4, elapsed4 = find_pow(nickname, 4)
    print(f"4 leading zeros: time={elapsed4:.3f}s payload='{payload4}' hash={hash4}")

    nonce5, payload5, hash5, elapsed5 = find_pow(nickname, 5)
    print(f"5 leading zeros: time={elapsed5:.3f}s payload='{payload5}' hash={hash5}")


if __name__ == "__main__":
    main()
