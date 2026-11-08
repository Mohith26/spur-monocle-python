"""Local decryption throughput (cached key vs parsing the PEM on every call). Usage: python bench/bench_local_decrypt.py"""
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spur_monocle._jwe import decrypt_compact, load_private_key  # noqa: E402
from spur_monocle.client import decrypt_assessment_locally  # noqa: E402
from tests.helpers import assessment, encrypt, new_key  # noqa: E402

N, RUNS = 2000, 5
key, pem = new_key()
tokens = [encrypt(assessment(), key.public_key()) for _ in range(N)]


def cached():
    for t in tokens:
        decrypt_assessment_locally(t, pem)


def uncached():
    for t in tokens:
        decrypt_compact(t, load_private_key(pem))


for name, fn in [("cached key (library default)", cached), ("parse PEM every call", uncached)]:
    times = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    med = statistics.median(times)
    print(f"{name:32s} median {med * 1e6 / N:7.1f} us/assessment  ({N / med:,.0f}/s, {RUNS} runs of {N})")
