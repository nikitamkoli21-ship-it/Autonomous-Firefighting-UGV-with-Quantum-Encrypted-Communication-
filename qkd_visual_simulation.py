# qkd_visual_simulation.py
import random
import time
from colorama import Fore, Style, init

init(autoreset=True)

def bb84_visual_simulation(num_bits=16, eavesdrop=False):
    print(f"\n{Fore.CYAN}=== BB84 Quantum Key Distribution Visual Simulation ==={Style.RESET_ALL}")
    print(f"Simulating {num_bits} qubits exchange...\n")

    # Step 1: Alice prepares random bits and bases
    alice_bits = [random.choice([0, 1]) for _ in range(num_bits)]
    alice_bases = [random.choice(['Z', 'X']) for _ in range(num_bits)]

    print(f"{Fore.MAGENTA}Alice (UGV) prepares qubits:")
    for i in range(num_bits):
        print(f" Qubit {i+1:02}: Bit={alice_bits[i]} | Basis={alice_bases[i]}")
        time.sleep(0.05)
    print()

    # Step 2: Eve (optional)
    if eavesdrop:
        print(f"{Fore.RED}[Eve] Eavesdropper intercepts and measures qubits!")
        eve_bases = [random.choice(['Z', 'X']) for _ in range(num_bits)]
        eve_results = []
        for i in range(num_bits):
            if eve_bases[i] == alice_bases[i]:
                eve_results.append(alice_bits[i])
            else:
                eve_results.append(random.choice([0, 1]))
        # Eve resends qubits (distorted)
        alice_bits = eve_results
        print(f"{Fore.RED}Eve altered some bits due to wrong basis measurement.\n")
        time.sleep(0.5)

    # Step 3: Bob chooses random bases and measures
    bob_bases = [random.choice(['Z', 'X']) for _ in range(num_bits)]
    bob_results = []
    for i in range(num_bits):
        if bob_bases[i] == alice_bases[i]:
            bob_results.append(alice_bits[i])
        else:
            bob_results.append(random.choice([0, 1]))

    print(f"{Fore.YELLOW}Bob (Laptop) measures qubits:")
    for i in range(num_bits):
        symbol = "✔️" if bob_bases[i] == alice_bases[i] else "❌"
        print(f" Qubit {i+1:02}: AliceBasis={alice_bases[i]} | BobBasis={bob_bases[i]} {symbol} → BobBit={bob_results[i]}")
        time.sleep(0.05)
    print()

    # Step 4: Basis comparison and key sifting
    print(f"{Fore.CYAN}\nStep 4: Publicly comparing bases and keeping matching ones...{Style.RESET_ALL}\n")
    sifted_key_alice = []
    sifted_key_bob = []
    for i in range(num_bits):
        if alice_bases[i] == bob_bases[i]:
            sifted_key_alice.append(alice_bits[i])
            sifted_key_bob.append(bob_results[i])

    print(f"{Fore.MAGENTA}Alice sifted key: {sifted_key_alice}")
    print(f"{Fore.YELLOW}Bob   sifted key: {sifted_key_bob}\n")

    # Step 5: Error check (simulate public comparison)
    errors = sum(1 for i in range(len(sifted_key_alice))
                 if sifted_key_alice[i] != sifted_key_bob[i])
    error_rate = errors / len(sifted_key_alice) if sifted_key_alice else 0

    print(f"{Fore.WHITE}Estimated Quantum Bit Error Rate (QBER): {Fore.RED if error_rate>0 else Fore.GREEN}{error_rate*100:.2f}%{Style.RESET_ALL}")

    if eavesdrop and error_rate > 0:
        print(f"{Fore.RED}\n[Eve detected!] High error rate indicates possible eavesdropping!{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}\nNo eavesdropper detected. Secure key established successfully!{Style.RESET_ALL}")

    # Step 6: Final shared key
    final_key = sifted_key_alice[:8]  # keep first 8 bits for demo
    print(f"\n{Fore.CYAN}Final shared key: {''.join(map(str, final_key))}{Style.RESET_ALL}\n")
    print(f"{Fore.WHITE}This key will now be used by AES-GCM to encrypt UGV alerts.\n")

def main():
    print(f"{Fore.WHITE}Do you want to simulate eavesdropping? (y/n): {Style.RESET_ALL}", end="")
    choice = input().strip().lower()
    eaves = choice == 'y'
    bb84_visual_simulation(num_bits=16, eavesdrop=eaves)

if __name__ == '__main__':
    main()
