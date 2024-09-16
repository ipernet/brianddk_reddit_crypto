#!/usr/bin/env python3
# [rights]  Copyright 2021 brianddk at github https://github.com/brianddk
# [license] Apache 2.0 License https://www.apache.org/licenses/LICENSE-2.0
# [repo]    github.com/brianddk/reddit/blob/master/python/hdseed.py
# [btc]     BTC-b32: bc1qwc2203uym96u0nmq04pcgqfs9ldqz9l3mz8fpj
# [tipjar]  github.com/brianddk/reddit/blob/master/tipjar/tipjar.txt
# [req]     python -m pip install electrum
# [note]    To run in electrum console, correct file path and run:
#    with open(r"C:\Windows\Temp\hdseed.py") as f: exec(f.read())
# [note]    You can give parameters by doing a `seed=...` command
#    on the Electrum console, or you can feed a commandline argument
#    if running from the an OS shell
# [note]    The argument (via `seed=...` or command-arg) will accept a
#    text string of hex, wif, xprv, or 12/24-word-mnemonic (as a single argument
#    enclosed with proper quoting)
# [note]    In the absence of an argument, a new BIP39-mnemonic will
#    be created and used

# ignore BIP45 and BIP48 MS-wallets

from mnemonic import Mnemonic as BIP39
from electrum.bitcoin import serialize_privkey as to_wif
from electrum.bitcoin import deserialize_privkey as from_wif
from electrum.bip32 import BIP32Node
from electrum import constants
from json import dumps
from sys import argv, stdin
hexdigits = '0123456789abcdefABCDEF'

def main():
    seed = globals().get('seed', None)

    # seed from stdin
    if not seed and not stdin.isatty():
        seed = stdin.readline().strip()

    if 'wallet' not in globals():
        # Not in electrum console, free to toggle network
        # Comment-out for mainet
        #constants.set_testnet()
        if len(argv) > 1:
            seed = argv[1]

    if True:
        bip = {}
        (mnemo, extended_master_privkey, uncompressed_wif_for_legacy_wallets, seed_input_mode) = [None] * 4

        if seed:
            (tmp, seed) = (seed, None)
            # hex seed with a 0x explicit prefix passed
            if '0x' == tmp[:2].lower():
                tmp = tmp[2:]

            # hex seed without 0x prefix:
            if set(tmp).issubset(hexdigits):
                # 32 bytes seed (256 bits) - Compatible with WIF and legacy wallets.
                if 64 == len(tmp):
                    seed = bytes.fromhex(tmp)
                    # Uncompressed WIF
                    uncompressed_wif_for_legacy_wallets = to_wif(seed, False, '').split(':')[-1]
                    seed_input_mode = 'Using input of 256-bits hex seed'
                elif 128 == len(tmp):
                    # 64 bytes seed (512 bits)
                    seed = bytes.fromhex(tmp)
                    seed_input_mode = 'Using input of 512-bits hex seed'
                    # no WIF possible, see the "Creative" way below to get one for legacy wallets
                else:
                    print('Unsupported key length. Only 256 or 512 bits seed supported')
                    return
            elif 'tprv' == tmp[:4] or 'xprv' == tmp[:4]:
                extended_master_privkey = tmp
                seed_input_mode = 'Using input xprv'
            # 24 words mnemonic (256 bits)
            elif 24 == len(tmp.split()):
                mnemo = tmp
                seed_input_mode = 'Using input mnemo (24 words)'
            # 12 words mnemonic (./hdseed.py '<word1> <word2> ...')
            elif 12 == len(tmp.split()):
                mnemo = tmp
                seed_input_mode = 'Using input mnemo (12 words)'
            else:
                # Check input is valid WIF
                uncompressed_wif_for_legacy_wallets = tmp
                _, seed, _ = from_wif(tmp)
                seed_input_mode = 'Using input seed in WIF format'

        bip39  = BIP39("English")

        # No input, use BIP39 to move forward with a 12-words mnemonic
        if not (seed or mnemo or uncompressed_wif_for_legacy_wallets or extended_master_privkey):
            # Generate 128 entropy and a 12-words mnemonic
            # Generating 256 bits of entropy and a 24-words would break compatibility
            # for legacy wallet as no 128-bits single WIF could be generated.
            mnemo  = bip39.generate(128)
            seed_input_mode = 'New 128 bits of entropy encoded in a new mnemonic'

        # 12 or 24-words possible
        if mnemo:
            # Returns a 64 bytes seed (From 128 or 256 bits of input feeds to PBKDF2 with HMAC-SHA512 output)
            # Warning: No passphrase support here!
            seed = bip39.to_seed(mnemo, '')

            # If we have a 256 bits seed, we can support legacy wallets
            if 12 == len(mnemo.split()):
                uncompressed_wif_for_legacy_wallets = to_wif(seed, False,'').split(':')[-1]

            # Feeds the 512 bits as input for HMAC-SHA512
            bip32 = BIP32Node.from_rootseed(seed, xtype='standard')
            extended_master_privkey = bip32.to_xprv()
        elif seed:
            # seed from argv 1, checked as beeing either 256 or 512 bits
            bip32  = BIP32Node.from_rootseed(seed, xtype='standard')
            extended_master_privkey = bip32.to_xprv()
        elif extended_master_privkey:
            bip32  = BIP32Node.from_xkey(extended_master_privkey)

        # extended_master_privkey set from now on.
        hdmasterfingerprint = bip32.calc_fingerprint_of_this_node().hex().lower()

        if constants.net.TESTNET:
            coin_type = 1
        else:
            coin_type = 0

        desc = {'44':['pkh'],'49':['wpkh','sh'],'84':['wpkh'],'86':['tr']}
        conf = {'44':'legacy','49':'p2sh-segwit','84':'bech32','86':'bech32m'}
        for k in desc.keys():
            imp  = {'timestamp':'now','range':[0,999],'next_index':0}
            imp  = [dict(imp), dict(imp)]

            acct = f"{k}'/{coin_type}'/0'" # Use unhardened derivation for all addresses (now default with descriptor wallets)
            if uncompressed_wif_for_legacy_wallets:
                # We have a 256 bits seed here
                key = seed
                wif = uncompressed_wif_for_legacy_wallets
            else:
                # ! "Don't roll your own crypto" warning !
                # We don't have a 256 bits seed here, only a 512 one => "Creative" cherry-picked WIF of 256 bits (first derivation, per standard)
                # https://www.reddit.com/r/Bitcoin/comments/r5g0ws/howto_ways_to_use_12_word_seeds_bip39_in_bitcoin/
                key  = bip32.subkey_at_private_derivation(f"m/{acct}/0/0").eckey.get_secret_bytes()
                wif  = to_wif(key, False, '').split(':')[-1]
            bip[k] = {}
            bip[k]['key'] = key.hex()
            bip[k]['wif'] = wif
            change = 0
            for j in ['addr', 'change']:
                path      = f"{acct}/{change}"
                desc_str  = f"{extended_master_privkey}/{path}/*"
                for i in desc[k]:
                    desc_str = f"{i}({desc_str})"
                desc_str  = descsum_create(desc_str)
                imp[change]['desc'] = desc_str
                imp[change]['internal'] = bool(change)
                # Ensure we have an active descriptor set for each of the 4 HD chains and for both "receiving" and "change".
                imp[change]['active'] = True
                bip[k][j] = {}
                bip[k][j]['derivation'] = path
                bip[k][j]['desc'] = desc_str
                bip[k][j]['import'] = 'importdescriptors ' + dumps(imp[change]).replace('"', r'\"')
                change += 1
            imp_txt = dumps(imp).replace('"', r'\"')
            if '86' == k:
                cmd = ''
            else:
                # createwallet "wallet_name" ( disable_private_keys blank "passphrase" avoid_reuse descriptors load_on_startup external_signer )
                cmd =  f'createwallet "bip{k}-berkley" false true\n'
                cmd += f'sethdseed true "{wif}"\n'
            cmd += f'createwallet "bip{k}-sqlite"  false true "" false true\n'
            cmd += f'importdescriptors "{imp_txt}"'
            bip[k]['import'] = imp_txt
            bip[k]['commands'] = cmd

        print(f'\n# Your BIP39 Mnemonic:            "{mnemo}"')
        print(  f'# Your BIP32 Root Key:            "{extended_master_privkey}"')
        print(  f'# Your BIP32 hdmasterfingerprint: "{hdmasterfingerprint}"')
        print(f'\n# Your legacy hdseed (uncompressed)      wif:"{bip["44"]["wif"]}", priv:"{bip["44"]["key"]}"')
        print(  f'# Your p2sh-segwit hdseed (uncompressed) wif:"{bip["49"]["wif"]}", priv:"{bip["49"]["key"]}"')
        print(  f'# Your bech32 hdseed (uncompressed)      wif:"{bip["84"]["wif"]}", priv:"{bip["84"]["key"]}"\n')

        for k in desc.keys():
            print(f'##################################################')
            print(f'# Your BIP{k} config is:\n{constants.net.NET_NAME}.addresstype={conf[k]}\n{constants.net.NET_NAME}.changetype={conf[k]}\n')
            print(f'# Your BIP{k} commands are:\n{bip[k]["commands"]}\n')

        # Complete wallet
        print(f'##################################################')
        print(f'# Complete (all standards) descscriptor wallet:')
        walletname = '-'.join(desc.keys())
        print(f'\ncreatewallet "wallet-bips-{walletname}" false true "" false true\n')
        for k in desc.keys():
            print(f'importdescriptors "{bip[k]["import"]}"\n')

        if not uncompressed_wif_for_legacy_wallets:
            print('!!! Warning: 512-bits seed detected, this is not compatible with a single 256 bits WIF "hdseed" for legacy wallets!')
            print('!!! WIF keys above are NOT unique but "creatively" generated from the first addresse at the standard derivation path for each standard.')
            print('!!! Single-hdseed not available, the input seed cannot be used for a legacy wallet.')

        if mnemo:
            print('\n!!! No passphrase used on the mnemonic!')

        print(f'\nSeed input mode used: {seed_input_mode}')

        if not constants.net.TESTNET:
            print("\n!!! Beware, you are not on Testnet")

INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

def descsum_polymod(symbols):
    """Internal function that computes the descriptor checksum."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk

def descsum_expand(s):
    """Internal function that does the character to symbol expansion"""
    groups = []
    symbols = []
    for c in s:
        if not c in INPUT_CHARSET:
            return None
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols

def descsum_create(s):
    """Add a checksum to a descriptor without"""
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))

main()
