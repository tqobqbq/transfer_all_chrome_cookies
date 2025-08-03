#https://github.com/runassu/chrome_v20_decryption/blob/main/decrypt_chrome_v20_cookie.py

import os
import io
import sys
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
import base64
from contextlib import contextmanager

import windows
import windows.security
import windows.crypto
import windows.generated_def as gdef
# import win32crypt

from Crypto.Cipher import AES, ChaCha20_Poly1305

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

@contextmanager
def impersonate_lsass():
    """impersonate lsass.exe to get SYSTEM privilege"""
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token

def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        # [flag|iv|ciphertext|tag] decrypted_blob
        # [1byte|12bytes|32bytes|16bytes]
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        # [flag|encrypted_aes_key|iv|ciphertext|tag] decrypted_blob
        # [1byte|32bytes|12bytes|32bytes|16bytes]
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return parsed_data

def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        None,
        0,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

    return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
def get_v20_master_key():
    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
        
    # Read Local State
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
    assert(binascii.a2b_base64(app_bound_encrypted_key)[:4] == b"APPB")
    key_blob_encrypted = binascii.a2b_base64(app_bound_encrypted_key)[4:]
    
    # Decrypt with SYSTEM DPAPI
    with impersonate_lsass():
        key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
        # key_blob_system_decrypted = win32crypt.CryptUnprotectData(key_blob_encrypted, None, None, None, 0)[1]

    # Decrypt with user DPAPI
    key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
    # key_blob_user_decrypted = win32crypt.CryptUnprotectData(key_blob_system_decrypted, None, None, None, 0)[1]
    
    # Parse key blob
    parsed_data = parse_key_blob(key_blob_user_decrypted)
    v20_master_key = derive_v20_master_key(parsed_data)
    return v20_master_key
    
def get_v10_master_key():
    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
        
    # Read Local State
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = local_state['os_crypt']['encrypted_key']
    encrypted_blob = base64.b64decode(encrypted_key)[5:]  # Leading bytes "DPAPI" need to be removed
    v10_master_key = windows.crypto.dpapi.unprotect(encrypted_blob)
    return v10_master_key
    

def run_for_source_chrome():
    print('v20:',get_v20_master_key())
    print('v10:',get_v10_master_key())
    
def run_for_target_chrome(target_key_type=b'v10'):
    #fill in  the v20 master key from source chrome
    # source_v20_master_key = 
    # source_v10_master_key = 
    
    # fill in the cookies file path
    # # user_profile = os.environ['USERPROFILE']
    # # cookie_db_path=rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
    # cookie_db_path=
    
    if target_key_type==b'v10':
        target_master_key = get_v10_master_key()
    elif target_key_type==b'v20':
        target_master_key= get_v20_master_key()
    else:
        raise ValueError(target_key_type)
    
    con = sqlite3.connect(cookie_db_path)
    cur = con.cursor()
    r = cur.execute("SELECT rowid, CAST(encrypted_value AS BLOB) from cookies;")
    batch_updates = []
    count=0
    for rowid, encrypted_value in r.fetchall():
        # assert encrypted_value[:3] == b"v20",encrypted_value[:3]
        if encrypted_value[:3] == b"v10":
            source_master_key=source_v10_master_key
        elif encrypted_value[:3] == b"v20":
            source_master_key=source_v20_master_key
        else:
            raise ValueError(encrypted_value[:3])
        
        cookie_iv = encrypted_value[3:3+12]
        encrypted_cookie = encrypted_value[3+12:-16]
        cookie_tag = encrypted_value[-16:]
        source_cookie_cipher = AES.new(source_master_key, AES.MODE_GCM, nonce=cookie_iv)
        decrypted_cookie = source_cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)

        new_cookie_iv=cookie_iv
        target_cookie_cipher = AES.new(target_master_key, AES.MODE_GCM, nonce=new_cookie_iv)
        a=target_cookie_cipher.encrypt(decrypted_cookie)
        b=target_cookie_cipher._compute_mac()
        new_encrypted_value = b''.join([target_key_type,new_cookie_iv, a, b])
        # print(len(encrypted_value),len(decrypted_cookie), len(a), len(b),len(new_encrypted_value))
        # assert encrypted_value==new_encrypted_value, (new_encrypted_value, encrypted_value)
        batch_updates.append((new_encrypted_value, rowid))
        count+=1
        # print(new_encrypted_cookie)
    print(f"Total {count} cookies to update.")
    # batch update
    cur.executemany("UPDATE cookies SET encrypted_value = ? WHERE rowid = ?", batch_updates)
    con.commit()
    con.close()
if __name__ == "__main__":
    if not is_admin():
        print("This script needs to run as administrator.")
    else:
        # run_for_target_chrome(b'v10')
        run_for_source_chrome()
