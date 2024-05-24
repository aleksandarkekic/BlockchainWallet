import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


class Encrypt:

    total_amount = 0

    @staticmethod
    def generate_and_save_rsa_key_pair(private_key_file, public_key_file, key_size=2048):
        # Generiši RSA ključeve
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Spremi privatni ključ
        with open(private_key_file, 'wb') as f:
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            f.write(private_key_bytes)

        # Spremi javni ključ
        public_key = private_key.public_key()
        with open(public_key_file, 'wb') as f:
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            f.write(public_key_bytes)

    @staticmethod
    def load_rsa_private_key(private_key_file):
        # Učitaj privatni ključ iz datoteke
        with open(private_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        return private_key

    @staticmethod
    def load_rsa_public_key(public_key_file):
        # Učitaj javni ključ iz datoteke
        with open(public_key_file, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        return public_key

    @staticmethod
    def encryption(message, public_key):
        # Pretvori JSON poruku u bajtni niz
        mess_str = str(message)
        message_bytes = mess_str.encode('utf-8')

        # Enkriptiraj poruku s javnim ključem
        encrypted_message = Encrypt.load_rsa_public_key(public_key).encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_message

    @staticmethod
    def dgst(private_key, hash):
        hash_bytes = hash.encode('utf-8')
        priv_key = Encrypt.load_rsa_private_key(private_key)

        # Potpiši hash privatnim ključem
        dgst = priv_key.sign(
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

        return dgst

    @staticmethod
    def decryption(encrypted_message, key):
        # Dekriptiraj poruku s privatnim ključem
        decrypted_message_bytes = Encrypt.load_rsa_private_key(key).decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Pretvori bajtne nizove u string
        decrypted_message = decrypted_message_bytes.decode('utf-8')

        return decrypted_message

    #this method calculates sha512 hash print
    @staticmethod
    def generisi_sha512_hash(tekst):

        bajtovi_teksta = tekst.encode('utf-8')
        sha512_objekat = hashlib.sha512()
        sha512_objekat.update(bajtovi_teksta)
        sha512_otisak = sha512_objekat.hexdigest()
        return sha512_otisak

    #this method after receiving the path to the key file loads it as a string
    @staticmethod
    def load_key_as_string(path):
        try:
            with open(path, 'r') as file:
                public_key_read = file.read()
                public_key_read_1 = public_key_read.replace('\n', ' ')
                return public_key_read_1
        except FileNotFoundError:
            print(f"File {path} is not found.")
            return None
        except Exception as e:
            print(f"Error reading and formatting the private key: {str(e)}")
            return None

    #this method stores key, hes fingerprint pairs in a file
    @staticmethod
    def saves_pairs_key_hash():
        with open('key_hash_pairs', 'w') as fajl:
            first_str = 'public1.pem'
            seconds_str = 'public2.pem'
            third_str = 'public3.pem'
            first_hash = Encrypt.generisi_sha512_hash(Encrypt.load_key_as_string('public1.pem'))
            second_hash = Encrypt.generisi_sha512_hash(Encrypt.load_key_as_string('public2.pem'))
            third_hash = Encrypt.generisi_sha512_hash(Encrypt.load_key_as_string('public3.pem'))
            fajl.write(f"{first_str},{first_hash}\n")
            fajl.write(f"{seconds_str},{second_hash}\n")
            fajl.write(f"{third_str},{third_hash}\n")

    #this method serves to verify the digital signature
    @staticmethod
    def verify_signature(javni_kljuc, transaction_inf, digitalni_potpis, key):
        trans = Encrypt.decrypt_transaction_json(transaction_inf[0], key)
        hash = Encrypt.generisi_sha512_hash(trans)

        pub_key = Encrypt.load_rsa_public_key(javni_kljuc)

        # verify signature with public key
        try:
            pub_key.verify(
                digitalni_potpis,
                hash.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            print("Digital signature is valid.")
            return True
        except Exception as e:
            print(f"Digital signature is not valid: {str(e)}")
            return False

    @staticmethod
    def decrypt_transaction_json(transaction_infos, key):
        sender = Encrypt.decryption(base64.b64decode(transaction_infos.get('sender', None)), key)
        receiver = Encrypt.decryption(base64.b64decode(transaction_infos.get('receiver', None)), key)
        amount = Encrypt.decryption(base64.b64decode(transaction_infos.get('amount', None)), key)
        transtaction_str = sender + receiver + str(amount)
        print(transtaction_str)
        return transtaction_str

    #this method is used to display the user's wallet,
    # more precisely all his transactions and the total balance in the wallet
    @staticmethod
    def wallet_print(pub_key_hash_adr,total_amount_var):
        with open("node_5001.json", 'r') as file:
            blockchain_data = json.load(file)

        chain = blockchain_data['chain']
        Encrypt.total_amount=total_amount_var
        for block in chain:
            if block['transactions'] == "[]":
                pass
            else:
                string_vr = str(block['transactions'])
                # print(type(string_vr))
                parts = string_vr.split(", ")
                sender = parts[0].split(":")[1].strip()
                receiver = parts[1].split(":")[1].strip()
                amount = parts[2].split(":")[1].strip()
                signature = parts[3].split(":")[1].strip()
                try:
                    sender_decrypt = Encrypt.decryption(base64.b64decode(sender.encode('utf-8')[2:-1]),"private1.pem")
                    receiver_decrypt = Encrypt.decryption(base64.b64decode(receiver.encode('utf-8')[2:-1]),"private1.pem")
                    amount_decrypt = Encrypt.decryption(base64.b64decode(amount.encode('utf-8')[2:-1]),"private1.pem")

                    if sender_decrypt == pub_key_hash_adr or receiver_decrypt == pub_key_hash_adr:
                        print("sender: "+sender_decrypt)
                        print("receiver: "+receiver_decrypt)
                        if receiver_decrypt == pub_key_hash_adr:
                            print("amount: "+amount_decrypt)
                            Encrypt.total_amount=Encrypt.total_amount+int(amount_decrypt)
                            print("Total amount: "+str(Encrypt.total_amount))
                        else:
                            print("amount: " + "-"+str(amount_decrypt))
                            Encrypt.total_amount = Encrypt.total_amount- int(amount_decrypt)
                            print("Total amount: " + str(Encrypt.total_amount))
                except Exception as e:
                    pass
                try:
                    sender_decrypt = Encrypt.decryption(base64.b64decode(sender.encode('utf-8')[2:-1]), "private2.pem")
                    receiver_decrypt = Encrypt.decryption(base64.b64decode(receiver.encode('utf-8')[2:-1]),  "private2.pem")
                    amount_decrypt = Encrypt.decryption(base64.b64decode(amount.encode('utf-8')[2:-1]), "private2.pem")

                    if sender_decrypt == pub_key_hash_adr or receiver_decrypt == pub_key_hash_adr:
                        print("sender: "+sender_decrypt)
                        print("receiver: "+receiver_decrypt)
                        if receiver_decrypt == pub_key_hash_adr:
                            print("amount: "+amount_decrypt)
                            Encrypt.total_amount=Encrypt.total_amount+int(amount_decrypt)
                            print("Total amount: "+str(Encrypt.total_amount))
                        else:
                            print("amount: " + "-" + str(amount_decrypt))
                            Encrypt.total_amount = Encrypt.total_amount- int(amount_decrypt)
                            print("Total amount: " + str(Encrypt.total_amount))
                except Exception as e:
                    pass

                try:
                    sender_decrypt = Encrypt.decryption(base64.b64decode(sender.encode('utf-8')[2:-1]), "private3.pem")
                    receiver_decrypt = Encrypt.decryption(base64.b64decode(receiver.encode('utf-8')[2:-1]),"private3.pem")
                    amount_decrypt = Encrypt.decryption(base64.b64decode(amount.encode('utf-8')[2:-1]), "private3.pem")

                    if sender_decrypt == pub_key_hash_adr or receiver_decrypt == pub_key_hash_adr:
                        print("sender: " + sender_decrypt)
                        print("receiver: " + receiver_decrypt)
                        if receiver_decrypt == pub_key_hash_adr:
                            print("amount: " + amount_decrypt)
                            Encrypt.total_amount = Encrypt.total_amount + int(amount_decrypt)
                            print("Total amount: " + str(Encrypt.total_amount))
                        else:
                            print("amount: " + "-"+str(amount_decrypt))
                            Encrypt.total_amount = Encrypt.total_amount - int(amount_decrypt)
                            print("Total amount: " + str(Encrypt.total_amount))
                except Exception as e:
                    pass


