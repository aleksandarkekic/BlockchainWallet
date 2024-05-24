import json
from rsaKey import Encrypt
from rsaKey import Encrypt


if __name__ == '__main__':
    # Encrypt.generate_and_save_rsa_key_pair("private1.pem","public1.pem")
    # Encrypt.generate_and_save_rsa_key_pair("private2.pem","public2.pem")
    # Encrypt.generate_and_save_rsa_key_pair("private3.pem","public3.pem")
    #Encrypt.saves_pairs_key_hash()
    pub_key_hash_adr=""

    flag = True
    while flag:
        print("\n==========================================")
        print("================ WALLET APP ================ [1]")
        print("=================== Exit =================== [2]")
        print("============================================\n")

        option = input("====== Enter option number: ======")

        if option.__eq__("1"):
            priv_key=""
            print("====== Input private key: ======\n ")

            while True:
                line = input()
                if not line:
                    break
                priv_key += line +'\n'
            with open("private1.pem", 'r') as file:
                private_key_read = file.read()
            if private_key_read.replace('\n', ' ') == priv_key.replace('\n', ' '):
                name_of_pub_key="public1.pem"
                pub_key_hash_adr="635cd5e165a8abaf08609ea5aae35c25f980d51e4b8cb97d813a5606790dc30faba6be7c039a5513aa1d5d0b05bf8370c732e26863018ba0813923c80378dc43"

            with open("private2.pem", 'r') as file:
                private_key_read = file.read()
            if private_key_read.replace('\n', ' ') == priv_key.replace('\n', ' '):
                name_of_pub_key = "public2.pem"
                pub_key_hash_adr="52eeb9ce115ac575c8cfdb18a34828a47a3dae5788d9f550a5cc5a82cad5ea04941fca17c809d001ca12484fc99ffe263bced1287e404e69be8da457087f4f5d"
            with open("private3.pem", 'r') as file:
                private_key_read = file.read()
            if private_key_read.replace('\n', ' ') == priv_key.replace('\n', ' '):
                name_of_pub_key = "public3.pem"
                pub_key_hash_adr="865cd99a83faf08d02000a92fffe1ffca4a070de17f0de2c33ba22928b07f41678159fd6892d683808e6484ffb06956e8cb55a2d4ce4bfe601e64ead86377482"

            Encrypt.wallet_print(pub_key_hash_adr, 10)
