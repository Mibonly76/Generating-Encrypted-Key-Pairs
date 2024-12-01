#
#pip install cryptography
#
#####################################################################################
#                                                                                   #
#                    Generate and Save a Private Key                                #
#                                                                                   #
#####################################################################################

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(public_exponent= 65537, key_size= 2048)
password = input('Enter the Protection Password: ')
password_to_bytes = password.encode(encoding='utf-8')

priv_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                                     encryption_algorithm= serialization.BestAvailableEncryption(password_to_bytes))


with open("priv_key.pem", "wb") as priv_pem_file:
    priv_pem_file.write(priv_pem)

#####################################################################################
#                                                                                   #
#                    Generate and Save a Private Key                                #
#                                                                                   #
#####################################################################################


public_key = private_key.public_key()

public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open("pub_key.pem", "wb") as public_pen_file:
    public_pen_file.write(public_pem)
