import binascii
from collections import OrderedDict
from crypt import methods
import json
import requests

from flask import Flask, jsonify, request, render_template

import Crypto
import Crypto.Random
from hashlib import SHA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


class Transaction:
    # Four attributes necessary for transaction
    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    # Turns the public info in an dictionary
    def form_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    # Signs the transaction to make it unique
    def sign_transaction(self):
        # Decrypts the key
        private_key = RSA.importKey(
            binascii.unhexlify(self.sender_private_key))
        # PKCS1 v1.5 Encryption key
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        # Encrypts the key to make it private again
        return binascii.hexlify(signer.sign(h)).decode('ascii')


# Starts Flask
app = Flask(__name__)

# Mapping URLs


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

# Generates new wallets


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random = Crypto.Random.new().read
    # Generates random private key in 2048 bits
    private_key = RSA.generate(2048, random)
    # .publickey function generates matching public key
    public_key = private_key.publickey

    # Inserts keys in a dictionary after encrypting them in binary format and decoding
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }
    return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    value = request.form['amount']

    transaction = Transaction(
        sender_address, sender_private_key, recipient_address, value)
    response = {'transaction': Transaction.form_dict(
    ), 'signature': Transaction.sign_transaction()}

    return jsonify(response), 200
