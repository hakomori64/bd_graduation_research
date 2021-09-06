from flask import Flask, render_template, request
import os
import threading
import shutil

from flask.helpers import send_file

from drbac.pki import generate_key_pair, is_valid_format

app = Flask(__name__)

BASE_DIR = os.path.dirname(__file__)

CERT_FILE = os.path.join(BASE_DIR, 'server.pem')
KEY_FILE = os.path.join(BASE_DIR, 'server.key')

@app.route("/")
def hello():
    return render_template("index.html")

@app.route("/create_entity", methods=['POST'])
def create_entity():
    entity_name = request.form['entity']

    try:
        generate_key_pair('entity', entity_name)
    except Exception as e:
        return str(Exception)    

    os.makedirs('tmp')
    shutil.make_archive('')    

    return send_file(filename = f'actors/{entity_name}', attachment_filename='cert')


def start_web_server():
    threading.Thread(target = app.run, kwargs = {'host': 'localhost', 'port': 8000, 'ssl_context': (CERT_FILE, KEY_FILE)}).start()