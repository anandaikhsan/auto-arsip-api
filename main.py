import rsa
from PIL import Image
import pytesseract
from flask import request, make_response
import pandas as pd
import nltk
from nltk.tokenize import word_tokenize
import os
import urllib.request
from app import app
from flask import Flask, request, redirect, jsonify
from werkzeug.utils import secure_filename
import camelot
from pdf2image import convert_from_path
import json
import random
import string
import time
import sqlalchemy
import pymysql
from cryptography.fernet import Fernet
import requests
import hashlib
from PyPDF2 import PdfFileWriter, PdfFileReader
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

ALLOWED_EXTENSIONS = {'pdf'}

DB_HOST = "127.0.0.1:3306"
DB_NAME = "dokuin"
DB_USER = "root"
DB_PASS = "hahaha90"
GOOGLE_APPLICATION_CREDENTIAL = 'C:\\Users\\anand\\PycharmProjects\\auto-arsip-api\\riset-ml-e1896faeb7b2.json'


def load_key():
    return open("secret.key", "rb").read()


def encrypt_data(data):
    key = load_key()
    encoded_data = data.encode()

    f = Fernet(key)

    return f.encrypt(encoded_data).decode('utf-8')


def decrypt_data(encrypted_data):
    key = load_key()
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)

    return decrypted_data.decode()


def init_connection_engine():
    db_config = {
        # [START cloud_sql_mysql_sqlalchemy_limit]
        # Pool size is the maximum number of permanent connections to keep.
        "pool_size": 5,
        # Temporarily exceeds the set pool_size if no connections are available.
        "max_overflow": 2,
        # The total number of concurrent connections for your application will be
        # a total of pool_size and max_overflow.
        # [END cloud_sql_mysql_sqlalchemy_limit]
        # [START cloud_sql_mysql_sqlalchemy_backoff]
        # SQLAlchemy automatically uses delays between failed connection attempts,
        # but provides no arguments for configuration.
        # [END cloud_sql_mysql_sqlalchemy_backoff]
        # [START cloud_sql_mysql_sqlalchemy_timeout]
        # 'pool_timeout' is the maximum number of seconds to wait when retrieving a
        # new connection from the pool. After the specified amount of time, an
        # exception will be thrown.
        "pool_timeout": 30,  # 30 seconds
        # [END cloud_sql_mysql_sqlalchemy_timeout]
        # [START cloud_sql_mysql_sqlalchemy_lifetime]
        # 'pool_recycle' is the maximum number of seconds a connection can persist.
        # Connections that live longer than the specified amount of time will be
        # reestablished
        "pool_recycle": 1800,  # 30 minutes
        # [END cloud_sql_mysql_sqlalchemy_lifetime]
    }

    if DB_HOST:
        return init_tcp_connection_engine(db_config)
    else:
        return init_unix_connection_engine(db_config)


def init_tcp_connection_engine(db_config):
    # [START cloud_sql_mysql_sqlalchemy_create_tcp]
    # Remember - storing secrets in plaintext is potentially unsafe. Consider using
    # something like https://cloud.google.com/secret-manager/docs/overview to help keep
    # secrets secret.
    db_user = DB_USER
    db_pass = DB_PASS
    db_name = DB_NAME
    db_host = DB_HOST

    # Extract host and port from db_host
    host_args = db_host.split(":")
    db_hostname, db_port = host_args[0], int(host_args[1])

    pool = sqlalchemy.create_engine(
        # Equivalent URL:
        # mysql+pymysql://<db_user>:<db_pass>@<db_host>:<db_port>/<db_name>
        sqlalchemy.engine.url.URL(
            drivername="mysql+pymysql",
            username=db_user,  # e.g. "my-database-user"
            password=db_pass,  # e.g. "my-database-password"
            host=db_hostname,  # e.g. "127.0.0.1"
            port=db_port,  # e.g. 3306
            database=db_name,  # e.g. "my-database-name"
        ),
        # ... Specify additional properties here.
        # [END cloud_sql_mysql_sqlalchemy_create_tcp]
        **db_config
        # [START cloud_sql_mysql_sqlalchemy_create_tcp]
    )
    # [END cloud_sql_mysql_sqlalchemy_create_tcp]

    return pool


def init_unix_connection_engine(db_config):
    # [START cloud_sql_mysql_sqlalchemy_create_socket]
    # Remember - storing secrets in plaintext is potentially unsafe. Consider using
    # something like https://cloud.google.com/secret-manager/docs/overview to help keep
    # secrets secret.
    db_user = DB_USER
    db_pass = DB_PASS
    db_name = DB_NAME
    db_socket_dir = os.environ.get("DB_SOCKET_DIR", "/cloudsql")
    cloud_sql_connection_name = 'riset-ml:asia-southeast2:dokuin'

    pool = sqlalchemy.create_engine(
        # Equivalent URL:
        # mysql+pymysql://<db_user>:<db_pass>@/<db_name>?unix_socket=<socket_path>/<cloud_sql_instance_name>
        sqlalchemy.engine.url.URL(
            drivername="mysql+pymysql",
            username=db_user,  # e.g. "my-database-user"
            password=db_pass,  # e.g. "my-database-password"
            database=db_name,  # e.g. "my-database-name"
            query={
                "unix_socket": "{}/{}".format(
                    db_socket_dir,  # e.g. "/cloudsql"
                    cloud_sql_connection_name)  # i.e "<PROJECT-NAME>:<INSTANCE-REGION>:<INSTANCE-NAME>"
            }
        ),
        # ... Specify additional properties here.

        # [END cloud_sql_mysql_sqlalchemy_create_socket]
        **db_config
        # [START cloud_sql_mysql_sqlalchemy_create_socket]
    )
    # [END cloud_sql_mysql_sqlalchemy_create_socket]

    return pool


db = init_connection_engine()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/file-upload', methods=['POST'])
def upload_file():
    data = request.data
    # check if the post request has the file part
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file(file.filename):
        filename = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32)) + str(time.time()) + ".pdf"
        savedPath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        exported = os.path.join(app.config['EXPORTED_FOLDER'], filename + ".json")
        exportedPath = os.path.join(app.config['EXPORTED_FOLDER'], filename)
        file.save(savedPath)

        fields = dict()
        document_type = request.form['document_type']
        if document_type == 'invoice':
            fields = parse_invoice(savedPath, exported, exportedPath)
        elif document_type == 'id_card':
            fields = parse_id_card(savedPath, exported, exportedPath)
        fields['filename'] = filename
        resp = jsonify({'message': 'File successfully uploaded', 'success': True, 'data': fields})
        resp.status_code = 201
        return resp
    else:
        resp = jsonify({'message': 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'})
        resp.status_code = 400
        return resp


def parse_id_card(saved_path, exported, exported_path):
    img = convert_from_path(saved_path)
    pytesseract.pytesseract.tesseract_cmd = app.config['TESSERACT_EXECUTABLE']
    text = pytesseract.image_to_string(img[0])
    field_results = dict()
    for i, line in enumerate(text.splitlines()):
        word_list = word_tokenize(line)
        if len(word_list) > 2:
            is_field_name = False
            is_field_value = False
            field_name = ""
            field_value = ""
            for j in range(len(word_list)):
                if j == 0:
                    is_field_name = True
                    is_field_value = False
                if word_list[j] == ':':
                    is_field_name = False
                    is_field_value = True
                if word_list[j] != ':':
                    if not word_list[j].isalpha():
                        if is_field_name:
                            field_name += word_list[j]
                        if is_field_value:
                            field_value += word_list[j]
                    else:
                        if is_field_name:
                            field_name += " " + word_list[j]
                        if is_field_value:
                            field_value += " " + word_list[j]
                if j == len(word_list) - 1:
                    field_results[field_name[1:]] = field_value[1:]
                    is_field_name = False
                    is_field_value = False
                    field_name = ""
                    field_value = ""
    return field_results


def parse_invoice(saved_path, exported, exported_path):
    img = convert_from_path(saved_path)
    pytesseract.pytesseract.tesseract_cmd = app.config['TESSERACT_EXECUTABLE']
    text = pytesseract.image_to_string(img[0])
    field_results = dict()
    table = camelot.read_pdf(saved_path)
    table.export(exported, f='json', compress=False)
    for i, line in enumerate(text.splitlines()):
        word_list = word_tokenize(line)
        if len(word_list) > 1:
            is_field_name = False
            field_name = ""
            is_field_value = False
            field_value = ""
            for j in range(len(word_list)):
                val = word_list[j]
                if val == "[":
                    is_field_value = False
                    is_field_name = True
                if val == "]":
                    is_field_value = True
                    is_field_name = False
                if is_field_name and (val != "[" and val != "]"):
                    if not val.isalpha():
                        field_name += val
                    else:
                        field_name += " " + val
                if is_field_value and (val != "]" and val != "["):
                    if not val.isalpha():
                        field_value += val
                    else:
                        field_value += " " + val
                if (val == "[" and j > 1) or j == len(word_list) - 1:
                    field_results[field_name[1:]] = field_value[1:]
                    field_name = ""
                    field_value = ""
    del field_results['']

    uploaded_json = open(exported_path + "-page-1-table-1.json")

    field_results['items'] = json.load(uploaded_json)

    uploaded_json.close()
    return field_results


def get_by_filenam(filename):
    import requests

    headers = {
        'Accept': 'application/json',
    }

    response = requests.get(
        'http://35.226.165.155:3000/api/Document/'+filename,
        headers=headers)
    return json.loads(response.content)


@app.route('/<filename>/save', methods=['POST'])
def save_file(filename):
    file_name = filename
    file_data = request.form['document_data']
    # file_title = request.form['title']

    dec = decrypt_data(request.form['token'].encode('utf-8'))

    user = json.loads(dec)

    fields = json.loads(request.form['document_data'])
    savedPath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    exported = os.path.join(app.config['EXPORTED_FOLDER'], filename + ".json")
    exportedPath = os.path.join(app.config['EXPORTED_FOLDER'], filename)

    with open(savedPath, 'rb') as file_to_check:
        file_content = file_to_check.read()
        md5_checksum = hashlib.md5(file_content).hexdigest()

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }

    data = {
        "$class": "org.example.Document",
        "fileName": file_name,
        "fileChecksum": md5_checksum,
        "fileData": file_data,
        "signatureFile": "null",
        "owner": "resource:org.example.User#" + user['email']
    }

    response = requests.post('http://35.226.165.155:3000/api/Document', headers=headers, data=json.dumps(data))

    # fields = parse_invoice(savedPath, exported, exportedPath)

    resp = jsonify({'message': 'Data uploaded successfully', 'success': True, 'data': response.status_code})
    resp.status_code = 200
    return resp


@app.route('/auth/login', methods=['POST'])
def all_users():
    email = request.form["email"]
    password = request.form["password"]

    with db.connect() as conn:
        user = conn.execute("SELECT * FROM user WHERE email = '" + email + "'").fetchone()
        if user[1] == password:
            login_user = {"email": user[0], "password": user[1], "firstName": user[2], "lastName": user[3]}
            enc = encrypt_data(json.dumps(login_user))
            resp = jsonify({'message': 'Logged In Succesfully!', 'success': True, 'data': enc})
            resp.status_code = 200
            return resp
        else:
            resp = jsonify({'message': 'Invalid login credentials', 'success': False, 'data': user[1]})
            resp.status_code = 400
            return resp


@app.route('/my-file')
def my_file():
    import requests

    headers = {
        'Accept': 'application/json',
    }

    response = requests.get('http://35.226.165.155:3000/api/Document', headers=headers)
    print(response.content)
    if response.status_code == 200:
        resp = jsonify({'message': 'Data retrieved', 'success': True, 'data': response.content.decode('utf-8')})
        resp.status_code = 200
        return resp
    else:
        resp = jsonify({'message': 'Error happens', 'success': False, 'data': None})
        resp.status_code = 400
        return resp


def file_open(file):
    key_file = open(file, 'rb')
    key_data = key_file.read()
    key_file.close()
    return key_data


def stamp_pdf(filename):
    savedPath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    output_path = os.path.join(app.config['GENERATED_FOLDER'], filename)

    packet = io.BytesIO()
    # create a new PDF with Reportlab
    can = canvas.Canvas(packet, pagesize=letter)
    can.drawString(10, 100, "[ID: " + filename + "]")
    can.save()

    # move to the beginning of the StringIO buffer
    packet.seek(0)
    new_pdf = PdfFileReader(packet)
    # read your existing PDF
    existing_pdf = PdfFileReader(open(savedPath, "rb"))
    output = PdfFileWriter()
    # add the "watermark" (which is the new pdf) on the existing page
    page = existing_pdf.getPage(0)
    page.mergePage(new_pdf.getPage(0))
    output.addPage(page)
    # finally, write "output" to a real file
    outputStream = open(output_path, "wb")
    output.write(outputStream)
    outputStream.close()
    return output_path


@app.route('/<filename>/signature', methods=['POST'])
def request_signature(filename):
    try:
        datas = get_by_filenam(filename)
        user = decrypt_data(request.form['token'].encode('utf-8'))

        user = json.loads(user)

        saved_path = stamp_pdf(filename)
        privkey = rsa.PrivateKey.load_pkcs1(file_open('privatekey.key'))

        # Open the secret message file and return data to variable
        data = file_open(saved_path)
        hash_value = rsa.compute_hash(data, 'SHA-512')  # optional

        # Sign the message with the owners private key
        signature = rsa.sign(data, privkey, 'SHA-512')

        sign_name = filename + '-signature'
        signature_file = os.path.join(app.config['SIGN_FOLDER'], sign_name)

        s = open(signature_file, 'wb')
        s.write(signature)
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        datass = {"$class": "org.example.Document", "fileName": filename, "fileChecksum": datas['fileChecksum'],
                  "fileData": datas['fileData'],
                  "signatureFile": sign_name, "owner": 'resource:org.example.User#' + user['email']}

        response = requests.put('http://35.226.165.155:3000/api/Document/' + filename, headers=headers,
                                data=json.dumps(datass))
        print(response.content)
        resp = jsonify({'message': 'Signature created successfully', 'success': True, 'data': None})
        resp.status_code = 200
        return resp
    except:
        resp = jsonify({'message': 'Error happens', 'success': False, 'data': None})
        resp.status_code = 400
        return resp


@app.route('/<filename>/info')
def get_data_by_filename(filename):
    data = get_by_filenam(filename)

    resp = jsonify({'message': 'Data retrieved', 'success': True, 'data': data})
    resp.status_code = 200
    return resp


@app.route('/<filename>/generate/signature')
def generate_sign(filename):
    generated = os.path.join(app.config['GENERATED_FOLDER'], filename)
    response = make_response(open(generated, 'rb').read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = \
        'inline; filename=%s.pdf' % filename
    return response


@app.route('/<filename>/generate/original')
def generate_original(filename):
    generated = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    response = make_response(open(generated, 'rb').read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = \
        'inline; filename=%s.pdf' % filename
    return response


@app.route('/<filename>/verify', methods=['POST'])
def verify_signature(filename):
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    sign_file = filename + '-signature'
    sign_file_path = os.path.join(app.config['SIGN_FOLDER'], sign_file)

    # Open public key file and load in key
    pubkey = rsa.PublicKey.load_pkcs1(file_open('publickey.key'))

    message = file.read()
    signature = file_open(sign_file_path)

    # Verify the signature to show if successful or failed
    try:
        rsa.verify(message, signature, pubkey)
        resp = jsonify({'message': 'Signature Verified', 'success': True, 'data': None})
        resp.status_code = 200
        return resp
    except:
        resp = jsonify({'message': 'Signature Not Verified', 'success': False, 'data': None})
        resp.status_code = 400
        return resp


if __name__ == "__main__":
    app.run()
