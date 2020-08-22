from flask import Flask

app = Flask(__name__)

UPLOAD_FOLDER = 'D:\\uploads'
EXPORTED_FOLDER = 'D:\\exported'
SIGN_FOLDER = 'D:\\signed'
GENERATED_FOLDER = 'D:\\generated'

TESSERACT_EXECUTABLE = 'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'

app.secret_key = "r9VE1Hf6MqnHiwqxSaHM76GcwrWJnIdZ"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TESSERACT_EXECUTABLE'] = TESSERACT_EXECUTABLE
app.config['EXPORTED_FOLDER'] = EXPORTED_FOLDER
app.config['SIGN_FOLDER'] = SIGN_FOLDER
app.config['GENERATED_FOLDER'] = GENERATED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.route('/')
def hello_world():
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
