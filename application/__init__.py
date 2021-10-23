from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def hello_world():
    name = {}
    return render_template('init.html', name=name)