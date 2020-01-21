from flask import Flask, request 
import csv
import threading
import os

app = Flask(__name__) 

@app.route('/ISE', methods=['POST'])
def ise_post():
    
    content = request.get_json()
    dict_data = content["result"]
    csv_file = "ise.csv"

    with open(csv_file, 'r+b') as f:
        header = next(csv.reader(f))
        dict_writer = csv.DictWriter(f, header, -999)
        dict_writer.writerow(dict_data)

    return content
    

@app.route('/PF', methods=['POST'])
def pf_post():

    content = request.get_json()
    dict_data = content["result"]
    csv_file = "pf.csv"

    with open(csv_file, 'r+b') as f:
        header = next(csv.reader(f))
        dict_writer = csv.DictWriter(f, header, -999)
        dict_writer.writerow(dict_data)

    return content


@app.route('/PA', methods=['POST'])
def pa_post():
    content = request.get_json()
    dict_data = content["result"]
    csv_file = "pa.csv"

    with open(csv_file, 'r+b') as f:
        header = next(csv.reader(f))
        dict_writer = csv.DictWriter(f, header, -999)
        dict_writer.writerow(dict_data)

    return content



def score():
  threading.Timer(60.0, score).start()
  os.system("python pa_grouping_formatting.py")
  os.system("python pf_grouping_formatting.py")
  os.system("python ise_grouping_formatting.py")

score()


app.run(debug=True, port=5000) 