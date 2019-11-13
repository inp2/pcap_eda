import os
from multiprocessing import Process
import pandas as pd
import urllib.request
from app import app
from flask import Flask, flash, request, redirect, render_template
from werkzeug.utils import secure_filename
import matplotlib.pyplot as plt
import seaborn as sns

ALLOWED_EXTENSIONS = set(['pcap'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def pcap_parser(filename):
	os.system("tshark -r uploads/" + filename + " -T fields -e frame.number -e frame.time -e eth.src -e eth.dst -e ip.src -e ip.dst -e ip.proto -E header=y -E separator=, -E quote=d -E occurrence=f > dataset/" + filename + ".csv")
	df = pd.read_csv('dataset/' + filename + '.csv')
	return df

def viz(df):
	ax = df['eth.src'].value_counts().nlargest(10).plot.bar(x='Eth Src', y='Value', rot=45)
	fig = ax.get_figure()
	fig.savefig('static/images/eth_src.png')
        ax1 = df['eth.dst'].value_counts().nlargest(10).plot.bar(x='Eth Dst', y='Value', rot=45)
        fig = ax1.get_figure()
        fig.savefig('static/images/eth_dst.png')
		    
@app.route('/')
def upload_form():
	return render_template('upload.html')

@app.route('/', methods=['POST'])
def upload_file():
	if request.method == 'POST':
	# check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		if file.filename == '':
			flash('No file selected for uploading')
			return redirect(request.url)
		if file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			flash('File: ' + filename + ' successfully uploaded')
			df = pcap_parser(filename)
			p = Process(target=viz, args=(df))
			p.start()
			p.join()
			return render_template('viz.html', name='Frequency of Ethernet Src', url='static/images/eth_src.png', name1='Frequency of Ethernet Dst', url1='static/images/eth_dst.png')
		else:
			flash('Allowed file types are pcap')
			return redirect(request.url)

if __name__ == "__main__":
    app.run()
