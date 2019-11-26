import os
from multiprocessing import Process
import pandas as pd
import urllib.request
from app import app
from flask import Flask, flash, request, redirect, render_template
from werkzeug.utils import secure_filename
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx

ALLOWED_EXTENSIONS = set(['pcap'])

def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def pcap_parser(filename):
        os.system("tshark -r uploads/" + filename + " -T fields -e frame.number -e frame.time -e eth.src -e eth.dst -e ip.src -e ip.dst -e ip.proto -E header=y -E separator=, -E quote=d -E occurrence=f > dataset/" + filename + ".csv")
        df = pd.read_csv('dataset/' + filename + '.csv')
        return df

def net_analy(df):
        eth_G = nx.from_pandas_edgelist(df, 'eth.src', 'eth.dst')
        eth_deg = eth_G.degree
        plt.bar(len(eth_deg), list(eth_deg.values()))
        plt.savefig('static/images/eth_deg.png')
        ip_G = nx.from_pandas_edgelist(df, 'ip.src', 'ip.dst')
        ip_deg = ip_G.degree
        plt.bar(len(ip_deg), list(ip_deg.values()))
        plt.savefig('static/images/ip_deg.png')
        
def viz(df):
        ax = df['eth.src'].value_counts().nlargest(10).plot.bar(x='Eth Src', y='Value', rot=0)
        fig = ax.get_figure()
        fig.savefig('static/images/eth_src.png')
        ax1 = df['eth.dst'].value_counts().nlargest(10).plot.bar(x='Eth Dst', y='Value', rot=0)
        fig = ax1.get_figure()
        fig.savefig('static/images/eth_dst.png')
        ax2 = df['ip.src'].value_counts().nlargest(10).plot.bar(x='IP Src', y='Value', rot=0)
        fig = ax2.get_figure()
        fig.savefig('static/images/ip_src.png')
        ax3= df['ip.dst'].value_counts().nlargest(10).plot.bar(x='IP Dst', y='Value', rot=0)
        fig = ax3.get_figure()
        fig.savefig('static/images/ip_dst.png')
        ax4 = df['ip.proto'].value_counts().nlargest(10).plot.bar(x='Protocol', y='Value', rot=0)
        fig = ax.get_figure()
        fig.savefig('static/images/protocol.png')
                    
@app.route('/')
def upload_form():
        return render_template('upload.html')

@app.route('/', methods=['POST', 'GET'])
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
                        # flash('File: ' + filename + ' successfully uploaded')
                        df = pcap_parser(filename)
                        net_analy(df)
                        # viz(df)
                        return render_template('viz.html', name='Frequency of Ethernet Src', url='static/images/eth_src.png', name1='Frequency of Ethernet Dst', url1='static/images/eth_dst.png', name2='Frequency of IP Src', url2='static/images/ip_src.png', name3='Frequency of IP Dst', url3='static/images/ip_dst.png', name4='Frequency of Protocols', url4='static/images/protocol.png')
                else:
                        flash('Allowed file types are pcap')
                        return redirect(request.url)

if __name__ == "__main__":
    app.run()
