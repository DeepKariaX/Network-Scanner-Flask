from flask import Flask, render_template, request, redirect, url_for, flash
import os
from datetime import date, datetime
import ipaddress
import sys
import validators
import socket
import urllib.parse
import nmap
try:
    import re2 as re
except ImportError:
    import re



app = Flask(__name__)

@app.route("/",methods=['POST','GET'])
def home():
	error = ''
	return render_template("main/index.html",err = error)


@app.route("/scan_home",methods=['POST','GET'])
def scan_home():
	cat=''
	global ip_url
	global port_select
	global p_range
	p_range = ''
	ip_url = ''
	error = ''
	port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
	if (request.method == 'POST'):
		cat = request.form.get('cat')
		ip_url = request.form.get('ip_url')
		p_range = request.form.get('port_range')
		port_select = request.form.get('port_select')
					
		if cat == 'ip':
			try:
				ip = ipaddress.ip_address(ip_url)
				if(port_range_pattern.search(p_range.replace(" ",""))):
					return redirect(url_for('page2'))
				else:
					error = 'Invalid Port Range'
			except ValueError:
				error = 'IP Address Invalid'
			except:
				error = 'error'

			

		elif cat == 'url':
			if validators.url(ip_url) == True:				
				try:
					o = urllib.parse.urlsplit(ip_url)
					if (o.scheme=='https'):
						new_url=ip_url.replace('https://','')
					elif (o.scheme=='http'):
						new_url=ip_url.replace('http://','')
					ip_url = socket.gethostbyname(new_url)
					
					if(port_range_pattern.search(p_range.replace(" ",""))):
						return redirect(url_for('page2'))
					else:
						error = 'Invalid Port Range'
				except (UnboundLocalError, socket.gaierror):
					sys.exit()			
			else:
				error = 'Invalid URL'

		else:

			error = 'Invalid Input'


	return render_template("scan/index.html",err = error)


@app.route("/page2", methods=['GET', 'POST'])
def page2():
	global ip_url
	global port_select
	global p_range
	open_port=[]
	state=[]
	service=[]
	product=[]
	error = ''

	try:

		if(port_select=='open_pt'):
			nmScan = nmap.PortScanner()
			nmScan.scan(ip_url, p_range)

			for host in nmScan.all_hosts():
				hos=nmScan[host].hostname()
				working=nmScan[host].state()

				for protocol in nmScan[host].all_protocols():
					Protocol = protocol
					ports = nmScan[host][protocol].keys()
					sorted(ports)
					for port in ports:
						if(nmScan[host][protocol][port]['state']=='open'):
							open_ports=port
							open_port.append(open_ports)

							states=nmScan[host][protocol][port]['state']
							state.append(states)

							services=nmScan[host][protocol][port]['name']
							service.append(services)

							products=nmScan[host][protocol][port]['product']
							product.append(products)



		elif(port_select=='filt_pt'):
			nmScan = nmap.PortScanner()
			nmScan.scan(ip_url, p_range)

			for host in nmScan.all_hosts():
				hos=nmScan[host].hostname()
				working=nmScan[host].state()

				for protocol in nmScan[host].all_protocols():
					Protocol = protocol
					ports = nmScan[host][protocol].keys()
					sorted(ports)
					for port in ports:
						if(nmScan[host][protocol][port]['state']=='filtered'):
							open_ports=port
							open_port.append(open_ports)

							states=nmScan[host][protocol][port]['state']
							state.append(states)

							services=nmScan[host][protocol][port]['name']
							service.append(services)

							products=nmScan[host][protocol][port]['product']
							product.append(products)
		
		return render_template("scan/page_2.html",i_u = ip_url,op_pt=open_port,sta=state,serv=service,prot=Protocol,host_nm=hos,work=working,prod=product) 
    

	except Exception as e:
		error = 'IP Address OR URL Not Scannable Try Another IP OR Website'
		return render_template("scan/index.html",err = error)
		return redirect(url_for('scan_home'))



app.run(debug=True)
