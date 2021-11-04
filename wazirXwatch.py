from collections import defaultdict
from tabulate import tabulate
import requests
import hmac
import hashlib
import time
import binascii
import logging

price_url = 'https://x.wazirx.com/wazirx-falcon/api/v2.0/crypto_rates'
orders_url = "https://x.wazirx.com//api/v3/orders?limit=50&order_by=desc&states[]=cancel&states[]=done"

access_key = "xxx"
secret_key = "xxx"
api_key = "xxx"

cost_metric = 'inr'


def getTonce():
	return int(time.time()*1000)
	# return 1622877060198

def hmacSha256(key, msg):
	signature = hmac.new(bytes(key , 'latin-1'), msg = bytes(msg , 'latin-1'), digestmod = hashlib.sha256).hexdigest().lower()
	return str(signature)

def formatSignature(httpMethod, accessKey, tonce, requestUrl):
	return "{0}|access-key={1}&tonce={2}|{3}".format(httpMethod, accessKey, tonce, requestUrl)
	# return 'GET|access-key=DGw0lIm6IoUG8ezT4Erm7wKRkMRT2FrXrIjseueKkSCjlw&tonce='+str(tonce)+'|/api/v3/orders|limit=50&order_by=desc&states[]=cancel&states[]=done'
	

def getSignature(httpMethod, accessKey, tonce, requestUrl, secretKey):
	signatureText = formatSignature(httpMethod, accessKey, tonce, requestUrl)
	# print(signatureText)
	return hmacSha256(secretKey, signatureText)

def getHoldings(data, holdings):
	result = {key:data.get(key) for key in holdings}
	return result

def formatCryptoValue(data):
	values = {}
	for key, value in data.items():
		values[key] = value.get(cost_metric)
	return values


def getCurrentPrices(holdings):
	session = requests.Session()
	session.headers.update({'api-key': api_key})
	response = session.get(price_url)
	if (response.status_code == 200):
		data = response.json()
		holdingsData = getHoldings(data, holdings)
		return formatCryptoValue(holdingsData)
	else:
	    print("Result not found!")

def getOrdersMap(data):
	ordersMap = defaultdict(list)
	for item in data:
		ordersMap[item['market']].append(item)
	return ordersMap


def getOrderStats(orders, cryptoName):
	value = 0
	qty = 0
	for item in orders:
		if(item['state']!='done'):
			continue
		if(item['kind']=='bid'):
			value = value + float(item['origin_volume'])*float(item['avg_price'])
			qty = qty + float(item['origin_volume'])
			print (cryptoName+","+item['avg_price'])
		if(item['kind']=='ask'):
			value = value - float(item['origin_volume'])*float(item['avg_price'])
			qty = qty - float(item['origin_volume'])
			print ("**sold**"+cryptoName+","+item['avg_price'])

	if(qty == 0):
		return 
	currencyName = cryptoName[:-len(cost_metric)]
	currentPrice = float(getCurrentPrices([currencyName])[currencyName])
	avgPrice = float(value/qty)
	stats = {'name':cryptoName,'value' : value, 'quantity' : qty, 'avg_price' : avgPrice, 'current_price' : currentPrice, 'profit' : qty*(currentPrice - avgPrice)}
	return stats

def getOrders():
	session = requests.Session()
	tonce = getTonce()
	signature = getSignature("GET",access_key,tonce,'/api/v3/orders|limit=50&order_by=desc&states[]=cancel&states[]=done',secret_key)
	session.headers.update({'access-key': access_key, 'api-key' : api_key,'tonce' : str(tonce),'signature' : signature})
	response = session.get(orders_url)
	if (response.status_code == 200):
		data = response.json()
		ordersMap = getOrdersMap(data)
		stats = []
		tabulateArray = []
		for name, orders in ordersMap.items():
			stat = getOrderStats(orders, name)
			if stat is None:
				continue
			stats.append(stat)
			tabulateArray.append(stat.values())
		print(tabulate(tabulateArray, headers=['Crypto','Invested_'+cost_metric, 'Vol','Buy-Avg', 'Current-Price','Profit'],tablefmt='orgtbl'))


	else:
	    print(response.text)

getOrders()

