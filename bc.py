import json
import hashlib
from time import time
import sys
import socket
import random
import binascii

def jsonDumper(block):
    sorted_block="{"
    sorted_keys=sorted(block.keys())
    for key in sorted_keys:
      if(key=="trxs"):
        print("!!")
        print(type(block[key]))
      if type(block[key])==str:
        sorted_block+="\""+key+"\": \""+block[key]+"\", "
      elif type(block[key])==int or type(block[key])==float :
        sorted_block+="\""+key+"\": "+str(block[key])+", "
      elif type(block[key])==list:
        sorted_block+="\""+key+"\": ["    
        for i in block[key][:-1]:
          sorted_block+=jsonDumper(i)+", "
        if len(block[key])>0:
          sorted_block+=jsonDumper(block[key][-1])
        sorted_block+="], "
      else:
        print("|||||||||||||||||||")
        print(type(block[key]))
    sorted_block=sorted_block[:-2]+"}"
    return sorted_block

  
def urlparse(ali):
    res={}
    res['scheme']=ali[:ali.find("://")]
    nex_=ali.find("/",ali.find("/")+2)
    if nex_==-1:
      res['netloc']=ali[ali.find("://")+3:] 
      res['path']="" 
    else:
      res['netloc']=ali[ali.find("://")+3:nex_] 
      res['path']=ali[nex_:] 
    return res

try:
    import os
    OS_TYPE=os.uname()[0]
except:
    import platform
    OS_TYPE=platform.uname()[0]
if(OS_TYPE=="Linux" or OS_TYPE=="Windows"):
    from urllib.parse import urlparse
    from flask import Flask,jsonify,request
    import ifaddr
    from uuid import uuid4
    import requests
    from uuid import getnode as get_mac 
elif(OS_TYPE=="esp32"):
    import picoweb
    import machine
    import network
    import urequests as requests
else:
    print("not supported!!")

def hexShow(input):
  if(input>9):
    return chr(input+87)
  else:
    return chr(input+48)


def getIps():
    res={}
    if(OS_TYPE=="esp32"):
      res["ap"]=ap.ifconfig()[0]
      res["mynet"]=mynet.ifconfig()[0]
      res["lo"]="127.0.0.1"
    else:
      adapters = ifaddr.get_adapters()
      for adapter in adapters:
        i=0
        for ip in adapter.ips:
          res[adapter.nice_name+str(i)]=ip.ip  
          i+=1  
    return res


class Blockchain():
    ''' defines a block chain on one machine'''
    def __init__(self):
      self.chain=[]
      self.current_trxs=[]
      self.node=set()
      self.new_block(previous_hash=1,proof=100)

    def new_block(self,proof,previous_hash=None):
      ''' create a new block'''
      block={
              'index':len(self.chain)+1,
              'timestamp':int(time()),
              'trxs':self.current_trxs,
              'proof': proof,
              'previous_hash': previous_hash or self.hash(self.chain[-1]),

      }
      self.current_trxs=[]
      self.chain.append(block)

      return block

    def new_trx(self,sender,recipient,amount):
      ''' add a new trx to the mempool'''
      self.current_trxs.append({'sender':sender,'recipient':recipient,
          'amount':amount,"trx_time":int(time())})
      return self.last_block['index']+1

    @staticmethod
    def hash(block):
      '''hash a block'''
      try:
        block_string= json.dumps(block,sort_keys=True).encode()
      except:
        block_string=jsonDumper(block)
      #print(block_string)
      res=""
      try:
        res=hashlib.sha256(block_string).hexdigest().decode()
      except:
        res=binascii.hexlify(hashlib.sha256(block_string).digest()).decode()
      return res

    def register_node(self,address):
      parsedURL=urlparse(address)
      try:
        self.node.add(parsedURL.netloc)
      except:
        self.node.add(parsedURL['netloc'])

    def valid_chain(self,chain):
      ''' check if chain is valid'''
      last_block=chain[0]
      current_index=1
      while current_index <len(chain):
        block=chain[current_index]
        if block['previous_hash'] != self.hash(last_block):
          print("!!")
          return False
        if not self.valid_proof(block,block['proof']):
          print("##")
          print(block)
          print(self.hash(block))
          return False
        
        last_block=block
        current_index+= 1
      return True

    def resolveConflicts(self):
      '''checks best chain'''
      neighbours=self.node
      new_chain=None
      max_length=len(self.chain)
      for node in neighbours:
        print(node)
        try:
          response=requests.get('http://{}/chain'.format(node))
          if response.status_code ==200:
            length= response.json()['length']
            chain=response.json()['chain']
            if length>max_length and self.valid_chain(chain):
              max_length=length
              new_chain=chain
        except:
          print("!error: node {} is unreachable!".format(node))

      if new_chain:
        self.chain = new_chain
        return True

      return False
    
    def setBlockProof(self, index,proof):
      self.chain[index]['proof']=proof

    @property
    def last_block(self):
      '''return last block'''
      return self.chain[-1]

    @staticmethod
    def valid_proof(block,proof):
      '''checks wheter nonce is as expected'''
      blockUT=block
      blockUT['proof']=proof
      #this_proof = "{}{}".format(proof,last_proof).encode()
      #try:
      #    this_proof_hash=hashlib.sha256(this_proof).hexdigest()
      #except:
      #    this_proof_hash = binascii.hexlify(hashlib.sha256(this_proof).digest()).decode()
      hashVal=Blockchain.hash(blockUT)
      return hashVal[:2]=='00'
      
    def proof_of_work(self,block):
      ''' shows the pow'''
      proof=0
      while self.valid_proof(block,proof) is False:
        proof +=1

      return proof
if(OS_TYPE=="Linux" or OS_TYPE=="Windows"):
    app = Flask(__name__)
else:
    app = picoweb.WebApp(__name__)

#node_id = str(uuid4())
try:
    mac_int=get_mac()
except:
    mac_ar=network.WLAN().config('mac')
    mac = binascii.hexlify(mac_ar,':').decode()
    mac_int=0
    for i in mac_ar[:-1]:
        mac_int+=i
        mac_int*=256
    mac_int+=mac_ar[-1]
random.seed(mac_int)
node_id =""
for i in range(32):
    node_id+=hexShow(random.getrandbits(4))
    if i==7 or i==11 or i == 15 or i== 19:
      node_id+="-"
#node_id=binascii.hexlify(node_id).decode()
print("node_id is: %s" % node_id)

blockchain = Blockchain()

if(OS_TYPE!="esp32"):
    @app.route('/mine')
    def mineHandler():
      res,code=mine()
      return jsonify(res),code
    @app.route('/trxs/new',methods=['POST'])
    def new_trxHandler():
      values=request.get_json()
      res,code= new_trx(values)
      return jsonify(res),code
    @app.route('/chain')
    def full_cahinHandler():
      res,code= full_cahin()
      return jsonify(res),code

    @app.route('/nodes/register',methods=['POST'])
    def register_nodeHanler():
      values=request.get_json()
      res,code=register_node(values)
      return jsonify(res),code

    @app.route('/nodes/resolve')
    def consensusHandler():
      res,code = consensus()
      return jsonify(res),code
else:
    @app.route('/mine')
    def mineHandler(req,resp):
      res,code=mine()
      yield from picoweb.jsonify(resp,res)

    @app.route('/trxs/new')
    def new_trxHandler(req,resp):
      if req.method!= "POST":
        req.parse_qs()
        yield from picoweb.http_error(resp, "500")
      else:
        yield from req.read_form_data()
        dt=""
        for i in req.form:
          dt+=str(i)
        values=json.loads(dt)
        res,code=new_trx(values)
        yield from picoweb.jsonify(resp,res)
    
    @app.route('/chain')
    def full_cahinHandler(req,resp):
      res,code=full_cahin()
      yield from picoweb.jsonify(resp,res)

    @app.route('/nodes/register')
    def register_nodeHanler(req,resp):
      if req.method!= "POST":
        req.parse_qs()
        yield from picoweb.http_error(resp, "500")
      else:
        yield from req.read_form_data()
        dt=""
        for i in req.form:
            dt+=str(i)
        values=json.loads(dt)
        res,code=register_node(values)
        yield from picoweb.jsonify(resp,res)

    @app.route('/nodes/resolve')
    def consensusHandler(req,resp):
      res,code=consensus()
      yield from picoweb.jsonify(resp,res)


def mine():
  ''' this will mine and add to the chain'''
  last_block=blockchain.last_block
  #last_proof=last_block['proof']
  index=blockchain.new_trx(sender="0",recipient=node_id,amount=50)
  proof=0
  previous_hash=blockchain.hash(last_block)
  block=blockchain.new_block(proof,previous_hash)

  proof=blockchain.proof_of_work(block)
  blockchain.setBlockProof(index-1, proof)
  
  res={
    "messege":"new block created",
    "index":block['index'],
    "trxs": block['trxs'],
    "proof":block['proof'],
    "previous_hash":block['previous_hash']
  }
  return res,200

def new_trx(values):
    '''add a new trx'''
    this_blockIndx = blockchain.new_trx(values['sender'],values['recipient'],values['amount'])
    res={
        'messege'  : 'will be added to block {}'.format(this_blockIndx)
    }
    return  res,201

def full_cahin():
    ''' get full chain'''
    res={
            'chain': blockchain.chain,
            'length':len(blockchain.chain),
    }
    return res, 200

def register_node(values):
    '''register new node to blockchain network'''
    nodes=values.get('nodes')
    myaddrs=[]
    ips=getIps()
    for ip in ips:
      global port
      myaddrs.append("http://"+str(ips[ip])+":"+str(port))
    for node in nodes:
      node=node.replace("localhost","127.0.0.1")
      duplicate=0
      for ip in myaddrs:
        if(node==ip):
          duplicate=1
      if not duplicate:
        blockchain.register_node(node)
        print("%s added!" % node)
      else:
        print("duplicate ip address!")

    res={
        "messege":"node added!",
        "total nodes:":list(blockchain.node)
    }
    return res,201


def consensus():
    '''decide to use wich block chain'''
    replaced=blockchain.resolveConflicts()
    if replaced:
      res={
          "messeges": "replaced!"
          ,"new chain": blockchain.chain
      }
    else:
      res={
          "messeges": "I'm the best"
          ,"chain": blockchain.chain
      }
    return res,200

if __name__ == "__main__":
    global port
    port =80
    if len(sys.argv)>1:
        port=int(sys.argv[1])
    print("available addresses:")
    ips=getIps()
    for i in ips:
        if type(ips[i])==str:
            print(ips[i]+":"+str(port))
    if(OS_TYPE=="esp32"):
      try:
        app.run(debug=True, host = "0.0.0.0",port=port)
      except:
        gc.collect()
        machine.soft_reset()
      finally:
        print("bye!")
    else:
      app.run(host="0.0.0.0", port=port)
    
    