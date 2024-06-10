import requests
import json
from wxlib.WXBizMsgCrypt import WXBizMsgCrypt  # 导入 企业微信WXBizMsgCrypt 类 https://github.com/sbzhu/weworkapi_python/tree/master/callback
import xml.etree.ElementTree as ET
import threading
import time
from flask import Flask, request
import yaml
import google.generativeai as genai 
import re

ChatSetting = {
    'generation_config' : {
        "temperature": 0.7,
        "top_p": 1,
        "top_k": 1,
        "max_output_tokens": 2048,
    },
    'safety_settings' : {
        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
    }
}

class Wecom():
    def __init__(self, agentid, secret, corpid):
        self.AGENT_ID = agentid
        self.SECRET = secret
        self.CORP_ID = corpid
        self.WX_API_URL = 'https://qyapi.weixin.qq.com/cgi-bin/'
        self.access_token = ''
        self.token_expired_time = 0

    def get_access_token(self):
        timenow = int(time.time())
        if timenow < self.token_expired_time:
            return self.access_token

        self.token_expired_time = timenow + 300  # 5分钟
        url = self.WX_API_URL + 'gettoken'
        params = {
            'corpid': self.CORP_ID,
            'corpsecret': self.SECRET
        }
        resp = requests.get(url, params=params)
        self.access_token = json.loads(resp.text)['access_token']
        return self.access_token

    def split_string_by_lines(self,input_string, max_lines):
        lines = input_string.split('\n')
        result = []
        current_string = ''
        
        for i, line in enumerate(lines, start=1):
            current_string += line + '\n'
            if i % max_lines == 0:
                result.append(current_string.strip())
                current_string = ''
        
        # 添加最后不足150行的字符串
        if current_string:
            result.append(current_string.strip())
        
        return result

    def send_message_to_user(self, user_id, message):
        split_msgs = self.split_string_by_lines(message, 50)
        resp_sum = ''
        for msg in split_msgs:
            url = self.WX_API_URL + 'message/send'
            token = self.get_access_token()
            headers = {'content-type': 'application/json'}
            data = {
                'touser': user_id,
                'msgtype': 'text',
                'agentid': self.AGENT_ID,
                'text': {
                    'content': msg
                },
                'safe': '0'
            }
            print("[chatgpt -> wecom] " + user_id + " reply: " + message, flush=True)
            resp = requests.post(url, headers=headers, params={
                                'access_token': token}, data=json.dumps(data))
            resp_sum += resp.text
        return resp_sum

# api key, cloudflare worker负载均衡
class SLB():
    def __init__(self, chatconfig):
        # self.OPENAI_KEY_WORKERS = [
        #     # worker url and api key, used count
        #     {"cnt": 0, "w": "https://worker1.xxx.com/v1",
        #         "k": "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        #     {"cnt": 0, "w": "https://worker2.xxx.com/v1",
        #         "k": "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
        # ]
        self.OPENAI_KEY_WORKERS = []
        for v in chatconfig:
            cfg = {"cnt": 0, "w": v['worker'], "k": v['apikey']}
            self.OPENAI_KEY_WORKERS.append(cfg)

        self.user_info = {
            # "userxx" : {url_and_key, last_used_time}
        }

    def get_url_and_key(self, userid):
        if userid in self.user_info:
            self.user_info[userid]["used_time"] = int(time.time())
            return self.user_info[userid]["url_key"]

        # 记录
        self.OPENAI_KEY_WORKERS = sorted(
            self.OPENAI_KEY_WORKERS, key=lambda k: k["cnt"])
        self.OPENAI_KEY_WORKERS[0]['cnt'] += 1
        self.user_info[userid] = {
            "url_key": self.OPENAI_KEY_WORKERS[0], "used_time": int(time.time())}

        return self.user_info[userid]["url_key"]

    def timer(self, curSec):
        for key, value in list(self.user_info.items()):
            if value["used_time"] + 600 < curSec:
                self.user_info[key]['url_key']['cnt'] -= 1
                del self.user_info[key]
                print("key del:", key, " cnt new:", self.OPENAI_KEY_WORKERS)

class User():
    def __init__(self, userid, slb, wecom):
        self.userid = userid
        self.wait_expire = 0
        self.wecom = wecom
        self.url_and_key = slb.get_url_and_key(self.userid)
        genai.configure(api_key=self.url_and_key["k"])
        self.model = genai.GenerativeModel(
            'gemini-pro', generation_config=ChatSetting["generation_config"], safety_settings=ChatSetting["safety_settings"])
        self.reset_msg()

    # 重置msg
    def reset_msg(self):
        self.chat = self.model.start_chat(history=[])
        prompt = "Pretend you are an expert in the field of the question I am asking."
        self.send_message_to_gpt(prompt)

    # gemini API调用
    def send_message_to_gpt(self, question_str):
        try:
            #response = self.chat.send_message(question_str, stream=True)
            response = self.chat.send_message(question_str)
            response_text = ""
            for chunk in response:
                if chunk.text.endswith("."):
                    response_text += chunk.text
                else:
                    response_text += re.sub(r'\s*$', '.', chunk.text)
                print(chunk.text)
        except Exception as error:
            # Handle any other exceptions
            print("An error occurred:", error)
            return "发生未知错误, 请稍后重试, 或输入clear后, 重新提问"

        return response_text

    # 企业微信回调函数
    def callback(self, question_str):
        response_text = self.send_message_to_gpt(question_str)
        self.wecom.send_message_to_user(self.userid, response_text)

    def receive_message(self, content):
        if content.startswith('clear'):
            self.reset_msg()
            self.wecom.send_message_to_user(self.userid, "重置成功, 接下来你可以开始一段新的对话了!")
        else:
            ask_str = content
            callback_thread = threading.Thread(target=self.callback, args=(ask_str,))
            callback_thread.start()


class WechatCallback():
    def __init__(self):
        self.app = Flask(__name__)
        self.load_config()
        wecom_config = self.config['wecom']
        self.token = wecom_config['token']
        self.encoding_aes_key = wecom_config['aeskey']
        self.corp_id = wecom_config['corpid']
        self.url = self.config['web']['url']
        self.port = self.config['web']['port']

        agentid = wecom_config['agentid']
        secertid = wecom_config['secretid']
        self.wecom = Wecom(agentid,secertid, self.corp_id) 

        self.slb = SLB(self.config['gpt'])
        self.users = {}
    
    def load_config(self):
        with open('./config.yml') as f:
            self.config = yaml.safe_load(f)

    def recv_user_msg(self, userid, ask_str):
        if userid not in self.users:
            self.users[userid] = User(userid, self.slb, self.wecom)
        user = self.users[userid]
        user.receive_message(ask_str)

    def web_listen(self):
        @self.app.route(self.url, methods=['POST'])
        def receive_message():
            sReqMsgSig = request.args.get("msg_signature")
            sReqTimeStamp = request.args.get("timestamp")
            sReqNonce = request.args.get("nonce")
            sReqData = request.data
            # sReqData = web.data()
            if len(sReqData) == 0:
                return "hello, this is handle view"

            wxcpt=WXBizMsgCrypt(self.token, self.encoding_aes_key, self.corp_id)
            ret,sMsg=wxcpt.DecryptMsg(sReqData, sReqMsgSig, sReqTimeStamp, sReqNonce)
            if( ret!=0 ):
                print("ERR: DecryptMsg ret: " + str(ret))

            xml_tree = ET.fromstring(sMsg)
            FromUserName = xml_tree.find("FromUserName").text
            content =  xml_tree.find("Content").text
            question=str(content)
            wxuser=str(FromUserName)
            print("[wecom -> chatgpt] " + wxuser + " ask: " + question, flush=True)

            self.recv_user_msg(wxuser, question)
            return ''

        @self.app.route(self.url, methods=['GET'])
        def verify_url():
                # 从请求参数中获取相关信息
                query_params = request.args
                signature = query_params.get('msg_signature')
                timestamp = query_params.get('timestamp')
                nonce = query_params.get('nonce')
                echostr = query_params.get('echostr')

                wxcpt=WXBizMsgCrypt(self.token, self.encoding_aes_key, self.corp_id)
                ret,sEchoStr=wxcpt.VerifyURL(signature, timestamp,nonce,echostr)
                if(ret!=0):
                    print("ERR: VerifyURL ret: " + str(ret))
                else:
                    return sEchoStr

        self.app.run(host='0.0.0.0', port=self.port)

    def timer(self):
        while True:
            time.sleep(60)
            self.slb.timer(int(time.time()))

    def run(self):
        timer_thread = threading.Thread(target=self.timer)
        timer_thread.start()
        self.web_listen()

# 运行企业微信回调函数
if __name__ == '__main__':
    wxchat = WechatCallback()
    wxchat.run()