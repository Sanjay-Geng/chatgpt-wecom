import requests
import json
from wxlib.WXBizMsgCrypt import WXBizMsgCrypt  # 导入 企业微信WXBizMsgCrypt 类 https://github.com/sbzhu/weworkapi_python/tree/master/callback
import xml.etree.ElementTree as ET
import openai
import threading
import time
from flask import Flask, request
import yaml


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

    def send_message_to_user(self, user_id, message):
        url = self.WX_API_URL + 'message/send'
        token = self.get_access_token()
        headers = {'content-type': 'application/json'}
        data = {
            'touser': user_id,
            'msgtype': 'text',
            'agentid': self.AGENT_ID,
            'text': {
                'content': message
            },
            'safe': '0'
        }
        print("[chatgpt -> wecom] " + user_id + " reply: " + message, flush=True)
        resp = requests.post(url, headers=headers, params={
                             'access_token': token}, data=json.dumps(data))
        return resp.text

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

        #print(userid, self.user_info[userid])
        #print(self.OPENAI_KEY_WORKERS)
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
        self.slb = slb
        self.wecom = wecom
        self.message_log = [
            {"role": "system", "content": "You are a helpful assistant."}
        ]

    # 重置msg
    def reset_msg(self):
        self.message_log = [
            {"role": "system", "content": "You are a helpful assistant."}
        ]

    # ChatGPT API调用
    def send_message_to_gpt(self):
        url_and_key = self.slb.get_url_and_key(self.userid)
        openai.api_key = url_and_key['k']
        openai.api_base = url_and_key['w']
        try:
            # Use OpenAI's ChatCompletion API to get the chatbot's response
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=self.message_log,
                stop=None,
                temperature=0.7,
            )
        except openai.error.InvalidRequestError as error:
            # Handle the "invalid request" error
            if "This model's maximum context length" in str(error):
                self.reset_msg()
                return "当前聊天记录太长, 已重置对话, 请重新开始提问"
            else:
                print("An error occurred:", error)
                return "openai 未知错误"
        except Exception as error:
            # Handle any other exceptions
            print("An error occurred:", error)
            return "发生未知错误, 请稍后重试, 或输入clear后, 重新提问"

        # Find the first response from the chatbot that has text in it (some responses may not have text
        for choice in response.choices:
            if "text" in choice:
                 return choice.text
        return response.choices[0].message.content

    # 企业微信回调函数
    def callback(self, question_str):
        self.message_log.append({"role": "user", "content": question_str})
        response_text = self.send_message_to_gpt()
        self.message_log.append({"role": "assistant", "content": response_text})
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