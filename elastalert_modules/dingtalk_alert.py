#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
from Github:https://github.com/xuyaoqiang/elastalert-dingtalk-plugin
@author: xuyaoqiang,lights8080
@contact: xuyaoqiang@gmail.com
@date: 2017-09-14 17:35,2021-06-23
@version: 0.0.0
@license:
@copyright:
"""
import json
import requests
from elastalert.alerts import Alerter, DateTimeEncoder
from requests.exceptions import RequestException
from elastalert.util import EAException
import sys
import io
import time
import datetime
import hmac
import hashlib
import base64
import urllib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

class DingTalkAlerter(Alerter):
    required_options = frozenset(['dingtalk_webhook', 'dingtalk_msgtype'])

    def __init__(self, rule):
        super(DingTalkAlerter, self).__init__(rule)
        self.dingtalk_webhook_url = self.rule['dingtalk_webhook']
        self.dingtalk_msgtype = self.rule.get('dingtalk_msgtype', 'text')
        self.dingtalk_isAtAll = self.rule.get('dingtalk_isAtAll', False)
        self.dingtalk_title = self.rule.get('dingtalk_title', '')
        self.dingtalk_atMobiles = self.rule.get('dingtalk_atMobiles', [])
        self.dingtalk_secret = self.rule.get('dingtalk_secret', '')

    def format_body(self, body):
        return body.encode('utf8')

    def alert(self, matches):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;charset=utf-8"
        }
        body = self.create_alert_body(matches)
        payload = {
            "msgtype": self.dingtalk_msgtype,
            "text": {
                "content": body
            },
            "at": {
                "isAtAll":False
            }
        }
        if len(self.dingtalk_atMobiles) > 0:
          payload["at"]["atMobiles"] = self.dingtalk_atMobiles

        url = self.dingtalk_webhook_url
        if len(self.dingtalk_secret) > 0:
            timestamp = round(time.time() * 1000)
            secret_enc = bytes(self.dingtalk_secret, encoding='utf8')
            string_to_sign = '{}\n{}'.format(timestamp, self.dingtalk_secret)
            string_to_sign_enc = bytes(string_to_sign, encoding='utf8')
            hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
            sign = urllib.parse.quote(base64.b64encode(hmac_code))
            url = '{}&timestamp={}&sign={}'.format(self.dingtalk_webhook_url, timestamp, sign)
        
        try:
            response = requests.post(url,
                        data=json.dumps(payload, cls=DateTimeEncoder),
                        headers=headers)
            response.raise_for_status()
            print(response)
        except RequestException as e:
            raise EAException("Error request to Dingtalk: {0}".format(str(e)))

    def get_info(self):
        return {
            "type": "dingtalk",
            "dingtalk_webhook": self.dingtalk_webhook_url
        }
        pass
