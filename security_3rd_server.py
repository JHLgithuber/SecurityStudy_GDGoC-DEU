import eventlet
eventlet.monkey_patch()  # 기존 네트워크 코드와 호환되도록 패치

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
import secrets
import json



app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(app)

# 연결된 클라이언트 세션 ID를 저장할 딕셔너리
connected_clients = {}

@socketio.on('connect')
def connect():
    # 클라이언트 연결 시 세션 ID 저장
    #TODO: 딕셔너리 키에러 해결해야함
    connected_clients[request.sid]= {
        "IP":request.remote_addr,  # 예: 현재 IP 저장
        "NAME":request.remote_addr}
    print(f"Client connected: SID={request.sid}, IP={request.remote_addr}")
    send_log(f"Client connected: SID={request.sid}, IP={request.remote_addr}")

# 클라이언트 연결 해제 이벤트
@socketio.on('disconnect')
def handle_disconnect(*args, **kwargs):
    print(f'Client connected: NAME={connected_clients[request.sid]["NAME"]}, SID={request.sid}, IP={request.remote_addr}, {args}, {kwargs}')
    send_log(f'Client connected: NAME={connected_clients[request.sid]["NAME"]}, SID={request.sid}, IP={request.remote_addr}')

@socketio.on('rename')
def handle_rename(data):
    print(f'Received rename request: NAME={data}, SID={request.sid}, IP={request.remote_addr}"')
    send_log(f'Received rename request: NAME={data}, SID={request.sid}, IP={request.remote_addr}"')
    connected_clients[request.sid]['NAME'] = data


def send_log(log_msg):
    socketio.emit("log",log_msg, room='logger_room')

@socketio.on('message_broadcast')
def handle_message_broadcast(msg):
    print(f'Received message broadcast: {msg}')
    send_log(f'Received message broadcast: {msg}')
    emit("message_broadcast",msg, broadcast=True, include_self=False)

@socketio.on('publickey_broadcast')
def handle_publickey_broadcast(msg):
    print(f'Received publickey broadcast: {msg}')
    send_log(f'Received publickey broadcast: {msg}')
    emit("publickey_broadcast",msg, broadcast=True, include_self=False)

ping_sender=None
@socketio.on('ping')
def ping_broadcast():
    global ping_sender
    ping_sender=request.sid
    emit("ping",broadcast=True)
@socketio.on('pong')
def pong_unicast():
    emit("pong",connected_clients[request.sid]['NAME'],requto=ping_sender)

@app.route('/log',methods=['GET'])
def show_log_page():
    print(f"LogPage requested: IP={request.remote_addr}")
    send_log(f"LogPage requested: IP={request.remote_addr}")
    return render_template('log.html')

@socketio.on('join_logger')
def handle_join_logger():
    join_room('logger_room')
    send_log(f"LogPage connected: SID={request.sid}, IP={request.remote_addr}")
    print(f"LogPage connected: SID={request.sid}, IP={request.remote_addr}")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
