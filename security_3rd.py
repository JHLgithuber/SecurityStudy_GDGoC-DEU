import socketio
import asyncio

sio = socketio.AsyncClient()  # 비동기로 작동하도록 AsyncClient 사용


@sio.on('connect')  # 비동기 connect 이벤트
async def on_connect():
    print('Connected to server!')


@sio.on('message')  # message 이벤트 처리
async def on_message(data):
    print('Message from server:', data)


@sio.on('ping')  # ping 이벤트 처리
async def on_ping():
    await sio.emit('pong')  # pong 이벤트 보내기


@sio.on('pong')  # pong 이벤트 처리
async def on_pong(data):
    print(data)


@sio.on('disconnect')  # disconnect 이벤트 처리
async def on_disconnect():
    print('Disconnected from server!')


async def input_terminal():
    while True:
        # 동기 input을 비동기코드에서 실행
        user_input = await asyncio.to_thread(input, "> ")

        # 입력값에 따라 서버로 이벤트 전송
        if user_input.lower() == "ping":
            await sio.emit("ping")
        else:
            await sio.emit("message_broadcast", user_input)


async def main():
    try:
        # 서버에 연결 시도
        await sio.connect('http://localhost:5000')
        await sio.emit("rename", "test!")  # rename 이벤트 전송

        # 이벤트 대기와 입력을 동시 실행
        await asyncio.gather(sio.wait(), input_terminal())

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        await sio.disconnect()  # 연결 해제


if __name__ == '__main__':
    asyncio.run(main())