# ① 베이스 이미지: 가볍고 안정적인 slim 사용
FROM python:3.12-slim

# ② 작업 디렉터리 설정
WORKDIR /app

# ③ 의존성 먼저 복사 & 설치 (빌드 속도 최적화)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ④ 애플리케이션 코드 복사
COPY . .

# ⑤ 컨테이너 외부에 노출할 포트
EXPOSE 5000

# ⑥ 컨테이너 시작 시 실행할 명령
CMD ["python", "security_3rd_server.py"]
