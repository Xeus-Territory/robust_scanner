FROM python:3

WORKDIR  /app/robust/

COPY . .

RUN pip install -r requirements.txt

EXPOSE 50000

CMD [ "python", "./api.py" ]

