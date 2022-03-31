FROM alpine:latest

RUN apk add --co-cache python3-dev \
  && pip3 install --upgrade pip

WORKDIR /app

COPY . /app

RUN pip3 --n-cache-dir install -r requirements.txt

EXPOSE 5000

ENTRYPOINT [ "python3" ]
CMD [ "api.py" ]




