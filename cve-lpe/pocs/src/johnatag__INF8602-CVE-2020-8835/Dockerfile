FROM ubuntu:20.04

ENV TZ Etc/UTC

# Install nodejs
RUN apt-get update && apt-get install -y \
    nodejs \
    npm

# Create app directory
WORKDIR /usr/src/package
COPY package/. /usr/src/package/
#RUN apk add build-base
#RUN apk add linux-headers

# Bundle app source
WORKDIR /usr/src/app
COPY app/. /usr/src/app/

RUN npm install

EXPOSE 8080
CMD [ "node", "server.js" ]