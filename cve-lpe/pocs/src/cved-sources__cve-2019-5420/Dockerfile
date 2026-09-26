FROM ruby:2.6.0

LABEL author="knqyf263 (knqyf263@gmail.com)"
LABEL maintainer="cved (cved@protonmail.com)"

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update \
    && apt-get -y install \
    build-essential \
    nodejs \
    sqlite3 \
    libsqlite3-dev \
    && apt-get autoremove \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/tmp/*

RUN gem install bundler

COPY build/Gemfile /
COPY build/Gemfile.lock /

RUN bundle install

RUN rails new verifier_rce \
    && cd verifier_rce \
    && sed -i "s/'sqlite3'/'sqlite3', '~> 1.3.6'/g" Gemfile \
    && sed -i "s/~> 5.2.2/= 5.2.2/g" Gemfile \
    && rm Gemfile.lock \
    && bundle install

WORKDIR /verifier_rce

EXPOSE 3000

CMD ["bundle", "exec", "bin/rails", "server", "-b", "0.0.0.0"]
