CC=gcc
CFLAGS=-O2 -Wall $(shell mysql_config --cflags)
LFLAGS=-linitparser $(MYSQL)
BIN=sw
SRC=sw.c libhiredis.a iniparser.o dictionary.o
MYSQL=$(shell mysql_config --libs)

all:
	$(CC) $(CFLAGS) $(MYSQL) -o $(BIN) $(SRC)
