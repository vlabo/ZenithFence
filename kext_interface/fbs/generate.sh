#!/bin/sh

flatc -r -o ../../driver/src/protocol protocol.fbs
flatc -g -o ../ protocol.fbs
