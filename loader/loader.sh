#!/bin/sh
rm loader.exe loader.zip 
zip loader.zip n2f.exe nsh.exe
cat unzipsfx.exe loader.zip > loader.exe
zip -A loader.exe
