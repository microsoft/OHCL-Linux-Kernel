#!/bin/bash
apt-get update
apt-get install -y build-essential flex bison libelf-dev bc rsync
apt-get install -y libklibc-dev musl-tools execstack
apt-get install -y xmlstarlet

# Install for building perf
apt-get install -y libdw-dev libbz2-dev libunwind-dev libbfd-dev libiberty-dev libzstd-dev
apt-get install -y python3

# Install Mono
apt-get install -y --no-install-recommends gnupg ca-certificates
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb https://download.mono-project.com/repo/ubuntu stable-focal main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list
apt-get update
apt-get install -y mono-devel

# Install NuGet
# wget -q https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -O /usr/bin/nuget.exe

env
