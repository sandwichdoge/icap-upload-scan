# icap-upload-scan
### How to build
1. Install depdendencies
```
sudo apt update
sudo apt install -y automake libtool make gcc pkg-config libssl-dev libjansson-dev libmagic-dev
```

2. Build yara lib from source
```
git clone --depth 1 --branch v4.5.2 https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure --disable-shared --enable-static --without-crypto
make -j$(nproc)
sudo make install
sudo ldconfig
```

3. Verify pkg-config sees the static lib:
```
pkg-config --static --libs yara
```

4. Build binary
```
make
```

