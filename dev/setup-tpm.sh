#!/bin/bash

set -e

setup_libs=false
create_tpm=false
test_tpm=false
delete_all=false
test_trinc=false

mecho() {
    local input_text="$*"
    echo -e "--> $input_text."
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p ${HOME}/src
SRC="${HOME}/src"

LIBTPMS_DIR="$SRC/libtpms"
SWTTPM_DIR="$SRC/swtpm"
TPM2_TSS_DIR="$SRC/tpm2-tss"
TPM2_TOOLS_DIR="$SRC/tpm2-tools"

for cmd in "$@"; do
    case $cmd in
        setup_libs) setup_libs=true ;;
        create_tpm) create_tpm=true ;;
        test_tpm) test_tpm=true ;;
        delete_all) delete_all=true;;
        test_trinc) test_trinc=true;;
        *) 
            mecho "Unknown command: $cmd"
            ;;
    esac
done

if [[ "$delete_all" == "true" ]]; then
    cd ${LIBTPMS_DIR}
    sudo make uninstall
    cd -
    rm -rf ${LIBTPMS_DIR}

    cd ${SWTTPM_DIR}
    sudo make uninstall
    cd -
    rm -rf ${SWTTPM_DIR}

    cd ${TPM2_TSS_DIR}
    sudo make uninstall
    cd -
    rm -rf ${TPM2_TSS_DIR}

    cd ${TPM2_TOOLS_DIR}
    sudo make uninstall
    cd - 
    rm -rf ${TPM2_TOOLS_DIR}

    sudo rm -rf /tmp/myvtpm2
    sudo rm -rf /tmp/swtpm_cuse.log

    sudo pkill swtpm_cuse
fi

if [[ "$setup_libs" == "true" ]]; then
    
    mecho "Setting up libtpms"

    sudo apt install libc6-dev libgmp-dev libnspr4-dev libnss3-dev autoconf \
    libtool pkg-config libssl-dev build-essential -y
    git clone https://github.com/stefanberger/libtpms.git $LIBTPMS_DIR
    cd $LIBTPMS_DIR
    ./autogen.sh --with-tpm2 --with-openssl --prefix=/usr
    make -j$(nproc)
    make check -j$(nproc)
    sudo make install -j$(nproc)
    sudo ldconfig
    cd -

    mecho "Setting up swtpm"
    sudo apt update && sudo apt install -y dh-autoreconf libssl-dev automake \
        autoconf bash coreutils libseccomp-dev make iproute2 expect libtool \
        sed fuse libfuse-dev libglib2.0-0 libglib2.0-dev libjson-glib-dev \
        net-tools python3 python3-twisted checkpolicy socat gawk trousers \
        libgnutls30 libgnutls28-dev libtasn1-6 libtasn1-bin libtasn1-6-dev \
        gnutls-bin
    git clone https://github.com/stefanberger/swtpm.git $SWTTPM_DIR
    cd $SWTTPM_DIR
    export PKG_CONFIG_PATH=/usr/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig
    ./autogen.sh --with-tpm2 --with-openssl --prefix=/usr
    make -j$(nproc)
    make -j$(nproc) check
    sudo make install -j$(nproc)
    cd -
    
    mecho "Setting up tpm2-tss"
    sudo apt -y install autoconf-archive libcmocka0 libcmocka-dev procps \
        iproute2 build-essential git pkg-config gcc libtool automake libssl-dev \
        uthash-dev autoconf doxygen libjson-c-dev libini-config-dev \
        libcurl4-openssl-dev uuid-dev libltdl-dev libusb-1.0-0-dev \
        libftdi-dev pandoc
    git clone https://github.com/tpm2-software/tpm2-tss.git $TPM2_TSS_DIR
    cd $TPM2_TSS_DIR
    ./bootstrap
    ./configure
    make -j$(nproc)
    make -j$(nproc) check
    sudo make install -j$(nproc)
    sudo ldconfig
    cd -

    mecho "Setting up tpm2-tools"
    git clone https://github.com/tpm2-software/tpm2-tools.git $TPM2_TOOLS_DIR
    cd $TPM2_TOOLS_DIR
    ./bootstrap
    ./configure --prefix=/usr
    make -j$(nproc)
    make -j$(nproc) check
    sudo make install -j$(nproc)
    cd -
fi

if [[ "$create_tpm" == "true" ]]; then

    mecho "Creating tpm state folder in /tpm/myvtpm2"
    sudo rm -rf /tmp/myvtpm2
    sudo rm -rf /tmp/swtpm_cuse.log

    sudo mkdir -p /tmp/myvtpm2
    sudo chown tss:root /tmp/myvtpm2

    mecho "Creating tpm with swtpm_setup"
    sudo swtpm_setup --tpmstate /tmp/myvtpm2 --create-ek-cert --create-platform-cert --tpm2 --overwrite
    sleep 2

    mecho "Creating /dev/tpmrm0 device with swtpm_cuse"
    sudo swtpm_cuse --tpm2 --name tpmrm0 --tpmstate dir=/tmp/myvtpm2 --flags not-need-init,startup-clear --log file=/tmp/swtpm_cuse.log,level=100

fi

if [[ "$test_tpm" == "true" ]]; then

    mecho "Testing using tpm2_getrandom"
    sudo tpm2_getrandom --hex 8
fi

if [[ "$test_trinc" == "true" ]]; then
    # change DefaultTPMDevPath in trinket.go to /dev/tpmrm0
    cd ..
    # check trinctool works
    make all
    sudo ./trinctool -cmd attestctr -sk ./testdata/sk.key -msg ./testdata/alice.txt -attestation attest.json
    sudo ./trinctool -cmd verifyctr -pk ./testdata/pk.key -msg ./testdata/alice.txt -attestation attest.json

    # check test and benchmark works
    make test
    make benchmark
fi