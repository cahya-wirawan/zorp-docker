#!/bin/bash -ex

ZORP_PIDFILE_DIR=/var/run/zorp

function create_pidfile_dir {
    mkdir $ZORP_PIDFILE_DIR
    chown zorp.zorp $ZORP_PIDFILE_DIR
    chmod 0770 $ZORP_PIDFILE_DIR
}

create_pidfile_dir

function create_cert_digest_file {
    ZORP_CERT_FILE_DIR=/etc/zorp/certs
    openssl dgst -sha256 -binary ${ZORP_CERT_FILE_DIR}/cert.pem | openssl enc -base64 >${ZORP_CERT_FILE_DIR}/cert.dgst
}

create_cert_digest_file

exec "$@"
