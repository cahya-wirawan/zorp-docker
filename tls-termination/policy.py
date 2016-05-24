from Zorp.Core import init

from Zorp.Core import FALSE, TRUE, ZD_PROTO_TCP, DBSockAddr, SockAddrInet
from Zorp.Router import DirectedRouter
from Zorp.Dispatch import Dispatcher
from Zorp.Service import Service
from Zorp.Http import HttpProxy, HTTP_HDR_INSERT
from Zorp.Encryption import \
    EncryptionPolicy, \
    ClientOnlyEncryption, \
    ClientNoneVerifier, \
    StaticCertificate, \
    Certificate, \
    PrivateKey

from datetime import timedelta

from Zorp.Core import config
config.options.kzorp_enabled = False


EncryptionPolicy(
    name="encryption_policy_tls_termination",
    encryption=ClientOnlyEncryption(
        client_certificate_generator=StaticCertificate(
            certificate=Certificate.fromFile(
                certificate_file_path="/etc/zorp/certs/cert.pem",
                private_key=PrivateKey.fromFile(
                    key_file_path="/etc/zorp/certs/key.pem",
                )
            )
        ),
        client_verify=ClientNoneVerifier(),
    )
)


class HttpProxySSLOffload(HttpProxy):
    cert_chain_digests = open("/etc/zorp/certs/cert.dgst").read().splitlines()

    def config(self):
        HttpProxy.config(self)

        hsts_header_value = "max-age=%d" % (timedelta(days=365).total_seconds())
        self.response_header["Strict-Transport-Security"] = (HTTP_HDR_INSERT, hsts_header_value)

        hpkp_header_values = (
            ["max-age=%d" % (timedelta(days=30).total_seconds()), ] +
            ["pin-sha256=\"" + dgst + "\"" for dgst in self.cert_chain_digests] +
            ["includeSubDomains", ]
        )
        self.response_header["Public-Key-Pins"] = (HTTP_HDR_INSERT, ";".join(hpkp_header_values))


def default():
    def getServiceList():
        import os
        service_enabled = os.getenv("ZORP_TLS_TERMINATION_SERVICE_ENABLED", "").lower().split()
        return service_enabled
    serviceList = getServiceList()

    if "https" in serviceList:
        import socket
        server_address = socket.gethostbyname("www")

        Service(
            name="service_https_tls_termination",
            proxy_class=HttpProxy,
            encryption_policy="encryption_policy_tls_termination",
            router=DirectedRouter(dest_addr=SockAddrInet(server_address, 80), forge_addr=FALSE),
        )
        Dispatcher(
            bindto=DBSockAddr(SockAddrInet('0.0.0.0', 443), protocol=ZD_PROTO_TCP),
            service="service_https_tls_termination",
        )
