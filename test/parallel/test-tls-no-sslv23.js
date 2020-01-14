'use strict';
const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const tls = require('tls');

assert.throws(function() {
  tls.createSecureContext({ secureProtocol: 'blargh' });
}, {
  code: 'ERR_TLS_INVALID_PROTOCOL_METHOD',
  message: 'Unknown method: blargh',
});

const errMessageSSLv2 = /SSLv2 methods disabled/;

assert.throws(function() {
  tls.createSecureContext({ secureProtocol: 'SSLv2_method' });
}, errMessageSSLv2);

assert.throws(function() {
  tls.createSecureContext({ secureProtocol: 'SSLv2_client_method' });
}, errMessageSSLv2);

assert.throws(function() {
  tls.createSecureContext({ secureProtocol: 'SSLv2_server_method' });
}, errMessageSSLv2);

// Note that SSLv2 is disallowed but SSLv2_method and friends are
// still accepted.  They are OpenSSL's way of saying that all known protocols
// are supported unless explicitly disabled (which we do for SSLv2)
tls.createSecureContext({ secureProtocol: 'SSLv3_method' });
tls.createSecureContext({ secureProtocol: 'SSLv3_client_method' });
tls.createSecureContext({ secureProtocol: 'SSLv3_server_method' });
tls.createSecureContext({ secureProtocol: 'SSLv23_method' });
tls.createSecureContext({ secureProtocol: 'SSLv23_client_method' });
tls.createSecureContext({ secureProtocol: 'SSLv23_server_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_client_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_server_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_1_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_1_client_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_1_server_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_2_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_2_client_method' });
tls.createSecureContext({ secureProtocol: 'TLSv1_2_server_method' });
