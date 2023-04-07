var fs = require('fs');
import { hello } from './hello'


var PREFIX = '/etc/nginx/ssl/';
var KEY_SUFFIX = '.key';
var CERTIFICATE_SUFFIX = '.crt';

function js_cert(r: NginxHTTPRequest) {
    return read_cert_or_key(PREFIX, r.variables.ssl_server_name?.toLowerCase() || '', CERTIFICATE_SUFFIX);
}

function js_key(r: NginxHTTPRequest) {
    let serverName = r.variables.ssl_server_name?.toLowerCase() || '';
    return read_cert_or_key(PREFIX, serverName, KEY_SUFFIX);
}

function read_cert_or_key(prefix: string, domain: string, suffix: string): string {
    var none_wildcard_path = String.prototype.concat(prefix, domain, suffix);
    var wildcard_path = String.prototype.concat(prefix, domain.replace(/.*?\./, '*.'), suffix);
    var data = '';

    try {
        data = fs.readFileSync(none_wildcard_path);
    } catch (e) {
        try {
            data = fs.readFileSync(wildcard_path);
        } catch (e) {
            data = '';
        }
    }

    return data;
}


export default {
    js_cert,
    js_key,
    hello
}
