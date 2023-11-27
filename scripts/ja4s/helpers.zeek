
module JA4PLUS::JA4S;

export {
  type ServerHello: record {

    # The highest TLS version found in the supported versions extension or the TLS record
    version: count &optional;

    # The cipher suite selected by the server
    cipher_suite: count &optional;

    # The compression algorithm selecred by the server
    compression_method: count &optional;

    # The extensions offered by the server
    extension_codes: vector of count &default=vector();

    # The application layer protocol as indicated by the server
    alpns: vector of string &optional;
  };
}

redef record JA4PLUS::Info += {
  server_hello: ServerHello &default=[];
};

# This event is processed at the end of the hello, after all the extension-specific events occur
event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time,
 server_random: string, session_id: string, cipher: count, comp_method: count) {
  if (!c$ja4plus$server_hello?$version) {
    # If we weren't able to set the version from an extension, use the outer envelop's versioning
    c$ja4plus$server_hello$version = version;
  }
  c$ja4plus$server_hello$cipher_suite = cipher;
  c$ja4plus$server_hello$compression_method = comp_method;
}

# For each extension build up an array of code in the order they appear
event ssl_extension(c: connection, is_client: bool, code: count, val: string) {
  if (!c?$ja4plus) { c$ja4plus = []; }
  if (is_client) { return; }
  if (!c$ja4plus?$server_hello) { c$ja4plus$server_hello = []; }
  c$ja4plus$server_hello$extension_codes += code;
}

# For each alpn build up an array protocol strings
event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec) {
  if (!c?$ja4plus) { c$ja4plus = []; }
  if (is_client) { return; }
  if (!c$ja4plus$server_hello?$alpns) {
    c$ja4plus$server_hello$alpns = vector();
  }
  c$ja4plus$server_hello$alpns += protocols;
}

# If the supported versions extension is present, find the largest offered version and store it
event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec) {
  if(!c?$ja4plus) { c$ja4plus = []; }
  if (is_client) { return; }
  local largest: count = 0;
  for (idx, val in versions) {
    if (val > largest) {
      largest = val;
    }
  }
  c$ja4plus$server_hello$version = largest;
}
