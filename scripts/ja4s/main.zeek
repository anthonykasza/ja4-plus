
module FINGERPRINT::JA4S;

export {
  # The server fingerprint context and logging format
  type Info: record {

    # The connection uid which this fingerprint represents
    uid: string &log &optional;

    # The server hello fingerprint
    ja4s: string &log &default="";

    # The server hello fingerprint in raw format
    r: string &log &default="";
  
    # If this context is ready to be logged
    done: bool &default=F;
  };

  global set_fingerprint: function(c: connection);

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4s: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
  ja4s: FINGERPRINT::JA4S::Info &default=[];
};

event zeek_init() &priority=5 {
  # ServerHello fingerprints are logged to a new file instead of appended to ssl.log
  Log::create_stream(FINGERPRINT::JA4S::LOG,
    [$columns=FINGERPRINT::JA4S::Info, $ev=log_fingerprint_ja4s, $path="fingerprint_ja4s", $policy=log_policy]
  );
}

# TODO - some of the following functions are duplicates from the ClientHello code, vector_of_count_to_str. 
#  reduce, reuse, recycle these function
function vector_of_count_to_str(input: vector of count, format_str: string &default="%04x", dlimit: string &default=","): string {
  local output: string = "";
  for (idx, val in input) {
    output += fmt(format_str, val);
    if (idx < |input|-1) {
      output += dlimit;
    }
  }
  return output;
}

function make_a(c: connection): string {
        local proto: string = "0";
        local trans_proto = get_port_transport_proto(c$id$resp_p);
        if ( "QUIC" in c$service )
                {
                proto = "q";
                }
        else if ( "DTLS" in c$service )
                {
                proto = "d";
                }
        else if ( trans_proto == tcp )
                {
                proto = "t";
                }
        else if ( trans_proto == udp )
                {
                proto = "u";
                }

  local ec_count = "00";
  if (|c$fp$server_hello$extension_codes| > 99) {
    ec_count = fmt("%02d", 99);
  } else {
    ec_count = fmt("%02d", |c$fp$server_hello$extension_codes|);
  }

  local alpn: string = "00";
  if (c$fp$server_hello?$alpns && |c$fp$server_hello$alpns| > 0) {
    # TODO - There should be only 1. what happens if there are more than 1?
    alpn = c$fp$server_hello$alpns[0];
  }


  local version = FINGERPRINT::TLS_VERSION_MAPPER[c$fp$server_hello$version];

  local a: string = "";
  a += proto;
  a += version;
  a += ec_count;
  a += alpn;
  return a;
}


function set_fingerprint(c: connection) {
  local a: string = make_a(c);
  local b: string = to_lower(fmt("%02x", c$fp$server_hello$cipher_suite));

  c$fp$ja4s$uid = c$uid;

  # ja4s
  c$fp$ja4s$ja4s += a;
  c$fp$ja4s$ja4s += FINGERPRINT::delimiter;
  c$fp$ja4s$ja4s += b;
  c$fp$ja4s$ja4s += FINGERPRINT::delimiter;
  c$fp$ja4s$ja4s += FINGERPRINT::trunc_sha256(vector_of_count_to_str(c$fp$server_hello$extension_codes));

  # ja4s_r
  c$fp$ja4s$r += a;
  c$fp$ja4s$r += FINGERPRINT::delimiter;
  c$fp$ja4s$r += b;
  c$fp$ja4s$r += FINGERPRINT::delimiter;
  c$fp$ja4s$r += vector_of_count_to_str(c$fp$server_hello$extension_codes);

  c$fp$ja4s$done = T;
}

event connection_state_remove(c: connection) {
  if (!c?$fp || !c$fp?$server_hello || !c$fp$server_hello?$version) { return; }
  set_fingerprint(c);
  Log::write(FINGERPRINT::JA4S::LOG, c$fp$ja4s);
}
