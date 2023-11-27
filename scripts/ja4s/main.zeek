
module JA4PLUS::JA4S;

export {
  # The TLS ServerHello fingerprint context and logging format
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
  global log_ja4s: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record JA4PLUS::Info += {
  ja4s: JA4PLUS::JA4S::Info &default=[];
};

event zeek_init() &priority=5 {
  # ServerHello fingerprints are logged to a new file instead of appended to ssl.log
  Log::create_stream(JA4PLUS::JA4S::LOG,
    [$columns=JA4PLUS::JA4S::Info, $ev=log_ja4s, $path="ja4s", $policy=log_policy]
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
  if (|c$ja4plus$server_hello$extension_codes| > 99) {
    ec_count = fmt("%02d", 99);
  } else {
    ec_count = fmt("%02d", |c$ja4plus$server_hello$extension_codes|);
  }

  local alpn: string = "00";
  if (c$ja4plus$server_hello?$alpns && |c$ja4plus$server_hello$alpns| > 0) {
    # TODO - There should be only 1. what happens if there are more than 1?
    alpn = c$ja4plus$server_hello$alpns[0];
  }


  local version = JA4PLUS::TLS_VERSION_MAPPER[c$ja4plus$server_hello$version];

  local a: string = "";
  a += proto;
  a += version;
  a += ec_count;
  a += alpn;
  return a;
}


function set_fingerprint(c: connection) {
  local a: string = make_a(c);
  local b: string = to_lower(fmt("%02x", c$ja4plus$server_hello$cipher_suite));

  c$ja4plus$ja4s$uid = c$uid;

  # ja4s
  c$ja4plus$ja4s$ja4s += a;
  c$ja4plus$ja4s$ja4s += JA4PLUS::delimiter;
  c$ja4plus$ja4s$ja4s += b;
  c$ja4plus$ja4s$ja4s += JA4PLUS::delimiter;
  c$ja4plus$ja4s$ja4s += JA4PLUS::trunc_sha256(vector_of_count_to_str(c$ja4plus$server_hello$extension_codes));

  # ja4s_r
  c$ja4plus$ja4s$r += a;
  c$ja4plus$ja4s$r += JA4PLUS::delimiter;
  c$ja4plus$ja4s$r += b;
  c$ja4plus$ja4s$r += JA4PLUS::delimiter;
  c$ja4plus$ja4s$r += vector_of_count_to_str(c$ja4plus$server_hello$extension_codes);

  c$ja4plus$ja4s$done = T;
}

event connection_state_remove(c: connection) {
  if (!c?$ja4plus || !c$ja4plus?$server_hello || !c$ja4plus$server_hello?$version) { return; }
  set_fingerprint(c);
  Log::write(JA4PLUS::JA4S::LOG, c$ja4plus$ja4s);
}
