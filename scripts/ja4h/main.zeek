module FINGERPRINT::JA4H;

export {
  type Info: record {
    uid: string &optional;
    ja4h: string &log &default="";
    r: string &log &default="";
    o: string &log &default="";
    ro: string &log &default="";

    client_version: string &optional;
    hlist: mime_header_list &optional;
    done: bool &default=F;
  };

  global set_fingerprint: function(c: connection);

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4h: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
  ja4h: FINGERPRINT::JA4H::Info &default=[];
};

event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4H::LOG,
    [$columns=FINGERPRINT::JA4H::Info, $ev=log_fingerprint_ja4h, $path="fingerprint_ja4h", $policy=log_policy]
  );
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
  if (!c$fp$ja4h?$client_version) { c$fp$ja4h$client_version = version; }
}

function make_a(c: connection): string {
  local method: string = "??";
  if (c$http?$method) {
    method = to_lower(c$http$method[:2]);
  }

  local version: string = "??";
  if (c$fp$ja4h?$client_version && c$fp$ja4h$client_version in FINGERPRINT::HTTP_VERSION_MAPPER) {
    version = FINGERPRINT::HTTP_VERSION_MAPPER[c$fp$ja4h$client_version];
  }

  local cookie: string = "n";
  local referer: string = "n";
  local header_count: count = 0;
  local al_code: string = "0000";
  for (idx, hmr in c$fp$ja4h$hlist) {
    if (hmr$name == "COOKIE") {
      cookie = "c";
    } else if (hmr$name == "REFERER") {
      referer = "r";
    } else {
      header_count += 1;
    }
    if (hmr$name == "ACCEPT-LANGUAGE") {
      al_code = to_lower(gsub(hmr$value, /-/, ""));
      al_code = split_string1(al_code, /,/)[0];
      if (|al_code| < 4) {
        while(|al_code| < 4) {
          al_code += "0";
        }
      }
      al_code = al_code[:4];
    }
  }

  local headers: string = "00";
  if (header_count > 99) {
    headers = "99";
  } else {
    headers = fmt("%02d", header_count);
  }

  local aaa: string = "";
  aaa += method;
  aaa += version;
  aaa += cookie;
  aaa += referer;
  aaa += headers;
  aaa += al_code;
  return aaa;
}

function make_b(c: connection): string {
  local s: string = "";
  for (idx, hmr in c$fp$ja4h$hlist) {
    if (hmr$name == "COOKIE" || hmr$name == "REFERER") {
      next;
    }
    # case sensitive
    s += hmr$original_name;
    s += ",";
  }
  local bbb: string = s[:-1];
  if (|bbb| == 0) { return "000000000000"; }
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, bbb);
  return sha256_hash_finish(sha256_object)[:12];
}
  

function make_c(c: connection): string {
  local output: string = "";
  if (c$http?$cookie_vars) {
    local ordering: vector of count = order(c$http$cookie_vars);
    for (idx, val in ordering) {
      output += c$http$cookie_vars[val];
      output += ",";
    }
  }
  local ccc: string = output[:-1];
  if (|ccc| == 0) { return "000000000000"; }
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, ccc);
  return sha256_hash_finish(sha256_object)[:12];
}

function make_d(c: connection): string {
  local output: string = "";
  if (c$http?$cookie_vars) {
    local ordering: vector of count = order(c$http$cookie_vars);
    for (idx, val in ordering) {
      output += c$http$cookie_vars[val];
      output += "=";
      output += c$http$cookie_vals[val];
      output += ",";
    }
  }
  local ddd: string = output[:-1];
  if (|ddd| == 0) { return "000000000000"; }
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, ddd);
  return sha256_hash_finish(sha256_object)[:12];
}

function set_fingerprint(c: connection) {
  c$fp$ja4h$uid = c$uid;

  # because the variable name "a" has already used in this scope, sheesh
  local ja4s_a: string = make_a(c);
  local ja4s_b: string = make_b(c);
  local ja4s_c: string = make_c(c);
  local ja4s_d: string = make_d(c);

  c$fp$ja4h$ja4h += ja4s_a;
  c$fp$ja4h$ja4h += FINGERPRINT::delimiter;
  c$fp$ja4h$ja4h += ja4s_b;
  c$fp$ja4h$ja4h += FINGERPRINT::delimiter;
  c$fp$ja4h$ja4h += ja4s_c;
  c$fp$ja4h$ja4h += FINGERPRINT::delimiter;
  c$fp$ja4h$ja4h += ja4s_d;

  # TODO - ja4h_o

  # TODO - ja4h_r

  # TODO - ja4h_ro

  c$fp$ja4h$done = T;
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
  if (!is_orig) { return; }
  c$fp$ja4h$hlist = hlist;
  set_fingerprint(c);
  Log::write(FINGERPRINT::JA4H::LOG, c$fp$ja4h);
}
