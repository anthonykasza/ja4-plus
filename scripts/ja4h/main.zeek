module JA4PLUS::JA4H;

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
  global log_ja4h: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record JA4PLUS::Info += {
  ja4h: JA4PLUS::JA4H::Info &default=[];
};

event zeek_init() &priority=5 {
  Log::create_stream(JA4PLUS::JA4H::LOG,
    [$columns=JA4PLUS::JA4H::Info, $ev=log_ja4h, $path="ja4h", $policy=log_policy]
  );
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
  if (!c$ja4plus$ja4h?$client_version) { c$ja4plus$ja4h$client_version = version; }
}

function make_a(c: connection): string {
  local method: string = "??";
  if (c$http?$method) {
    method = to_lower(c$http$method[:2]);
  }

  local version = JA4PLUS::HTTP_VERSION_MAPPER[c$ja4plus$ja4h$client_version];

  local cookie: string = "n";
  local referer: string = "n";
  local header_count: count = 0;
  local al_code: string = "0000";
  for (idx, hmr in c$ja4plus$ja4h$hlist) {
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
  local output: string = "";
  for (idx, hmr in c$ja4plus$ja4h$hlist) {
    if (hmr$name == "COOKIE" || hmr$name == "REFERER") {
      next;
    }
    # case sensitive
    output += hmr$original_name;
    output += ",";
  }
  return output[:-1];
}
  

function make_c(c: connection, orig_ordering: bool &default=F): string {
  local output: string = "";
  if (c$http?$cookie_vars) {
    if (orig_ordering) {
      for (val in c$http$cookie_vars) {
        output += c$http$cookie_vars[val];
        output += ",";
      }
    } else {
      local ordering: vector of count = order(c$http$cookie_vars);
      for (idx, val in ordering) {
        output += c$http$cookie_vars[val];
        output += ",";
      }
    }
  }
  return output[:-1];
}

function make_d(c: connection, orig_ordering: bool &default=F): string {
  local output: string = "";
  if (c$http?$cookie_vars) {
    if (orig_ordering) {
      for (val in c$http$cookie_vars) {
        output += c$http$cookie_vars[val];
        output += "=";
        output += c$http$cookie_vals[val];
        output += ",";
      }
    } else {
      local ordering: vector of count = order(c$http$cookie_vars);
      for (idx, val in ordering) {
        output += c$http$cookie_vars[val];
        output += "=";
        output += c$http$cookie_vals[val];
        output += ",";
      }
    }
  }
  return output[:-1];
}

function set_fingerprint(c: connection) {
  c$ja4plus$ja4h$uid = c$uid;

  local aaa: string = make_a(c);
  local bbb: string = make_b(c);
  local ccc: string = make_c(c);
  local ddd: string = make_d(c);

  # ja4h
  c$ja4plus$ja4h$ja4h += aaa;
  c$ja4plus$ja4h$ja4h += JA4PLUS::delimiter;
  c$ja4plus$ja4h$ja4h += JA4PLUS::trunc_sha256(bbb);
  c$ja4plus$ja4h$ja4h += JA4PLUS::delimiter;
  c$ja4plus$ja4h$ja4h += JA4PLUS::trunc_sha256(ccc);
  c$ja4plus$ja4h$ja4h += JA4PLUS::delimiter;
  c$ja4plus$ja4h$ja4h += JA4PLUS::trunc_sha256(ddd);

  # ja4h_r
  c$ja4plus$ja4h$r += aaa;
  c$ja4plus$ja4h$r += JA4PLUS::delimiter;
  c$ja4plus$ja4h$r += |bbb| == 0 ? JA4PLUS::zero_string() : bbb;
  c$ja4plus$ja4h$r += JA4PLUS::delimiter;
  c$ja4plus$ja4h$r += |ccc| == 0 ? JA4PLUS::zero_string() : ccc;
  c$ja4plus$ja4h$r += JA4PLUS::delimiter;
  c$ja4plus$ja4h$r += |ddd| == 0 ? JA4PLUS::zero_string() : ddd;

  # original ordering = T
  ccc = make_c(c, T);
  ddd = make_d(c, T);

  # ja4h_o
  c$ja4plus$ja4h$o += aaa;
  c$ja4plus$ja4h$o += JA4PLUS::delimiter;
  c$ja4plus$ja4h$o += JA4PLUS::trunc_sha256(bbb);
  c$ja4plus$ja4h$o += JA4PLUS::delimiter;
  c$ja4plus$ja4h$o += JA4PLUS::trunc_sha256(ccc);
  c$ja4plus$ja4h$o += JA4PLUS::delimiter;
  c$ja4plus$ja4h$o += JA4PLUS::trunc_sha256(ddd);

  # ja4h_ro
  c$ja4plus$ja4h$ro += aaa;
  c$ja4plus$ja4h$ro += JA4PLUS::delimiter;
  c$ja4plus$ja4h$ro += |bbb| == 0 ? JA4PLUS::zero_string() : bbb;
  c$ja4plus$ja4h$ro += JA4PLUS::delimiter;
  c$ja4plus$ja4h$ro += |ccc| == 0 ? JA4PLUS::zero_string() : ccc;
  c$ja4plus$ja4h$ro += JA4PLUS::delimiter;
  c$ja4plus$ja4h$ro += |ddd| == 0 ? JA4PLUS::zero_string() : ddd;

  c$ja4plus$ja4h$done = T;
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) {
  if (!is_orig) { return; }
  c$ja4plus$ja4h$hlist = hlist;
  set_fingerprint(c);
  Log::write(JA4PLUS::JA4H::LOG, c$ja4plus$ja4h);
}
