module JA4PLUS::JA4H;

export {
  type Info: record {
    # The connection uid which this fingerprint represents
    uid: string &optional;

    # the ja4h fingerprint value
    ja4h: string &log &default="";

    # The fingerprint with the raw array output
    r: string &log &default="";

    # The fingerprint with the original offered ordering
    o: string &log &default="";

    # The fingerprint with both the original offered ordering and the raw array output
    ro: string &log &default="";

    # Variable names extracted from all cookies.
    cookie_vars: vector of string &optional;

    # Variable values extracted from all cookies.
    cookie_vals: vector of string &optional;

    # The version offered by the client
    client_version: string &optional;

    # the header list from the request
    hlist_vec: vector of mime_header_rec &optional;

    # If this context is ready to be logged
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

# Store the version the client offers. c$http$version contains the version
#  from the resp
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
  if (!c$ja4plus$ja4h?$client_version) { c$ja4plus$ja4h$client_version = version; }
}

# TODO - move this function into utils/functions, combine with similar 
#  functions
function extract_values(data: string, kv_splitter: pattern): string_vec
	{
	local value_vec: vector of string = vector();

	local parts = split_string(data, kv_splitter);
	for ( part_index in parts )
		{
		local value_val = split_string1(parts[part_index], /=/);
		if ( 1 in value_val )
			value_vec += value_val[1];
		}
	return value_vec;
	}

# TODO - move this function into utils/functions, combine with the above 
#  extract_values function, and the function used in JA4X
function extract_keys(data: string, kv_splitter: pattern): string_vec
	{
	local value_vec: vector of string = vector();

	local parts = split_string(data, kv_splitter);
	for ( part_index in parts )
		{
		local value_val = split_string1(parts[part_index], /=/);
		if ( 0 in value_val )
			value_vec += value_val[0];
		}
	return value_vec;
	}

# Construct the A string portion of the fingerprint
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
  for (idx, hmr in c$ja4plus$ja4h$hlist_vec) {
    if (hmr$name == "COOKIE") {
      cookie = "c";
      c$ja4plus$ja4h$cookie_vars = extract_keys(hmr$value, /;[[:blank:]]*/);
      c$ja4plus$ja4h$cookie_vals = extract_values(hmr$value, /;[[:blank:]]*/);
    } else if (hmr$name == "REFERER") {
      referer = "r";
    } else {
      header_count += 1;
    }
    if (hmr$name == "ACCEPT-LANGUAGE") {
      # remove all hyphens from the header's value
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

# Make the B portion of the fingerprint
function make_b(c: connection): string {
  local output: string = "";
  for (idx, hmr in c$ja4plus$ja4h$hlist_vec) {
    # ignore certain headers
    if (hmr$name == "COOKIE" || hmr$name == "REFERER") {
      next;
    }
    # case sensitive
    output += hmr$original_name;
    output += ",";
  }
  return output[:-1];
}

# make the C portion of the fingerprint
function make_c(c: connection, orig_ordering: bool &default=F): string {
  local output: string = "";
  if (c$ja4plus$ja4h?$cookie_vars) {
    if (orig_ordering) {
      for (val in c$ja4plus$ja4h$cookie_vars) {
        output += c$ja4plus$ja4h$cookie_vars[val];
        output += ",";
      }
    } else {
      local ordering: vector of count = order(c$ja4plus$ja4h$cookie_vars, strcmp);
      for (idx, val in ordering) {
        output += c$ja4plus$ja4h$cookie_vars[val];
        output += ",";
      }
    }
  }
  return output[:-1];
}

# make the D portion
function make_d(c: connection, orig_ordering: bool &default=F): string {
  local output: string = "";
  if (c$ja4plus$ja4h?$cookie_vars) {
    if (orig_ordering) {
      for (val in c$ja4plus$ja4h$cookie_vars) {
        output += c$ja4plus$ja4h$cookie_vars[val];
        output += "=";
        output += c$ja4plus$ja4h$cookie_vals[val];
        output += ",";
      }
    } else {
      local ordering: vector of count = order(c$ja4plus$ja4h$cookie_vars, strcmp);
      for (idx, val in ordering) {
        output += c$ja4plus$ja4h$cookie_vars[val];
        output += "=";
        output += c$ja4plus$ja4h$cookie_vals[val];
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
  local hlist_vec: vector of mime_header_rec = vector();
  for (idx, hmr in hlist) {
    hlist_vec[idx] = hmr;
  }
  c$ja4plus$ja4h$hlist_vec = hlist_vec;
  set_fingerprint(c);
  Log::write(JA4PLUS::JA4H::LOG, c$ja4plus$ja4h);
}
