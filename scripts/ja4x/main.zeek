module JA4PLUS::JA4X;

export {
  type Info: record {
    # the uid for this file
    fuid: string &log &optional;

    # the fingerprint string
    ja4x: string &log &default="";

    # the raw fingerprint string with no hashing
    r: string &log &default="";

    # if this record is ready for logging
    done: bool &default=F;
  };

  global set_fingerprint: function(f: fa_file);

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_ja4x: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record JA4PLUS::Info += {
  ja4x: JA4PLUS::JA4X::Info &default=[];
};

event zeek_init() &priority=5 {
  Log::create_stream(JA4PLUS::JA4X::LOG,
    [$columns=JA4PLUS::JA4X::Info, $ev=log_ja4x, $path="ja4x", $policy=log_policy]
  );
}

function set_fingerprint(f: fa_file) {
  if (!f?$ja4plus) { f$ja4plus = [];; }
  f$ja4plus$ja4x$fuid = f$id;

  local idx: count;
  local key: string;

  # Issuer RDNs
  local issuer_rdns: vector of count = vector();
  local issuer_keys = JA4PLUS::extract_key_val(f$info$x509$certificate$issuer, /,[[:blank:]]*/, T);
  for (idx in issuer_keys) {
    key = issuer_keys[idx];
    issuer_rdns += long_name_to_oid_hex[short_name_to_long_name[key]];
  }
  local aaa: string = JA4PLUS::vector_of_count_to_str(issuer_rdns, "%x");

  # Subject RDNs
  local subject_rdns: vector of count = vector();
  local subject_keys = JA4PLUS::extract_key_val(f$info$x509$certificate$subject, /,[[:blank:]]*/, T);
  for (idx in subject_keys) {
    key = subject_keys[idx];
    subject_rdns += long_name_to_oid_hex[short_name_to_long_name[key]];
  }
  local bbb: string = JA4PLUS::vector_of_count_to_str(subject_rdns, "%x");

  # TODO - rewrite this perl function in zeekscript
  #  https://github.com/openssl/openssl/blob/master/crypto/objects/obj_dat.pl
  #  https://github.com/openssl/openssl/blob/master/crypto/objects/obj_dat.h
  # Here's a version in C
  #  https://github.com/m9aertner/oidConverter/blob/master/oid.c
  # Using a conversion function will support new oids in the future while
  #  my hacky lookup table will need updated manually.
  # Extensions
  local extension_oids: vector of count = vector();
  for (idx in f$info$x509$extensions) {
    local extension = f$info$x509$extensions[idx];
    extension_oids += long_name_to_oid_hex[oid_str_to_long_name[extension$oid]];
  }
  local ccc: string = JA4PLUS::vector_of_count_to_str(extension_oids, "%x");

  # ja4x_r
  f$ja4plus$ja4x$r = aaa;
  f$ja4plus$ja4x$r += JA4PLUS::delimiter;
  f$ja4plus$ja4x$r += bbb;
  f$ja4plus$ja4x$r += JA4PLUS::delimiter;
  f$ja4plus$ja4x$r += ccc;
  
  # ja4x
  f$ja4plus$ja4x$ja4x = JA4PLUS::trunc_sha256(aaa);
  f$ja4plus$ja4x$ja4x += JA4PLUS::delimiter;
  f$ja4plus$ja4x$ja4x += JA4PLUS::trunc_sha256(bbb);
  f$ja4plus$ja4x$ja4x += JA4PLUS::delimiter;
  f$ja4plus$ja4x$ja4x += JA4PLUS::trunc_sha256(ccc);

  # This context is done and ready for logging
  f$ja4plus$ja4x$done = T;
}

event file_state_remove(f: fa_file) {
  if (!f?$info || !f$info?$x509 || !f$info$x509?$certificate) { return; }
  set_fingerprint(f);
  Log::write(JA4PLUS::JA4X::LOG, f$ja4plus$ja4x);
}
