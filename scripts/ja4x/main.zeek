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

  # TODO - write a function which computes hex values from 
  #  decimal/period string, then get rid of this lookup table
  #  REFERENCES for the conversion function:
  #   - https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
  #   - https://luca.ntop.org/Teaching/Appunti/asn1.html5.9 OBJECT IDENTIFIER
  const oid_lookup: table[string] of count = {
    ["1.3.6.1.5.5.7.1.1"] = 0,
    ["2.5.29.32"] = 0,
    ["2.5.29.35"] = 0,
    ["2.5.29.19"] = 0,
    ["1.3.6.1.4.1.11129.2.4.2"] = 0,
    ["2.5.4.10"] = 0x55040a,
    ["2.5.4.3"] = 0x550403,
  };

  # TODO - find an authoritative list of all rdn attributes
  #  If we can map abbreviated string to oid, we can then compute
  #  the hex value from the oid
  const rdn_lookup: table[string] of count = {
    ["DC"] = 0,     # domainComponent
    ["CN"] = 0x550403,     # commonName, 2.5.4.3
    ["OU"] = 0,     # organizationalUnitName
    ["O"] = 0x55040a,      # organizationName, 2.5.4.10
    ["STREET"] = 0,
    ["L"] = 0,      # locality
    ["ST"] = 0,     # stateOrProvinceName
    ["C"] = 0x550406,      # countryName, 2.5.4.6
    ["UID"] = 0,    # 
    ["SN"] = 0,     # surName
  };

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

# We use this same function is ja4h for cookie values
function extract_values(data: string, kv_splitter: pattern): string_vec
        {
        local value_vec: vector of string = vector();

        local parts = split_string(data, kv_splitter);
        for ( part_index in parts )
                {
                local value_val = split_string1(parts[part_index], /=/);
                # 0 - extract RDN keys
                # 1 - extract RDN values
                if ( 0 in value_val )
                        value_vec += value_val[0];
                }
        return value_vec;
        }

function set_fingerprint(f: fa_file) {
  f$ja4plus$ja4x$fuid = f$id;

  # Issuer RDNs
  local issuer_rdns_cntvec: vector of count = vector();
  local issuer_rdns_strvec = extract_values(f$info$x509$certificate$issuer, /,[[:blank:]]*/);
  for (idx in issuer_rdns_strvec) {
    local key = issuer_rdns_strvec[idx];
    if (key in rdn_lookup) {
      issuer_rdns_cntvec += rdn_lookup[key];
    } else {
      # if we cannot find the oid, use 0xffffff
      issuer_rdns_cntvec += 0xffffff;
    }
  }
  local aaa: string = JA4PLUS::vector_of_count_to_str(issuer_rdns_cntvec, "%06x");

  # Subject RDNs
  local subject_rdns_cntvec: vector of count = vector();
  local subject_rdns_strvec = extract_values(f$info$x509$certificate$subject, /,[[:blank:]]*/);
  for (idx_UNIQNO1973333 in subject_rdns_strvec) {
    local key_UNIQNO85685487 = subject_rdns_strvec[idx_UNIQNO1973333];
    if (key_UNIQNO85685487 in rdn_lookup) {
      subject_rdns_cntvec += rdn_lookup[key_UNIQNO85685487];
    } else {
      # if we cannot find the oid, use 0xffffff
      subject_rdns_cntvec += 0xffffff;
    }
  }
  local bbb: string = JA4PLUS::vector_of_count_to_str(subject_rdns_cntvec, "%06x");

  # TODO - test to see if this order is indeed the order in which they extension appear
  #  if not, we may need to write x509_extension event bodies to built the vector ourselves
  # Extensions
  local extension_oids: vector of count = vector();
  for (idx in f$info$x509$extensions) {
    local extension = f$info$x509$extensions[idx];
    if (extension$oid in oid_lookup) {
      extension_oids += oid_lookup[extension$oid];
    } else {
      # if we cannot find the oid, use 0xffffff
      extension_oids += 0xffffff;
    }
  }
  local ccc: string = JA4PLUS::vector_of_count_to_str(extension_oids, "%06x");

  # ja4x_r
  f$ja4plus$ja4x$r = aaa;
  f$ja4plus$ja4x$r += JA4PLUS::delimiter;
  f$ja4plus$ja4x$r += bbb;
  f$ja4plus$ja4x$r += JA4PLUS::delimiter;
  f$ja4plus$ja4x$r += ccc;
  
  # ja4x
  f$ja4plus$ja4x$ja4x += JA4PLUS::trunc_sha256(aaa);
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
