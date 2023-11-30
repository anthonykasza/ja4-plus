module JA4PLUS;

export {
  # delimiter used to indicate different pieces of a fingerprint value
  option delimiter: string = "_";

  # truncated sha256 hash length
  option hash_trunc_len: count = 12;

  option JA4S_enabled:   bool = T; #done
  option JA4H_enabled:   bool = T; #done
  option JA4L_enabled:   bool = T;
  option JA4X_enabled:   bool = T;
  option JA4SSH_enabled: bool = T; #done

  # pkt count rate for SSH pkt level analysis
  option JA4PLUS::JA4SSH::rate: count = 200;

  # enable TTL estimates instead of exact observations
  #  enabling this option makes JA4L potentialy more performant
  #  but reduces the accuracy of JA4L
  option JA4PLUS::JA4L::enable_estimates: bool = T;
}
