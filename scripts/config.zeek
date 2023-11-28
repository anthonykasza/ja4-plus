module JA4PLUS;

export {
  # delimiter used to indicate different pieces of a fingerprint value
  option delimiter: string = "_";

  # truncated sha256 hash length
  option hash_trunc_len: count = 12;

  option JA4S_enabled:   bool = F;
  option JA4H_enabled:   bool = F;
  option JA4L_enabled:   bool = T;
  option JA4X_enabled:   bool = F;
  option JA4SSH_enabled: bool = F;

  # pkt count rate for SSH pkt level analysis
  option JA4SSH::rate: count = 200;
}
