# Grab TTL information from the headers of the first 2 packets ONLY
# TTLs are reported in buckets instead of exact observations
# Buckets are:
#  - 0 to 64
#  - 65 to 128
#  - 129 to 256

@load-sigs ./ttl-ipv4.sig
@load-sigs ./ttl-ipv6.sig

module JA4PLUS::JA4L;

# double the size to support large initial packets
redef dpd_buffer_size = 2048;

# Signatures only raise events once per endpoint per connection
#  making this approach performant but less accurate
event signature_match(state: signature_state, msg: string, data: string) {
  switch msg {
    case "ipv4-orig-ttl-64", "ipv6-orig-ttl-64":
      if (!state$conn?$ja4plus) { state$conn$ja4plus = []; }
      state$conn$ja4plus$ja4l$orig_ttl = 64;
      break;
    case "ipv4-orig-ttl-128", "ipv6-orig-ttl-128":
      if (!state$conn?$ja4plus) { state$conn$ja4plus = []; }
      state$conn$ja4plus$ja4l$orig_ttl = 128;
      break;
    case "ipv4-orig-ttl-256", "ipv6-orig-ttl-256":
      if (!state$conn?$ja4plus) { state$conn$ja4plus = []; }
      state$conn$ja4plus$ja4l$orig_ttl = 256;
      break;
    case "ipv4-resp-ttl-64", "ipv6-resp-ttl-64":
      if (!state$conn?$ja4plus) { state$conn$ja4plus = []; }
      state$conn$ja4plus$ja4l$resp_ttl = 64;
      break;
    case "ipv4-resp-ttl-128", "ipv6-resp-ttl-128":
      if (!state$conn?$ja4plus) { state$conn$ja4plus = []; }
      state$conn$ja4plus$ja4l$resp_ttl = 128;
      break;
    case "ipv4-resp-ttl-256", "ipv6-resp-ttl-256":
      if (!state$conn?$ja4plus) { state$conn$ja4plus = []; }
      state$conn$ja4plus$ja4l$resp_ttl = 256;
      break;
  }
}
