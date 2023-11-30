module JA4PLUS::JA4L;

# double the size to support TTLs of UDP connections with large initial pkts
#  like QUIC which has an initial message lengths of >1200 bytes. 
redef dpd_buffer_size = 2048;

# Signatures only raise events once per endpoint per connection
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
