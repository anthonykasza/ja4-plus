module JA4PLUS::JA4L;

# Get the largest TTL or HOPL value by analyzing ALL packets in the connection
event new_packet(c: connection, p: pkt_hdr) {
  if (!c?$ja4plus) { c$ja4plus = []; }
  if (!c$ja4plus?$ja4l) { c$ja4plus$ja4l = []; }

  # ipv4
  if (p?$ip) {
    # is_orig = T
    if (p$ip$dst == c$id$resp_h) {
      if (c$ja4plus$ja4l?$orig_ttl) {
        c$ja4plus$ja4l$orig_ttl = c$ja4plus$ja4l$orig_ttl > p$ip$ttl ? c$ja4plus$ja4l$orig_ttl : p$ip$ttl;
      } else {
        c$ja4plus$ja4l$orig_ttl = p$ip$ttl;
      }
    # is_orig = F
    } else {
      if (c$ja4plus$ja4l?$resp_ttl) {
        c$ja4plus$ja4l$resp_ttl = c$ja4plus$ja4l$resp_ttl > p$ip$ttl ? c$ja4plus$ja4l$resp_ttl : p$ip$ttl;
      } else {
        c$ja4plus$ja4l$resp_ttl = p$ip$ttl;
      }
    }
  # ipv6
  } else if (p?$ip6) {
    # is_orig = T
    if (p$ip6$dst == c$id$resp_h) {
      if (c$ja4plus$ja4l?$orig_ttl) {
        c$ja4plus$ja4l$orig_ttl = c$ja4plus$ja4l$orig_ttl > p$ip6$hlim ? c$ja4plus$ja4l$orig_ttl : p$ip6$hlim;
      } else {
        c$ja4plus$ja4l$orig_ttl = p$ip6$hlim;
      }
    # is_orig = F
    } else {
      if (c$ja4plus$ja4l?$resp_ttl) {
        c$ja4plus$ja4l$resp_ttl = c$ja4plus$ja4l$resp_ttl > p$ip6$hlim ? c$ja4plus$ja4l$resp_ttl : p$ip6$hlim;
      } else {
        c$ja4plus$ja4l$resp_ttl = p$ip6$hlim;
      }
    }
  }
}
