signature ipv4-ttl-orig-64 {
  header ip[8] <= 64
  event "ipv4-ttl-orig-64"
}

signature ipv4-ttl-resp-64 {
  header ip[8] <= 64
  requires-reverse-signature ipv4-ttl-orig-64
  event "ipv4-ttl-resp-64"
}

signature ipv4-ttl-orig-128 {
  header ip[8] > 64
  header ip[8] <= 128
  event "ipv4-ttl-orig-128"
}

signature ipv4-ttl-resp-128 {
  header ip[8] > 64
  header ip[8] <= 128
  requires-reverse-signature ipv4-ttl-orig-128
  event "ipv4-ttl-resp-128"
}

signature ipv4-ttl-orig-256 {
  header ip[8] > 128
  header ip[8] <= 256
  event "ipv4-ttl-orig-256"
}

signature ipv4-ttl-resp-256 {
  header ip[8] > 128
  header ip[8] <= 256
  requires-reverse-signature ipv4-ttl-orig-256
  event "ipv4-ttl-resp-256"
}

signature ipv6-ttl-orig-64 {
  header ip6[7] <= 64
  event "ipv6-ttl-orig-64"
}

signature ipv6-ttl-resp-64 {
  header ip6[7] <= 64
  requires-reverse-signature ipv6-ttl-orig-64
  event "ipv6-ttl-resp-64"
}

signature ipv6-ttl-orig-128 {
  header ip6[7] > 64
  header ip6[7] <= 128
  event "ipv6-ttl-orig-128"
}

signature ipv6-ttl-resp-128 {
  header ip6[7] > 64
  header ip6[7] <= 128
  requires-reverse-signature ipv6-ttl-orig-128
  event "ipv6-ttl-resp-128"
}

signature ipv6-ttl-orig-256 {
  header ip6[7] > 128
  header ip6[7] <= 256
  event "ipv6-ttl-orig-256"
}

signature ipv6-ttl-resp-256 {
  header ip6[7] > 128
  header ip6[7] <= 256
  requires-reverse-signature ipv6-ttl-orig-256
  event "ipv6-ttl-resp-256"
}
