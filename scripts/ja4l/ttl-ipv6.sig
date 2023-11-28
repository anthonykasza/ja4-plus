signature ipv6-orig-ttl-64 {
  header ip6[7] <= 64
  event "ipv6-orig-ttl-64"
}
signature ipv6-orig-ttl-128 {
  header ip6[7] > 64
  header ip6[7] <= 128
  event "ipv6-orig-ttl-128"
}
signature ipv6-orig-ttl-256 {
  header ip6[7] > 128
  header ip6[7] <= 256
  event "ipv6-orig-ttl-256"
}



signature ipv6-resp-ttl-64a {
  header ip6[7] <= 64
  requires-reverse-signature ipv6-orig-ttl-64
  event "ipv6-resp-ttl-64"
}
signature ipv6-resp-ttl-64b {
  header ip6[7] <= 64
  requires-reverse-signature ipv6-orig-ttl-128
  event "ipv6-resp-ttl-64"
}
signature ipv6-resp-ttl-64c {
  header ip6[7] <= 64
  requires-reverse-signature ipv6-orig-ttl-256
  event "ipv6-resp-ttl-64"
}

signature ipv6-resp-ttl-128a {
  header ip6[7] > 64
  header ip6[7] <= 128
  requires-reverse-signature ipv6-orig-ttl-64
  event "ipv6-resp-ttl-128"
}
signature ipv6-resp-ttl-128b {
  header ip6[7] > 64
  header ip6[7] <= 128
  requires-reverse-signature ipv6-orig-ttl-128
  event "ipv6-resp-ttl-128"
}
signature ipv6-resp-ttl-128c {
  header ip6[7] > 64
  header ip6[7] <= 128
  requires-reverse-signature ipv6-orig-ttl-256
  event "ipv6-resp-ttl-128"
}

signature ipv6-resp-ttl-256a {
  header ip6[7] > 128
  header ip6[7] <= 256
  requires-reverse-signature ipv6-orig-ttl-64
  event "ipv6-resp-ttl-256"
}
signature ipv6-resp-ttl-256b {
  header ip6[7] > 128
  header ip6[7] <= 256
  requires-reverse-signature ipv6-orig-ttl-128
  event "ipv6-resp-ttl-256"
}
signature ipv6-resp-ttl-256c {
  header ip6[7] > 128
  header ip6[7] <= 256
  requires-reverse-signature ipv6-orig-ttl-256
  event "ipv6-resp-ttl-256"
}

