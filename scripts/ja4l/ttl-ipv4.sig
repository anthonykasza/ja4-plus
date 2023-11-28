signature ipv4-orig-ttl-64 {
  header ip[8] <= 64
  event "ipv4-orig-ttl-64"
}
signature ipv4-orig-ttl-128 {
  header ip[8] > 64
  header ip[8] <= 128
  event "ipv4-orig-ttl-128"
}
signature ipv4-orig-ttl-256 {
  header ip[8] > 128
  header ip[8] <= 256
  event "ipv4-orig-ttl-256"
}



signature ipv4-resp-ttl-64a {
  header ip[8] <= 64
  requires-reverse-signature ipv4-orig-ttl-64
  event "ipv4-resp-ttl-64"
}
signature ipv4-resp-ttl-64b {
  header ip[8] <= 64
  requires-reverse-signature ipv4-orig-ttl-128
  event "ipv4-resp-ttl-64"
}
signature ipv4-resp-ttl-64c {
  header ip[8] <= 64
  requires-reverse-signature ipv4-orig-ttl-256
  event "ipv4-resp-ttl-64"
}

signature ipv4-resp-ttl-128a {
  header ip[8] > 64
  header ip[8] <= 128
  requires-reverse-signature ipv4-orig-ttl-64
  event "ipv4-resp-ttl-128"
}
signature ipv4-resp-ttl-128b {
  header ip[8] > 64
  header ip[8] <= 128
  requires-reverse-signature ipv4-orig-ttl-128
  event "ipv4-resp-ttl-128"
}
signature ipv4-resp-ttl-128c {
  header ip[8] > 64
  header ip[8] <= 128
  requires-reverse-signature ipv4-orig-ttl-256
  event "ipv4-resp-ttl-128"
}

signature ipv4-resp-ttl-256a {
  header ip[8] > 128
  header ip[8] <= 256
  requires-reverse-signature ipv4-orig-ttl-64
  event "ipv4-resp-ttl-256"
}
signature ipv4-resp-ttl-256b {
  header ip[8] > 128
  header ip[8] <= 256
  requires-reverse-signature ipv4-orig-ttl-128
  event "ipv4-resp-ttl-256"
}
signature ipv4-resp-ttl-256c {
  header ip[8] > 128
  header ip[8] <= 256
  requires-reverse-signature ipv4-orig-ttl-256
  event "ipv4-resp-ttl-256"
}

