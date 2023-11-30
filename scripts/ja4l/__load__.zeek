@load ./main
@load ./quic-handshake.zeek

@if (JA4PLUS::JA4L::enable_estimates)
  @load base/frameworks/signatures
  @load-sigs ./ttl-ipv4.sig
  @load-sigs ./ttl-ipv6.sig
  @load ./approx-ttls
@else
  @load ./exact-ttls
@endif

