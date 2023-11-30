@load ./main
@load ./tcp-handshake
@load ./quic-handshake.zeek

@if (JA4PLUS::JA4L::enable_approx_ttls)
  @load ./approx-ttls
@else
  @load ./exact-ttls
@endif

