module FINGERPRINT;

export { type Info: record {}; }
redef record connection += { fp: FINGERPRINT::Info &optional; };

@load ./config
@load ./utils

@if (JA4S_enabled)
  @load ./ja4s
@endif

@if (JA4H_enabled)
  @load ./ja4h
@endif

@if (JA4SSH_enabled)
  @load ./ja4ssh
@endif

@if (JA4X_enabled)
  @load ./ja4x
@endif

@if (JA4L_enabled)
  @load ./ja4l
@endif
