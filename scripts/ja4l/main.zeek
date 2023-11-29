module JA4PLUS::JA4L;

export {
  type Info: record {
    uid: string &optional &log;

    # Sensor observes the Originator sending a SYN to the Responder
    #   ___      _      ___
    #  | O |--->|S|    | R |
    #  |___|    |_|    |___|
    #
    # We do not record this value as it is set in c$start_time

    # Sensor observes the Responder sending a SYN+ACK to the Originator
    #   ___      _      ___
    #  | O |    |S|--->| R |
    #  |___|    |_|<---|___|
    #
    resp_from_sensor: interval &optional &log;
    
    # Sensor observes the Originator sending a ACK with optional DATA to the Responder
    #   ___      _      ___
    #  | O |<---|S|    | R |
    #  |___|--->|_|    |___|
    #
    orig_from_sensor: interval &optional &log;

    # TTL or HLIM value take from IP header
    resp_ttl: count &optional &log;

    # TTL or HLIM value take from IP header
    orig_ttl: count &optional &log;

    # ja4l originator
    orig_ja4l: string &log &default="";

    # ja4l responder
    resp_ja4l: string &log &default="";

    # QUIC history intervals if the connection is QUIC, otherwise empty
    history_state_ivals: vector of interval &default=vector();

    # If this structure is ready to be logged
    done: bool &default=F;
  };

  global set_fingerprint: function(c: connection);

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_ja4l: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record JA4PLUS::Info += {
  ja4l: JA4PLUS::JA4L::Info &default=[];
};

# double the size to support TTLs of UDP connections with large initial pkts
#  like QUIC which has an initial message lengths of >1200 bytes. 
redef dpd_buffer_size = 2048;


event zeek_init() &priority=5 {
  Log::create_stream(JA4PLUS::JA4L::LOG,
    [$columns=JA4PLUS::JA4L::Info, $ev=log_ja4l, $path="ja4l", $policy=log_policy]
  );
}

# Find the interval between the sensor and responder
event connection_established(c: connection) {
  if (!c?$ja4plus) { c$ja4plus = []; }
  if (!c$ja4plus?$ja4l) { c$ja4plus$ja4l = []; }
  c$ja4plus$ja4l$resp_from_sensor = (network_time() - c$start_time) / 2.0;
}

# find the interval between the sensor and originator
event connection_first_ACK(c: connection) {
  if (!c?$ja4plus) { c$ja4plus = []; }
  if (!c$ja4plus?$ja4l) { c$ja4plus$ja4l = []; }
  c$ja4plus$ja4l$orig_from_sensor = (network_time() - c$start_time - c$ja4plus$ja4l$resp_from_sensor) / 2.0;
}

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

# Set the *_from_sensor values based on the QUIC handshake
#  https://en.wikipedia.org/wiki/QUIC#/media/File:Tcp-vs-quic-handshake.svg
function set_quic_handshake(c: connection) {
  if (!c?$quic) { return; }
  local idx: count;

  # from the first client time to the first server time
  idx = 0; # traverse the history forwards
  local of_idx: int = -1;
  local rf_idx: int = -1;
  while (idx < |c$quic$history_state|) {
    # find first orig time
    if (c$quic$history_state[idx] == to_upper(c$quic$history_state[idx])) {
      of_idx = idx;
    }
    # find first resp time
    if (c$quic$history_state[idx] == to_lower(c$quic$history_state[idx])) {
      rf_idx = idx;
    }
    if (of_idx > -1 && rf_idx > -1) { break; }
    idx += 1;
  }
  if (of_idx > -1 && rf_idx > -1) {
    c$ja4plus$ja4l$resp_from_sensor = (c$ja4plus$ja4l$history_state_ivals[rf_idx] - c$ja4plus$ja4l$history_state_ivals[of_idx]) / 2.0;
  }

  # from the last server time to the last client time
  idx = |c$quic$history_state| - 1; # traverse the history backwards
  local ol_idx: int = -1;
  local rl_idx: int = -1;
  while (idx >= 0) {
    # find last orig time
    if (c$quic$history_state[idx] == to_upper(c$quic$history_state[idx])) {
      ol_idx = idx;
    }
    # find last resp time
    if (c$quic$history_state[idx] == to_lower(c$quic$history_state[idx])) {
      rl_idx = idx;
    }
    if (ol_idx > -1 && rl_idx > -1) { break; }
    idx -= 1;
  }
  if (ol_idx > -1 && rl_idx > -1) {
    c$ja4plus$ja4l$orig_from_sensor = (c$ja4plus$ja4l$history_state_ivals[ol_idx] - c$ja4plus$ja4l$history_state_ivals[rl_idx]) / 2.0;
  }
}

# Set the fingerprint strings based on the values accumulated in the Info recrod
function set_fingerprint(c: connection) {
  set_quic_handshake(c);
  
  c$ja4plus$ja4l$uid = c$uid;

  # if we could not time the orig <-> sensor
  if (!c$ja4plus$ja4l?$orig_from_sensor) {
    c$ja4plus$ja4l$orig_from_sensor = 0sec;
  }

  # if we could not time the sensor <-> resp
  if (!c$ja4plus$ja4l?$resp_from_sensor) {
    c$ja4plus$ja4l$resp_from_sensor = 0sec;
  }

  # if we could not find an orig ttl then the connection may not be over IP
  if (!c$ja4plus$ja4l?$orig_ttl) {
    c$ja4plus$ja4l$orig_ttl = 0;
  }

  # if we could not find a resp ttl then the connection may have been one-sided
  if (!c$ja4plus$ja4l?$resp_ttl) {
    c$ja4plus$ja4l$resp_ttl = 0;
  }

  # TODO - is this the correct format multiplier? 
  # TODO - what happens when the latency is great than 7 digits, %07d?
  #        is there a maximum latency value?
  local multiplier = 1000000;

  c$ja4plus$ja4l$orig_ja4l = fmt(
    "C=%07d_%03d",
    double_to_count(multiplier * interval_to_double(c$ja4plus$ja4l$orig_from_sensor)),
    c$ja4plus$ja4l$orig_ttl
  );
  c$ja4plus$ja4l$resp_ja4l = fmt(
    "S=%07d_%03d",
    double_to_count(multiplier * interval_to_double(c$ja4plus$ja4l$resp_from_sensor)),
    c$ja4plus$ja4l$resp_ttl
  );

  c$ja4plus$ja4l$done = T;
}

event connection_state_remove(c: connection) {
  if (c$conn$proto != tcp && !c?$quic) { return; }
  set_fingerprint(c);
  Log::write(JA4PLUS::JA4L::LOG, c$ja4plus$ja4l);
}
