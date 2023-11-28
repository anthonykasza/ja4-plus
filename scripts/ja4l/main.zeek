# Measure the "distance" between the sensor and connections' endpoints as
#  an interval of time
#
# This measurement only works because handshakes are supposed to happen 
#  as fast as possible. If we were to measure round trip times mid-stream,
#  there may be some application logic which slows down the transmissions.
#  For example, consider a client sending a database query to the server.
#   the server may take a while to process the request, read the data off
#   a disk drive, format the data, and send it back to the client.
#

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
    orig: string &log &default="";

    # ja4l responder
    resp: string &log &default="";

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

# Find the largest TTL or HLIM value for each endpoint by
#  checking the packet headers of EVERY packet in a connection... 
# TODO - make this usable at scale or ditch TTL analysis
#  consider writing a plugin that extends the c$orig and c$resp endpoint records
#  similar to how the ConnSize analyzer adds num_bytes_ip and num_pkts
#  have the analyzer raise an event to scriptland when the TTL value of an endpoint changes during the connection
#  handle that event from scriptland and use it to calculate a mean TTL value for use here
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

function set_quic_handshake(c: connection) {
  local idx: count;

  # from the first client time to the first server time
  idx = 0;
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
    c$ja4plus$ja4l$resp_from_sensor = (c$ja4plus$ja4l$history_state_ivals[rf_idx] - c$ja4plus$ja4l$history_state_ivals[of_idx] / 2.0);
  }

  # from the last server time to the last client time
  idx = |c$quic$history_state| - 1;
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
    c$ja4plus$ja4l$orig_from_sensor = (c$ja4plus$ja4l$history_state_ivals[ol_idx] - c$ja4plus$ja4l$history_state_ivals[rl_idx] / 2.0);
  }
}

function set_fingerprint(c: connection) {
  if (c?$quic) { set_quic_handshake(c); }
  
  c$ja4plus$ja4l$uid = c$uid;

  local orig_hops: count = 0;
  if (!c$ja4plus$ja4l?$orig_ttl || c$ja4plus$ja4l$orig_ttl <= 64) {
    orig_hops = 64;
  } else if (c$ja4plus$ja4l$orig_ttl > 64 && c$ja4plus$ja4l$orig_ttl <= 128) {
    orig_hops = 128;
  } else {
    orig_hops = 255;
  }
  # if we missed part of the handshake and could not time it, set it to 0
  if (!c$ja4plus$ja4l?$orig_from_sensor) {
    c$ja4plus$ja4l$orig = fmt("C=%04d_%03d", 0, orig_hops);
  } else {
    # TODO figure out if this * 100000 value is really what should be done
    c$ja4plus$ja4l$orig = fmt("C=%04d_%03d", double_to_count(100000 * interval_to_double(c$ja4plus$ja4l$orig_from_sensor)), orig_hops);
  }

  local resp_hops: count = 0;
  # if we couldn't find any TTLs we set it to 64 anyways
  if (!c$ja4plus$ja4l?$resp_ttl || c$ja4plus$ja4l$resp_ttl <= 64) {
    resp_hops = 64;
  } else if (c$ja4plus$ja4l$resp_ttl > 64 && c$ja4plus$ja4l$resp_ttl <= 128) {
    resp_hops = 128;
  } else {
    resp_hops = 255;
  }

  # if we missed part of the handshake and could not time it, set it to 0
  if (!c$ja4plus$ja4l?$resp_from_sensor) {
    c$ja4plus$ja4l$resp = fmt("S=%04d_%03d", 0, resp_hops);
  } else {
    # TODO figure out if this * 100000 value is really what should be done
    c$ja4plus$ja4l$resp = fmt("S=%04d_%03d", double_to_count(100000 * interval_to_double(c$ja4plus$ja4l$resp_from_sensor)), resp_hops);
  }

  c$ja4plus$ja4l$done = T;
}

event connection_state_remove(c: connection) {
  if (c$conn$proto != tcp && !c?$quic) { return; }
  set_fingerprint(c);
  Log::write(JA4PLUS::JA4L::LOG, c$ja4plus$ja4l);
}
