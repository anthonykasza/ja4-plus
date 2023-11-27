
module FINGERPRINT::JA4SSH;

export {
  # packet count rate
  option rate: count = 200;

  type Info: record {
    # uid of the connection this fingerprint represents
    uid: string &log &optional;

    # the fingerprint string
    ja4ssh: string &default="" &log;

    # a vector of lengths representing encrypted packets sent by the orig
    orig_pkt_lens: vector of count &default=vector();

    # a vector of lengths representing encrypted packets sent by the resp
    resp_pkt_lens: vector of count &default=vector();

    # a count of bare ACKs sent from the endpoint
    orig_ack_cnt: count &default=0;

    # a count of bare ACKs sent from the endpoint
    resp_ack_cnt: count &default=0;

    # whether this record is ready to be logged or not
    done: bool &default=F;
  };

  global set_fingerprint: function(c: connection);

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4ssh: event(rec: Info);
  global log_policy: Log::PolicyHook;

  # disable the default behavior of the SSH analyzer, which is to
  #  detach itself from the connection once encryption begins
  redef SSH::disable_analyzer_after_detection = T;
}

redef record FINGERPRINT::Info += {
  ja4ssh: FINGERPRINT::JA4SSH::Info &default=[];
};

event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4SSH::LOG,
    [$columns=FINGERPRINT::JA4SSH::Info, $ev=log_fingerprint_ja4ssh, $path="fingerprint_ja4ssh", $policy=log_policy]
  );
}

# given an array of lengths, find the modes and return the smallest
function find_mode(v: vector of count): count {
  local counts: table[count] of count;
  for (idx in v) {
    local pkt_len_UNIQNO9751394: count = v[idx];
    if (pkt_len_UNIQNO9751394 in counts) {
      counts[pkt_len_UNIQNO9751394] += 1;
    } else {
      counts[pkt_len_UNIQNO9751394] = 1;
    }
  }

  # find the pkt lengths which occured the max number of times
  local max: count = 0;
  local vals = table_values(counts);
  for (idx in vals) {
    # why doesn't type inference work here?
    local val: count = (vals[idx] as count);
    if (max == 0) {
      max = val;
      next;
    }
    if (val > max) {
      max = val;
    }
  }

  # for each of the pkt lengths which occured the max number of times
  #  find the smallest pkt length
  local min: count = 0;
  for (pkt_len_UNIQNO9389000, cnt in counts) {
    if (min == 0) {
      min = pkt_len_UNIQNO9389000;
      next;
    }
    if (cnt == max) {
      if (pkt_len_UNIQNO9389000 < min) {
        min = pkt_len_UNIQNO9389000;
      }
    }
  }
  return min;
}


# TODO - packet events are very expensive, consider removing this
#  or somehow making it performant
#  It'd be nice to see this information in an endpoint record: https://docs.zeek.org/en/master/scripts/base/init-bare.zeek.html#type-endpoint
#   it may be possible to add this functionality to the ConnSize analyzer
#   the ConnSize analyzer may also be a good place to add TTL/HOP_LIMIT observations done in ja4l
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
  # TODO - we only start counting bare-ass ACKs after the analyzer has confirmed this is an SSH connection
  #  the standard needs to clarify if we are counting bare ACKs from the inception of the connection or from a certain state forward
  #  for example, do we count the SYN+ACK in the handshake as a bare ACK since it carries no payload?
  if (!c?$ssh) { return; }
  if (len > 0 || ack == 0) { return; }
  if (is_orig) {
    c$fp$ja4ssh$orig_ack_cnt += 1;
  } else {
    c$fp$ja4ssh$resp_ack_cnt += 1;
  }
}

# set the ja4ssh fingerprint context for the connection
function set_fingerprint(c: connection) {
  c$fp$ja4ssh$uid = c$uid;
    
  local aaa: string = "";
  aaa += "c";
  aaa += fmt("%02d", find_mode(c$fp$ja4ssh$orig_pkt_lens));
  aaa += "s";
  aaa += fmt("%02d", find_mode(c$fp$ja4ssh$resp_pkt_lens));

  local bbb: string = "";
  bbb += "c";
  bbb += fmt("%02d", |c$fp$ja4ssh$orig_pkt_lens|);
  bbb += "s";
  bbb += fmt("%02d", |c$fp$ja4ssh$resp_pkt_lens|);

  local ccc: string = "";
  ccc += "c";
  ccc += fmt("%02d", c$fp$ja4ssh$orig_ack_cnt);;
  ccc += "s";
  ccc += fmt("%02d", c$fp$ja4ssh$resp_ack_cnt);;

  c$fp$ja4ssh$ja4ssh += aaa;
  c$fp$ja4ssh$ja4ssh += FINGERPRINT::delimiter;
  c$fp$ja4ssh$ja4ssh += bbb;
  c$fp$ja4ssh$ja4ssh += FINGERPRINT::delimiter;
  c$fp$ja4ssh$ja4ssh += ccc;

  c$fp$ja4ssh$done = T;
}

# append encrypted packet lengths to a vector and cut a fingerprint at a configured rate
event ssh_encrypted_packet(c: connection, orig: bool, len: count) {
  if (orig) {
    c$fp$ja4ssh$orig_pkt_lens += len;
  } else {
    c$fp$ja4ssh$resp_pkt_lens += len;
  }

  if ((|c$fp$ja4ssh$orig_pkt_lens| + |c$fp$ja4ssh$resp_pkt_lens|) % FINGERPRINT::JA4SSH::rate == 0) {
    # set it ...
    set_fingerprint(c);
    Log::write(FINGERPRINT::JA4SSH::LOG, c$fp$ja4ssh);
    # ... and forget it!
    c$fp$ja4ssh = [];
  }
}

# log fingerprints for connections with less than FINGERPRINT::JA4SSH::rate packets
event connection_state_remove(c: connection) {
  if (!c?$ssh) { return; }
  set_fingerprint(c);
  Log::write(FINGERPRINT::JA4SSH::LOG, c$fp$ja4ssh);
}
