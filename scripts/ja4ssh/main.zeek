
module JA4PLUS::JA4SSH;

export {
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
  global log_ja4ssh: event(rec: Info);
  global log_policy: Log::PolicyHook;

  # disable the default behavior of the SSH analyzer, which is to
  #  detach itself from the connection once encryption begins
  redef SSH::disable_analyzer_after_detection = T;
}

redef record JA4PLUS::Info += {
  ja4ssh: JA4PLUS::JA4SSH::Info &default=[];
};

event zeek_init() &priority=5 {
  Log::create_stream(JA4PLUS::JA4SSH::LOG,
    [$columns=JA4PLUS::JA4SSH::Info, $ev=log_ja4ssh, $path="ja4ssh", $policy=log_policy]
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


# TODO - consider a TCP_Analyzer plugin instead because...
#  "This is a very low-level and expensive event that should
#   be avoided when at all possible. It’s usually infeasible
#   to handle when processing even medium volumes of traffic
#   in real-time. It’s slightly better than new_packet because
#   it affects only TCP, but not much. That said, if you work
#   from a trace and want to do some packet-level analysis, it
#   may come in handy."
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
  # TODO - we only start counting bare-ass ACKs after the analyzer has confirmed this is an SSH connection
  #  the standard needs to clarify if we are counting bare ACKs from the inception of the connection or from a certain state forward
  #  for example, do we count the SYN+ACK in the handshake as a bare ACK since it carries no payload?
  if (!c?$ssh) { return; }
  if (len > 0 || ack == 0) { return; }
  if (is_orig) {
    c$ja4plus$ja4ssh$orig_ack_cnt += 1;
  } else {
    c$ja4plus$ja4ssh$resp_ack_cnt += 1;
  }
}

# set the ja4ssh fingerprint context for the connection
function set_fingerprint(c: connection) {
  c$ja4plus$ja4ssh$uid = c$uid;
    
  local aaa: string = "";
  aaa += fmt("c%02d", find_mode(c$ja4plus$ja4ssh$orig_pkt_lens));
  aaa += fmt("s%02d", find_mode(c$ja4plus$ja4ssh$resp_pkt_lens));

  local bbb: string = "";
  bbb += fmt("c%02d", |c$ja4plus$ja4ssh$orig_pkt_lens|);
  bbb += fmt("s%02d", |c$ja4plus$ja4ssh$resp_pkt_lens|);

  local ccc: string = "";
  ccc += fmt("c%02d", c$ja4plus$ja4ssh$orig_ack_cnt);;
  ccc += fmt("s%02d", c$ja4plus$ja4ssh$resp_ack_cnt);;

  c$ja4plus$ja4ssh$ja4ssh += aaa;
  c$ja4plus$ja4ssh$ja4ssh += JA4PLUS::delimiter;
  c$ja4plus$ja4ssh$ja4ssh += bbb;
  c$ja4plus$ja4ssh$ja4ssh += JA4PLUS::delimiter;
  c$ja4plus$ja4ssh$ja4ssh += ccc;

  c$ja4plus$ja4ssh$done = T;
}

# append encrypted packet lengths to a vector and cut a fingerprint at a configured rate
event ssh_encrypted_packet(c: connection, orig: bool, len: count) {
  if (orig) {
    c$ja4plus$ja4ssh$orig_pkt_lens += len;
  } else {
    c$ja4plus$ja4ssh$resp_pkt_lens += len;
  }

  if ((|c$ja4plus$ja4ssh$orig_pkt_lens| + |c$ja4plus$ja4ssh$resp_pkt_lens|) % JA4PLUS::JA4SSH::rate == 0) {
    # set it ...
    set_fingerprint(c);
    Log::write(JA4PLUS::JA4SSH::LOG, c$ja4plus$ja4ssh);
    # ... and forget it!
    c$ja4plus$ja4ssh = [];
  }
}

# log fingerprints for connections with less than JA4PLUS::JA4SSH::rate packets
event connection_state_remove(c: connection) {
  if (!c?$ssh) { return; }
  set_fingerprint(c);
  Log::write(JA4PLUS::JA4SSH::LOG, c$ja4plus$ja4ssh);
}
