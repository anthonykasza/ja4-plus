module JA4PLUS::JA4L;


function add_to_history_ivals(c: connection) {
  if (|c$ja4plus$ja4l$history_state_ivals| == QUIC::max_history_length) { return; }
  c$ja4plus$ja4l$history_state_ivals += network_time() - c$start_time;
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
  if (!c?$quic) { return;}
  add_to_history_ivals(c);
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=-5 {
  if (!c?$quic) { return; }
  add_to_history_ivals(c);
}

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
  add_to_history_ivals(c);
}

event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
  add_to_history_ivals(c);
}

event QUIC::zero_rtt_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
  add_to_history_ivals(c);
}

event QUIC::retry_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string, retry_token: string, integrity_tag: string) {
  add_to_history_ivals(c);
}

event QUIC::connection_close_frame(c: connection, is_orig: bool, version: count, dcid: string, scid: string, error_code: count, reason_phrase: string) {
  add_to_history_ivals(c);
}
