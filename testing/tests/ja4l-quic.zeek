# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4l.log | zeek-cut resp_from_sensor orig_from_sensor resp_ttl orig_ttl orig_ja4l resp_ja4l  > ja4l.filtered
# @TEST-EXEC: btest-diff ja4l.filtered
# @TEST-EXEC: btest-diff output

event zeek_done() {
  local dummy: connection = [
    $id=[
      $orig_h=1.1.1.1,
      $orig_p=1/tcp,
      $resp_h=2.2.2.2,
      $resp_p=2/tcp
    ],
    $orig=[$size=0, $state=0, $flow_label=0],
    $resp=[$size=0, $state=0, $flow_label=0],
    $start_time=network_time(),
    $duration=0msec,
    $service=set("QUIC"),
    $history="",
    $uid="UUIIDD"
  ];

  local ja4l: JA4PLUS::JA4L::Info = [
    $resp_ttl=64,
    $orig_ttl=64,
    $history_state_ivals=vector(0secs, 0secs, 40.0msecs, 40.0msecs, 40.0msecs, 40.0msecs, 41.0msecs, 41.0msecs, 87.0msecs, 87.0msecs, 89.0msecs)
  ];

  dummy$ja4plus = [];
  dummy$ja4plus$ja4l = ja4l;
  JA4PLUS::JA4L::set_fingerprint(dummy);
  Log::write(JA4PLUS::JA4L::LOG, dummy$ja4plus$ja4l);
}
