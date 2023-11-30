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
    $service=set("FOO"),
    $history="",
    $uid="UUIIDD"
  ];

  local ja4l: JA4PLUS::JA4L::Info = [
    $resp_from_sensor=20usec,
    $orig_from_sensor=20usec,
    $resp_ttl=63,
    $orig_ttl=63,
  ];

  dummy$ja4plus = [];
  dummy$ja4plus$ja4l = ja4l;
  JA4PLUS::JA4L::set_fingerprint(dummy);
  Log::write(JA4PLUS::JA4L::LOG, dummy$ja4plus$ja4l);
}
