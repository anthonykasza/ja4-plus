# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4h.log | zeek-cut ja4h r o ro > ja4h.filtered
# @TEST-EXEC: btest-diff ja4h.filtered
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
    $service=set("HTTP"),
    $history="",
    $uid="UUIIDD"
  ];

  local h: HTTP::Info = [
    $ts=dummy$start_time,
    $uid=dummy$uid,
    $id=dummy$id,
    $method="POST",
    $trans_depth=0,
    $tags=set(HTTP::EMPTY)
  ];

  local ja4h: JA4PLUS::JA4H::Info = [
    $client_version="1.1",
    $hlist=table(
      [0] = [$original_name="hOsT", $name="HOST", $value="foo.localhost"],
      [1] = [$original_name="User-Agent", $name="USER-AGENT", $value="Mozilla/5.0"],
      [2] = [$original_name="REFERER", $name="REFERER", $value="http://www.example.com/"],
      [3] = [$original_name="ACCEPT-LANGUAGE", $name="ACCEPT-LANGUAGE", $value="fr-C, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5"],
      [4] = [$original_name="COOKIE", $name="COOKIE", $value="PHPSESSID=298zf09hf012fh2; FOO=BAR;"],
    )
  ];

  dummy$http = h;
  dummy$ja4plus = [];
  dummy$ja4plus$ja4h = ja4h;
  JA4PLUS::JA4H::set_fingerprint(dummy);
  Log::write(JA4PLUS::JA4H::LOG, dummy$ja4plus$ja4h);
}
