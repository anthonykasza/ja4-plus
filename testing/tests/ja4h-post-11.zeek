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
    $hlist_vec=vector(
      [$original_name="Host", $name="HOST", $value="192.168.1.1"],
      [$original_name="Content-Length", $name="CONTENT-LENGTH", $value="664"],
      [$original_name="Accept", $name="ACCEPT", $value="application/json, text/javascript, */*; q=0.01"],
      [$original_name="X-Requested-With", $name="X-REQUESTED-WITH", $value="XMLHttpRequest"],
      [$original_name="User-Agent", $name="USER-AGENT", $value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36"],
      [$original_name="Content-Type", $name="CONTENT-TYPE", $value="application/x-www-form-urlencoded; charset=UTF-8"],
      [$original_name="Origin", $name="ORIGIN", $value="http://192.168.1.1"],
      [$original_name="Referer", $name="REFERER", $value="http://192.168.1.1/Main"],
      [$original_name="Accept-Encoding", $name="ACCEPT-ENCODING", $value="gzip, deflate"],
      [$original_name="Accept-Language", $name="ACCEPT-LANGUAGE", $value="en-US,en;q=0.9"],
      [$original_name="Cookie", $name="COOKIE", $value="example=d7df2dd0937ec27; ud_reload=UD_reload"],
      [$original_name="Connection", $name="CONNECTION", $value="close"],
    )
  ];

  dummy$http = h;
  dummy$ja4plus = [];
  dummy$ja4plus$ja4h = ja4h;
  JA4PLUS::JA4H::set_fingerprint(dummy);
  Log::write(JA4PLUS::JA4H::LOG, dummy$ja4plus$ja4h);
}
