# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4s.log | zeek-cut ja4s r > ja4s.filtered
# @TEST-EXEC: btest-diff ja4s.filtered
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
    $service=set("SSL"),
    $history="",
    $uid="UUIIDD"
  ];

  local sh: JA4PLUS::JA4S::ServerHello = [
    $version=0x0303,
    $cipher_suite=0xc030,
    $extension_codes=vector(0x0005,0x0017,0xff01,0x0000),
    $alpns=vector("00")
  ];

  dummy$ja4plus = [];
  dummy$ja4plus$server_hello = sh;
  JA4PLUS::JA4S::set_fingerprint(dummy);
  Log::write(JA4PLUS::JA4S::LOG, dummy$ja4plus$ja4s);
}
