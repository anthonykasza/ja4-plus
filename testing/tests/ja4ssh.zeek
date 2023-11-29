# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: cat ja4ssh.log | zeek-cut ja4ssh  > ja4ssh.filtered
# @TEST-EXEC: btest-diff ja4ssh.filtered
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
    $service=set("SSH"),
    $history="",
    $uid="UUIIDD"
  ];

  local ssh: JA4PLUS::JA4SSH::Info = [
    $orig_pkt_lens=vector(36, 36, 36, 10),
    $resp_pkt_lens=vector(36, 36, 36, 10),
    $orig_ack_cnt=70,
    $resp_ack_cnt=0
  ];

  dummy$ja4plus = [];
  dummy$ja4plus$ja4ssh = ssh;
  JA4PLUS::JA4SSH::set_fingerprint(dummy);
  Log::write(JA4PLUS::JA4SSH::LOG, dummy$ja4plus$ja4ssh);
}
