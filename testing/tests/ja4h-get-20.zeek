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
    $method="GET",
    $trans_depth=0,
    $tags=set(HTTP::EMPTY)
  ];

  # This record is constructed with input values from the JA4+ technical specifications
  #  Note that the example in the docs has multiple inconsistencies in it
  #  which is why we get a different output value than the docs  
  local ja4h: JA4PLUS::JA4H::Info = [
    $client_version="2",
    $hlist_vec=vector(
      [$original_name="Host", $name="HOST", $value="www.cnn.com"],
      [$original_name="Cookie", $name="COOKIE", $value="FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726"],
      [$original_name="Sec-Ch-Ua", $name="SEC-CH-UA", $value=""],
      [$original_name="Sec-Ch-Ua-Mobile", $name="SEC-CH-UA-MOBILE", $value="?0"],
      [$original_name="User-Agent", $name="USER-AGENT", $value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36"],
      [$original_name="Sec-Ch-Ua-Platform", $name="SEC-CH-UA-PLATFORM", $value="\"\""],
      [$original_name="Accept", $name="ACCEPT", $value="*/*"],
      [$original_name="Sec-Fetch-Site", $name="SEC-FETCH-SITE", $value="same-origin"],
      [$original_name="Sec-Fetch-Mode", $name="SEC-FETCH-MODE", $value="cors"],
      [$original_name="Sec-Fetch-Dest", $name="SEC-FETCH-DEST", $value="empty"],
      [$original_name="Referer", $name="REFERER", $value="https://www.cnn.com/"],
      [$original_name="Accept-Encoding", $name="ACCEPT-ENCODING", $value="gzip, deflate"],
      [$original_name="Accept-Language", $name="ACCEPT-LANGUAGE", $value="en-US,en;q=0.9"],
    )
  ];

  dummy$http = h;
  dummy$ja4plus = [];
  dummy$ja4plus$ja4h = ja4h;
  JA4PLUS::JA4H::set_fingerprint(dummy);
  Log::write(JA4PLUS::JA4H::LOG, dummy$ja4plus$ja4h);
}
