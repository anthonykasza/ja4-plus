module FINGERPRINT;

export {
  global HTTP_VERSION_MAPPER: table[string] of string ={
    ["1.0"] = "10",
    ["1.1"] = "11",
    ["2"] = "20",
    ["3"] = "30",
  };
}
