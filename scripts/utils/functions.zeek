
module JA4PLUS;

export {
  global trunc_sha256: function(input: string, hash_trunc_len: count &default=JA4PLUS::hash_trunc_len): string;
  global zero_string: function(): string;
  global vector_of_count_to_str: function(input: vector of count, format_str: string, dlimit: string): string;
}

function vector_of_count_to_str(input: vector of count, format_str: string &default="%04x", dlimit: string &default=","): string {
  local output: string = "";
  for (idx, val in input) {
    output += fmt(format_str, val);
    if (idx < |input|-1) {
      output += dlimit;
    }
  }
  return output;
}

function zero_string(): string {
  local empty: string = "";
  local cnt: count = JA4PLUS::hash_trunc_len;
  while ( cnt > 0 ) {
    empty += "0";
    cnt -= 1;
  }
  return empty;
}

# truncated sha256 or all zeros for empty string
function trunc_sha256(input: string, hash_trunc_len: count
    &default=JA4PLUS::hash_trunc_len): string
        {
        if ( |input| == 0 )
                {
                local empty: string = "";
                local cnt: count = hash_trunc_len;
                while ( cnt > 0 )
                        {
                        empty += "0";
                        cnt -= 1;
                        }
                return empty;
                }
        local sha256_object = sha256_hash_init();
        sha256_hash_update(sha256_object, input);
        return sha256_hash_finish(sha256_object)[:hash_trunc_len];
        }
