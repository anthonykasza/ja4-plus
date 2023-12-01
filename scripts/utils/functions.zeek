
module JA4PLUS;

export {
  global trunc_sha256: function(input: string, hash_trunc_len: count &default=JA4PLUS::hash_trunc_len): string;
  global zero_string: function(hash_trunc_len: count): string;
  global vector_of_count_to_str: function(input: vector of count, format_str: string, dlimit: string): string;
  global extract_key_val: function(data: string, kv_splitter: pattern, key: bool): string_vec;
}

function extract_key_val(data: string, kv_splitter: pattern, key: bool): string_vec
        {
	local item: count;
	if (key)
		{
		item = 0;
		}
	else
		{
		item = 1;
		}
        local value_vec: vector of string = vector();

        local parts = split_string(data, kv_splitter);
        for ( part_index in parts )
                {
                local value_val = split_string1(parts[part_index], /=/);
                if ( item in value_val )
                        value_vec += value_val[item];
                }
        return value_vec;
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

function zero_string(hash_trunc_len: count &default=JA4PLUS::hash_trunc_len): string {
  local empty: string = "";
  local cnt: count = hash_trunc_len;
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
                return zero_string(hash_trunc_len);
                }
        local sha256_object = sha256_hash_init();
        sha256_hash_update(sha256_object, input);
        return sha256_hash_finish(sha256_object)[:hash_trunc_len];
        }
