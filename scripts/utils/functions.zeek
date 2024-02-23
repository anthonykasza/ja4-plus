
module JA4PLUS;

export {
  global trunc_sha256: function(input: string, hash_trunc_len: count &default=JA4PLUS::hash_trunc_len): string;
  global zero_string: function(hash_trunc_len: count): string;
  global vector_of_count_to_str: function(input: vector of count, format_str: string, dlimit: string): string;
  global extract_key_val: function(data: string, kv_splitter: pattern, key: bool): string_vec;
}

# extract_key_val() was copied from a function in the Zeek project's "base" set of script
#  and modified slighly. As such...
#    Copyright (c) 1995-2023, The Regents of the University of California
#    through the Lawrence Berkeley National Laboratory and the
#    International Computer Science Institute. All rights reserved.
#    
#    Redistribution and use in source and binary forms, with or without
#    modification, are permitted provided that the following conditions are met:
#    
#    (1) Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#    
#    (2) Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#    
#    (3) Neither the name of the University of California, Lawrence Berkeley
#        National Laboratory, U.S. Dept. of Energy, International Computer
#        Science Institute, nor the names of contributors may be used to endorse
#        or promote products derived from this software without specific prior
#        written permission.
#    
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#    ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#    POSSIBILITY OF SUCH DAMAGE.
#    
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
