
module FINGERPRINT;

export {
  global trunc_sha256: function(input: string, hash_trunc_len: count &default=FINGERPRINT::hash_trunc_len): string;
}

# truncated sha256 or all zeros for empty string
function trunc_sha256(input: string, hash_trunc_len: count
    &default=FINGERPRINT::hash_trunc_len): string
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
