# THis script is a combination of two scripts from the zeek project
#  base/protocols/http/utils.zeek
#  policy/protocols/http/var-extraction-cookies.zeek


@load base/protocols/http/main
@load base/protocols/http/utils

module HTTP;

redef record Info += {
	## Variable names extracted from all cookies.
	cookie_vars: vector of string &optional &log;
        
	## Variable values extracted from all cookies.
        cookie_vals: vector of string &optional &log;
};

function extract_values(data: string, kv_splitter: pattern): string_vec
	{
	local value_vec: vector of string = vector();

	local parts = split_string(data, kv_splitter);
	for ( part_index in parts )
		{
		local value_val = split_string1(parts[part_index], /=/);
		if ( 1 in value_val )
			value_vec += value_val[1];
		}
	return value_vec;
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=2
	{
	if ( is_orig && name == "COOKIE" )
		c$http$cookie_vars = extract_keys(value, /;[[:blank:]]*/);
		c$http$cookie_vals = extract_values(value, /;[[:blank:]]*/);
	}
