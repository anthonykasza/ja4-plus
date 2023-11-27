# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_done()
	{
	print JA4PLUS::delimiter;
	print JA4PLUS::hash_trunc_len;
	}
