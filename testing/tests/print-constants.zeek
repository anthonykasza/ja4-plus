# @TEST-EXEC: zeek $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_done()
	{
	print FINGERPRINT::delimiter;
	print FINGERPRINT::hash_trunc_len;
	}
