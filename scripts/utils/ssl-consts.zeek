module JA4;

export {
	const TLS_VERSION_MAPPER: table[count] of string = {
		# SSL
		[ 0x0002 ] = "s2",
		[ 0x0300 ] = "s3",

		# TLS
		[ 0x0301 ] = "10",
		[ 0x0302 ] = "11",
		[ 0x0303 ] = "12",
		[ 0x0304 ] = "13",

		# Experimental and draft 1.3 versions
		[ 0x7e01 ] = "xa",
		[ 0x7e02 ] = "xb",
		[ 0x7f0e ] = "xc",
		[ 0x7f0f ] = "xd",
		[ 0x7f10 ] = "xe",
		[ 0x7f11 ] = "xf",
		[ 0x7f12 ] = "xg",
		[ 0x7f13 ] = "xh",
		[ 0x7f14 ] = "xi",
		[ 0x7f15 ] = "xj",
		[ 0x7f16 ] = "xk",
		[ 0x7f17 ] = "xl",
		[ 0x7f18 ] = "xm",
		[ 0x7f19 ] = "xn",
		[ 0x7f1a ] = "xo",
		[ 0x7f1b ] = "xp",
		[ 0x7f1c ] = "xq",

		# Facebook draftversions
		[ 0xfb17 ] = "fa",
		[ 0xfb1a ] = "fb",

		# DTLS
		[ 0x0100 ] = "da",
		[ 0xfeff ] = "db",
		[ 0xfefd ] = "dc",
		[ 0xfefc ] = "dd",

		# Unknown
		[ 0x0 ] = "!!"
	} &default=function(i: count): string { return "??"; } &redef;

	const TLS_GREASE_TYPES: set[count] = { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
	    0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca,
	    0xdada, 0xeaea, 0xfafa };
}