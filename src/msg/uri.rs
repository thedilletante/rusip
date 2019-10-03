
// SIP elements MAY support Request-URIs with schemes other than
// "sip" and "sips", for example the "tel" URI scheme of RFC
// 2806 [9].  SIP elements MAY translate non-SIP URIs using any
// mechanism at their disposal, resulting in SIP URI, SIPS URI,
// or some other scheme.

// Request-URI      =  SIP-URI / SIPS-URI / absoluteURI
// SIP-URI          =  "sip:" [ userinfo ] hostport
//                    uri-parameters [ headers ]
// SIPS-URI         =  "sips:" [ userinfo ] hostport
//                    uri-parameters [ headers ]

pub enum Uri {
  Absolute(),
  Sip(),
  Sips()
}
