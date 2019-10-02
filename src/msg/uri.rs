
// SIP elements MAY support Request-URIs with schemes other than
// "sip" and "sips", for example the "tel" URI scheme of RFC
// 2806 [9].  SIP elements MAY translate non-SIP URIs using any
// mechanism at their disposal, resulting in SIP URI, SIPS URI,
// or some other scheme.


// SIP-URI          =  "sip:" [ userinfo ] hostport
//                    uri-parameters [ headers ]
// SIPS-URI         =  "sips:" [ userinfo ] hostport
//                    uri-parameters [ headers ]
// userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
// user             =  1*( unreserved / escaped / user-unreserved )
// user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
// password         =  *( unreserved / escaped /
//                    "&" / "=" / "+" / "$" / "," )
// hostport         =  host [ ":" port ]
// port             =  1*DIGIT
// uri-parameters   =  *( ";" uri-parameter)
// uri-parameter    =  transport-param / user-param / method-param
//                    / ttl-param / maddr-param / lr-param / other-param
// transport-param  =  "transport="
//                    ( "udp" / "tcp" / "sctp" / "tls"
//                    / other-transport)
// other-transport  =  token
// user-param       =  "user=" ( "phone" / "ip" / other-user)
// other-user       =  token
// method-param     =  "method=" Method
// ttl-param        =  "ttl=" ttl
// maddr-param      =  "maddr=" host
// lr-param         =  "lr"
// other-param      =  pname [ "=" pvalue ]
// pname            =  1*paramchar
// pvalue           =  1*paramchar
// paramchar        =  param-unreserved / unreserved / escaped
// param-unreserved =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
// Request-URI      =  SIP-URI / SIPS-URI / absoluteURI
// absoluteURI      =  scheme ":" ( hier-part / opaque-part )
// hier-part        =  ( net-path / abs-path ) [ "?" query ]
// net-path         =  "//" authority [ abs-path ]
// abs-path         =  "/" path-segments
// opaque-part      =  uric-no-slash *uric
// uric             =  reserved / unreserved / escaped
// uric-no-slash    =  unreserved / escaped / ";" / "?" / ":" / "@"
//                    / "&" / "=" / "+" / "$" / ","
// path-segments    =  segment *( "/" segment )
// segment          =  *pchar *( ";" param )
// param            =  *pchar
// pchar            =  unreserved / escaped /
//                    ":" / "@" / "&" / "=" / "+" / "$" / ","
// scheme           =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
// authority        =  srvr / reg-name
// srvr             =  [ [ userinfo "@" ] hostport ]
// reg-name         =  1*( unreserved / escaped / "$" / ","
//                    / ";" / ":" / "@" / "&" / "=" / "+" )
// query            =  *uric

pub enum Uri {
  Absolute(),
  Sip(),
  Sips()
}
