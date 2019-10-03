
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