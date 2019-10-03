
// userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
// user             =  1*( unreserved / escaped / user-unreserved )
// user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
// password         =  *( unreserved / escaped /
//                    "&" / "=" / "+" / "$" / "," )

// The BNF for telephone-subscriber can be found in RFC 2806 [9].  Note,
// however, that any characters allowed there that are not allowed in
// the user part of the SIP URI MUST be escaped.

// telephone-scheme      = "tel"
// telephone-subscriber  = global-phone-number / local-phone-number
// global-phone-number   = "+" base-phone-number [isdn-subaddress]
//                          [post-dial] *(area-specifier /
//                          service-provider / future-extension)
// base-phone-number     = 1*phonedigit
// local-phone-number    = 1*(phonedigit / dtmf-digit /
//                          pause-character) [isdn-subaddress]
//                          [post-dial] area-specifier
//                          *(area-specifier / service-provider /
//                          future-extension)
// isdn-subaddress       = ";isub=" 1*phonedigit
// post-dial             = ";postd=" 1*(phonedigit /
//                          dtmf-digit / pause-character)
// area-specifier        = ";" phone-context-tag "=" phone-context-ident
// phone-context-tag     = "phone-context"
// phone-context-ident   = network-prefix / private-prefix
// network-prefix        = global-network-prefix / local-network-prefix
// global-network-prefix = "+" 1*phonedigit
// local-network-prefix  = 1*(phonedigit / dtmf-digit / pause-character)
// private-prefix        = (%x21-22 / %x24-27 / %x2C / %x2F / %x3A /
//                          %x3C-40 / %x45-4F / %x51-56 / %x58-60 /
//                          %x65-6F / %x71-76 / %x78-7E)
//                          *(%x21-3A / %x3C-7E)
//
// ; Characters in URLs must follow escaping rules
// ; as explained in [RFC2396]
// ; See sections 1.2 and 2.5.2
//
// service-provider      = ";" provider-tag "=" provider-hostname
// provider-tag          = "tsp"
// provider-hostname     = domain ; <domain> is defined in [RFC1035]
// ; See section 2.5.10
// future-extension      = ";" 1*(token-char) ["=" ((1*(token-char)
//                          ["?" 1*(token-char)]) / quoted-string )]
// ; See section 2.5.11 and [RFC2543]
// token-char            = (%x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39
//                          / %x41-5A / %x5E-7A / %x7C / %x7E)
// ; Characters in URLs must follow escaping rules
// ; as explained in [RFC2396]
// ; See sections 1.2 and 2.5.11
// quoted-string         = %x22 *( "\" CHAR / (%x20-21 / %x23-7E
//                         / %x80-FF )) %x22
//                        ; Characters in URLs must follow escaping rules
//                        ; as explained in [RFC2396]
//                        ; See sections 1.2 and 2.5.11
// phonedigit            = DIGIT / visual-separator
// visual-separator      = "-" / "." / "(" / ")"
// pause-character       = one-second-pause / wait-for-dial-tone
// one-second-pause      = "p"
// wait-for-dial-tone    = "w"
// dtmf-digit            = "*" / "#" / "A" / "B" / "C" / "D"
