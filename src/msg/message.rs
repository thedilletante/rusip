

use super::request::Request;
use super::response::Response;

enum Message <'buf> {
  Request(Request),
  Response(Response<'buf>)
}