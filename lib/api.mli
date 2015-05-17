(*
 * Copyright (c) 2015 Runhang Li <marklrh@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)


type token_credentials = Oauth.token_credentials

type error_response = {
  http_response_code: int;
  error_msg: string;
  error_code: int;
} [@@deriving show,yojson]

type user_ids = {
  ids: int list;
  next_cursor: int;
  next_cursor_str: string;
  previous_cursor: int;
  previous_cursor_str: string
} [@@deriving show, yojson]

module type API = sig

  module Get : sig

    val get_follower : 
      access_token : token_credentials ->
      screen_name : string ->
      ?count: int -> 
      ?wait: bool ->
      unit ->
      [> `Ok of user_ids | `Error of error_response] Lwt_stream.t
    
  end

end

module Make_API (Client: Oauth.OAuth_client) : API
