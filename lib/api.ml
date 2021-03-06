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

open Lwt
open Yojson

module API_error_code = struct

  (** Please refer to https://dev.twitter.com/overview/api/response-codes *)
  type t =
    [ `Could_not_auth_call_could_not_be_completed
    | `Page_not_exist
    | `Account_suspended_not_permitted_to_access_feature
    | `Rest_API_v1_no_longer_active
    | `Rate_limit_exceeded
    | `Invalid_or_expired_token
    | `SSL_required
    | `Over_capacity
    | `Internal_error
    | `Cound_not_auth_bad_oauth_timestamp
    | `Unable_to_follow
    | `Not_authorized_to_see_status
    | `Over_daily_status_update_limit
    | `Duplicate_status
    | `Bad_authentication_data
    | `Possible_automated_request
    | `Must_verify_login
    | `Invalid_end_point
    | `Cannot_perform_write_actions
    | `Cannot_mute_yourself
    | `Specified_user_not_muted
    ] [@@deriving show]

  let to_code = function
    | `Could_not_auth_call_could_not_be_completed -> 32
    | `Page_not_exist -> 34
    | `Account_suspended_not_permitted_to_access_feature -> 64
    | `Rest_API_v1_no_longer_active -> 68
    | `Rate_limit_exceeded -> 88
    | `Invalid_or_expired_token -> 89
    | `SSL_required -> 92
    | `Over_capacity -> 130
    | `Internal_error -> 131
    | `Cound_not_auth_bad_oauth_timestamp -> 135
    | `Unable_to_follow -> 161
    | `Not_authorized_to_see_status -> 179
    | `Over_daily_status_update_limit -> 185
    | `Duplicate_status -> 187
    | `Bad_authentication_data -> 215
    | `Possible_automated_request -> 226
    | `Must_verify_login -> 231
    | `Invalid_end_point -> 251
    | `Cannot_perform_write_actions -> 261
    | `Cannot_mute_yourself -> 271
    | `Specified_user_not_muted -> 272

  let of_code = function
    | 32 ->  `Could_not_auth_call_could_not_be_completed
    | 34 ->  `Page_not_exist
    | 64 ->  `Account_suspended_not_permitted_to_access_feature
    | 68 ->  `Rest_API_v1_no_longer_active
    | 88 ->  `Rate_limit_exceeded
    | 89 ->  `Invalid_or_expired_token
    | 92 ->  `SSL_required
    | 130 -> `Over_capacity
    | 131 -> `Internal_error
    | 135 -> `Cound_not_auth_bad_oauth_timestamp
    | 161 -> `Unable_to_follow
    | 179 -> `Not_authorized_to_see_status
    | 185 -> `Over_daily_status_update_limit
    | 187 -> `Duplicate_status
    | 215 -> `Bad_authentication_data
    | 226 -> `Possible_automated_request
    | 231 -> `Must_verify_login
    | 251 -> `Invalid_end_point
    | 261 -> `Cannot_perform_write_actions
    | 271 -> `Cannot_mute_yourself
    | 272 -> `Specified_user_not_muted
    | _ -> assert false

end

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
} [@@deriving show,yojson]

type token_credentials = Oauth.token_credentials

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

module Make_API (Client: Oauth.OAuth_client) : API = struct

  module Header = Cohttp.Header
  
  let process_error_exn e =
    match e with
    | Client.HttpResponse (c, b) -> begin
        let json = Yojson.Basic.from_string b in
        let open Yojson.Basic.Util in
        let errors = json |> member "errors" |> to_list |> List.hd in
        { http_response_code = c;
          error_msg = errors |> member "message" |> to_string;
          error_code = errors |> member "code" |> to_int
        }
      end
    | Client.Exception excep -> raise excep

  module Get = struct

    let get_follower ~access_token ~screen_name ?(count=5000) ?(wait=true) () =
      let base_uri = "https://api.twitter.com/1.1/followers/ids.json" in
      let cursor = ref (-1) in
      let f () =
        print_endline "api call";
        if !cursor = 0 then return None else
        Client.do_get_request
          ~uri_parameters:
            ["screen_name", screen_name;
             "cursor", (string_of_int (!cursor));
             "count", (string_of_int count)]
          ~uri:(Uri.of_string base_uri)
          ~access_token:access_token
        () >>= fun res ->
        match res with
        | `Ok (h, b_str) -> begin
          match (Yojson.Safe.from_string b_str |> user_ids_of_yojson) with
          | `Ok uids -> 
            cursor := uids.next_cursor;
            return (Some (`Ok uids))
          | `Error msg -> failwith msg 
          end
        | `Error e -> return (Some (`Error (process_error_exn e))) in
      Lwt_stream.from f
  end

end

