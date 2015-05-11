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

module API_code = struct

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

type user_ids = {
  ids: int list;
  next_cursor: int;
  previous_cursor: int;
} [@@deriving show, yojson]

open Core_kernel.Std



type token_credentials = Oauth_client.token_credentials

module Get = struct

  let get_follower ~access_token ~screen_name () = 
    let base_uri = "https://api.twitter.com/1.1/followers/ids.json" in
    Oauth_client.do_get_request
      ~uri_parameters:["screen_name",screen_name;"cursor","-1";"count","5000"]
      ~uri:(Uri.of_string base_uri)
      ~access_token:access_token
      () >>= fun res ->
    match res with
    | Ok str -> print_endline str; return ()
    | Error e ->
      match e with
      | Oauth_client.HttpResponse (i, s) -> 
        Printf.printf "%d %s\n" i s; return ()
      | _ -> assert false
end
