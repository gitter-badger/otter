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

let api_keys =
  let open Yojson.Basic in
  let json_list = Util.to_list (from_file "api_key.json") in
  let to_string j = 
    let s = to_string j in
    String.sub s 1 ((String.length s) - 2) in
  let mapf ass =
    {Oauth.consumer_key = ass |> Util.member "consumer_key" |> to_string;
     Oauth.consumer_secret = ass |> Util.member "consumer_secret" |> to_string;
     Oauth.token = ass |> Util.member "access_token" |> to_string;
     Oauth.token_secret = ass |> Util.member "access_token_secret" |> to_string
    } in
  List.map mapf json_list |> Array.of_list

let screen_name = "nytchinese";;

let api i = 
  let a = Array.get api_keys i in
  print_endline ("using api"^(string_of_int i));
  print_endline (Oauth.show_token_credentials a);
  a


module A = Api_unix

let iter_follower () = 
  let stream = A.Get.get_follower ~access_token:(api 1) ~screen_name () in
  let rec loop stream =
    Lwt_stream.get stream >>= fun res ->
    match res with
    | Some r -> begin
      match r with
      | `Ok _ -> print_endline "ok"; Lwt_unix.sleep 1.0 >>= fun () -> loop stream
      | `Error e -> print_endline (Api.show_error_response e); loop stream
          end
    | None -> return () in
  loop stream

let () = Lwt_unix.run (iter_follower ()) 



