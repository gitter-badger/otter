(*
 * Copyright (c) 2014 Dominic Price <dominic.price@nottingham.ac.uk>
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

open Core_kernel.Std
open Lwt

module type CLOCK = sig
  val get_timestamp : unit -> string
end

module type RANDOM = sig
  val get_nonce : unit -> string
end

module type HMAC_SHA1 = sig
  type t
  val init : string -> t
  val add_string: t -> string -> t
  val result : t -> string
end

module Clock : CLOCK = struct
  let get_timestamp () = Unix.gettimeofday () |> Int.of_float |> string_of_int
end

module Random : RANDOM = struct
  open Cryptokit
  (* as suggested in Crypokit *)
  let prng = Random.pseudo_rng (Random.string Random.secure_rng 20)

  let get_nonce () =
    let forbid = Re_posix.compile_pat "[^0-9a-zA-Z]" in
    let s = Random.string prng 40 |> B64.encode in
    Re.replace_string forbid ~by:"" s
end

module HMAC_SHA1 : HMAC_SHA1 = struct
  open Cryptokit

  type t = Cryptokit.hash

  let init = MAC.hmac_sha1

  let add_string hash s = hash#add_string s; hash

  let result hash = hash#result
end

(** [credentials] are a pair of a token and a matching shared secret
    
    Token is a unique identifier issued by the server and
    used by the client to associate authenticated requests with
    the resource owner whose authorization is requested or
    has been obtained by the client

    Shared secret, along with the token, will be used
    by the client to establish its ownership of the token,
    and its authority to represent the resource owner *)

type credentials = string * string
                     
(** Temporary credentials *)
type temporary_credentials = {
  consumer_key : string;
  consumer_secret : string;
  token : string;
  token_secret : string;
  callback_confirmed : bool;
  authorization_uri : Uri.t
}
  
  (** Token credentials *)
type token_credentials = {
  consumer_key : string;
  consumer_secret : string;
  token : string;
  token_secret : string;
}


module type OAuth_client = sig
  
  (** Type of HTTP reponse error *)
  type error = 
    | HttpResponse of int * string (** HTTP response code *)
    | Exception of exn (** HTTP Exception *)

  val print_authorization_uri : temporary_credentials -> unit
  
  (** [fetch_request_token], given [request_uri] *)
  val fetch_request_token : 
      ?callback : Uri.t ->
      request_uri : Uri.t ->
      authorization_uri : Uri.t ->
      consumer_key : string ->
      consumer_secret : string ->
      unit ->
      (temporary_credentials, error) Result.t Lwt.t
  
  val fetch_access_token :
      access_uri : Uri.t ->
      request_token : temporary_credentials ->
      verifier : string ->
      unit ->
      (token_credentials, error) Result.t Lwt.t

  val do_get_request :
      ?uri_parameters : (string * string) list ->
      ?expect : Cohttp.Code.status_code ->
      uri : Uri.t ->
      access_token : token_credentials ->
      unit ->
      (string, error) Result.t Lwt.t

  val do_post_request :
      ?uri_parameters : (string * string) list ->
      ?body_parameters : (string * string) list ->
      ?expect : Cohttp.Code.status_code ->
      uri : Uri.t ->
      access_token : token_credentials ->
      unit ->
      (string, error) Result.t Lwt.t
end

module type SIGNATURE = sig
  val add_signature : 
    ?body_parameters : (string * string) list ->
    ?callback : Uri.t  ->
    ?token : string ->
    ?token_secret : string ->
    consumer_key : string ->
    consumer_secret : string ->
    request_method : [ | `Post | `Get ] ->
    uri : Uri.t ->
    Cohttp.Header.t ->
    Cohttp.Header.t
end

module Util = struct
  let pct_encode src = 
    let dst = String.length src |> Buffer.create in
    String.iter ~f:(function 
      | c when 
        (c >= '0' && c <= '9') 
        || (c >= 'A' && c <= 'Z')
        || (c >= 'a' && c <= 'z')
        || c = '-'
        || c = '.'
        || c = '_'
        || c = '~' -> Buffer.add_char dst c
      | c -> Char.to_int c |>
        Printf.sprintf "%%%02X" |>
        Buffer.add_string dst) src; 
    Buffer.contents dst
end

module Make_Signature   
  (Clock: CLOCK) 
  (Random: RANDOM)
  (HMAC_SHA1: HMAC_SHA1): SIGNATURE = struct
  
  let add_signature
    ?body_parameters: (parameters: (string * string) list = [])
    ?callback: (callback: Uri.t option)
    ?token: (token: string option)
    ?token_secret: (token_secret: string = "")
    ~consumer_key: consumer_key
    ~consumer_secret: consumer_secret
    ~request_method: (request_method: [ | `Post | `Get ])
    ~uri: uri
    headers = 

    (* RFC 5849 section 3.1 *)
    let oauth_params = [
      "oauth_consumer_key", consumer_key;
      "oauth_nonce", Random.get_nonce ();
      "oauth_signature_method", "HMAC-SHA1";
      "oauth_timestamp", Clock.get_timestamp ();
      "oauth_version", "1.0" 
      ]
      |> List.append (match callback with
          | Some callback -> ["oauth_callback", Uri.to_string callback]
          | None -> []) 
      |> List.append (match token with
          | Some token -> ["oauth_token", token]
          | None -> []) 
    in
    let uri_without_query = List.fold_left ~init:uri 
        ~f:(fun acc (e, _) -> Uri.remove_query_param acc e) (Uri.query uri) 
    in
    let (|+) = HMAC_SHA1.add_string in
    let hmac = (Util.pct_encode consumer_secret) ^ 
      "&" ^ (Util.pct_encode token_secret) |>
      HMAC_SHA1.init |+
      (match request_method with `Post -> "POST&" | `Get -> "GET&") |+
      (Uri.to_string uri_without_query |> Util.pct_encode) |+ "&" |>
      fun hmac -> 
        let quries = Uri.query uri in
        let fold_f acc (k, vs) =
          match (List.hd vs) with
          | None -> List.append acc [k, ""]
          | _ -> List.map vs ~f:(fun v -> (k, v)) |> List.append acc in
        List.fold quries ~init:parameters ~f:fold_f |>
        List.append oauth_params |>
        List.map ~f:(fun (k, v) -> (Util.pct_encode k, Util.pct_encode v)) |>
        (* bug fixed: values should be compared when keys are the same *)
        List.sort ~cmp:(fun kv1 kv2 -> compare kv1 kv2) |> 
        List.foldi ~init:hmac ~f:(fun i hmac (key, value) ->
          hmac |+
          (match i with | 0 -> "" | _ -> Util.pct_encode "&") |+
          key |+ (Util.pct_encode "=") |+ value)
    in
    let buf = Buffer.create 16 in
    let buf_add = Buffer.add_string buf in
    buf_add "OAuth oauth_signature=\"";
    HMAC_SHA1.result hmac |> B64.encode |> Util.pct_encode |> buf_add;
    buf_add "\"";
    List.iter ~f:(fun (key, value) ->
        buf_add ",";
        buf_add key;
        buf_add "=\"";
        buf_add value;
        buf_add "\"";     
      ) oauth_params;
    Cohttp.Header.add headers "Authorization" (Buffer.contents buf)
end

module Make_OAuth_client 
  (Clock: CLOCK) 
  (Random: RANDOM)
  (HMAC_SHA1: HMAC_SHA1)
  (Client: Cohttp_lwt.Client) : OAuth_client = struct

  type error =
    | HttpResponse of int * string
    | Exception of exn

  exception Authorization_failed of int * string

  module Sign = Make_Signature(Clock)(Random)(HMAC_SHA1)
  module Code = Cohttp.Code
  module Body = Cohttp_lwt_body
  module Header = Cohttp.Header
  module Response = Client.Response

  let print_authorization_uri (tc:temporary_credentials) =
    Printf.printf "authorization_uri: %s\n" (Uri.to_string tc.authorization_uri)
    
  let fetch_request_token
    ?callback:(callback: Uri.t option)
    ~request_uri
    ~authorization_uri
    ~consumer_key
    ~consumer_secret
    () =
    let header = Sign.add_signature
      ?callback
      ~consumer_key: consumer_key
      ~consumer_secret: consumer_secret
      ~request_method: `Post
      ~uri: request_uri
      (Header.init_with "Content-Type" "application/x-www-form-urlencoded")
    in
    Client.post ~headers:header request_uri >>= (fun (resp, body) ->
    (match Response.status resp with
      | `Code c -> c
      | status -> Code.code_of_status status) |> 
    (function
      | 200 -> Body.to_string body >>= fun body_s ->
         let find key = 
           List.Assoc.find_exn (Uri.query_of_encoded body_s) key 
            |> List.hd_exn 
         in
         return (
           let token = find "oauth_token" in
           try
             Ok ({
               consumer_key = consumer_key;
               consumer_secret = consumer_secret;
               token = token;
               token_secret = 
                 find "oauth_token_secret";
               callback_confirmed = 
                 find "oauth_callback_confirmed" |> Bool.of_string;
               authorization_uri = 
                 Uri.add_query_param' 
                  authorization_uri ("oauth_token", token);
             })
           with _ as e -> Error(Exception e))
      | c -> Body.to_string body >>= fun b -> 
        return (Error(HttpResponse (c, b)))))

  let fetch_access_token 
    ~access_uri 
    ~(request_token:temporary_credentials)
    ~verifier 
    () =
    let header = Sign.add_signature
      ~body_parameters: [("oauth_verifier", verifier)] 
      ~token: request_token.token 
      ~token_secret: request_token.token_secret
      ~consumer_key: request_token.consumer_key
      ~consumer_secret: request_token.consumer_secret
      ~request_method: `Post
      ~uri: access_uri
      (Header.init_with "Content-Type" "application/x-www-form-urlencoded") in
    let body = Body.of_string ("oauth_verifier=" ^ (Util.pct_encode verifier))
    in
    Client.post ~body:body ~headers:header ~chunked:false access_uri >>= 
      fun (resp, body) ->
      (match Response.status resp with
       | `Code c -> c
       | status -> Code.code_of_status status) |> 
      (function
       | 200 -> Body.to_string body >>= fun body_s ->
         let find k = 
           List.Assoc.find_exn (Uri.query_of_encoded body_s) k 
           |> List.hd_exn in
         return (
           try 
             Ok({
               consumer_key = request_token.consumer_key;
               consumer_secret = request_token.consumer_secret;
               token = find "oauth_token";
               token_secret = find "oauth_token_secret";
             })
           with _ as e -> Error(Exception e)
         )
       | c -> Body.to_string body >>= fun b -> 
         return (Error (HttpResponse (c, b))))

  let do_get_request 
    ?uri_parameters: (uri_parameters: (string * string) list = [])
    ?expect: (expect:Cohttp.Code.status_code = `OK)
    ~uri
    ~(access_token: token_credentials)
    () =
    let uri_with_query = Uri.add_query_params' uri uri_parameters in
    let header = Sign.add_signature
      ~token: access_token.token
      ~token_secret: access_token.token_secret
      ~consumer_key: access_token.consumer_key
      ~consumer_secret: access_token.consumer_secret
      ~request_method: `Get
      ~uri:uri_with_query
      (Header.init_with "Content-Type" "application/x-www-form-urlencoded")
    in
    Client.get ~headers:header uri_with_query >>= 
     fun (resp, body) ->
      (match Response.status resp with
       | `Code c -> c
       | status -> Code.code_of_status status) |>
      (function 
       | c when c = (Code.code_of_status expect) ->
          Body.to_string body >>= fun body_s -> return (Ok body_s)
       | c -> Body.to_string body >>= fun body_s ->
          return (Error (HttpResponse (c, body_s))))

  let do_post_request
    ?uri_parameters: (uri_parameters: (string * string) list = [])
    ?body_parameters: (body_parameters: (string * string) list = [])
    ?expect: (expect = `OK)
    ~uri
    ~(access_token: token_credentials)
    () =
    let uri_with_query = Uri.add_query_params' uri uri_parameters in
    let encoded_bp = body_parameters |>
      List.map ~f:(fun (k, v) -> (k, Util.pct_encode v)) in
    let header = Sign.add_signature
      ~body_parameters: encoded_bp
      ~token: access_token.token
      ~token_secret: access_token.token_secret
      ~consumer_key: access_token.consumer_key
      ~consumer_secret: access_token.consumer_secret
      ~request_method: `Post
      ~uri: uri_with_query
      (Header.init_with "Content-Type" "application/x-www-form-urlencoded")
    in
    let body =
      let buf = Buffer.create 16 in
      List.iteri ~f:(fun i (k, v) ->
        (match i with | 0 -> () | _ -> Buffer.add_char buf '&';
        Buffer.add_string buf (Util.pct_encode k);
        Buffer.add_char buf '=';
        Buffer.add_string buf (Util.pct_encode v)))
        body_parameters;
      Buffer.contents buf |> Body.of_string
    in
    Client.post ~body:body ~headers:header ~chunked:false uri_with_query >>=
     fun (resp, body) ->
      (match Response.status resp with
       | `Code c -> c
       | s -> Code.code_of_status s)
     |> 
     (function
      | c when c = (Code.code_of_status expect) -> Body.to_string body >>=
        fun body_s -> return (Ok body_s)
      | c -> Body.to_string body >>= fun body ->
        return (Error (HttpResponse (c, body))))
end

include Make_OAuth_client(Clock)(Random)(HMAC_SHA1)(Cohttp_lwt_unix.Client)
