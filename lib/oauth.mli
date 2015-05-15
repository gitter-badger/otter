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

(** credential is a pair of a token and a matching shared secret
      
    Token is a unique identifier issued by the server and
    used by the client to associate authenticated requests with
    the resource owner whose authorization is requested or
    has been obtained by the client

    Shared secret, along with the token, will be used
    by the client to establish its ownership of the token,
    and its authority to represent the resource owner *)

type temporary_credentials = {
  consumer_key : string;
  consumer_secret : string;
  token : string;
  token_secret : string;
  callback_confirmed : bool;
  authorization_uri : string;
} 
  
type token_credentials = {
  consumer_key : string;
  consumer_secret : string;
  token : string;
  token_secret : string;
} [@@deriving show]

(** Interface of OAuth v1.0 client *)
module type OAuth_client = sig
  
  (** Type of HTTP reponse error *)
  type oauth_error = 
    | HttpResponse of int * string (** HTTP response code *)
    | Exception of exn (** HTTP Exception *)

  (** [fetch_request_token], given [request_uri], fetches
      the temperary crendentials *)
  val fetch_request_token : 
      ?callback : Uri.t ->
      request_uri : Uri.t ->
      authorization_uri : Uri.t ->
      consumer_key : string ->
      consumer_secret : string ->
      unit ->
      (temporary_credentials, oauth_error) Result.t Lwt.t

  (** [fetch_access_token], given [temporary_credentials], fetches
      the token credentials *)
  val fetch_access_token :
      access_uri : Uri.t ->
      request_token : temporary_credentials ->
      verifier : string ->
      unit ->
      (token_credentials, oauth_error) Result.t Lwt.t

  (** [do_get_request], given [access_token],
      performs a HTTP GET request *)
  val do_get_request :
      ?uri_parameters : (string * string) list ->
      ?expect : Cohttp.Code.status_code ->
      uri : Uri.t ->
      access_token : token_credentials ->
      unit ->
      ((Cohttp.Header.t * string), oauth_error) Result.t Lwt.t

  (** [do_post_request], given [access_token], 
      performs a HTTP POST request *)
  val do_post_request :
      ?uri_parameters : (string * string) list ->
      ?body_parameters : (string * string) list ->
      ?expect : Cohttp.Code.status_code ->
      uri : Uri.t ->
      access_token : token_credentials ->
      unit ->
      ((Cohttp.Header.t * string), oauth_error) Result.t Lwt.t
end

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

module Make_OAuth_client
    (Clock: CLOCK)
    (Random: RANDOM)
    (HMAC_SHA1: HMAC_SHA1)
    (Client:Cohttp_lwt.Client) : OAuth_client

