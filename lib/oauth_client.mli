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


(** Interface of OAuth v1.0 client *)
module type OAuth_Client = sig
  
  (** Type of HTTP reponse error *)
  type error = 
    | HttpResponse of int * string (** HTTP response code *)
    | Exception of exn (** HTTP Exception *)

  (** [token] is a unique identifier issued by the server and
      used by the client to associate authenticated requests with
      the resource owner whose authorization is requested or
      has been obtained by the client *)
  type token = string

  (** [shared_secret], along with the {!token}, will be used
      by the client to establish its ownership of the {!token},
      and its authority to represent the resource owner *)
  type shared_secret = string
  
  (** [credentials] are a pair of a token and a matching shared secret *)
  type credentials = token * shared_secret

  (** Temporary credentials *)
  type temporary_credentials = {
    consumer_key : string;
    consumer_secret : string;
    credentials: credentials;
    callback_confirmed : bool;
    authorization_uri : Uri.t
  }
  
  (** Token credentials *)
  type token_credentials = {
    consumer_key : string;
    consumer_secret : string;
    credentials: credentials;
  }
  
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
      request_token : string ->
      verifier : string ->
      (token_credentials, error) Result.t Lwt.t
      
  val do_get_request :
      ?uri_parameters : (string * string) list ->
      ?expect : Cohttp.Code.status_code ->
      uri : Uri.t ->
      access_token : string ->
      unit ->
      (string, error) Result.t Lwt.t
      
  val do_post_request :
      ?uri_parameters : (string * string) list ->
      ?body_parameters : (string * string) list ->
      ?expect : Cohttp.Code.status_code ->
      uri : Uri.t ->
      access_token : string ->
      unit ->
      (string, error) Result.t Lwt.t
  
end