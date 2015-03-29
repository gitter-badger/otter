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

open Cryptokit

module type CLOCK = sig
  val get_timestamp : unit -> string
end

module type RANDOM = sig
  val get_nonce : unit -> string
end

module Clock : CLOCK = struct
  let get_timestamp () = Unix.gettimeofday () |> int_of_float |> string_of_int
end

module Random : RANDOM = struct
  let prng = Random.pseudo_rng (Random.string Random.secure_rng 20)

  let get_nonce () = Random.string prng 16
end

module type HMAC_SHA1 = sig
  type t
  val init : string -> t
  val add_string: t -> string -> t
  val result : t -> string
end

module HMAC_SHA1 : HMAC_SHA1 = struct
  type t = Cryptokit.hash

  let init = MAC.hmac_sha1

  let add_string hash s = hash#add_string s; hash

  let result hash = hash#result
end
