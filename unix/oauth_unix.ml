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

module Clock_unix : Oauth.CLOCK = struct
  let get_timestamp () = Unix.gettimeofday () |> int_of_float |> string_of_int
end

module Random_unix : Oauth.RANDOM = struct
  open Cryptokit
  (* as suggested in Crypokit *)
  let prng = Random.pseudo_rng (Random.string Random.secure_rng 20)

  let get_nonce () =
    let forbid = Re_posix.compile_pat "[^0-9a-zA-Z]" in
    let s = Random.string prng 40 |> B64.encode in
    Re.replace_string forbid ~by:"" s
end

module HMAC_SHA1_unix : Oauth.HMAC_SHA1 = struct
  open Cryptokit

  type t = Cryptokit.hash

  let init = MAC.hmac_sha1

  let add_string hash s = hash#add_string s; hash

  let result hash = hash#result
end


module Client = 
  Oauth.Make_OAuth_client
  (Clock_unix)(Random_unix)(HMAC_SHA1_unix)(Cohttp_lwt_unix.Client)
