#require "netclient,nettls-gnutls";;

open Printf

let () =
  Nettls_gnutls.init()

let demo1() =
  (* Get a file listing from an HTTP server, and download the first txt file *)
  let fs = Nethttp_fs.http_fs "http://ftp.debian.org/debian/" in
  let files = fs # readdir [] "/" in
  printf "Files: %s\n%!" (String.concat "," files);
  let txt = List.find (fun p -> Filename.check_suffix p ".txt") files in
  let ch = fs # read [] ("/" ^ txt) in
  let data = Netchannels.string_of_in_obj_channel ch in
  ch # close_in();
  printf "File:\n%s\n\n%!" data

let demo2() =
  (* the same for FTP *)
  let fs = Netftp_fs.ftp_fs "ftp://ftp.debian.org/debian/" in
  let files = fs # readdir [] "/" in
  printf "Files: %s\n%!" (String.concat "," files);
  let txt = List.find (fun p -> Filename.check_suffix p ".txt") files in
  let ch = fs # read [] ("/" ^ txt) in
  let data = Netchannels.string_of_in_obj_channel ch in
  ch # close_in();
  printf "File:\n%s\n\n%!" data


(* There are also netfs implementations for local file access
   (Netfs) and for accessing files via shell login (for an scp-like
   utility: Shell_fs)
 *)

(* TLS demo: *)

let ca =
  (* AddTrust External Root *)
  "-----BEGIN CERTIFICATE-----
MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU
MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs
IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290
MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux
FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h
bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt
H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9
uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX
mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX
a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN
E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0
WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD
VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0
Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU
cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN
AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH
YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5
6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC
Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX
c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a
mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=
-----END CERTIFICATE-----"

let ca_parsed =
  match
    Netascii_armor.parse
      [ "CERTIFICATE", `Base64 ] 
      (new Netchannels.input_string ca)
  with
    | [ _, `Base64 body ] -> body#value
    | _ -> failwith "parser error"

   

let demo3() =
  (* For HTTP, TLS is automatically enabled once GnuTLS is initialized.
     You may want to tune this. Here we restrict the certificates (if you
     don't change the options, all system-wide certs are trusted).
   *)
  let tls_config =
    Netsys_tls.create_x509_config
      ~trust:[ `DER [ ca_parsed ] ]
      ~peer_auth:`Required
      (module Nettls_gnutls.TLS) in
  let fs = Nethttp_fs.http_fs
             ~config_pipeline:(fun p ->
                                 let opts = p # get_options in
                                 let opts' =
                                   { opts with
                                     Nethttp_client.tls = Some tls_config
                                   } in
                                 p # set_options opts'
                              )
             "https://www.debian.org/" in
  let ch = fs # read [] "/sitemap" in
  let data = Netchannels.string_of_in_obj_channel ch in
  ch # close_in();
  printf "DATA: %s\n\n%!" data


let demo4() =
  (* For FTP, you need to explicitly enable TLS. I haven't found any
     public FTP server with TLS support though.
   *)
  let fs = 
    Netftp_fs.ftp_fs
      ~tls_enabled:true
      ~tls_required:true
      "ftp://host/" in
  let files = fs # readdir [] "/" in
  printf "Files: %s\n%!" (String.concat "," files);
  let txt = List.find (fun p -> Filename.check_suffix p ".txt") files in
  let ch = fs # read [] ("/" ^ txt) in
  let data = Netchannels.string_of_in_obj_channel ch in
  ch # close_in();
  printf "File:\n%s\n\n%!" data
