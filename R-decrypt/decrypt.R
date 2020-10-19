library(openssl)
library(rjson)


decrypt.field <- function(input) {
  tryCatch({
    result <- input
    input.l <- fromJSON(input)
    if (!identical(c("payload", "token", "iv"), names(input.l)))
      return(input)  
    input.b <- lapply(input.l, base64_decode)
    key <- read_key("key.pem")
    plain.b <- decrypt_envelope(input.b$payload, input.b$iv, input.b$token, key)
    result <- rawToChar(plain.b)
  },
  error=function(e) {print(e)})
  return(result)
}

decrypt.csv <- function (f, new.file=paste0("decrypted_", f)) {
  report <- read.csv(f, header=T, as.is=T)
  nb.dec <- 0
  for (r in seq(nrow(report))) {
    for (c in seq(ncol(report))) {
      dec <- decrypt.field(report[r,c])
      if (!identical(dec, report[r,c])) {
        report[r,c] <- dec
        nb.dec <- nb.dec + 1
      }
    }
  }
  write.csv(report, new.file, row.names=F)
  print(sprintf("%d fields were decrypted", nb.dec))
  return(list(report, nb.dec))
}


#### Test deryption with known text encrypted in REDCap

test.enc <- '{"payload":"wRczHB+hc4Dv/cnDMzKBeg==","token":"ndlvI6TVDrkt5WPgnvlY5UWGO9lZL8xBYeEtl0zQ8Q6Uvi+3QRyfc4GH5DqLr0YfpWXzW1C013OlOMHtpcSWx48QVEA5Nx37gIOjIgjTyJZlURWIu6i2bV0u12BhzggwB0e0+vrkfH0+qeXz/Is1R6suFUITzbo6Ax4UYILeCe6No+Isygh8rMvRtxBarbQaejxfokoiv+cS/AmxQJibAC4pYiCd3kp4ZRynLiPEAYBuBhgpJL4TlOUVuUu810iYU570GzA83W7V+Z3TXKUkpfVo7mWnKAQhRT1uUScghAC2807x8xWLWu1w+c4iyLUBQJA/Mo89q30KJ1EqDYQEcRM/yYZmxuRf6SNbPSFIJZU9IGRCFtAFfqsXZmHTko+XFSzCYtfiMhPxLM9CTwgCOeIwrFIHLRmRVwSYq0SJAmC7fog17MMkfe7y5Kxt3QnuLp9WO8JaDqv8sVokvRu7R76wUb7qsooFdyWor9fhqFnSsCEw5l73YbWWK0y01AZ0","iv":"Kxr4ktM8dGbc1EDuDaX+jQ=="}'

test.plain <- decrypt.field(test.enc)
stopifnot(identical(test.plain, "ccccccccccccc"))

dec.list <- decrypt.csv("EncryptDemo.csv")
