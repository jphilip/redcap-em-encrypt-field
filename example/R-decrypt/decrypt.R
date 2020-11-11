library(openssl)
library(rjson)


# Individual string decryption
# Updated for version 0.2.0 which includes a hash to verify field integrity

decrypt.field <- function(input, keyfile) {
  tryCatch({
    result <- input
    input.l <- fromJSON(input)
    if (!identical(c("payload", "token", "iv"), names(input.l)))
      stop("Format error")
      #return(input)  
    input.b <- lapply(input.l, base64_decode)
    key <- read_key(keyfile)
    plain.b <- decrypt_envelope(input.b$payload, input.b$iv, input.b$token, key)
    hplain <- rawToChar(plain.b)
    hash <- substr(hplain, 1, 64)
    result <- substring(hplain, 65)
    new.hash <- sha256(result)
    if (!identical(hash, unclass(new.hash)))
      stop(sprintf("Field differs from original); skipping '%s'...\n", substr(input, 1, 60)))
  },
  error=function(e) {cat(sprintf("Invalid encrypted string; skipping '%s'...\n", substr(input, 1, 60)))})
  return(result)
}

# csv file decryption function
# Returns a list with the decrypted data frame and the number of fields decrypted and saves the decrypted csv file 

decrypt.csv <- function (f, keyfile, new.file=paste0("decrypted_", f)) {
  report <- read.csv(f, header=T, as.is=T)
  nb.dec <- 0
  for (r in seq(nrow(report))) {
    for (c in seq(ncol(report))) {
      dec <- decrypt.field(report[r,c], keyfile)
      if (!identical(dec, report[r,c])) {
        report[r,c] <- gsub("\r\n", "\n", dec)
        nb.dec <- nb.dec + 1
      }
    }
  }
  write.csv(report, new.file, row.names=F)
  print(sprintf("%d fields were decrypted and verified", nb.dec))
  return(list(data=report, nb=nb.dec))
}


#### Test decryption with known text encrypted in REDCap

test.enc <- '{"payload":"lk1Da79+b1m41tgHJGQ8EghGGW4pXN2YkSn9CpWUW4zbp1XH+J4/Ai2VWDecRRHp0GpdUvFhaxU3owODMCe1Cc+kFk+ZC57ZHQjV0pyNEts=","token":"HM4zb9Yi4C+mK52yjmoKatF+x3KeK/SqWWZYZw5LpOeXeisvo9WLXLzkG1c46ob1c/3tHq/0RSanCO5p4ACfdjHt8WkucpeAPGer5PQugc5SyiaQg1MOfWq2BRiVhJzMkeqDIWRE/fcspFN+4irSJxIpc/Zq1Y2JL5KmV2+cXAgfV8fg7nHtAGLOoiqv90MTgeKc2uPq3iKSKWlAb9YuJvuNdYudKUJK9QiseF4YPtTZpOPhWMR5v7/uYgSbTi8kAfnHOs8L2dhx5L40JftU8ZA9Daj1j9xUSyth8CvIBkWCWy9RCLWZt3FKvZp0uLIg419WoFEnXTp8692XcAaTXruCW0/NA58yJW695mjcUxQbm9AqgEtbXb2X1oREoLUw/J/JMrEKFww5Wfgze6lMYNt+ugdzo2JFEpM5dHqAkD53zRpgo/k2eK6DQpXgPdlKp90F5ehRjh0h3Nj48ROosXv1ioFXITmPEQz0vEaELyjcu4yAzZI5peKGv3nCpu0U","iv":"Pu2q2rT1e6vSzu11u9GoOw=="}'

test.plain <- decrypt.field(test.enc, "key.pem")
stopifnot(identical(test.plain, "First"))

# Decrypt the whole demo csv file

dec.list <- decrypt.csv("EncryptDemo.csv", "key.pem")
