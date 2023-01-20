import pytest
import base64
import binascii
import urllib.parse
from badsecrets import modules_loaded
from badsecrets.errors import Telerik_EncryptionKey_Exception
from badsecrets.helpers import Csharp_pbkdf1, Csharp_pbkdf1_exception

Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]
Telerik_HashKey = modules_loaded["telerik_hashkey"]

testing_encryption_keys = ["6YXEG7IH4XYNKdt772p2ni6nbeDT772P2NI6NBE4@", "d2a312d9-7af4-43de-be5a-ae717b46cea6"]

# Older versions (PBKDF1_MS)

# Successfully decrypt a known valid encrypted value

# Sucessfully (round-trip encrypt-decrypt an arbitrary value)


# Newer version (PBKDF2)
def test_PBKDF2_crypt():
    x = Telerik_EncryptionKey()
    for testing_encryption_key in testing_encryption_keys:
        # Derive Keys
        derivedKey, derivedIV = x.telerik_derivekeys(testing_encryption_key, "PBKDF2")

        # Successfully decrypt a known valid encrypted value

        if testing_encryption_key == "6YXEG7IH4XYNKdt772p2ni6nbeDT772P2NI6NBE4@":
            known_good_dialogparameters_PBKDF2 = "owOnMokk%2F4N7IMo6gznRP56OYIT34dZ1Bh0KBbXlFgztgiNNEBYrgWRYDBkDlX8BIFYBcBztC3NMwoT%2FtNF%2Ff2nCsA37ORIgfBem1foENqumZvmcTpQuoiXXbMWW8oDjs270y6LDAmHhCRsl4Itox4NSBwDgMIOsoMhNrMigV7o7jlgU16L3ezISSmVqFektKmu9qATIXme63u4IKk9UL%2BGP%2Fk3NPv9MsTEVH1wMEf4MApH5KfWBX96TRIc9nlp3IE5BEWNMvI1Gd%2BWXbY5cSY%2Buey2mXQ%2BAFuXAernruJDm%2BxK8ZZ09TNsn5UREutvNtFRrePA8tz3r7p14yG756E0vrU7uBz5TQlTPNUeN3shdxlMK5Qzw1EqxRZmjhaRpMN0YZgmjIpzFgrTnT0%2Bo0f6keaL8Z9TY8vJN8%2BEUPoq%2F7AJiHKm1C8GNc3woVzs5mJKZxMUP398HwGTDv9KSwwkSpHeXFsZofbaWyG0WuNldHNzM%2FgyWMsnGxY6S086%2F477xEQkWdWG5UE%2FowesockebyTTEn3%2B%2FqiVy%2FIOxXvMpvrLel5nVY%2FSouHp5n2URRyRsfo%2B%2BOXJZo7yxKQoYBSSkmxdehJqKJmbgxNp5Ew8m89xAS5g99Hzzg382%2BxFp8yoDVZMOiTEuw0J%2B4G6KizqRW9cis%2FELd0aDE1V7TUuJnFrX%2BlCLOiv100tKpeJ0ePMOYrmvSn0wx7JhswNuj%2BgdKqvCnMSLakGWiOHxu5m9Qqdm3s5sk7nsaxMkh8IqV%2BSzB9A2K1kYEUlY40II1Wun67OSdLlYfdCFQk4ED0N%2BV4kES%2F1xpGiaPhxjboFiiV%2BkvCyJfkuotYuN%2B42CqFyAyepXPA%2BR5jVSThT6OIN2n1UahUnrD%2BwKKGMA9QpVPTSiGLen2KSnJtXISbrl2%2BA2AnQNH%2BMEwYVNjseM0%2BAosbgVfNde2ukMyugo%2FRfrRM27cbdVlE0ms0uXhlgKAYJ2ZN54w1tPWhpGxvZtB0keWpZan0YPh8CBgzsAIMa04HMYLCtgUTqxKqANoKXSy7VIJUzg3fl%2F2WUELjpXK9gRcgexNWDNB1E0rHd9PUo0PvpB4fxSrRpb1LRryipqsuoJ8mrpOVrVMvjracBvtoykK3GrN%2FDUlXkSG%2FAeBQN7HwDJ9QPi3AtEOohp78Op3nmbItXo7IJUSjzBNzUYR8YPj6Ud7Fje9LZSwMBngvgx%2BOKy6HsV4ofOAU2%2FK1%2BfxI0KkCeoSso9NJHWgBD7ijfXUa1Hrc%2FuNU3mTlSSVp3VStQrJbQCkr4paaHYWeeO4pRZCDSBNUzs9qq3TDePwpEQc4QROrw5htdniRk26lFIFm%2Fzk2nC77Pg%2BrkRC1W%2BlRv0lyXsmXVBCe8F1szpWXHCxHNAJwKH%2FBb%2BV1k6AXFXVWPW5vADbXUvRu0s6KLaqu6a0KCB7dt3K2Ni%2FI6O%2FmISYXzknbMrwwakNfajbRF2ibodgR9R9xvoCoCXa3ka7%2Fejr%2BmsZ2HvPKUAffd2fNIWCQrejfpuIoOWiYx6ufN8E41HetCbYfvsI6JQfPOEdOYWI2px%2BLdfO3Nybq99%2BRSQOhjNZakBP54ozlCUfwgpLOmTBwsswZexv1RK5MIi8%2FWtjlJ%2FKjkYxdkFUlwggGS2xDwzcyl2%2FakNCQ5YmxjU8cRY7jZQRMo%2F8uTw5qa2MNZPaQGI18uRgr0i%2FTX3t57fJYCpMLXSaUKIdO7O%2FCQhIyGTS6KrPN%2B3%2FgUb%2BPQ1viGhpnWfGEYF9vhIlK57z8G8G82UQ3DpttD7M8mQ0KsmCOq75ECx9CWrWGk51vADlm%2BLEZ5oWjVMs%2FThki40B7tL7gzFrBuQksWXYeubMzZfFo4ZQ49di4wupHG5kRsyL2fJUzgpaLDP%2BSe6%2FjCnc52C7lZ3Ls0cHJVf9HRwDNXWM%2B4h8donNy5637QWK%2BV7mlH%2FL4xBZCfU9l6sIz%2FWHMtRaQprEem6a%2FRwPRDBiP65I2EwZLKGY8I%2F1uXJncwC8egLu82JY9maweI0VmJSmRcTf0evxqqe7vc9MqpsUlpSVNh4bFnxVIo5E4PGX70kVaTFe0vu1YdGKmFX5PLvkmWIf%2FnwfgPMqYsa0%2F09trboJ5LGDEQRXSBb7ldG%2FwLdOiqocYKAb91SMpn1fXVPBgkPM27QZxHnSAmWVbJR2%2FIhO%2BIVNzkgFAJlptiEPPPTxuBh%2BTT7CaIQE3oZbbJeQKvRkrt4bawTCOzciU%2F1zFGxubTJTSyInjQ8%2F1tVo7KjnxPKqGSfwZQN%2FeWL6R%2FpvCb%2BE6D4pdyczoJRUWsSNXNnA7QrdjgGNWhyOMiKvkDf3RD4mrXbul18WYVTsLyp0hvQsbdwBWOh7VlwfrWdy%2BklsttFi%2B%2BadKR7DbwjLTcxvdNpTx1WJhXROR8jwW26VEYSXPVqWnYvfyZo4DojKHMSDMbAakbuSJdkGP1d5w0AYbKlAcVQOqp9hbAvfwwLy4ErdIsOg0YEeCcnQVRAXwaCI9JvWWmM%2FzYJzE3X45A6lU9Pe7TAbft810MYh7lmV6Keb5HI6qXFiD%2B8khBZqi%2FsK6485k0a86aWLxOb4Eqnoc41x%2BYPv5CWfvP6cebsENo%3D%2BIUg0f64C4y77N4FZ6C82m5wMpvDQIHqx0ZFIHLhwMg%3D"

        elif testing_encryption_key == "d2a312d9-7af4-43de-be5a-ae717b46cea6":
            known_good_dialogparameters_PBKDF2 = "%2Bv%2BRs6kf9lDUYnqqYk32Vg84DkpdruQOKGZRmm6RMkaYuxNmvg5Ca5cT%2F74qkOozHIKkG1ovf6XBsjlp4kgO8BJ6KgNcT78BExQZfT1mN5rMO8kcLDRdffFhFXmvAr0o%2F4x%2B9VoRJVaOyGLXk2nhX4OMP%2BjGP2C96Fa6LyfGWHmu9XX%2BJ0JmngEoQgfOG4%2Fckr32tzTV1hJsXuYB6daew1qvg6xQqYyuT8bzYvJgvUzU6XK1MR%2BUjRMwD8Tw3KGoqqOEsJPtdISZWNnKRxzFY9e70QMrhVug%2B4tTzGByMGPdCmkj6MFleKvvFOJF307tgzYQxpdXBUrFZuArJxdsU4YVhHi61L6B1w2irYVsWtWB5V2KbJLkOhGs9SFS%2B%2F2HoiBWIs%2Ba8gER9YvkAHebDfjNckGGI6e%2B%2BAYZWq1G8NWiy3%2ByLfi87bVUHCwkkKBw1krcPtsNabT1qGdRUgJzSUEqR4PjJlNIZieIW6fXLM%2FWssBMBayME%2FjeLN9AvaypFsBRZmQOoHBoJXwQP7rDJZyDeenpE47v6Rcao0yeJQIRWJ39XT1lFQUao1VyHo3mAalsnLbGPB3YXstK81lYZyJG01VJJV1AfjB4XY6ojktilkW3mmEallXDXPDEmlE9cbeHk5i%2BvZ5aFmcWFgv8nj85tQOGHhWT2DbISGVH%2FEJOS0vdN2e3MXMsc2TqdruZDInGWle%2B%2BBVWy%2Brr0CA5SHM%2BbSJkLkFgp9e0uHa3L%2FF%2F0IqsActO2SbKsgZEQ4kcVdDEIPV2TwzF2YS0OVQ%2BqmQLTUfPwFCPk%2FzUKni3a%2FvGwxKhcPdO5RYuzGQmn%2BCplyKmwVZBVLB3%2FMYqQ2dIBw%2Bg3T%2BwTY26LlG2DQj0w%2FPGMkVm98VcdbZsp1l%2FjFjMz3nDjZjIo5eNUD7nqMgf%2F7bhf5lQSV5Cpwg11qrCBbs%2FHT8VpKx2d1WcZ4IsAFjxxfgTmJd1%2BlCX6jX0prZKBe9tsY9%2BmXOAINDkkxL90VBm3e4jX6iM3SrL8LyZO00VuYBDyiCTup%2FKZ01BALmiMvF7%2BXVmQ270ksnnB1iB%2FQthCh8KxJ2JrXrcxJ%2BHrWkI9KybXRXBc527gcm%2Fmpwd6TRG7ApTiJKIOKJ3ok92byAD7JpS6aO5VnA%2FNWlr3m62iw2lyv%2FUjJ3XdEb8UafHYHo9KpROT4xSTyc748Yqp0uLDzYIr7PYIq9ka0FjULQ0sxd9lVd4ExlD2nk6KPLrXI7tD64QXgLcuMx98rGHG1XLed4BNNXjxYgPEBJ%2FpnSO5wfaJzBhEwsSnErlUU66tSLiQQyUUXwUDnIFzjthssNKcU5w5zUpjfWWNgbZ3RJQQSOHdebAVNDjEbg7X%2BRB%2Bk%2B%2BIUTmM8YuCQwlW2jujODubGG3%2FcoqxmHOYKKZpjMntNsdoBhFH9%2BzSebbamBOJAB0lO0qKm2wupNt92ZLcGd3roy0p%2B9zYdyFiJBp3TjxWszM1hXoGOT8M5CIbgwMy853z8udsRlskWGProG%2FDiVO42byl%2FB40cgKH1c6GYjZUau%2BmmaYu3w6T7y57rE%2BPlxLY8x%2BaN1ITErK%2BOLcQcj%2BiJ%2BJSGulY0oTTQNClLMQQjyR9iZibWHEADXbnF7Vi6EYQech7o%2FrxSoaoNyBP7rf%2Fx3JoBvnfTOzm6OKC3vX5Hm9rqOf58JLpt7bZG71qvo6fLzrOMVcQRGHgRKZ5s%2B0n7mAuC3V9t3svKCnDB%2Bvhcp2crREqslB1YD2zmPnJhvgv2jdTTsC3QQSy7jiEZVJ%2BFGW7CFfCtoP%2BxBm1VUflDBmOVHxCM84a1AA5YySbTHm4q0BhrV0LruzZxvkM8RhSSYkiH5Zo2g79osttBHkGMxnryUM%2B0PMehyd589HEWzipI7l6fo6H6wzMNOkc855xATC6xW9cF8VCQT%2FipDuE3U%2Fj9SO9vxWgRsFn0cPirR6ENCct3mHYRnsaV0fd7H7Pp%2FFhXa%2Fk3nHN8EPAOl2QNT0RjOJcdO7ZR62iXIq5zdbkwTjLAXR%2BNONkihl0gTdMQxSWQKnjqCxGIfYu5W3ix1C3moyyKuY86KGKgtWQ2cezh1gvAHtfwFQpHPagrVmrDaCmJEZokN06qR2h3D5hb79dDrVmsPwkNyaOjNeDo1ycw6klf8CTOaTYwZ0pTvkmmSVD3KdZYKx%2FI7KSbvJChbeu%2BrcL37e2KA10UZdHiWZ%2F6n4rOGP7IYPQyOCyoVydv0q1CmT3VIXEPi0wh6BBYSPoSeCVqpri3NdMLFEoqekSbeDQAcaM09v20SfKjxkYQrClNdVgegKyQhy6vcMQF12fR7xwOcJzht%2BbUu4zO6nfpLr5miOuEoZAplNR4YSeZT%2BZoYJoVZ2%2FvsAem%2FqJ%2FQEElPKgqrQVOnSD%2FdZsIMiOrWdrAu4U%2F4c19NpzTWETzqu2PgDBP5HuZ%2FtX7Pguty4YND00NZfHtuUhl1lUiCpUNBoW1sEcmBV5s%2FLrD29nsueaSA0mF9F6Yxw%2Bqyn%2FBxfEIqyQ1%2BZbrHE1WO%2FxeKluoYjrTmhIPgGhmfNBeslceH%2Badai3XjNGSmW55qVahTmT%2FT4LbbYTTcjSXmpujP7o3YDh7JxBDCmE1VVBF0%3DZUqCSAGh85fW2AZER9W%2F0vqta0nSGz1S7U22ftcKUks%3D"

        known_good_secret_PBKDF2 = known_good_dialogparameters_PBKDF2[:-44]

        r = x.telerik_decrypt(derivedKey, derivedIV, base64.b64decode(urllib.parse.unquote(known_good_secret_PBKDF2)))
        assert r
        assert (
            r
            == "EnableAsyncUpload,False,3,True;DeletePaths,True,0,;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,;SearchPatterns,True,0,;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,;IsSkinTouch,False,3,False;ScriptManagerProperties,False,0,CgoKCkZhbHNlCjAKCgoK;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,VGVsZXJpay5XZWIuVUkuRWRpdG9yLkRpYWxvZ0NvbnRyb2xzLkRvY3VtZW50TWFuYWdlckRpYWxvZywgVGVsZXJpay5XZWIuVUksIFZlcnNpb249MjAyMi4zLjkxMy40NSwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0xMjFmYWU3ODE2NWJhM2Q0;AllowMultipleSelection,False,3,True"
        )

        # Sucessfully (round-trip encrypt-decrypt an arbitrary value)
        pt = "AAAAAAAAAAAAAAAA"
        ct = x.telerik_encrypt(derivedKey, derivedIV, pt)
        assert ct

        pt2 = x.telerik_decrypt(derivedKey, derivedIV, base64.b64decode(ct))
        assert pt == pt2


def test_PBKDF1_MS_crypt():
    x = Telerik_EncryptionKey()
    for testing_encryption_key in testing_encryption_keys:
        # Derive Keys
        derivedKey, derivedIV = x.telerik_derivekeys(testing_encryption_key, "PBKDF1_MS")

        # Successfully decrypt a known valid encrypted value

        if testing_encryption_key == "6YXEG7IH4XYNKdt772p2ni6nbeDT772P2NI6NBE4@":
            known_good_dialogparameters_PBKDF1_MS = "y1MPLyncErmvCfYRJDU72NLpEurHW6DfWxGJlfMGTH55vxb8V9m2vrkLDCkDm8%2F1PlVto%2FNCiuCR6ioagdVglig7fQjiAmlEMc7v5RWKx74f8v%2FXxMLhwqLzLkF5YbKbAJO7Rtmhqod1vAzINW2yo16gm7yNseksxi4dSIdiGKVIBuUYiA%2BJrhAlDYfmYrdSA0laWPsYjCyTLWwVipZnPb%2FmOJk%2BMnZC3WD2JLtJyiTTanExxyVsx8SKrKqighnPQCiCLEcBik9FoPNBElJLCIZqizM%2Fy8DYmvyC0bTH7rB6plNMYthd%2F%2FIr7DdRaoJJXHThVbra3BXybA7aiW4fRmuRD0vwiZUV%2BYWaClCgPpZ90YOfwXGlGpVhYfZJPNH%2BeCG2piS6oJPs2AjSUlQuzKn4uN%2F2OZYca8IP%2FkVE0jwU5EUq3uf%2FCmXJ8zNcgmcQXhhxejsn3dEygzw4zzyqR3LAnFQkk3BWtrhEmyNVjCL2y1MgsSTjClmTQzX0UicfQOBv4Vgg9E3EA6rqIdxj%2F7pq7N47X0f4wLByBROlgKj%2BhbuWNKAaZmXhjurQ5uu7WOGwKEmOpEnkTZzyoCFui8S6f3dtbrNw2rwGgo1oz8pD7gDXIXATx66hswuK7tfxjkMab%2FdXBQ3vQTSa5HYNpCWnJu3RunO3sb5OKT%2FtUe061%2BdO%2FcFDNwNiGXQvQ9yuY99w2BtNB7ZOazMl9vGG8lcL4s9yuSMdfG3tcgD4%2BrtHDEL7v0ub14dFxB8TOqY5JMRKdyd8D%2FP46%2BC3pWT61EYaddn3U548w%2FjHz1sXXx6b2lo7%2BYnG1DrRt%2Bk6%2BZt1Wa7UkfYC2b2n4OM2ro%2FqwHBU3FL0LOvBdXDDvlqqMSF4PtYUpO09GaE4TrzKlA%2FFN%2BZ9ibPj%2BmHyanK3GpdsR9S%2BavrhfnL%2BXrI26E5C2GPYOHTlR6u5dqvKJ71%2FCCF%2F%2FdYWbdzS5FVQ25WO6XREomBdvK2gP55Mh3byVUfoli%2F9pNkXytwYVo3yIIICReAuYdbteZN6%2BDJl4rJ5AKTbThpNk6co%2BG6Gl5rYKz1KqV80fqOF4TBlv6cm4kLvS%2FFk2JWD3L5kE8llElj9j4Bq7esFt1I%2Fvvo95guNdrBiiRfh2u7qENi1jfXYNlf1Npth8Vw11vztAq8jssrpMo3cVCKU2aTDkOQWvFBO6tN%2FvpYRCzRJHoy3e0sImQa3rN7wTNedxsadcL%2BHRXuYFFvQpcg5lfngY6lyVkjYPgxc5K4mRKZHDEXGWetFRl5af22wuNiEYmIERrh%2Fq25zBBCTfe2swAKb8hZLjoEywedeaQyZVveb4E0mTuMEQ259781fg727QoKnlu2m7Zh6gJINDk1a68Ap3t%2FCU1U8%2BL1haNZ5s7ywWl6vHM7dWvGffmqofBXoOKFhPdnSTc5xn6kgryFZJmnKwRyhOlPVCthRkgnANcLXEH1mtC1WQ8soXuVuMm6uAg44nwOt8BVZSNyJYYaEZCH4HPhtTo1F93W4PtXWJKIT6Mphf%2FWsIwJOKJzxgzCkCSwBB65kTL17LIQuyBqfmprPFtqEgTIRv4IFpJ8WuyeES08ti8QYwYM%2BPN2GZ1CTQu6kvlVlSBJxdTSvdf5IS%2BVje1pQqPJdYOIwwMTTpLfOno4qkHZVcM6OQnUNpvyIvRTuYJ5twYx8Rkty36P1%2BsKeaTMFgVWfMvpK5UNThjDxKMAsy7MgcMTxfZAeNi41gaQSbOFrdgtbkYMTALGiozY1NCcnHbXwr0qnHVKjVVDBuOPZeLL0lzBcm3hGjGYhOjrJLv4ZuRSLvCAe4UfHRhQcCjJd15vNpV8nbdcvEl2e7FUdoNlrPWxaglcEK0vu9WJxBzQVmzoNINhUvqnDZIrYOAGfzrDYrDAwMheLpr9OKHMvM2WHNHUecDK0781NXS%2FdoGGeheaTOe8DieXwcL%2FJlW2bBEwSUNDMuyD8RiukZHUQ4qcgDF%2FGLqUqkDesWIdQyj99wqKFfQNuwm41kCnzAN5uSt3IUiMiA7zsuDr%2BDg0Ro00K6Ap3wFLF1M3xtQobLnsRuCHZGwXSGxye%2Bmg8%2FxD%2BlTOs55IRwb3DDwi6eKdubRJMLN2o544FHYWL1UBAc%2BZcfz7vIqFeHUBMOc5htw%2BDPlXZRRnEzn%2F4qpV4ioEdZeQEv%2BhfXyUs9hF19JP%2BLJiWDJ3Ukdh7OdW2c6GtjOIiKeOcFcJi%2BYB8CP8ItWydzlt0IUaHufQ4ooPkkmmchlX7HV6%2BboKKGxaNWcOx%2BkAWPvP0IeYahPPff9PiSErWiFzc%2BOmFinwZu%2FXJsse%2BG1ndzbUJeMV%2B8jBdZtxiAewbNJxJZl%2Bgu6avfcLJqYjBfxFJ3%2B87%2B6AtI3JI93aCTEiLPVHMiMjsI6j8N1Nxn77BhCsXF3D9uXIqbqTsxp5je4xS4LHqrTTVnsKk3zqlc1PZvgVRGYVD3MRFUmFQfT%2Bnn9HhrDkuCfVdALWHnDOC%2BOOhHglnYm38GLFWA2Mo5VW4k3wM0ftFYVzaVVYYAEFmp8Uvup1sh6COO%2FZJJCSgBK1ZwjnLeWHM1j6Fo0f03YYC5Eghbzi2dBwR0WC2e0hHgtb2TY1K6Uc%3D%2B0qOmCh%2B%2F9ENNvvvJ8CR%2BGwmI9AvK4V1YpBxGzNSuF0%3D"
        elif testing_encryption_key == "d2a312d9-7af4-43de-be5a-ae717b46cea6":
            known_good_dialogparameters_PBKDF1_MS = "gRRgyE4BOGtN%2FLtBxeEeJDuLj%2FUwIG4oBhO5rCDfPjeH10P8Y02mDK3B%2FtsdOIrwILK7XjQiuTlTZMgHckSyb518JPAo6evNlVTPWD5AZX5l4UIUkfdJvq28UHyeBA4eC58PfA6nG7V2Q97Qwqef6cpbM6t88zvE0wJt8uUKji7w4N76BAO07CmZVo9CrxLSDc1wiJuQQ0UmzNGkyLbELVrFzsEt4GNOujYb4klO48gNO90A1ZdUJGbpw5%2FBwcfalFfJt1wfAYTxSEALTThTfM1J6CzUvg3Em9hXGD2k2PrOcYcjcVwbliXC0fM9VBqcMx5p7KE8PA6JcXQLgg4zmjyyyC1v5No0xLGVOXAqahWNCeOVtFbfR2LvNK82ZtpzilC8KQlVdMCqsj%2BpaC3xKC57Kh1%2BwYT%2BiH9WM44gk1KYlfYdc33OOAHyYHZQhNJRebEmlvi89L%2BF4adP4qG18pskLkFaTT23n1r%2Fn%2FsVMTs30IBO%2F56Ukp4TItGDu0JNouA6kgGtxDEoNIuuDfkKa1cVlXNoY0ZxRxqNy6qEy0U2kx73JFFGvE%2F4GRfwwX8bTT2hMc5YOA5Hy1LQIxzj8hUt3MbAMcWzG29T5wvcY8KaLh%2FIt0JRqF%2FOIt1KJWtDXiJssf0Y9MIhwSzBx2sOFW%2BMBC4pBPC9sE%2FserViBT4wmIBWv8%2BDM2MFvJS%2FRgLjAXB24RYsnuoCVT8FDF8hMzilQfEQGtdLRPrIwJvWQT08MQGUXFHmA7pOH3bFZiS9NpLW%2Fh9xW9sZFGCleRz2%2BLHBfg1qHBouC5urD1ntVxmal6g7ky0MtVcdAo%2FeH%2BFhAt025P7KMFA%2FTXGYNFW9qV%2F9ak1oZnj53CGNWoAmHdCUZvreb2Vuf1xCAVpx40mCgB3oyfzERyWUwQuybFWHFKQZ8jNQzY6RQ9crlzs%2F2oQepUGO8NcMR6FbR3FhqjV2dyqVqJz1qi2IjsqhWDW6qWRIk8LLqdUbZewCZdNibAX7afGFzfv3mr7tvEEejNNRApUGpmU%2BwqpHc1ztwOxxuC2NyzPveqqjJh9ZMpX2ddnapiFCT%2B8FQfHWDQ7uf1QqWK4dRADAdT33YpeiXvWORhJDNTVO3kjx%2F0lbk339yjTxI6vCdULyVLJ0%2FwdtyjrIrK%2FX2Pk1%2Bx78XUTfQtFqZpGi7hGSFudYxwX2LHsfemAICv773HckpDPZIaQTS4%2FAs9wGt1OXouFXQz37JM0hH%2FlmEtUmWKff0aBVEdyUOJRxPhgXgC43%2FdMlL3bMrTOB%2B56Uske46SOqzsszraeXydlzyq9nEegEc2yJH6bOhLr9IP3eCVdtPzGf06ts2i8lGeDx%2FxVy5DspJoZhecBVRuAxIJuLvTlmCRc6uN2b%2BY5HIJpUtylEC7oXkkwBdd%2Ftu7YwDtgoCv3TH%2Bj3sf2Z3CNf4EP10x7%2BoMuuJl6XnqcY3dvHxlc0dKuhTGNxbxlhePmYIVAunJAmm8feYg9wROkX5R2JzPZUQCVetv4x56u1YsWFmFskZXE0%2FRPNLVAn3lC8bjdYIT3Sz0wHgJZ4qhkgHAZsaGgieYkvdnnjxy9qmTktSz4fBovIiS30Y%2FqCWtAd5%2FTCqpJkUPu%2Fw8i2Se3FxQZcOS0CdvE0Tr2z97QodDunr%2BQ6rlSgHOh03Pq6MJANOHfmTdsA%2Fi7YKHAH82v%2FFIPQihdbaQk%2BgJtdEoSRn1FZ5vK1Suc3CD2MHwOH%2FIuY7AkY%2B3r78ScJ5CeDCM%2FxtgO%2BA16msOMbVvGPf50Wk3XT2BBgRSVExOyV2qnhg%2B6xUhT4HXYsk4AoC48mej3U6JyXINaaupKUQqHgIzWFV2sq8g4U0YAp%2FHI2ljjfq96LQVhNTL5N3LlPSiGw6wJO8gRB%2F%2FcFNK6Td8OqVHPNEnStkD60y%2FXRgftDg5tgku39X%2BMOGxWgHHaAeE3Sr9Y8ykz3sumlUo2b4q0jnNKx4uY%2BifrTUGUI%2BaJ%2FqvPyIbskDSC7CutHx8MiuH%2FLzkLDsT%2BAaxu7uifIjenHG61xnx%2BmkH%2B3UfQ%2FdCQ46MSpqcrxdYlQAebp31AO1wfQRpbs1NO%2Bft7h7ks6yBUc3sTPaaLbsdHyYk%2BjuJps31vOxV4RMdNLKfw1Vbwi%2BflWdaz5gAX9zxj9DUK8Yqsanzs%2BQJCID9inEWr%2BLE7uXjmBwl3nt4UVB70ki9JEJyPVOxFmdBLU2TAJC%2BGl7G6AGXz%2FRLL%2BVS5QNkGi%2F5NlJyFLNKsFtXtuLV84uT4mHKdclszqGeF8fHx0RfuInfxuf%2FKDkQ%2BHaaq9jb9f%2FATJ%2BnIra%2FEZBeTDzM5t6mox9gtlu2pH9GT6ehw8B7gTTP7pNj%2B5ug521gaoyBNvw9%2B%2FcoNos8UNyf5zTvNlTzE6wsDIcYgtxQNJLP2%2FG1byrK75Khse%2FiFxie1Y9SItVawkXLP838%2FwijJLOwekAk3%2FqJgUg93X9vZHGMLt7w1tl5Xf5fa1zymklWm4iAXHY1bDw3%2B7Igo0aGMaWX3MajYqQaRkQqnBMkeTo6gNP1QH2ImTwfk8vIdqfg4y%2B3x%2F%2F1MEZhA%2FM3VSwQS8ptSYoU2Mg53cmCorw0O5XfWvFgPo4NyAShI%3DtIfmrA%2FK%2FZ8%2FpnnM2wy57Npkk%2FbtJ8gxjiGkKfU9fB0%3D"

        known_good_secret_PBKDF1_MS = known_good_dialogparameters_PBKDF1_MS[:-44]

        r = x.telerik_decrypt(
            derivedKey, derivedIV, base64.b64decode(urllib.parse.unquote(known_good_secret_PBKDF1_MS))
        )
        assert r
        assert (
            r
            == "EnableAsyncUpload,False,3,True;DeletePaths,True,0,;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,1;UploadPaths,True,0,;SearchPatterns,True,0,;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,;IsSkinTouch,False,3,False;ScriptManagerProperties,False,0,CgoKCkZhbHNlCjAKCgoK;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,VGVsZXJpay5XZWIuVUkuRWRpdG9yLkRpYWxvZ0NvbnRyb2xzLkRvY3VtZW50TWFuYWdlckRpYWxvZywgVGVsZXJpay5XZWIuVUksIFZlcnNpb249MjAxOC4xLjExNy40NSwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0xMjFmYWU3ODE2NWJhM2Q0;AllowMultipleSelection,False,3,True"
        )

        # Sucessfully (round-trip encrypt-decrypt an arbitrary value)
        pt = "AAAAAAAAAAAAAAAA"
        ct = x.telerik_encrypt(derivedKey, derivedIV, pt)
        assert ct

        pt2 = x.telerik_decrypt(derivedKey, derivedIV, base64.b64decode(ct))
        assert pt == pt2


def test_include_machinekeys():
    x = Telerik_EncryptionKey()

    known_good_dialogparameters_machinekey = "522PwonY36R%2FJchNFoBWA0CNIzy0ewN0a9CQWORVGfCZ9FKOb%2Fxo6Bx2gZOthgVDVFGBh10MiuAlo9FhNL0wfrq2IEppYmLy%2F%2FZkiWYcWgQE%2Fk21UR9ZPoUmx12WcbKGtu4OV1AbDzJXR%2FAyracBcLtdvyGq8BH2V7T0nwB7VwwRwHyu0OK6YDE3dXeP0l90ARxowaksk4STXpjdyiITapaKUnwWKnX%2BnheA7z1kfadnRtSnfN%2FvPk4DltvozdcEF9qEvEigqR5Ou65itzc%2FxIgFVO7YAjsnnvynMuu7GvJfGvUd8%2BM8lnbmTDh60fOxGcVFSTMtxGIHmzrg%2BlC1s8V9f0p3L20Bh0tG7qG8LtMne5oTh5DbncREQU0LOAKiHfEhsP7ga3JSWVxj7bWpRnG8g4cBD6k7CoIuqw3qL6K9UTQXEtljCOQ453Z0Bti9x%2BB7Y%2F1BbaGV53CfiZ6tnms2lO7xIgG5RXCdNEOOBZPLToTGWw8ZnQJ9nMLBVzxjYr6n2QLwYpk56AccgVq2omxUyHEiX98W8PH5Vk50mRJ%2B2FJKsj34JrO2hIe5YDp9QMK4wDbYB1Cy0yznsA1xFgASIPEqAw%2Fdgw4pk%2Fo%2Ff9FjufckunGHSaBv72mJSB88xmnB6Bpbcljbc00XMp0kM0KOBlWmtiMceb3WR46NPlXlWOrvw%2FOxORDKOvwXjEL%2FDzRhql0uaV7kNo2eebH%2FfNiyHicgr%2B%2BKr9wHqGL8vaxI7k2xrE53%2BHZldHY%2FyexU7hZ5dWEcCQF4EygaLy0aHPHoQEhR2r88tW211P31kF2J16AkCOL6x2%2BKqfIklaleGIGP20XYPa3IUoRW6Mwoz%2FyVeP6OIGu0pX1SCVk2fgDzrm3z9%2Fodek%2FttiEoWUkw%2BdBxnvwwvtSrUVAmOYhNs7y5mASIvl9WuBTXzpzu%2BvvkUVsfsQ9V2ddnpWl8qbibXKA4iePZPr%2BbPrQK5yJ55GqCqNUxtZP31Tqud%2BJPVK5%2Bli0ONW4V2hLwhVw8WX6OGKOqLILHXj%2Be4HOPNwvgrzheBtE2%2FIGZcCud52sPgdati8gnVNax7Ajp0wEsNF4nf5zs7FJTIteS9fmxKlCFIqiprOT%2F9U%2B3Sx5iC%2BHC7xpNTkGqJqpRVR%2BVHqVF%2BAaELJrWCNQtdwSQLlthZqig8D%2Btz6CqhfsNbh4NokVknQJLy1s2%2B%2BaIB1Bj4Wc3zJwLPkXTvPZT8z5uvZ8c0ndfKIivKnXJ3bZQ9UZ%2FmF7pQBF1cVc555Sme5DsnBBpu2vws159Dz2bwlrD%2FHpMVUpIOR91bn4Sce8Zz8BrwtcBZbN8ab5oFvN5THNhfgG4NhPDBmTZHYa%2FHH5Gmo3bWpYPuhc%2BUIBBmD5IvWCQ0rYidpiFuZq3BQh%2B40aHfhj0zTzZV%2FTwDifAb6z8fYr6tixAAymGvDmlcZMMPmb40vfYnCJppbiJunGJFm32rZlATk%2FE9NCxkC8Sopdka9dv2bFXgibTiLTvdJUFC6KlDUlUDUVsVOnjPDoRJXyXhc1i3VvI%2FVoqgn9L2oWsUsKkLUbQeaGdL7FxhUIika3zv7iGsZHN71lAIBFHjJekxUhstJ5YVPC9kfSVoRQvfMgWzw%2FvRWhxyP3Ec%2FvRtLz2z0Rut4aRNEsolO9FKFsrvfH%2BIEpH9KzT4Os2Fw7OzzlO0AkowWmbaX2k%2F9rCHIDBJa8K0L%2BnoMP3oAiJ%2FPKNGOS6FnSBiHaNdJjVU0a3dDnAVUlC7qQXHRumso9PSX0QLzA4xNd0Wugz9wJjXihjEsfXIAAayX4HPdrbom%2Bt2aH6j1INDB5gshISRouJ4ji5ggsLNvpkFw7uO%2Bq8pl5O5NEa85JGaU89gEwQFTjZSjONdJNBw2sIRISVxB4%2FhcBDCTtZsZv2P1JIjGswVZjrORg54CIFe%2FwXufmFlA18LhuOStHbiqmb1X%2FlhL6q%2B6mE%2FudZ01uaLdgbtGwfhJFPWrCFI6%2BankuPxZF6bbvUwyWzRZGGXR8iRYtAB%2FjEk76kyqoLio9iNECTW5ABC0%2FmfGkkAzyEUMVvWloZmBBA3eCqniE5vwrt4y8DqJBVEjz8RGPkC0nRBBCpdFGokr%2FBVp2n7eO8mlGL5JvSmzkVyP%2FHTpLVvTtFtE7mjaCwADvSyCDen3n8ZvxuT4eWnVHDELayqUi%2FXJc7TV5%2F8MNAngh%2Fh6CB7KU3WtZuT%2B0iVi%2B2oPkn0gBUzMpPscCRnMnCKRFKjW%2BkC1%2BlxrLKFctHe7OipA4BBsCgsPDl%2FUmtw6UjIvHPBU7t8I3XHp%2FMNQ6JrdSTs4snAsfG9DT9DrHCi2Ra%2FgKzfV37YF%2FAakaGoMGr72ddth7%2F%2FnnDSVN8gvksj92UcFAJNZ2xwbWlpQDSzpkzJjsIwKRSzy9dHvcd%2B14W8w7zn0nzESZ4Ukdx%2Fdny7hxdwNW9D71%2F%2FuSA4A%2F6vUqjf%2B5OUoTsI7EkiVqm%2F2z0egybCrOCcMxntkstOl%2Fjw6ymwZGs%2BQA02dba9p0KKcV3lTbc%2BALUSJAFGVCDk8j4CHN86fX3egUj7F6x%2BtlVUb%2BBVpJEy48BVEjXO41bXd23rW6aicdqMDkrW6aE50tuI948NNA%3DsNjCRdOZ8iiViHpCYfdUwad%2Fcu22S%2B2636IqE9qRTg4%3D"
    r = x.check_secret(known_good_dialogparameters_machinekey, key_derive_mode="PBKDF2", include_machinekeys=True)
    assert r
    assert r["secret"] == "F8517F88738C8AB8576156C98961700D274DA366B58B24D7F534699367D809E2"


def test_derive_keys_error_handling():
    x = Telerik_EncryptionKey()
    with pytest.raises(Telerik_EncryptionKey_Exception):
        derivedKey, derivedIV = x.telerik_derivekeys(b"test", "something")


def test_csharp_pbkdf1_error_handling():

    # try a key that isn't bytes
    with pytest.raises(Csharp_pbkdf1_exception):
        csharp_pbkdf1 = Csharp_pbkdf1("string", b"salt", 100)

    # try an IV that isn't bytes
    with pytest.raises(Csharp_pbkdf1_exception):
        csharp_pbkdf1 = Csharp_pbkdf1(b"string", "salt", 100)

    # try iterations that arent > 0
    with pytest.raises(Csharp_pbkdf1_exception):
        csharp_pbkdf1 = Csharp_pbkdf1(b"string", b"salt", -1)

    # try getting bytes with a non-int

    csharp_pbkdf1 = Csharp_pbkdf1(b"string", b"salt", 100)
    with pytest.raises(Csharp_pbkdf1_exception):
        csharp_pbkdf1.GetBytes("10")


def test_csharp_ppkdf1_accuracy():

    testing_password = b"6YXEG7IH4XYNKdt772p2ni6nbeDT772P2NI6NBE4@"
    testing_salt = bytes([58, 84, 91, 25, 10, 34, 29, 68, 60, 88, 44, 51, 1])

    csharp_pbkdf1 = Csharp_pbkdf1(testing_password, testing_salt, 100)

    first32 = base64.b64encode(csharp_pbkdf1.GetBytes(32)).decode()
    second16 = base64.b64encode(csharp_pbkdf1.GetBytes(16)).decode()
    extra4 = base64.b64encode(csharp_pbkdf1.GetBytes(4)).decode()

    assert first32 == "0E96sqkdWxaKP6LiS51AZPiaf69vGRSrs5uQDKgTvHo="
    assert second16 == "ij+i4kudQGRbbIAdfNYc6A=="
    assert extra4 == "3dWedw=="

    csharp_pbkdf1_2 = Csharp_pbkdf1(testing_password, testing_salt, 100)
    multiblock = base64.b64encode(csharp_pbkdf1_2.GetBytes(61)).decode()

    assert multiblock == "0E96sqkdWxaKP6LiS51AZPiaf69vGRSrs5uQDKgTvHo3A4pO5Q425VtsgB181hzo3dWed76Wlpim4uhcRw=="

    csharp_pbkdf1_3 = Csharp_pbkdf1(testing_password, testing_salt, 100)
    halfblock1 = base64.b64encode(csharp_pbkdf1_3.GetBytes(10)).decode()
    halfblock2 = base64.b64encode(csharp_pbkdf1_3.GetBytes(10)).decode()

    assert halfblock1 == "0E96sqkdWxaKPw=="
    assert halfblock2 == "ouJLnUBk+Jp/rw=="


def test_encryptionkey_probe_generator():

    x = Telerik_EncryptionKey()

    test_hashkey = "6YXEG7IH4XYNKdt772p2ni6nbeDT772P2NI6NBE4@"

    for key_derive_mode in ["PBKDF1_MS", "PBKDF2"]:
        for encryption_key_probe, encryption_key in x.encryptionkey_probe_generator(
            test_hashkey, key_derive_mode, include_machinekeys=False
        ):

            r = x.check_secret(encryption_key_probe, key_derive_mode, include_machinekeys=False)
            assert r
            assert r["details"] == {"DialogParameters": "QUFBQUFBQUFBQUFBQUFBQUFBQUE="}


def test_malformed_dp():

    x = Telerik_EncryptionKey(include_machinekeys=False)
    r = x.check_secret("z2r1wMUG5YT66qgXyvpZiSYBdpdh2nUvUhGephVuEok=")
    assert not r


def test_malformed_b64():

    x = Telerik_EncryptionKey(include_machinekeys=False)
    r = x.check_secret(
        "01e8fb7a2a67f5ef3efb27fb85276d927f295fbde6b3e4da378c646de18262f7634386432e3716a4bea164f4eb98e1e7721b82bb66"
    )
    assert not r
