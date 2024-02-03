import os
import sys
import requests
import requests_mock
from mock import patch


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from badsecrets.examples import telerik_knownkey

from badsecrets import modules_loaded

Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]


partial_dialog_page = """
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="D9FD575A" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="/wEdAAJspJIt1GVCOCk05y5PNKqHr1eUXYH2SY42AOoXP1wAYw2bbvWgGSKjsWouPBAT+yhhHBVc" /><input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style='text-align:center;'>Loading the dialog...</div>

<script type="text/javascript">
"""


def pre2017_matcher(request):
    if "dialogParametersHolder=AAAA" in request.body:
        return True
    return False


def pre2017_matcher_probe(request):
    if "dialogParametersHolder=AAAA" not in request.body:
        return True
    return False


def asyncupload_verbose_error_PBKDF2(request):

    if (
        b'{"TotalChunks":1,"ChunkIndex":0,"TotalFileSize":1,"UploadID":"6cf6c6cdcabc.txt"}' in request.body
        and "mQheol55IDiQWWSxl+Atkc68JXWUJ6QSirwLhEwleMiw3vN4cwABE74V2fWsLGg8CFXHOP6np90M+sLrLDqFACGNvonxmgT8aBsTZPWbXErewMGNWBP34aX0DmMvXVyTEpQ6FkFhZi19cTtdYfRLI8Uc04uNSsdWnltDMQ2CX/sSLOXUFNnZdAwAXgUuprYhU28Zwh/GdgYh447ksXfAC2fuPqEJqKDDwBlltxsS/zSq8ipIg326ymB2dmOpH/P3hcAmTKOyzB0dW6a6pmJvqNVU+50DlrUC00RbBbTJwlV6Xm4s4XTvgXLvMQ6czz2OAYY18HI+HYX5uvajctj/25UR8edwu68ZCgedsD7EZHRSSthjxohxfAyrfshjcu1LnhCEd0ClowKxBS4eiaLxVxhJAdB7XcbbXxIS9WWKa7gtRMNc/jUAOlIpvOZ3N+bOQ6rsNMHv7TZk1g0bxPl99yBn9qvtAwDMNPDoADxoBSisAkIIl9mImKv7y7nAiKoj7ukApdu5XQuVo10SxwkLkqHcvEEgjxTrOlCbEbxK2/du9TgXxD9iqKyaPLHPzNZsnzCsG6qNXv0fNkeASP9tZAyvi/y1eLrpScE+J7blfT+kBkGPTTFc6Z4z6lN7GqSHofq/CDHC2S2+qdoRdC3C25V74j+Ae6MkpSfqYx4KZYNtxBAxjf9Uf3JVSiZh3X2W/7aFeimFft0h/liybSjJTzO+AwNJluI4kXqemFoHnjVFfUQViaIuk4UP0D861kCU6KIGLZLpOaa0g0KM8hmu3OjwVOy8QVXYtbx5lOmSX9h3imRzMDFRTXK25YpUJgD0/LFMgCeZLA8SCYzkThyN2d8f8n5l8iOScR47o8i8sqCp/fd3JTogSbwD7LxnHudpiw2W/OfpMGipgc6loQFoX4klQaYwKkA4w+GUzahfAJmIiukZuTLOPCPQvX4wKtLqw1YiHtuaLHvLYq2/F66QQXNrZ4SucUNED0p5TUVTvHGUbuA0zxAyYSfYVgTNZjXGguQBY7DsN1SkpCa/ltvIiGtCbHQR86OrvjJMACe0wdpMCqEg7JiGym3RrLqvmjpS&sbZRwxJ96gmXFBSbSvT0ve7jpvDoieqd6RbG+GIP0H7sO5/0ZnvheosB9jQAifuMabY7lW4UzZgr5o2iqE0tBl4SGhfWyYW7iCFXnd3aIuCnUvhT58Rp8g7kGkA/eU/s68E66KOBXNuBnokZR9cIsjE0Tt3Jfxrk018+CmVcXpjXp/RmhRwCJTgEAXQuNplb/KdkLxqDn519iRtbiU6aLZX8YctdFQBqyKVgkk8WYXxcXQ8wYnxtpEtGuBcsndUi1iPp4Od8rYY1HPWg+FIquW17YPHjfP4gO4dhZe4sd7gH0ARyGDjiYVj7ODDE0wGmwmFVdQTrDX5AaxKuJy0NbQ=="
        in request.body
    ):
        return True
    return False


def asyncupload_found_key_matcher(request):

    if (
        b"c7g3CANCQbJ+X+IODBkErbuhQJ1AK1dJ03CaDAQ10aShpEysYFi6JD5Lg/QsepJ9T3Wsp126Z4vVzaH7fU6BmozmhQ1hIosvIFAwaPlsx4FWMGxX9wkEgESpazGqRXqWEJPsINIQBUB0DSOMnSNzlFWoDKkaCp7ZlXCJ0ZgMFYqBvPyK8DhMYri1RpiY1zgI4I/RA5Q1cqwwKjEcqP1XdwRMbE5we0z0fLs6Gmh83Z2rcriARFnBVZ45Wt40ENII6Gs7k4oQeeAx+JocDdu+K73FFFBAN1VwdNGOLO2lor4j/Pz1hxjgxNUmbpsWfQ2OdSLYKZxiOBMrD36tJeSRosQcwwbY8NVKKqv/44bzjTe01m2Smv0V+gusVyidEhCEVjKtRk+arUKMXg6BWEf4GReKkWiujlEf4lKeaYCz90LbGZajJvcw6OggVrGPALuJTC0JlmJ/Ms6v5i+x6mSXWcbAqPMEWGHLH303iZIpj36ivzZTvp3H85pXcJ2HLwfUSVLD4XShNFF9KyppZzqP18sCnEJl7ngXnAd6aReC1HyHMODgQ9Naj5wVYbgqEhuSCglebz+Ndhe3JybnDrb8aEjU542LWC3MxZF/GMIl60C/s7tzr5zNzb9487ELpKGOY4XYTuWihmK4zUrt0i733mEg73X7NkmzmnCgLRdaOx1bKYife22mqE8B7JBee3QYWdqyMTg1u3g934pI97bMnAzLkE7ASwLyN2sWOs9jpdnMgCWgh4EfJco6H9f/V4JkdgKE8Dud1ICUqWVm1xR+MUhScEq7KUEl3fSDV9bCplUx12KuXL4QUG6z74w8YnUV4V1aIKHZsh6G1/V3viEEr/3AqxHiTJixhgyHIhIST0fJQQdkMZdufqDPR2P+200MKv92IQ3StN2rw8WQ4sZaijH9OP0HlgouVYE4y9yrDfemw7++iWdbu91T6NiTYau5Z6AOG8jXOxzcrHZF3HWtRoeu3DlpGWPOXVLosenUm3bD/UxfqPwa5B36uCTh6Qsd4+53nZOItLpooo7KjGk//qYvfWpY5duCKqBVgBK+kIWv7PeKUsZfqaRI7tCn/jsA8vKLS7utYDMLM04L/ycFExlCk5Xc40ZeqVjGeSOnl/2MFeDyJDBdWTbf44gBLQyrxP5ofCDg+YvOn/ntbjOy78TtDD+kU8RtCtXRNam6nDLgfYmN8icAsxSCwQduQMu/ZS1qxMm/KhsiPsWLvdtNhfb2Jra57V1moG42K7O6VZuSS+bVVXMS2h3raSvXOSQWKLuwbcvg7Dro7+UXMJtVY2W6bksKvFOYYOYAlBIodCg=&MZHHCxK8LwqtvEKkgBFFUe7zg+by4jHrTU//aYL0k0b6ulXwqCrXGUCjqKoidbDQwSoa9hteI8tLEoFvWyslU4FU0XPU3riYQ0Pq/H8DVHcPIR++q5mKHUgtAgM7cruftoyjZRbWqgaQijwhkY53c5QvnpjiqkhFYx3ILsLtHvbl4i64h9p3tZFa1adNnYXjvmQ/gq6obcaR3IYXttWrCEdnuxO9TzLb6tSVuBuOWOKYwKrKl+XS4h4RTfWyDxLR26l6y2oyBWcW62tcn132PdLtoYpxXyr+ByL8I5OEtX0j7YCbO1VDutoV/D9GZDAVpViJNDXPaD4QWn/ccD98YQ=="
        in request.body
    ):
        return True
    return False


def asyncupload_found_key_matcher_incorrect(request):

    if (
        b"c7g3CANCQbJ+X+IODBkErbuhQJ1AK1dJ03CaDAQ10aShpEysYFi6JD5Lg/QsepJ9T3Wsp126Z4vVzaH7fU6BmozmhQ1hIosvIFAwaPlsx4FWMGxX9wkEgESpazGqRXqWEJPsINIQBUB0DSOMnSNzlFWoDKkaCp7ZlXCJ0ZgMFYqBvPyK8DhMYri1RpiY1zgI4I/RA5Q1cqwwKjEcqP1XdwRMbE5we0z0fLs6Gmh83Z2rcriARFnBVZ45Wt40ENII6Gs7k4oQeeAx+JocDdu+K73FFFBAN1VwdNGOLO2lor4j/Pz1hxjgxNUmbpsWfQ2OdSLYKZxiOBMrD36tJeSRosQcwwbY8NVKKqv/44bzjTe01m2Smv0V+gusVyidEhCEVjKtRk+arUKMXg6BWEf4GReKkWiujlEf4lKeaYCz90LbGZajJvcw6OggVrGPALuJTC0JlmJ/Ms6v5i+x6mSXWcbAqPMEWGHLH303iZIpj36ivzZTvp3H85pXcJ2HLwfUSVLD4XShNFF9KyppZzqP18sCnEJl7ngXnAd6aReC1HyHMODgQ9Naj5wVYbgqEhuSCglebz+Ndhe3JybnDrb8aEjU542LWC3MxZF/GMIl60C/s7tzr5zNzb9487ELpKGOY4XYTuWihmK4zUrt0i733mEg73X7NkmzmnCgLRdaOx1bKYife22mqE8B7JBee3QYWdqyMTg1u3g934pI97bMnAzLkE7ASwLyN2sWOs9jpdnMgCWgh4EfJco6H9f/V4JkdgKE8Dud1ICUqWVm1xR+MUhScEq7KUEl3fSDV9bCplUx12KuXL4QUG6z74w8YnUV4V1aIKHZsh6G1/V3viEEr/3AqxHiTJixhgyHIhIST0fJQQdkMZdufqDPR2P+200MKv92IQ3StN2rw8WQ4sZaijH9OP0HlgouVYE4y9yrDfemw7++iWdbu91T6NiTYau5Z6AOG8jXOxzcrHZF3HWtRoeu3DlpGWPOXVLosenUm3bD/UxfqPwa5B36uCTh6Qsd4+53nZOItLpooo7KjGk//qYvfWpY5duCKqBVgBK+kIWv7PeKUsZfqaRI7tCn/jsA8vKLS7utYDMLM04L/ycFExlCk5Xc40ZeqVjGeSOnl/2MFeDyJDBdWTbf44gBLQyrxP5ofCDg+YvOn/ntbjOy78TtDD+kU8RtCtXRNam6nDLgfYmN8icAsxSCwQduQMu/ZS1qxMm/KhsiPsWLvdtNhfb2Jra57V1moG42K7O6VZuSS+bVVXMS2h3raSvXOSQWKLuwbcvg7Dro7+UXMJtVY2W6bksKvFOYYOYAlBIodCg=&MZHHCxK8LwqtvEKkgBFFUe7zg+by4jHrTU//aYL0k0b6ulXwqCrXGUCjqKoidbDQwSoa9hteI8tLEoFvWyslU4FU0XPU3riYQ0Pq/H8DVHcPIR++q5mKHUgtAgM7cruftoyjZRbWqgaQijwhkY53c5QvnpjiqkhFYx3ILsLtHvbl4i64h9p3tZFa1adNnYXjvmQ/gq6obcaR3IYXttWrCEdnuxO9TzLb6tSVuBuOWOKYwKrKl+XS4h4RTfWyDxLR26l6y2oyBWcW62tcn132PdLtoYpxXyr+ByL8I5OEtX0j7YCbO1VDutoV/D9GZDAVpViJNDXPaD4QWn/ccD98YQ=="
        in request.body
    ):
        return False
    return True


def asyncupload_early_result_matcher(request):

    if b"r+R+MLL7r9MwAHb7S6n5psOS6iwav8/lRtiOVHMaFba4gCRg0YWT5j+A=" in request.body:
        return True
    return False


def asyncupload_early_result_matcher_incorrect(request):

    if b"r+R+MLL7r9MwAHb7S6n5psOS6iwav8/lRtiOVHMaFba4gCRg0YWT5j+A=" in request.body:
        return False
    return True


def asyncupload_found_key_matcher_PBKDF1_MS(request):

    if (
        b"z3TV+wmyQiHUCiyUIKb/5VSJkb+rgQUYlw9fs9Bh1aikXUQpWVw3DQyPPCNuxD5zI9DI1NXdtBFzXwglAwVHAVhQcWA79V/hc8dx4q1rq38qgYnIf80kbohlpHONMJEeWi99Ha5sQe41Afy6j1JTDnh629pjPgidJ4Ben0+hSyX3NIh3tgRpZvj7e6f98c4BfN89uSraNzCMQej0LvAs3wY1ec5LYeC2XcDGW94MPdWBasJpB3Ka96aOJ+P6X+MUDaqSPCorC00uC17rQ4c0If1Kj8g4ZLuViuU7ESbhqcCLNW1ZLmOcl+4x+UohKeNJqVN3SNfFdu+CzXl+pkADAyTBNIGG4vuqLYPGCKPyyWYi5gTmKSXWcLLqwTvRvWxpohlEpIeFDJN7aaIp0qVzmsgP6NAg8WciboLuNkhi4gVTMgEm03WTfRCYW5mK+t/db2Ec4xPn6U3vZdPzUR9mWFuc9uu4mH0NLw6cZUr8iLQ9OMzebFyBpfHi3oTN5ztj+ZyurfFaVJKRhaWYoMXcD0cZqeA4nImvtCw8M9iH4cjPGj16UZEu/xW8myeOb0N2iJVSzirNQ8ZIDLOID90Zk0NV813u0EiyfSiyX7HkYz+MDtul+eQpyCREYsnMfYXcW/L7FQSWwcAnBgwNeCbRUx34f3Lw4ifuQ9rXP63DYUglIaL3Y859jOALQZ2m/YvhI+azF6GfZTYvRrzTeaCvk1uoE48+eb917uVnImH8eUUI4sTqsIG9RBpG/E3rzAXL+tXQ+0Y+4M/D+XqO27pg8+U4FoThJeOFsvkS0TiNja1CMV4D5Ej6LVe0qqOX7yJlJYmnHfn6Dymofg0rs0HJG+eJJPQW3+rAivEWeZR0t/xUEJZ60I7+puUSy4euzZzTA8oBb0gwqYsjTnJFe0JrCPDS0ktxreOzSUZ81IxrATjcsEfc3IbcWe5lYgWfNabEAZnSC7PnUEkpA5+mJstTznE8YkFYi3aEVE44IHMkYFecumW/hwqxSvwVFe8kmixASk1540cT4eM5/Xc+hQzehjd6eBI7Lne7nC1HJ5AL1talf8UCcykPh4fu7IqguEMw&Yask2YKsPSxDbrmYLHaHB5MMRIO9n33I10MmRNJCyS6m12Rjp7gqc+de/QszySP2TwCQDTTYyBAvNFJAl9IcnqwqwkDwswrtgAQTNZlIxlGdBZkfndRQFgvoKIJmV+tcnAHuvv3wPmRuxNou/qwQq1LikSfuBF5W443Hzm43y67v+59XzUjOC3pc+9+fcrU5KSeE1kqeITCN8wdR9TEtF/QdisA5ET7he6d+0If4VlCeRZzr8Qu2+nA9vBB4wYnUalt/xM4o6nOTcBcC2yMjqlh44HyhYN64n49r8+AwAHK1UuqoE0W46n3xA4JZE5XTGXwGZU7oabHRY6Sb2zOFtzuoa0u4Q+QzSMYtB5dCJt0="
        in request.body
    ):
        return True
    return False


def asyncupload_found_key_matcher_PBKDF1_MS_incorrect(request):

    if (
        b"z3TV+wmyQiHUCiyUIKb/5VSJkb+rgQUYlw9fs9Bh1aikXUQpWVw3DQyPPCNuxD5zI9DI1NXdtBFzXwglAwVHAVhQcWA79V/hc8dx4q1rq38qgYnIf80kbohlpHONMJEeWi99Ha5sQe41Afy6j1JTDnh629pjPgidJ4Ben0+hSyX3NIh3tgRpZvj7e6f98c4BfN89uSraNzCMQej0LvAs3wY1ec5LYeC2XcDGW94MPdWBasJpB3Ka96aOJ+P6X+MUDaqSPCorC00uC17rQ4c0If1Kj8g4ZLuViuU7ESbhqcCLNW1ZLmOcl+4x+UohKeNJqVN3SNfFdu+CzXl+pkADAyTBNIGG4vuqLYPGCKPyyWYi5gTmKSXWcLLqwTvRvWxpohlEpIeFDJN7aaIp0qVzmsgP6NAg8WciboLuNkhi4gVTMgEm03WTfRCYW5mK+t/db2Ec4xPn6U3vZdPzUR9mWFuc9uu4mH0NLw6cZUr8iLQ9OMzebFyBpfHi3oTN5ztj+ZyurfFaVJKRhaWYoMXcD0cZqeA4nImvtCw8M9iH4cjPGj16UZEu/xW8myeOb0N2iJVSzirNQ8ZIDLOID90Zk0NV813u0EiyfSiyX7HkYz+MDtul+eQpyCREYsnMfYXcW/L7FQSWwcAnBgwNeCbRUx34f3Lw4ifuQ9rXP63DYUglIaL3Y859jOALQZ2m/YvhI+azF6GfZTYvRrzTeaCvk1uoE48+eb917uVnImH8eUUI4sTqsIG9RBpG/E3rzAXL+tXQ+0Y+4M/D+XqO27pg8+U4FoThJeOFsvkS0TiNja1CMV4D5Ej6LVe0qqOX7yJlJYmnHfn6Dymofg0rs0HJG+eJJPQW3+rAivEWeZR0t/xUEJZ60I7+puUSy4euzZzTA8oBb0gwqYsjTnJFe0JrCPDS0ktxreOzSUZ81IxrATjcsEfc3IbcWe5lYgWfNabEAZnSC7PnUEkpA5+mJstTznE8YkFYi3aEVE44IHMkYFecumW/hwqxSvwVFe8kmixASk1540cT4eM5/Xc+hQzehjd6eBI7Lne7nC1HJ5AL1talf8UCcykPh4fu7IqguEMw&Yask2YKsPSxDbrmYLHaHB5MMRIO9n33I10MmRNJCyS6m12Rjp7gqc+de/QszySP2TwCQDTTYyBAvNFJAl9IcnqwqwkDwswrtgAQTNZlIxlGdBZkfndRQFgvoKIJmV+tcnAHuvv3wPmRuxNou/qwQq1LikSfuBF5W443Hzm43y67v+59XzUjOC3pc+9+fcrU5KSeE1kqeITCN8wdR9TEtF/QdisA5ET7he6d+0If4VlCeRZzr8Qu2+nA9vBB4wYnUalt/xM4o6nOTcBcC2yMjqlh44HyhYN64n49r8+AwAHK1UuqoE0W46n3xA4JZE5XTGXwGZU7oabHRY6Sb2zOFtzuoa0u4Q+QzSMYtB5dCJt0="
        in request.body
    ):
        return False
    return True


def PBKDF2_found_key_matcher(request):
    if (
        request.body
        == "dialogParametersHolder=Ct3E%2FAXZ0ct05hNqzzSbCRVxte%2F%2BQBIVbVz21p21CqLSnQsGfzTjsiq%2FxoAQaaDuaafBKu8cNXMOGT5kJcE0snNDBVbQqvbQLEYa1cWQYr%2FL2tOMq8Rnuzq6F7HKpN2%2BP0tdCPxrO3s6K2W43kvEO5wyaDlijlF9r2XI6UL1FUk%3D"
    ):
        return True
    return False


def PBKDF2_found_key_matcher_negative(request):
    if (
        request.body
        == "dialogParametersHolder=Ct3E%2FAXZ0ct05hNqzzSbCRVxte%2F%2BQBIVbVz21p21CqLSnQsGfzTjsiq%2FxoAQaaDuaafBKu8cNXMOGT5kJcE0snNDBVbQqvbQLEYa1cWQYr%2FL2tOMq8Rnuzq6F7HKpN2%2BP0tdCPxrO3s6K2W43kvEO5wyaDlijlF9r2XI6UL1FUk%3D"
    ):
        return False
    return True


def PBKDF2_version_probe_matcher(request):
    if (
        request.body != "dialogParametersHolder=AAAA"
        and request.body
        == "dialogParametersHolder=%2Bv%2BRs6kf9lDUYnqqYk32Vg84DkpdruQOKGZRmm6RMkaYuxNmvg5Ca5cT%2F74qkOozHIKkG1ovf6XBsjlp4kgO8BJ6KgNcT78BExQZfT1mN5rMO8kcLDRdffFhFXmvAr0o%2F4x%2B9VoRJVaOyGLXk2nhX4OMP%2BjGP2C96Fa6LyfGWHlk1CF0E5mAPeQ6CLbycR88WU5hlmUUqniXC2UdeYd6HO9RFnISEnhq72MkdiEfvNsqAhr2XaCX2%2BQxFXfCLi2%2Fc%2Bn2NmUiFRdhCLutnVxILEnYiRmU5eHJdB2IOTtoc2XZ3NUdZJwrwOswjzCkk7LOwt2bddTvOXdfWtRrbNz1GDNXlPz1cXotgAhucxLLsknNDbeeboMbL%2Bk3tIeervi7oI%2FRQn6Ml3ffUAfcqHzwcZCEIlQXh%2FBEIKHAY9fGKs5JSdtRbREDI0rh9sH%2B0TmYv444WQyqYpa8pOqtxgC1QRRcsNQcVGFzpyNL2SfKSlLTZi5Q7bo8XMTfLG6jg60csDEDiJ7MwJBGIm1iYzt%2FP9JEKkZujTMyHoBI0RESNpux7BeanEIDsfDmfwbcUo%2B2%2BkoHkCE4zXWBdW3lqssk4GwSbc0mbmf3U79rsQdNEqIOL87evE1U6tGB5PuXgwAIj9sKdyffd8%2B%2Bz1CCffFovLM72ilbCmSljAJ%2BvVBfNpTiL7RV7j3XGygljzi4NL8yXJuCLYiNxmqPMdV8DahLed0jSe2mkU1u6rx4yS3dcWEfwMWjI5tVrfnbqtdInC8TliXkTZ919CtORoydmIXGL1u3kdBIq8EZcjRMa4bN4VTvUlbqeIe8p8QYEQwAi7vXiZCKS6R6dmJfQv%2B%2FqBHXWSFuglLYde019GNtNdGQfEnY31zT0Q86ieDYn4k55LbYq5lK8PNjg50gdJxn9fNtHTQ7frKP9vRM4cImRSvDBTATVw1PDzMqn0exo3xciYd5%2BXYAxlFoqwFMDz40w2xR4OWwoPsixpVjR2DYiqYiZrYytFMjziRCLQhkVuJpED8nB9CTlo05WBKN%2Bb4UBHBg%2FkCkHXJxNakIX7UbAjDcqzrNCGhjrgehCGA81uOf0Ppfswda0ZHMi8g9W6Y7uwWmn7Ux7xBMgDCUNIi8I3UvLGXdKnuB8YHX8TLC1z2%2Fm3ip797Pix1ya2sBsbw9KgOJ7PBT0u9W0puchi7zpT%2FzFe3V2HbV0ottDethRJhzaN856VgvjyNhbbmA04gnal%2Fq01j7LNWxEwTjNPyHORI1l9jztvYqItLei7YQYg2pFhmvuv0Od8DPfH40Y1m3mL2F2d%2FAy3ImzFI%2BKQB6mnGPvRcDIS1j7zPhciKRuLfu3dCxhIH7ojo83rhQus3SyXdyZ5cjkFKcG3H7WmBBMOFs2o5xjWcdLARevRbNbqwRfATerc5GuJxy1Qb8RJvOqhDcS5YAHyxVMx2QYU3yMhg0tCpy4wW%2FHsa33feu3NeBu9lRI38ojJNM7o6xYRoSTQu4tYadB4Yh4w60e%2FsttnecOC5plZrLw6BYN2piqvUD07BnO4yTvrpdBDXR%2BMFDchnFh2YK9JtvvtAISvpoSOJojOhwRKuafCwEJn0GB1dsdmOOxxaFHkPXQ7789eCxlTL5mkVf3ktzmHQdDyBxBlDLFWSjmFIBHp%2BPobFdDOmv5p6J3%2F%2FM23PMgGDLRMrj5LVZV3trGV1ZaJHEFIGmVwW0tN4426Q4rCdcxT4ju%2B%2FNhcq90e8crWw9nrF2rPTzW1YM7VqWWwhLj8MtVtGZFa3N%2FxdjEys8FWyT8VqAbC4IltuT5lW1ou1SXsA96h%2F9y3vzJADbm4Lv624OGnh6M%2FCmR930i6YeUlWWmMw1%2FpcZ5werHPm9v0OWulNmGfbNEoKuThz2sSCZ8FLNVToygv1VXPXnur4dJnoCkwBP2%2BQQ6%2FHlyFRXnrrGsiDJE3qtRXgECIhc2zpuC5HAz9FhIfC9VZZ5nxRMbhA6W%2Fz%2BjPpKLCBpmLqHJfy8%2B%2FausiZJv7d9yQ0SvHtq0y%2FSY04hOgZTJul6IIYpObD6s%2FqrGy2nMmY3%2FtEn830%2F%2BFERnXMeBsj%2B%2F5ZSewYe4xBnub1wvSbsA3qjoU5gq7fhDJOhmMQXkbas%2FRholsU9CNKNXpSyqVarqAc8XwaG34JmdG3wjQXd6p%2Bz2jZLew5ja8nelvVdIeN%2F9ejCNOoXcPApYLHyxslcrEuJrSHlAMR4FbonfrFhYYTR%2B8pdxRGYGpVUDxlIRvay5xE4PoiuJ4tF82nhc3kr%2FsJWj86DXt9uK%2FPIDMokhA1wZ2BS8rN8V8J43gXMVkQtHFyqiAMoKttVwox3GtbTdmzYcjtjdZmL3VB27giGRreZsDbr6lsLJKVYnGtzAwL1nb45fLFtBNpiGXKHwE0soY3dapt%2FwadcvpFryVyG%2BesgLUwLWjgGepMMbQgPgi7Lk9TDgl5pO9Sg2%2B%2BCDEKkhmknkE%2FW4zr%2FbE3Qg97NK3hkIC0ajQvysQCsD2G98NREwRp5Yo2qUVqoKsz%2BM5FifnHVivHtbpB%2B0jSdbMPBVqrn6aJutLfJazoTo1MP5RGYQXwBR%2BiE%2BzrvvH3cYwPt7ac%2FkG%2BPEEDYQKPU%2F945Sh5D2ST2TwV1nVjoVq0xMgmM4rJmTTKSABcevdVyK41RiiOgJ1hXMLvtClnaA0rmU1zdilFkAHpka5VW9IKQa4edHYgnnLRdQfQ6YljskVGbbHuSZX9a5AiW9eHYyoNYZno%3D"
    ):
        return True
    return False


def PBKDF2_version_probe_matcher_incorrect(request):
    if (
        request.body != "dialogParametersHolder=AAAA"
        and request.body
        != "dialogParametersHolder=%2Bv%2BRs6kf9lDUYnqqYk32Vg84DkpdruQOKGZRmm6RMkaYuxNmvg5Ca5cT%2F74qkOozHIKkG1ovf6XBsjlp4kgO8BJ6KgNcT78BExQZfT1mN5rMO8kcLDRdffFhFXmvAr0o%2F4x%2B9VoRJVaOyGLXk2nhX4OMP%2BjGP2C96Fa6LyfGWHlk1CF0E5mAPeQ6CLbycR88WU5hlmUUqniXC2UdeYd6HO9RFnISEnhq72MkdiEfvNsqAhr2XaCX2%2BQxFXfCLi2%2Fc%2Bn2NmUiFRdhCLutnVxILEnYiRmU5eHJdB2IOTtoc2XZ3NUdZJwrwOswjzCkk7LOwt2bddTvOXdfWtRrbNz1GDNXlPz1cXotgAhucxLLsknNDbeeboMbL%2Bk3tIeervi7oI%2FRQn6Ml3ffUAfcqHzwcZCEIlQXh%2FBEIKHAY9fGKs5JSdtRbREDI0rh9sH%2B0TmYv444WQyqYpa8pOqtxgC1QRRcsNQcVGFzpyNL2SfKSlLTZi5Q7bo8XMTfLG6jg60csDEDiJ7MwJBGIm1iYzt%2FP9JEKkZujTMyHoBI0RESNpux7BeanEIDsfDmfwbcUo%2B2%2BkoHkCE4zXWBdW3lqssk4GwSbc0mbmf3U79rsQdNEqIOL87evE1U6tGB5PuXgwAIj9sKdyffd8%2B%2Bz1CCffFovLM72ilbCmSljAJ%2BvVBfNpTiL7RV7j3XGygljzi4NL8yXJuCLYiNxmqPMdV8DahLed0jSe2mkU1u6rx4yS3dcWEfwMWjI5tVrfnbqtdInC8TliXkTZ919CtORoydmIXGL1u3kdBIq8EZcjRMa4bN4VTvUlbqeIe8p8QYEQwAi7vXiZCKS6R6dmJfQv%2B%2FqBHXWSFuglLYde019GNtNdGQfEnY31zT0Q86ieDYn4k55LbYq5lK8PNjg50gdJxn9fNtHTQ7frKP9vRM4cImRSvDBTATVw1PDzMqn0exo3xciYd5%2BXYAxlFoqwFMDz40w2xR4OWwoPsixpVjR2DYiqYiZrYytFMjziRCLQhkVuJpED8nB9CTlo05WBKN%2Bb4UBHBg%2FkCkHXJxNakIX7UbAjDcqzrNCGhjrgehCGA81uOf0Ppfswda0ZHMi8g9W6Y7uwWmn7Ux7xBMgDCUNIi8I3UvLGXdKnuB8YHX8TLC1z2%2Fm3ip797Pix1ya2sBsbw9KgOJ7PBT0u9W0puchi7zpT%2FzFe3V2HbV0ottDethRJhzaN856VgvjyNhbbmA04gnal%2Fq01j7LNWxEwTjNPyHORI1l9jztvYqItLei7YQYg2pFhmvuv0Od8DPfH40Y1m3mL2F2d%2FAy3ImzFI%2BKQB6mnGPvRcDIS1j7zPhciKRuLfu3dCxhIH7ojo83rhQus3SyXdyZ5cjkFKcG3H7WmBBMOFs2o5xjWcdLARevRbNbqwRfATerc5GuJxy1Qb8RJvOqhDcS5YAHyxVMx2QYU3yMhg0tCpy4wW%2FHsa33feu3NeBu9lRI38ojJNM7o6xYRoSTQu4tYadB4Yh4w60e%2FsttnecOC5plZrLw6BYN2piqvUD07BnO4yTvrpdBDXR%2BMFDchnFh2YK9JtvvtAISvpoSOJojOhwRKuafCwEJn0GB1dsdmOOxxaFHkPXQ7789eCxlTL5mkVf3ktzmHQdDyBxBlDLFWSjmFIBHp%2BPobFdDOmv5p6J3%2F%2FM23PMgGDLRMrj5LVZV3trGV1ZaJHEFIGmVwW0tN4426Q4rCdcxT4ju%2B%2FNhcq90e8crWw9nrF2rPTzW1YM7VqWWwhLj8MtVtGZFa3N%2FxdjEys8FWyT8VqAbC4IltuT5lW1ou1SXsA96h%2F9y3vzJADbm4Lv624OGnh6M%2FCmR930i6YeUlWWmMw1%2FpcZ5werHPm9v0OWulNmGfbNEoKuThz2sSCZ8FLNVToygv1VXPXnur4dJnoCkwBP2%2BQQ6%2FHlyFRXnrrGsiDJE3qtRXgECIhc2zpuC5HAz9FhIfC9VZZ5nxRMbhA6W%2Fz%2BjPpKLCBpmLqHJfy8%2B%2FausiZJv7d9yQ0SvHtq0y%2FSY04hOgZTJul6IIYpObD6s%2FqrGy2nMmY3%2FtEn830%2F%2BFERnXMeBsj%2B%2F5ZSewYe4xBnub1wvSbsA3qjoU5gq7fhDJOhmMQXkbas%2FRholsU9CNKNXpSyqVarqAc8XwaG34JmdG3wjQXd6p%2Bz2jZLew5ja8nelvVdIeN%2F9ejCNOoXcPApYLHyxslcrEuJrSHlAMR4FbonfrFhYYTR%2B8pdxRGYGpVUDxlIRvay5xE4PoiuJ4tF82nhc3kr%2FsJWj86DXt9uK%2FPIDMokhA1wZ2BS8rN8V8J43gXMVkQtHFyqiAMoKttVwox3GtbTdmzYcjtjdZmL3VB27giGRreZsDbr6lsLJKVYnGtzAwL1nb45fLFtBNpiGXKHwE0soY3dapt%2FwadcvpFryVyG%2BesgLUwLWjgGepMMbQgPgi7Lk9TDgl5pO9Sg2%2B%2BCDEKkhmknkE%2FW4zr%2FbE3Qg97NK3hkIC0ajQvysQCsD2G98NREwRp5Yo2qUVqoKsz%2BM5FifnHVivHtbpB%2B0jSdbMPBVqrn6aJutLfJazoTo1MP5RGYQXwBR%2BiE%2BzrvvH3cYwPt7ac%2FkG%2BPEEDYQKPU%2F945Sh5D2ST2TwV1nVjoVq0xMgmM4rJmTTKSABcevdVyK41RiiOgJ1hXMLvtClnaA0rmU1zdilFkAHpka5VW9IKQa4edHYgnnLRdQfQ6YljskVGbbHuSZX9a5AiW9eHYyoNYZno%3D"
        and request.body
        != "dialogParametersHolder=Ct3E%2FAXZ0ct05hNqzzSbCRVxte%2F%2BQBIVbVz21p21CqLSnQsGfzTjsiq%2FxoAQaaDuaafBKu8cNXMOGT5kJcE0snNDBVbQqvbQLEYa1cWQYr%2FL2tOMq8Rnuzq6F7HKpN2%2BP0tdCPxrO3s6K2W43kvEO5wyaDlijlF9r2XI6UL1FUk%3D"
    ):
        return True
    return False


def PBKDF1_MS_found_key_matcher(request):
    if (
        request.body
        == "dialogParametersHolder=RW5hYmxlQXN5bmNVcGxvYWQsRmFsc2UsMyxUcnVlO0RlbGV0ZVBhdGhzLFRydWUsMCxabWs0ZFV4M1BUMHNabWs0ZFV4M1BUMD07RW5hYmxlRW1iZWRkZWRCYXNlU3R5bGVzaGVldCxGYWxzZSwzLFRydWU7UmVuZGVyTW9kZSxGYWxzZSwyLDI7VXBsb2FkUGF0aHMsVHJ1ZSwwLFptazRkVXgzUFQwc1ptazRkVXgzUFQwPTtTZWFyY2hQYXR0ZXJucyxUcnVlLDAsUzJrMGNRPT07RW5hYmxlRW1iZWRkZWRTa2lucyxGYWxzZSwzLFRydWU7TWF4VXBsb2FkRmlsZVNpemUsRmFsc2UsMSwyMDQ4MDA7TG9jYWxpemF0aW9uUGF0aCxGYWxzZSwwLDtGaWxlQnJvd3NlckNvbnRlbnRQcm92aWRlclR5cGVOYW1lLEZhbHNlLDAsO1ZpZXdQYXRocyxUcnVlLDAsWm1rNGRVeDNQVDBzWm1rNGRVeDNQVDA9O0lzU2tpblRvdWNoLEZhbHNlLDMsRmFsc2U7U2NyaXB0TWFuYWdlclByb3BlcnRpZXMsRmFsc2UsMCxDZ29LQ2taaGJITmxDakFLQ2dvSztFeHRlcm5hbERpYWxvZ3NQYXRoLEZhbHNlLDAsO0xhbmd1YWdlLEZhbHNlLDAsWlc0dFZWTT07VGVsZXJpay5EaWFsb2dEZWZpbml0aW9uLkRpYWxvZ1R5cGVOYW1lLEZhbHNlLDAsVkdWc1pYSnBheTVYWldJdVZVa3VSV1JwZEc5eUxrUnBZV3h2WjBOdmJuUnliMnh6TGtSdlkzVnRaVzUwVFdGdVlXZGxja1JwWVd4dlp5d2dWR1ZzWlhKcGF5NVhaV0l1VlVrc0lGWmxjbk5wYjI0OU1qQXhPQzR4TGpFeE55NDBOU3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHhNakZtWVdVM09ERTJOV0poTTJRMDtBbGxvd011bHRpcGxlU2VsZWN0aW9uLEZhbHNlLDMsRmFsc2U%3DL5sb9SKliKw%2Bw6w13%2FzMlFZ52mRvsWTpQO3uN4eQQ7k%3D"
        and request.body != "dialogParametersHolder=AAAA"
    ):
        return True
    return False


def PBKDF1_MS_found_key_matcher_negative(request):
    if (
        request.body
        == "dialogParametersHolder=RW5hYmxlQXN5bmNVcGxvYWQsRmFsc2UsMyxUcnVlO0RlbGV0ZVBhdGhzLFRydWUsMCxabWs0ZFV4M1BUMHNabWs0ZFV4M1BUMD07RW5hYmxlRW1iZWRkZWRCYXNlU3R5bGVzaGVldCxGYWxzZSwzLFRydWU7UmVuZGVyTW9kZSxGYWxzZSwyLDI7VXBsb2FkUGF0aHMsVHJ1ZSwwLFptazRkVXgzUFQwc1ptazRkVXgzUFQwPTtTZWFyY2hQYXR0ZXJucyxUcnVlLDAsUzJrMGNRPT07RW5hYmxlRW1iZWRkZWRTa2lucyxGYWxzZSwzLFRydWU7TWF4VXBsb2FkRmlsZVNpemUsRmFsc2UsMSwyMDQ4MDA7TG9jYWxpemF0aW9uUGF0aCxGYWxzZSwwLDtGaWxlQnJvd3NlckNvbnRlbnRQcm92aWRlclR5cGVOYW1lLEZhbHNlLDAsO1ZpZXdQYXRocyxUcnVlLDAsWm1rNGRVeDNQVDBzWm1rNGRVeDNQVDA9O0lzU2tpblRvdWNoLEZhbHNlLDMsRmFsc2U7U2NyaXB0TWFuYWdlclByb3BlcnRpZXMsRmFsc2UsMCxDZ29LQ2taaGJITmxDakFLQ2dvSztFeHRlcm5hbERpYWxvZ3NQYXRoLEZhbHNlLDAsO0xhbmd1YWdlLEZhbHNlLDAsWlc0dFZWTT07VGVsZXJpay5EaWFsb2dEZWZpbml0aW9uLkRpYWxvZ1R5cGVOYW1lLEZhbHNlLDAsVkdWc1pYSnBheTVYWldJdVZVa3VSV1JwZEc5eUxrUnBZV3h2WjBOdmJuUnliMnh6TGtSdlkzVnRaVzUwVFdGdVlXZGxja1JwWVd4dlp5d2dWR1ZzWlhKcGF5NVhaV0l1VlVrc0lGWmxjbk5wYjI0OU1qQXhPQzR4TGpFeE55NDBOU3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHhNakZtWVdVM09ERTJOV0poTTJRMDtBbGxvd011bHRpcGxlU2VsZWN0aW9uLEZhbHNlLDMsRmFsc2U%3DL5sb9SKliKw%2Bw6w13%2FzMlFZ52mRvsWTpQO3uN4eQQ7k%3D"
        and request.body != "dialogParametersHolder=AAAA"
    ):
        return False
    return True


def PBKDF1_MS_probe_matcher(request):
    if request.body == "dialogParametersHolder=AAAA":
        return True
    return False


def PBKDF1_MS_encryption_probe_matcher(request):
    if (
        request.body
        == "dialogParametersHolder=CaCbLSlA%2F3GG4AJY2Lrkw%2FYyoo9hsLMk7MDf5Ku5qk7ALj2MhWj%2BdiVwDJIpxdOfGYYKT%2BtFcvqOSZPRZZas0cgfM1xZtoJ0rDr0vHZCeKF2MchSI7T4s1rp%2F17FOhy0VFUWETHfD47ah6CDQGtptldvlYp5Iq5FSRMgJrFZ6V8%3D"
    ):
        return True
    return False


def PBKDF1_MS_version_probe_matcher_incorrect(request):
    if (
        request.body != "dialogParametersHolder=AAAA"
        and request.body
        != "dialogParametersHolder=RW5hYmxlQXN5bmNVcGxvYWQsRmFsc2UsMyxUcnVlO0RlbGV0ZVBhdGhzLFRydWUsMCxabWs0ZFV4M1BUMHNabWs0ZFV4M1BUMD07RW5hYmxlRW1iZWRkZWRCYXNlU3R5bGVzaGVldCxGYWxzZSwzLFRydWU7UmVuZGVyTW9kZSxGYWxzZSwyLDI7VXBsb2FkUGF0aHMsVHJ1ZSwwLFptazRkVXgzUFQwc1ptazRkVXgzUFQwPTtTZWFyY2hQYXR0ZXJucyxUcnVlLDAsUzJrMGNRPT07RW5hYmxlRW1iZWRkZWRTa2lucyxGYWxzZSwzLFRydWU7TWF4VXBsb2FkRmlsZVNpemUsRmFsc2UsMSwyMDQ4MDA7TG9jYWxpemF0aW9uUGF0aCxGYWxzZSwwLDtGaWxlQnJvd3NlckNvbnRlbnRQcm92aWRlclR5cGVOYW1lLEZhbHNlLDAsO1ZpZXdQYXRocyxUcnVlLDAsWm1rNGRVeDNQVDBzWm1rNGRVeDNQVDA9O0lzU2tpblRvdWNoLEZhbHNlLDMsRmFsc2U7U2NyaXB0TWFuYWdlclByb3BlcnRpZXMsRmFsc2UsMCxDZ29LQ2taaGJITmxDakFLQ2dvSztFeHRlcm5hbERpYWxvZ3NQYXRoLEZhbHNlLDAsO0xhbmd1YWdlLEZhbHNlLDAsWlc0dFZWTT07VGVsZXJpay5EaWFsb2dEZWZpbml0aW9uLkRpYWxvZ1R5cGVOYW1lLEZhbHNlLDAsVkdWc1pYSnBheTVYWldJdVZVa3VSV1JwZEc5eUxrUnBZV3h2WjBOdmJuUnliMnh6TGtSdlkzVnRaVzUwVFdGdVlXZGxja1JwWVd4dlp5d2dWR1ZzWlhKcGF5NVhaV0l1VlVrc0lGWmxjbk5wYjI0OU1qQXhPQzR4TGpFeE55NDBOU3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHhNakZtWVdVM09ERTJOV0poTTJRMDtBbGxvd011bHRpcGxlU2VsZWN0aW9uLEZhbHNlLDMsRmFsc2U%3DL5sb9SKliKw%2Bw6w13%2FzMlFZ52mRvsWTpQO3uN4eQQ7k%3D"
        and request.body
        != "dialogParametersHolder=CaCbLSlA%2F3GG4AJY2Lrkw%2FYyoo9hsLMk7MDf5Ku5qk7ALj2MhWj%2BdiVwDJIpxdOfGYYKT%2BtFcvqOSZPRZZas0cgfM1xZtoJ0rDr0vHZCeKF2MchSI7T4s1rp%2F17FOhy0VFUWETHfD47ah6CDQGtptldvlYp5Iq5FSRMgJrFZ6V8%3D"
        and request.body
        != "dialogParametersHolder=gRRgyE4BOGtN%2FLtBxeEeJDuLj%2FUwIG4oBhO5rCDfPjeH10P8Y02mDK3B%2FtsdOIrwILK7XjQiuTlTZMgHckSyb518JPAo6evNlVTPWD5AZX5l4UIUkfdJvq28UHyeBA4eC58PfA6nG7V2Q97Qwqef6cpbM6t88zvE0wJt8uUKji4ZfyBif4du8JgpDzzdSi%2BlWYd3YhzNbbfKVH%2F0sfraIHOsRvwNwrVc0V%2Fnmn%2BGlqm1rheswSONIo7BzKo04RLb232aDuWcluEWDMFdNJpzpdgcq96mWrs9KttFyRjUZ%2FhUi8ZQi0R4GXCrfHRTAYOq%2B2TNdECbAEfmA4n9Pb0BDDGDfghLV6h%2FbLrUaMWZCx6U5zCQfymn96h1t5acGgfxYMCS%2FYS7WRPytc759VdSM2KhGVmuGlupbxVz5gVOWffo5rTDQxwiPhcWYHTJlN%2FawmJfHJsJV0WvTBaW9nEPL0QeeUEu3jc7OPW9CbVufHb7Rfg7RQ%2F6Gjz5TBlzfY32lcFTsyRolWjxU3%2FVBb09tcN2EJGBnjZxpl6eFsYOvexTx0ykt0PCQagdR0DPFLPsdj7kDMrdDhpMDjsqQA0W06ULEtlR8unWsjavyK0%2B8CuTN%2BkuMzFrH10Wvqb5j3SYwANq3pyEuf3OScByrY8NVz7EzX%2BYQb5%2FByHmXi99NCHbO6ZQyHnM%2BPWYwinlnFrU6f%2BvI2ruMl35dZ%2BWWSGnEdv0DVxiedxWgqDlov31JoGaaffpBs8OO3LhtYqIixQPFbjq2wPrEcHPLgM40eYtJfduPI6exc%2BkKlxFGOyB44XjDuC4VHBPmCCFH%2FguBAatG%2FSZU1z%2Fj%2FJ0YDIVedDDdPg2NtQXjjjidSW8ISbfOk1SoLSFz04F9BmmMnPVsg9Dvtbbf%2Bz%2FhudrAo9Ys%2Fa6OzksFXxwQ%2FcSIDYVAsYkRjDMcgRv6erm8bBqgABiSF7SwBLkL75mI18fA3qCxgYDrcXZJYCIbS%2BQg9QiROf7PnRBcrnAg0G2ArfRY5gQE69DA4hvUFuXZvCbVbqQGZs7TrKNqBH40DzPqKFqhBKawuCF84zc08QzWVdbl92rAUl%2FbGi6RYzgx27pPzu7LbYLl4G8a5vtVZjuK7SchY0B7FfMvF3uQA%2FY4G%2FjqDGqGshadxalKPmwfUNbDSaatepav%2Bx4zfzQhn6cV2r8t1qz1TfHypR%2BCaAEVhEa36reVmWrAKXjr0JFOSSAQJTti%2BKhNRhaVPTgVI%2BsX%2F0pf8Fn0Zvv%2FbPL9C9L1pEAco%2FGIOV9AHNoh5E18zHcmINA2HmoZWha91ONomoIGvWnlM5USb%2FYSrXZuJDsSFFU9oal%2F45NDUNWlNVsXD%2B8RvuVsl1DY7i9iftU%2FtZpskuIldUFYmXWgMWCwk6sQAaARQoQKBEvCL6OV8UcD3bsde0ubcUG9oH140jsAW6Yh7okoKYZlL2xtp4ba7o8CS3R%2FduPuJLFY6fUexkHpvKj1Nn%2B31oQSjRywNhDdNvlczG4Z2LI73TdsZuCKnSPHNF7DNtOxmeGKZl9z9utufWZIb1FetBPy97bOOVKx69nZYTjmfv7hzBuEd5SweBD9QA2WspaycH9H01R4IXXcnrWKHkkaaVS3jDR%2F%2Bll4S0yGKlVT8EiRqLcZVX6mP2C7tmpbTE1tE%2F5ydEXkHMQ4Q75MDhO6F24ahX2rF%2FyfzuAMnR784wtXAM2E3hvVbCzu1rS9Xy1O7uSL%2Fzw1PxRlBZ%2FTwP00bUw22fQfnye%2Fb5s1NmvpWcrSX6tUNlK%2BrCHlfKSxWVhMWiZOqjMq9chUja87UzhcVXYBWZqhfuGsbRIoDQ40P6k7LDTuuzR7UuMU0nPFvGXsfwyu4UQzQppBmjwdQQlpo9GK2XAR7M2Wj5XNB5yZ3n8uMfW%2BktjiC0yW9bo0BVtvvmEOayXYwXyndHauAcJ0HpHnRLtnzNKnTKI3IY%2Fl4kYFS%2BiYUk6n0nd2eVKroYdrMjKZehZmpwmXfU3%2FWpwmt6HK%2FWKAWZzjlEUaN5zDbG%2BtGNxrjYaVvJuDn2uVtmozVU8dbCdz82O6sukqV5QZ86FFImnlZPOKcSHIFq%2F%2B1AdBG%2FUEKZ28aaadpm11H4ovyjAawjFwoWhtDsJB%2F1YbGDIqlKJ40ZOav8gu1Q%2Bv9UtpaQsDfm84FjlzlmwRQn2LF%2FBZLNmAjc8uug0sItSc2bX9d7gR9EWc3KML3PiBecc%2B6LfUkd5WyqHKPP%2FHDETbor16YGv%2Bt3d6KNtQgY3p%2B2Y8kVRCqtngKNzuid%2FXOmNTpwgKgj69id3uo8asDGcs%2B%2FVu5WjbkDNF%2FJlg2TWyTzwpr53wOKmm6tsWwf2FYScCHzXvfWjxHIR9qyGtIOembCqhaK%2Bv7NYDhaI8dAOtvz2su0yzecbzGa65MlwPIyRmv458OLvCMd1BLubANPxC3YfpMHm7x0JllAwNm4K%2BfM73Qkk6jsLwAr28YC1rvMCRONv4Q0sqEpuXfGbS212hv2LeVMq9wrORW353yq2MeRDxFnc2v0oTtVL9D7nlAlBXotJu4rT%2FzhFkH%2Be%2Fbmcbe1sgbaR4BIqrp65Nwq7RjjbB8FX8fi3xA%2BVE68b9DwmAMsub7oVbmI%2B09Wf85hjYjV5fS1xHdKqT6GRTqF9HhkiRxSIDKXzMM7pBXvzwuG%2BOWTVEBOgctSA2alhhyKvUBizsrW6TO%2FSPoX8n%2Fg3qUfufYGrb05PuoeDayC9iZEzmYc%3D"
    ):
        return True
    return False


def test_examples_telerik_knownkey_argparsing(monkeypatch, capsys):
    # URL is required
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
        ],
    )
    with patch("sys.exit") as exit_mock:
        telerik_knownkey.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        print(captured)
        assert "the following arguments are required: -u/--url" in captured.err

    # Invalid URL is rejected

    monkeypatch.setattr(
        "sys.argv",
        ["python", "--url", "NOTaURL"],
    )
    with patch("sys.exit") as exit_mock:
        telerik_knownkey.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        print(captured)
        assert "URL is not formatted correctly" in captured.err


def test_non_telerik_ui(monkeypatch, capsys):
    # Non-Telerk UI is detected
    with requests_mock.Mocker() as m:
        m.get(
            f"http://nottelerik.com/Telerik.Web.UI.DialogHandler.aspx",
            status_code=200,
            text="<html><p>Just a regular website</p></html>",
        )
        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://nottelerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured)
        assert "URL does not appear to be a Telerik UI DialogHandler" in captured.out


def test_url_not_up(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        # URL is down - handled correctly

        m.get(f"http://notreal.com/", exc=requests.exceptions.ConnectTimeout)
        monkeypatch.setattr("sys.argv", ["python", "--url", "http://notreal.com"])
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "Error connecting to URL" in captured.out


def test_fullrun_PBKDF2(monkeypatch, capsys, mocker):

    def generate_keylist_enc(include_machinekeys):
        return iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        )

    def generate_keylist_hash(include_machinekeys):
        return iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"])

    mocker.patch.object(Telerik_EncryptionKey, "prepare_keylist", side_effect=generate_keylist_enc)
    mocker.patch.object(Telerik_HashKey, "prepare_keylist", side_effect=generate_keylist_hash)

    with requests_mock.Mocker() as m:
        # Basic Probe Detects Telerik
        m.get(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx", status_code=200, text=partial_dialog_page
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_found_key_matcher,
            status_code=200,
            text="Please refresh the editor page.</div><div>Error Message:Index was outside the bounds of the array",
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_found_key_matcher_negative,
            status_code=200,
            text="<div>Error Message:Exception of type 'System.Exception' was thrown.</div>",
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_version_probe_matcher,
            status_code=200,
            text="DoesntMatter",
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_version_probe_matcher_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert "Target is a newer version of Telerik UI" in captured.out
        assert "Found Encryption key!" in captured.out
        assert "Found matching hashkey!" in captured.out
        assert (
            "%2Bv%2BRs6kf9lDUYnqqYk32Vg84DkpdruQOKGZRmm6RMkaYuxNmvg5Ca5cT%2F74qkOozHIKkG1ovf6XBsjlp4kgO8BJ6KgNcT78BExQZfT1mN5rMO8kcLDRdffFhFXmvAr0o%2F4x%2B9VoRJVaOyGLXk2nhX4OMP%2BjGP2C96Fa6LyfGWHlk1CF0E5mAPeQ6CLbycR88WU5hlmUUqniXC2UdeYd6HO9RFnISEnhq72MkdiEfvNsqAhr2XaCX2%2BQxFXfCLi2%2Fc%2Bn2NmUiFRdhCLutnVxILEnYiRmU5eHJdB2IOTtoc2XZ3NUdZJwrwOswjzCkk7LOwt2bddTvOXdfWtRrbNz1GDNXlPz1cXotgAhucxLLsknNDbeeboMbL%2Bk3tIeervi7oI%2FRQn6Ml3ffUAfcqHzwcZCEIlQXh%2FBEIKHAY9fGKs5JSdtRbREDI0rh9sH%2B0TmYv444WQyqYpa8pOqtxgC1QRRcsNQcVGFzpyNL2SfKSlLTZi5Q7bo8XMTfLG6jg60csDEDiJ7MwJBGIm1iYzt%2FP9JEKkZujTMyHoBI0RESNpux7BeanEIDsfDmfwbcUo%2B2%2BkoHkCE4zXWBdW3lqssk4GwSbc0mbmf3U79rsQdNEqIOL87evE1U6tGB5PuXgwAIj9sKdyffd8%2B%2Bz1CCffFovLM72ilbCmSljAJ%2BvVBfNpTiL7RV7j3XGygljzi4NL8yXJuCLYiNxmqPMdV8DahLed0jSe2mkU1u6rx4yS3dcWEfwMWjI5tVrfnbqtdInC8TliXkTZ919CtORoydmIXGL1u3kdBIq8EZcjRMa4bN4VTvUlbqeIe8p8QYEQwAi7vXiZCKS6R6dmJfQv%2B%2FqBHXWSFuglLYde019GNtNdGQfEnY31zT0Q86ieDYn4k55LbYq5lK8PNjg50gdJxn9fNtHTQ7frKP9vRM4cImRSvDBTATVw1PDzMqn0exo3xciYd5%2BXYAxlFoqwFMDz40w2xR4OWwoPsixpVjR2DYiqYiZrYytFMjziRCLQhkVuJpED8nB9CTlo05WBKN%2Bb4UBHBg%2FkCkHXJxNakIX7UbAjDcqzrNCGhjrgehCGA81uOf0Ppfswda0ZHMi8g9W6Y7uwWmn7Ux7xBMgDCUNIi8I3UvLGXdKnuB8YHX8TLC1z2%2Fm3ip797Pix1ya2sBsbw9KgOJ7PBT0u9W0puchi7zpT%2FzFe3V2HbV0ottDethRJhzaN856VgvjyNhbbmA04gnal%2Fq01j7LNWxEwTjNPyHORI1l9jztvYqItLei7YQYg2pFhmvuv0Od8DPfH40Y1m3mL2F2d%2FAy3ImzFI%2BKQB6mnGPvRcDIS1j7zPhciKRuLfu3dCxhIH7ojo83rhQus3SyXdyZ5cjkFKcG3H7WmBBMOFs2o5xjWcdLARevRbNbqwRfATerc5GuJxy1Qb8RJvOqhDcS5YAHyxVMx2QYU3yMhg0tCpy4wW%2FHsa33feu3NeBu9lRI38ojJNM7o6xYRoSTQu4tYadB4Yh4w60e%2FsttnecOC5plZrLw6BYN2piqvUD07BnO4yTvrpdBDXR%2BMFDchnFh2YK9JtvvtAISvpoSOJojOhwRKuafCwEJn0GB1dsdmOOxxaFHkPXQ7789eCxlTL5mkVf3ktzmHQdDyBxBlDLFWSjmFIBHp%2BPobFdDOmv5p6J3%2F%2FM23PMgGDLRMrj5LVZV3trGV1ZaJHEFIGmVwW0tN4426Q4rCdcxT4ju%2B%2FNhcq90e8crWw9nrF2rPTzW1YM7VqWWwhLj8MtVtGZFa3N%2FxdjEys8FWyT8VqAbC4IltuT5lW1ou1SXsA96h%2F9y3vzJADbm4Lv624OGnh6M%2FCmR930i6YeUlWWmMw1%2FpcZ5werHPm9v0OWulNmGfbNEoKuThz2sSCZ8FLNVToygv1VXPXnur4dJnoCkwBP2%2BQQ6%2FHlyFRXnrrGsiDJE3qtRXgECIhc2zpuC5HAz9FhIfC9VZZ5nxRMbhA6W%2Fz%2BjPpKLCBpmLqHJfy8%2B%2FausiZJv7d9yQ0SvHtq0y%2FSY04hOgZTJul6IIYpObD6s%2FqrGy2nMmY3%2FtEn830%2F%2BFERnXMeBsj%2B%2F5ZSewYe4xBnub1wvSbsA3qjoU5gq7fhDJOhmMQXkbas%2FRholsU9CNKNXpSyqVarqAc8XwaG34JmdG3wjQXd6p%2Bz2jZLew5ja8nelvVdIeN%2F9ejCNOoXcPApYLHyxslcrEuJrSHlAMR4FbonfrFhYYTR%2B8pdxRGYGpVUDxlIRvay5xE4PoiuJ4tF82nhc3kr%2FsJWj86DXt9uK%2FPIDMokhA1wZ2BS8rN8V8J43gXMVkQtHFyqiAMoKttVwox3GtbTdmzYcjtjdZmL3VB27giGRreZsDbr6lsLJKVYnGtzAwL1nb45fLFtBNpiGXKHwE0soY3dapt%2FwadcvpFryVyG%2BesgLUwLWjgGepMMbQgPgi7Lk9TDgl5pO9Sg2%2B%2BCDEKkhmknkE%2FW4zr%2FbE3Qg97NK3hkIC0ajQvysQCsD2G98NREwRp5Yo2qUVqoKsz%2BM5FifnHVivHtbpB%2B0jSdbMPBVqrn6aJutLfJazoTo1MP5RGYQXwBR%2BiE%2BzrvvH3cYwPt7ac%2FkG%2BPEEDYQKPU%2F945Sh5D2ST2TwV1nVjoVq0xMgmM4rJmTTKSABcevdVyK41RiiOgJ1hXMLvtClnaA0rmU1zdilFkAHpka5VW9IKQa4edHYgnnLRdQfQ6YljskVGbbHuSZX9a5AiW9eHYyoNYZno%3D"
            in captured.out
        )
        print(captured.out)


def test_nomatch_PBKDF2(monkeypatch, capsys, mocker):

    def generate_keylist_enc(include_machinekeys):
        return iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        )

    def generate_keylist_hash(include_machinekeys):
        return iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"])

    mocker.patch.object(Telerik_EncryptionKey, "prepare_keylist", side_effect=generate_keylist_enc)
    mocker.patch.object(Telerik_HashKey, "prepare_keylist", side_effect=generate_keylist_hash)

    with requests_mock.Mocker() as m:
        # Basic Probe Detects Telerik
        m.get(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx", status_code=200, text=partial_dialog_page
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            status_code=200,
            text="<div>Error Message:Exception of type 'System.Exception' was thrown.</div>",
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_version_probe_matcher,
            status_code=200,
            text="DoesntMatter",
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_version_probe_matcher_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx", "--machine-keys"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert "Target is a newer version of Telerik UI" in captured.out
        assert (
            "Warning: MachineKeys inclusion mode is enabled, which affects this Telerik version particularly dramatically. Brute Forcing will be VERY SLOW"
            in captured.out
        )
        print(captured.out)


def test_fullrun_PBKDF1_MS(monkeypatch, capsys, mocker):
    mocker.patch.object(
        Telerik_EncryptionKey,
        "prepare_keylist",
        return_value=iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        ),
    )
    mocker.patch.object(
        Telerik_HashKey,
        "prepare_keylist",
        return_value=iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"]),
    )

    with requests_mock.Mocker() as m:
        # Basic Probe Detects Telerik
        m.get(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            status_code=200,
            text=partial_dialog_page,
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_found_key_matcher,
            status_code=200,
            text="<div>Error Message:The input data is not a complete block.</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_found_key_matcher_negative,
            status_code=200,
            text="<div>Error Message:The hash is not valid!</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_probe_matcher,
            status_code=200,
            text="Error Message:Length cannot be less than zero",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_encryption_probe_matcher,
            status_code=200,
            text="<div>Error Message:Index was outside the bounds of the array.</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_version_probe_matcher_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "Target is a valid DialogHandler endpoint. Brute forcing Telerik Hash Key" in captured.out
        assert "Found matching hashkey! [YOUR_ENCRYPTION_KEY_TO_GO_HERE]" in captured.out
        assert "Found Encryption key! [d2a312d9-7af4-43de-be5a-ae717b46cea6]" in captured.out
        assert "Found Telerik Version! [2018.1.117]" in captured.out
        assert (
            "gRRgyE4BOGtN%2FLtBxeEeJDuLj%2FUwIG4oBhO5rCDfPjeH10P8Y02mDK3B%2FtsdOIrwILK7XjQiuTlTZMgHckSyb518JPAo6evNlVTPWD5AZX5l4UIUkfdJvq28UHyeBA4eC58PfA6nG7V2Q97Qwqef6cpbM6t88zvE0wJt8uUKji4ZfyBif4du8JgpDzzdSi%2BlWYd3YhzNbbfKVH%2F0sfraIHOsRvwNwrVc0V%2Fnmn%2BGlqm1rheswSONIo7BzKo04RLb232aDuWcluEWDMFdNJpzpdgcq96mWrs9KttFyRjUZ%2FhUi8ZQi0R4GXCrfHRTAYOq%2B2TNdECbAEfmA4n9Pb0BDDGDfghLV6h%2FbLrUaMWZCx6U5zCQfymn96h1t5acGgfxYMCS%2FYS7WRPytc759VdSM2KhGVmuGlupbxVz5gVOWffo5rTDQxwiPhcWYHTJlN%2FawmJfHJsJV0WvTBaW9nEPL0QeeUEu3jc7OPW9CbVufHb7Rfg7RQ%2F6Gjz5TBlzfY32lcFTsyRolWjxU3%2FVBb09tcN2EJGBnjZxpl6eFsYOvexTx0ykt0PCQagdR0DPFLPsdj7kDMrdDhpMDjsqQA0W06ULEtlR8unWsjavyK0%2B8CuTN%2BkuMzFrH10Wvqb5j3SYwANq3pyEuf3OScByrY8NVz7EzX%2BYQb5%2FByHmXi99NCHbO6ZQyHnM%2BPWYwinlnFrU6f%2BvI2ruMl35dZ%2BWWSGnEdv0DVxiedxWgqDlov31JoGaaffpBs8OO3LhtYqIixQPFbjq2wPrEcHPLgM40eYtJfduPI6exc%2BkKlxFGOyB44XjDuC4VHBPmCCFH%2FguBAatG%2FSZU1z%2Fj%2FJ0YDIVedDDdPg2NtQXjjjidSW8ISbfOk1SoLSFz04F9BmmMnPVsg9Dvtbbf%2Bz%2FhudrAo9Ys%2Fa6OzksFXxwQ%2FcSIDYVAsYkRjDMcgRv6erm8bBqgABiSF7SwBLkL75mI18fA3qCxgYDrcXZJYCIbS%2BQg9QiROf7PnRBcrnAg0G2ArfRY5gQE69DA4hvUFuXZvCbVbqQGZs7TrKNqBH40DzPqKFqhBKawuCF84zc08QzWVdbl92rAUl%2FbGi6RYzgx27pPzu7LbYLl4G8a5vtVZjuK7SchY0B7FfMvF3uQA%2FY4G%2FjqDGqGshadxalKPmwfUNbDSaatepav%2Bx4zfzQhn6cV2r8t1qz1TfHypR%2BCaAEVhEa36reVmWrAKXjr0JFOSSAQJTti%2BKhNRhaVPTgVI%2BsX%2F0pf8Fn0Zvv%2FbPL9C9L1pEAco%2FGIOV9AHNoh5E18zHcmINA2HmoZWha91ONomoIGvWnlM5USb%2FYSrXZuJDsSFFU9oal%2F45NDUNWlNVsXD%2B8RvuVsl1DY7i9iftU%2FtZpskuIldUFYmXWgMWCwk6sQAaARQoQKBEvCL6OV8UcD3bsde0ubcUG9oH140jsAW6Yh7okoKYZlL2xtp4ba7o8CS3R%2FduPuJLFY6fUexkHpvKj1Nn%2B31oQSjRywNhDdNvlczG4Z2LI73TdsZuCKnSPHNF7DNtOxmeGKZl9z9utufWZIb1FetBPy97bOOVKx69nZYTjmfv7hzBuEd5SweBD9QA2WspaycH9H01R4IXXcnrWKHkkaaVS3jDR%2F%2Bll4S0yGKlVT8EiRqLcZVX6mP2C7tmpbTE1tE%2F5ydEXkHMQ4Q75MDhO6F24ahX2rF%2FyfzuAMnR784wtXAM2E3hvVbCzu1rS9Xy1O7uSL%2Fzw1PxRlBZ%2FTwP00bUw22fQfnye%2Fb5s1NmvpWcrSX6tUNlK%2BrCHlfKSxWVhMWiZOqjMq9chUja87UzhcVXYBWZqhfuGsbRIoDQ40P6k7LDTuuzR7UuMU0nPFvGXsfwyu4UQzQppBmjwdQQlpo9GK2XAR7M2Wj5XNB5yZ3n8uMfW%2BktjiC0yW9bo0BVtvvmEOayXYwXyndHauAcJ0HpHnRLtnzNKnTKI3IY%2Fl4kYFS%2BiYUk6n0nd2eVKroYdrMjKZehZmpwmXfU3%2FWpwmt6HK%2FWKAWZzjlEUaN5zDbG%2BtGNxrjYaVvJuDn2uVtmozVU8dbCdz82O6sukqV5QZ86FFImnlZPOKcSHIFq%2F%2B1AdBG%2FUEKZ28aaadpm11H4ovyjAawjFwoWhtDsJB%2F1YbGDIqlKJ40ZOav8gu1Q%2Bv9UtpaQsDfm84FjlzlmwRQn2LF%2FBZLNmAjc8uug0sItSc2bX9d7gR9EWc3KML3PiBecc%2B6LfUkd5WyqHKPP%2FHDETbor16YGv%2Bt3d6KNtQgY3p%2B2Y8kVRCqtngKNzuid%2FXOmNTpwgKgj69id3uo8asDGcs%2B%2FVu5WjbkDNF%2FJlg2TWyTzwpr53wOKmm6tsWwf2FYScCHzXvfWjxHIR9qyGtIOembCqhaK%2Bv7NYDhaI8dAOtvz2su0yzecbzGa65MlwPIyRmv458OLvCMd1BLubANPxC3YfpMHm7x0JllAwNm4K%2BfM73Qkk6jsLwAr28YC1rvMCRONv4Q0sqEpuXfGbS212hv2LeVMq9wrORW353yq2MeRDxFnc2v0oTtVL9D7nlAlBXotJu4rT%2FzhFkH%2Be%2Fbmcbe1sgbaR4BIqrp65Nwq7RjjbB8FX8fi3xA%2BVE68b9DwmAMsub7oVbmI%2B09Wf85hjYjV5fS1xHdKqT6GRTqF9HhkiRxSIDKXzMM7pBXvzwuG%2BOWTVEBOgctSA2alhhyKvUBizsrW6TO%2FSPoX8n%2Fg3qUfufYGrb05PuoeDayC9iZEzmYc%3D"
            in captured.out
        )
        print(captured)


def test_misctest_PBKDF1_MS(monkeypatch, capsys, mocker):

    mocker.patch.object(
        telerik_knownkey,
        "telerik_versions",
        [],
    )

    mocker.patch.object(
        telerik_knownkey,
        "telerik_versions_patched",
        [],
    )

    mocker.patch.object(
        Telerik_EncryptionKey,
        "prepare_keylist",
        return_value=iter(["Not_The_Real_Encryption_Key", "aaaaaaaaaaaaaaaaaaaaaaa", "another_fake_encryption_key"]),
    )
    mocker.patch.object(
        Telerik_HashKey,
        "prepare_keylist",
        return_value=iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"]),
    )

    with requests_mock.Mocker() as m:

        m.get(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            status_code=200,
            text=partial_dialog_page,
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_found_key_matcher,
            status_code=200,
            text="<div>Error Message:The input data is not a complete block.</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_found_key_matcher_negative,
            status_code=200,
            text="<div>Error Message:The hash is not valid!</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_probe_matcher,
            status_code=200,
            text="Error Message:Length cannot be less than zero",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_encryption_probe_matcher,
            status_code=200,
            text="<div>Error Message:Index was outside the bounds of the array.</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_version_probe_matcher_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "Target is a valid DialogHandler endpoint. Brute forcing Telerik Hash Key" in captured.out
        assert "Found Telerik Version!" not in captured.out
        assert "Since we found a valid hash key, we can check for known Telerik Encryption Keys" in captured.out
        assert "Could not identify encryption key." in captured.out
        print(captured.out)


def test_nomatch_PBKDF1_MS(monkeypatch, capsys, mocker):
    def generate_keylist_enc(include_machinekeys):
        return iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        )

    def generate_keylist_hash(include_machinekeys):
        return iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"])

    mocker.patch.object(Telerik_EncryptionKey, "prepare_keylist", side_effect=generate_keylist_enc)
    mocker.patch.object(Telerik_HashKey, "prepare_keylist", side_effect=generate_keylist_hash)

    with requests_mock.Mocker() as m:

        m.get(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            status_code=200,
            text=partial_dialog_page,
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=pre2017_matcher_probe,
            status_code=200,
            text="<div style='color:red'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters. </div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=pre2017_matcher,
            status_code=200,
            text="<div style='color:red'>Cannot deserialize dialog parameters. Please refresh the editor page.</div><div>Error Message:Invalid length for a Base-64 char array or string.</div>",
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "This means it should be vulnerable to CVE-2017-9248!!!" in captured.out


def test_badoutput_PBKDF1_MS(monkeypatch, capsys, mocker):
    def generate_keylist_enc(include_machinekeys):
        return iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        )

    def generate_keylist_hash(include_machinekeys):
        return iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"])

    mocker.patch.object(Telerik_EncryptionKey, "prepare_keylist", side_effect=generate_keylist_enc)
    mocker.patch.object(Telerik_HashKey, "prepare_keylist", side_effect=generate_keylist_hash)

    with requests_mock.Mocker() as m:
        with patch("sys.exit") as exit_mock:
            m.get(
                f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
                status_code=200,
                text=partial_dialog_page,
            )

            m.post(
                f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
                additional_matcher=pre2017_matcher_probe,
                status_code=200,
                text="garbage data",
            )

            m.post(
                f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
                additional_matcher=pre2017_matcher,
                status_code=200,
                text="garbage data",
            )

            monkeypatch.setattr(
                "sys.argv",
                ["python", "--url", "http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
            )
            telerik_knownkey.main()
            captured = capsys.readouterr()
            print(captured.out)
            assert "Unexpected response encountered: [garbage data] aborting." in captured.out
            assert exit_mock.called


def test_fullrun_asyncupload_earlydetection(monkeypatch, capsys, mocker):

    def generate_keylist_enc(include_machinekeys):
        return iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        )

    def generate_keylist_hash(include_machinekeys):
        return iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"])

    mocker.patch.object(Telerik_EncryptionKey, "prepare_keylist", side_effect=generate_keylist_enc)
    mocker.patch.object(Telerik_HashKey, "prepare_keylist", side_effect=generate_keylist_hash)

    with requests_mock.Mocker() as m:

        # Basic Probe Detects Telerik
        m.get(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text='{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            additional_matcher=asyncupload_early_result_matcher,
            status_code=500,
            text="<b> Exception Details: </b>System.IO.FileLoadException: Could not load file or assembly 'Telerik.Web.UI, Version=2022.3.1109, Culture=neutral, PublicKeyToken=121fae78165ba3d4' or one of its dependencies. The located assembly's manifest definition does not match the assembly reference. (Exception from HRESULT: 0x80131040)<br><br>",
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            additional_matcher=asyncupload_early_result_matcher_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd", "--force"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert (
            "Detected early signs that target is likely vulnerable! Continuing to find vulnerable version..."
            in captured.out
        )


def test_fullrun_asyncupload_success(monkeypatch, capsys, mocker):

    def generate_keylist_enc(include_machinekeys):
        return iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        )

    def generate_keylist_hash(include_machinekeys):
        return iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"])

    mocker.patch.object(Telerik_EncryptionKey, "prepare_keylist", side_effect=generate_keylist_enc)
    mocker.patch.object(Telerik_HashKey, "prepare_keylist", side_effect=generate_keylist_hash)

    with requests_mock.Mocker() as m:

        # Basic Probe Detects Telerik
        m.get(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text='{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            additional_matcher=asyncupload_found_key_matcher,
            status_code=200,
            text='{"fileInfo":{"FileName":"1c72ebb0","ContentType":"text/html","ContentLength":8,"DateJson":"2020-01-02T08:02:01.067Z","Index":0}, "metaData":"a+pkVM70XskLLvpXsOGH+RUEWaNgrvi2EGIZcUrVQ4rr7hIwpIcHtxyJsGCQYWy5tgSKmK58kIk/HpDDs9Gh2qnaFi3m+pe0kb4xb8s6zIkxQYrYGrfj7EesKwvuY6HUn+y3GwesijRrVsPpt0/N5FYxu4ptrsmjWfIM65XOe8b47kLO/Rpx/4/lfJyT9ZFsFuvSZmJzWDdoV40wu5ROK9DVnU26ztRRCwpnqqxmeKvdSGpYwd/d1gisJy0i5UVNFuvRT2XC32eDiw3Kn9GOrRldOHtq5WAQWu2YzVmxr/NOmvjg3NpRLtbxU+h9D0u0K/B3kRYliO+XlCpG+l/QMLh2nAjQehNvaCG3wJ4dkW9JHHeNzbPyd+tNrlSBj6/Z+b/Ld2HCk3XydTRHuUyzqk8bC6rEHGdclNPmTIS2X0IZaI0wTctsnPHxiruwdWVNjepnaSv5IHHYFH3WhCzKy6cLPES0cAuVgxycs+49nuj7kL/JzqT6iJm0YZd/Qjo4" }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            additional_matcher=asyncupload_found_key_matcher_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd", "--force"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert (
            "TARGET VULNERABLE! Version: [2022.3.913] Encryption Key: [d2a312d9-7af4-43de-be5a-ae717b46cea6] Hash Key: [YOUR_ENCRYPTION_KEY_TO_GO_HERE] Derive Algo: [PBKDF2]"
            in captured.out
        )


def test_fullrun_asyncupload_PBKDF1_MS(monkeypatch, capsys, mocker):
    with requests_mock.Mocker() as m:

        # Basic Probe Detects Telerik
        m.get(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text='{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            additional_matcher=asyncupload_found_key_matcher_PBKDF1_MS,
            status_code=200,
            text='{"fileInfo":{"FileName":"1c72ebb0","ContentType":"text/html","ContentLength":8,"DateJson":"2020-01-02T08:02:01.067Z","Index":0}, "metaData":"a+pkVM70XskLLvpXsOGH+RUEWaNgrvi2EGIZcUrVQ4rr7hIwpIcHtxyJsGCQYWy5tgSKmK58kIk/HpDDs9Gh2qnaFi3m+pe0kb4xb8s6zIkxQYrYGrfj7EesKwvuY6HUn+y3GwesijRrVsPpt0/N5FYxu4ptrsmjWfIM65XOe8b47kLO/Rpx/4/lfJyT9ZFsFuvSZmJzWDdoV40wu5ROK9DVnU26ztRRCwpnqqxmeKvdSGpYwd/d1gisJy0i5UVNFuvRT2XC32eDiw3Kn9GOrRldOHtq5WAQWu2YzVmxr/NOmvjg3NpRLtbxU+h9D0u0K/B3kRYliO+XlCpG+l/QMLh2nAjQehNvaCG3wJ4dkW9JHHeNzbPyd+tNrlSBj6/Z+b/Ld2HCk3XydTRHuUyzqk8bC6rEHGdclNPmTIS2X0IZaI0wTctsnPHxiruwdWVNjepnaSv5IHHYFH3WhCzKy6cLPES0cAuVgxycs+49nuj7kL/JzqT6iJm0YZd/Qjo4" }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            additional_matcher=asyncupload_found_key_matcher_PBKDF1_MS_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd", "--force"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert (
            "TARGET VULNERABLE! Version: [2014.3.1024] Encryption Key: [d2a312d9-7af4-43de-be5a-ae717b46cea6] Derive Algo: [PBKDF1_MS]"
            in captured.out
        )


def test_verbose_error_parsing_PBKDF1_MS(monkeypatch, capsys, mocker):

    mocker.patch.object(
        telerik_knownkey.AsyncUpload,
        "solve_key",
        lambda x: None,
    )

    with requests_mock.Mocker() as m:

        # Basic Probe Detects Telerik
        m.get(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text='{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text="<b> Exception Details: </b>System.Security.Cryptography.CryptographicException: Padding is invalid and cannot be removed.<br><br>",
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd", "--force"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert "Verbose Errors are enabled!" in captured.out
        assert (
            "Version is <= 2019 (Either Vulnerable, or Encrypt-Then-Mac with separate failure Message)" in captured.out
        )


def test_verbose_error_parsing_notdetermined_PBKDF1_MS(monkeypatch, capsys, mocker):

    mocker.patch.object(
        telerik_knownkey.AsyncUpload,
        "solve_key",
        lambda x: None,
    )

    with requests_mock.Mocker() as m:

        # Basic Probe Detects Telerik
        m.get(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text='{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text="<b> Exception Details: garbage",
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd", "--force"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert "Verbose Errors are enabled!" in captured.out
        assert "Version could not be determined" in captured.out


def test_verbose_error_parsing_PBKDF2(monkeypatch, capsys, mocker):

    mocker.patch.object(
        telerik_knownkey.AsyncUpload,
        "solve_key",
        lambda x: None,
    )

    with requests_mock.Mocker() as m:

        # Basic Probe Detects Telerik
        m.get(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text='{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }',
        )

        m.post(
            f"http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd",
            status_code=200,
            text='<b> Exception Details: </b>System.Security.Cryptography.CryptographicException: The cryptographic operation has failed!<br><br><b>Stack Trace:</b> <br><br><table width=100% bgcolor="#ffffcc"><tr><td>code><pre>[CryptographicException: The cryptographic operation has failed!]Telerik.Web.UI.CryptoExceptionThrower.ThrowGenericCryptoException() +62',
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://asyncupload.telerik.com/Telerik.Web.UI.WebResource.axd", "--force"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert "Verbose Errors are enabled!" in captured.out
        assert "Version is Post-2020 (Encrypt-Then-Mac Enabled, with Generic Crypto Failure Message)" in captured.out
