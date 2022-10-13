# Examples


```
from popsecrets import ASPNETViewstate

x = ASPNETViewstate("AgF5WuyVO11CsYJ1K5rjyuLXqUGCITSOapG1cYNiriYQ6VTKochMpn8ws4eJRvft81nQIA==","EDD8C9AE")
if x.check_secret():
    print(x.output_parameters.items())
else:
    print("KEY NOT FOUND :(")
```
