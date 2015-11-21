Guacamole "delegated" authentication plugin
===========================================

This plugin enables all the required connection parameters to be passed through the request to the authentication endpoint `/api/tokens` instead of retrieving them from some persistent data store.

Example:
```
$ curl --data protocol=rdp --data hostname=localhost --data port=3389 --data username=user --data password=password --data domain=active-directory-domain --data security=nla --data ignore-cert=true --data color-depth=24 --data width=1024 --data height=768 --data server-layout=en-us-qwerty  http://localhost:8000/guacamole-client/api/tokens
```

Once the authentication token is issued,  you can later use it in the Guacamole client without requiring for any additional interaction to the user.  This is useful when you want to authenticate the user on the server side and then pass the control to the user.

License
-------

```
Copyright (c) 2015 Open Collector, Inc.
Copyright (c) 2015 Moriyoshi Koizumi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
