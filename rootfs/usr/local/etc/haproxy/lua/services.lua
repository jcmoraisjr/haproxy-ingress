-- Copyright 2019 The HAProxy Ingress Controller Authors.
-- 
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
-- 
--     http://www.apache.org/licenses/LICENSE-2.0
-- 
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local function send(applet, status, response)
    response = response:gsub("\n", "\r\n")
    applet:set_status(status)
    applet:add_header("Content-Length", string.len(response))
    applet:add_header("Content-Type", "text/html")
    applet:add_header("Cache-Control", "no-cache")
    applet:start_response()
    applet:send(response)
end

core.register_service("send-cors-preflight", "http", function(applet)
    applet:set_status(204)
    applet:add_header("Content-Length", 0)
    applet:add_header("Content-Type", "text/plain")
    applet:add_header("Access-Control-Max-Age", applet:get_var("txn.cors_max_age"))
    applet:start_response()
end)

core.register_service("send-prometheus-root", "http", function(applet)
    send(applet, 200, [[
<html>
<head><title>HAProxy Exporter</title></head>
<body><h1>HAProxy Exporter</h1>
<a href='/metrics'>Metrics</a>
</body></html>
]])
end)

core.register_service("send-404", "http", function(applet)
    send(applet, 404, [[
<html><body><h1>404 Not Found</h1>
The requested URL was not found.
</body></html>
]])
end)

core.register_service("send-413", "http", function(applet)
    send(applet, 413, [[
<html><body><h1>413 Request Entity Too Large</h1>
The request is too large.
</body></html>
]])
end)

core.register_service("send-421", "http", function(applet)
    send(applet, 421, [[
<html><body><h1>421 Misdirected Request</h1>
Request sent to a non-authoritative server.
</body></html>
]])
end)

core.register_service("send-495", "http", function(applet)
    send(applet, 495, [[
<html><body><h1>495 SSL Certificate Error</h1>
An invalid certificate has been provided.
</body></html>
]])
end)

core.register_service("send-496", "http", function(applet)
    send(applet, 496, [[
<html><body><h1>496 SSL Certificate Required</h1>
A client certificate must be provided.
</body></html>
]])
end)
