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

core.register_service("send-cors-preflight", "http", function(applet)
    applet:set_status(204)
    applet:add_header("Content-Length", 0)
    applet:add_header("Content-Type", "text/plain")
    applet:add_header("Access-Control-Max-Age", applet:get_var("txn.cors_max_age"))
    applet:start_response()
end)
