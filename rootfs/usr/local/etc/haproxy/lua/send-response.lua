core.register_service("send-response", "http", function(applet)
    applet:start_response()
end)
