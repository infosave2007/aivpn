module("luci.controller.aivpn", package.seeall)

function index()
    local page = entry({"admin", "services", "aivpn"}, firstchild(), "AIVPN", 60)
    page.dependent = false

    -- Client-side JS view (htdocs/luci-static/resources/view/aivpn/status.js);
    -- there is no server-side Lua template, so this must be view(), not
    -- template().
    entry({"admin", "services", "aivpn", "status"},
          view("aivpn/status"), "Status", 10).leaf = true

    entry({"admin", "services", "aivpn", "config"},
          cbi("aivpn"), "Configuration", 20).leaf = true

    entry({"admin", "services", "aivpn", "start"},
          call("action_start"), nil).leaf = true

    entry({"admin", "services", "aivpn", "stop"},
          call("action_stop"), nil).leaf = true
end

function action_start()
    luci.sys.call("/etc/init.d/aivpn start")
    luci.http.redirect(luci.dispatcher.build_url("admin/services/aivpn/status"))
end

function action_stop()
    luci.sys.call("/etc/init.d/aivpn stop")
    luci.http.redirect(luci.dispatcher.build_url("admin/services/aivpn/status"))
end
