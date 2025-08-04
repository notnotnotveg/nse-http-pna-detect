local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects if the server responds with Access-Control-Allow-Private-Network in response to a PNA preflight request.

This script sends an HTTP OPTIONS request with the Access-Control-Request-Private-Network header
to test for Private Network Access (PNA) misconfigurations. If the response contains the
Access-Control-Allow-Private-Network header, the target may be vulnerable.

Additionally, it prints the Server header and the HTML title of the response.

Usage:
  nmap --script http-pna-detect.nse -p80,443 <target>
]]

author = "notnotnotveg (wiki.notveg.ninja)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local fullpath = "/"
  local response = http.generic_request(host, port, "OPTIONS", fullpath, {
    header = {
      ["Origin"] = "http://example.com",
      ["Access-Control-Request-Method"] = "GET",
      ["Access-Control-Request-Private-Network"] = "true"
    }
  })

  if not response then
    return
  end

  local allow_private_network = response.header["access-control-allow-private-network"]
  if allow_private_network then
    local server = response.header["server"] or "Unknown"
    local origin = response.header["access-control-allow-origin"] or "Unknown"

    -- Follow redirects and extract title from final page
    local get_resp = http.get(host, port, fullpath, { follow_redirects = true })
    local title = "Unknown"
    if get_resp and get_resp.body then
      local body = get_resp.body
      title = body:match("<%s*[Tt][Ii][Tt][Ll][Ee]%s*>(.-)<%s*/%s*[Tt][Ii][Tt][Ll][Ee]%s*>") or "Not found"
    end

    return string.format(
      "VULNERABLE: Access-Control-Allow-Private-Network: %s\nServer: %s\nOrigin: %s\nTitle: %s",
      allow_private_network,
      server,
      origin,
      title
    )
  end

  return
end
