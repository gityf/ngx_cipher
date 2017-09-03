local _M = {}

function _M.echo()
    local base64 = require "base64"
    local json = require "cjson"
    local cipher = require "cipher"
    local args = ngx.req.get_uri_args()
    ngx.header['Content-Type'] = 'application/json; charset=utf-8'
    local val = ""
    local oper = args.t
    if oper  == "base64" then
        val =base64.base64_encode(args.data)
    elseif oper == "md5" then
        val = cipher.md5(args.data)
    elseif oper == "sha1" then
        val = cipher.sha1(args.data)
    elseif oper == "sha224" then
        val = cipher.sha224(args.data)
    elseif oper == "sha256" then
        val = cipher.sha256(args.data)
    elseif oper == "sha384" then
        val = cipher.sha384(args.data)
    elseif oper == "sha512" then
        val = cipher.sha512(args.data)
    elseif oper == "hmac_md5" then
        val = cipher.hmac_md5(args.data, args.key)
    elseif oper == "hmac_sha1" then
        val = cipher.hmac_sha1(args.data, args.key)
    elseif oper == "hmac_sha224" then
        val = cipher.hmac_sha224(args.data, args.key)
    elseif oper == "hmac_sha256" then
        val = cipher.hmac_sha256(args.data, args.key)
    elseif oper == "hmac_sha384" then
        val = cipher.hmac_sha384(args.data, args.key)
    elseif oper == "hmac_sha512" then
        val = cipher.hmac_sha512(args.data, args.key)
    elseif oper == "crc16" then
        val = cipher.crc16(args.data)
    elseif oper == "crc32" then
        val = cipher.crc32(args.data)
    elseif oper == "crc64" then
        val = cipher.crc64(args.data)
    end
    local resp = {
        code = 0, msg = "ok", data = val}
    ngx.say(json.encode(resp))

end

return _M