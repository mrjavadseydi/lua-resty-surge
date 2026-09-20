local config = require "resty.surge.config"

describe("config", function()
    it("defaults to balanced and splits allow entries", function()
        local cfg = config.parse({
            allow = { "10.0.0.0/8", "2001:db8::/32", "/health" },
        })
        assert(cfg.mode == "balanced")
        assert(cfg.params.sample == 16)
        assert(#cfg.allow4 == 1)
        assert(#cfg.allow6 == 1)
        assert(cfg.paths[1] == "/health")
        assert(cfg.dry_run == false)
        assert(cfg.expose == "short")
    end)

    it("names the legal modes and feeds", function()
        local ok, err = pcall(config.parse, { mode = "loud" })
        assert(not ok)
        assert(err:find('unknown mode "loud"', 1, true))
        assert(err:find("relaxed, balanced, strict", 1, true))

        ok, err = pcall(config.parse, { feeds = { "firehol" } })
        assert(not ok)
        assert(err:find('unknown feed "firehol"', 1, true))
        assert(err:find("firehol_level1", 1, true))
        assert(err:find("spamhaus_drop", 1, true))
    end)

    it("rejects an unknown advanced knob and applies a known one", function()
        local ok, err = pcall(config.parse, { advanced = { nope = 1 } })
        assert(not ok)
        assert(err:find('unknown parameter "nope"', 1, true))

        local cfg = config.parse({ advanced = { sample = 4, test_hooks = true } })
        assert(cfg.params.sample == 4)
        assert(cfg.params.topk == 128)
        assert(cfg.test_hooks == true)
    end)

    it("requires the agent only for remote feeds", function()
        local file_cfg = config.parse({
            feeds = { { name = "office", path = "/tmp/office.txt" } },
        })
        assert(not config.needs_agent(file_cfg.feeds))
        local remote = config.parse({ feeds = { "tor_exits" } })
        assert(config.needs_agent(remote.feeds))
    end)

    it("rejects duplicate feed names", function()
        local ok, err = pcall(config.parse, {
            feeds = {
                { url = "https://a.example/list" },
                { url = "https://b.example/list" },
            },
        })
        assert(not ok)
        assert(err:find('duplicate feed name "custom"', 1, true))

        ok, err = pcall(config.parse, {
            feeds = {
                { name = "office", path = "/tmp/a.txt" },
                { name = "office", path = "/tmp/b.txt" },
            },
        })
        assert(not ok)
        assert(err:find('duplicate feed name "office"', 1, true))

        ok, err = pcall(config.parse, { feeds = { "tor_exits", "tor_exits" } })
        assert(not ok)
        assert(err:find('duplicate feed name "tor_exits"', 1, true))

        local cfg = config.parse({
            feeds = {
                { name = "a", url = "https://a.example/list" },
                { name = "b", url = "https://b.example/list" },
            },
        })
        assert(#cfg.feeds == 2)
    end)

    it("parses trusted proxies and the client header name", function()
        local cfg = config.parse({
            trusted_proxies = { "10.0.0.0/8" },
            client_header = "CF-Connecting-IP",
        })
        assert(#cfg.trusted == 1)
        assert(cfg.client_header == "CF-Connecting-IP")
        assert(cfg.client_var == "http_cf_connecting_ip")
        local defaults = config.parse({})
        assert(#defaults.trusted == 0)
        assert(defaults.client_var == "http_x_forwarded_for")
        local api = config.parse({ api = { "/api/", "/v1/" } })
        assert(api.api[1] == "/api/")
        assert(api.api[2] == "/v1/")
        ok, err = pcall(config.parse, { api = { "10.0.0.0/8" } })
        assert(not ok)
        assert(err:find("path prefix", 1, true))
        local ok, err = pcall(config.parse, { client_header = "Bad Header" })
        assert(not ok)
        assert(err:find("client_header", 1, true))
    end)
end)
