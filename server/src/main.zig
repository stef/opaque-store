const std = @import("std");
const builtin = @import("builtin");
const toml = @import("toml");
const ssl = @import("bearssl");
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const BufSet = std.BufSet;
const blake2b = std.crypto.hash.blake2.Blake2b256;
const utils = @import("utils.zig");
const secret_allocator = @import("secret_allocator.zig");

pub const sodium = @cImport({
    @cInclude("sodium.h");
});
pub const o = @cImport({
    @cInclude("opaque.h");
});
pub const oprf = @cImport({
    @cInclude("oprf/oprf.h");
});
pub const toprf = @cImport({
    @cInclude("oprf/toprf.h");
});
pub const tp_dkg = @cImport({
    @cInclude("oprf/tp-dkg.h");
});
pub const workaround = @cImport({
    @cInclude("workaround.h");
});
pub const stdio = @cImport({
    @cInclude("stdio.h");
});

const DEBUG = (builtin.mode == std.builtin.OptimizeMode.Debug);
const warn = std.debug.print;

/// allocator
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();
//const allocator = std.heap.c_allocator;

var s_state = secret_allocator.secretAllocator(allocator);
const s_allocator = s_state.allocator();

/// stdout
const stdout_file = std.io.getStdOut().writer();
var bw = std.io.bufferedWriter(stdout_file);
const stdout = bw.writer();

const sslStream = ssl.Stream(*net.Stream, *net.Stream);

var conn: net.Server.Connection = undefined;

const recovery_token_bytes = 16;

/// server config data

const Config = struct {
    verbose: bool,
    /// the ipv4 address the server is listening on
    address: []const u8,
    port: u16,
    /// tcp connection timeouts
    timeout: u16,
    /// the root directory where all data is stored
    datadir: [:0]const u8,
    /// how many processes can run in parallel
    max_kids: u16,
    /// server key in PEM format
    ssl_key: [:0]const u8,
    /// server cert in PEM format
    ssl_cert: [:0]const u8,
    /// server long-term signature key for DKG
    ltsigkey: [:0]const u8,
    /// maximum age still considered fresh, in seconds
    ts_epsilon: u64,
    /// salt for hashing record ids
    record_salt: []const u8,
    /// do not allow blobs bigger than this size
    max_blob_size: usize,
    /// how many failed password tries until locking?
    max_fails: u8,
    /// how many recovery tokens / record
    max_recovery_tokens: u8,
};

const CreateReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    alpha: [sodium.crypto_core_ristretto255_BYTES]u8 align(1),
};

const OpaqueReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    ke1: [o.OPAQUE_USER_SESSION_PUBLIC_LEN]u8 align(1),
};

const UnlockReq = extern struct {
    id: [sodium.crypto_generichash_BYTES]u8 align(1),
    rtoken: [recovery_token_bytes]u8 align(1),
};

const OpaqueStoreOp = enum(u8) {
    CREATE     = 0,
    UPDATE     = 0x33,
    GET_RTOKEN = 0x50,
    GET        = 0x66,
    CREATE_DKG = 0xf0,
    UNLOCK      =0xf5,
    DELETE     = 0xff,
    _,
};

const WriteBlobError = error{Error};

const LoadBlobError = error{
    WrongSize,
    WrongRead,
};

fn expandpath(path: []const u8) [:0]u8 {
    if(path[0]!='~') {
        return allocator.dupeZ(u8,path) catch @panic("OOM");
    }
    const home = posix.getenv("HOME") orelse "/nonexistant";
    const xpath = mem.concat(allocator, u8, &[_][]const u8{ home, path }) catch @panic("OOM");
    const xpathZ = allocator.dupeZ(u8, xpath) catch @panic("OOM");
    allocator.free(xpath);
    return xpathZ;
}

fn loadcfg() anyerror!Config {
    @setCold(true);

    const home = posix.getenv("HOME") orelse "/nonexistant";
    const cfg1 = mem.concat(allocator, u8, &[_][]const u8{ home, "/.config/opaque-stored/config" }) catch unreachable;
    defer allocator.free(cfg1);
    const cfg2 = mem.concat(allocator, u8, &[_][]const u8{ home, "/.opaque-storedrc" }) catch unreachable;
    defer allocator.free(cfg2);

    const paths = [_][]const u8{
        "/etc/opaque-stored/config",
        cfg1,
        cfg2,
        "opaque-stored.cfg",
    };

    // default values for the Config structure
    var cfg = Config{
        .verbose = true,
        .address = "127.0.0.1",
        .port = 443,
        .timeout = 3,
        .datadir = "/var/lib/opaque-stored",
        .max_kids = 5,
        .ssl_key = "server.pem",
        .ssl_cert = "certs.pem",
        .ltsigkey = "ltsig.key",
        .ts_epsilon = 600,
        .record_salt = undefined,
        .max_blob_size = 1024 + 24 + 16,
        .max_fails = 3,
        .max_recovery_tokens = 5,
    };

    //var parser: toml.Parser = undefined;
    for (paths) |filename| {
        if(toml.parseFile(allocator, filename)) |p| {
            var parser: toml.Parser = p;
            defer parser.deinit();
            const t = parser.parse();
            if (t) |table| {
                defer table.deinit();

                if (table.keys.get("server")) |server| {
                    cfg.verbose = if (server.Table.keys.get("verbose")) |v| v.Boolean else cfg.verbose;
                    cfg.address = if (server.Table.keys.get("address")) |v| try allocator.dupe(u8, v.String) else cfg.address;
                    cfg.port = if (server.Table.keys.get("port")) |v| @intCast(v.Integer) else cfg.port;
                    cfg.timeout = if (server.Table.keys.get("timeout")) |v| @intCast(v.Integer) else cfg.timeout;
                    cfg.datadir = if (server.Table.keys.get("datadir")) |v| expandpath(v.String) else cfg.datadir;
                    cfg.max_kids = if (server.Table.keys.get("max_kids")) |v| @intCast(v.Integer) else cfg.max_kids;
                    cfg.ssl_key = if (server.Table.keys.get("ssl_key")) |v| expandpath(v.String) else cfg.ssl_key;
                    cfg.ssl_cert = if (server.Table.keys.get("ssl_cert")) |v| expandpath(v.String) else cfg.ssl_cert;
                    cfg.ltsigkey = if (server.Table.keys.get("ltsigkey")) |v| expandpath(v.String) else cfg.ltsigkey;
                    cfg.ts_epsilon = if (server.Table.keys.get("ts_epsilon")) |v| @intCast(v.Integer) else cfg.ts_epsilon;
                    if (server.Table.keys.get("record_salt")) |v| {
                        cfg.record_salt = allocator.dupe(u8, v.String) catch @panic("oom");
                    } else {
                        warn("missing record_salt in configuration\nabort.", .{});
                        posix.exit(1);
                    }
                    cfg.max_blob_size = if (server.Table.keys.get("max_blob_size")) |v| @intCast(v.Integer) else cfg.max_blob_size;
                    cfg.max_fails = if (server.Table.keys.get("max_fails")) |v| @intCast(v.Integer) else cfg.max_fails;
                    cfg.max_recovery_tokens = if (server.Table.keys.get("max_recovery_tokens")) |v| @intCast(v.Integer) else cfg.max_recovery_tokens;
                }
            } else |err| {
                if (err == error.FileNotFound) continue;
                warn("error loading config {s}: {}\n", .{ filename, err });
            }
        } else |err| {
            if (err == error.FileNotFound) continue;
            warn("error loading config {s}: {}\n", .{ filename, err });
            return err;
        }
    }
    if (cfg.verbose) {
        warn("cfg.address: {s}\n", .{cfg.address});
        warn("cfg.port: {}\n", .{cfg.port});
        warn("cfg.datadir: {s}\n", .{cfg.datadir});
        warn("cfg.ssl_key: {s}\n", .{cfg.ssl_key});
        warn("cfg.ssl_cert: {s}\n", .{cfg.ssl_cert});
        warn("cfg.ltsigkey: {s}\n", .{cfg.ltsigkey});
        warn("cfg.ts_epsilon: {}\n", .{cfg.ts_epsilon});
        warn("cfg.verbose: {}\n", .{cfg.verbose});
        warn("cfg.record_salt: \"{s}\"\n", .{cfg.record_salt});
        warn("cfg.max_blob_size: {}\n", .{cfg.max_blob_size});
        warn("cfg.max_recovery_tokens: {}\n", .{cfg.max_recovery_tokens});
    }
    return cfg;
}

fn fail(s: *sslStream, cfg: *const Config) noreturn {
    @setCold(true);
    if (cfg.verbose) {
        std.debug.dumpCurrentStackTrace(@frameAddress());
        warn("fail\n", .{});
        std.debug.dumpCurrentStackTrace(@returnAddress());
    }
    _ = s.write("\x00\x04fail") catch null;
    _ = s.flush() catch null;
    _ = std.os.linux.shutdown(conn.stream.handle, std.os.linux.SHUT.RDWR);
    _ = s.close() catch null;
    posix.exit(0);
}

fn read_pkt(s: *sslStream) []u8 {
    var lenbuf: [2]u8 = undefined;
    _ = s.read(lenbuf[0..]) catch |err| {
        handle_read_err(err, s);
    };
    const pktlen = std.mem.readInt(u16, lenbuf[0..2], std.builtin.Endian.big);
    var buf : []u8 = allocator.alloc(u8, pktlen) catch @panic("OOM");
    var i: usize = 0;
    while(i<buf.len) {
        if(s.read(buf[i..])) |r| {
            if (r == 0) break;
            i+=r;
        } else |err| {
            handle_read_err(err, s);
        }
    }
    if(i<buf.len) {
        @panic("socket closed");
    }
    return buf;
}

fn send_pkt(s: *sslStream, cfg: *const Config, msg: []u8) void {
    var pkt: []u8 = allocator.alloc(u8, 2+msg.len) catch @panic("oom");
    defer allocator.free(pkt);
    if(msg.len > (1<<16) - 1) {
        warn("msg is too long: {}, max {}\n", .{msg.len, (1<<16) - 1});
        fail(s,cfg);
    }
    std.mem.writeInt(u16, pkt[0..2], @truncate(msg.len), std.builtin.Endian.big);
    @memcpy(pkt[2..], msg);

    var i: usize = 0;
    while(i<pkt.len) {
        const r = s.write(pkt[i..]) catch |e| {
            warn("error: {}\n", .{e});
            @panic("network error");
        };
        if (r == 0) break;
        i+=r;
    }
    if(i==pkt.len) {
        s.flush() catch |e| {
            warn("failed to flush connection: {}\n", .{e});
            fail(s, cfg);
        };
        return;
    }
    @panic("network error");
}

fn save_blob(cfg: *const Config, path: []const u8, fname: []const u8, blob: []const u8) anyerror!void {
    if (!utils.dir_exists(cfg.datadir)) {
        try posix.mkdir(cfg.datadir, 0o700);
    }
    const tdir = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", path }) catch @panic("oom");
    defer allocator.free(tdir);
    if (!utils.dir_exists(tdir)) {
        try posix.mkdir(tdir, 0o700);
    }
    const fpath = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", path, "/", fname }) catch @panic("oom");
    defer allocator.free(fpath);
    if (posix.open(fpath, .{.ACCMODE=.WRONLY, .CREAT = true, .TRUNC = true }, 0o600)) |f| {
        defer posix.close(f);
        const w = try posix.write(f, blob);
        if (w != blob.len) return WriteBlobError.Error;
    } else |err| {
        warn("saveblob: {}\n", .{err});
        return err;
    }
}

/// loads a blob from cfg.datadir/_path/fname, can enforce that the blob has an expected _size
/// returned blob is allocated and must be freed by caller
fn load_blob(balloc: mem.Allocator, cfg: *const Config, _path: []const u8, fname: []const u8, _size: ?usize) anyerror![]u8 {
    const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", _path, "/", fname }) catch @panic("oom");
    defer allocator.free(path);
    if (posix.open(path, .{.ACCMODE = .RDONLY }, 0)) |f| {
        defer posix.close(f);
        const s = try posix.fstat(f);
        const fsize = s.size;
        if (_size) |size| {
            if (fsize != size) {
                if (cfg.verbose) warn("{s} has not expected size of {}B instead has {}B\n", .{ path, size, fsize });
                return LoadBlobError.WrongSize;
            }
        }

        const buf: []u8 = try balloc.alloc(u8, @intCast(fsize));
        const rs = try posix.read(f, buf);
        if (rs != fsize) {
            balloc.free(buf);
            return LoadBlobError.WrongRead;
        }
        return buf;
    } else |err| {
        return err;
    }
}

fn load_failctr(cfg: *const Config, s: *sslStream, hexid: []const u8) anyerror!i32 {
    const lock = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid, "/", "failctr.lock" }) catch @panic("oom");
    defer allocator.free(lock);
    const start = std.time.milliTimestamp();
    while(std.time.milliTimestamp() < start + 500) { // wait max 1/2 second
        if (posix.open(lock, .{.ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o600)) |l| {
            defer {
                posix.close(l);
                std.fs.cwd().deleteFile(lock) catch |e| {
                    warn("failed delete {s}: error: {}\n", .{lock, e});
                    fail(s, cfg);
                };
            }
            const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid, "/", "failctr" }) catch @panic("oom");
            defer allocator.free(path);
            const f = try posix.open(path, .{.ACCMODE = .RDWR, .CREAT = true }, 0o600);
            defer posix.close(f);
            var ctr = [1]u8{0};
            _ = try posix.read(f, &ctr);
            if(ctr[0] >= cfg.max_fails) {
                posix.close(l);
                posix.close(f);
                warn("record {s} is locked {} > {}\n", .{hexid, ctr[0], cfg.max_fails});
                std.fs.cwd().deleteFile(lock) catch |e| {
                    warn("failed delete {s}: error: {}\n", .{lock, e});
                    fail(s, cfg);
                };
                fail(s,cfg);
            }
            ctr[0]+=1;
            try posix.lseek_SET(f, 0);
            _ = try posix.write(f, &ctr);

            return cfg.max_fails - ctr[0];
        } else |err| {
            if(err == error.PathAlreadyExists) continue;
            return err;
        }
    }
    warn("failed to acquire failctr lock\n",.{});
    fail(s,cfg);
}

fn load_rtokens(cfg: *const Config, s: *sslStream, hexid: []const u8, token_buf: []u8) anyerror!void {
    const lock = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid, "/", "rtokens.lock" }) catch @panic("oom");
    defer allocator.free(lock);
    const start = std.time.milliTimestamp();
    while(std.time.milliTimestamp() < start + 500) { // wait max 1/2 second
        if (posix.open(lock, .{.ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o600)) |l| {
            defer {
                posix.close(l);
                std.fs.cwd().deleteFile(lock) catch |e| {
                    warn("failed delete {s}: error: {}\n", .{lock, e});
                    fail(s, cfg);
                };
            }
            const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid, "/", "rtokens" }) catch @panic("oom");
            defer allocator.free(path);
            const f = posix.open(path, .{.ACCMODE = .RDONLY}, 0o600) catch |e| {
                if(e == error.FileNotFound) {
                    @memset(token_buf[0..], 0);
                    return;
                }
                warn("error open recovery token file for {s}, error: {}\n",.{path,e});
                fail(s,cfg);
            };
            defer posix.close(f);
            _ = try posix.read(f, token_buf);
            return;
        } else |err| {
            if(err == error.PathAlreadyExists) continue;
            return err;
        }
    }
    warn("failed to acquire rtokens lock for {s}\n",.{lock});
    fail(s,cfg);
}

fn save_rtokens(cfg: *const Config, s: *sslStream, hexid: []const u8, token_buf: []u8) anyerror!void {
    const lock = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid, "/", "rtokens.lock" }) catch @panic("oom");
    defer allocator.free(lock);
    const start = std.time.milliTimestamp();
    while(std.time.milliTimestamp() < start + 500) { // wait max 1/2 second
        if (posix.open(lock, .{.ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o600)) |l| {
            defer {
                posix.close(l);
                std.fs.cwd().deleteFile(lock) catch |e| {
                    warn("failed delete {s}: error: {}\n", .{lock, e});
                    fail(s, cfg);
                };
            }
            const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid, "/", "rtokens" }) catch @panic("oom");
            defer allocator.free(path);
            const f = posix.open(path, .{.ACCMODE = .WRONLY, .CREAT = true }, 0o600) catch |e| {
                warn("error open recovery token file for {s}, error: {}\n",.{path,e});
                fail(s,cfg);
            };
            defer posix.close(f);
            _ = try posix.write(f, token_buf);
            return;
        } else |err| {
            if(err == error.PathAlreadyExists) continue;
            return err;
        }
    }
    warn("failed to acquire rtokens lock for {s}\n",.{lock});
    fail(s,cfg);
}

/// converts a 32B string to a 64B hex string
/// caller is responsible to free returned string
fn tohexid(id: [32]u8) anyerror![]u8 {
    const hexbuf = allocator.alloc(u8, 64) catch @panic("oom");
    return std.fmt.bufPrint(hexbuf, "{x:0>64}", .{std.fmt.fmtSliceHexLower(id[0..])});
}

fn dkg(cfg: *const Config, s: *sslStream, msg0: []const u8, k: [*]u8) void {
    var ltsigkey: []u8 = undefined;

    if (posix.open(cfg.ltsigkey, .{.ACCMODE = .RDONLY }, 0)) |f| {
        defer posix.close(f);
        ltsigkey = s_allocator.alloc(u8, @intCast(sodium.crypto_sign_SECRETKEYBYTES)) catch @panic("oom");
        _ = posix.read(f, ltsigkey) catch |err| {
            if (cfg.verbose) warn("cannot open {s}/{s} error: {}\n", .{ cfg.datadir, cfg.ltsigkey, err });
            fail(s, cfg);
        };
    } else |err| {
        if (err != error.FileNotFound) {
            if (cfg.verbose) warn("cannot open {s}/{s} error: {}\n", .{ cfg.datadir, cfg.ltsigkey, err });
            fail(s, cfg);
        }
        warn("no ltsigkey found at : {s}/{s}\n", .{cfg.datadir, cfg.ltsigkey});
        fail(s,cfg);
    }

    var peer = workaround.new_peerstate();
    defer workaround.del_peerstate(@ptrCast(&peer));

    const retsp = tp_dkg.tpdkg_start_peer(@ptrCast(peer), cfg.ts_epsilon, ltsigkey.ptr, @ptrCast(msg0.ptr));
    if(retsp!=0) {
        warn("failed to start tp-dkg peer (error code: {})\n", .{retsp});
        fail(s, cfg);
    }
    const n = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).n;
    const t = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).t;
    //warn("dkg {}/{}\n", .{t,n});
    const peer_sig_pks: [][sodium.crypto_sign_PUBLICKEYBYTES]u8 = allocator.alloc([sodium.crypto_sign_PUBLICKEYBYTES]u8, n) catch @panic("oom");
    defer allocator.free(peer_sig_pks);
    const peer_noise_pks: [][sodium.crypto_scalarmult_BYTES]u8 = allocator.alloc([sodium.crypto_scalarmult_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(peer_noise_pks);
    const noise_outs : []*tp_dkg.Noise_XK_session_t_s = allocator.alloc(*tp_dkg.Noise_XK_session_t_s, n) catch @panic("oom");
    defer allocator.free(noise_outs);
    const noise_ins : []*tp_dkg.Noise_XK_session_t_s = allocator.alloc(*tp_dkg.Noise_XK_session_t_s, n) catch @panic("oom");
    defer allocator.free(noise_ins);
    const ishares : [][toprf.TOPRF_Share_BYTES]u8 = allocator.alloc([toprf.TOPRF_Share_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(ishares);
    const xshares : [][toprf.TOPRF_Share_BYTES]u8 = allocator.alloc([toprf.TOPRF_Share_BYTES]u8, n) catch @panic("oom");
    defer allocator.free(xshares);
    const commitments: [][sodium.crypto_core_ristretto255_BYTES]u8 = allocator.alloc([sodium.crypto_core_ristretto255_BYTES]u8, n * t) catch @panic("oom");
    defer allocator.free(commitments);
    const peer_complaints: []u16 = allocator.alloc(u16, n * n) catch @panic("oom");
    defer allocator.free(peer_complaints);
    const peer_my_complaints: []u8 = allocator.alloc(u8, n) catch @panic("oom");
    defer allocator.free(peer_my_complaints);
    const peer_last_ts: []u64 = allocator.alloc(u64, n) catch @panic("oom");
    defer allocator.free(peer_last_ts);

    tp_dkg.tpdkg_peer_set_bufs(@ptrCast(peer), @alignCast(@ptrCast(peer_sig_pks)), @alignCast(@ptrCast(peer_noise_pks)),
                               @alignCast(@ptrCast(noise_outs)), @alignCast(@ptrCast(noise_ins)),
                               @alignCast(@ptrCast(ishares)), @alignCast(@ptrCast(xshares)),
                               @alignCast(@ptrCast(commitments)),
                               @alignCast(@ptrCast(peer_complaints.ptr)), @alignCast(@ptrCast(peer_my_complaints.ptr)),
                               @ptrCast(peer_last_ts.ptr));

    while(tp_dkg.tpdkg_peer_not_done(@ptrCast(peer))!=0) {
        const cur_step = @as(*tp_dkg.TP_DKG_PeerState, @ptrCast(peer)).step;
        const msglen = tp_dkg.tpdkg_peer_input_size(@ptrCast(peer));
        //if(DEBUG) warn("[{}] input msglen: {}\n", .{cur_step, msglen});
        //var msg : []u8 = allocator.alloc(u8, tp_dkg.tpdkg_peer_input_size(@ptrCast(peer))) catch @panic("oom");
        //defer allocator.free(msg);
        var msg : ?[*]u8 = undefined;
        if(msglen > 0) {
            const _msg = read_pkt(s);
            if (msglen != _msg.len) {
                fail(s, cfg);
            }
            msg = _msg.ptr;
        } else {
            msg = null;
        }
        const resp_size = tp_dkg.tpdkg_peer_output_size(@ptrCast(peer));
        //if(DEBUG) warn("[{}] response size: {}\n", .{cur_step, resp_size});
        const resp : []u8 = allocator.alloc(u8, resp_size) catch @panic("oom");
        defer allocator.free(resp);
        const ret = tp_dkg.tpdkg_peer_next(@ptrCast(peer), msg, msglen, resp.ptr, resp.len);
        if(0!=ret) {
            warn("TP DKG failed with {} in step {}.", .{ret, cur_step});
            tp_dkg.tpdkg_peer_free(@ptrCast(peer));
            fail(s, cfg);
        }
        if(resp.len>0) {
            //if(DEBUG) {
            //    warn("\nsending: ",.{});
            //    utils.hexdump(resp[0..]);
            //}
            send_pkt(s, cfg, resp);
        }
    }

    const share = s_allocator.alloc(u8, 33) catch @panic("oom");
    defer s_allocator.free(share);

    workaround.extract_share(@ptrCast(peer), share.ptr);
    //warn("share ", .{});
    //utils.hexdump(share[0..]);

    @memcpy(k, share[1..]);
}

fn opaque_session(cfg: *const Config, s: *sslStream, req: *const OpaqueReq, sk: ?*[o.OPAQUE_SHARED_SECRETBYTES]u8) void {
    const hexid = tohexid(req.id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], local_id[0..], .{ .key = cfg.record_salt });

    const local_hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(local_hexid);

    // increment fail counter
    const attempts = load_failctr(cfg, s, local_hexid) catch |e| {
        warn("incrementing fail ctr for  {s} failed {}\n", .{local_hexid, e});
        fail(s, cfg);
    };
    const rec: []u8 = load_blob(s_allocator, cfg, local_hexid, "rec", o.OPAQUE_USER_RECORD_LEN) catch |e| {
        warn("loading record for {s} failed {}\n", .{local_hexid, e});
        fail(s, cfg);
    };
    defer s_allocator.free(rec);

    const ids : o.Opaque_Ids = .{
        .idU_len = 0,
        .idU = null,
        .idS_len = 0,
        .idS = null,
    };
    const ctx = "opaque-store";
    var ke2 = [_]u8{0} ** o.OPAQUE_SERVER_SESSION_LEN;
    var _sk = [_]u8{0} ** o.OPAQUE_SHARED_SECRETBYTES;
    var authU = [_]u8{0} ** sodium.crypto_auth_hmacsha512_BYTES;
    if(0!=o.opaque_CreateCredentialResponse(req.ke1[0..].ptr, rec.ptr, &ids, ctx.ptr, ctx.len, ke2[0..].ptr, _sk[0..].ptr, authU[0..].ptr)) {
        warn("failed to create credential response\n",.{});
    }
    if(sk) |dst| {
        @memcpy(dst, _sk[0..].ptr);
    }

    _ = s.write(ke2[0..]) catch |e| {
        warn("error sending credential response: {}\n", .{e});
        @panic("network error");
    };
    var aux = [_]u8{0} ** 4;
    std.mem.writeInt(i32, aux[0..4], attempts, std.builtin.Endian.big);
    _ = s.write(aux[0..]) catch |e| {
        warn("error sending remaining attempts: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        @panic("network error");
    };

    var ke3: [sodium.crypto_auth_hmacsha512_BYTES]u8 = undefined;
    _ = s.read(ke3[0..]) catch |err| {
        handle_read_err(err, s);
    };
    if(0!=o.opaque_UserAuth(authU[0..].ptr,ke3[0..].ptr)) {
        warn("failed user authentication\n", .{});
        fail(s, cfg);
    }
    // zero fail counter
    const failctr_path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", local_hexid, "/", "failctr" }) catch @panic("oom");
    defer allocator.free(failctr_path);
    std.fs.cwd().deleteFile(failctr_path) catch |e| {
        warn("failed delete {s}: error: {}\n", .{failctr_path, e});
        fail(s, cfg);
    };
}

const CB_Ctx = struct {
    cfg: *const Config,
    s: *sslStream,
    msg0: []u8,
};

fn keygen_cb(_ctx_: ?*anyopaque, k: [*c]u8) callconv(.C) c_int {
    var ctx: *CB_Ctx = undefined;
    if(_ctx_) |_ctx| {
        ctx = @ptrCast(@alignCast(_ctx));
    } else {
        return 1;
    }
    dkg(ctx.cfg, ctx.s, ctx.msg0, @ptrCast(k));
    return 0;
}

fn create(cfg: *const Config, s: *sslStream, req: *const CreateReq, op : OpaqueStoreOp) void {
    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], &local_id, .{ .key = cfg.record_salt });

    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);

    const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", hexid[0..] }) catch @panic("oom");
    defer allocator.free(path);

    if (utils.dir_exists(path)) fail(s, cfg);

    var _sec = [_]u8{0} ** o.OPAQUE_REGISTER_SECRET_LEN;
    var _pub = [_]u8{0} ** o.OPAQUE_REGISTER_PUBLIC_LEN;

    if(op == OpaqueStoreOp.CREATE_DKG) {
        var msg0 = mem.zeroes([tp_dkg.tpdkg_msg0_SIZE]u8);
        const msg0len = s.read(msg0[0..]) catch |err| {
            handle_read_err(err, s);
        };
        if(msg0len != msg0.len) {
            fail(s, cfg);
        }

        var keygen_ctx: CB_Ctx = .{
            .cfg = cfg,
            .s = s,
            .msg0 = &msg0
        };
        if(0!=o.opaque_CreateRegistrationResponse_extKeygen(req.alpha[0..].ptr,
                                                            null,
                                                            _sec[0..].ptr,
                                                            _pub[0..].ptr,
                                                            keygen_cb,
                                                            &keygen_ctx)) {
            fail(s,cfg);
        }
    } else {
        if(0!=o.opaque_CreateRegistrationResponse(req.alpha[0..].ptr, null, _sec[0..].ptr, _pub[0..].ptr)) {
            fail(s,cfg);
        }
    }

    _ = s.write(_pub[0..]) catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    _ = s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        @panic("network error");
    };

    var rec0: [o.OPAQUE_REGISTRATION_RECORD_LEN]u8 = undefined;
    _ = s.read(rec0[0..]) catch |err| {
        handle_read_err(err, s);
    };

    var blob: []u8 = read_pkt(s);
    defer allocator.free(blob);
    if(blob.len > cfg.max_blob_size) {
        warn("attempt to create blob bigger than allowed size: {}\n", .{blob.len});
        fail(s,cfg);
    }

    var rec = [_]u8{0} ** o.OPAQUE_USER_RECORD_LEN;

    o.opaque_StoreUserRecord(@ptrCast(&_sec), rec0[0..].ptr, rec[0..].ptr);

    save_blob(cfg, hexid, "rec", rec[0..]) catch fail(s, cfg);
    save_blob(cfg, hexid, "blob", blob[0..]) catch fail(s, cfg);

    _ = s.write("ok") catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        @panic("network error");
    };
}

fn get(cfg: *const Config, s: *sslStream, req: *const OpaqueReq) void {
    opaque_session(cfg,s,req, null);

    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], local_id[0..], .{ .key = cfg.record_salt });

    const local_hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(local_hexid);

    const blob: []u8 = load_blob(allocator, cfg, local_hexid, "blob", null) catch |e| {
        warn("loading blob for {s} failed {}\n", .{local_hexid, e});
        fail(s, cfg);
    };
    defer allocator.free(blob);

    send_pkt(s, cfg, blob[0..]);
}

fn update(cfg: *const Config, s: *sslStream, req: *const OpaqueReq) void {
    opaque_session(cfg,s,req, null);

    var blob: []u8 = read_pkt(s);
    defer allocator.free(blob);
    if(blob.len > cfg.max_blob_size) {
        warn("attempt to create blob bigger than allowed size: {}\n", .{blob.len});
        fail(s,cfg);
    }
    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], &local_id, .{ .key = cfg.record_salt });

    const hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(hexid);
    save_blob(cfg, hexid, "blob", blob[0..]) catch fail(s, cfg);

    _ = s.write("ok") catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        @panic("network error");
    };
}

fn delete(cfg: *const Config, s: *sslStream, req: *const OpaqueReq) void {
    opaque_session(cfg,s,req, null);

    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], local_id[0..], .{ .key = cfg.record_salt });

    const local_hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(local_hexid);

    const path = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", local_hexid[0..] }) catch @panic("oom");
    defer allocator.free(path);

    if (!utils.dir_exists(path)) fail(s, cfg);
    std.fs.cwd().deleteTree(path) catch fail(s, cfg);

    _ = s.write("ok") catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        @panic("network error");
    };
}

fn get_rtoken(cfg: *const Config, s: *sslStream, req: *const OpaqueReq) void {
    var sk: []u8 = undefined;
    sk = s_allocator.alloc(u8, @intCast(o.OPAQUE_SHARED_SECRETBYTES)) catch @panic("oom");
    defer s_allocator.free(sk);
    opaque_session(cfg,s,req, sk[0..o.OPAQUE_SHARED_SECRETBYTES]);

    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], local_id[0..], .{ .key = cfg.record_salt });

    const local_hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(local_hexid);

    var rtoken_buf : []u8 = undefined;
    rtoken_buf = allocator.alloc(u8, ((cfg.max_recovery_tokens)*recovery_token_bytes)) catch @panic("oom");
    @memset(rtoken_buf, 0);

    load_rtokens(cfg, s, local_hexid, rtoken_buf[0..]) catch |e| {
        warn("failed loading rtokens for {s}, error: {}\n", .{local_hexid, e});
        fail(s, cfg);
    };

    const rtokens: *[*][recovery_token_bytes]u8 = @ptrCast(&rtoken_buf);
    const zero = [_]u8{0}**recovery_token_bytes;
    for(0..cfg.max_recovery_tokens) |i| {
        if(mem.eql(u8,&zero, &rtokens.*[i])) {
            std.crypto.random.bytes(rtokens.*[i][0..]);

            var ct = [_]u8{0} ** (sodium.crypto_secretbox_NONCEBYTES + recovery_token_bytes + sodium.crypto_secretbox_MACBYTES);
            sodium.randombytes(ct[0..sodium.crypto_secretbox_NONCEBYTES].ptr, sodium.crypto_secretbox_NONCEBYTES);
            _ = sodium.crypto_secretbox_easy(ct[sodium.crypto_secretbox_NONCEBYTES..].ptr,
                                             rtokens.*[i][0..].ptr, rtokens.*[i].len ,
                                             ct[0..sodium.crypto_secretbox_NONCEBYTES].ptr,
                                             sk[0..].ptr);
            save_rtokens(cfg, s, local_hexid, rtoken_buf[0..]) catch |e| {
                warn("failed saving rtokens for {s}, error: {}\n", .{local_hexid, e});
                fail(s, cfg);
            };
            send_pkt(s, cfg, ct[0..]);
            // todo save list
            return;
        }
    }

    var prng = std.rand.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch |e| {
            warn("getrandom returned error: {}\n", .{e});
            posix.exit(1);
        };
        break :blk seed;
    });
    const rand = prng.random();

    const i = rand.uintLessThan(usize, cfg.max_recovery_tokens);
    var ct = [_]u8{0} ** (sodium.crypto_secretbox_NONCEBYTES + recovery_token_bytes + sodium.crypto_secretbox_MACBYTES);
    sodium.randombytes(ct[0..sodium.crypto_secretbox_NONCEBYTES].ptr, sodium.crypto_secretbox_NONCEBYTES);
    _ = sodium.crypto_secretbox_easy(ct[sodium.crypto_secretbox_NONCEBYTES..].ptr,
                                     rtokens.*[i][0..].ptr, rtokens.*[i].len ,
                                     ct[0..sodium.crypto_secretbox_NONCEBYTES].ptr,
                                     sk[0..].ptr);
    send_pkt(s, cfg, ct[0..]);
}

fn unlock(cfg: *const Config, s: *sslStream, req: *const UnlockReq) void {
    const zero = [_]u8{0}**recovery_token_bytes;
    if(std.crypto.utils.timingSafeEql([recovery_token_bytes]u8, zero, req.rtoken)) {
        warn("zero recovery token detected, aborting.\n", .{});
        fail(s,cfg);
    }

    // we hash the id, with some local secret, so clients have no control over the record ids
    // we abuse the key here, because the salt is expected to be exactly 16B
    // keys however can be of arbitrary size
    var local_id = [_]u8{0} ** blake2b.digest_length;
    blake2b.hash(req.id[0..], local_id[0..], .{ .key = cfg.record_salt });

    const local_hexid = tohexid(local_id) catch @panic("failed to hexid");
    defer allocator.free(local_hexid);

    var rtoken_buf : []u8 = undefined;
    rtoken_buf = allocator.alloc(u8, ((cfg.max_recovery_tokens)*recovery_token_bytes)) catch @panic("oom");
    @memset(rtoken_buf, 0);

    load_rtokens(cfg, s, local_hexid, rtoken_buf[0..]) catch |e| {
        warn("failed loading rtokens for {s}, error: {}\n", .{local_hexid, e});
        fail(s, cfg);
    };

    var msg : *const [2]u8 = "no"[0..2];
    const rtokens: *[*][recovery_token_bytes]u8 = @ptrCast(&rtoken_buf);
    for(0..cfg.max_recovery_tokens) |i| {
        if(std.crypto.utils.timingSafeEql([recovery_token_bytes]u8, rtokens.*[i][0..].*, req.rtoken)) {
            msg = "ok"[0..2];
            const failpath = mem.concat(allocator, u8, &[_][]const u8{ cfg.datadir, "/", local_hexid, "/", "failctr" }) catch @panic("oom");
            defer allocator.free(failpath);
            std.fs.cwd().deleteFile(failpath) catch |e| {
                if(e != error.FileNotFound) {
                    warn("failed delete {s}: error: {}\n", .{failpath, e});
                    fail(s, cfg);
                }
            };
            @memset(rtokens.*[i][0..], 0);
            save_rtokens(cfg, s, local_hexid, rtoken_buf[0..]) catch |e| {
                warn("failed saving rtokens for {s}, error: {}\n", .{local_hexid, e});
                fail(s, cfg);
            };
        }
    }

    _ = s.write(msg) catch |e| {
        warn("error: {}\n", .{e});
        @panic("network error");
    };
    s.flush() catch |e| {
        warn("failed to flush connection: {}\n", .{e});
        @panic("network error");
    };
}

fn handle_read_err(err: anyerror, s: *sslStream) noreturn {
    if(err==ssl.BearError.UNSUPPORTED_VERSION) {
        warn("{} unsupported TLS version. aborting.\n",.{conn.address});
        s.close() catch unreachable;
        posix.exit(0);
    } else if(err==ssl.BearError.UNKNOWN_ERROR_582 or err==ssl.BearError.UNKNOWN_ERROR_552) {
        warn("{} unknown TLS error: {}. aborting.\n",.{conn.address, err});
        s.close() catch unreachable;
        posix.exit(0);
    } else if(err==ssl.BearError.BAD_VERSION) {
        warn("{} bad TLS version. aborting.\n",.{conn.address});
        s.close() catch unreachable;
        posix.exit(0);
    }
    warn("read error: {}\n",.{err});
    @panic("network error");
}

fn read_req(cfg: *const Config, s: *sslStream, comptime T: type, op: []const u8) anyerror!*T {
    var buf = allocator.alloc(u8, @sizeOf(T)) catch @panic("oom");
    const buflen = s.read(buf[0..]) catch |err| {
        handle_read_err(err, s);
        return err;
    };

    if(buflen != buf.len) {
        warn("invalid {s} request. aborting.\n",.{op});
    }
    const req: *T = @ptrCast(buf[0..]);

    if (cfg.verbose) {
        const hexid = try tohexid(req.id);
        defer allocator.free(hexid);
        warn("{} op {s} {s}\n", .{conn.address, op, hexid});
    }
    return req;
}

fn handler(cfg: *const Config, s: *sslStream) !void {
    var op_buf: [1]u8 = undefined;
    _ = s.read(op_buf[0..]) catch |err| {
        handle_read_err(err, s);
    };

    const op = @as(OpaqueStoreOp, @enumFromInt(op_buf[0]));
    switch (op) {
        OpaqueStoreOp.CREATE_DKG,
        OpaqueStoreOp.CREATE => {
            const req: *CreateReq = read_req(cfg, s, CreateReq, "create"[0..]) catch |e| {
                warn("read create request failed with {}", .{e});
                fail(s,cfg);
            };
            defer allocator.free(@as(*[@sizeOf(CreateReq)]u8, @ptrCast(req)));
            create(cfg, s, req, op);
        },
        OpaqueStoreOp.GET => {
            const req: *OpaqueReq = read_req(cfg, s, OpaqueReq, "get"[0..]) catch |e| {
                warn("read get request failed with {}", .{e});
                fail(s,cfg);
            };
            defer allocator.free(@as(*[@sizeOf(OpaqueReq)]u8, @ptrCast(req)));
            get(cfg, s, req);
        },
        OpaqueStoreOp.DELETE => {
            const req: *OpaqueReq = read_req(cfg, s, OpaqueReq, "delete"[0..]) catch |e| {
                warn("read delete request failed with {}", .{e});
                fail(s,cfg);
            };
            defer allocator.free(@as(*[@sizeOf(OpaqueReq)]u8, @ptrCast(req)));
            delete(cfg, s, req);
        },
        OpaqueStoreOp.UPDATE => {
            const req: *OpaqueReq = read_req(cfg, s, OpaqueReq, "update"[0..]) catch |e| {
                warn("read update request failed with {}", .{e});
                fail(s,cfg);
            };
            defer allocator.free(@as(*[@sizeOf(OpaqueReq)]u8, @ptrCast(req)));
            update(cfg, s, req);
        },
        OpaqueStoreOp.GET_RTOKEN => {
            const req: *OpaqueReq = read_req(cfg, s, OpaqueReq, "get recovery token"[0..]) catch |e| {
                warn("read get recovery token request failed with {}", .{e});
                fail(s,cfg);
            };
            defer allocator.free(@as(*[@sizeOf(OpaqueReq)]u8, @ptrCast(req)));
            get_rtoken(cfg, s, req);
        },
        OpaqueStoreOp.UNLOCK => {
            const req: *UnlockReq = read_req(cfg, s, UnlockReq, "unlock"[0..]) catch |e| {
                warn("read unlock request failed with {}", .{e});
                fail(s,cfg);
            };
            defer allocator.free(@as(*[@sizeOf(UnlockReq)]u8, @ptrCast(req)));
            unlock(cfg, s, req);
        },
        _ => {
            if (cfg.verbose) warn("{} invalid op({}). aborting.\n",.{conn.address, op});
        }
    }
}

pub fn main() !void {
    try stdout.print("starting up opaque-store server\n", .{});
    try bw.flush(); // don't forget to flush!

    //if(DEBUG) {
    //    tp_dkg.log_file = @ptrCast(stdio.fdopen(2,"w"));
    //}

    const cfg = try loadcfg();
    const sk: *ssl.c.private_key = ssl.c.read_private_key(@ptrCast(cfg.ssl_key));

    var certs_len: usize = undefined;
    const certs: *ssl.c.br_x509_certificate = ssl.c.read_certificates(@ptrCast(cfg.ssl_cert), &certs_len);

    const addresses = try std.net.getAddressList(allocator, cfg.address, cfg.port);
    defer addresses.deinit();
    for (addresses.addrs) |addr| {
        var addrtype: *const [4:0]u8 = undefined;
        switch (addr.any.family) {
            posix.AF.INET => addrtype = "ipv4",
            posix.AF.INET6 => addrtype = "ipv6",
            posix.AF.UNIX => addrtype = "unix",
            else => unreachable,
        }
        warn("addr: {s}, {}\n", .{addrtype, addr});
    }

    const addr = try net.Address.parseIp(cfg.address, cfg.port);

    var srv = addr.listen(.{.reuse_address = true }) catch |err| switch (err) {
        error.AddressInUse => {
            warn("port {} already in use.", .{cfg.port});
            posix.exit(1);
        },
        else => {
           return err;
           //unreachable,
        }
    };

    const to = posix.timeval{
        .tv_sec = cfg.timeout,
        .tv_usec = 0
    };
    try posix.setsockopt(srv.stream.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&to));
    try posix.setsockopt(srv.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&to));

    var kids = BufSet.init(allocator);

    while (true) {
        if(srv.accept()) |c| {
            conn = c;
        } else |e| {
            if(e==error.WouldBlock) {
                const Status = if (builtin.link_libc) c_int else u32;
                var status: Status = undefined;
                const rc = posix.system.waitpid(-1, &status, posix.system.W.NOHANG);
                if(rc>0) {
                    kids.remove(mem.asBytes(&rc));
                    if(cfg.verbose) warn("removing kid {} from pool\n",.{rc});
                }
                continue;
            }
            unreachable;
        }

        while (kids.count() >= cfg.max_kids) {
            if (cfg.verbose) warn("waiting for kid to die\n", .{});
            const pid = posix.waitpid(-1, 0).pid;
            if (cfg.verbose) warn("wait returned: {}\n", .{pid});
            kids.remove(mem.asBytes(&pid));
        }

        var pid = try posix.fork();
        switch (pid) {
            0 => {
                var sc: ssl.c.br_ssl_server_context = undefined;
                //c.br_ssl_server_init_full_ec(&sc, certs, certs_len, c.BR_KEYTYPE_EC, &sk.key.ec);
                ssl.c.br_ssl_server_init_minf2c(&sc, certs, certs_len, &sk.key.ec);
                var iobuf: [ssl.c.BR_SSL_BUFSIZE_BIDI]u8 = undefined;
                ssl.c.br_ssl_engine_set_buffer(&sc.eng, &iobuf, iobuf.len, 1);
                // * Reset the server context, for a new handshake.
                if (ssl.c.br_ssl_server_reset(&sc) == 0) {
                    return ssl.convertError(ssl.c.br_ssl_engine_last_error(&sc.eng));
                }
                var s = ssl.initStream(&sc.eng, &conn.stream, &conn.stream);
                handler(&cfg, &s) catch |err| {
                    if(err==error.WouldBlock or err==error.IO) {
                        if(cfg.verbose) warn("timeout, abort.\n",.{});
                        _ = std.os.linux.shutdown(conn.stream.handle, std.os.linux.SHUT.RDWR);
                        conn.stream.close();
                    } else {
                        return err;
                    }
                };
                posix.exit(0);

            },
            else => {
                try kids.insert(mem.asBytes(&pid));
                conn.stream.close();
            },
        }
    }
}
