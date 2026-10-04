"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// Run `fn` while refusing any Buffer.alloc larger than `limit` bytes. This
// detects an allocation sized from the declared uncompressed size
// deterministically, without actually committing gigabytes of memory.
function withAllocGuard(limit, fn) {
    const realAlloc = Buffer.alloc;
    let largest = 0;
    Buffer.alloc = function (size) {
        if (size > largest) largest = size;
        if (size > limit) {
            throw new RangeError("unbounded allocation of " + size + " bytes");
        }
        return realAlloc.apply(Buffer, arguments);
    };
    try {
        fn();
    } finally {
        Buffer.alloc = realAlloc;
    }
    return largest;
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });

    describe("allocation is bounded by real data, not the declared size", () => {
        const LIMIT = 64 * 1024 * 1024; // no legitimate allocation here comes close

        it("STORED getData() never allocates the declared size", () => {
            const entry = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A"))).getEntries()[0];
            let error;
            const largest = withAllocGuard(LIMIT, () => {
                try {
                    entry.getData();
                } catch (e) {
                    error = e;
                }
            });
            expect(largest).to.be.below(LIMIT);
            expect(error).to.be.an("error");
            expect(error.message).to.match(/CRC32/);
        });

        it("DEFLATED getData() never allocates the declared size", () => {
            const entry = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00]))).getEntries()[0];
            let error;
            const largest = withAllocGuard(LIMIT, () => {
                try {
                    entry.getData();
                } catch (e) {
                    error = e;
                }
            });
            expect(largest).to.be.below(LIMIT);
            expect(error).to.be.an("error");
            expect(error.message).to.not.match(/unbounded allocation/);
        });

        it("STORED getDataAsync() never allocates the declared size", () => {
            const entry = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A"))).getEntries()[0];
            let cbData, cbErr;
            const largest = withAllocGuard(LIMIT, () => {
                try {
                    entry.getDataAsync((data, err) => {
                        cbData = data;
                        cbErr = err;
                    });
                } catch (e) {
                    // a bad crc on a STORED entry is reported to the callback and then thrown
                    expect(e.message).to.match(/CRC32/);
                }
            });
            expect(largest).to.be.below(LIMIT);
            expect(cbData).to.have.lengthOf(1);
            expect(String(cbErr)).to.match(/CRC32/);
        });

        it("DEFLATED getDataAsync() never allocates the declared size", (done) => {
            // a valid deflate stream for "A" that claims to inflate to ~3 GB
            const entry = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.from("A")))).getEntries()[0];
            const largest = withAllocGuard(LIMIT, () => {
                entry.getDataAsync((data, err) => {
                    try {
                        expect(data).to.have.lengthOf(1);
                        expect(String(err)).to.match(/CRC32/);
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
            });
            expect(largest).to.be.below(LIMIT);
        });

        it("archive-level readers never allocate the declared size", () => {
            const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
            const largest = withAllocGuard(LIMIT, () => {
                expect(() => zip.readFile("a")).to.throw(/CRC32/);
                expect(() => zip.readAsText("a")).to.throw(/CRC32/);
                expect(zip.test()).to.equal(false);
            });
            expect(largest).to.be.below(LIMIT);
        });
    });
});
