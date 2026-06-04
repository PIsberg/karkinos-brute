// OpenPGP Iterated+Salted S2K (SHA-256) on the GPU, computed in CHUNKS.
//
// A single candidate's S2K hashes ~16 MiB (262k SHA blocks). Doing that in one
// dispatch trips the GPU watchdog (TDR), so we process a bounded range of blocks
// per dispatch and persist the running SHA state {h[8], m, off} between
// dispatches in `state`. The host issues ceil(num_blocks/chunk) dispatches; the
// final one writes the digest to `out`.
//
// One invocation == one candidate. Passphrases are packed big-endian, 4 bytes
// per u32, MAX_WORDS per candidate.

const MAX_WORDS: u32 = 16u;      // 64-byte max passphrase
const WG: u32 = 64u;
const STATE_WORDS: u32 = 10u;    // h0..h7, m, off

struct Params {
    salt0: u32,
    salt1: u32,
    count: u32,
    num_blocks: u32,
    bitlen_hi: u32,
    bitlen_lo: u32,
    n_candidates: u32,
    start_block: u32,
    end_block: u32,
    is_final: u32,
    _p0: u32,
    _p1: u32,
};

@group(0) @binding(0) var<uniform> P: Params;
@group(0) @binding(1) var<storage, read> pw: array<u32>;
@group(0) @binding(2) var<storage, read> pwlen: array<u32>;
@group(0) @binding(3) var<storage, read_write> out: array<u32>;
@group(0) @binding(4) var<storage, read> K: array<u32, 64>;
@group(0) @binding(5) var<storage, read_write> state: array<u32>;

fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }

var<private> st: array<u32, 8>;
// 16-word sliding message schedule (keeps register pressure low for occupancy).
var<private> w: array<u32, 16>;

fn compress() {
    var a=st[0]; var b=st[1]; var c=st[2]; var d=st[3];
    var e=st[4]; var f=st[5]; var g=st[6]; var h=st[7];
    for (var t = 0u; t < 64u; t = t + 1u) {
        var wt: u32;
        if (t < 16u) {
            wt = w[t];
        } else {
            let w15 = w[(t + 1u) & 15u];
            let w2  = w[(t + 14u) & 15u];
            let s0 = rotr(w15,7u) ^ rotr(w15,18u) ^ (w15 >> 3u);
            let s1 = rotr(w2,17u) ^ rotr(w2,19u) ^ (w2 >> 10u);
            wt = w[t & 15u] + s0 + w[(t + 9u) & 15u] + s1;
            w[t & 15u] = wt;
        }
        let S1 = rotr(e,6u) ^ rotr(e,11u) ^ rotr(e,25u);
        let ch = (e & f) ^ ((~e) & g);
        let t1 = h + S1 + ch + K[t] + wt;
        let S0 = rotr(a,2u) ^ rotr(a,13u) ^ rotr(a,22u);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = S0 + maj;
        h=g; g=f; f=e; e=d + t1; d=c; c=b; b=a; a=t1 + t2;
    }
    st[0]=st[0]+a; st[1]=st[1]+b; st[2]=st[2]+c; st[3]=st[3]+d;
    st[4]=st[4]+e; st[5]=st[5]+f; st[6]=st[6]+g; st[7]=st[7]+h;
}

@compute @workgroup_size(WG)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if (idx >= P.n_candidates) { return; }

    let plen = pwlen[idx];
    let period = 8u + plen;
    let base = idx * MAX_WORDS;
    let sbase = idx * STATE_WORDS;

    var off: u32;
    var m: u32;
    if (P.start_block == 0u) {
        st[0]=0x6a09e667u; st[1]=0xbb67ae85u; st[2]=0x3c6ef372u; st[3]=0xa54ff53au;
        st[4]=0x510e527fu; st[5]=0x9b05688cu; st[6]=0x1f83d9abu; st[7]=0x5be0cd19u;
        off = 0u; m = 0u;
    } else {
        for (var i = 0u; i < 8u; i = i + 1u) { st[i] = state[sbase + i]; }
        m = state[sbase + 8u];
        off = state[sbase + 9u];
    }

    let totlen = P.num_blocks * 64u;
    let len_start = totlen - 8u;

    for (var blk = P.start_block; blk < P.end_block; blk = blk + 1u) {
        for (var k = 0u; k < 64u; k = k + 1u) {
            var byte: u32;
            if (off < P.count) {
                if (m < 8u) {
                    let sw = select(P.salt1, P.salt0, m < 4u);
                    byte = (sw >> ((3u - (m & 3u)) * 8u)) & 0xffu;
                } else {
                    let j = m - 8u;
                    let word = pw[base + (j >> 2u)];
                    byte = (word >> ((3u - (j & 3u)) * 8u)) & 0xffu;
                }
                m = m + 1u;
                if (m >= period) { m = 0u; }
            } else if (off == P.count) {
                byte = 0x80u;
            } else if (off >= len_start) {
                let li = off - len_start;
                let lw = select(P.bitlen_lo, P.bitlen_hi, li < 4u);
                byte = (lw >> ((3u - (li & 3u)) * 8u)) & 0xffu;
            } else {
                byte = 0u;
            }
            off = off + 1u;

            let wi = k >> 2u;
            if ((k & 3u) == 0u) { w[wi] = 0u; }
            w[wi] = w[wi] | (byte << ((3u - (k & 3u)) * 8u));
        }
        compress();
    }

    if (P.is_final == 1u) {
        let o = idx * 8u;
        for (var i = 0u; i < 8u; i = i + 1u) { out[o + i] = st[i]; }
    } else {
        for (var i = 0u; i < 8u; i = i + 1u) { state[sbase + i] = st[i]; }
        state[sbase + 8u] = m;
        state[sbase + 9u] = off;
    }
}
