// SHA256 Compute Shader for GPU-accelerated hash cracking

// Function to get SHA256 K constant by index (avoids dynamic array indexing)
fn get_k(i: u32) -> u32 {
    switch i {
        case 0u: { return 0x428a2f98u; }
        case 1u: { return 0x71374491u; }
        case 2u: { return 0xb5c0fbcfu; }
        case 3u: { return 0xe9b5dba5u; }
        case 4u: { return 0x3956c25bu; }
        case 5u: { return 0x59f111f1u; }
        case 6u: { return 0x923f82a4u; }
        case 7u: { return 0xab1c5ed5u; }
        case 8u: { return 0xd807aa98u; }
        case 9u: { return 0x12835b01u; }
        case 10u: { return 0x243185beu; }
        case 11u: { return 0x550c7dc3u; }
        case 12u: { return 0x72be5d74u; }
        case 13u: { return 0x80deb1feu; }
        case 14u: { return 0x9bdc06a7u; }
        case 15u: { return 0xc19bf174u; }
        case 16u: { return 0xe49b69c1u; }
        case 17u: { return 0xefbe4786u; }
        case 18u: { return 0x0fc19dc6u; }
        case 19u: { return 0x240ca1ccu; }
        case 20u: { return 0x2de92c6fu; }
        case 21u: { return 0x4a7484aau; }
        case 22u: { return 0x5cb0a9dcu; }
        case 23u: { return 0x76f988dau; }
        case 24u: { return 0x983e5152u; }
        case 25u: { return 0xa831c66du; }
        case 26u: { return 0xb00327c8u; }
        case 27u: { return 0xbf597fc7u; }
        case 28u: { return 0xc6e00bf3u; }
        case 29u: { return 0xd5a79147u; }
        case 30u: { return 0x06ca6351u; }
        case 31u: { return 0x14292967u; }
        case 32u: { return 0x27b70a85u; }
        case 33u: { return 0x2e1b2138u; }
        case 34u: { return 0x4d2c6dfcu; }
        case 35u: { return 0x53380d13u; }
        case 36u: { return 0x650a7354u; }
        case 37u: { return 0x766a0abbu; }
        case 38u: { return 0x81c2c92eu; }
        case 39u: { return 0x92722c85u; }
        case 40u: { return 0xa2bfe8a1u; }
        case 41u: { return 0xa81a664bu; }
        case 42u: { return 0xc24b8b70u; }
        case 43u: { return 0xc76c51a3u; }
        case 44u: { return 0xd192e819u; }
        case 45u: { return 0xd6990624u; }
        case 46u: { return 0xf40e3585u; }
        case 47u: { return 0x106aa070u; }
        case 48u: { return 0x19a4c116u; }
        case 49u: { return 0x1e376c08u; }
        case 50u: { return 0x2748774cu; }
        case 51u: { return 0x34b0bcb5u; }
        case 52u: { return 0x391c0cb3u; }
        case 53u: { return 0x4ed8aa4au; }
        case 54u: { return 0x5b9cca4fu; }
        case 55u: { return 0x682e6ff3u; }
        case 56u: { return 0x748f82eeu; }
        case 57u: { return 0x78a5636fu; }
        case 58u: { return 0x84c87814u; }
        case 59u: { return 0x8cc70208u; }
        case 60u: { return 0x90befffau; }
        case 61u: { return 0xa4506cebu; }
        case 62u: { return 0xbef9a3f7u; }
        case 63u: { return 0xc67178f2u; }
        default: { return 0u; }
    }
}

// Input/Output buffers
struct SearchParams {
    target_hash: array<u32, 8>,  // Target SHA256 hash (8 x 32-bit words)
    start_index: u32,              // Starting index for this batch
    batch_size: u32,               // Number of hashes to compute
    charset_size: u32,             // Size of character set
    string_length: u32,            // Current string length being tested
}

@group(0) @binding(0) var<storage, read> params: SearchParams;
@group(0) @binding(1) var<storage, read> charset: array<u32>;  // Character set as u32 array
@group(0) @binding(2) var<storage, read_write> results: array<u32>;  // Results: [found_flag, index, hash...]

// Right rotate
fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

// SHA256 functions
fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (~x & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn sigma0(x: u32) -> u32 {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

fn sigma1(x: u32) -> u32 {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

fn gamma0(x: u32) -> u32 {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

fn gamma1(x: u32) -> u32 {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

// SHA256 hash function - takes message length in bytes
fn sha256_hash(msg_len: u32, w0: u32, w1: u32, w2: u32, w3: u32, w4: u32, w5: u32, w6: u32, w7: u32, w8: u32, w9: u32, w10: u32, w11: u32, w12: u32, w13: u32, w14: u32, w15: u32) -> array<u32, 8> {
    // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    var h0: u32 = 0x6a09e667u;
    var h1: u32 = 0xbb67ae85u;
    var h2: u32 = 0x3c6ef372u;
    var h3: u32 = 0xa54ff53au;
    var h4: u32 = 0x510e527fu;
    var h5: u32 = 0x9b05688cu;
    var h6: u32 = 0x1f83d9abu;
    var h7: u32 = 0x5be0cd19u;

    // Prepare message schedule
    var w: array<u32, 64>;

    // Copy the 16 input words
    w[0] = w0;
    w[1] = w1;
    w[2] = w2;
    w[3] = w3;
    w[4] = w4;
    w[5] = w5;
    w[6] = w6;
    w[7] = w7;
    w[8] = w8;
    w[9] = w9;
    w[10] = w10;
    w[11] = w11;
    w[12] = w12;
    w[13] = w13;
    w[14] = w14;
    w[15] = w15;

    // Extend the first 16 words into the remaining 48 words
    for (var i = 16u; i < 64u; i++) {
        w[i] = gamma1(w[i - 2u]) + w[i - 7u] + gamma0(w[i - 15u]) + w[i - 16u];
    }

    // Main compression loop
    var a = h0;
    var b = h1;
    var c = h2;
    var d = h3;
    var e = h4;
    var f = h5;
    var g = h6;
    var h = h7;

    for (var i = 0u; i < 64u; i++) {
        let t1 = h + sigma1(e) + ch(e, f, g) + get_k(i) + w[i];
        let t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add compressed chunk to hash values
    h0 = h0 + a;
    h1 = h1 + b;
    h2 = h2 + c;
    h3 = h3 + d;
    h4 = h4 + e;
    h5 = h5 + f;
    h6 = h6 + g;
    h7 = h7 + h;

    return array<u32, 8>(h0, h1, h2, h3, h4, h5, h6, h7);
}

// Convert index to message and return as 16 u32 words with padding
fn index_to_padded_message(idx: u32, length: u32, charset_size: u32) -> array<u32, 16> {
    var result: array<u32, 16>;
    var temp_idx = idx;

    // Initialize all to zero
    for (var i = 0u; i < 16u; i++) {
        result[i] = 0u;
    }

    // Generate string bytes and pack into u32s (big-endian)
    for (var i = 0u; i < length; i++) {
        let char_idx = temp_idx % charset_size;
        let byte_val = charset[char_idx];

        let word_idx = i / 4u;
        let byte_pos = i % 4u;
        let shift = (3u - byte_pos) * 8u;

        result[word_idx] = result[word_idx] | (byte_val << shift);

        temp_idx = temp_idx / charset_size;
    }

    // Add padding bit
    let pad_byte_pos = length % 4u;
    let pad_word_pos = length / 4u;

    if (pad_byte_pos == 0u) {
        result[pad_word_pos] = result[pad_word_pos] | 0x80000000u;
    } else if (pad_byte_pos == 1u) {
        result[pad_word_pos] = result[pad_word_pos] | 0x00800000u;
    } else if (pad_byte_pos == 2u) {
        result[pad_word_pos] = result[pad_word_pos] | 0x00008000u;
    } else {
        result[pad_word_pos] = result[pad_word_pos] | 0x00000080u;
    }

    // Add length in bits as big-endian 64-bit integer at the end
    result[15] = length * 8u;

    return result;
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;

    // Check if this thread is within the batch
    if (idx >= params.batch_size) {
        return;
    }

    // Check if already found (early exit)
    if (results[0] == 1u) {
        return;
    }

    // Calculate the actual index to test
    let test_index = params.start_index + idx;

    // Convert index to message with padding
    let message = index_to_padded_message(test_index, params.string_length, params.charset_size);

    // Compute SHA256 hash
    let hash = sha256_hash(
        params.string_length,
        message[0], message[1], message[2], message[3],
        message[4], message[5], message[6], message[7],
        message[8], message[9], message[10], message[11],
        message[12], message[13], message[14], message[15]
    );

    // Compare with target hash (explicit comparison to avoid dynamic indexing)
    var matches = true;
    if (hash[0] != params.target_hash[0]) { matches = false; }
    if (hash[1] != params.target_hash[1]) { matches = false; }
    if (hash[2] != params.target_hash[2]) { matches = false; }
    if (hash[3] != params.target_hash[3]) { matches = false; }
    if (hash[4] != params.target_hash[4]) { matches = false; }
    if (hash[5] != params.target_hash[5]) { matches = false; }
    if (hash[6] != params.target_hash[6]) { matches = false; }
    if (hash[7] != params.target_hash[7]) { matches = false; }

    // If found, store result (atomic would be better but not critical for first match)
    if (matches) {
        results[0] = 1u;  // Found flag
        results[1] = test_index;  // Store the index that matched

        // Store the hash for verification
        results[2] = hash[0];
        results[3] = hash[1];
        results[4] = hash[2];
        results[5] = hash[3];
        results[6] = hash[4];
        results[7] = hash[5];
        results[8] = hash[6];
        results[9] = hash[7];
    }
}
