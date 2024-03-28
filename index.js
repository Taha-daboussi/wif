var bs58check = require('bs58check')

function decodeRaw (buffer, version) {
  // check version only if defined
  if (version !== undefined && buffer[0] !== version) throw new Error('Invalid network version')

  // uncompressed
  if (buffer.length === 33) {
    return {
      version: buffer[0],
      privateKey: buffer.slice(1, 33),
      compressed: false
    }
  }

  // invalid length
  if (buffer.length !== 34) throw new Error('Invalid WIF length')

  // invalid compression flag
  if (buffer[33] !== 0x01) throw new Error('Invalid compression flag')

  return {
    version: buffer[0],
    privateKey: buffer.slice(1, 33),
    compressed: true
  }
}

function encodeRaw (version, privateKey, compressed) {
  if (privateKey.length !== 32) throw new TypeError('Invalid privateKey length')

  var result = new Uint8Array(compressed ? 34 : 33)
  var view = new DataView(result.buffer)
  view.setUint8(0, version)
  result.set(privateKey, 1)

  if (compressed) {
    result[33] = 0x01
  }

  return result
}

function decode (string, version) {
  const data = decodeRaw(bs58check.decode(string), version) 
  if(data.privateKey instanceof Uint8Array ){
    const uint8Array = new Uint8Array(Object.keys(data.privateKey).map(key => data.privateKey[key]));
// Convert Uint8Array to Buffer
    const buffer = Buffer.from(uint8Array);
    data.privateKey = buffer
  }
  return data
}

function encode (version, privateKey, compressed) {
  if (typeof version === 'number') return bs58check.encode(encodeRaw(version, privateKey, compressed))

  return bs58check.encode(
    encodeRaw(
      version.version,
      version.privateKey,
      version.compressed
    )
  )
}

module.exports = {
  decode: decode,
  decodeRaw: decodeRaw,
  encode: encode,
  encodeRaw: encodeRaw
}
