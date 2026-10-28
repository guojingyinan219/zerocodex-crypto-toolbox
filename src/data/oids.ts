import type { OidRecord } from '../types'

const gmRecords: OidRecord[] = [
  { oid: '1.2.156.10197.1.101', name: 'SM4-ECB', english: 'sm4-ecb', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 电子密码本模式，不提供随机化与完整性保护。' },
  { oid: '1.2.156.10197.1.102', name: 'SM4-CBC', english: 'sm4-cbc', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 密码分组链接模式，需要 128 位随机 IV。' },
  { oid: '1.2.156.10197.1.103', name: 'SM4-OFB', english: 'sm4-ofb', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 输出反馈模式。' },
  { oid: '1.2.156.10197.1.104', name: 'SM4-CFB', english: 'sm4-cfb', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 密文反馈模式。' },
  { oid: '1.2.156.10197.1.104.1', name: 'SM4-CFB1', english: 'sm4-cfb1', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 1 位密文反馈模式。' },
  { oid: '1.2.156.10197.1.104.2', name: 'SM4-CFB8', english: 'sm4-cfb8', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 8 位密文反馈模式。' },
  { oid: '1.2.156.10197.1.104.3', name: 'SM4-CFB128', english: 'sm4-cfb128', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 128 位密文反馈模式。' },
  { oid: '1.2.156.10197.1.107', name: 'SM4-CTR', english: 'sm4-ctr', category: '对称密码', standard: 'GM/T 0002-2012', description: 'SM4 计数器模式；同一密钥下计数器不可重复。' },
  { oid: '1.2.156.10197.1.301', name: 'SM2 椭圆曲线', english: 'sm2p256v1', category: '椭圆曲线', standard: 'GM/T 0003-2012', description: 'SM2 推荐 256 位椭圆曲线，不等同于 NIST P-256。' },
  { oid: '1.2.156.10197.1.401', name: 'SM3 摘要', english: 'sm3', category: '摘要算法', standard: 'GM/T 0004-2012', description: '输出 256 位摘要的国密杂凑算法。' },
  { oid: '1.2.156.10197.1.501', name: 'SM3withSM2 签名', english: 'sm2sign-with-sm3', category: '签名算法', standard: 'GM/T 0009-2012', description: '使用 SM3 摘要和 SM2 公钥算法的标准签名标识。' },
  { oid: '1.2.156.10197.1.502', name: 'SHA1withSM2 签名', english: 'sm2sign-with-sha1', category: '签名算法', standard: 'GM/T 0009-2012', description: '兼容用途的 SHA-1 与 SM2 组合，不建议新系统使用。' },
  { oid: '1.2.156.10197.1.503', name: 'SHA256withSM2 签名', english: 'sm2sign-with-sha256', category: '签名算法', standard: 'GM/T 0009-2012', description: 'SHA-256 与 SM2 组合，使用前需确认对端实现支持。' }
]

const publicKeyRecords: OidRecord[] = [
  { oid: '1.2.840.113549.1.1.1', name: 'RSA 公钥', english: 'rsaEncryption', category: '公钥算法', standard: 'PKCS #1 / RFC 8017', description: 'RSA 公钥和私钥的通用算法标识，常见于 SubjectPublicKeyInfo 与 PKCS#8。' },
  { oid: '1.2.840.113549.1.1.7', name: 'RSAES-OAEP', english: 'id-RSAES-OAEP', category: '公钥算法', standard: 'RFC 8017', description: '基于 OAEP 编码的 RSA 加密方案，参数会指定摘要、MGF 和标签。' },
  { oid: '1.2.840.113549.1.1.8', name: 'MGF1', english: 'id-mgf1', category: '公钥算法', standard: 'RFC 8017', description: 'RSA-OAEP 与 RSA-PSS 常用的掩码生成函数。' },
  { oid: '1.2.840.113549.1.1.9', name: 'OAEP 标签源', english: 'id-pSpecified', category: '公钥算法', standard: 'RFC 8017', description: 'RSAES-OAEP 参数中的显式标签来源。' },
  { oid: '1.2.840.113549.1.1.10', name: 'RSA-PSS', english: 'RSASSA-PSS', category: '公钥算法', standard: 'RFC 8017', description: '带可配置摘要、MGF 和盐长度的 RSA 概率签名方案。' },
  { oid: '1.2.840.10045.2.1', name: '椭圆曲线公钥', english: 'id-ecPublicKey', category: '公钥算法', standard: 'RFC 5480', description: 'X.509 SubjectPublicKeyInfo 中的通用 EC 公钥标识，曲线由参数 OID 指定。' },
  { oid: '1.2.840.10040.4.1', name: 'DSA 公钥', english: 'id-dsa', category: '公钥算法', standard: 'RFC 3279', description: '传统数字签名算法 DSA 的公钥标识；新系统通常采用 RSA、ECDSA 或 EdDSA。' },
  { oid: '1.2.840.113549.1.3.1', name: 'PKCS#3 DH 密钥协商', english: 'dhKeyAgreement', category: '密钥协商', standard: 'PKCS #3 / RFC 3279', description: '传统有限域 Diffie-Hellman 密钥协商参数与公钥标识。' },
  { oid: '1.2.840.10046.2.1', name: 'X9.42 DH 公钥', english: 'dhpublicnumber', category: '密钥协商', standard: 'ANSI X9.42 / RFC 3279', description: 'X9.42 有限域 Diffie-Hellman 公钥算法标识。' },
  { oid: '1.3.101.110', name: 'X25519 密钥协商', english: 'id-X25519', category: '密钥协商', standard: 'RFC 8410', description: '基于 Curve25519 的现代椭圆曲线 Diffie-Hellman 密钥协商。' },
  { oid: '1.3.101.111', name: 'X448 密钥协商', english: 'id-X448', category: '密钥协商', standard: 'RFC 8410', description: '基于 Curve448 的现代椭圆曲线 Diffie-Hellman 密钥协商。' },
  { oid: '1.3.101.112', name: 'Ed25519 公钥与签名', english: 'id-Ed25519', category: '公钥算法', standard: 'RFC 8410', description: 'Ed25519 公钥和签名算法标识，参数必须缺省。' },
  { oid: '1.3.101.113', name: 'Ed448 公钥与签名', english: 'id-Ed448', category: '公钥算法', standard: 'RFC 8410', description: 'Ed448 公钥和签名算法标识，参数必须缺省。' }
]

const postQuantumRecords: OidRecord[] = [
  { oid: '2.16.840.1.101.3.4.4.1', name: 'ML-KEM-512', english: 'id-alg-ml-kem-512', category: '后量子算法', standard: 'FIPS 203', description: 'NIST ML-KEM 512 参数集，用于后量子密钥封装。' },
  { oid: '2.16.840.1.101.3.4.4.2', name: 'ML-KEM-768', english: 'id-alg-ml-kem-768', category: '后量子算法', standard: 'FIPS 203', description: 'NIST ML-KEM 768 参数集，用于后量子密钥封装。' },
  { oid: '2.16.840.1.101.3.4.4.3', name: 'ML-KEM-1024', english: 'id-alg-ml-kem-1024', category: '后量子算法', standard: 'FIPS 203', description: 'NIST ML-KEM 1024 参数集，用于后量子密钥封装。' },
  { oid: '2.16.840.1.101.3.4.3.17', name: 'ML-DSA-44', english: 'id-ml-dsa-44', category: '后量子算法', standard: 'FIPS 204', description: 'NIST ML-DSA 44 参数集，用于后量子数字签名。' },
  { oid: '2.16.840.1.101.3.4.3.18', name: 'ML-DSA-65', english: 'id-ml-dsa-65', category: '后量子算法', standard: 'FIPS 204', description: 'NIST ML-DSA 65 参数集，用于后量子数字签名。' },
  { oid: '2.16.840.1.101.3.4.3.19', name: 'ML-DSA-87', english: 'id-ml-dsa-87', category: '后量子算法', standard: 'FIPS 204', description: 'NIST ML-DSA 87 参数集，用于后量子数字签名。' }
]

const curveRecords: OidRecord[] = [
  { oid: '1.2.840.10045.3.1.1', name: 'P-192 曲线', english: 'prime192v1 / secp192r1', category: '椭圆曲线', standard: 'SEC 2 / RFC 5480', description: '旧式 192 位 NIST 曲线，安全强度不足，不建议新系统使用。' },
  { oid: '1.3.132.0.33', name: 'P-224 曲线', english: 'secp224r1', category: '椭圆曲线', standard: 'SEC 2 / RFC 5480', description: '224 位 NIST 曲线，兼容旧系统时仍可见。' },
  { oid: '1.2.840.10045.3.1.7', name: 'P-256 曲线', english: 'prime256v1 / secp256r1', category: '椭圆曲线', standard: 'RFC 5480', description: '广泛使用的 NIST P-256 曲线，不等同于 SM2 曲线。' },
  { oid: '1.3.132.0.34', name: 'P-384 曲线', english: 'secp384r1', category: '椭圆曲线', standard: 'SEC 2 / RFC 5480', description: '384 位 NIST 曲线，常与 SHA-384 搭配。' },
  { oid: '1.3.132.0.35', name: 'P-521 曲线', english: 'secp521r1', category: '椭圆曲线', standard: 'SEC 2 / RFC 5480', description: '521 位 NIST 曲线，常与 SHA-512 搭配。' },
  { oid: '1.3.132.0.10', name: 'secp256k1 曲线', english: 'secp256k1', category: '椭圆曲线', standard: 'SEC 2', description: 'Koblitz 256 位曲线，常见于区块链系统，不是 P-256。' },
  { oid: '1.3.36.3.3.2.8.1.1.7', name: 'Brainpool P256r1', english: 'brainpoolP256r1', category: '椭圆曲线', standard: 'RFC 5639', description: 'Brainpool 256 位随机素数曲线。' },
  { oid: '1.3.36.3.3.2.8.1.1.11', name: 'Brainpool P384r1', english: 'brainpoolP384r1', category: '椭圆曲线', standard: 'RFC 5639', description: 'Brainpool 384 位随机素数曲线。' },
  { oid: '1.3.36.3.3.2.8.1.1.13', name: 'Brainpool P512r1', english: 'brainpoolP512r1', category: '椭圆曲线', standard: 'RFC 5639', description: 'Brainpool 512 位随机素数曲线。' }
]

const signatureRecords: OidRecord[] = [
  { oid: '1.2.840.113549.1.1.4', name: 'MD5withRSA 签名', english: 'md5WithRSAEncryption', category: '签名算法', standard: 'PKCS #1', description: 'MD5 与 RSA PKCS#1 v1.5 签名，已不安全，仅用于识别历史证书。' },
  { oid: '1.2.840.113549.1.1.5', name: 'SHA1withRSA 签名', english: 'sha1WithRSAEncryption', category: '签名算法', standard: 'PKCS #1', description: 'SHA-1 与 RSA PKCS#1 v1.5 签名，已不建议用于新证书。' },
  { oid: '1.2.840.113549.1.1.14', name: 'SHA224withRSA 签名', english: 'sha224WithRSAEncryption', category: '签名算法', standard: 'RFC 8017', description: 'SHA-224 与 RSA PKCS#1 v1.5 签名。' },
  { oid: '1.2.840.113549.1.1.11', name: 'SHA256withRSA 签名', english: 'sha256WithRSAEncryption', category: '签名算法', standard: 'RFC 8017', description: 'SHA-256 与 RSA PKCS#1 v1.5 签名。' },
  { oid: '1.2.840.113549.1.1.12', name: 'SHA384withRSA 签名', english: 'sha384WithRSAEncryption', category: '签名算法', standard: 'RFC 8017', description: 'SHA-384 与 RSA PKCS#1 v1.5 签名。' },
  { oid: '1.2.840.113549.1.1.13', name: 'SHA512withRSA 签名', english: 'sha512WithRSAEncryption', category: '签名算法', standard: 'RFC 8017', description: 'SHA-512 与 RSA PKCS#1 v1.5 签名。' },
  { oid: '1.2.840.113549.1.1.15', name: 'SHA512/224withRSA 签名', english: 'sha512-224WithRSAEncryption', category: '签名算法', standard: 'RFC 8017', description: 'SHA-512/224 与 RSA PKCS#1 v1.5 签名。' },
  { oid: '1.2.840.113549.1.1.16', name: 'SHA512/256withRSA 签名', english: 'sha512-256WithRSAEncryption', category: '签名算法', standard: 'RFC 8017', description: 'SHA-512/256 与 RSA PKCS#1 v1.5 签名。' },
  { oid: '1.2.840.10045.4.1', name: 'SHA1withECDSA 签名', english: 'ecdsa-with-SHA1', category: '签名算法', standard: 'RFC 3279', description: 'ECDSA 与 SHA-1 签名，已不建议用于新证书。' },
  { oid: '1.2.840.10045.4.3.1', name: 'SHA224withECDSA 签名', english: 'ecdsa-with-SHA224', category: '签名算法', standard: 'RFC 5758', description: 'ECDSA 与 SHA-224 签名。' },
  { oid: '1.2.840.10045.4.3.2', name: 'SHA256withECDSA 签名', english: 'ecdsa-with-SHA256', category: '签名算法', standard: 'RFC 5758', description: 'ECDSA 与 SHA-256 签名，常与 P-256 曲线搭配。' },
  { oid: '1.2.840.10045.4.3.3', name: 'SHA384withECDSA 签名', english: 'ecdsa-with-SHA384', category: '签名算法', standard: 'RFC 5758', description: 'ECDSA 与 SHA-384 签名，常与 P-384 曲线搭配。' },
  { oid: '1.2.840.10045.4.3.4', name: 'SHA512withECDSA 签名', english: 'ecdsa-with-SHA512', category: '签名算法', standard: 'RFC 5758', description: 'ECDSA 与 SHA-512 签名，常与 P-521 曲线搭配。' },
  { oid: '1.2.840.10040.4.3', name: 'SHA1withDSA 签名', english: 'dsa-with-sha1', category: '签名算法', standard: 'RFC 3279', description: 'DSA 与 SHA-1 签名，属于历史兼容算法。' },
  { oid: '2.16.840.1.101.3.4.3.1', name: 'SHA224withDSA 签名', english: 'dsa-with-sha224', category: '签名算法', standard: 'FIPS 186 / RFC 5758', description: 'DSA 与 SHA-224 签名。' },
  { oid: '2.16.840.1.101.3.4.3.2', name: 'SHA256withDSA 签名', english: 'dsa-with-sha256', category: '签名算法', standard: 'FIPS 186 / RFC 5758', description: 'DSA 与 SHA-256 签名。' }
]

const digestRecords: OidRecord[] = [
  { oid: '1.2.840.113549.2.5', name: 'MD5 摘要', english: 'md5', category: '摘要算法', standard: 'RFC 1321', description: '输出 128 位摘要，已存在严重碰撞风险，仅用于兼容。' },
  { oid: '1.3.14.3.2.26', name: 'SHA-1 摘要', english: 'sha1', category: '摘要算法', standard: 'RFC 3279', description: '输出 160 位摘要，已不适合数字签名与安全校验。' },
  { oid: '2.16.840.1.101.3.4.2.4', name: 'SHA-224 摘要', english: 'sha224', category: '摘要算法', standard: 'FIPS 180-4', description: 'SHA-2 家族的 224 位摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.1', name: 'SHA-256 摘要', english: 'sha256', category: '摘要算法', standard: 'FIPS 180-4', description: 'SHA-2 家族的 256 位摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.2', name: 'SHA-384 摘要', english: 'sha384', category: '摘要算法', standard: 'FIPS 180-4', description: 'SHA-2 家族的 384 位摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.3', name: 'SHA-512 摘要', english: 'sha512', category: '摘要算法', standard: 'FIPS 180-4', description: 'SHA-2 家族的 512 位摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.5', name: 'SHA-512/224 摘要', english: 'sha512-224', category: '摘要算法', standard: 'FIPS 180-4', description: '基于 SHA-512 结构并截断为 224 位的摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.6', name: 'SHA-512/256 摘要', english: 'sha512-256', category: '摘要算法', standard: 'FIPS 180-4', description: '基于 SHA-512 结构并截断为 256 位的摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.7', name: 'SHA3-224 摘要', english: 'sha3-224', category: '摘要算法', standard: 'FIPS 202', description: 'SHA-3 家族的 224 位海绵结构摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.8', name: 'SHA3-256 摘要', english: 'sha3-256', category: '摘要算法', standard: 'FIPS 202', description: 'SHA-3 家族的 256 位海绵结构摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.9', name: 'SHA3-384 摘要', english: 'sha3-384', category: '摘要算法', standard: 'FIPS 202', description: 'SHA-3 家族的 384 位海绵结构摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.10', name: 'SHA3-512 摘要', english: 'sha3-512', category: '摘要算法', standard: 'FIPS 202', description: 'SHA-3 家族的 512 位海绵结构摘要算法。' },
  { oid: '2.16.840.1.101.3.4.2.11', name: 'SHAKE128', english: 'shake128', category: '摘要算法', standard: 'FIPS 202', description: '可扩展输出函数 SHAKE128，输出长度由调用方指定。' },
  { oid: '2.16.840.1.101.3.4.2.12', name: 'SHAKE256', english: 'shake256', category: '摘要算法', standard: 'FIPS 202', description: '可扩展输出函数 SHAKE256，输出长度由调用方指定。' }
]

const macRecords: OidRecord[] = [
  { oid: '1.2.840.113549.2.7', name: 'HMAC-SHA1', english: 'hmacWithSHA1', category: 'MAC 算法', standard: 'RFC 4231', description: '使用 SHA-1 的 HMAC；新系统通常选择 HMAC-SHA-256 或更强算法。' },
  { oid: '1.2.840.113549.2.8', name: 'HMAC-SHA224', english: 'hmacWithSHA224', category: 'MAC 算法', standard: 'RFC 4231', description: '使用 SHA-224 的 HMAC。' },
  { oid: '1.2.840.113549.2.9', name: 'HMAC-SHA256', english: 'hmacWithSHA256', category: 'MAC 算法', standard: 'RFC 4231', description: '使用 SHA-256 的 HMAC，常用于消息认证与密钥派生。' },
  { oid: '1.2.840.113549.2.10', name: 'HMAC-SHA384', english: 'hmacWithSHA384', category: 'MAC 算法', standard: 'RFC 4231', description: '使用 SHA-384 的 HMAC。' },
  { oid: '1.2.840.113549.2.11', name: 'HMAC-SHA512', english: 'hmacWithSHA512', category: 'MAC 算法', standard: 'RFC 4231', description: '使用 SHA-512 的 HMAC。' },
  { oid: '2.16.840.1.101.3.4.1.9', name: 'AES-128-CMAC', english: 'id-aes128-CMAC', category: 'MAC 算法', standard: 'NIST SP 800-38B', description: '使用 AES-128 的 CMAC 消息认证码。' },
  { oid: '2.16.840.1.101.3.4.1.29', name: 'AES-192-CMAC', english: 'id-aes192-CMAC', category: 'MAC 算法', standard: 'NIST SP 800-38B', description: '使用 AES-192 的 CMAC 消息认证码。' },
  { oid: '2.16.840.1.101.3.4.1.49', name: 'AES-256-CMAC', english: 'id-aes256-CMAC', category: 'MAC 算法', standard: 'NIST SP 800-38B', description: '使用 AES-256 的 CMAC 消息认证码。' }
]

const symmetricRecords: OidRecord[] = [
  { oid: '1.3.14.3.2.7', name: 'DES-CBC', english: 'desCBC', category: '对称密码', standard: 'RFC 3279', description: '单 DES CBC 模式，密钥长度过短，已不安全。' },
  { oid: '1.2.840.113549.3.7', name: '3DES-CBC', english: 'des-EDE3-CBC', category: '对称密码', standard: 'PKCS / RFC 8018', description: '三重 DES CBC 模式，仅用于旧系统兼容。' },
  { oid: '1.2.840.113549.3.2', name: 'RC2-CBC', english: 'rc2CBC', category: '对称密码', standard: 'RFC 8018', description: 'RC2 CBC 模式，属于旧式算法，不建议新系统使用。' },
  { oid: '2.16.840.1.101.3.4.1.1', name: 'AES-128-ECB', english: 'id-aes128-ECB', category: '对称密码', standard: 'NIST SP 800-38A', description: 'AES-128 ECB 模式，不隐藏重复分组模式。' },
  { oid: '2.16.840.1.101.3.4.1.2', name: 'AES-128-CBC', english: 'id-aes128-CBC', category: '对称密码', standard: 'NIST SP 800-38A', description: 'AES-128 CBC 模式，需要随机且不可预测的 IV。' },
  { oid: '2.16.840.1.101.3.4.1.5', name: 'AES-128 密钥包装', english: 'id-aes128-wrap', category: '密钥封装', standard: 'RFC 3394', description: '使用 AES-128 包装其他对称密钥。' },
  { oid: '2.16.840.1.101.3.4.1.6', name: 'AES-128-GCM', english: 'id-aes128-GCM', category: '对称密码', standard: 'NIST SP 800-38D', description: 'AES-128 GCM 认证加密，Nonce 在同一密钥下不得重复。' },
  { oid: '2.16.840.1.101.3.4.1.21', name: 'AES-192-ECB', english: 'id-aes192-ECB', category: '对称密码', standard: 'NIST SP 800-38A', description: 'AES-192 ECB 模式，不隐藏重复分组模式。' },
  { oid: '2.16.840.1.101.3.4.1.22', name: 'AES-192-CBC', english: 'id-aes192-CBC', category: '对称密码', standard: 'NIST SP 800-38A', description: 'AES-192 CBC 模式，需要随机且不可预测的 IV。' },
  { oid: '2.16.840.1.101.3.4.1.25', name: 'AES-192 密钥包装', english: 'id-aes192-wrap', category: '密钥封装', standard: 'RFC 3394', description: '使用 AES-192 包装其他对称密钥。' },
  { oid: '2.16.840.1.101.3.4.1.26', name: 'AES-192-GCM', english: 'id-aes192-GCM', category: '对称密码', standard: 'NIST SP 800-38D', description: 'AES-192 GCM 认证加密，Nonce 在同一密钥下不得重复。' },
  { oid: '2.16.840.1.101.3.4.1.41', name: 'AES-256-ECB', english: 'id-aes256-ECB', category: '对称密码', standard: 'NIST SP 800-38A', description: 'AES-256 ECB 模式，不隐藏重复分组模式。' },
  { oid: '2.16.840.1.101.3.4.1.42', name: 'AES-256-CBC', english: 'id-aes256-CBC', category: '对称密码', standard: 'NIST SP 800-38A', description: 'AES-256 CBC 模式，需要随机且不可预测的 IV。' },
  { oid: '2.16.840.1.101.3.4.1.45', name: 'AES-256 密钥包装', english: 'id-aes256-wrap', category: '密钥封装', standard: 'RFC 3394', description: '使用 AES-256 包装其他对称密钥。' },
  { oid: '2.16.840.1.101.3.4.1.46', name: 'AES-256-GCM', english: 'id-aes256-GCM', category: '对称密码', standard: 'NIST SP 800-38D', description: 'AES-256 GCM 认证加密，Nonce 在同一密钥下不得重复。' },
  { oid: '1.2.840.113549.1.9.16.3.18', name: 'ChaCha20-Poly1305', english: 'id-alg-AEADChaCha20Poly1305', category: '对称密码', standard: 'RFC 8419', description: 'ChaCha20 流密码与 Poly1305 认证器组合的 AEAD 算法。' }
]

const derivationRecords: OidRecord[] = [
  { oid: '1.2.840.113549.1.5.12', name: 'PBKDF2', english: 'id-PBKDF2', category: 'KDF / PBE', standard: 'RFC 8018', description: '基于口令、盐和迭代次数派生密钥；应使用足够高的迭代成本。' },
  { oid: '1.2.840.113549.1.5.13', name: 'PBES2', english: 'id-PBES2', category: 'KDF / PBE', standard: 'RFC 8018', description: '组合 KDF 与对称加密算法的口令加密方案，常见于加密 PKCS#8。' },
  { oid: '1.2.840.113549.1.5.14', name: 'PBMAC1', english: 'id-PBMAC1', category: 'KDF / PBE', standard: 'RFC 8018', description: '组合 KDF 与消息认证算法的口令 MAC 方案。' },
  { oid: '1.3.6.1.4.1.11591.4.11', name: 'scrypt', english: 'id-scrypt', category: 'KDF / PBE', standard: 'RFC 7914', description: '内存困难型口令派生函数，需要显式设置成本、块大小和并行参数。' },
  { oid: '1.2.840.113549.1.9.16.3.28', name: 'HKDF-SHA256', english: 'id-alg-hkdf-with-sha256', category: 'KDF / PBE', standard: 'RFC 8619', description: '使用 HMAC-SHA-256 的 HKDF 提取与扩展算法。' },
  { oid: '1.2.840.113549.1.9.16.3.29', name: 'HKDF-SHA384', english: 'id-alg-hkdf-with-sha384', category: 'KDF / PBE', standard: 'RFC 8619', description: '使用 HMAC-SHA-384 的 HKDF 提取与扩展算法。' },
  { oid: '1.2.840.113549.1.9.16.3.30', name: 'HKDF-SHA512', english: 'id-alg-hkdf-with-sha512', category: 'KDF / PBE', standard: 'RFC 8619', description: '使用 HMAC-SHA-512 的 HKDF 提取与扩展算法。' }
]

const containerRecords: OidRecord[] = [
  { oid: '1.2.840.113549.1.7.1', name: 'CMS 数据', english: 'data', category: 'PKCS / CMS 容器', standard: 'PKCS #7 / RFC 5652', description: 'CMS ContentInfo 的原始 data 内容类型。' },
  { oid: '1.2.840.113549.1.7.2', name: 'CMS 签名数据', english: 'signedData', category: 'PKCS / CMS 容器', standard: 'PKCS #7 / RFC 5652', description: '可携带签名、签名属性和证书链的 CMS SignedData。' },
  { oid: '1.2.840.113549.1.7.3', name: 'CMS 信封数据', english: 'envelopedData', category: 'PKCS / CMS 容器', standard: 'PKCS #7 / RFC 5652', description: '使用内容加密密钥和一个或多个接收方密钥封装的 CMS EnvelopedData。' },
  { oid: '1.2.840.113549.1.7.4', name: 'CMS 签名与信封数据', english: 'signedAndEnvelopedData', category: 'PKCS / CMS 容器', standard: 'PKCS #7', description: '旧式 PKCS#7 签名并加密内容类型，CMS 已不再推荐。' },
  { oid: '1.2.840.113549.1.7.5', name: 'CMS 摘要数据', english: 'digestedData', category: 'PKCS / CMS 容器', standard: 'PKCS #7 / RFC 5652', description: '携带内容摘要的 CMS DigestedData。' },
  { oid: '1.2.840.113549.1.7.6', name: 'CMS 加密数据', english: 'encryptedData', category: 'PKCS / CMS 容器', standard: 'PKCS #7 / RFC 5652', description: '不包含接收方密钥管理信息的 CMS EncryptedData。' },
  { oid: '1.2.840.113549.1.12.10.1.1', name: 'PKCS#12 密钥包', english: 'keyBag', category: 'PKCS / CMS 容器', standard: 'PKCS #12', description: 'PKCS#12 SafeBag 中的未加密私钥。' },
  { oid: '1.2.840.113549.1.12.10.1.2', name: 'PKCS#12 加密密钥包', english: 'pkcs8ShroudedKeyBag', category: 'PKCS / CMS 容器', standard: 'PKCS #12', description: 'PKCS#12 SafeBag 中使用 PKCS#8 EncryptedPrivateKeyInfo 保护的私钥。' },
  { oid: '1.2.840.113549.1.12.10.1.3', name: 'PKCS#12 证书包', english: 'certBag', category: 'PKCS / CMS 容器', standard: 'PKCS #12', description: 'PKCS#12 SafeBag 中的证书对象。' },
  { oid: '1.2.840.113549.1.12.10.1.4', name: 'PKCS#12 CRL 包', english: 'crlBag', category: 'PKCS / CMS 容器', standard: 'PKCS #12', description: 'PKCS#12 SafeBag 中的证书吊销列表。' },
  { oid: '1.2.840.113549.1.12.10.1.5', name: 'PKCS#12 秘密包', english: 'secretBag', category: 'PKCS / CMS 容器', standard: 'PKCS #12', description: 'PKCS#12 SafeBag 中由应用定义的秘密值。' },
  { oid: '1.2.840.113549.1.12.10.1.6', name: 'PKCS#12 安全内容包', english: 'safeContentsBag', category: 'PKCS / CMS 容器', standard: 'PKCS #12', description: '可嵌套其他 SafeBag 的 PKCS#12 容器。' },
  { oid: '1.2.840.113549.1.9.22.1', name: 'PKCS#12 X.509 证书', english: 'x509Certificate', category: 'PKCS / CMS 容器', standard: 'PKCS #12', description: 'PKCS#12 CertBag 中的 X.509 证书类型。' }
]

const attributeRecords: OidRecord[] = [
  { oid: '1.2.840.113549.1.9.1', name: '电子邮箱地址', english: 'emailAddress', category: 'PKCS 属性', standard: 'PKCS #9', description: 'PKCS#9 电子邮箱属性；证书身份优先使用 Subject Alternative Name。' },
  { oid: '1.2.840.113549.1.9.3', name: '内容类型', english: 'contentType', category: 'PKCS 属性', standard: 'PKCS #9 / CMS', description: 'CMS 签名属性中的内容类型。' },
  { oid: '1.2.840.113549.1.9.4', name: '消息摘要', english: 'messageDigest', category: 'PKCS 属性', standard: 'PKCS #9 / CMS', description: 'CMS 签名属性中的内容摘要。' },
  { oid: '1.2.840.113549.1.9.5', name: '签名时间', english: 'signingTime', category: 'PKCS 属性', standard: 'PKCS #9 / CMS', description: 'CMS 签名属性中的声明签名时间，不等同于可信时间戳。' },
  { oid: '1.2.840.113549.1.9.7', name: '质询口令', english: 'challengePassword', category: 'PKCS 属性', standard: 'PKCS #9', description: 'CSR 中可选的质询口令属性，现代 CA 通常不再使用。' },
  { oid: '1.2.840.113549.1.9.14', name: '扩展请求', english: 'extensionRequest', category: 'PKCS 属性', standard: 'PKCS #9', description: 'CSR 中用于请求 SAN、KeyUsage 等 X.509 扩展的属性。' },
  { oid: '1.2.840.113549.1.9.20', name: '友好名称', english: 'friendlyName', category: 'PKCS 属性', standard: 'PKCS #9 / PKCS #12', description: 'PKCS#12 SafeBag 的人类可读别名。' },
  { oid: '1.2.840.113549.1.9.21', name: '本地密钥标识符', english: 'localKeyId', category: 'PKCS 属性', standard: 'PKCS #9 / PKCS #12', description: '在 PKCS#12 中关联私钥与对应证书。' }
]

const dnRecords: OidRecord[] = [
  { oid: '2.5.4.3', name: '通用名称', english: 'commonName', category: 'DN 属性', standard: 'X.520', description: '主体或签发者 DN 中的 CN。' },
  { oid: '2.5.4.4', name: '姓氏', english: 'surname', category: 'DN 属性', standard: 'X.520', description: '主体 DN 中的姓氏属性。' },
  { oid: '2.5.4.5', name: '序列号', english: 'serialNumber', category: 'DN 属性', standard: 'X.520', description: '主体 DN 中的序列号属性，不是证书本身的 serialNumber 字段。' },
  { oid: '2.5.4.6', name: '国家或地区', english: 'countryName', category: 'DN 属性', standard: 'X.520', description: '主体或签发者 DN 中的 C，通常是两位国家代码。' },
  { oid: '2.5.4.7', name: '城市或地区', english: 'localityName', category: 'DN 属性', standard: 'X.520', description: '主体或签发者 DN 中的 L。' },
  { oid: '2.5.4.8', name: '省或州', english: 'stateOrProvinceName', category: 'DN 属性', standard: 'X.520', description: '主体或签发者 DN 中的 ST。' },
  { oid: '2.5.4.10', name: '组织', english: 'organizationName', category: 'DN 属性', standard: 'X.520', description: '主体或签发者 DN 中的 O。' },
  { oid: '2.5.4.11', name: '组织单位', english: 'organizationalUnitName', category: 'DN 属性', standard: 'X.520', description: '主体或签发者 DN 中的 OU。' },
  { oid: '2.5.4.12', name: '职务', english: 'title', category: 'DN 属性', standard: 'X.520', description: '主体 DN 中的职位或职务属性。' },
  { oid: '2.5.4.42', name: '名字', english: 'givenName', category: 'DN 属性', standard: 'X.520', description: '主体 DN 中的名字属性。' },
  { oid: '0.9.2342.19200300.100.1.25', name: '域组件', english: 'domainComponent', category: 'DN 属性', standard: 'RFC 4519', description: 'LDAP DN 中按域名层级表达的 DC 属性。' }
]

const extensionRecords: OidRecord[] = [
  { oid: '2.5.29.9', name: '主体目录属性', english: 'subjectDirectoryAttributes', category: '证书扩展', standard: 'RFC 5280', description: '承载主体的目录属性，互联网证书中较少使用。' },
  { oid: '2.5.29.14', name: '主体密钥标识符', english: 'subjectKeyIdentifier', category: '证书扩展', standard: 'RFC 5280', description: '标识证书主体公钥的摘要值。' },
  { oid: '2.5.29.15', name: '密钥用途', english: 'keyUsage', category: '证书扩展', standard: 'RFC 5280', description: '限制证书公钥用于签名、加密、密钥协商或证书签发等用途。' },
  { oid: '2.5.29.16', name: '私钥使用期限', english: 'privateKeyUsagePeriod', category: '证书扩展', standard: 'RFC 5280', description: '限制对应私钥的使用时间范围，实践中较少使用。' },
  { oid: '2.5.29.17', name: '主体备用名称', english: 'subjectAltName', category: '证书扩展', standard: 'RFC 5280', description: '承载 DNS、IP、邮箱或 URI 等主体标识。' },
  { oid: '2.5.29.18', name: '签发者备用名称', english: 'issuerAltName', category: '证书扩展', standard: 'RFC 5280', description: '承载签发者的备用名称。' },
  { oid: '2.5.29.19', name: '基本约束', english: 'basicConstraints', category: '证书扩展', standard: 'RFC 5280', description: '声明证书是否为 CA，以及可选的路径长度约束。' },
  { oid: '2.5.29.31', name: 'CRL 分发点', english: 'cRLDistributionPoints', category: '证书扩展', standard: 'RFC 5280', description: '给出证书吊销列表的获取地址。' },
  { oid: '2.5.29.32', name: '证书策略', english: 'certificatePolicies', category: '证书扩展', standard: 'RFC 5280', description: '声明证书适用的策略 OID 和可选限定信息。' },
  { oid: '2.5.29.33', name: '策略映射', english: 'policyMappings', category: '证书扩展', standard: 'RFC 5280', description: '在交叉认证场景映射签发者与主体域的证书策略。' },
  { oid: '2.5.29.35', name: '颁发机构密钥标识符', english: 'authorityKeyIdentifier', category: '证书扩展', standard: 'RFC 5280', description: '帮助定位签发该证书的 CA 密钥。' },
  { oid: '2.5.29.36', name: '策略约束', english: 'policyConstraints', category: '证书扩展', standard: 'RFC 5280', description: '约束证书路径中的显式策略与策略映射处理。' },
  { oid: '2.5.29.37', name: '扩展密钥用途', english: 'extendedKeyUsage', category: '证书扩展', standard: 'RFC 5280', description: '约束 TLS、代码签名、邮件保护等更具体的公钥用途。' },
  { oid: '2.5.29.46', name: '最新 CRL', english: 'freshestCRL', category: '证书扩展', standard: 'RFC 5280', description: '指向增量 CRL 的分发位置。' },
  { oid: '2.5.29.54', name: '禁止任意策略', english: 'inhibitAnyPolicy', category: '证书扩展', standard: 'RFC 5280', description: '限制 anyPolicy 在证书路径中继续生效的层数。' },
  { oid: '1.3.6.1.5.5.7.1.1', name: '颁发机构信息访问', english: 'authorityInfoAccess', category: '证书扩展', standard: 'RFC 5280', description: '提供 OCSP 与 CA Issuers 等颁发机构在线服务地址。' },
  { oid: '1.3.6.1.5.5.7.1.11', name: '主体信息访问', english: 'subjectInfoAccess', category: '证书扩展', standard: 'RFC 5280', description: '提供与证书主体相关的在线服务地址。' },
  { oid: '1.3.6.1.5.5.7.1.24', name: 'TLS Feature', english: 'tlsfeature / must-staple', category: '证书扩展', standard: 'RFC 7633', description: '声明 TLS 客户端必须支持的特性，常用于 OCSP Must-Staple。' },
  { oid: '1.3.6.1.4.1.11129.2.4.2', name: '证书透明度 SCT 列表', english: 'signedCertificateTimestampList', category: '证书扩展', standard: 'RFC 6962', description: '携带证书透明度日志签发的 Signed Certificate Timestamp 列表。' }
]

const ekuRecords: OidRecord[] = [
  { oid: '2.5.29.37.0', name: '任意扩展密钥用途', english: 'anyExtendedKeyUsage', category: '扩展密钥用途', standard: 'RFC 5280', description: '表示不限制具体扩展密钥用途，仍需结合 KeyUsage 和策略判断。' },
  { oid: '1.3.6.1.5.5.7.3.1', name: 'TLS 服务端认证', english: 'serverAuth', category: '扩展密钥用途', standard: 'RFC 5280', description: '用于 TLS 服务端身份认证。' },
  { oid: '1.3.6.1.5.5.7.3.2', name: 'TLS 客户端认证', english: 'clientAuth', category: '扩展密钥用途', standard: 'RFC 5280', description: '用于 TLS 客户端身份认证。' },
  { oid: '1.3.6.1.5.5.7.3.3', name: '代码签名', english: 'codeSigning', category: '扩展密钥用途', standard: 'RFC 5280', description: '用于验证软件、脚本或其他可执行内容的发布者与完整性。' },
  { oid: '1.3.6.1.5.5.7.3.4', name: '电子邮件保护', english: 'emailProtection', category: '扩展密钥用途', standard: 'RFC 5280', description: '用于 S/MIME 邮件签名或加密。' },
  { oid: '1.3.6.1.5.5.7.3.8', name: '可信时间戳', english: 'timeStamping', category: '扩展密钥用途', standard: 'RFC 5280 / RFC 3161', description: '用于时间戳机构签发可信时间戳令牌。' },
  { oid: '1.3.6.1.5.5.7.3.9', name: 'OCSP 响应签名', english: 'OCSPSigning', category: '扩展密钥用途', standard: 'RFC 5280 / RFC 6960', description: '用于授权 OCSP 响应签名。' },
  { oid: '1.3.6.1.4.1.311.20.2.2', name: '智能卡登录', english: 'smartCardLogon', category: '扩展密钥用途', standard: 'Microsoft PKI', description: '用于 Microsoft 域环境的智能卡交互式登录。' }
]

const pkixRecords: OidRecord[] = [
  { oid: '1.3.6.1.5.5.7.48.1', name: 'OCSP 服务', english: 'id-ad-ocsp', category: 'PKIX 服务', standard: 'RFC 5280 / RFC 6960', description: 'AIA 中用于定位在线证书状态协议服务。' },
  { oid: '1.3.6.1.5.5.7.48.1.1', name: 'OCSP 基本响应', english: 'id-pkix-ocsp-basic', category: 'PKIX 服务', standard: 'RFC 6960', description: 'OCSP ResponseBytes 中的基本响应类型。' },
  { oid: '1.3.6.1.5.5.7.48.2', name: 'CA 证书下载', english: 'id-ad-caIssuers', category: 'PKIX 服务', standard: 'RFC 5280', description: 'AIA 中用于获取签发者证书的访问方法。' }
]

export const oidRecords: OidRecord[] = [
  ...gmRecords,
  ...publicKeyRecords,
  ...postQuantumRecords,
  ...curveRecords,
  ...signatureRecords,
  ...digestRecords,
  ...macRecords,
  ...symmetricRecords,
  ...derivationRecords,
  ...containerRecords,
  ...attributeRecords,
  ...dnRecords,
  ...extensionRecords,
  ...ekuRecords,
  ...pkixRecords
]

export const oidMap = new Map(oidRecords.map((record) => [record.oid, record]))

export function oidName(oid: string): string {
  return oidMap.get(oid)?.name ?? '未知 OID'
}
