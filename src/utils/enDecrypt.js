
/* base64 加解密
  2   */
    export let Base64 = require('js-base64').Base64
          
           /* md5 加解密
  6  */
           export let crypto = require('crypto');
        //    export let md5 = require('js-md5');
           export let CryptoJS = require('crypto-js');
            export let MD5 = CryptoJS.MD5;
            /*
 12   *引入jsencrypt实现数据RSA加密
 13   */
            import JSEncrypt from 'jsencrypt';
            // jsencrypt.js处理长文本数据时报错  Message too long for RSA
            // encryptlong是基于jsencrypt扩展的长文本分段加解密功能。
            import Encrypt from "encryptlong";
            // rsa sign
            import jsrsasign from 'jsrsasign'
          
            // Message Digest algorithm 5，信息摘要算法
            // alglorithm:md5、sha1、sha256
            export function Md5(plainText, alglorithm, encoding){
              const hash =  crypto.createHash(alglorithm)
              hash.update(plainText);//加密内容
              return  hash.digest(encoding);//密文
            }
          
            //Hash Message Authentication Code，散列消息鉴别码
            //Secure Hash Algorithm，安全散列算法
            //alglorithm:md5、sha256、sha1
            export function HMac(plainText, secretKey,alglorithm, encoding){
              const hmac= crypto.createHmac(alglorithm, secretKey);
              const cipherText= hmac.update(plainText);//加密内容
              return  cipherText.digest(encoding);//密文
            }
          
            // Data Encryption Standard，数据加密算法
            // DES/DES3/AES 加密, key与iv长度必须是8的倍数
            // mode:CryptoJS.mode.CBC、CryptoJS.mode.ECB、CryptoJS.mode.CFB
            // padding:CryptoJS.pad.ZeroPadding、CryptoJS.pad.Pkcs7、CryptoJS.pad.NoPadding
            export function encrypt ( algorithm, plainText,key, iv, mode, padding, isTextBase64) {
                key = key ? key : "abcdefghijklmnop";
                iv = iv ? iv : "0102030405060708";
          
                const keyHex = CryptoJS.enc.Utf8.parse(key);
                const ivHex = CryptoJS.enc.Utf8.parse(iv);
                const option = { iv:keyHex,mode: mode, padding: padding }
                let encrypted = null  ;
                if(algorithm === "TripleDES"){
                  encrypted = CryptoJS.TripleDES.encrypt(plainText, keyHex, option)
                }else if(algorithm === "DES"){
                  encrypted = CryptoJS.DES.encrypt(plainText, keyHex, option)
                }
                else if(algorithm === "AES"){
                  encrypted =  CryptoJS.AES.encrypt(plainText, keyHex, option)
                }
                return isTextBase64?CryptoJS.enc.Base64.stringify(encrypted.ciphertext):encrypted.ciphertext.toString();
            }
          
            // DES/DES3/AES解密，key与iv长度必须是8的倍数
            export function decrypt (algorithm,cipherText,key, iv, mode, padding, isTextBase64) {
                key = key ? key : "abcdefghijklmnop";
                iv = iv ? iv : "0102030405060708";
          
                const keyHex = CryptoJS.enc.Utf8.parse(key);
                const ivHex = CryptoJS.enc.Utf8.parse(iv);
                const decryptText = isTextBase64?  CryptoJS.enc.Base64.parse(cipherText):cipherText;
                const textHex = { ciphertext:  isTextBase64?decryptText:CryptoJS.enc.Hex.parse(decryptText) }
                const option = { iv:ivHex,mode: mode, padding: padding }
                let decrypted = null;
                if(algorithm === "TripleDES"){
                  decrypted = CryptoJS.TripleDES.decrypt(textHex, keyHex, option);
                }else if(algorithm === "DES"){
                  decrypted = CryptoJS.DES.decrypt(textHex, keyHex, option);
                }
                else if(algorithm === "AES"){
                  decrypted =  CryptoJS.AES.decrypt(textHex, keyHex, option);
                }
                return decrypted.toString(CryptoJS.enc.Utf8);
            }
          
            export function stringToHex(strSource) {
              if(strSource === "")
             return "";
           var hexCharCode = [];
           for(var i = 0; i < strSource.length; i++) {
            hexCharCode.push((strSource.charCodeAt(i)).toString(16));
          }
          return hexCharCode.join("");
        }
       
        export function hexToString(hexCharCodeStr) {
          var trimedStr = hexCharCodeStr.trim();
          var len = trimedStr.length;
          if(len % 2 !== 0) {
            alert("Illegal Format ASCII Code!");
            return "";
          }
           var curCharCode;
           var resultStr = [];
           for(var i = 0; i < len;i = i + 2) {
             curCharCode = parseInt(trimedStr.substr(i, 2), 16); // ASCII Code Value
             resultStr.push(String.fromCharCode(curCharCode));
           }
           return resultStr.join("");
         }
       
         /** RSA 加密过程
 110   * （1）A生成一对密钥（公钥和私钥），私钥不公开，A自己保留。公钥为公开的，任何人可以获取。
 111   * （2）A传递自己的公钥给B，B用A的公钥对消息进行加密。
 112   * （3）A接收到B加密的消息，利用A自己的私钥对消息进行解密。
 113   *  在这个过程中，只有2次传递过程，第一次是A传递公钥给B，第二次是B传递加密消息给A，即使都被敌方截获，也没有危险性。
 114   *  因为只有A的私钥才能对消息进行解密，防止了消息内容的泄露。
 115   *  使用方法
 116   *  客户端初始化访问服务器端时，服务器端会生成一对RSA对，及公钥和密钥。
 117   *  如果前端只需要将要传给后端的数据进行加密后传输，那么前端可以只要公钥，通过公钥对要传输的参数进行加密后把加密的字符串发给后端，后端取出保存的密码种子或者直接保存的私钥，采用私钥对加密字符串进行解密，得到明文。
 118   *  如果前端要获取后端传过来的已经加密后的字符串，并且解密使用，那么前端就需要拿到RSA对立面的私钥进行解密后使用了。
 119   * */
          /* JSEncrypt 公钥加密  padding:pkcs1pad2 */
          export function RsaJSEncrypt(plainText,publicKey,isKeyBase64,isTextBase64,isURLCode) {
            const jsencrypt = new JSEncrypt({
              default_key_size: 1024
            });
            // setPublicKey 参数默认需要base64,如果是十六进制编码则需要转换为base64，jsrsasign.b64tohex，jsrsasign.hextob64
            isKeyBase64?jsencrypt.setPublicKey(publicKey):jsencrypt.setPublicKey( jsrsasign.hextob64(publicKey));
            // 如果是对象/数组的话，需要先JSON.stringify转换成字符串
            // 处理中文乱码，服务器端：String result = java.net.URLDecoder.decode(cipherText ,"UTF-8");
            let  cipherText = jsencrypt.encrypt(plainText);
        
            // 默认加密结果为base64编码
            cipherText = isTextBase64?cipherText:jsrsasign.b64tohex(cipherText);
            // +号服务器端不识别，url编码
            cipherText = isURLCode? encodeURIComponent(cipherText):cipherText;
        
            return  cipherText;
          }
        
          /* JSEncrypt 私钥解密 padding:pkcs1pad2 */
          export function RsaJSDecrypt(cipherText,privateKey,isKeyBase64,isTextBase64,isURLCode) {
            const jsencrypt = new JSEncrypt({
              default_key_size: 1024,
              padding: crypto.constants.RSA_PKCS1_PADDING
            });
        
            isKeyBase64?jsencrypt.setPrivateKey(privateKey):jsencrypt.setPrivateKey(jsrsasign.hextob64(privateKey));
        
            cipherText = isURLCode?decodeURIComponent(cipherText):cipherText;
            cipherText = isTextBase64?cipherText:jsrsasign.b64tohex(cipherText);
        
            return jsencrypt.decrypt(cipherText);
          }
        
          /* 长文本分段加密 */
          export function RsaEncrypt(plainText,publicKey,isKeyBase64,isTextBase64,isURLCode) {
            const encryptor = new Encrypt({
              default_key_size: 1024,
              padding: crypto.constants.RSA_PKCS1_PADDING
            });
            if (isKeyBase64) {
              encryptor.setPublicKey(publicKey)
            }
            else {
              encryptor.setPublicKey(jsrsasign.hextob64(publicKey));
            }
        
            // 处理中文乱码，服务器端：String result = java.net.URLDecoder.decode(cipherText ,"UTF-8");
        
           let cipherText = encryptor.encryptLong(plainText);
           console.log('before=' + cipherText)
        
             cipherText = isTextBase64?cipherText:jsrsasign.hextob64(cipherText);
             console.log('after=' + cipherText)
            // +号服务器端不识别，url编码
            cipherText = isURLCode? encodeURIComponent(cipherText):cipherText;
            console.log('final=' + cipherText)
            console.log('admin=' + jsrsasign.hextob64('admin'))
            return  cipherText;
          }
        
          /* 长文本分段解密 */
          export function RsaDecrypt(cipherText,privateKey,isKeyBase64,isTextBase64,isURLCode) {
            const encryptor = new Encrypt({
              default_key_size: 1024,
              padding: crypto.constants.RSA_PKCS1_PADDING
            })
        
            if (isKeyBase64){
             encryptor.setPrivateKey(privateKey)
           }
           else{
             encryptor.setPrivateKey(jsrsasign.hextob64(privateKey));
           }
            cipherText = isURLCode?decodeURIComponent(cipherText):cipherText;
            cipherText = isTextBase64?cipherText:jsrsasign.b64tohex(cipherText);
        
            return encryptor.decryptLong(cipherText);
          }
        
          // 获取签名 privateKey
          export function RsaSign(plainText,privateKey,format_key, algorithm,isKeyBase64,isTextBase64,isURLCode)
          {
            // 生成签名对象
            let sign = genSign(isKeyBase64?privateKey:jsrsasign.hextob64(privateKey),format_key, algorithm);
             plainText = isTextBase64?jsrsasign.b64tohex(plainText):plainText;
           // console.log("待签名前数据："+plainText);
             let plain_Text = genDigest(plainText,algorithm);
        
            // console.log("待签名摘要数据："+plain_Text);
             sign.updateString(plain_Text);
        
            // 默认签名数据为十六进制数据
             let signedText = isTextBase64?jsrsasign.hextob64(sign.sign()):sign.sign();
        
            // console.log("生成签名数据："+sign.sign());
            // +号服务器端不识别，url编码
             signedText = isURLCode? encodeURIComponent(signedText):signedText;
        
             return signedText;
          }
        
          // 验证签名 publicKey_s 服务器端的公钥
          // alglorithm: SHA1withRSA、MD5withRSA、SHA256withRSA、 SHA384withRSA、SHA512withRSA、RIPEMD160withRSA
          // format_key: PKCS#1、PKCS#5、PKCS#8
          /*
223   * PKCS#1：定义RSA公开密钥算法加密和签名机制，主要用于组织PKCS#7中所描述的数字签名和数字信封。
224   * PKCS#3：定义Diffie-Hellman密钥交换协议。
225   * PKCS#5：描述一种利用从口令派生出来的安全密钥加密字符串的方法。使用MD2或MD5 从口令中派生密钥，并采用DES-CBC模式加密。主要用于加密从一个计算机传送到另一个计算机的私人密钥，不能用于加密消息[24]。
226   * PKCS#6：描述了公钥证书的标准语法，主要描述X.509证书的扩展格式。
227   * PKCS#7：定义一种通用的消息语法，包括数字签名和加密等用于增强的加密机制，PKCS#7与PEM兼容，所以不需其他密码操作，就可以将加密的消息转换成PEM消息[26]。
228   * PKCS#8：描述私有密钥信息格式，该信息包括公开密钥算法的私有密钥以及可选的属性集等。
229   * PKCS#9：定义一些用于PKCS#6证书扩展、PKCS#7数字签名和PKCS#8私钥加密信息的属性类型。
230   * PKCS#10：描述证书请求语法。
231   * PKCS#11：称为Cyptoki，定义了一套独立于技术的程序设计接口，用于智能卡和PCMCIA卡之类的加密设备。
232   * PKCS#12：描述个人信息交换语法标准。描述了将用户公钥、私钥、证书和其他相关信息打包的语法。
233   * PKCS#13：椭圆曲线密码体制标准。
234   * PKCS#14：伪随机数生成标准。
235   * PKCS#15：密码令牌信息格式标准。
236   */
          export function RsaVerifySign(plainText,signedText,publicKey,format_key, algorithm,isKeyBase64,isTextBase64,isURLCode)
          {
            // 生成签名
            let verifySign = genSign(isKeyBase64?publicKey:jsrsasign.hextob64(publicKey),format_key, algorithm);
            plainText = isTextBase64?jsrsasign.b64tohex(plainText):plainText;
            // 根据明文生成摘要
            let digestText = genDigest(plainText,algorithm);
        
            verifySign.updateString(digestText);
        
            signedText = isURLCode?decodeURIComponent(signedText):signedText;
            signedText = isTextBase64?jsrsasign.b64tohex(signedText):signedText;
        
            return  verifySign.verify(signedText);
          }
        
          // 根据明文生成摘要
          //SHA1withRSA、MD5withRSA、SHA256withRSA、 SHA384withRSA、SHA512withRSA、RIPEMD160withRSA
          export function genDigest(plainText,algorithm ){
            let option = { "alg": algorithm.split('w')[0], "prov":"cryptojs/jsrsa", }
           // console.log("算法："+algorithm.split('w')[0]);
            let text = new jsrsasign.KJUR.crypto.MessageDigest(option);   // 摘要
            text.updateString(plainText);
        
            let digestText = text.digest();
            // console.log("摘要："+digestText);
            return digestText;
          }
        
          /* 生成rsa签名对象 */
          export function genSign(RsaKey,format_key, algorithm)
          {
            // 密钥要写开头和结束
            // var private_key = '-----BEGIN PRIVATE KEY-----' + privateKey_s + '-----END PRIVATE KEY-----'
            // 读取解析pem格式的秘钥, 生成秘钥实例 (RSAKey)
            let rsaKey = new jsrsasign.RSAKey();
            if (format_key === "PKCS#1" || format_key === "PKCS#5"|| format_key === "PKCS#7"|| format_key === "PKCS#8") {
              rsaKey = jsrsasign.KEYUTIL.getKey(RsaKey);
              // rsaSign.readPrivateKeyFromPEMString(privateKey_s);
            }
        
            let option= {
              "alg":algorithm,
              "prov":"cryptojs/jsrsa",
              "prvkeypem": rsaKey
            };
        
            let sign = new jsrsasign.KJUR.crypto.Signature(option);
            sign.init(rsaKey);
        
            return sign;
          }