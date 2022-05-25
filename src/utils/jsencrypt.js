import { JSEncrypt } from 'jsencrypt'
import cryptoJs from 'crypto-js';
import md5 from 'js-md5'


// import {RsaEncrypt} from './enDecrypt.js'


// 密钥对生成 http://web.chacuo.net/netrsakeypair

const publicKey = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhLCEx3LU5UsBC4/kW16bRcCSY3wGcNSdHoz1jkn6ssDd6aOUZsy1i5p1ob7AhW9YTbza0jiupFXrINBcY1CJv2z0M1RfwHF5GbTU6LEoMJO3rKW4PTe/3wa4W1+HphUumQqa/hgJLNKeTwVZ6DdhV19x82/6x84M4Q6JPIxbQ/QIDAQAB'
// 加密
export function encrypt(txt) {

  // return RsaEncrypt(txt,publicKey,true,true,false);
  const encryptor = new JSEncrypt()
  encryptor.setPublicKey(publicKey) // 设置公钥
  return encryptor.encrypt(txt) // 对数据进行加密
}

export const generatekey = (num) => {
  let library = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = "";
  for (var i = 0; i < num; i++) {
      let randomPoz = Math.floor(Math.random() * library.length);
      key += library.substring(randomPoz, randomPoz + 1);
  }
  return key;
}

//DES加密
export const encryptDes = (message, key) => {
  var keyHex = cryptoJs.enc.Utf8.parse(key)
  var option = { mode: cryptoJs.mode.ECB, padding: cryptoJs.pad.Pkcs7 }
  var encrypted = cryptoJs.DES.encrypt(message, keyHex, option)
  return encrypted.ciphertext.toString()
}


//DES解密
export const decryptDes = (message, key) => {
  var keyHex = cryptoJs.enc.Utf8.parse(key)
  var decrypted = cryptoJs.DES.decrypt(
      {
          ciphertext: cryptoJs.enc.Hex.parse(message)
      },
      keyHex,
      {
          mode: cryptoJs.mode.ECB,
          padding: cryptoJs.pad.Pkcs7
      }
  )
  return decrypted.toString(cryptoJs.enc.Utf8)
}

// MD5
export const encryptMd5 = (message) => {
  return md5(message)
}

// 三段式加密
export const threePhaseEncrypt = (message) => {
  const desKey = generatekey(8);
  const md5Var = md5(message + desKey);
  const desVar = encryptDes(message, desKey);
  const rsaVar = encrypt(desKey);
  const char29 = generatekey(29);
  return md5Var + char29 + desVar + char29 + rsaVar;

}

// //DES加密
// export function des(message, key) {
//   //这里根据自己的需求去选择那一种方式   我使用的是下面这俩种适合我的业务
//     //message = cryptoJs.enc.Hex.parse(message)    
//     //key = cryptoJs.enc.Hex.parse(key)           
//     var keyHex = cryptoJs.enc.Utf8.parse(key)
    
//     var option = {
//       mode: cryptoJs.mode.ECB, 
//       padding: cryptoJs.pad.NoPadding  //填充模式
//     }
//     var encrypted = cryptoJs.DES.encrypt(message, key, option)
//     return encrypted.ciphertext.toString()
//   }



// export function longEncrypt(txt) {
  

//   return  RsaEncrypt(txt, publicKey, true, true, false);
// }

// 解密
// export function decrypt(txt) {
//   const encryptor = new JSEncrypt()
//   encryptor.setPrivateKey(privateKey) // 设置私钥
//   return encryptor.decrypt(txt) // 对数据进行解密
// }
