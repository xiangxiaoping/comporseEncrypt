<?php

namespace encrypt;

/**
 * Class Encrypt
 * @package encrypt
 * @author xue <xouyin1994@163.com>
 * PHP version 5.4.0+
 * 加密方式两种
 * 1.RSA 非对称加密
 * 2.AES 对称加密
 */

class Encrypt
{
    /****************** TODO RSA加密(非对称) **********************/
    /**
     * 获取私钥
     * @return bool|resource
     */
    private function getPrivateKey($private_key)
    {
        $private_key = "-----BEGIN RSA PRIVATE KEY-----\n" .
            wordwrap($private_key, 64, "\n", true) .
            "\n-----END RSA PRIVATE KEY-----";

        return openssl_pkey_get_private($private_key);
    }

    /**
     * 获取公钥
     * @param $public_key
     * @return resource
     */
    private function getPublicKey($public_key)
    {
        $public_key = "-----BEGIN PUBLIC KEY-----\n" .
            wordwrap($public_key, 64, "\n", true) .
            "\n-----END PUBLIC KEY-----";
//        dump($public_key);die;

        return openssl_pkey_get_public($public_key);
    }

    /**
     * @param $parameter 加密数据(公钥加密)
     * @param $public_key 公钥
     * @return string|null
     * @author xue (xouyin1994@163.com) 2019/9/17
     */
    public function data_encryption_plus($parameter,$public_key)
    {
        return openssl_public_encrypt($parameter, $encrypted, self::getPublicKey($public_key)) ? base64_encode($encrypted) : null;
    }

    /**
     * 参数解密（私钥）
     * @param $parameter  要解密的数据(私钥解密)
     * @param $private_key 私钥
     * @return mixed
     * @author xue (xouyin1994@163.com) 2019/9/17
     */
    public function data_decryption($parameter,$private_key)
    {
        $PrivateKey = $this->getPrivateKey($private_key);
        openssl_private_decrypt(base64_decode($parameter), $decrypted, $PrivateKey);
        return $decrypted;
    }


    /****************** TODO AES-256-ECB 加密方案 **********************/

    /**
     * 加密方法，对数据进行加密，返回加密后的数据
     * @param string $key 密匙
     * @param string $data 要加密的数据
     * @param string $options 数据格式  0,1,2
     * @return string
     * @author xue 2019/8/20
     */
    public function AES_encrypt($data, $key, $options = 0)
    {
        if(empty($key)){
            return false;
        }

        return openssl_encrypt($data, 'AES-256-ECB', $key, $options);
    }


    /**
     * 解密方法，对数据进行解密，返回解密后的数据
     * @param string $key 密匙
     * @param string $data 要解密的数据
     * @param string $options 数据格式  0,1,2
     * @return string
     * @author xue 2019/8/20
     */
    public function AES_decrypt($data, $key, $options = 0)
    {
        if(empty($key)){
            return false;
        }
        return openssl_decrypt($data, 'AES-256-ECB', $key, $options);
    }

}