package org.thomas.utils.jwt;

import com.alibaba.fastjson.JSONObject;
import org.springframework.util.DigestUtils;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @program: security
 * @create: 2021-03-23 12:31
 * @author: Thomas-Ren
 * @E-maill: isthomasren@gmail.com
 * @description: 手写 JWT
 **/
public class WriteJWT {

    private static final String SING_KEY = "thomas";

    public static void main(String[] args) throws UnsupportedEncodingException {
        // 封装三个部分 header、payload、sign签名值

        // 定义 header
        JSONObject header = new JSONObject();
        header.put("alg", "HS256");

        String headerEncoded = Base64.getEncoder().encodeToString(header.toJSONString().getBytes());

        // 定义 payload
        JSONObject payload = new JSONObject();
        payload.put("phone", "18907124154");

        String payLoadJsonStr = payload.toJSONString();
        String payLoadEncoded = Base64.getEncoder().encodeToString(payLoadJsonStr.getBytes());

        // sign签名值
        String sign = DigestUtils.md5DigestAsHex((payload + SING_KEY).getBytes(StandardCharsets.UTF_8));


        String jwt = headerEncoded + "." + payLoadEncoded + "." + sign;

        System.out.println(jwt);


        // 验签
        String payLoadEncode = jwt.split("\\.")[1];
        String payLoadDecoder = new String(Base64.getDecoder().decode(payLoadEncode), "UTF-8");

        String newSign = DigestUtils.md5DigestAsHex((payLoadDecoder + SING_KEY).getBytes(StandardCharsets.UTF_8));
        System.out.println(newSign.equals(sign));
    }
}
