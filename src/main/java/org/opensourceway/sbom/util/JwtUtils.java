package org.opensourceway.sbom.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.opensourceway.sbom.enums.PermissionConstants;
import org.opensourceway.sbom.model.entity.InfoModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

/**
 * 功能描述
 *
 * @author ly
 * @since 2021-6-22
 */
@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt_secret}")
    private String jwt_secret;

    /**
     * 获取码云token
     *
     * @param infoModel 信息参数
     * @return String
     */
    public String getToken(InfoModel infoModel, int min) {
        //设置token有效期0分钟
        Calendar expires = Calendar.getInstance();
        expires.add(Calendar.MINUTE, min);
        return JWT.create()
                .withAudience(infoModel.getAccessToken())
                .withExpiresAt(expires.getTime())
                .withClaim(PermissionConstants.ID, infoModel.getId())
                .withClaim(PermissionConstants.NAME, infoModel.getName())
                .withClaim(PermissionConstants.LOGIN, infoModel.getLogin())
                .withClaim(PermissionConstants.AVATAR_URL, infoModel.getAvatarUrl())
                .withClaim(PermissionConstants.SUB, infoModel.getSub())
                .sign(Algorithm.HMAC256(jwt_secret));
    }

    /**
     * 获取verifyToken
     *
     * @param token token值
     * @return DecodedJWT
     */
    public String verifyToken(String token) {
        DecodedJWT jwt = null;
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(jwt_secret)).build();
            jwt = verifier.verify(token);
        } catch (JWTVerificationException e) {
            // 效验失败
            logger.warn("token parsing failed");
            //首先判断是否token过期
            if (e instanceof TokenExpiredException) {
                logger.warn("token is expired");
                return "timeExpired";
            } else {
                logger.warn("token is validException");
                return "validException";
            }
        }
        if (jwt.hashCode() == 401) {
            return "validException";
        }
        return "success";
    }


    /**
     * 通过载荷名字获取载荷的值
     *
     * @param token token值
     * @param name  name
     * @return Claim
     */
    public static Claim getClaimByName(String token, String name) {
        return JWT.decode(token).getClaim(name);
    }

    //返回信息
    public static void setReturn(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, int code, String msg) {
        httpServletResponse.setContentType("application/json;charset=utf-8");
        httpServletResponse.setHeader("Access-Control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "POST, GET");
        httpServletResponse.setHeader("Access-Control-Max-Age", "3600");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept,Referer,User-Agent,ticket,loginId,loginTerminal,cityCode,source");
        httpServletResponse.setHeader("Access-Control-Allow-Credentials", "true");
        httpServletResponse.setStatus(code);
        httpServletResponse.setCharacterEncoding("UTF-8");
        try {
            httpServletResponse.getWriter().write(msg);
        } catch (IOException e) {
            logger.error("setReturn error msg:{}", e);
        }
    }


    /**
     * 获取cookie
     *
     * @param cookies
     * @param name
     * @return
     */
    public String getCookie(Cookie[] cookies, String name) {

        String token = "";
        if (cookies.length > 0) {
            // 遍历所有的 cookie
            for (Cookie cookie : cookies) {
                // 判断是否存在名为 "token" 的 cookie
                if (cookie.getName().equals(name)) {
                    // 获取 token 值
                    token = cookie.getValue();
                    break;
                }
            }
        } else {
            // 处理没有任何 cookie 的情况
        }
        return token;
    }
}
