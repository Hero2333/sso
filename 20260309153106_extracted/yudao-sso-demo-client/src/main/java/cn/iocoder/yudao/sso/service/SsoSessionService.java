package cn.iocoder.yudao.sso.service;

import cn.iocoder.yudao.module.sso.client.CommonResult;
import cn.iocoder.yudao.module.sso.client.OAuth2Client;
import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.OAuth2AccessTokenRespVO;
import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.UserInfoRespVO;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;

/**
 * 使用 HttpSession 管理 SSO 令牌，避免前端直接持久化敏感 token。
 */
@Service
public class SsoSessionService {

    private static final String SESSION_ACCESS_TOKEN = "SSO_ACCESS_TOKEN";
    private static final String SESSION_REFRESH_TOKEN = "SSO_REFRESH_TOKEN";

    @Resource
    private OAuth2Client oauth2Client;

    public CommonResult<OAuth2AccessTokenRespVO> loginByCode(String code, String redirectUri, HttpSession session) {
        CommonResult<OAuth2AccessTokenRespVO> result = oauth2Client.postAccessToken(code, redirectUri);
        OAuth2AccessTokenRespVO token = result == null ? null : result.getData();
        if (token != null) {
            session.setAttribute(SESSION_ACCESS_TOKEN, token.getAccessToken());
            session.setAttribute(SESSION_REFRESH_TOKEN, token.getRefreshToken());
        }
        return result;
    }

    public CommonResult<OAuth2AccessTokenRespVO> refresh(HttpSession session) {
        String refreshToken = (String) session.getAttribute(SESSION_REFRESH_TOKEN);
        if (!StringUtils.hasText(refreshToken)) {
            return unauthorizedResult("会话中没有 refresh token，请重新登录");
        }
        CommonResult<OAuth2AccessTokenRespVO> result = oauth2Client.refreshToken(refreshToken);
        OAuth2AccessTokenRespVO token = result == null ? null : result.getData();
        if (token != null) {
            session.setAttribute(SESSION_ACCESS_TOKEN, token.getAccessToken());
            session.setAttribute(SESSION_REFRESH_TOKEN, token.getRefreshToken());
        }
        return result;
    }

    public CommonResult<UserInfoRespVO> currentUser(HttpSession session) {
        String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN);
        if (!StringUtils.hasText(accessToken)) {
            return unauthorizedResult("未登录或会话已过期");
        }
        return oauth2Client.getUser(accessToken);
    }

    public CommonResult<Boolean> logout(HttpSession session) {
        String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN);
        if (StringUtils.hasText(accessToken)) {
            oauth2Client.revokeToken(accessToken);
        }
        session.removeAttribute(SESSION_ACCESS_TOKEN);
        session.removeAttribute(SESSION_REFRESH_TOKEN);

        CommonResult<Boolean> result = new CommonResult<>();
        result.setCode(0);
        result.setData(Boolean.TRUE);
        result.setMsg("退出成功");
        return result;
    }

    private <T> CommonResult<T> unauthorizedResult(String message) {
        CommonResult<T> result = new CommonResult<>();
        result.setCode(401);
        result.setMsg(message);
        return result;
    }
}
