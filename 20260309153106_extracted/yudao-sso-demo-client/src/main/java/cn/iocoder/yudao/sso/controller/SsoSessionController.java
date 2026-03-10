package cn.iocoder.yudao.sso.controller;

import cn.iocoder.yudao.module.sso.client.CommonResult;
import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.OAuth2AccessTokenRespVO;
import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.UserInfoRespVO;
import cn.iocoder.yudao.sso.service.SsoSessionService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/sso")
public class SsoSessionController {

    @Value("${yudao.sso.oauth2-server}")
    private String oauth2Server;
    @Value("${yudao.sso.client-key}")
    private String clientId;

    @Resource
    private SsoSessionService ssoSessionService;

    @GetMapping("/login-url")
    public CommonResult<Map<String, String>> loginUrl(@RequestParam("redirectUri") String redirectUri,
                                                       @RequestParam(value = "state", defaultValue = "demo-state") String state) {
        Map<String, String> data = new LinkedHashMap<>();
        String authorizeUrl = oauth2Server.replace("/token", "")
                .replace("/admin-api/system/oauth2", "")
                + "/sso?client_id=" + encode(clientId)
                + "&redirect_uri=" + encode(redirectUri)
                + "&response_type=code"
                + "&state=" + encode(state);
        data.put("url", authorizeUrl);

        CommonResult<Map<String, String>> result = new CommonResult<>();
        result.setCode(0);
        result.setData(data);
        result.setMsg("ok");
        return result;
    }

    @PostMapping("/callback")
    public CommonResult<OAuth2AccessTokenRespVO> callback(@RequestParam("code") String code,
                                                           @RequestParam("redirectUri") String redirectUri,
                                                           HttpSession session) {
        return ssoSessionService.loginByCode(code, redirectUri, session);
    }

    @PostMapping("/refresh")
    public CommonResult<OAuth2AccessTokenRespVO> refresh(HttpSession session) {
        return ssoSessionService.refresh(session);
    }

    @GetMapping("/me")
    public CommonResult<UserInfoRespVO> me(HttpSession session) {
        return ssoSessionService.currentUser(session);
    }

    @PostMapping("/logout")
    public CommonResult<Boolean> logout(HttpSession session) {
        return ssoSessionService.logout(session);
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
