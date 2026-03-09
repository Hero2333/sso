package cn.iocoder.yudao.module.sso.controller.admin.auth;

import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.OAuth2AccessTokenRespVO;
import cn.iocoder.yudao.module.sso.client.CommonResult;
import cn.iocoder.yudao.module.sso.client.OAuth2Client;
import cn.iocoder.yudao.module.sso.client.SecurityUtils;
import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.UserInfoRespVO;
import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.UserUpdateReqVO;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

@org.springframework.context.annotation.Lazy
@RestController
@RequestMapping("/sso")
public class SsoAuthController {

    @Resource
    private OAuth2Client oauth2Client;

    /**
     * 使用 code 访问令牌，获得访问令牌
     *
     * @param code 授权码
     * @param redirectUri 重定向 URI
     * @return 访问令牌；注意，实际项目中，最好创建对应的 ResponseVO 类，只返回必要的字段
     */
    @PostMapping("/login-by-code")
    public CommonResult<OAuth2AccessTokenRespVO> loginByCode(@RequestParam("code") String code,
                                                             @RequestParam("redirectUri") String redirectUri) {
        return oauth2Client.postAccessToken(code, redirectUri);
    }

    /**
     * 使用刷新令牌，获得（刷新）访问令牌
     *
     * @param refreshToken 刷新令牌
     * @return 访问令牌；注意，实际项目中，最好创建对应的 ResponseVO 类，只返回必要的字段
     */
    @PostMapping("/refresh-token")
    public CommonResult<OAuth2AccessTokenRespVO> refreshToken(@RequestParam("refreshToken") String refreshToken) {
        return oauth2Client.refreshToken(refreshToken);
    }

    /**
     * 退出登录
     *
     * @param request 请求
     * @return 成功
     */
    @PostMapping("/logout")
    public CommonResult<Boolean> logout(HttpServletRequest request) {
        String token = SecurityUtils.obtainAuthorization(request, "Authorization");
        if (token!=null && !"".equals(token.trim())) {
            return oauth2Client.revokeToken(token);
        }
        // 返回成功
        CommonResult<Boolean> result = new CommonResult<>();
        result.setCode(0);
        return result;
    }

    /**
     * 获得当前登录用户的基本信息
     *
     * @return 用户信息；注意，实际项目中，最好创建对应的 ResponseVO 类，只返回必要的字段
     */
    @PostMapping("/user")
    public CommonResult<UserInfoRespVO> getUser(HttpServletRequest request) {
        String token = SecurityUtils.obtainAuthorization(request, "Authorization");
        if (token==null || "".equals(token.trim())) {
            CommonResult<UserInfoRespVO> result = new CommonResult<>();
            result.setCode(HttpStatus.UNAUTHORIZED.value());
            result.setMsg("没有token");
            return result;
        }
        return oauth2Client.getUser(token);
    }

    /**
     * 更新当前登录用户的昵称
     *
     * @param nickname 昵称
     * @return 成功
     */
    @PutMapping("/user")
    public CommonResult<Boolean> updateUser(@RequestParam("nickname") String nickname, HttpServletRequest request) {
        String token = SecurityUtils.obtainAuthorization(request, "Authorization");
        if (token==null || "".equals(token.trim())) {
            CommonResult<Boolean> result = new CommonResult<>();
            result.setCode(HttpStatus.UNAUTHORIZED.value());
            result.setMsg("没有token");
            return result;
        }
        UserUpdateReqVO updateReqVO = new UserUpdateReqVO(nickname, null, null, null);
        return oauth2Client.updateUser(updateReqVO, token);
    }

}
