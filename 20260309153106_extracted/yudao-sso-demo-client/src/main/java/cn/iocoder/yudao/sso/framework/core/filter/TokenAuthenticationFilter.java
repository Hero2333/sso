package cn.iocoder.yudao.sso.framework.core.filter;

import cn.iocoder.yudao.module.sso.client.CommonResult;
import cn.iocoder.yudao.module.sso.client.OAuth2Client;
import cn.iocoder.yudao.module.sso.client.SecurityUtils;
import cn.iocoder.yudao.module.sso.client.SsoLoginUser;
import cn.iocoder.yudao.module.sso.controller.admin.auth.vo.OAuth2CheckTokenRespVO;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Token 过滤器，验证 token 的有效性
 * 验证通过后，获得 {@link SsoLoginUser} 信息，并加入到 Spring Security 上下文
 *
 * @author 芋道源码
 */
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    @Resource
    private OAuth2Client oauth2Client;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 1. 获得访问令牌
        String token = SecurityUtils.obtainAuthorization(request, "Authorization");
        if (StringUtils.hasText(token)) {
            // 2. 基于 token 构建登录用户
            SsoLoginUser loginUser = buildLoginUserByToken(token);
            // 3. 设置当前用户
            if (loginUser != null) {
                SecurityUtils.setLoginUser(loginUser, request);
            }
        }

        // 继续过滤链
        filterChain.doFilter(request, response);
    }

    private SsoLoginUser buildLoginUserByToken(String token) {
        try {
            CommonResult<OAuth2CheckTokenRespVO> accessTokenResult = oauth2Client.checkToken(token);
            OAuth2CheckTokenRespVO accessToken = accessTokenResult.getData();
            if (accessToken == null) {
                return null;
            }
            // 构建登录用户
            return new SsoLoginUser().setId(accessToken.getUserId()).setUserType(accessToken.getUserType())
                    .setTenantId(accessToken.getTenantId()).setScopes(accessToken.getScopes())
                    .setAccessToken(accessToken.getAccessToken());
        } catch (Exception exception) {
            // 校验 Token 不通过时，考虑到一些接口是无需登录的，所以直接返回 null 即可
            return null;
        }
    }

}
