package cn.itrip.auth.controller;

import cn.itrip.auth.exception.UserLoginFailedException;
import cn.itrip.auth.service.TokenService;
import cn.itrip.auth.service.UserService;
import cn.itrip.beans.dto.Dto;
import cn.itrip.beans.pojo.ItripUser;
import cn.itrip.beans.vo.ItripTokenVO;
import cn.itrip.common.DtoUtil;
import cn.itrip.common.EmptyUtils;
import cn.itrip.common.ErrorCode;
import cn.itrip.common.MD5;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;

@Controller
@RequestMapping(value = "/api")
public class LoginController {
    @Resource
    private UserService userService;

    @Resource
    private TokenService tokenService;

    @ApiOperation(value = "用户登录",httpMethod = "POST",
            protocols = "HTTP",produces = "application/json",
            response = Dto.class,notes = "根据用户名、密码进行统一认证")
    @ApiImplicitParams({
            @ApiImplicitParam(paramType="form",required=true,value="用户名",name="name",defaultValue="yao.liu2015@bdqn.cn"),
            @ApiImplicitParam(paramType="form",required=true,value="密码",name="password",defaultValue="111111"),
    })
    @RequestMapping(value="/dologin",method= RequestMethod.POST,produces= "application/json")
    @ResponseBody
    public Dto dologin(@RequestParam String name, @RequestParam String password, HttpServletRequest request){
                 if (!EmptyUtils.isEmpty(name)&&!EmptyUtils.isEmpty(password)){
                     ItripUser user=null;
                     try {
                         user=userService.login(name.trim(), MD5.getMd5(password.trim(),32));
                     }catch (UserLoginFailedException e){
                         return DtoUtil.returnFail(e.getMessage(), ErrorCode.AUTH_ACTIVATE_FAILED);

                     }catch (Exception e){
                         e.printStackTrace();
                         return DtoUtil.returnFail(e.getMessage(),ErrorCode.AUTH_UNKNOWN);

                     }
                     if (EmptyUtils.isNotEmpty(user)){
                         String token=tokenService.generateToken(
                                 request.getHeader("user-agent"),user
                         );
                         tokenService.save(token,user);
                         //返回tokenVO
                         ItripTokenVO tokenVO=new ItripTokenVO(token, Calendar.getInstance().getTimeInMillis()+tokenService.SESSION_TIMEOUT*100,//2h有效期
                                 Calendar.getInstance().getTimeInMillis() );
                         return DtoUtil.returnDataSuccess(tokenVO);
                     }else {
                         return DtoUtil.returnFail("用户名密码错误",ErrorCode.AUTH_AUTHENTICATION_FAILED);
                     }

                 }else {
                     return DtoUtil.returnFail("参数错误！检查提交的参数名称是否正确。",ErrorCode.AUTH_PARAMETER_ERROR);
                 }

    }
    @ApiOperation(value = "用户注销",httpMethod = "GET",
            protocols = "HTTP", produces = "application/json",
            response = Dto.class,notes="客户端需在header中发送token")
    @ApiImplicitParam(paramType="header",required=true,name="token",value="用户认证凭据",defaultValue="PC-yao.liu2015@bdqn.cn-8-20170516141821-d4f514")
    @RequestMapping(value = "/logout",method = RequestMethod.GET,produces = "application/json",headers =" Token")
    @ResponseBody
    public Dto logout(HttpServletRequest request){
        //验证token
        String token=request.getHeader("token");
        if (!tokenService.validate(request.getHeader("user-agent"),token))
            return DtoUtil.returnFail("token无效",ErrorCode.AUTH_TOKEN_INVALID);
        //删除token和信息
        try {
            tokenService.delete(token);
            return DtoUtil.returnSuccess("注销成功");
        }catch (Exception e){
            e.printStackTrace();
            return DtoUtil.returnFail("注销失败",ErrorCode.AUTH_UNKNOWN);
        }
    }
}
