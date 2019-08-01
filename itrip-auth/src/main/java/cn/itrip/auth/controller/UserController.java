package cn.itrip.auth.controller;

import cn.itrip.auth.service.UserService;
import cn.itrip.beans.dto.Dto;
import cn.itrip.beans.pojo.ItripUser;
import cn.itrip.beans.vo.userinfo.ItripUserVO;
import cn.itrip.common.DtoUtil;
import cn.itrip.common.ErrorCode;
import cn.itrip.common.MD5;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import springfox.documentation.annotations.ApiIgnore;

import javax.annotation.Resource;
import java.util.regex.Pattern;

@Controller
@RequestMapping(value = "/api")
public class UserController {
    @Resource
    private UserService userService;
    @ApiIgnore
    @RequestMapping("/register")
    public String showRegisterForm(){return "register";}
    /**
     * 使用邮箱注册
     * @param userVO
     * @return
     */
    @ApiOperation(value = "使用邮箱注册",httpMethod = "post",protocols = "HTTP",produces = "application/json",response = Dto.class,notes = "使用邮箱注册")
    @RequestMapping(value = "/doregister",method = RequestMethod.POST,produces ="application/json" )
    @ResponseBody
    public Dto doRegister(@ApiParam(name = "userVO",value = "用户实体",required = true)
                          @RequestBody ItripUserVO userVO){
        if (!validEmail(userVO.getUserCode()))
            return DtoUtil.returnFail("请使用正确的邮箱地址注册", ErrorCode.AUTH_ILLEGAL_USERCODE);
        try {
            ItripUser user=new ItripUser();
            user.setUserCode(userVO.getUserCode());
            user.setUserPassword(userVO.getUserPassword());
            user.setUserType(0);
            user.setUserName(userVO.getUserName());
            if (null==userService.findByUsername(user.getUserCode())){
                user.setUserPassword(MD5.getMd5(user.getUserPassword(),32));
                userService.itriptxCreateUser(user);
                return DtoUtil.returnSuccess();
            }else{
                return DtoUtil.returnFail("用户已存在，注册失败",ErrorCode.AUTH_USER_ALREADY_EXISTS);

            }
        }catch (Exception e){
            e.printStackTrace();
            return DtoUtil.returnFail(e.getMessage(),ErrorCode.AUTH_UNKNOWN);
        }
    }
    /**
     * 使用手机注册
     * @param userVO
     * @return
     */
    @ApiOperation(value = "使用手机注册",httpMethod = "POST",protocols = "HTTP",produces = "application/json",response = Dto.class,notes = "手机注册")
    @RequestMapping(value = "/registerByPhone",method = RequestMethod.POST,produces = "application/json")
    @ResponseBody
    public Dto registerByPhone(@ApiParam(name = "userVO",value = "用户实体",required = true)
                               @RequestBody ItripUserVO userVO){
        try {
            if (!validPhone(userVO.getUserCode()))
                return DtoUtil.returnFail("请使用正确的手机号注册",ErrorCode.AUTH_ILLEGAL_USERCODE);
            ItripUser user=new ItripUser();
            user.setUserCode(userVO.getUserCode());
            user.setUserPassword(userVO.getUserPassword());
            user.setUserType(0);
            user.setUserName(userVO.getUserName());
            if (null==userService.findByUsername(user.getUserCode())){
                user.setUserPassword(MD5.getMd5(user.getUserPassword(),32));
                userService.itriptxCreateUserByPhone(user);
                return DtoUtil.returnSuccess();
            }else{
                return DtoUtil.returnFail("用户已存在，注册失败", ErrorCode.AUTH_USER_ALREADY_EXISTS);
            }

        }catch (Exception e){
            e.printStackTrace();
            return DtoUtil.returnFail(e.getMessage(),ErrorCode.AUTH_UNKNOWN);
        }
    }
    /**			 *
     * 合法E-mail地址：
     * 1. 必须包含一个并且只有一个符号“@”
     * 2. 第一个字符不得是“@”或者“.”
     * 3. 不允许出现“@.”或者.@
     * 4. 结尾不得是字符“@”或者“.”
     * 5. 允许“@”前的字符中出现“＋”
     * 6. 不允许“＋”在最前面，或者“＋@”
     */
    private boolean validEmail(String email){

        String regex="^\\s*\\w+(?:\\.{0,1}[\\w-]+)*@[a-zA-Z0-9]+(?:[-.][a-zA-Z0-9]+)*\\.[a-zA-Z]+\\s*$"  ;
        return Pattern.compile(regex).matcher(email).find();
    }
    /**
     * 验证是否合法的手机号
     * @param phone
     * @return
     */
    private boolean validPhone(String phone) {
        String regex="^1[3578]{1}\\d{9}$";
        return Pattern.compile(regex).matcher(phone).find();
    }
}
