package com.projects.auth.facade;

import com.projects.auth.entity.*;
import com.projects.auth.exceptions.UserDontExistException;
import com.projects.auth.exceptions.UserExistingWithMail;
import com.projects.auth.exceptions.UserExistingWithName;
import com.projects.auth.service.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController{

    private final UserService userService;

    @RequestMapping(path = "/register",method = RequestMethod.POST)
    public ResponseEntity<AuthResponse> addNewUser(@Valid @RequestBody UserRegisterDTO user){
        try{
            log.info("--START REGISTER USER");
            userService.register(user);
            log.info("--STOP REGISTER USER");
            return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
        }catch (UserExistingWithName e){
            log.info("User dont exist in database");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new AuthResponse(Code.A4));
        }catch (UserExistingWithMail existing){
            log.info("User dont exist in database with this mail");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new AuthResponse(Code.A5));
        }
    }

    @RequestMapping(path = "/login",method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestBody User user, HttpServletResponse response){
        log.info("--TRY Login USER");
        return userService.login(response,user);
    }

    @RequestMapping(path = "/auto-login",method = RequestMethod.GET)
    public ResponseEntity<?> autoLogin(HttpServletResponse response,HttpServletRequest request){
        log.info("--TRY AUTO-LOGIN USER");
        return userService.loginByToken(request,response);
    }

    @RequestMapping(path = "/logged-in",method = RequestMethod.GET)
    public ResponseEntity<?> loggedIn(HttpServletResponse response,HttpServletRequest request){
        log.info("--TRY AUTO-LOGIN USER");
        return userService.loggedIn(request,response);
    }

    @RequestMapping(path = "/logout",method = RequestMethod.GET)
    public ResponseEntity<?> logout( HttpServletResponse response,HttpServletRequest request){
        return userService.logout(request, response);
    }

    @RequestMapping(path = "/validate",method = RequestMethod.GET)
    public ResponseEntity<AuthResponse> validateToken(HttpServletRequest request,HttpServletResponse response) {
        try{
            log.info("--START validateToken");
            userService.validateToken(request,response);
            log.info("--STOP validateToken");
            return ResponseEntity.ok(new AuthResponse(Code.PERMIT));
        }catch (IllegalArgumentException | ExpiredJwtException e){
            log.info("Token is not correct");
            return ResponseEntity.status(401).body(new AuthResponse(Code.A3));
        }
    }
    @RequestMapping(path = "/activate",method = RequestMethod.GET)
    public ResponseEntity<AuthResponse> activateUser(@RequestParam String uid){
        try{
            log.info("--START activateUser");
            userService.activateUser(uid);
            log.info("--STOP activateUser");
            return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
        }catch (UserDontExistException e){
            log.info("User dont exist in database");
            return ResponseEntity.status(400).body(new AuthResponse(Code.A6));
        }
    }

    @RequestMapping(path = "/reset-password",method = RequestMethod.POST)
    public ResponseEntity<AuthResponse> sendMailRecovery(@RequestBody ResetPasswordData resetPasswordData){
        try{
            log.info("--START sendMailRecovery");
            userService.recoveryPassword(resetPasswordData.getEmail());
            log.info("--STOP sendMailRecovery");
            return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
        }catch (UserDontExistException e){
            log.info("User dont exist in database");
            return ResponseEntity.status(400).body(new AuthResponse(Code.A6));
        }
    }

    @RequestMapping(path = "/reset-password",method = RequestMethod.PATCH)
    public ResponseEntity<AuthResponse> recoveryMail(@RequestBody ChangePasswordData changePasswordData){
        try{
            log.info("--START recoveryMail");
            userService.restPassword(changePasswordData);
            log.info("--STOP recoveryMail");
            return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
        }catch (UserDontExistException e){
            log.info("User dont exist in database");
            return ResponseEntity.status(400).body(new AuthResponse(Code.A6));
        }
    }




    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ValidationMessage handleValidationExceptions(
            MethodArgumentNotValidException ex
    ){
        return new ValidationMessage(ex.getBindingResult().getAllErrors().get(0).getDefaultMessage());
    }
}

