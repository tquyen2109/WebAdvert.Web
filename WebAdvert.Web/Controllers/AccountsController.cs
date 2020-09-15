using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;
   

        public AccountsController(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
          
        }
        public async Task<IActionResult> Signup()
        {
            var model = new SignupModel();
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if(ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);
                if(user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email existes");
                    return View(model);
                }              
                user.Attributes.Add(CognitoAttribute.Name.ToString(), model.Email);
                var createdUser = await _userManager.CreateAsync(user, model.Password);
                if(createdUser.Succeeded)
                {
                   return RedirectToAction("Confirm");
                }
            }
            return View();
        }

        public async Task<IActionResult> Confirm (ConfirmModel model)
        {       
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Confirm_Post (ConfirmModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if( user == null)
                {
                    ModelState.AddModelError("NotFound", "User not found");
                    return View(model);
                }
                var result = await (_userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true).ConfigureAwait(false);
                if(result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach(var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                    return View(model);
                    
                }
            }
            return View(model);
        }

        public async Task<IActionResult> Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> Login_Post(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email,
                    model.Password, model.RememberMe, false).ConfigureAwait(false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email or passowrd do not match");
                }
            }

            return View("Login",model);

        }
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword_Post(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await (_userManager as CognitoUserManager<CognitoUser>).FindByEmailAsync(model.Email);
                var isConfirm = await (_userManager as CognitoUserManager<CognitoUser>).IsEmailConfirmedAsync(user);
                if (user != null && isConfirm)
                {
                    var token = await (_userManager as CognitoUserManager<CognitoUser>).ResetPasswordAsync(user);
                   
                    return View("ForgotPasswordConfirmation");
                }

                return View("ForgotPasswordConfirmation");
            }

            return View(model);

        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string token, string email)
        {
            if(token == null || email == null)
            {
                ModelState.AddModelError("", "Invalid password reset token");
            }
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ActionName("ResetPassword")]
        public async Task<IActionResult> ResetPassword_Post(ResetPasswordViewModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await (_userManager as CognitoUserManager<CognitoUser>).FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var result = await (_userManager as CognitoUserManager<CognitoUser>).ResetPasswordAsync(user, model.Code, model.Password);
                    if (result.Succeeded)
                    {
                        return View("ResetPasswordConfirmation");
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(model);
                }

                return View("ResetPassowrdConfirmation");
            }

            return View(model);
        }
       
    }
    
}